// Package orchestrator runs the recon chain (subfinder, naabu, httpx, nmap,
// nuclei, ffuf, katana and the injection testers) and persists the results.
//
// ffuf is fanned out one goroutine per target behind a worker pool. Fuzzing is
// network-bound, so N targets cost about as much wall-clock as the slowest one
// rather than the sum of them.
package orchestrator

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"snitch/internal/parsers"
	"snitch/internal/store"
)

var webServiceNames = map[string]bool{
	"http": true, "https": true, "http-proxy": true, "http-alt": true, "ssl/http": true,
}

func toolAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// RunNmap shells out to nmap, parses the XML, and upserts assets.
func RunNmap(ws *store.Workspace, target string, extraArgs []string, timeout time.Duration) ([]parsers.ParsedAsset, error) {
	if !toolAvailable("nmap") {
		return nil, fmt.Errorf("nmap not found on PATH (install it, or use --nmap-xml to import existing results)")
	}

	run := ws.StartRun("nmap", target)
	xmlOut := filepath.Join(os.TempDir(), fmt.Sprintf("nmap-%d.xml", time.Now().UnixNano()))
	defer os.Remove(xmlOut)

	// --stats-every makes nmap emit a periodic progress line (it stays silent
	// by default), which runStreaming relays live so a long scan visibly moves.
	args := append([]string{"-sV", "--stats-every", "5s", "-oX", xmlOut}, extraArgs...)
	args = append(args, target)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	banner("[*] nmap: scanning %s …", target)
	start := time.Now()
	cmd := exec.CommandContext(ctx, "nmap", args...)
	if err := runStreaming(cmd, "nmap", true, true); err != nil {
		ws.FinishRun(run, "failed", 0, 0, 0)
		return nil, fmt.Errorf("nmap failed after %s: %w", fmtElapsed(start), err)
	}

	assets, err := parsers.ParseNmapXML(xmlOut)
	if err != nil {
		ws.FinishRun(run, "failed", 0, 0, 0)
		return nil, err
	}

	newCount := 0
	for _, a := range assets {
		isNew, err := ws.UpsertAsset(&store.Asset{
			Host: a.Host, Port: a.Port, Protocol: a.Protocol,
			Service: a.Service, Product: a.Product, Version: a.Version,
			SourceTool: "nmap",
		})
		if err != nil {
			return nil, err
		}
		if isNew {
			newCount++
		}
	}
	ws.FinishRun(run, "completed", newCount, 0, 0)
	banner("[+] nmap: done in %s — %d open service(s), %d new", fmtElapsed(start), len(assets), newCount)
	return assets, nil
}

// IngestNmapXML skips running nmap and ingests an existing XML file instead.
func IngestNmapXML(ws *store.Workspace, xmlPath, targetLabel string) ([]parsers.ParsedAsset, error) {
	run := ws.StartRun("nmap (imported)", targetLabel)
	assets, err := parsers.ParseNmapXML(xmlPath)
	if err != nil {
		ws.FinishRun(run, "failed", 0, 0, 0)
		return nil, err
	}
	newCount := 0
	for _, a := range assets {
		isNew, err := ws.UpsertAsset(&store.Asset{
			Host: a.Host, Port: a.Port, Protocol: a.Protocol,
			Service: a.Service, Product: a.Product, Version: a.Version,
			SourceTool: "nmap",
		})
		if err != nil {
			return nil, err
		}
		if isNew {
			newCount++
		}
	}
	ws.FinishRun(run, "completed", newCount, 0, 0)
	return assets, nil
}

// RunSubfinder enumerates subdomains of a domain and persists them.
func RunSubfinder(ws *store.Workspace, domain string, timeout time.Duration) ([]string, error) {
	if !toolAvailable("subfinder") {
		return nil, fmt.Errorf("subfinder not found on PATH (install from github.com/projectdiscovery/subfinder, or pass --skip-subfinder)")
	}
	run := ws.StartRun("subfinder", domain)
	out := filepath.Join(os.TempDir(), fmt.Sprintf("subfinder-%d.txt", time.Now().UnixNano()))
	defer os.Remove(out)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	banner("[*] subfinder: enumerating subdomains of %s …", domain)
	start := time.Now()
	cmd := exec.CommandContext(ctx, "subfinder", "-d", domain, "-silent", "-o", out)
	if err := runStreaming(cmd, "subfinder", false, true); err != nil {
		ws.FinishRun(run, "failed", 0, 0, 0)
		return nil, fmt.Errorf("subfinder failed after %s: %w", fmtElapsed(start), err)
	}

	hosts, err := parsers.ParseSubfinderLines(out)
	if err != nil {
		ws.FinishRun(run, "failed", 0, 0, 0)
		return nil, err
	}

	newCount := 0
	for _, h := range hosts {
		isNew, err := ws.UpsertSubdomain(&store.Subdomain{Host: h, SourceTool: "subfinder"})
		if err != nil {
			return nil, err
		}
		if isNew {
			newCount++
		}
	}
	ws.FinishRun(run, "completed", newCount, 0, 0)
	banner("[+] subfinder: done in %s — %d subdomain(s), %d new", fmtElapsed(start), len(hosts), newCount)
	return hosts, nil
}

// RunHttpx probes hosts for live HTTP(S) services, persists them as assets
// (with title/tech/status metadata), and returns their URLs as web targets.
func RunHttpx(ws *store.Workspace, hosts []string, timeout time.Duration) ([]string, error) {
	if len(hosts) == 0 {
		return nil, nil
	}
	if !toolAvailable("httpx") {
		return nil, fmt.Errorf("httpx not found on PATH (install from github.com/projectdiscovery/httpx, or pass --skip-httpx)")
	}
	run := ws.StartRun("httpx", fmt.Sprintf("%d host(s)", len(hosts)))

	inFile := filepath.Join(os.TempDir(), fmt.Sprintf("httpx-in-%d.txt", time.Now().UnixNano()))
	if err := os.WriteFile(inFile, []byte(strings.Join(hosts, "\n")), 0o644); err != nil {
		ws.FinishRun(run, "failed", 0, 0, 0)
		return nil, err
	}
	defer os.Remove(inFile)
	outFile := filepath.Join(os.TempDir(), fmt.Sprintf("httpx-%d.jsonl", time.Now().UnixNano()))
	defer os.Remove(outFile)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	banner("[*] httpx: probing %d host(s) for live web services …", len(hosts))
	start := time.Now()
	args := []string{
		"-l", inFile, "-json", "-o", outFile, "-silent",
		"-title", "-tech-detect", "-status-code", "-web-server",
	}
	cmd := exec.CommandContext(ctx, "httpx", args...)
	if err := runStreaming(cmd, "httpx", false, true); err != nil {
		ws.FinishRun(run, "failed", 0, 0, 0)
		return nil, fmt.Errorf("httpx failed after %s: %w", fmtElapsed(start), err)
	}

	services, err := parsers.ParseHttpxJSONL(outFile)
	if err != nil && !os.IsNotExist(err) {
		ws.FinishRun(run, "failed", 0, 0, 0)
		return nil, err
	}

	newCount := 0
	var webTargets []string
	for _, s := range services {
		service := s.Scheme
		if service == "" {
			service = "http"
		}
		isNew, err := ws.UpsertAsset(&store.Asset{
			Host: s.Host, Port: s.Port, Protocol: "tcp", Service: service,
			SourceTool: "httpx", Scheme: s.Scheme, StatusCode: s.StatusCode,
			Title: s.Title, Webserver: s.Webserver, Tech: s.Tech,
		})
		if err != nil {
			return nil, err
		}
		if isNew {
			newCount++
		}
		webTargets = append(webTargets, s.URL)
	}
	ws.FinishRun(run, "completed", newCount, 0, 0)
	banner("[+] httpx: done in %s — %d live web service(s), %d new", fmtElapsed(start), len(services), newCount)
	return uniqueStrings(webTargets), nil
}

// RunNaabu fast-scans hosts for open ports and records them as assets, widening
// coverage to ports on subdomains that a target-only nmap run would miss.
func RunNaabu(ws *store.Workspace, hosts []string, allPorts bool, timeout time.Duration) (int, error) {
	if len(hosts) == 0 {
		return 0, nil
	}
	if !toolAvailable("naabu") {
		return 0, fmt.Errorf("naabu not found on PATH (install from github.com/projectdiscovery/naabu, or pass --skip-naabu)")
	}
	run := ws.StartRun("naabu", fmt.Sprintf("%d host(s)", len(hosts)))

	inFile := filepath.Join(os.TempDir(), fmt.Sprintf("naabu-in-%d.txt", time.Now().UnixNano()))
	if err := os.WriteFile(inFile, []byte(strings.Join(hosts, "\n")), 0o644); err != nil {
		ws.FinishRun(run, "failed", 0, 0, 0)
		return 0, err
	}
	defer os.Remove(inFile)
	outFile := filepath.Join(os.TempDir(), fmt.Sprintf("naabu-%d.jsonl", time.Now().UnixNano()))
	defer os.Remove(outFile)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	banner("[*] naabu: port-scanning %d host(s) …", len(hosts))
	start := time.Now()
	naabuArgs := []string{"-list", inFile, "-json", "-o", outFile, "-silent"}
	if allPorts {
		naabuArgs = append(naabuArgs, "-p", "-") // all 65535 ports
	}
	cmd := exec.CommandContext(ctx, "naabu", naabuArgs...)
	if err := runStreaming(cmd, "naabu", false, true); err != nil {
		ws.FinishRun(run, "failed", 0, 0, 0)
		return 0, fmt.Errorf("naabu failed after %s: %w", fmtElapsed(start), err)
	}

	ports, err := parsers.ParseNaabuJSONL(outFile)
	if err != nil && !os.IsNotExist(err) {
		ws.FinishRun(run, "failed", 0, 0, 0)
		return 0, err
	}

	newCount := 0
	for _, p := range ports {
		isNew, err := ws.UpsertAsset(&store.Asset{
			Host: p.Host, Port: p.Port, Protocol: "tcp", SourceTool: "naabu",
		})
		if err != nil {
			return newCount, err
		}
		if isNew {
			newCount++
		}
	}
	ws.FinishRun(run, "completed", newCount, 0, 0)
	banner("[+] naabu: done in %s — %d open port(s), %d new", fmtElapsed(start), len(ports), newCount)
	return newCount, nil
}

// RunKatana crawls the web targets for linked endpoints and records them as
// paths. Its URLs (especially those with query parameters) are the raw material
// for later injection testing (XSS/SQLi).
func RunKatana(ws *store.Workspace, webTargets []string, target string, hosts []string, timeout time.Duration) (int, error) {
	if len(webTargets) == 0 {
		return 0, nil
	}
	if !toolAvailable("katana") {
		return 0, fmt.Errorf("katana not found on PATH (install from github.com/projectdiscovery/katana, or pass --skip-katana)")
	}
	run := ws.StartRun("katana", fmt.Sprintf("%d target(s)", len(webTargets)))

	inFile := filepath.Join(os.TempDir(), fmt.Sprintf("katana-in-%d.txt", time.Now().UnixNano()))
	if err := os.WriteFile(inFile, []byte(strings.Join(webTargets, "\n")), 0o644); err != nil {
		ws.FinishRun(run, "failed", 0, 0, 0)
		return 0, err
	}
	defer os.Remove(inFile)
	outFile := filepath.Join(os.TempDir(), fmt.Sprintf("katana-%d.txt", time.Now().UnixNano()))
	defer os.Remove(outFile)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	banner("[*] katana: crawling %d web target(s) …", len(webTargets))
	start := time.Now()
	cmd := exec.CommandContext(ctx, "katana", "-list", inFile, "-silent", "-o", outFile)
	if err := runStreaming(cmd, "katana", false, true); err != nil {
		ws.FinishRun(run, "failed", 0, 0, 0)
		return 0, fmt.Errorf("katana failed after %s: %w", fmtElapsed(start), err)
	}

	endpoints, err := parsers.ParseKatanaLines(outFile)
	if err != nil && !os.IsNotExist(err) {
		ws.FinishRun(run, "failed", 0, 0, 0)
		return 0, err
	}

	// Only keep endpoints on in-scope hosts — katana follows links to CDNs,
	// social media and other third parties, which are just noise in the report
	// (and out of scope for anything active).
	inScope := scopeMatcher(target, hosts)
	newCount, kept, external := 0, 0, 0
	for _, e := range endpoints {
		if !inScope(e.Host) {
			external++
			continue
		}
		kept++
		isNew, err := ws.UpsertPath(&store.WebPath{
			Host: e.Host, URL: e.URL, SourceTool: "katana",
		})
		if err != nil {
			return newCount, err
		}
		if isNew {
			newCount++
		}
	}
	ws.FinishRun(run, "completed", 0, 0, newCount)
	msg := fmt.Sprintf("[+] katana: done in %s — %d in-scope endpoint(s), %d new", fmtElapsed(start), kept, newCount)
	if external > 0 {
		msg += fmt.Sprintf(" (%d external skipped)", external)
	}
	banner(msg)
	return newCount, nil
}

// upsertFindings stores parser findings under the given source tool and returns
// how many were newly discovered. Shared by the injection-testing stages.
func upsertFindings(ws *store.Workspace, findings []parsers.ParsedFinding, sourceTool string) (int, error) {
	newCount := 0
	for _, f := range findings {
		isNew, err := ws.UpsertFinding(&store.Finding{
			Host: f.Host, Port: f.Port, TemplateID: f.TemplateID,
			Name: f.Name, Severity: f.Severity, MatchedAt: f.MatchedAt,
			SourceTool:  sourceTool,
			Description: f.Description, Remediation: f.Remediation,
			References: f.References, Tags: f.Tags,
			CVEIDs: f.CVEIDs, CVSSScore: f.CVSSScore, CVSSMetrics: f.CVSSMetrics,
			CURLCommand: f.CURLCommand, ExtractedResults: f.ExtractedResults, Raw: f.Raw,
		})
		if err != nil {
			return newCount, err
		}
		if isNew {
			newCount++
		}
	}
	return newCount, nil
}

// RunDalfox tests parameterized URLs for XSS with dalfox and records findings.
func RunDalfox(ws *store.Workspace, urls []string, timeout time.Duration) (int, error) {
	if len(urls) == 0 {
		return 0, nil
	}
	if !toolAvailable("dalfox") {
		return 0, fmt.Errorf("dalfox not found on PATH (install from github.com/hahwul/dalfox, or pass --skip-dalfox)")
	}
	run := ws.StartRun("dalfox", fmt.Sprintf("%d URL(s)", len(urls)))

	inFile := filepath.Join(os.TempDir(), fmt.Sprintf("dalfox-in-%d.txt", time.Now().UnixNano()))
	if err := os.WriteFile(inFile, []byte(strings.Join(urls, "\n")), 0o644); err != nil {
		ws.FinishRun(run, "failed", 0, 0, 0)
		return 0, err
	}
	defer os.Remove(inFile)
	outFile := filepath.Join(os.TempDir(), fmt.Sprintf("dalfox-%d.json", time.Now().UnixNano()))
	defer os.Remove(outFile)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	banner("[*] dalfox: testing %d parameterized URL(s) for XSS …", len(urls))
	start := time.Now()
	cmd := exec.CommandContext(ctx, "dalfox", "file", inFile, "--format", "json", "-o", outFile, "--silence")
	if err := runStreaming(cmd, "dalfox", false, true); err != nil {
		ws.FinishRun(run, "failed", 0, 0, 0)
		return 0, fmt.Errorf("dalfox failed after %s: %w", fmtElapsed(start), err)
	}

	findings, err := parsers.ParseDalfoxJSON(outFile)
	if err != nil && !os.IsNotExist(err) {
		ws.FinishRun(run, "failed", 0, 0, 0)
		return 0, err
	}
	newCount, err := upsertFindings(ws, findings, "dalfox")
	if err != nil {
		return newCount, err
	}
	ws.FinishRun(run, "completed", 0, newCount, 0)
	banner("[+] dalfox: done in %s — %d XSS finding(s), %d new", fmtElapsed(start), len(findings), newCount)
	return newCount, nil
}

// RunCrlfuzz tests parameterized URLs for CRLF injection with crlfuzz.
func RunCrlfuzz(ws *store.Workspace, urls []string, timeout time.Duration) (int, error) {
	if len(urls) == 0 {
		return 0, nil
	}
	if !toolAvailable("crlfuzz") {
		return 0, fmt.Errorf("crlfuzz not found on PATH (install from github.com/dwisiswant0/crlfuzz, or pass --skip-crlfuzz)")
	}
	run := ws.StartRun("crlfuzz", fmt.Sprintf("%d URL(s)", len(urls)))

	inFile := filepath.Join(os.TempDir(), fmt.Sprintf("crlfuzz-in-%d.txt", time.Now().UnixNano()))
	if err := os.WriteFile(inFile, []byte(strings.Join(urls, "\n")), 0o644); err != nil {
		ws.FinishRun(run, "failed", 0, 0, 0)
		return 0, err
	}
	defer os.Remove(inFile)
	outFile := filepath.Join(os.TempDir(), fmt.Sprintf("crlfuzz-%d.txt", time.Now().UnixNano()))
	defer os.Remove(outFile)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	banner("[*] crlfuzz: testing %d parameterized URL(s) for CRLF injection …", len(urls))
	start := time.Now()
	cmd := exec.CommandContext(ctx, "crlfuzz", "-l", inFile, "-s", "-o", outFile)
	if err := runStreaming(cmd, "crlfuzz", false, true); err != nil {
		ws.FinishRun(run, "failed", 0, 0, 0)
		return 0, fmt.Errorf("crlfuzz failed after %s: %w", fmtElapsed(start), err)
	}

	vulnURLs, err := parsers.ParseLines(outFile)
	if err != nil && !os.IsNotExist(err) {
		ws.FinishRun(run, "failed", 0, 0, 0)
		return 0, err
	}
	var findings []parsers.ParsedFinding
	for _, u := range vulnURLs {
		_, host, port := parsers.URLParts(u)
		findings = append(findings, parsers.ParsedFinding{
			Host: host, Port: port, TemplateID: "crlfuzz-crlf",
			Name: "CRLF Injection", Severity: "medium", MatchedAt: u,
			Description: "The response headers can be split via CRLF sequences in a parameter, enabling header injection / response splitting.",
			Remediation: "Strip CR/LF characters from user input used in HTTP headers or redirects.",
			Tags:        []string{"crlf", "crlfuzz"}, CURLCommand: "curl -i '" + u + "'",
		})
	}
	newCount, err := upsertFindings(ws, findings, "crlfuzz")
	if err != nil {
		return newCount, err
	}
	ws.FinishRun(run, "completed", 0, newCount, 0)
	banner("[+] crlfuzz: done in %s — %d CRLF finding(s), %d new", fmtElapsed(start), len(findings), newCount)
	return newCount, nil
}

// RunSqlmap tests parameterized URLs for SQL injection with sqlmap. This is
// opt-in (active exploitation), runs each URL in --batch mode, and is capped at
// maxURLs so it can't run away on a large crawl.
func RunSqlmap(ws *store.Workspace, urls []string, maxURLs int, timeout time.Duration) (int, error) {
	if len(urls) == 0 {
		return 0, nil
	}
	if !toolAvailable("sqlmap") {
		return 0, fmt.Errorf("sqlmap not found on PATH (install it, or drop --sqli)")
	}
	if maxURLs > 0 && len(urls) > maxURLs {
		urls = urls[:maxURLs]
	}

	banner("[*] sqlmap: testing %d URL(s) for SQLi (opt-in, active) …", len(urls))
	start := time.Now()
	newCount := 0
	for _, u := range urls {
		run := ws.StartRun("sqlmap", u)
		banner("      sqlmap → %s", u)

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		out, _ := exec.CommandContext(ctx, "sqlmap", "-u", u, "--batch", "--disable-coloring").CombinedOutput()
		cancel()

		detail, injectable := parsers.ParseSqlmapOutput(string(out))
		if !injectable {
			ws.FinishRun(run, "completed", 0, 0, 0)
			continue
		}
		host := u
		if pu, err := url.Parse(u); err == nil && pu.Hostname() != "" {
			host = pu.Hostname()
		}
		isNew, err := ws.UpsertFinding(&store.Finding{
			Host: host, TemplateID: "sqlmap-sqli", Name: "SQL Injection",
			Severity: "critical", MatchedAt: u, SourceTool: "sqlmap",
			Description: detail,
			Remediation: "Use parameterized queries / prepared statements; never build SQL from raw input. Apply least-privilege DB accounts.",
			Tags:        []string{"sqli", "sqlmap"},
			CURLCommand: "sqlmap -u '" + u + "' --batch",
		})
		if err != nil {
			return newCount, err
		}
		if isNew {
			newCount++
		}
		ws.FinishRun(run, "completed", 0, 1, 0)
	}
	banner("[+] sqlmap: done in %s — %d injectable URL(s)", fmtElapsed(start), newCount)
	return newCount, nil
}

// WebTargetsFromAssets builds http(s)://host:port URLs for web-looking services.
func WebTargetsFromAssets(assets []parsers.ParsedAsset) []string {
	var urls []string
	for _, a := range assets {
		isWeb := webServiceNames[strings.ToLower(a.Service)] ||
			a.Port == 80 || a.Port == 443 || a.Port == 8080 || a.Port == 8443
		if !isWeb {
			continue
		}
		scheme := "http"
		if strings.Contains(strings.ToLower(a.Service), "ssl") || a.Port == 443 || a.Port == 8443 {
			scheme = "https"
		}
		urls = append(urls, fmt.Sprintf("%s://%s:%d", scheme, a.Host, a.Port))
	}
	return urls
}

// RunNuclei shells out to nuclei against all web targets at once (nuclei
// handles its own internal concurrency across the target list).
func RunNuclei(ws *store.Workspace, webTargets []string, extraArgs []string, timeout time.Duration) ([]parsers.ParsedFinding, error) {
	if len(webTargets) == 0 {
		return nil, nil
	}
	if !toolAvailable("nuclei") {
		return nil, fmt.Errorf("nuclei not found on PATH (install from github.com/projectdiscovery/nuclei, or pass --skip-nuclei)")
	}

	run := ws.StartRun("nuclei", strings.Join(webTargets, ", "))

	targetsFile := filepath.Join(os.TempDir(), fmt.Sprintf("nuclei-targets-%d.txt", time.Now().UnixNano()))
	if err := os.WriteFile(targetsFile, []byte(strings.Join(webTargets, "\n")), 0o644); err != nil {
		ws.FinishRun(run, "failed", 0, 0, 0)
		return nil, err
	}
	defer os.Remove(targetsFile)

	jsonlOut := filepath.Join(os.TempDir(), fmt.Sprintf("nuclei-%d.jsonl", time.Now().UnixNano()))
	defer os.Remove(jsonlOut)

	// -stats makes nuclei print a periodic progress line (requests done / total
	// and percentage) to stderr, which is exactly the "when will this finish"
	// signal the run was missing before.
	args := append([]string{"-l", targetsFile, "-jsonl", "-o", jsonlOut, "-stats"}, extraArgs...)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	banner("[*] nuclei: testing %d web target(s) …", len(webTargets))
	start := time.Now()
	cmd := exec.CommandContext(ctx, "nuclei", args...)
	// Mute nuclei's stdout — it just echoes the JSONL we already save to file;
	// the useful [INF]/stats progress comes on stderr.
	if err := runStreaming(cmd, "nuclei", false, true); err != nil {
		ws.FinishRun(run, "failed", 0, 0, 0)
		return nil, fmt.Errorf("nuclei failed after %s: %w", fmtElapsed(start), err)
	}

	findings, err := parsers.ParseNucleiJSONL(jsonlOut)
	if err != nil && !os.IsNotExist(err) {
		ws.FinishRun(run, "failed", 0, 0, 0)
		return nil, err
	}

	newCount := 0
	for _, f := range findings {
		isNew, err := ws.UpsertFinding(&store.Finding{
			Host: f.Host, Port: f.Port, TemplateID: f.TemplateID,
			Name: f.Name, Severity: f.Severity, MatchedAt: f.MatchedAt,
			SourceTool:  "nuclei",
			Description: f.Description, Remediation: f.Remediation,
			References: f.References, Tags: f.Tags,
			CVEIDs: f.CVEIDs, CVSSScore: f.CVSSScore, CVSSMetrics: f.CVSSMetrics,
			CURLCommand: f.CURLCommand, ExtractedResults: f.ExtractedResults,
			Raw: f.Raw,
		})
		if err != nil {
			return nil, err
		}
		if isNew {
			newCount++
		}
	}
	ws.FinishRun(run, "completed", 0, newCount, 0)
	banner("[+] nuclei: done in %s — %d finding(s), %d new", fmtElapsed(start), len(findings), newCount)
	return findings, nil
}

// ffufJobResult carries one target's outcome back through the results channel.
type ffufJobResult struct {
	target string
	paths  []parsers.ParsedPath
	err    error
}

// RunFfufConcurrent fuzzes every web target in parallel, bounded by maxWorkers,
// so a batch costs roughly one target's wall-clock time rather than the sum.
func RunFfufConcurrent(ws *store.Workspace, webTargets []string, wordlist string, maxWorkers int, timeout time.Duration) ([]parsers.ParsedPath, error) {
	if len(webTargets) == 0 {
		return nil, nil
	}
	if !toolAvailable("ffuf") {
		return nil, fmt.Errorf("ffuf not found on PATH (install it, or pass --skip-ffuf)")
	}
	if _, err := os.Stat(wordlist); err != nil {
		return nil, fmt.Errorf("wordlist not found: %s", wordlist)
	}

	total := len(webTargets)
	banner("[*] ffuf: fuzzing %d web target(s) with %d worker(s) …", total, maxWorkers)
	start := time.Now()

	sem := make(chan struct{}, maxWorkers)
	results := make(chan ffufJobResult, total)
	var wg sync.WaitGroup
	var completed atomic.Int64

	// A single heartbeat renders aggregate progress for the whole ffuf stage.
	// We can't stream each ffuf's own \r progress bar cleanly when several run
	// at once, so instead we report "N/total targets done" every few seconds.
	hb := startHeartbeat(10*time.Second, func(e string) string {
		return fmt.Sprintf("ffuf: %d/%d targets done (%s elapsed)", completed.Load(), total, e)
	})

	for _, target := range webTargets {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			paths, err := runFfufOne(ws, target, wordlist, timeout)
			completed.Add(1)
			results <- ffufJobResult{target: target, paths: paths, err: err}
		}(target)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var all []parsers.ParsedPath
	var firstErr error
	for r := range results {
		if r.err != nil {
			// Don't abort the whole batch if one target fails - just note it.
			if firstErr == nil {
				firstErr = fmt.Errorf("ffuf against %s failed: %w", r.target, r.err)
			}
			continue
		}
		all = append(all, r.paths...)
	}
	hb.Stop()
	banner("[+] ffuf: done in %s — %d path(s) across %d target(s)", fmtElapsed(start), len(all), total)
	return all, firstErr
}

func runFfufOne(ws *store.Workspace, target, wordlist string, timeout time.Duration) ([]parsers.ParsedPath, error) {
	run := ws.StartRun("ffuf", target)

	jsonOut := filepath.Join(os.TempDir(), fmt.Sprintf("ffuf-%d-%s.json", time.Now().UnixNano(), sanitize(target)))
	defer os.Remove(jsonOut)

	url := strings.TrimRight(target, "/") + "/FUZZ"
	args := []string{
		"-u", url, "-w", wordlist, "-of", "json", "-o", jsonOut,
		"-mc", "200,204,301,302,307,401,403",
		// -ac auto-calibrates against wildcard/catch-all responses, so a host
		// that returns 200 for every path doesn't flood the report with noise.
		"-ac",
		// -s silences ffuf's own \r progress bar; several targets fuzzing at
		// once would garble it. The stage heartbeat reports progress instead.
		"-s",
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	host := hostLabel(target)
	banner("      ffuf → %s starting", host)
	start := time.Now()
	cmd := exec.CommandContext(ctx, "ffuf", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		ws.FinishRun(run, "failed", 0, 0, 0)
		return nil, fmt.Errorf("%w\n%s", err, out)
	}

	paths, err := parsers.ParseFfufJSON(jsonOut)
	if err != nil {
		ws.FinishRun(run, "failed", 0, 0, 0)
		return nil, err
	}

	newCount := 0
	for _, p := range paths {
		isNew, err := ws.UpsertPath(&store.WebPath{
			Host: p.Host, URL: p.URL, StatusCode: p.StatusCode, Length: p.Length,
			SourceTool: "ffuf",
		})
		if err != nil {
			return nil, err
		}
		if isNew {
			newCount++
		}
	}
	ws.FinishRun(run, "completed", 0, 0, newCount)
	banner("      ffuf ✓ %s — %d path(s), %d new (%s)", host, len(paths), newCount, fmtElapsed(start))
	return paths, nil
}

// hostLabel strips the scheme from a web target URL for compact display in
// progress lines (https://demo.local:443 -> demo.local:443).
func hostLabel(target string) string {
	if i := strings.Index(target, "://"); i != -1 {
		return target[i+3:]
	}
	return target
}

func sanitize(s string) string {
	replacer := strings.NewReplacer("/", "_", ":", "_", "\\", "_")
	return replacer.Replace(s)
}

// Summary is returned by FullChain for the CLI to print.
type Summary struct {
	SubdomainsFound int
	AssetsFound     int
	WebTargets      []string
	FindingsFound   int
	PathsFound      int
	// Warnings holds non-fatal problems (e.g. nuclei failing, or some ffuf
	// targets erroring) that didn't stop the rest of the scan from completing.
	Warnings []string
	Elapsed  time.Duration
}

type ChainOptions struct {
	Wordlist      string
	SkipSubfinder bool
	SkipNaabu     bool
	SkipHttpx     bool
	SkipNmap      bool
	NmapXML       string
	SkipNuclei    bool
	SkipFfuf      bool
	SkipKatana    bool
	SkipDalfox    bool
	SkipCrlfuzz   bool
	SQLi          bool // opt-in: sqlmap actively tests for SQL injection
	SQLiMax       int  // cap on URLs handed to sqlmap
	FullPorts     bool // scan all 65535 ports (naabu + nmap), not just the top ports
	MaxWorkers    int
	Timeout       time.Duration
}

// FullChain runs subfinder -> httpx -> nmap -> nuclei -> ffuf, respecting
// whichever stages the caller wants to skip, and returns a summary for the CLI.
//
// subfinder widens a domain into its subdomains; httpx probes every host for
// live HTTP(S) and is the authoritative web-target source; nmap adds
// service/version depth on the primary target; nuclei and ffuf then run against
// the confirmed web targets. Discovery-tool failures are non-fatal warnings.
func FullChain(ws *store.Workspace, target string, opts ChainOptions) (*Summary, error) {
	chainStart := time.Now()
	var warnings []string
	var err error

	// 1. subfinder: expand a domain into its subdomains.
	hosts := []string{target}
	if !opts.SkipSubfinder && looksLikeDomain(target) {
		subs, sErr := RunSubfinder(ws, target, opts.Timeout)
		if sErr != nil {
			warnings = append(warnings, sErr.Error())
			banner("[!] subfinder: %v", sErr)
		}
		hosts = append(hosts, subs...)
	}
	hosts = uniqueStrings(hosts)

	// 2. naabu: fast port sweep across every host (breadth nmap-on-target misses).
	if !opts.SkipNaabu {
		if _, nErr := RunNaabu(ws, hosts, opts.FullPorts, opts.Timeout); nErr != nil {
			warnings = append(warnings, nErr.Error())
			banner("[!] naabu: %v", nErr)
		}
	}

	// 3. httpx: probe every host for live HTTP(S) + metadata (authoritative
	//    web-target list when enabled).
	var webTargets []string
	if !opts.SkipHttpx {
		wt, hErr := RunHttpx(ws, hosts, opts.Timeout)
		if hErr != nil {
			warnings = append(warnings, hErr.Error())
			banner("[!] httpx: %v", hErr)
		}
		webTargets = wt
	}

	// 4. nmap: service/version depth on the primary target.
	var assets []parsers.ParsedAsset
	if opts.SkipNmap {
		if opts.NmapXML != "" {
			assets, err = IngestNmapXML(ws, opts.NmapXML, target)
		}
	} else {
		var nmapArgs []string
		if opts.FullPorts {
			nmapArgs = []string{"-p-"}
		}
		assets, err = RunNmap(ws, target, nmapArgs, opts.Timeout)
	}
	if err != nil {
		return nil, err
	}

	// Fall back to nmap's web heuristic only if httpx wasn't run or found nothing.
	if len(webTargets) == 0 {
		webTargets = WebTargetsFromAssets(assets)
	}
	if len(webTargets) == 0 && (!opts.SkipNuclei || !opts.SkipFfuf) {
		banner("[*] No web services found — nothing for nuclei/ffuf to test")
	}

	// 5. nuclei: vulnerability templates against the confirmed web targets.
	if !opts.SkipNuclei {
		if _, nErr := RunNuclei(ws, webTargets, nil, opts.Timeout); nErr != nil {
			// A nuclei failure shouldn't throw away data we already stored or
			// block later stages — record it and carry on.
			warnings = append(warnings, nErr.Error())
			banner("[!] nuclei: %v", nErr)
		}
	}
	// 6. ffuf: content discovery on the web targets.
	if !opts.SkipFfuf {
		if opts.Wordlist == "" {
			return nil, fmt.Errorf("ffuf requires --wordlist unless --skip-ffuf is set")
		}
		workers := opts.MaxWorkers
		if workers <= 0 {
			workers = 5
		}
		if _, fErr := RunFfufConcurrent(ws, webTargets, opts.Wordlist, workers, opts.Timeout); fErr != nil {
			warnings = append(warnings, fErr.Error())
			banner("[!] ffuf: %v", fErr)
		}
	}
	// 7. katana: crawl the web targets for linked endpoints.
	if !opts.SkipKatana {
		if _, kErr := RunKatana(ws, webTargets, target, hosts, opts.Timeout); kErr != nil {
			warnings = append(warnings, kErr.Error())
			banner("[!] katana: %v", kErr)
		}
	}

	// 8. injection testing on the parameterized URLs the crawl turned up —
	//    scoped to the target and its subdomains. dalfox/sqlmap/crlfuzz fire
	//    active payloads, so we must never hand them a third-party host katana
	//    happened to link to: that's out of scope AND a waste of time.
	allParamURLs := ws.ParamURLs()
	scoped := inScopeURLs(allParamURLs, target, hosts)
	paramURLs := dedupeParamURLs(scoped)
	if len(allParamURLs) > 0 {
		banner("[*] injection: %d param URL(s) discovered → %d in scope → %d unique to test",
			len(allParamURLs), len(scoped), len(paramURLs))
	}
	if len(paramURLs) > 0 {
		if !opts.SkipDalfox {
			if _, dErr := RunDalfox(ws, paramURLs, opts.Timeout); dErr != nil {
				warnings = append(warnings, dErr.Error())
				banner("[!] dalfox: %v", dErr)
			}
		}
		if !opts.SkipCrlfuzz {
			if _, cErr := RunCrlfuzz(ws, paramURLs, opts.Timeout); cErr != nil {
				warnings = append(warnings, cErr.Error())
				banner("[!] crlfuzz: %v", cErr)
			}
		}
		if opts.SQLi {
			if _, sErr := RunSqlmap(ws, paramURLs, opts.SQLiMax, opts.Timeout); sErr != nil {
				warnings = append(warnings, sErr.Error())
				banner("[!] sqlmap: %v", sErr)
			}
		}
	} else if (!opts.SkipDalfox || !opts.SkipCrlfuzz || opts.SQLi) && !opts.SkipKatana {
		banner("[*] No parameterized URLs discovered — nothing to injection-test")
	}

	return &Summary{
		SubdomainsFound: len(ws.AllSubdomains()),
		AssetsFound:     len(ws.AllAssets()),
		WebTargets:      webTargets,
		FindingsFound:   len(ws.AllFindings()),
		PathsFound:      len(ws.AllPaths()),
		Warnings:        warnings,
		Elapsed:         time.Since(chainStart),
	}, nil
}

// looksLikeDomain reports whether target is a DNS name subfinder can enumerate
// (i.e. not an IP address and containing a dot).
func looksLikeDomain(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" || net.ParseIP(target) != nil {
		return false
	}
	return strings.Contains(target, ".")
}

// uniqueStrings de-duplicates while preserving first-seen order.
func uniqueStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// dedupeParamURLs collapses URLs that share the same injectable surface —
// same host, path and set of parameter NAMES — keeping one representative each.
// Injection testers mutate parameter values, so `/s?q=1` and `/s?q=2` exercise
// the identical test; only distinct (path, param-name-set) tuples add coverage.
// Unparseable URLs are kept as-is rather than dropped.
func dedupeParamURLs(urls []string) []string {
	seen := make(map[string]bool, len(urls))
	var out []string
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			out = append(out, raw)
			continue
		}
		names := make([]string, 0)
		for k := range u.Query() {
			names = append(names, k)
		}
		sort.Strings(names)
		sig := strings.ToLower(u.Host) + "|" + u.Path + "|" + strings.Join(names, ",")
		if seen[sig] {
			continue
		}
		seen[sig] = true
		out = append(out, raw)
	}
	return out
}

// scopeMatcher returns a predicate reporting whether a host is in scope: the
// target itself, one of the enumerated hosts, or a subdomain of the target.
func scopeMatcher(target string, hosts []string) func(host string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	suffix := "." + target
	inHosts := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		inHosts[strings.ToLower(h)] = true
	}
	return func(host string) bool {
		host = strings.ToLower(host)
		return host == target || inHosts[host] || strings.HasSuffix(host, suffix)
	}
}

// inScopeURLs keeps only URLs whose host is in scope. Used to gate the injection
// stage so active payloads never reach a third-party host katana linked to.
func inScopeURLs(urls []string, target string, hosts []string) []string {
	inScope := scopeMatcher(target, hosts)
	var out []string
	for _, u := range urls {
		if _, host, _ := parsers.URLParts(u); inScope(host) {
			out = append(out, u)
		}
	}
	return out
}
