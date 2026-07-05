// Package parsers turns raw tool output (nmap XML, the ProjectDiscovery tools'
// JSON/JSONL, dalfox, sqlmap, and plain URL/host lists) into plain structs.
// Stdlib only.
package parsers

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"os"
	"strconv"
	"strings"
)

// ---------- Nmap ----------

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddress `xml:"address"`
	Hostnames nmapHostnames `xml:"hostnames"`
	Ports     nmapPorts     `xml:"ports"`
}

type nmapAddress struct {
	Addr string `xml:"addr,attr"`
}

type nmapHostnames struct {
	Hostname []nmapHostname `xml:"hostname"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
}

type nmapPorts struct {
	Port []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   string      `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

// ParsedAsset is the parser's plain output for one open port.
type ParsedAsset struct {
	Host     string
	Port     int
	Protocol string
	Service  string
	Product  string
	Version  string
}

// ParseNmapXML reads an Nmap -oX file and returns one ParsedAsset per open port.
func ParseNmapXML(path string) ([]ParsedAsset, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, err
	}

	var assets []ParsedAsset
	for _, h := range run.Hosts {
		if len(h.Addresses) == 0 {
			continue
		}
		host := h.Addresses[0].Addr
		if len(h.Hostnames.Hostname) > 0 && h.Hostnames.Hostname[0].Name != "" {
			host = h.Hostnames.Hostname[0].Name
		}

		for _, p := range h.Ports.Port {
			if p.State.State != "open" {
				continue
			}
			portNum, err := strconv.Atoi(p.PortID)
			if err != nil {
				continue
			}
			assets = append(assets, ParsedAsset{
				Host:     host,
				Port:     portNum,
				Protocol: p.Protocol,
				Service:  p.Service.Name,
				Product:  p.Service.Product,
				Version:  p.Service.Version,
			})
		}
	}
	return assets, nil
}

// ---------- Nuclei ----------

type nucleiLine struct {
	TemplateID       string     `json:"template-id"`
	Host             string     `json:"host"`
	Port             string     `json:"port"`
	MatchedAt        string     `json:"matched-at"`
	CURLCommand      string     `json:"curl-command"`
	ExtractedResults []string   `json:"extracted-results"`
	Info             nucleiInfo `json:"info"`
}

type nucleiInfo struct {
	Name           string          `json:"name"`
	Severity       string          `json:"severity"`
	Description    string          `json:"description"`
	Remediation    string          `json:"remediation"`
	Reference      json.RawMessage `json:"reference"`      // []string | string | null
	Tags           json.RawMessage `json:"tags"`           // []string | "a,b" | null
	Classification *nucleiClass    `json:"classification"` // may be absent
}

type nucleiClass struct {
	CVEID       json.RawMessage `json:"cve-id"` // []string | string
	CVSSMetrics string          `json:"cvss-metrics"`
	CVSSScore   float64         `json:"cvss-score"`
}

// ParsedFinding is the parser's plain output for one Nuclei match. Beyond the
// bare name/severity, it carries the context nuclei already ships in each
// template — description, remediation, CVE/CVSS, references, and a
// reproduction curl command — so the report can tell you what to DO about a
// finding, not just that it exists.
type ParsedFinding struct {
	Host             string
	Port             int
	TemplateID       string
	Name             string
	Severity         string
	MatchedAt        string
	Description      string
	Remediation      string
	References       []string
	Tags             []string
	CVEIDs           []string
	CVSSScore        float64
	CVSSMetrics      string
	CURLCommand      string
	ExtractedResults []string
	Raw              json.RawMessage
}

// ParseNucleiJSONL reads Nuclei's -jsonl output, one finding per line.
func ParseNucleiJSONL(path string) ([]ParsedFinding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []ParsedFinding
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024) // nuclei lines can be long
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var l nucleiLine
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			continue // skip malformed lines rather than aborting the whole parse
		}
		port, _ := strconv.Atoi(l.Port)
		name := l.Info.Name
		if name == "" {
			name = l.TemplateID
		}
		severity := l.Info.Severity
		if severity == "" {
			severity = "unknown"
		}
		pf := ParsedFinding{
			Host:             l.Host,
			Port:             port,
			TemplateID:       l.TemplateID,
			Name:             name,
			Severity:         severity,
			MatchedAt:        l.MatchedAt,
			Description:      strings.TrimSpace(l.Info.Description),
			Remediation:      strings.TrimSpace(l.Info.Remediation),
			References:       normList(l.Info.Reference, false),
			Tags:             normList(l.Info.Tags, true),
			CURLCommand:      strings.TrimSpace(l.CURLCommand),
			ExtractedResults: cleanStrings(l.ExtractedResults),
			Raw:              json.RawMessage(line),
		}
		if l.Info.Classification != nil {
			pf.CVEIDs = normList(l.Info.Classification.CVEID, false)
			pf.CVSSScore = l.Info.Classification.CVSSScore
			pf.CVSSMetrics = strings.TrimSpace(l.Info.Classification.CVSSMetrics)
		}
		findings = append(findings, pf)
	}
	return findings, scanner.Err()
}

// normList normalizes a nuclei JSON value that may be a []string, a single
// string, or null into a clean []string. When splitCommas is set, a single
// comma-separated string (how nuclei sometimes emits tags) is split apart.
func normList(raw json.RawMessage, splitCommas bool) []string {
	if len(raw) == 0 {
		return nil
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return cleanStrings(arr)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if s = strings.TrimSpace(s); s != "" {
			if splitCommas {
				return cleanStrings(strings.Split(s, ","))
			}
			return []string{s}
		}
	}
	return nil
}

// cleanStrings trims each element and drops the empties.
func cleanStrings(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ---------- ffuf ----------

type ffufOutput struct {
	Results []ffufResult `json:"results"`
}

type ffufResult struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Length int    `json:"length"`
}

// ParsedPath is the parser's plain output for one ffuf hit.
type ParsedPath struct {
	Host       string
	URL        string
	StatusCode int
	Length     int
}

// ParseFfufJSON reads ffuf's -of json output.
func ParseFfufJSON(path string) ([]ParsedPath, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out ffufOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}

	var paths []ParsedPath
	for _, r := range out.Results {
		host := r.URL
		if idx := strings.Index(r.URL, "://"); idx != -1 {
			rest := r.URL[idx+3:]
			if slash := strings.Index(rest, "/"); slash != -1 {
				host = rest[:slash]
			} else {
				host = rest
			}
			// strip port so it correlates with the same host key nmap/nuclei use
			if colon := strings.Index(host, ":"); colon != -1 {
				host = host[:colon]
			}
		}
		paths = append(paths, ParsedPath{
			Host:       host,
			URL:        r.URL,
			StatusCode: r.Status,
			Length:     r.Length,
		})
	}
	return paths, nil
}

// ---------- subfinder ----------

// ParseSubfinderLines reads subfinder's default (-silent) output: one hostname
// per line. It also tolerates JSON-lines output ({"host":"..."}) so it works
// whichever mode the caller ran. Duplicates and blanks are dropped.
func ParseSubfinderLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := map[string]bool{}
	var hosts []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		host := line
		if strings.HasPrefix(line, "{") {
			var j struct {
				Host string `json:"host"`
			}
			if err := json.Unmarshal([]byte(line), &j); err == nil && j.Host != "" {
				host = j.Host
			}
		}
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		hosts = append(hosts, host)
	}
	return hosts, scanner.Err()
}

// ---------- httpx ----------

type httpxLine struct {
	URL        string   `json:"url"`
	Input      string   `json:"input"`
	Host       string   `json:"host"`
	Port       any      `json:"port"` // httpx emits port as number or string across versions
	Scheme     string   `json:"scheme"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title"`
	Webserver  string   `json:"webserver"`
	Tech       []string `json:"tech"`
}

// ParsedWebService is one live HTTP(S) endpoint confirmed by httpx, with the
// metadata that makes the report useful (status, title, detected tech).
type ParsedWebService struct {
	URL        string
	Host       string
	Port       int
	Scheme     string
	StatusCode int
	Title      string
	Webserver  string
	Tech       []string
}

// ParseHttpxJSONL reads httpx's -json output, one probed URL per line.
func ParseHttpxJSONL(path string) ([]ParsedWebService, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []ParsedWebService
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 256*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var l httpxLine
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			continue // skip malformed lines rather than aborting
		}

		host := l.Host
		scheme := l.Scheme
		port := anyToInt(l.Port)
		// Backfill host/scheme/port from the URL when httpx didn't split them.
		if host == "" || scheme == "" || port == 0 {
			s, h, p := splitURL(l.URL)
			if scheme == "" {
				scheme = s
			}
			if host == "" {
				host = h
			}
			if port == 0 {
				port = p
			}
		}

		out = append(out, ParsedWebService{
			URL:        l.URL,
			Host:       strings.ToLower(host),
			Port:       port,
			Scheme:     scheme,
			StatusCode: l.StatusCode,
			Title:      strings.TrimSpace(l.Title),
			Webserver:  strings.TrimSpace(l.Webserver),
			Tech:       cleanStrings(l.Tech),
		})
	}
	return out, scanner.Err()
}

// ---------- naabu ----------

type naabuLine struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// ParsedPort is one open port found by naabu.
type ParsedPort struct {
	Host string
	Port int
}

// ParseNaabuJSONL reads naabu's -json output, one open port per line. It falls
// back to the IP when naabu didn't echo the input hostname.
func ParseNaabuJSONL(path string) ([]ParsedPort, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []ParsedPort
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var l naabuLine
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			continue
		}
		host := l.Host
		if host == "" {
			host = l.IP
		}
		if host == "" || l.Port == 0 {
			continue
		}
		out = append(out, ParsedPort{Host: strings.ToLower(host), Port: l.Port})
	}
	return out, scanner.Err()
}

// ---------- katana ----------

// ParseKatanaLines reads katana's default (-silent) output: one crawled URL per
// line. The host is normalized (scheme and port stripped) so crawled endpoints
// correlate to the same host key the other tools use.
func ParseKatanaLines(path string) ([]ParsedPath, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := map[string]bool{}
	var out []ParsedPath
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 256*1024), 4*1024*1024)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url == "" || seen[url] {
			continue
		}
		seen[url] = true
		_, host, _ := splitURL(url)
		out = append(out, ParsedPath{Host: strings.ToLower(host), URL: url})
	}
	return out, scanner.Err()
}

// ParseLines reads a file into a slice of trimmed, de-duplicated, non-empty
// lines. Used for tools (like crlfuzz) whose output is just one URL per line.
func ParseLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := map[string]bool{}
	var out []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 256*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}
	return out, scanner.Err()
}

// URLParts is the exported form of splitURL: scheme, host and port from a URL.
func URLParts(raw string) (scheme, host string, port int) {
	return splitURL(raw)
}

// ---------- dalfox (XSS) ----------

type dalfoxPoC struct {
	Type       string `json:"type"`        // V (verified) / R (reflected) / G (grep)
	InjectType string `json:"inject_type"` // e.g. inHTML-URL
	Method     string `json:"method"`
	Data       string `json:"data"` // the PoC URL carrying the payload
	Param      string `json:"param"`
	Payload    string `json:"payload"`
	Evidence   string `json:"evidence"`
	CWE        string `json:"cwe"`
	Severity   string `json:"severity"`
	MessageStr string `json:"message_str"`
}

// ParseDalfoxJSON reads dalfox's --format json output (a JSON array or JSON
// lines of PoC objects) and turns each into a finding.
func ParseDalfoxJSON(path string) ([]ParsedFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, nil
	}

	var pocs []dalfoxPoC
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal([]byte(trimmed), &pocs); err != nil {
			return nil, err
		}
	} else {
		// JSON lines fallback.
		for _, line := range strings.Split(trimmed, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var p dalfoxPoC
			if err := json.Unmarshal([]byte(line), &p); err == nil {
				pocs = append(pocs, p)
			}
		}
	}

	var out []ParsedFinding
	for _, p := range pocs {
		if strings.TrimSpace(p.Data) == "" {
			continue // no location to act on / report — skip it
		}
		_, host, port := splitURL(p.Data)
		sev := strings.ToLower(strings.TrimSpace(p.Severity))
		if sev == "" {
			sev = dalfoxSeverity(p.Type)
		}
		name := "Cross-Site Scripting (XSS)"
		if p.InjectType != "" {
			name = "XSS: " + p.InjectType
		}
		desc := strings.TrimSpace(p.MessageStr)
		if p.Evidence != "" {
			desc = strings.TrimSpace(desc + " Evidence: " + p.Evidence)
		}
		f := ParsedFinding{
			Host:        host,
			Port:        port,
			TemplateID:  "dalfox-xss",
			Name:        name,
			Severity:    sev,
			MatchedAt:   p.Data,
			Description: desc,
			Remediation: "Encode/escape user input on output and apply a strict Content-Security-Policy. Validate and sanitize the '" + p.Param + "' parameter.",
			Tags:        cleanStrings([]string{"xss", "dalfox", p.Param}),
		}
		if p.Data != "" {
			f.CURLCommand = "curl '" + p.Data + "'"
		}
		if p.Payload != "" {
			f.ExtractedResults = []string{p.Payload}
		}
		out = append(out, f)
	}
	return out, nil
}

func dalfoxSeverity(pocType string) string {
	switch strings.ToUpper(pocType) {
	case "V": // verified via headless browser
		return "high"
	case "R": // reflected
		return "medium"
	default: // G (grep) and anything else
		return "low"
	}
}

// ---------- sqlmap (SQLi) ----------

// ParseSqlmapOutput inspects sqlmap's (batch-mode) stdout for a confirmed
// injection and, if present, returns a compact detail string of the injection
// point(s). It intentionally keys off sqlmap's own definitive success line so a
// merely-attempted target isn't reported as vulnerable.
func ParseSqlmapOutput(output string) (detail string, injectable bool) {
	if !strings.Contains(output, "identified the following injection point") &&
		!strings.Contains(output, "is vulnerable") {
		return "", false
	}
	var parts []string
	for _, ln := range strings.Split(output, "\n") {
		t := strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(t, "Parameter:"),
			strings.HasPrefix(t, "Type:"),
			strings.HasPrefix(t, "Title:"):
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, " | "), true
}

// anyToInt coerces httpx's port field (number or quoted string) to an int.
func anyToInt(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	default:
		return 0
	}
}

// splitURL breaks "https://host:8443/x" into scheme, host, port (with a sane
// default port per scheme when none is present).
func splitURL(raw string) (scheme, host string, port int) {
	rest := raw
	if i := strings.Index(raw, "://"); i != -1 {
		scheme = raw[:i]
		rest = raw[i+3:]
	}
	// Cut the authority off at the first path / query / fragment delimiter —
	// not just '/', or a URL like "host?q=1" (no path) keeps the query in host.
	if i := strings.IndexAny(rest, "/?#"); i != -1 {
		rest = rest[:i]
	}
	if at := strings.LastIndexByte(rest, '@'); at != -1 { // drop any user:pass@
		rest = rest[at+1:]
	}
	host = rest
	if colon := strings.LastIndexByte(rest, ':'); colon != -1 {
		host = rest[:colon]
		port, _ = strconv.Atoi(rest[colon+1:])
	}
	if port == 0 {
		if scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}
	return scheme, host, port
}
