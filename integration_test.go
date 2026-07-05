package integration_test

import (
	"os"
	"path/filepath"
	"testing"

	"snitch/internal/parsers"
	"snitch/internal/report"
	"snitch/internal/store"
)

// TestFullPipeline proves parsing, dedup, and correlated reporting all work
// end to end using sample tool output — no live nmap/nuclei/ffuf required.
// It also ingests everything TWICE to prove dedup actually prevents
// duplicate rows on a second run.
func TestFullPipeline(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test-project.json")
	ws, err := store.Open(dbPath, "demo-project")
	if err != nil {
		t.Fatalf("open workspace: %v", err)
	}

	samplesDir := "samples"

	ingestAll := func() (newAssets, newFindings, newPaths int) {
		assets, err := parsers.ParseNmapXML(filepath.Join(samplesDir, "nmap_sample.xml"))
		if err != nil {
			t.Fatalf("parse nmap: %v", err)
		}
		for _, a := range assets {
			isNew, err := ws.UpsertAsset(&store.Asset{
				Host: a.Host, Port: a.Port, Protocol: a.Protocol,
				Service: a.Service, Product: a.Product, Version: a.Version,
				SourceTool: "nmap",
			})
			if err != nil {
				t.Fatalf("upsert asset: %v", err)
			}
			if isNew {
				newAssets++
			}
		}

		findings, err := parsers.ParseNucleiJSONL(filepath.Join(samplesDir, "nuclei_sample.jsonl"))
		if err != nil {
			t.Fatalf("parse nuclei: %v", err)
		}
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
				t.Fatalf("upsert finding: %v", err)
			}
			if isNew {
				newFindings++
			}
		}

		paths, err := parsers.ParseFfufJSON(filepath.Join(samplesDir, "ffuf_sample.json"))
		if err != nil {
			t.Fatalf("parse ffuf: %v", err)
		}
		for _, p := range paths {
			isNew, err := ws.UpsertPath(&store.WebPath{
				Host: p.Host, URL: p.URL, StatusCode: p.StatusCode, Length: p.Length,
				SourceTool: "ffuf",
			})
			if err != nil {
				t.Fatalf("upsert path: %v", err)
			}
			if isNew {
				newPaths++
			}
		}
		return
	}

	a1, f1, p1 := ingestAll()
	if a1 != 3 || f1 != 3 || p1 != 4 {
		t.Fatalf("first ingest: expected (3,3,4) new, got (%d,%d,%d)", a1, f1, p1)
	}

	a2, f2, p2 := ingestAll()
	if a2 != 0 || f2 != 0 || p2 != 0 {
		t.Fatalf("second ingest: expected (0,0,0) new (dedup should block re-inserts), got (%d,%d,%d)", a2, f2, p2)
	}

	if got := len(ws.AllAssets()); got != 3 {
		t.Errorf("stored assets = %d, want 3", got)
	}
	if got := len(ws.AllFindings()); got != 3 {
		t.Errorf("stored findings = %d, want 3", got)
	}
	if got := len(ws.AllPaths()); got != 4 {
		t.Errorf("stored paths = %d, want 4", got)
	}

	// All ffuf paths should correlate to the SAME host as nmap/nuclei
	// (i.e. "demo.local", not "demo.local:443").
	assets := ws.AllAssets()
	paths := ws.AllPaths()
	if assets[0].Host != paths[0].Host {
		t.Errorf("host correlation broken: asset host=%q path host=%q", assets[0].Host, paths[0].Host)
	}

	// The enriched nuclei fields (description, remediation, references, CVSS)
	// must survive parse -> store so the report can render actionable detail.
	var git *store.Finding
	for _, f := range ws.AllFindings() {
		if f.TemplateID == "exposed-git-config" {
			git = f
		}
	}
	if git == nil {
		t.Fatal("expected exposed-git-config finding not found")
	}
	if git.Remediation == "" {
		t.Error("finding lost its remediation text through parse/store")
	}
	if len(git.References) == 0 {
		t.Error("finding lost its references through parse/store")
	}
	if git.CVSSScore == 0 {
		t.Error("finding lost its CVSS score through parse/store")
	}
	if git.CURLCommand == "" {
		t.Error("finding lost its reproduction curl command through parse/store")
	}

	// --- extended chain: subfinder + httpx ---
	subs, err := parsers.ParseSubfinderLines(filepath.Join(samplesDir, "subfinder_sample.txt"))
	if err != nil {
		t.Fatalf("parse subfinder: %v", err)
	}
	for _, h := range subs {
		if _, err := ws.UpsertSubdomain(&store.Subdomain{Host: h, SourceTool: "subfinder"}); err != nil {
			t.Fatalf("upsert subdomain: %v", err)
		}
	}
	if got := len(ws.AllSubdomains()); got != 4 {
		t.Errorf("stored subdomains = %d, want 4", got)
	}

	webSvcs, err := parsers.ParseHttpxJSONL(filepath.Join(samplesDir, "httpx_sample.jsonl"))
	if err != nil {
		t.Fatalf("parse httpx: %v", err)
	}
	for _, s := range webSvcs {
		if _, err := ws.UpsertAsset(&store.Asset{
			Host: s.Host, Port: s.Port, Protocol: "tcp", Service: s.Scheme,
			SourceTool: "httpx", Scheme: s.Scheme, StatusCode: s.StatusCode,
			Title: s.Title, Webserver: s.Webserver, Tech: s.Tech,
		}); err != nil {
			t.Fatalf("upsert httpx asset: %v", err)
		}
	}

	// httpx's demo.local:443 must MERGE onto nmap's existing 443 asset (same
	// host:port), not create a duplicate — and carry both nmap's product and
	// httpx's title/tech.
	var web443 *store.Asset
	for _, a := range ws.AllAssets() {
		if a.Host == "demo.local" && a.Port == 443 {
			web443 = a
		}
	}
	if web443 == nil {
		t.Fatal("demo.local:443 asset missing after httpx merge")
	}
	if web443.Title != "Demo Home" {
		t.Errorf("httpx title not merged onto nmap asset: %q", web443.Title)
	}
	if web443.Product != "nginx" {
		t.Errorf("nmap product lost after merge: %q", web443.Product)
	}
	if len(web443.Tech) == 0 {
		t.Errorf("httpx tech not merged onto nmap asset")
	}

	mdPath := filepath.Join(t.TempDir(), "report.md")
	if err := report.WriteMarkdown(ws, mdPath); err != nil {
		t.Fatalf("write markdown: %v", err)
	}
	if info, err := os.Stat(mdPath); err != nil || info.Size() == 0 {
		t.Errorf("markdown report missing or empty")
	}

	htmlPath := filepath.Join(t.TempDir(), "report.html")
	if err := report.WriteHTML(ws, htmlPath); err != nil {
		t.Fatalf("write html: %v", err)
	}
	if info, err := os.Stat(htmlPath); err != nil || info.Size() == 0 {
		t.Errorf("html report missing or empty")
	}

	t.Logf("Markdown report:\n%s", report.GenerateMarkdown(ws))
}
