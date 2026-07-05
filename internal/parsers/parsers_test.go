package parsers

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSubfinderLines(t *testing.T) {
	hosts, err := ParseSubfinderLines(filepath.Join("..", "..", "samples", "subfinder_sample.txt"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(hosts) != 4 {
		t.Fatalf("expected 4 subdomains, got %d: %v", len(hosts), hosts)
	}
	if hosts[0] != "demo.local" {
		t.Errorf("unexpected first host %q", hosts[0])
	}
}

func TestParseHttpxJSONL(t *testing.T) {
	svcs, err := ParseHttpxJSONL(filepath.Join("..", "..", "samples", "httpx_sample.jsonl"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(svcs) != 3 {
		t.Fatalf("expected 3 web services, got %d", len(svcs))
	}

	// port as a string ("443") must parse the same as the numeric form.
	if svcs[0].Port != 443 {
		t.Errorf("string port not parsed: got %d", svcs[0].Port)
	}
	// port as a number (443) on the second entry.
	if svcs[1].Port != 443 {
		t.Errorf("numeric port not parsed: got %d", svcs[1].Port)
	}
	if svcs[0].Title != "Demo Home" || svcs[0].StatusCode != 200 {
		t.Errorf("metadata lost: %+v", svcs[0])
	}
	if len(svcs[0].Tech) != 2 {
		t.Errorf("expected 2 tech entries, got %v", svcs[0].Tech)
	}
	// dev entry: port from the URL host:port form.
	if svcs[2].Host != "dev.demo.local" || svcs[2].Port != 8080 {
		t.Errorf("host:port from URL not parsed: %+v", svcs[2])
	}
}

func TestParseNaabuJSONL(t *testing.T) {
	ports, err := ParseNaabuJSONL(filepath.Join("..", "..", "samples", "naabu_sample.jsonl"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(ports) != 3 {
		t.Fatalf("expected 3 ports, got %d", len(ports))
	}
	if ports[0].Host != "demo.local" || ports[0].Port != 22 {
		t.Errorf("unexpected first port: %+v", ports[0])
	}
}

func TestParseKatanaLines(t *testing.T) {
	eps, err := ParseKatanaLines(filepath.Join("..", "..", "samples", "katana_sample.txt"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// 5 lines, one duplicate -> 4 unique endpoints.
	if len(eps) != 4 {
		t.Fatalf("expected 4 unique endpoints, got %d", len(eps))
	}
	// host must be normalized (no scheme, no query).
	if eps[1].Host != "demo.local" {
		t.Errorf("host not normalized: %q", eps[1].Host)
	}
	if eps[3].Host != "api.demo.local" {
		t.Errorf("unexpected host: %q", eps[3].Host)
	}
}

func TestParseDalfoxJSON(t *testing.T) {
	fs, err := ParseDalfoxJSON(filepath.Join("..", "..", "samples", "dalfox_sample.json"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(fs) != 2 {
		t.Fatalf("expected 2 XSS findings, got %d", len(fs))
	}
	if fs[0].Severity != "high" {
		t.Errorf("verified PoC should be high severity, got %q", fs[0].Severity)
	}
	if fs[0].Host != "demo.local" {
		t.Errorf("host not parsed from PoC URL: %q", fs[0].Host)
	}
	if fs[0].CURLCommand == "" || fs[0].TemplateID != "dalfox-xss" {
		t.Errorf("finding missing repro/template: %+v", fs[0])
	}
	if fs[1].Severity != "medium" {
		t.Errorf("reflected PoC should be medium, got %q", fs[1].Severity)
	}
}

func TestParseLines(t *testing.T) {
	lines, err := ParseLines(filepath.Join("..", "..", "samples", "crlfuzz_sample.txt"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 unique lines (one dup), got %d", len(lines))
	}
}

func TestParseSqlmapOutput(t *testing.T) {
	vuln := `[*] starting @ 12:00:01
[12:00:05] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[12:00:07] [INFO] GET parameter 'id' is 'AND boolean-based blind' injectable
sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1
---`
	detail, ok := ParseSqlmapOutput(vuln)
	if !ok {
		t.Fatal("expected injectable=true")
	}
	if !strings.Contains(detail, "Parameter: id") || !strings.Contains(detail, "Type: boolean-based blind") {
		t.Errorf("detail missing injection specifics: %q", detail)
	}

	benign := `[12:00:05] [INFO] testing parameter 'id'
[12:00:09] [WARNING] GET parameter 'id' does not seem to be injectable`
	if _, ok := ParseSqlmapOutput(benign); ok {
		t.Error("benign output should not be reported injectable")
	}
}

func TestSplitURL(t *testing.T) {
	scheme, host, port := splitURL("https://a.example.com/x/y")
	if scheme != "https" || host != "a.example.com" || port != 443 {
		t.Errorf("default https port wrong: %s %s %d", scheme, host, port)
	}
	scheme, host, port = splitURL("http://a.example.com:8080")
	if scheme != "http" || host != "a.example.com" || port != 8080 {
		t.Errorf("explicit port wrong: %s %s %d", scheme, host, port)
	}
	// query right after the host (no path) must not end up inside the host.
	if _, host, _ = splitURL("https://example.com?pag=cultgva"); host != "example.com" {
		t.Errorf("query leaked into host: %q", host)
	}
	if _, host, _ = splitURL("https://user:pass@example.com/x"); host != "example.com" {
		t.Errorf("userinfo leaked into host: %q", host)
	}
}
