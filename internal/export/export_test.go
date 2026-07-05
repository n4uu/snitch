package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"snitch/internal/store"
)

func demoWorkspace(t *testing.T) *store.Workspace {
	t.Helper()
	ws, err := store.Open(filepath.Join(t.TempDir(), "e.json"), "exp")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ws.UpsertFinding(&store.Finding{
		Host: "demo.local", TemplateID: "exposed-git-config", Name: "Exposed .git Config",
		Severity: "high", MatchedAt: "https://demo.local/.git/config", SourceTool: "nuclei",
		CVSSScore: 7.5, References: []string{"https://owasp.org/x"}, Tags: []string{"git", "exposure"},
	})
	ws.UpsertFinding(&store.Finding{
		Host: "demo.local", TemplateID: "nginx-version-detect", Name: "Nginx Version",
		Severity: "info", MatchedAt: "https://demo.local/", SourceTool: "nuclei",
	})
	return ws
}

func TestFindingsCSV(t *testing.T) {
	ws := demoWorkspace(t)
	var buf bytes.Buffer
	if err := FindingsCSV(&buf, ws); err != nil {
		t.Fatalf("csv: %v", err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("reparse csv: %v", err)
	}
	if len(rows) != 3 { // header + 2 findings
		t.Fatalf("expected 3 rows, got %d", len(rows))
	}
	if rows[0][0] != "severity" || rows[0][6] != "cvss" {
		t.Errorf("unexpected header: %v", rows[0])
	}
	// findings come back most-severe first, so the high/git one leads.
	if rows[1][0] != "high" || rows[1][6] != "7.5" {
		t.Errorf("unexpected first data row: %v", rows[1])
	}
}

func TestSARIF(t *testing.T) {
	ws := demoWorkspace(t)
	var buf bytes.Buffer
	if err := SARIF(&buf, ws); err != nil {
		t.Fatalf("sarif: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("sarif is not valid JSON: %v", err)
	}
	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", log.Version)
	}
	if len(log.Runs) != 1 || log.Runs[0].Tool.Driver.Name != "snitch" {
		t.Fatalf("driver name wrong: %+v", log.Runs)
	}
	run := log.Runs[0]
	if len(run.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(run.Results))
	}
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("expected 2 distinct rules, got %d", len(run.Tool.Driver.Rules))
	}
	// high severity must map to SARIF "error".
	if run.Results[0].Level != "error" {
		t.Errorf("high finding level = %q, want error", run.Results[0].Level)
	}
	// GitHub code scanning reads security-severity off the rule.
	if ss, _ := run.Tool.Driver.Rules[0].Properties["security-severity"].(string); ss != "7.5" {
		t.Errorf("security-severity = %q, want 7.5", ss)
	}
}

func TestJSON(t *testing.T) {
	ws := demoWorkspace(t)
	var buf bytes.Buffer
	if err := JSON(&buf, ws); err != nil {
		t.Fatalf("json: %v", err)
	}
	if !strings.Contains(buf.String(), `"project": "exp"`) {
		t.Errorf("json missing project field:\n%s", buf.String())
	}
}
