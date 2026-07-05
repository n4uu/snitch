package tui

import (
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"snitch/internal/store"
)

// Bubble Tea models are pure functions, so we can drive the TUI headlessly:
// feed it messages via Update and assert on the string View returns — no TTY.
func TestModelRendersAndNavigates(t *testing.T) {
	ws, err := store.Open(filepath.Join(t.TempDir(), "tui.json"), "tui-demo")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ws.UpsertSubdomain(&store.Subdomain{Host: "api.demo.local", SourceTool: "subfinder"})
	ws.UpsertAsset(&store.Asset{Host: "demo.local", Port: 443, Protocol: "tcp", Service: "https", Title: "Home"})
	ws.UpsertFinding(&store.Finding{
		Host: "demo.local", TemplateID: "dalfox-xss", Name: "Reflected XSS",
		Severity: "high", MatchedAt: "https://demo.local/?q=1",
		Remediation: "Encode output and set a CSP.", CURLCommand: "curl 'https://demo.local/?q=1'",
	})

	var m tea.Model = newModel(ws)
	m, _ = m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})

	view := m.View()
	for _, want := range []string{"snitch", "tui-demo", "Findings", "Services", "Reflected XSS"} {
		if !strings.Contains(view, want) {
			t.Errorf("findings view missing %q\n---\n%s", want, view)
		}
	}

	// Switch to the Services tab and confirm the service row shows.
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyRight})
	if v := m.View(); !strings.Contains(v, "443") || !strings.Contains(v, "Home") {
		t.Errorf("services view missing service row\n---\n%s", v)
	}

	// Back to Findings, open the detail pane, and confirm remediation shows.
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyLeft})
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if v := m.View(); !strings.Contains(v, "How to fix") || !strings.Contains(v, "Encode output") {
		t.Errorf("detail pane missing remediation\n---\n%s", v)
	}

	// Esc closes the detail pane.
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if mm, ok := m.(model); ok && mm.showDetail {
		t.Error("esc should close the detail pane")
	}
}
