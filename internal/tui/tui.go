// Package tui is an interactive terminal browser for a snitch workspace, built
// on Bubble Tea. It opens a stored project and lets you page through the
// discovered subdomains, services, findings and crawled paths with the arrow
// keys — findings colour-coded by severity, with a detail pane (Enter) showing
// the description, remediation and reproduction command for a selected finding.
package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"snitch/internal/store"
)

// Run launches the interactive browser for ws and blocks until the user quits.
func Run(ws *store.Workspace) error {
	p := tea.NewProgram(newModel(ws), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

type tab int

const (
	tabFindings tab = iota
	tabServices
	tabSubdomains
	tabPaths
	tabCount
)

var tabTitles = [tabCount]string{"Findings", "Services", "Subdomains", "Paths"}

var (
	accent    = lipgloss.Color("#58a6ff")
	dim       = lipgloss.Color("#8b949e")
	titleBar  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#0d1117")).Background(accent).Padding(0, 1)
	activeTab = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#0d1117")).Background(accent).Padding(0, 2)
	idleTab   = lipgloss.NewStyle().Foreground(dim).Padding(0, 2)
	footer    = lipgloss.NewStyle().Foreground(dim)
	detailBox = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(accent).Padding(0, 1)
	labelSt   = lipgloss.NewStyle().Bold(true).Foreground(accent)
)

var sevColor = map[string]lipgloss.Color{
	"critical": lipgloss.Color("#f85149"),
	"high":     lipgloss.Color("#ff7b72"),
	"medium":   lipgloss.Color("#d29922"),
	"low":      lipgloss.Color("#58a6ff"),
	"info":     dim,
	"unknown":  dim,
}

func colorSeverity(sev string) string {
	c, ok := sevColor[strings.ToLower(sev)]
	if !ok {
		c = dim
	}
	return lipgloss.NewStyle().Foreground(c).Render(sev)
}

type model struct {
	ws       *store.Workspace
	active   tab
	tables   [tabCount]table.Model
	findings []*store.Finding // parallel to the findings table rows

	width, height int

	showDetail bool
	detail     viewport.Model
}

func newModel(ws *store.Workspace) model {
	m := model{ws: ws, detail: viewport.New(0, 0)}
	m.findings = ws.AllFindings()
	m.tables[tabFindings] = findingsTable(m.findings)
	m.tables[tabServices] = servicesTable(ws.AllAssets())
	m.tables[tabSubdomains] = subdomainsTable(ws.AllSubdomains())
	m.tables[tabPaths] = pathsTable(ws.AllPaths())
	for i := range m.tables {
		m.tables[i].Focus()
	}
	return m
}

func baseTable(cols []table.Column, rows []table.Row) table.Model {
	t := table.New(
		table.WithColumns(cols),
		table.WithRows(rows),
		table.WithFocused(true),
	)
	s := table.DefaultStyles()
	s.Header = s.Header.BorderStyle(lipgloss.NormalBorder()).BorderForeground(dim).BorderBottom(true).Bold(true)
	s.Selected = s.Selected.Foreground(lipgloss.Color("#0d1117")).Background(accent).Bold(true)
	t.SetStyles(s)
	return t
}

func findingsTable(fs []*store.Finding) table.Model {
	cols := []table.Column{
		{Title: "Severity", Width: 9},
		{Title: "Name", Width: 40},
		{Title: "Host", Width: 22},
		{Title: "Template", Width: 24},
	}
	rows := make([]table.Row, 0, len(fs))
	for _, f := range fs {
		rows = append(rows, table.Row{colorSeverity(f.Severity), f.Name, f.Host, f.TemplateID})
	}
	return baseTable(cols, rows)
}

func servicesTable(as []*store.Asset) table.Model {
	cols := []table.Column{
		{Title: "Host", Width: 26},
		{Title: "Port", Width: 6},
		{Title: "Service", Width: 12},
		{Title: "Title", Width: 26},
		{Title: "Tech", Width: 22},
	}
	rows := make([]table.Row, 0, len(as))
	for _, a := range as {
		rows = append(rows, table.Row{a.Host, fmt.Sprintf("%d", a.Port), a.Service, a.Title, strings.Join(a.Tech, ", ")})
	}
	return baseTable(cols, rows)
}

func subdomainsTable(subs []*store.Subdomain) table.Model {
	cols := []table.Column{{Title: "Subdomain", Width: 50}, {Title: "Source", Width: 16}}
	rows := make([]table.Row, 0, len(subs))
	for _, s := range subs {
		rows = append(rows, table.Row{s.Host, s.SourceTool})
	}
	return baseTable(cols, rows)
}

func pathsTable(ps []*store.WebPath) table.Model {
	cols := []table.Column{
		{Title: "Status", Width: 7},
		{Title: "Host", Width: 24},
		{Title: "URL", Width: 50},
	}
	rows := make([]table.Row, 0, len(ps))
	for _, p := range ps {
		status := "-"
		if p.StatusCode != 0 {
			status = fmt.Sprintf("%d", p.StatusCode)
		}
		rows = append(rows, table.Row{status, p.Host, p.URL})
	}
	return baseTable(cols, rows)
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		bodyHeight := msg.Height - 5 // header + tabs + footer
		if bodyHeight < 3 {
			bodyHeight = 3
		}
		for i := range m.tables {
			m.tables[i].SetHeight(bodyHeight)
		}
		m.detail.Width = msg.Width - 2
		m.detail.Height = bodyHeight
		return m, nil

	case tea.KeyMsg:
		if m.showDetail {
			switch msg.String() {
			case "esc", "q", "enter":
				m.showDetail = false
				return m, nil
			}
			var cmd tea.Cmd
			m.detail, cmd = m.detail.Update(msg)
			return m, cmd
		}

		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "right", "tab", "l":
			m.active = (m.active + 1) % tabCount
			return m, nil
		case "left", "shift+tab", "h":
			m.active = (m.active + tabCount - 1) % tabCount
			return m, nil
		case "enter":
			if m.active == tabFindings {
				if f := m.selectedFinding(); f != nil {
					m.detail.SetContent(renderFinding(f))
					m.detail.GotoTop()
					m.showDetail = true
				}
			}
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.tables[m.active], cmd = m.tables[m.active].Update(msg)
	return m, cmd
}

func (m model) selectedFinding() *store.Finding {
	i := m.tables[tabFindings].Cursor()
	if i < 0 || i >= len(m.findings) {
		return nil
	}
	return m.findings[i]
}

func (m model) View() string {
	if m.width == 0 {
		return "loading…"
	}

	title := titleBar.Render("🕵️  snitch — " + m.ws.Project)
	summary := footer.Render(fmt.Sprintf("  %d subdomains · %d services · %d findings · %d paths",
		len(m.ws.AllSubdomains()), len(m.ws.AllAssets()), len(m.ws.AllFindings()), len(m.ws.AllPaths())))
	header := lipgloss.JoinHorizontal(lipgloss.Center, title, summary)

	tabs := make([]string, tabCount)
	for i := tab(0); i < tabCount; i++ {
		label := tabTitles[i]
		if i == m.active {
			tabs[i] = activeTab.Render(label)
		} else {
			tabs[i] = idleTab.Render(label)
		}
	}
	tabBar := lipgloss.JoinHorizontal(lipgloss.Bottom, tabs...)

	var body string
	if m.showDetail {
		body = detailBox.Render(m.detail.View())
	} else {
		body = m.tables[m.active].View()
	}

	help := "←/→ tabs · ↑/↓ move"
	if m.active == tabFindings && !m.showDetail {
		help += " · enter details"
	}
	if m.showDetail {
		help = "↑/↓ scroll · esc back"
	}
	help += " · q quit"

	return lipgloss.JoinVertical(lipgloss.Left, header, tabBar, body, footer.Render(help))
}

// renderFinding builds the detail-pane text for one finding.
func renderFinding(f *store.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s  %s\n\n", colorSeverity(strings.ToUpper(f.Severity)), lipgloss.NewStyle().Bold(true).Render(f.Name))
	line := func(label, val string) {
		if val != "" {
			fmt.Fprintf(&b, "%s %s\n", labelSt.Render(label), val)
		}
	}
	line("Host:", f.Host)
	line("Location:", f.MatchedAt)
	line("Template:", f.TemplateID)
	if len(f.CVEIDs) > 0 {
		line("CVE:", strings.Join(f.CVEIDs, ", "))
	}
	if f.CVSSScore > 0 {
		line("CVSS:", fmt.Sprintf("%.1f", f.CVSSScore))
	}
	if len(f.Tags) > 0 {
		line("Tags:", strings.Join(f.Tags, ", "))
	}
	if f.Description != "" {
		fmt.Fprintf(&b, "\n%s\n%s\n", labelSt.Render("What it is:"), f.Description)
	}
	if f.Remediation != "" {
		fmt.Fprintf(&b, "\n%s\n%s\n", labelSt.Render("How to fix:"), f.Remediation)
	}
	if f.CURLCommand != "" {
		fmt.Fprintf(&b, "\n%s\n%s\n", labelSt.Render("Reproduce:"), f.CURLCommand)
	}
	if len(f.References) > 0 {
		fmt.Fprintf(&b, "\n%s\n", labelSt.Render("References:"))
		for _, r := range f.References {
			fmt.Fprintf(&b, "  %s\n", r)
		}
	}
	return b.String()
}
