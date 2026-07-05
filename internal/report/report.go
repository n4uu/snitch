// Package report renders a workspace into correlated Markdown and HTML.
//
// Findings are split into priority (critical/high/medium) and informational
// buckets; each priority finding is expanded with its description, remediation,
// CVE/CVSS and a reproduction command, ahead of a short triage guide.
package report

import (
	"fmt"
	"html/template"
	"os"
	"sort"
	"strings"
	"time"

	"snitch/internal/store"
)

// isPriority reports whether a severity is worth acting on directly, as
// opposed to informational context.
func isPriority(sev string) bool {
	switch strings.ToLower(sev) {
	case "critical", "high", "medium":
		return true
	}
	return false
}

type hostView struct {
	Host     string
	Assets   []*store.Asset
	Findings []*store.Finding
	Paths    []*store.WebPath
}

func buildHostViews(ws *store.Workspace) []hostView {
	assets := ws.AllAssets()
	findings := ws.AllFindings()
	paths := ws.AllPaths()

	byHost := map[string]*hostView{}
	order := []string{}

	get := func(host string) *hostView {
		if v, ok := byHost[host]; ok {
			return v
		}
		v := &hostView{Host: host}
		byHost[host] = v
		order = append(order, host)
		return v
	}

	for _, a := range assets {
		v := get(a.Host)
		v.Assets = append(v.Assets, a)
	}
	for _, f := range findings {
		v := get(f.Host)
		v.Findings = append(v.Findings, f)
	}
	for _, p := range paths {
		v := get(p.Host)
		v.Paths = append(v.Paths, p)
	}

	sort.Strings(order)
	views := make([]hostView, 0, len(order))
	for _, h := range order {
		v := byHost[h]
		sort.Slice(v.Findings, func(i, j int) bool {
			return store.SeverityRank[v.Findings[i].Severity] < store.SeverityRank[v.Findings[j].Severity]
		})
		views = append(views, *v)
	}
	return views
}

func severityCounts(findings []*store.Finding) map[string]int {
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}

// priorityFindings returns the actionable findings (critical/high/medium)
// across all hosts, most severe first.
func priorityFindings(findings []*store.Finding) []*store.Finding {
	var out []*store.Finding
	for _, f := range findings {
		if isPriority(f.Severity) {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return store.SeverityRank[out[i].Severity] < store.SeverityRank[out[j].Severity]
	})
	return out
}

func severitySummary(counts map[string]int) string {
	parts := []string{}
	for _, sev := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		if counts[sev] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[sev], sev))
		}
	}
	return strings.Join(parts, ", ")
}

// cveCvss renders a compact "CVE-… · CVSS 7.5" label, or "" if neither present.
func cveCvss(f *store.Finding) string {
	parts := []string{}
	if len(f.CVEIDs) > 0 {
		parts = append(parts, strings.Join(f.CVEIDs, ", "))
	}
	if f.CVSSScore > 0 {
		parts = append(parts, fmt.Sprintf("CVSS %.1f", f.CVSSScore))
	}
	return strings.Join(parts, " · ")
}

// GenerateMarkdown builds the full Markdown report as a string.
func GenerateMarkdown(ws *store.Workspace) string {
	subdomains := ws.AllSubdomains()
	assets := ws.AllAssets()
	findings := ws.AllFindings()
	paths := ws.AllPaths()
	runs := ws.RecentRuns(20)
	views := buildHostViews(ws)
	counts := severityCounts(findings)
	priority := priorityFindings(findings)

	var b strings.Builder
	fmt.Fprintf(&b, "# snitch report — %s\n\n", ws.Project)
	fmt.Fprintf(&b, "_Generated %s_\n\n", time.Now().UTC().Format(time.RFC3339))

	fmt.Fprint(&b, "## Summary\n\n")
	fmt.Fprintf(&b, "- Hosts in scope: **%d**\n", len(views))
	if len(subdomains) > 0 {
		fmt.Fprintf(&b, "- Subdomains discovered: **%d**\n", len(subdomains))
	}
	fmt.Fprintf(&b, "- Open services discovered: **%d**\n", len(assets))
	fmt.Fprintf(&b, "- Findings: **%d** (%s)\n", len(findings), severitySummary(counts))
	fmt.Fprintf(&b, "- Actionable (critical/high/medium): **%d** · Informational: **%d**\n", len(priority), len(findings)-len(priority))
	fmt.Fprintf(&b, "- Fuzzed paths recorded: **%d**\n\n", len(paths))

	// --- diff since last run ---
	if since, ok := ws.SinceLastRun(); ok {
		newFindings, newAssets := 0, 0
		for _, f := range findings {
			if f.FirstSeen.After(since) {
				newFindings++
			}
		}
		for _, a := range assets {
			if a.FirstSeen.After(since) {
				newAssets++
			}
		}
		fmt.Fprint(&b, "## What's new since the last scan\n\n")
		fmt.Fprintf(&b, "Comparing against the previous completed run (started %s):\n\n", since.Format(time.RFC3339))
		fmt.Fprintf(&b, "- New services: **%d**\n", newAssets)
		fmt.Fprintf(&b, "- New findings: **%d**\n\n", newFindings)
	}

	// --- how to act ---
	fmt.Fprint(&b, howToActMarkdown)

	// --- priority findings, expanded ---
	fmt.Fprint(&b, "## Priority findings\n\n")
	if len(priority) == 0 {
		fmt.Fprint(&b, "_No critical/high/medium findings. Everything below is informational context._\n\n")
	}
	for _, f := range priority {
		fmt.Fprintf(&b, "### [%s] %s\n\n", strings.ToUpper(f.Severity), f.Name)
		fmt.Fprintf(&b, "- **Host:** %s\n", f.Host)
		if f.MatchedAt != "" {
			fmt.Fprintf(&b, "- **Location:** %s\n", f.MatchedAt)
		}
		fmt.Fprintf(&b, "- **Template:** `%s`\n", f.TemplateID)
		if cc := cveCvss(f); cc != "" {
			fmt.Fprintf(&b, "- **Risk:** %s\n", cc)
		}
		if len(f.Tags) > 0 {
			fmt.Fprintf(&b, "- **Tags:** %s\n", strings.Join(f.Tags, ", "))
		}
		fmt.Fprintln(&b)
		if f.Description != "" {
			fmt.Fprintf(&b, "**What it is:** %s\n\n", f.Description)
		}
		if f.Remediation != "" {
			fmt.Fprintf(&b, "**How to fix:** %s\n\n", f.Remediation)
		}
		if len(f.ExtractedResults) > 0 {
			fmt.Fprintf(&b, "**Extracted:** `%s`\n\n", strings.Join(f.ExtractedResults, "`, `"))
		}
		if f.CURLCommand != "" {
			fmt.Fprintf(&b, "**Reproduce:**\n\n```bash\n%s\n```\n\n", f.CURLCommand)
		}
		if len(f.References) > 0 {
			fmt.Fprint(&b, "**References:**\n")
			for _, r := range f.References {
				fmt.Fprintf(&b, "- %s\n", r)
			}
			fmt.Fprintln(&b)
		}
	}

	// --- subdomains ---
	if len(subdomains) > 0 {
		fmt.Fprintf(&b, "## Subdomains (%d)\n\n", len(subdomains))
		for _, s := range subdomains {
			fmt.Fprintf(&b, "- %s\n", s.Host)
		}
		fmt.Fprintln(&b)
	}

	// --- per-host detail ---
	fmt.Fprint(&b, "## Findings by host\n\n")
	for _, v := range views {
		fmt.Fprintf(&b, "### %s\n\n", v.Host)

		if len(v.Assets) > 0 {
			fmt.Fprint(&b, "**Open services:**\n\n")
			fmt.Fprintln(&b, "| Port | Service | Status | Title | Tech | Product/Version |")
			fmt.Fprintln(&b, "|------|---------|--------|-------|------|------------------|")
			for _, a := range v.Assets {
				pv := strings.TrimSpace(strings.Join(nonEmpty(a.Product, a.Version), " / "))
				fmt.Fprintf(&b, "| %d | %s | %s | %s | %s | %s |\n",
					a.Port, orDash(a.Service), statusCell(a.StatusCode),
					orDash(a.Title), orDash(strings.Join(a.Tech, ", ")), orDash(pv))
			}
			fmt.Fprintln(&b)
		}

		if len(v.Findings) > 0 {
			fmt.Fprint(&b, "**Findings:**\n\n")
			fmt.Fprintln(&b, "| Severity | Name | Template | Location |")
			fmt.Fprintln(&b, "|----------|------|----------|----------|")
			for _, f := range v.Findings {
				fmt.Fprintf(&b, "| %s | %s | `%s` | %s |\n", orDash(f.Severity), f.Name, f.TemplateID, f.MatchedAt)
			}
			fmt.Fprintln(&b)
		}

		if len(v.Paths) > 0 {
			fmt.Fprintf(&b, "**Discovered paths (%d):**\n\n", len(v.Paths))
			fmt.Fprintln(&b, "| Status | Length | URL |")
			fmt.Fprintln(&b, "|--------|--------|-----|")
			sortedPaths := append([]*store.WebPath{}, v.Paths...)
			sort.Slice(sortedPaths, func(i, j int) bool { return sortedPaths[i].StatusCode < sortedPaths[j].StatusCode })
			for _, p := range sortedPaths {
				fmt.Fprintf(&b, "| %d | %d | %s |\n", p.StatusCode, p.Length, p.URL)
			}
			fmt.Fprintln(&b)
		}

		if len(v.Assets) == 0 && len(v.Findings) == 0 && len(v.Paths) == 0 {
			fmt.Fprint(&b, "_No data recorded for this host yet._\n\n")
		}
	}

	fmt.Fprint(&b, "## Scan history\n\n")
	fmt.Fprintln(&b, "| Tool | Target | Status | New assets | New findings | New paths | Started |")
	fmt.Fprintln(&b, "|------|--------|--------|------------|--------------|-----------|---------|")
	for _, r := range runs {
		fmt.Fprintf(&b, "| %s | %s | %s | %d | %d | %d | %s |\n",
			r.Tool, r.Target, r.Status, r.NewAssets, r.NewFindings, r.NewPaths,
			r.StartedAt.Format(time.RFC3339))
	}

	return b.String()
}

const howToActMarkdown = `## How to act on this report

1. **Start with Priority findings below.** They are ordered critical → high →
   medium. Informational and low findings are context (detected technologies,
   missing hardening headers), not directly exploitable on their own.
2. **Verify before you report.** Automated scanners produce false positives —
   confirm each priority finding manually (use the reproduction command shown
   with it) before treating it as real.
3. **Read "How to fix".** Each priority finding includes nuclei's remediation
   guidance and reference links; that's your starting point for the writeup.
4. **Correlate per host.** The "Findings by host" section ties services,
   findings and discovered paths together so you can see the full picture of a
   single target rather than three disconnected lists.

`

func nonEmpty(vals ...string) []string {
	out := []string{}
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func statusCell(code int) string {
	if code == 0 {
		return "-"
	}
	return fmt.Sprintf("%d", code)
}

// WriteMarkdown writes the Markdown report to outputPath.
func WriteMarkdown(ws *store.Workspace, outputPath string) error {
	return os.WriteFile(outputPath, []byte(GenerateMarkdown(ws)), 0o644)
}

// ---------- HTML report ----------

const htmlTemplateSrc = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>snitch report — {{.Project}}</title>
<style>
  :root { color-scheme: dark; }
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; background: #0d1117; color: #c9d1d9; max-width: 980px; margin: 2rem auto; padding: 0 1rem; line-height: 1.55; }
  a { color: #58a6ff; }
  h1 { border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; }
  h2 { margin-top: 2.5rem; color: #58a6ff; border-bottom: 1px solid #21262d; padding-bottom: 0.3rem; }
  h3 { margin-top: 2rem; font-family: monospace; background: #161b22; padding: 0.5rem 0.75rem; border-radius: 6px; border-left: 3px solid #58a6ff; }
  table { border-collapse: collapse; width: 100%; margin: 0.75rem 0 1.5rem; }
  th, td { border: 1px solid #30363d; padding: 0.4rem 0.7rem; text-align: left; font-size: 0.92rem; vertical-align: top; }
  th { background: #161b22; }
  .sev-critical { color: #f85149; font-weight: bold; }
  .sev-high { color: #ff7b72; font-weight: bold; }
  .sev-medium { color: #d29922; }
  .sev-low { color: #58a6ff; }
  .sev-info, .sev-unknown { color: #8b949e; }
  .summary { background: #161b22; border-radius: 8px; padding: 1rem 1.5rem; }
  .muted { color: #8b949e; font-size: 0.85rem; }
  code { background: #161b22; padding: 0.1rem 0.35rem; border-radius: 4px; font-size: 0.9em; }
  pre { background: #161b22; padding: 0.75rem 1rem; border-radius: 6px; overflow-x: auto; border: 1px solid #30363d; }
  pre code { background: none; padding: 0; }
  .howto { background: #0f1620; border: 1px solid #21262d; border-left: 3px solid #3fb950; border-radius: 6px; padding: 0.5rem 1.25rem; }
  .card { background: #12181f; border: 1px solid #30363d; border-radius: 8px; padding: 1rem 1.25rem; margin: 1rem 0; }
  .card.critical { border-left: 4px solid #f85149; }
  .card.high { border-left: 4px solid #ff7b72; }
  .card.medium { border-left: 4px solid #d29922; }
  .badge { display: inline-block; font-size: 0.72rem; font-weight: bold; text-transform: uppercase; padding: 0.15rem 0.5rem; border-radius: 999px; margin-right: 0.5rem; letter-spacing: 0.03em; }
  .badge.critical { background: #f85149; color: #0d1117; }
  .badge.high { background: #ff7b72; color: #0d1117; }
  .badge.medium { background: #d29922; color: #0d1117; }
  .card h4 { margin: 0.2rem 0 0.6rem; display: flex; align-items: center; flex-wrap: wrap; }
  .card .meta { font-size: 0.85rem; color: #8b949e; margin: 0.15rem 0; }
  .card .label { color: #c9d1d9; font-weight: bold; }
  .card p { margin: 0.5rem 0; }
  .refs a { display: inline-block; margin-right: 0.75rem; word-break: break-all; }
  details { margin: 1rem 0; }
  summary { cursor: pointer; color: #58a6ff; font-weight: bold; }
  .clean { color: #3fb950; }
</style>
</head>
<body>
  <h1>🕵️ snitch report — {{.Project}}</h1>
  <p class="muted">Generated {{.Generated}}</p>

  <div class="summary">
    <p>Hosts in scope: <strong>{{.HostCount}}</strong>{{if gt .SubdomainCount 0}} · Subdomains: <strong>{{.SubdomainCount}}</strong>{{end}} · Open services: <strong>{{.AssetCount}}</strong> · Fuzzed paths: <strong>{{.PathCount}}</strong></p>
    <p>Findings: <strong>{{.FindingCount}}</strong> ({{.SeveritySummary}})</p>
    <p>{{if gt .PriorityCount 0}}<span class="sev-high">{{.PriorityCount}} actionable</span>{{else}}<span class="clean">0 actionable</span>{{end}} (critical/high/medium) · {{.InfoCount}} informational</p>
    {{if .HasDiff}}
    <p style="margin-top:1rem; border-top:1px solid #30363d; padding-top:0.75rem;">
      Since last scan ({{.SinceLabel}}): <strong>{{.NewAssets}}</strong> new services,
      <strong>{{.NewFindings}}</strong> new findings.
    </p>
    {{end}}
  </div>

  {{if .Subdomains}}
  <details>
    <summary>Subdomains discovered ({{.SubdomainCount}})</summary>
    <ul>{{range .Subdomains}}<li><code>{{.}}</code></li>{{end}}</ul>
  </details>
  {{end}}

  <h2>How to act on this report</h2>
  <div class="howto">
    <ol>
      <li><strong>Start with Priority findings.</strong> Ordered critical → high → medium. Informational/low findings are context (detected tech, missing hardening headers), not directly exploitable on their own.</li>
      <li><strong>Verify before reporting.</strong> Scanners produce false positives — confirm each priority finding manually (use the reproduction command) before treating it as real.</li>
      <li><strong>Read "How to fix".</strong> Each priority finding carries nuclei's remediation guidance and reference links — your starting point for the writeup.</li>
      <li><strong>Correlate per host.</strong> The per-host section ties services, findings and discovered paths together for the full picture of each target.</li>
    </ol>
  </div>

  <h2>Priority findings</h2>
  {{if not .Priority}}
  <p class="clean">✔ No critical/high/medium findings. Everything below is informational context.</p>
  {{end}}
  {{range .Priority}}
  <div class="card {{.Severity}}">
    <h4><span class="badge {{.Severity}}">{{.Severity}}</span> {{.Name}}</h4>
    <p class="meta"><span class="label">Host:</span> {{.Host}}</p>
    {{if .MatchedAt}}<p class="meta"><span class="label">Location:</span> <a href="{{.MatchedAt}}">{{.MatchedAt}}</a></p>{{end}}
    <p class="meta"><span class="label">Template:</span> <code>{{.TemplateID}}</code>{{if .RiskLabel}} · <span class="label">Risk:</span> {{.RiskLabel}}{{end}}</p>
    {{if .Tags}}<p class="meta"><span class="label">Tags:</span> {{.TagsJoined}}</p>{{end}}
    {{if .Description}}<p><span class="label">What it is:</span> {{.Description}}</p>{{end}}
    {{if .Remediation}}<p><span class="label">How to fix:</span> {{.Remediation}}</p>{{end}}
    {{if .ExtractedResults}}<p><span class="label">Extracted:</span> <code>{{.ExtractedJoined}}</code></p>{{end}}
    {{if .CURLCommand}}<p class="label">Reproduce:</p><pre><code>{{.CURLCommand}}</code></pre>{{end}}
    {{if .References}}<p class="refs"><span class="label">References:</span><br>{{range .References}}<a href="{{.}}">{{.}}</a>{{end}}</p>{{end}}
  </div>
  {{end}}

  <h2>Findings by host</h2>
  {{range .Hosts}}
  <h3>{{.Host}}</h3>
  {{if .Assets}}
  <table>
    <tr><th>Port</th><th>Service</th><th>Status</th><th>Title</th><th>Tech</th><th>Product/Version</th></tr>
    {{range .Assets}}<tr><td>{{.Port}}</td><td>{{.Service}}</td><td>{{.Status}}</td><td>{{.Title}}</td><td>{{.Tech}}</td><td>{{.ProductVersion}}</td></tr>{{end}}
  </table>
  {{end}}
  {{if .Findings}}
  <table>
    <tr><th>Severity</th><th>Name</th><th>Template</th><th>Location</th></tr>
    {{range .Findings}}<tr><td class="sev-{{.Severity}}">{{.Severity}}</td><td>{{.Name}}</td><td><code>{{.TemplateID}}</code></td><td>{{.MatchedAt}}</td></tr>{{end}}
  </table>
  {{end}}
  {{if .Paths}}
  <details>
    <summary>Discovered paths ({{.PathCount}})</summary>
    <table>
      <tr><th>Status</th><th>Length</th><th>URL</th></tr>
      {{range .Paths}}<tr><td>{{.StatusCode}}</td><td>{{.Length}}</td><td>{{.URL}}</td></tr>{{end}}
    </table>
  </details>
  {{end}}
  {{end}}
</body>
</html>
`

type htmlAsset struct {
	Port           int
	Protocol       string
	Service        string
	Status         string
	Title          string
	Tech           string
	ProductVersion string
}

type htmlHostView struct {
	Host      string
	Assets    []htmlAsset
	Findings  []*store.Finding
	Paths     []*store.WebPath
	PathCount int
}

type htmlFinding struct {
	Host             string
	Severity         string
	Name             string
	TemplateID       string
	MatchedAt        string
	Description      string
	Remediation      string
	References       []string
	RiskLabel        string
	TagsJoined       string
	Tags             []string
	CURLCommand      string
	ExtractedResults []string
	ExtractedJoined  string
}

type htmlData struct {
	Project         string
	Generated       string
	HostCount       int
	SubdomainCount  int
	Subdomains      []string
	AssetCount      int
	FindingCount    int
	PathCount       int
	PriorityCount   int
	InfoCount       int
	SeveritySummary string
	Priority        []htmlFinding
	Hosts           []htmlHostView
	HasDiff         bool
	SinceLabel      string
	NewAssets       int
	NewFindings     int
}

func toHTMLFinding(f *store.Finding) htmlFinding {
	return htmlFinding{
		Host:             f.Host,
		Severity:         f.Severity,
		Name:             f.Name,
		TemplateID:       f.TemplateID,
		MatchedAt:        f.MatchedAt,
		Description:      f.Description,
		Remediation:      f.Remediation,
		References:       f.References,
		RiskLabel:        cveCvss(f),
		Tags:             f.Tags,
		TagsJoined:       strings.Join(f.Tags, ", "),
		CURLCommand:      f.CURLCommand,
		ExtractedResults: f.ExtractedResults,
		ExtractedJoined:  strings.Join(f.ExtractedResults, ", "),
	}
}

// WriteHTML writes a self-contained (no external assets) HTML report.
func WriteHTML(ws *store.Workspace, outputPath string) error {
	subdomains := ws.AllSubdomains()
	assets := ws.AllAssets()
	findings := ws.AllFindings()
	paths := ws.AllPaths()
	views := buildHostViews(ws)
	counts := severityCounts(findings)
	priority := priorityFindings(findings)

	data := htmlData{
		Project:         ws.Project,
		Generated:       time.Now().UTC().Format(time.RFC3339),
		HostCount:       len(views),
		SubdomainCount:  len(subdomains),
		AssetCount:      len(assets),
		FindingCount:    len(findings),
		PathCount:       len(paths),
		PriorityCount:   len(priority),
		InfoCount:       len(findings) - len(priority),
		SeveritySummary: severitySummary(counts),
	}
	for _, s := range subdomains {
		data.Subdomains = append(data.Subdomains, s.Host)
	}

	for _, f := range priority {
		data.Priority = append(data.Priority, toHTMLFinding(f))
	}

	if since, ok := ws.SinceLastRun(); ok {
		data.HasDiff = true
		data.SinceLabel = since.Format(time.RFC3339)
		for _, f := range findings {
			if f.FirstSeen.After(since) {
				data.NewFindings++
			}
		}
		for _, a := range assets {
			if a.FirstSeen.After(since) {
				data.NewAssets++
			}
		}
	}

	for _, v := range views {
		hv := htmlHostView{Host: v.Host, Findings: v.Findings, Paths: v.Paths, PathCount: len(v.Paths)}
		for _, a := range v.Assets {
			pv := strings.TrimSpace(strings.Join(nonEmpty(a.Product, a.Version), " / "))
			hv.Assets = append(hv.Assets, htmlAsset{
				Port: a.Port, Protocol: a.Protocol, Service: a.Service,
				Status: statusCell(a.StatusCode), Title: a.Title,
				Tech: strings.Join(a.Tech, ", "), ProductVersion: pv,
			})
		}
		data.Hosts = append(data.Hosts, hv)
	}

	tmpl, err := template.New("report").Parse(htmlTemplateSrc)
	if err != nil {
		return err
	}
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()
	return tmpl.Execute(f, data)
}
