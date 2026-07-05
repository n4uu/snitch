// Package store persists a snitch project — subdomains, services, findings,
// paths and run history — as a JSON snapshot backed by mutex-guarded in-memory
// maps.
//
// Not SQLite: its Go driver needs CGO, which would forfeit the single static
// binary. At recon scale (thousands of rows, not millions) a JSON file is
// plenty and keeps the dependency surface at zero.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Asset struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
	Service    string `json:"service"`
	Product    string `json:"product"`
	Version    string `json:"version"`
	SourceTool string `json:"source_tool"`
	// Web metadata filled in by httpx (empty for non-web / nmap-only assets).
	Scheme     string    `json:"scheme,omitempty"`
	StatusCode int       `json:"status_code,omitempty"`
	Title      string    `json:"title,omitempty"`
	Webserver  string    `json:"webserver,omitempty"`
	Tech       []string  `json:"tech,omitempty"`
	DedupKey   string    `json:"dedup_key"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// Subdomain is a hostname discovered by subfinder for a scoped domain.
type Subdomain struct {
	Host       string    `json:"host"`
	SourceTool string    `json:"source_tool"`
	DedupKey   string    `json:"dedup_key"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

type Finding struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	TemplateID string `json:"template_id"`
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	MatchedAt  string `json:"matched_at"`
	SourceTool string `json:"source_tool"`
	// Actionable context nuclei ships with each finding.
	Description      string          `json:"description,omitempty"`
	Remediation      string          `json:"remediation,omitempty"`
	References       []string        `json:"references,omitempty"`
	Tags             []string        `json:"tags,omitempty"`
	CVEIDs           []string        `json:"cve_ids,omitempty"`
	CVSSScore        float64         `json:"cvss_score,omitempty"`
	CVSSMetrics      string          `json:"cvss_metrics,omitempty"`
	CURLCommand      string          `json:"curl_command,omitempty"`
	ExtractedResults []string        `json:"extracted_results,omitempty"`
	Raw              json.RawMessage `json:"raw,omitempty"`
	DedupKey         string          `json:"dedup_key"`
	FirstSeen        time.Time       `json:"first_seen"`
	LastSeen         time.Time       `json:"last_seen"`
}

type WebPath struct {
	Host       string    `json:"host"`
	URL        string    `json:"url"`
	StatusCode int       `json:"status_code"`
	Length     int       `json:"length"`
	SourceTool string    `json:"source_tool"`
	DedupKey   string    `json:"dedup_key"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

type ScanRun struct {
	Tool        string    `json:"tool"`
	Target      string    `json:"target"`
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  time.Time `json:"finished_at"`
	Status      string    `json:"status"`
	NewAssets   int       `json:"new_assets"`
	NewFindings int       `json:"new_findings"`
	NewPaths    int       `json:"new_paths"`
}

// snapshot is what actually gets marshaled to disk.
type snapshot struct {
	Project    string       `json:"project"`
	Subdomains []*Subdomain `json:"subdomains,omitempty"`
	Assets     []*Asset     `json:"assets"`
	Findings   []*Finding   `json:"findings"`
	Paths      []*WebPath   `json:"paths"`
	Runs       []*ScanRun   `json:"runs"`
}

// Workspace is a single project's persisted recon state.
// Safe for concurrent use (ffuf runs one goroutine per target).
type Workspace struct {
	mu         sync.Mutex
	path       string
	Project    string
	subdomains map[string]*Subdomain
	assets     map[string]*Asset
	findings   map[string]*Finding
	paths      map[string]*WebPath
	runs       []*ScanRun
}

func dedupKey(parts ...string) string {
	h := sha256.New()
	for i, p := range parts {
		if i > 0 {
			h.Write([]byte("|"))
		}
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))[:24]
}

// Open loads an existing workspace file or creates a new empty one.
func Open(dbPath, project string) (*Workspace, error) {
	ws := &Workspace{
		path:       dbPath,
		Project:    project,
		subdomains: map[string]*Subdomain{},
		assets:     map[string]*Asset{},
		findings:   map[string]*Finding{},
		paths:      map[string]*WebPath{},
	}

	data, err := os.ReadFile(dbPath)
	if os.IsNotExist(err) {
		if mkErr := os.MkdirAll(filepath.Dir(dbPath), 0o755); mkErr != nil {
			return nil, mkErr
		}
		return ws, nil
	}
	if err != nil {
		return nil, err
	}

	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("corrupt workspace file %s: %w", dbPath, err)
	}
	for _, s := range snap.Subdomains {
		ws.subdomains[s.DedupKey] = s
	}
	for _, a := range snap.Assets {
		ws.assets[a.DedupKey] = a
	}
	for _, f := range snap.Findings {
		ws.findings[f.DedupKey] = f
	}
	for _, p := range snap.Paths {
		ws.paths[p.DedupKey] = p
	}
	ws.runs = snap.Runs
	return ws, nil
}

// save must be called with mu held.
func (w *Workspace) save() error {
	snap := snapshot{
		Project:    w.Project,
		Subdomains: mapValues(w.subdomains),
		Assets:     mapValues(w.assets),
		Findings:   mapValues(w.findings),
		Paths:      mapValues(w.paths),
		Runs:       w.runs,
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp := w.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, w.path)
}

func mapValues[V any](m map[string]V) []V {
	out := make([]V, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

// UpsertAsset returns true if this is a newly discovered asset.
func (w *Workspace) UpsertAsset(a *Asset) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Keyed by host:port:protocol (not service) so the same endpoint described
	// by two tools — nmap's "ssl/http" and httpx's "https" on 443 — collapses
	// into one asset that accumulates both tools' detail instead of duplicating.
	key := dedupKey(w.Project, a.Host, fmt.Sprint(a.Port), a.Protocol)
	now := time.Now().UTC()

	if existing, ok := w.assets[key]; ok {
		existing.LastSeen = now
		// Merge in any richer metadata a later tool contributed (e.g. httpx
		// filling title/tech/status onto a service nmap discovered first).
		mergeAssetMeta(existing, a)
		return false, w.save()
	}
	a.DedupKey = key
	a.FirstSeen = now
	a.LastSeen = now
	w.assets[key] = a
	return true, w.save()
}

// mergeAssetMeta copies non-empty enrichment fields from src onto dst without
// clobbering existing values.
func mergeAssetMeta(dst, src *Asset) {
	if dst.Service == "" && src.Service != "" {
		dst.Service = src.Service
	}
	if src.Scheme != "" {
		dst.Scheme = src.Scheme
	}
	if src.StatusCode != 0 {
		dst.StatusCode = src.StatusCode
	}
	if src.Title != "" {
		dst.Title = src.Title
	}
	if src.Webserver != "" {
		dst.Webserver = src.Webserver
	}
	if len(src.Tech) > 0 {
		dst.Tech = src.Tech
	}
	if src.Product != "" {
		dst.Product = src.Product
	}
	if src.Version != "" {
		dst.Version = src.Version
	}
}

// UpsertSubdomain returns true if this is a newly discovered subdomain.
func (w *Workspace) UpsertSubdomain(s *Subdomain) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	key := dedupKey(w.Project, "subdomain", s.Host)
	now := time.Now().UTC()

	if existing, ok := w.subdomains[key]; ok {
		existing.LastSeen = now
		return false, w.save()
	}
	s.DedupKey = key
	s.FirstSeen = now
	s.LastSeen = now
	w.subdomains[key] = s
	return true, w.save()
}

// UpsertFinding returns true if this is a newly discovered finding.
func (w *Workspace) UpsertFinding(f *Finding) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	key := dedupKey(w.Project, f.Host, fmt.Sprint(f.Port), f.TemplateID, f.MatchedAt)
	now := time.Now().UTC()

	if existing, ok := w.findings[key]; ok {
		existing.LastSeen = now
		return false, w.save()
	}
	f.DedupKey = key
	f.FirstSeen = now
	f.LastSeen = now
	w.findings[key] = f
	return true, w.save()
}

// UpsertPath returns true if this is a newly discovered path.
func (w *Workspace) UpsertPath(p *WebPath) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	key := dedupKey(w.Project, p.Host, p.URL, fmt.Sprint(p.StatusCode))
	now := time.Now().UTC()

	if existing, ok := w.paths[key]; ok {
		existing.LastSeen = now
		return false, w.save()
	}
	p.DedupKey = key
	p.FirstSeen = now
	p.LastSeen = now
	w.paths[key] = p
	return true, w.save()
}

func (w *Workspace) StartRun(tool, target string) *ScanRun {
	w.mu.Lock()
	defer w.mu.Unlock()
	run := &ScanRun{Tool: tool, Target: target, StartedAt: time.Now().UTC(), Status: "running"}
	w.runs = append(w.runs, run)
	_ = w.save()
	return run
}

func (w *Workspace) FinishRun(run *ScanRun, status string, newAssets, newFindings, newPaths int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	run.FinishedAt = time.Now().UTC()
	run.Status = status
	run.NewAssets = newAssets
	run.NewFindings = newFindings
	run.NewPaths = newPaths
	_ = w.save()
}

func (w *Workspace) AllAssets() []*Asset {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := mapValues(w.assets)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// SeverityRank orders severities from most to least serious. Shared so the
// store, report and CLI all sort and threshold findings the same way.
var SeverityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

func (w *Workspace) AllFindings() []*Finding {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := mapValues(w.findings)
	sort.Slice(out, func(i, j int) bool {
		return SeverityRank[out[i].Severity] < SeverityRank[out[j].Severity]
	})
	return out
}

func (w *Workspace) AllPaths() []*WebPath {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := mapValues(w.paths)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].URL < out[j].URL
	})
	return out
}

func (w *Workspace) AllSubdomains() []*Subdomain {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := mapValues(w.subdomains)
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// SubdomainsSince returns subdomains first seen at or after t.
func (w *Workspace) SubdomainsSince(t time.Time) []*Subdomain {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []*Subdomain
	for _, s := range w.subdomains {
		if !s.FirstSeen.Before(t) {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// ParamURLs returns discovered URLs that carry a query string (contain "?"),
// de-duplicated. These are the candidates worth handing to injection testers
// (dalfox/crlfuzz/sqlmap) — a URL with no parameters has nothing to inject.
func (w *Workspace) ParamURLs() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, p := range w.paths {
		if !strings.Contains(p.URL, "?") || seen[p.URL] {
			continue
		}
		seen[p.URL] = true
		out = append(out, p.URL)
	}
	sort.Strings(out)
	return out
}

func (w *Workspace) RecentRuns(limit int) []*ScanRun {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := len(w.runs)
	if n == 0 {
		return nil
	}
	start := 0
	if n > limit {
		start = n - limit
	}
	// most recent first
	out := make([]*ScanRun, 0, n-start)
	for i := n - 1; i >= start; i-- {
		out = append(out, w.runs[i])
	}
	return out
}

// FindingsSince returns findings first seen at or after t, most severe first.
// Used by `monitor` to decide what to alert on after a scan cycle.
func (w *Workspace) FindingsSince(t time.Time) []*Finding {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []*Finding
	for _, f := range w.findings {
		if !f.FirstSeen.Before(t) {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return SeverityRank[out[i].Severity] < SeverityRank[out[j].Severity]
	})
	return out
}

// AssetsSince returns services first seen at or after t.
func (w *Workspace) AssetsSince(t time.Time) []*Asset {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []*Asset
	for _, a := range w.assets {
		if !a.FirstSeen.Before(t) {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// PathsSince returns fuzzed paths first seen at or after t.
func (w *Workspace) PathsSince(t time.Time) []*WebPath {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []*WebPath
	for _, p := range w.paths {
		if !p.FirstSeen.Before(t) {
			out = append(out, p)
		}
	}
	return out
}

// SinceLastRun returns assets/findings/paths whose FirstSeen is after the
// start time of the second-to-last completed run — i.e. "what's new since
// the previous scan". Used by the report's diff section.
func (w *Workspace) SinceLastRun() (time.Time, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	completed := make([]*ScanRun, 0)
	for _, r := range w.runs {
		if r.Status == "completed" {
			completed = append(completed, r)
		}
	}
	if len(completed) < 2 {
		return time.Time{}, false
	}
	sort.Slice(completed, func(i, j int) bool { return completed[i].StartedAt.Before(completed[j].StartedAt) })
	return completed[len(completed)-2].StartedAt, true
}
