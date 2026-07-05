// Command snitch runs a full recon chain (subfinder, naabu, httpx, nmap,
// nuclei, ffuf, katana, dalfox, crlfuzz and optionally sqlmap) into one
// correlated, deduplicated, re-runnable workspace, and snitches — alerts a
// webhook — when your attack surface changes between runs.
//
// Usage:
//
//	snitch scan example.com --project acme --wordlist /path/to/wordlist.txt
//	snitch scan example.com --project acme --skip-nmap --nmap-xml scan.xml --skip-ffuf
//	snitch monitor example.com --project acme --wordlist wl.txt --notify <webhook> --interval 6h
//	snitch report --project acme --format html -o report.html
//	snitch tui --project acme
//	snitch status --project acme
//	snitch export --project acme -o findings.json
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"snitch/internal/export"
	"snitch/internal/notify"
	"snitch/internal/orchestrator"
	"snitch/internal/report"
	"snitch/internal/store"
	"snitch/internal/tui"
)

// version is stamped at build time with -ldflags "-X main.version=v1.2.3".
var version = "dev"

func dbPath(project string) string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".snitch", project+".json")
}

// normalizeTarget accepts either a bare host (example.com) or a full URL
// (https://example.com/path) and reduces it to the bare host that subfinder,
// nmap and friends expect — stripping scheme, path, credentials and trailing dot.
func normalizeTarget(t string) string {
	t = strings.TrimSpace(t)
	if i := strings.Index(t, "://"); i != -1 {
		t = t[i+3:]
	}
	if i := strings.IndexAny(t, "/?#"); i != -1 {
		t = t[:i]
	}
	if i := strings.LastIndex(t, "@"); i != -1 { // drop user:pass@
		t = t[i+1:]
	}
	return strings.ToLower(strings.TrimSuffix(t, "."))
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		cmdScan(os.Args[2:])
	case "monitor":
		cmdMonitor(os.Args[2:])
	case "report":
		cmdReport(os.Args[2:])
	case "tui":
		cmdTui(os.Args[2:])
	case "status":
		cmdStatus(os.Args[2:])
	case "reset":
		cmdReset(os.Args[2:])
	case "export":
		cmdExport(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("snitch %s\n", version)
	case "-h", "--help", "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`snitch - the recon tool that snitches on your attack surface

Commands:
  scan     Run the full chain: subfinder,naabu,httpx,nmap,nuclei,ffuf,katana,dalfox,crlfuzz (+sqlmap via --sqli)
  monitor  Re-scan and alert a webhook about what's new (the snitch)
  report   Generate a correlated Markdown or HTML report
  tui      Browse a project's results in an interactive terminal UI
  status   Show stored counts and recent scan history
  reset    Delete a project's stored data (start fresh)
  export   Dump results as JSON, CSV, or SARIF for other tooling
  version  Print the snitch version

Run 'snitch <command> -h' for command-specific flags.`)
}

// reorderArgs moves the positional target argument to the end of the slice
// regardless of where the user typed it, so `scan TARGET --project X` and
// `scan --project X TARGET` both work. Go's flag package otherwise stops
// parsing at the first non-flag token, silently dropping everything after
// it — a sharp edge that isn't obvious until a flag you typed gets ignored.
// boolFlags lists flag names that take no separate value argument.
func reorderArgs(args []string, boolFlags map[string]bool) []string {
	var flagArgs, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 0 && a[0] == '-' {
			name := strings.TrimLeft(a, "-")
			if eq := strings.Index(name, "="); eq != -1 {
				// -flag=value form: self-contained, no lookahead needed.
				flagArgs = append(flagArgs, a)
				continue
			}
			flagArgs = append(flagArgs, a)
			if !boolFlags[name] && i+1 < len(args) {
				// this flag consumes the next token as its value
				i++
				flagArgs = append(flagArgs, args[i])
			}
			continue
		}
		positional = append(positional, a)
	}
	return append(flagArgs, positional...)
}

// scanFlags holds the flags shared by the `scan` and `monitor` commands, so
// the two stay in lockstep instead of drifting apart.
type scanFlags struct {
	project       *string
	wordlist      *string
	nmapXML       *string
	skipSubfinder *bool
	skipNaabu     *bool
	skipHttpx     *bool
	skipNmap      *bool
	skipNuclei    *bool
	skipFfuf      *bool
	skipKatana    *bool
	skipDalfox    *bool
	skipCrlfuzz   *bool
	sqli          *bool
	sqliMax       *int
	enumOnly      *bool
	fullPorts     *bool
	workers       *int
	timeout       *time.Duration
}

func addScanFlags(fs *flag.FlagSet) *scanFlags {
	return &scanFlags{
		project:       fs.String("project", "", "project name (required)"),
		wordlist:      fs.String("wordlist", "wordlists/common.txt", "wordlist for ffuf content discovery (bundled default; pass a bigger one for deeper scans)"),
		nmapXML:       fs.String("nmap-xml", "", "existing nmap XML to ingest instead of scanning"),
		skipSubfinder: fs.Bool("skip-subfinder", false, "skip subdomain enumeration"),
		skipNaabu:     fs.Bool("skip-naabu", false, "skip fast port scanning"),
		skipHttpx:     fs.Bool("skip-httpx", false, "skip live web-service probing"),
		skipNmap:      fs.Bool("skip-nmap", false, "skip running nmap"),
		skipNuclei:    fs.Bool("skip-nuclei", false, "skip running nuclei"),
		skipFfuf:      fs.Bool("skip-ffuf", false, "skip running ffuf"),
		skipKatana:    fs.Bool("skip-katana", false, "skip crawling for endpoints"),
		skipDalfox:    fs.Bool("skip-dalfox", false, "skip XSS testing (dalfox)"),
		skipCrlfuzz:   fs.Bool("skip-crlfuzz", false, "skip CRLF-injection testing (crlfuzz)"),
		sqli:          fs.Bool("sqli", false, "enable active SQLi testing with sqlmap (opt-in)"),
		sqliMax:       fs.Int("sqli-max", 15, "max URLs to hand to sqlmap"),
		enumOnly:      fs.Bool("enum-only", false, "enumeration only: skip nuclei/dalfox/crlfuzz/sqlmap (e.g. OSCP-legal recon)"),
		fullPorts:     fs.Bool("full-ports", false, "scan all 65535 ports with naabu and nmap, not just the top ports"),
		workers:       fs.Int("workers", 5, "max concurrent ffuf jobs"),
		timeout:       fs.Duration("timeout", 30*time.Minute, "per-tool timeout"),
	}
}

func (s *scanFlags) chainOptions() orchestrator.ChainOptions {
	opts := orchestrator.ChainOptions{
		Wordlist:      *s.wordlist,
		SkipSubfinder: *s.skipSubfinder,
		SkipNaabu:     *s.skipNaabu,
		SkipHttpx:     *s.skipHttpx,
		SkipNmap:      *s.skipNmap,
		NmapXML:       *s.nmapXML,
		SkipNuclei:    *s.skipNuclei,
		SkipFfuf:      *s.skipFfuf,
		SkipKatana:    *s.skipKatana,
		SkipDalfox:    *s.skipDalfox,
		SkipCrlfuzz:   *s.skipCrlfuzz,
		SQLi:          *s.sqli,
		SQLiMax:       *s.sqliMax,
		FullPorts:     *s.fullPorts,
		MaxWorkers:    *s.workers,
		Timeout:       *s.timeout,
	}
	// enum-only keeps discovery (subfinder/naabu/httpx/nmap/ffuf/katana) but
	// drops every automated vuln-scan / exploitation stage.
	if *s.enumOnly {
		opts.SkipNuclei = true
		opts.SkipDalfox = true
		opts.SkipCrlfuzz = true
		opts.SQLi = false
	}
	return opts
}

// scanBoolFlags are the value-less flags common to scan and monitor, needed by
// reorderArgs so it doesn't consume the next token as their argument.
func scanBoolFlags() map[string]bool {
	return map[string]bool{
		"skip-subfinder": true, "skip-naabu": true, "skip-httpx": true,
		"skip-nmap": true, "skip-nuclei": true, "skip-ffuf": true, "skip-katana": true,
		"skip-dalfox": true, "skip-crlfuzz": true, "sqli": true,
		"enum-only": true, "full-ports": true,
	}
}

func cmdScan(args []string) {
	bf := scanBoolFlags()
	bf["open"] = true
	args = reorderArgs(args, bf)
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	sf := addScanFlags(fs)
	reportFmt := fs.String("report", "", "generate a report when the scan finishes: html or markdown")
	open := fs.Bool("open", false, "open the generated report in your browser (implies -report html)")
	notifyURL := fs.String("notify", "", "also POST a summary to this webhook (Discord/Slack/generic)")
	fs.Parse(args)

	if fs.NArg() < 1 || *sf.project == "" {
		fmt.Fprintln(os.Stderr, "usage: snitch scan <target> --project NAME [flags]")
		fs.PrintDefaults()
		os.Exit(1)
	}
	target := normalizeTarget(fs.Arg(0))

	ws, err := store.Open(dbPath(*sf.project), *sf.project)
	if err != nil {
		fatal(err)
	}

	t0 := time.Now().UTC()
	summary, err := orchestrator.FullChain(ws, target, sf.chainOptions())
	if err != nil {
		fatal(err)
	}

	fmt.Printf("\n=== Scan complete in %s ===\n", summary.Elapsed.Round(time.Second))
	if summary.SubdomainsFound > 0 {
		fmt.Printf("[+] Subdomains:     %d\n", summary.SubdomainsFound)
	}
	fmt.Printf("[+] Services:       %d\n", summary.AssetsFound)
	fmt.Printf("[+] Web targets:    %d\n", len(summary.WebTargets))
	fmt.Printf("[+] Findings:       %d\n", summary.FindingsFound)
	fmt.Printf("[+] Paths fuzzed:   %d\n", summary.PathsFound)
	if len(summary.Warnings) > 0 {
		fmt.Printf("\n[!] Completed with %d warning(s):\n", len(summary.Warnings))
		for _, w := range summary.Warnings {
			fmt.Printf("    - %s\n", firstLine(w))
		}
	}
	fmt.Printf("\n[+] Stored in %s\n", dbPath(*sf.project))

	// Optional webhook: a one-off scan can also ping a channel with what it
	// found. quietIfEmpty=false so a manual run always gets a confirmation.
	if *notifyURL != "" {
		nf, na, sent, aerr := alertNew(ws, *sf.project, target, *notifyURL, store.SeverityRank["info"], false, t0)
		if aerr != nil {
			fmt.Fprintf(os.Stderr, "[!] alert delivery failed: %v\n", aerr)
		} else if sent {
			fmt.Printf("[+] Alert sent to webhook — %d finding(s), %d service(s)\n", nf, na)
		}
	}

	// Auto-report: -open implies an HTML report; -report picks the format
	// explicitly. Either way we save it next to the CWD and optionally open it,
	// so a scan can go straight to a readable result with no second command.
	format := *reportFmt
	if format == "" && *open {
		format = "html"
	}
	if format == "" {
		fmt.Printf("    Run 'snitch report --project %s' for the full report.\n", *sf.project)
		return
	}
	out := writeReport(*sf.project, ws, format)
	fmt.Printf("[+] Report written to %s\n", out)
	if *open {
		if err := openInBrowser(out); err != nil {
			fmt.Fprintf(os.Stderr, "[!] could not open report automatically: %v\n", err)
		}
	}
}

// writeReport renders a report for the workspace in the given format and
// returns the path it was written to (report-<project>.html|md in the CWD).
func writeReport(project string, ws *store.Workspace, format string) string {
	if format == "html" {
		out := "report-" + project + ".html"
		if err := report.WriteHTML(ws, out); err != nil {
			fatal(err)
		}
		return out
	}
	out := "report-" + project + ".md"
	if err := report.WriteMarkdown(ws, out); err != nil {
		fatal(err)
	}
	return out
}

// openInBrowser opens path in the OS default handler (browser for .html).
func openInBrowser(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", abs)
	case "darwin":
		cmd = exec.Command("open", abs)
	default:
		cmd = exec.Command("xdg-open", abs)
	}
	return cmd.Start()
}

// cmdMonitor runs a scan cycle and alerts a webhook about what's NEW since the
// cycle started — the feature snitch is named for. With -interval it keeps
// looping so you can leave it running (or fire it from cron without -interval).
func cmdMonitor(args []string) {
	args = reorderArgs(args, scanBoolFlags())
	fs := flag.NewFlagSet("monitor", flag.ExitOnError)
	sf := addScanFlags(fs)
	notifyURL := fs.String("notify", "", "webhook URL for alerts — Discord/Slack/generic (required)")
	interval := fs.Duration("interval", 0, "repeat every interval (e.g. 6h); default: run once and exit")
	minSev := fs.String("min-severity", "info", "only alert on new findings at or above this severity")
	quiet := fs.Bool("quiet-if-empty", true, "skip the webhook call when a cycle finds nothing new")
	fs.Parse(args)

	if fs.NArg() < 1 || *sf.project == "" || *notifyURL == "" {
		fmt.Fprintln(os.Stderr, "usage: snitch monitor <target> --project NAME --notify URL [--interval 6h] [flags]")
		fs.PrintDefaults()
		os.Exit(1)
	}
	target := normalizeTarget(fs.Arg(0))
	threshold, ok := store.SeverityRank[strings.ToLower(*minSev)]
	if !ok {
		fatal(fmt.Errorf("invalid -min-severity %q (use critical|high|medium|low|info)", *minSev))
	}

	runCycle := func() {
		ws, err := store.Open(dbPath(*sf.project), *sf.project)
		if err != nil {
			fatal(err)
		}
		t0 := time.Now().UTC()
		if _, err := orchestrator.FullChain(ws, target, sf.chainOptions()); err != nil {
			// In watch mode a single failed cycle shouldn't kill the loop.
			fmt.Fprintf(os.Stderr, "[!] scan cycle failed: %v\n", err)
			if *interval <= 0 {
				os.Exit(1)
			}
			return
		}

		nf, na, sent, err := alertNew(ws, *sf.project, target, *notifyURL, threshold, *quiet, t0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] alert delivery failed: %v\n", err)
			return
		}
		if sent {
			fmt.Printf("[+] snitch: alert sent — %d new finding(s), %d new service(s)\n", nf, na)
		} else {
			fmt.Println("[*] snitch: nothing new this cycle — no alert sent")
		}
	}

	if *interval <= 0 {
		runCycle()
		return
	}
	fmt.Printf("[*] snitch: watching %s every %s (Ctrl-C to stop)\n", target, *interval)
	for {
		runCycle()
		time.Sleep(*interval)
	}
}

// alertNew gathers everything first seen since `since`, filters findings to the
// severity threshold, and POSTs a summary to the webhook. When quietIfEmpty is
// set and nothing qualifies, it sends nothing and reports sent=false. Shared by
// `monitor` (each cycle) and `scan` (its --notify flag).
func alertNew(ws *store.Workspace, project, target, notifyURL string, threshold int, quietIfEmpty bool, since time.Time) (newFindings, newServices int, sent bool, err error) {
	assets := ws.AssetsSince(since)
	var findings []*store.Finding
	for _, f := range ws.FindingsSince(since) {
		if store.SeverityRank[f.Severity] <= threshold {
			findings = append(findings, f)
		}
	}

	if len(findings) == 0 && len(assets) == 0 && quietIfEmpty {
		return 0, 0, false, nil
	}

	msg := buildAlert(project, target, findings, assets, len(ws.PathsSince(since)))
	if err := notify.Send(notifyURL, msg); err != nil {
		return len(findings), len(assets), false, err
	}
	return len(findings), len(assets), true, nil
}

// buildAlert composes the webhook message summarizing this cycle's new items.
func buildAlert(project, target string, findings []*store.Finding, assets []*store.Asset, newPaths int) notify.Message {
	var b strings.Builder
	fmt.Fprintf(&b, "Project **%s** · target `%s`\n", project, target)

	if len(findings) > 0 {
		fmt.Fprintf(&b, "\n__New findings (%d):__\n", len(findings))
		for i, f := range findings {
			if i >= 15 {
				fmt.Fprintf(&b, "…and %d more\n", len(findings)-15)
				break
			}
			risk := ""
			if f.CVSSScore > 0 {
				risk = fmt.Sprintf(" (CVSS %.1f)", f.CVSSScore)
			}
			fmt.Fprintf(&b, "• [%s] %s — `%s`%s\n", strings.ToUpper(f.Severity), f.Name, f.Host, risk)
		}
	}
	if len(assets) > 0 {
		fmt.Fprintf(&b, "\n__New services (%d):__\n", len(assets))
		for i, a := range assets {
			if i >= 10 {
				fmt.Fprintf(&b, "…and %d more\n", len(assets)-10)
				break
			}
			fmt.Fprintf(&b, "• %s:%d %s\n", a.Host, a.Port, a.Service)
		}
	}
	if newPaths > 0 {
		fmt.Fprintf(&b, "\n%d new path(s) discovered.\n", newPaths)
	}

	title := fmt.Sprintf("🕵️ snitch: %d new finding(s) on %s", len(findings), target)
	return notify.Message{Title: title, Body: strings.TrimRight(b.String(), "\n")}
}

func cmdReport(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	project := fs.String("project", "", "project name (required)")
	output := fs.String("o", "report.md", "output file path")
	format := fs.String("format", "markdown", "output format: markdown or html")
	open := fs.Bool("open", false, "open the report in your browser after writing")
	fs.Parse(args)

	if *project == "" {
		fmt.Fprintln(os.Stderr, "usage: snitch report --project NAME [-o path] [-format markdown|html] [-open]")
		os.Exit(1)
	}

	ws, err := store.Open(dbPath(*project), *project)
	if err != nil {
		fatal(err)
	}

	switch *format {
	case "html":
		if err := report.WriteHTML(ws, *output); err != nil {
			fatal(err)
		}
	default:
		if err := report.WriteMarkdown(ws, *output); err != nil {
			fatal(err)
		}
	}
	fmt.Printf("[+] Report written to %s\n", *output)
	if *open {
		if err := openInBrowser(*output); err != nil {
			fmt.Fprintf(os.Stderr, "[!] could not open report automatically: %v\n", err)
		}
	}
}

func cmdTui(args []string) {
	fs := flag.NewFlagSet("tui", flag.ExitOnError)
	project := fs.String("project", "", "project name (required)")
	fs.Parse(args)

	if *project == "" {
		fmt.Fprintln(os.Stderr, "usage: snitch tui --project NAME")
		os.Exit(1)
	}

	ws, err := store.Open(dbPath(*project), *project)
	if err != nil {
		fatal(err)
	}
	if err := tui.Run(ws); err != nil {
		fatal(err)
	}
}

func cmdStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	project := fs.String("project", "", "project name (required)")
	fs.Parse(args)

	if *project == "" {
		fmt.Fprintln(os.Stderr, "usage: snitch status --project NAME")
		os.Exit(1)
	}

	ws, err := store.Open(dbPath(*project), *project)
	if err != nil {
		fatal(err)
	}

	fmt.Printf("Project: %s\n", *project)
	fmt.Printf("  Subdomains: %d\n", len(ws.AllSubdomains()))
	fmt.Printf("  Services:   %d\n", len(ws.AllAssets()))
	fmt.Printf("  Findings:   %d\n", len(ws.AllFindings()))
	fmt.Printf("  Paths:      %d\n", len(ws.AllPaths()))
	fmt.Println("\nRecent runs:")
	for _, r := range ws.RecentRuns(10) {
		fmt.Printf("  [%9s] %-8s %-30s +%da +%df +%dp\n",
			r.Status, r.Tool, r.Target, r.NewAssets, r.NewFindings, r.NewPaths)
	}
}

func cmdReset(args []string) {
	fs := flag.NewFlagSet("reset", flag.ExitOnError)
	project := fs.String("project", "", "project name (required)")
	yes := fs.Bool("yes", false, "skip the confirmation prompt")
	fs.Parse(args)

	if *project == "" {
		fmt.Fprintln(os.Stderr, "usage: snitch reset --project NAME [--yes]")
		os.Exit(1)
	}

	path := dbPath(*project)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		fmt.Printf("[*] nothing to reset — no data for project %q\n", *project)
		return
	}
	if !*yes {
		fmt.Printf("Delete all stored data for project %q (%s)? [y/N] ", *project, path)
		var resp string
		fmt.Scanln(&resp)
		if strings.ToLower(strings.TrimSpace(resp)) != "y" {
			fmt.Println("aborted.")
			return
		}
	}
	if err := os.Remove(path); err != nil {
		fatal(err)
	}
	fmt.Printf("[+] reset project %q — stored data deleted.\n", *project)
}

func cmdExport(args []string) {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	project := fs.String("project", "", "project name (required)")
	format := fs.String("format", "json", "output format: json, csv, or sarif")
	output := fs.String("o", "", "output file path (default: findings.<ext>)")
	fs.Parse(args)

	if *project == "" {
		fmt.Fprintln(os.Stderr, "usage: snitch export --project NAME [-format json|csv|sarif] [-o path]")
		os.Exit(1)
	}

	writers := map[string]func(io.Writer, *store.Workspace) error{
		"json":  export.JSON,
		"csv":   export.FindingsCSV,
		"sarif": export.SARIF,
	}
	write, ok := writers[strings.ToLower(*format)]
	if !ok {
		fatal(fmt.Errorf("unknown format %q (use json, csv, or sarif)", *format))
	}

	out := *output
	if out == "" {
		out = "findings." + strings.ToLower(*format)
	}

	ws, err := store.Open(dbPath(*project), *project)
	if err != nil {
		fatal(err)
	}

	f, err := os.Create(out)
	if err != nil {
		fatal(err)
	}
	defer f.Close()
	if err := write(f, ws); err != nil {
		fatal(err)
	}
	fmt.Printf("[+] Exported %d finding(s) to %s\n", len(ws.AllFindings()), out)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "[!] %v\n", err)
	os.Exit(1)
}

// firstLine trims a possibly multi-line error (ffuf embeds captured tool
// output) down to its first line for the compact warning summary.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i != -1 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
