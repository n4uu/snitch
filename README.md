# snitch

[![CI](https://github.com/n4uu/snitch/actions/workflows/ci.yml/badge.svg)](https://github.com/n4uu/snitch/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/n4uu/snitch)](https://goreportcard.com/report/github.com/n4uu/snitch)

**The recon tool that snitches on your attack surface.**

`snitch` chains subfinder → naabu → httpx → Nmap → Nuclei → ffuf → katana into
one correlated, deduplicated, re-runnable recon pipeline — and then *watches*
your targets: run it on a schedule and it alerts a webhook (Discord/Slack/
anything) the moment something **new** appears. One static Go binary, no runtime
dependencies, no infra.

Most recon tooling is either heavy (spin up Docker + Postgres + a web stack) or
fire-and-forget (scan once, diff by hand). `snitch` is the lightweight middle
ground: a single binary you can `cron` and forget, that tells you what changed.

## Why it's different

| | snitch | typical bash orchestrator | reNgine-style platform |
|---|---|---|---|
| Deploy | one static binary | scripts + tool deps | Docker + Postgres + web |
| Re-runnable + dedup | ✅ built in | ✗ | ✅ |
| **Diff + webhook alerts** | ✅ `monitor` | ✗ | partial |
| Correlated per-host report | ✅ MD + HTML | ✗ | ✅ |
| Actionable findings (remediation/CVE/curl) | ✅ | ✗ | varies |

## Features

- **Full discovery chain**: subfinder widens a domain into its subdomains,
  naabu fast-scans them for open ports, httpx probes for live HTTP(S) (title,
  tech, status), Nmap adds service/version depth, Nuclei + ffuf run against the
  confirmed web targets, and katana crawls them for linked endpoints. Every
  stage is optional (`--skip-subfinder`, `--skip-naabu`, `--skip-katana`, …).
- **Injection testing**: the parameterized URLs katana discovers — **filtered
  to the target and its subdomains** so active payloads never reach a
  third-party host — are fed to dalfox (XSS) and crlfuzz (CRLF) automatically,
  and, opt-in with `--sqli`, to sqlmap. Confirmed hits land in the report as
  priority findings with a reproduction command. sqlmap is off by default and
  capped (`--sqli-max`) because it actively exploits.
- **Chained, not parallel-blind**: discovery drives what gets tested — only
  live web services reach Nuclei and ffuf, no HTTP templates fired at an SSH
  port. Findings from every tool are correlated back onto one asset per
  host:port (nmap's service + httpx's title/tech merged into a single row).
- **`monitor` mode with alerts**: re-scan on a schedule, diff against everything
  seen before, and POST an alert to a Discord/Slack/generic webhook when a new
  service or finding shows up. Auto-detects the webhook type from the URL.
- **Deduplication with a real dedup key**: re-run next week and you see what's
  *new*, not the same 200 rows — verified under `go test -race` with 20
  concurrent goroutines writing at once.
- **Concurrent ffuf**: every web target fuzzed in its own goroutine, bounded by
  a worker pool (`-workers`, default 5).
- **Live progress**: each tool's output streams line by line with elapsed-time
  banners and heartbeats — no more staring at a frozen terminal.
- **Actionable reports, not data dumps**: findings split into *priority*
  (critical/high/medium) and *informational*, each priority finding expanded
  with description, remediation, CVE/CVSS, references and a reproduction `curl`
  command — plus a "how to act on this report" triage section.
- **Interactive TUI**: `snitch tui --project X` opens a Bubble Tea terminal UI
  to page through subdomains, services, findings (colour-coded by severity) and
  crawled paths, with a detail pane showing a finding's remediation and repro.
- **One-command flow**: `scan --report html --open` runs the chain and pops the
  finished report open in your browser.
- **Export** to JSON, CSV (a flat findings sheet), or **SARIF 2.1.0** — the
  latter uploads straight into GitHub code scanning or DefectDojo, with
  severity mapped to `security-severity` so it buckets correctly.

## Installation

snitch is a single Go binary that shells out to well-known recon tools. **You
don't need all of them** — any that are missing are skipped with a warning, so
even just `nmap`, `httpx`, `nuclei` and `ffuf` gives you a working scan.

### On Kali / Debian (one command)

```bash
git clone https://github.com/n4uu/snitch.git
cd snitch
./install.sh        # installs EVERY tool: apt packages + the few via go install
make build
./snitch version
```

Then point it at a target you own or are authorised to test:

```bash
./snitch scan yourdomain.com --project demo --report html --open
```

`install.sh` is short and readable (have a look before running it). It `apt
install`s the packaged tools — nmap, ffuf, sqlmap, subfinder, httpx, naabu,
nuclei — links ProjectDiscovery's httpx, then `go install`s the three that
aren't in apt (katana, dalfox, crlfuzz) and fetches nuclei's templates. Anything
that fails is simply skipped by snitch at scan time with a warning, so a partial
install still works.

### Other distros / building the tools from source

No apt? `make tools` installs every Go-based tool with `go install`. Heads-up:
this **compiles each from source and pulls a lot of dependencies** (nuclei and
katana are big), so it's slow — prefer precompiled packages when you can.

```bash
sudo apt install -y libpcap-dev   # naabu needs libpcap
make tools
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc && source ~/.bashrc
```

## Quickstart

```bash
# Full chain (flags can go in any order — target position is normalized)
./snitch scan example.com --project acme --wordlist /usr/share/wordlists/dirb/common.txt

# One shot: scan, then write and open the HTML report automatically
./snitch scan example.com --project acme --wordlist wl.txt --report html --open

# Add active SQL-injection testing with sqlmap (opt-in, tests crawled param URLs)
./snitch scan example.com --project acme --wordlist wl.txt --sqli

# Watch a target and get pinged on Discord/Slack when something new appears
./snitch monitor example.com --project acme --wordlist wl.txt \
    --notify https://discord.com/api/webhooks/XXX/YYY --interval 6h

# Or run one cycle from cron (no --interval); snitch stays quiet if nothing's new
./snitch monitor example.com --project acme --skip-ffuf --notify <webhook>

# Reports (-open launches it in your browser)
./snitch report --project acme -format html -o report.html -open

# Browse results interactively in the terminal
./snitch tui --project acme

# Status / history and machine-readable export (json | csv | sarif)
./snitch status --project acme
./snitch export --project acme -format sarif -o findings.sarif
```

## Why Go, and why not SQLite

Go's standard SQLite driver needs CGO, which defeats the "ship one static
binary" advantage that's the whole reason to use Go for a CLI like this.
Storage is a JSON file guarded by a mutex — plenty for a project's recon data
(thousands of rows, not millions) and no database to stand up. The scan
pipeline, storage and alerts use only the standard library; the only
third-party code is the pure-Go Bubble Tea stack behind `tui`. Everything still
compiles to a single CGO-free static binary.

## Testing

```bash
go vet ./...
gofmt -l .          # should print nothing
go test -race ./... # concurrency test + webhook delivery test
```

`integration_test.go` runs the whole parse → dedup → report pipeline against
the sample files in `samples/` — no live nmap/nuclei/ffuf needed.

## Architecture

```
cmd/snitch/main.go        # CLI: scan / monitor / report / status / export
internal/store/           # JSON-backed workspace, dedup, concurrency-safe
internal/parsers/         # subfinder/naabu/httpx/nmap/nuclei/ffuf/katana/dalfox/sqlmap -> structs
internal/orchestrator/    # Chains the tools, runs ffuf concurrently, live output
internal/report/          # Actionable Markdown + HTML reports
internal/notify/          # Discord / Slack / generic webhook alerts
internal/export/          # JSON / CSV / SARIF exporters
internal/tui/             # Bubble Tea interactive results browser
samples/                  # Sample tool output for testing
integration_test.go       # End-to-end pipeline test
```

## Roadmap

- [x] Webhook alerts + `monitor` mode
- [x] Full discovery chain: subfinder → naabu → httpx → nmap → nuclei → ffuf → katana
- [x] Injection testing: dalfox (XSS), crlfuzz (CRLF), opt-in sqlmap (SQLi)
- [x] Interactive TUI (Bubble Tea) for browsing results
- [x] Exporters: JSON, CSV, SARIF 2.1.0
- [ ] Scan profiles + in/out-of-scope rules

## Legal

For use only against systems you own or are explicitly authorized to test.
