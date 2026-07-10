# SecuritScanner

[![CI](https://github.com/James-Agall/SecuritScanner/actions/workflows/ci.yml/badge.svg)](https://github.com/James-Agall/SecuritScanner/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.14-blue)
![Coverage](https://img.shields.io/badge/coverage-93%25-brightgreen)
![Tests](https://img.shields.io/badge/tests-215%20passing-brightgreen)

A from-scratch Python web application security scanner: crawler, passive header
analysis, 14 active vulnerability scanners, SQLite persistence, and HTML/PDF
report generation — built without wrapping an existing tool (no ZAP/Burp
under the hood).

> **Authorized testing only.** This scanner sends live HTTP requests, injects
> payloads, and attempts authentication bypass. Every request is gated through
> a scope enforcer (`enforcer.py`) that blocks anything outside an explicit
> allowlist of domains/CIDRs/ports, but the tool is still only meant to be
> pointed at targets you own or are explicitly authorized to test — such as
> the bundled `local_target.py`, an intentionally vulnerable Flask app used
> as the default scan target in development.

## Why this exists

Most "scanner" side projects are thin wrappers around `requests` + a payload
list. This one is built around a single non-negotiable rule instead: **every
outbound HTTP call, from every scanner, must pass through one scope-checking
choke point.** That constraint shapes the whole architecture — see
[Architecture](#architecture) below — and is enforced by tests, not just
convention.

## Features

| Category | Modules |
|---|---|
| **Recon / passive** | BFS crawler, security header analysis (HSTS, CSP, X-Frame-Options, verbose `Server` headers) |
| **Injection** | Reflected XSS, error-based SQL injection, OS command injection, XXE |
| **Access control** | IDOR (authenticated), directory/file fuzzing (`.env`, `.git/config`, admin paths, ...) |
| **Request forgery** | CSRF (missing token detection), SSRF, open redirect |
| **Transport / session** | SSL/TLS certificate & config checks, cookie security flags (`Secure`, `HttpOnly`, `SameSite`) |
| **Misconfiguration** | CORS policy analysis |
| **Evasion** | WAF/bot-protection detection and stealth request pacing (`evasion.py`) |

Every scanner returns findings in one common shape (type, severity, URL,
vulnerable parameter, payload, description, remediation), persisted to
SQLite and rendered into a single HTML/PDF report per scan.

## Architecture

```mermaid
flowchart TD
    CLI([main.py CLI<br/>hardcoded target + roe_config]) --> RUNNER
    API([POST /scans<br/>api/routers/scans.py]) -->|BackgroundTasks| RUNNER

    RUNNER[scan_runner.run_scan_pipeline] --> ENF

    subgraph Guard["Scope Guard"]
        ENF[enforcer.ScopeEnforcer<br/>ROE: allowed domains / CIDRs / ports]
    end

    ENF -->|safe_http_request only| CRAWL[crawler.HTMLCrawler<br/>BFS from seed URL]
    CRAWL -->|assets: url, status, headers, links| FANOUT

    subgraph FANOUT["Passive + active scanners (all consume the same asset list)"]
        A1[analyzer.SecurityHeaderAnalyzer]
        A2[xss_scanner / sqli_scanner]
        A3[cmd_injection_scanner / xxe_scanner]
        A4[csrf_scanner / ssrf_scanner / open_redirect_scanner]
        A5[idor_scanner / cookie_scanner / cors_scanner]
        A6[fuzzer.DirectoryFuzzer / ssl_scanner]
    end

    ENF -.every outbound call.-> FANOUT
    FANOUT -->|vulnerability dicts| DB[(database.py<br/>scanner.db: scans, vulnerabilities)]
    DB --> REPORT[reporter.generate_html_report<br/>scan_id-specific or most recent]
    REPORT --> OUT[report_&lt;id&gt;.html / .pdf]
    DB -.GET /scans, /scans/id, /scans/id/vulnerabilities.-> API
```

`scan_runner.run_scan_pipeline()` is the single implementation of the pipeline; both `main.py` (CLI, target
URL and `roe_config` hardcoded, not CLI flags) and the FastAPI app (`api/`, see [Web API](#web-api) below)
call it — so the CLI and the web API can never drift apart. See `CLAUDE.md` for the full per-module
breakdown and the conventions new scanners must follow.

## Quickstart

### Local (venv)

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements-dev.txt

# terminal 1 - the intentionally vulnerable target
python local_target.py          # https://localhost:5000

# terminal 2 - crawl + scan + report
python main.py
```

PDF report generation additionally requires the `wkhtmltopdf` system binary
on your `PATH` (https://wkhtmltopdf.org/); without it, the scanner still
produces the HTML report and logs a warning instead of the PDF.

### Docker

One image (`Dockerfile`, no fixed `ENTRYPOINT`) serves all three roles below — `docker-compose.yml` just
gives each service its own `command:`. The image runs the full test suite as a build step, so it won't
build if a test fails.

```bash
docker compose up --build
```

This starts three services on one Docker network:
- `target` — `local_target.py`, the vulnerable Flask app, published on host port `5000`
- `scanner` — the CLI (`python main.py`), one-shot; shares `target`'s network namespace so its hardcoded
  `https://localhost:5000` resolves correctly without touching source
- `api` — the FastAPI backend, published on host port `8000`; reaches `target` via Docker DNS as
  `https://target:5000` (see [Web API](#web-api) below for why `allow_local_testing: true` is required
  when targeting it)

`scanner` and `api` share a named volume mounted at `/app`, so `scanner.db` and reports persist across
restarts and are visible to both. Grab results directly:

```bash
docker cp $(docker compose ps -q scanner):/app/scanner.db .
```

or from the running API:

```bash
curl http://localhost:8000/scans
```

## Web API

A REST API (`api/app.py`, FastAPI) exposes the same pipeline over HTTP, in front of a future React
frontend. `python main.py` keeps working exactly as before — the API is an additional interface, not a
replacement.

```bash
uvicorn api.app:app --reload
```

Interactive OpenAPI docs: `http://localhost:8000/docs`. `POST /scans` runs the full crawl + 14-scanner
pipeline as a background task and returns immediately (`status=pending`); poll `GET /scans/{id}` until
`status` reaches `completed`/`failed`.

| Method | Path | Description |
|---|---|---|
| `POST` | `/scans` | Start a scan (`target_url` required; scope/creds optional, see `/docs`) |
| `GET` | `/scans` | List all scans, most recent first, with `vulnerability_count` |
| `GET` | `/scans/{id}` | Get one scan |
| `DELETE` | `/scans/{id}` | Delete a scan and its findings |
| `GET` | `/scans/{id}/vulnerabilities` | List findings for a scan |
| `GET` | `/scans/{id}/report?format=html\|pdf` | Download the report (404 if scan not found, 409 if still running) |

```bash
curl -X POST http://localhost:8000/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://localhost:5000/", "allow_local_testing": true, "test_username": "admin", "test_password": "admin123"}'
```

## Testing & quality

```bash
pytest              # 215 tests, 93% branch coverage (pyproject.toml config)
ruff check .         # lint
mypy .               # static typing (application modules; tests/ excluded)
```

All three run in CI on every push/PR to `main` (`.github/workflows/ci.yml`),
alongside a Docker build that re-validates the test-gated image.

## Project structure

```
enforcer.py              ROE / SSRF guardrail — every request goes through safe_http_request()
crawler.py                BFS crawler, produces the shared "asset" list
analyzer.py                passive security-header analysis
xss_scanner.py, sqli_scanner.py, cmd_injection_scanner.py, xxe_scanner.py
csrf_scanner.py, ssrf_scanner.py, open_redirect_scanner.py
idor_scanner.py, cookie_scanner.py, cors_scanner.py
fuzzer.py, ssl_scanner.py  active vulnerability scanners
evasion.py                 WAF/bot-protection evasion helpers
database.py                 sqlite3 persistence + read API (scans, vulnerabilities)
reporter.py                 HTML/PDF report generation
scan_runner.py              shared pipeline (crawl + all scanners + persistence + report) — used by both main.py and api/
local_target.py            intentionally vulnerable Flask app used as the default scan target
main.py                     CLI entrypoint (hardcoded target + roe_config), delegates to scan_runner.py
api/                        FastAPI app: app.py (CORS, lifespan), routers/scans.py, schemas.py — see Web API above
tests/                      215 tests incl. two live-server end-to-end integration tests
```

## Known limitations

- `main.py` is a fixed pipeline script, not a CLI — the target URL and
  `roe_config` (allowed domains/ports, credentials, stealth mode) are edited
  directly in the file. The web API (`api/`) does accept `target_url` and
  scope/credentials per request, since that's the whole point of exposing it
  over HTTP.
- `local_target.py` and `reporter.py` contain deliberately unsafe patterns
  (raw SQL interpolation, unescaped HTML templating) that exist specifically
  to give the scanners something to find — see `CLAUDE.md`.
- The named volume `scanner_data` (shared by `scanner`/`api` in
  `docker-compose.yml`) is auto-seeded from the image's `/app` the first
  time it's created, but a later `docker compose build` won't update code
  already sitting in an existing volume — run `docker compose down -v`
  before rebuilding after a source change.
