# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A from-scratch Python web security scanner (crawler + passive header analysis + active XSS/SQLi probing +
directory fuzzing + SQLite persistence + HTML report generation). `local_target.py` is a small intentionally
vulnerable Flask app used as the scan target during development/testing.

## Running

Dependencies are in `requirements.txt` (runtime) and `requirements-dev.txt` (+ pytest/ruff/mypy/httpx),
installed into `venv/`. Tests, linting, and type checking all run via `pytest`, `ruff check .`, and `mypy .`
(see CONTRIBUTING.md).

Typical local CLI workflow — run the vulnerable target in one terminal, then the scanner in another:

```bash
python local_target.py    # starts Flask app on https://localhost:5000
python main.py             # crawls + scans localhost:5000, writes to scanner.db, opens an HTML report
```

`main.py` is a single top-level script, not a CLI with arguments — the target URL and scan config
(`roe_config`) are hardcoded at the bottom of the file. It builds `roe_config`, then delegates the actual
crawl+scan+persist+report work to `scan_runner.run_scan_pipeline()` (see below).

There is also a REST API exposing the same pipeline over HTTP, and a React frontend that talks to it:

```bash
uvicorn api.app:app --reload    # http://localhost:8000/docs for interactive OpenAPI docs
cd frontend && npm run dev      # http://localhost:5173, expects the API at http://localhost:8000
```

`POST /scans` kicks off `run_scan_pipeline()` as a FastAPI `BackgroundTasks` job and returns immediately
with `status=pending`; poll `GET /scans/{id}` until `status` reaches `completed`/`failed`.

`Dockerfile` builds one image with no fixed `ENTRYPOINT` (CMD is the whole command, freely replaceable) so
it can serve any of the three roles; `docker-compose.yml` wires up `target` (the vulnerable app, port 5000),
`scanner` (the CLI, one-shot, shares `target`'s network namespace since `main.py`'s target is hardcoded),
and `api` (FastAPI, port 8000, reaches `target` via Docker DNS as `https://target:5000` — since that
resolves to a private Docker-internal IP, requests scanning it need `"allow_local_testing": true` in the
`POST /scans` body). `scanner` and `api` share a named volume mounted at `/app` so `scanner.db`/reports
persist and are visible to both.

## Architecture

`scan_runner.run_scan_pipeline()` wires together the fixed pipeline below; both `main.py` (CLI, under
`if __name__ == "__main__":`) and the FastAPI background task in `api/routers/scans.py` call this same
function, so there is exactly one implementation of "run a full scan":

1. **`enforcer.ScopeEnforcer`** — a rules-of-engagement (ROE) gate built from `roe_config` (allowed domains,
   CIDRs, ports, excluded paths, `allow_local_testing`). Every single outbound HTTP request in the codebase
   must go through `enforcer.safe_http_request(url, enforcer)`, which itself calls `enforcer.check(url)`
   before connecting. This is the SSRF/scope-creep guardrail — new scanners/fuzzers must reuse this
   function rather than calling `requests` directly. `_check_ip_resolution` blocks private/loopback/
   link-local IPs unless `allow_local_testing` or an explicit CIDR allows them.
2. **`crawler.HTMLCrawler`** — BFS crawl from a seed URL (bounded by `max_pages`), respecting the enforcer
   on every URL before visiting. Extracts links from `<a href>`, `<form action>`, `<iframe src>`. Produces a
   list of "asset" dicts (`url`, `status_code`, `is_html`, `headers`, `links_found`) — this asset list is the
   shared data structure every downstream analyzer/scanner consumes.
3. **`analyzer.SecurityHeaderAnalyzer`** — passive check: diffs each asset's response headers against
   `REQUIRED_HEADERS` (HSTS, CSP, X-Frame-Options, etc.) and flags verbose `Server` headers. No network calls.
4. **`xss_scanner.XSSScanner`** / **`sqli_scanner.SQLiScanner`** — active scanners. Both filter the asset
   list down to URLs containing `?`, re-inject payloads into each query parameter one at a time via
   `safe_http_request`, and check the response for reflection (XSS) or DB error strings (SQLi).
5. **`fuzzer.DirectoryFuzzer`** — active scanner: takes the base origin from the first crawled asset and
   requests each path in a hardcoded `wordlist` (`.env`, `.git/config`, `admin`, etc.), flagging 200s as HIGH
   and 403s as MEDIUM.
6. **`database.py`** — raw `sqlite3` against `scanner.db` (two tables: `scans`, `vulnerabilities`). Each
   scanner call site in `scan_runner.py` calls `save_vulnerability(scan_id, vuln)` per finding after printing
   it — persistence is not automatic inside the scanner classes themselves. `save_scan()`/`update_scan_status()`
   write; `get_scan()`/`get_all_scans()`/`get_vulnerabilities_for_scan()`/`delete_scan()` read (the API's
   read side) — `get_scan`/`get_all_scans` include a `vulnerability_count` via a `LEFT JOIN`.
7. **`reporter.generate_html_report(scan_id=None, open_browser=True)`** — with no `scan_id`, reads the most
   recent scan (CLI default, since `scan_runner.py` now always passes its own `scan_id` explicitly this is
   effectively the same scan); with an explicit `scan_id` (the API's report-download endpoint), targets that
   scan specifically. Renders an HTML report (`report_<scan_id>.html`), generates a PDF via `pdfkit`/
   `wkhtmltopdf`, and — only when `open_browser=True` (the CLI default; the API always passes `False`, since
   auto-opening a browser on the server makes no sense for an HTTP client) — opens both in the browser via
   `webbrowser.open`.
8. **`api/`** — a FastAPI app (`api/app.py`) exposing the same pipeline over REST: `POST /scans` runs
   `scan_runner.run_scan_pipeline()` as a `BackgroundTasks` job and returns immediately with
   `status=pending`; `GET /scans`, `GET /scans/{id}`, `DELETE /scans/{id}`, `GET /scans/{id}/vulnerabilities`,
   and `GET /scans/{id}/report?format=html|pdf` cover the rest of the read/delete/report surface. Routes live
   in `api/routers/scans.py`, request/response shapes in `api/schemas.py`. CORS is open for local dev origins
   (`CORS_ORIGINS` env var), which the `frontend/` dev server (`http://localhost:5173`) relies on.
9. **`frontend/`** — a Vite + React + TypeScript + Tailwind dashboard, entirely separate from the Python
   package (own `package.json`, not part of the Docker backend image — see `.dockerignore`). `src/api.ts` is
   the single Axios client plus the `Scan`/`Vulnerability` types mirroring `api/schemas.py`; `src/pages/`
   holds the two routed views (`Dashboard` = scan list + new-scan form, `ScanDetail` = one scan's status,
   report links, and findings), both polling their `GET` endpoint every 3s while a scan is `pending`/`running`.
   No state management library — plain `useState`/`useEffect` per page, since there are only two.

### Conventions to preserve when extending

- **Vulnerability dict shape** is the common contract between scanners, `scan_runner.py`'s printing loop, and
  `database.save_vulnerability`: `type`, `severity` (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`), `url`,
  `vulnerable_param` (or `"N/A"`), `payload_used`, `description`, `remediation` — typed as the `Vulnerability`
  TypedDict in `database.py`. New scanners should return findings in this shape.
- Every scanner/fuzzer class takes an `enforcer: ScopeEnforcer` in its constructor and exposes a single
  `scan(assets) -> List[Dict]` method operating on the crawler's asset list.
- Each scanner implements its own `_deduplicate()` — keyed differently per scanner (by `(url, param)`,
  by `url`, or by `(type, domain)`), since duplicate semantics differ per vulnerability class.
- All outbound requests must go through `enforcer.safe_http_request`, never `requests` directly — it also
  handles redirect-following and WAF/bot-protection (403/406/429) detection/logging.

### Known rough edges (do not silently "fix" without being asked — some are intentional for the local dev flow)

- `local_target.py`'s `/user` route is deliberately SQL-injectable (raw f-string interpolation, raw
  exception messages returned) — it exists to give the SQLi scanner something to find.
- `reporter.generate_html_report` builds HTML via string formatting with values pulled straight from
  `scanner.db` and interpolated into the template without escaping.
