# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A from-scratch Python web security scanner (crawler + passive header analysis + active XSS/SQLi probing +
directory fuzzing + SQLite persistence + HTML report generation). `local_target.py` is a small intentionally
vulnerable Flask app used as the scan target during development/testing.

## Running

There is no requirements.txt/setup.py — dependencies (`flask`, `requests`, `beautifulsoup4`) are installed
ad hoc into `venv/`. There is no test suite, linter, or build step in this repo currently.

Typical local workflow — run the vulnerable target in one terminal, then the scanner in another:

```bash
python local_target.py    # starts Flask app on http://localhost:5000
python main.py             # crawls + scans localhost:5000, writes to scanner.db, opens an HTML report
```

`main.py` is a single top-level script, not a CLI with arguments — the target URL and scan config
(`roe_config`) are hardcoded at the bottom of the file.

## Architecture

`main.py` wires together a fixed pipeline, run once per invocation:

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
   scanner call site in `main.py` calls `save_vulnerability(scan_id, vuln)` per finding after printing it —
   persistence is not automatic inside the scanner classes themselves.
7. **`reporter.generate_html_report()`** — reads the *most recent* scan from `scanner.db` (not the current
   `scan_id` passed around in `main.py`), renders an HTML report (`report_<scan_id>.html`), and opens it in
   the browser via `webbrowser.open`.

### Conventions to preserve when extending

- **Vulnerability dict shape** is the common contract between scanners, `main.py`'s printing loop, and
  `database.save_vulnerability`: `type`, `severity` (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`), `url`,
  `vulnerable_param` (or `"N/A"`), `payload_used`, `description`, `remediation`. New scanners should return
  findings in this shape.
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
