# Contributing to SecuritScanner

Thanks for taking a look at this project. It's a from-scratch Python web
security scanner (crawler + passive header analysis + 14 active vulnerability
scanners + SQLite persistence + HTML/PDF reporting) — see `CLAUDE.md` for
the full architecture writeup before making non-trivial changes.

## Development setup

```bash
git clone https://github.com/James-Agall/SecuritScanner.git
cd SecuritScanner

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements-dev.txt   # runtime deps + pytest/ruff/mypy
```

PDF report generation additionally needs the `wkhtmltopdf` system binary on
your `PATH` (https://wkhtmltopdf.org/) — optional for development, since the
reporter tests mock `pdfkit` and don't need the real binary.

## Running the target

The scanner is developed against `local_target.py`, a small intentionally
vulnerable Flask app bundled in this repo. It generates its own self-signed
cert on first run:

```bash
python local_target.py     # -> https://localhost:5000
```

In a second terminal, run the scanner against it:

```bash
python main.py
```

`main.py` is a fixed pipeline script, not a CLI — the target URL and
`roe_config` (allowed domains/ports, credentials, stealth mode) are set
directly at the bottom of the file, not passed as arguments.

## Running tests, type checks, and lint

```bash
pytest                          # full suite, coverage config lives in pyproject.toml
mypy .                          # application modules (tests/ is excluded, see pyproject.toml)
ruff check .                    # lint, whole repo
```

All three run in CI (`.github/workflows/ci.yml`) on every push/PR to `main`,
alongside a `docker build` that re-runs the test suite as a build step.

## Pull request process

- Run `pytest`, `mypy .`, and `ruff check .` locally before opening a PR —
  all three must be clean.
- Don't drop test coverage. If you add a code path, add a test for it;
  `pytest --cov=. --cov-report=term-missing` will show exactly which lines
  are untested.
- Keep PRs focused on one change. A new scanner, a bug fix, and a docs
  update are three PRs, not one.
- Every scanner/fuzzer must route outbound requests through
  `enforcer.safe_http_request()` — never call `requests` directly. This is
  the project's SSRF/scope-creep guardrail and is treated as non-negotiable
  in review.
- Match the existing vulnerability dict shape (`type`, `severity`, `url`,
  `vulnerable_param`, `payload_used`, `description`, `remediation`) so new
  findings work with `database.save_vulnerability` and the reporter without
  extra glue code.

## Adding a new scanner

1. **Create the module** (`your_scanner.py`), with a class that takes an
   `enforcer: ScopeEnforcer` in `__init__` and exposes
   `scan(self, assets: list[Asset]) -> list[Vulnerability]` (import
   `Asset` from `crawler.py` and `Vulnerability` from `database.py` — both
   are `TypedDict`s documenting the exact shape everything else expects).
   Route every request through `safe_http_request(url, self.enforcer)`, and
   implement your own `_deduplicate()` — duplicate semantics differ per
   vulnerability class, so there's no shared base implementation to inherit.
2. **Use the enforcer, never `requests` directly.** Call
   `self.enforcer.check(url)` (or just let `safe_http_request` do it) before
   touching the network, so scans stay inside the configured
   domains/CIDRs/ports.
3. **Wire it into `main.py`**: import the class, instantiate it with the
   shared `enforcer`, call `.scan(results)`, and add a findings block that
   prints results and calls `save_vulnerability(scan_id, vuln)` per finding,
   following the pattern of the existing scanner blocks.
4. **Write tests** in `tests/test_your_scanner.py` — mock `safe_http_request`
   or use `responses`/`monkeypatch` against a real or fake asset list, cover
   both the "vulnerability found" and "clean" paths, and confirm
   `_deduplicate()` collapses repeated findings the way you intend.
