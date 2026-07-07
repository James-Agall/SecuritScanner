# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-07-07

### Added
- 14 scanner modules: XSS, SQL Injection, Command Injection, LFI, SSRF, XXE,
  IDOR, CSRF, CORS, Open Redirect, Cookie Security, SSL/TLS, Header Analysis,
  and Directory Fuzzing.
- BFS web crawler with redirect tracking.
- Central Enforcer pattern for SSRF prevention, scope validation, and
  stealth evasion.
- Stealth/Evasion engine (User-Agent rotation, human-like delays, proxy
  support).
- HTML and PDF report generation.
- Comprehensive test suite (177 tests, 93% coverage).
- Docker containerization (multi-stage build, non-root runtime).
- docker-compose orchestration for scanner + vulnerable target.
- GitHub Actions CI/CD pipeline (ruff, mypy, pytest, Docker build).
- Full type hinting (mypy clean) and linting (ruff clean).
- Professional README with architecture diagram.

### Fixed
- `main.py` import side effect: all execution logic is now properly guarded
  by `if __name__ == "__main__":`, so importing the module no longer runs a
  full scan as a side effect.
- `enforcer.py` malformed URL edge case: URLs like `http://:8080/` (where
  `urlparse().hostname` is `None`) are now cleanly denied instead of raising
  an unhandled exception.

### Security
- Central Enforcer prevents SSRF by blocking requests to internal IPs
  (127.0.0.1, 10.x.x.x, 192.168.x.x, 169.254.x.x).
- All HTTP requests pass through scope validation and stealth features.
