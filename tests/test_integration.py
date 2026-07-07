"""
Flagship end-to-end integration test: runs the real local_target.py Flask
app on a real (ephemeral) TCP port via werkzeug's server, then drives the
real crawler and several real scanners against it -- no mocking, no
`responses` stubs. This is the closest thing to actually running
`python local_target.py` + `python main.py` that a CI box can do safely.
"""
import threading

import pytest
from werkzeug.serving import make_server

from cookie_scanner import CookieScanner
from crawler import HTMLCrawler
from enforcer import ScopeEnforcer
from idor_scanner import IDORScanner
from lfi_scanner import LFIScanner
from sqli_scanner import SQLiScanner
from ssrf_scanner import SSRFScanner
from xss_scanner import XSSScanner


@pytest.fixture(scope="module")
def live_server(tmp_path_factory):
    workdir = tmp_path_factory.mktemp("live_target")
    import os
    original_cwd = os.getcwd()
    os.chdir(workdir)

    (workdir / "welcome.txt").write_text("hello from the live integration server")

    import local_target
    local_target.init_user_db()
    local_target.app.testing = False

    server = make_server("127.0.0.1", 0, local_target.app, threaded=True)
    port = server.server_port

    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    yield f"http://127.0.0.1:{port}"

    server.shutdown()
    thread.join(timeout=5)
    os.chdir(original_cwd)


@pytest.fixture(scope="module")
def live_enforcer(live_server):
    import urllib.parse
    port = urllib.parse.urlparse(live_server).port
    return ScopeEnforcer({
        "allowed_domains": ["127.0.0.1"],
        "allowed_ports": [port],
        "allow_local_testing": True,
        "stealth_mode": False,
    })


@pytest.fixture(scope="module")
def crawled_assets(live_server, live_enforcer):
    crawler = HTMLCrawler(seed_url=f"{live_server}/", enforcer=live_enforcer, max_pages=20, delay=0)
    return crawler.crawl()


class TestLiveCrawl:
    def test_crawl_discovers_multiple_real_pages(self, crawled_assets):
        urls = {a["url"] for a in crawled_assets}
        assert any(u.endswith("/") for u in urls)
        assert any("/login" in u for u in urls)
        assert len(crawled_assets) > 3

    def test_redirect_endpoint_captured_with_raw_status(self, live_server, live_enforcer):
        # Confirms the crawler redirect fix works against a REAL server, not
        # just mocked responses: the /redirect page's own 302 must be stored
        # as its own asset, separate from wherever it points.
        crawler = HTMLCrawler(seed_url=f"{live_server}/redirect?next=/dashboard", enforcer=live_enforcer, max_pages=5, delay=0)
        assets = crawler.crawl()
        redirect_asset = next(a for a in assets if "/redirect" in a["url"])
        assert redirect_asset["status_code"] == 302


class TestLiveScanners:
    def test_xss_scanner_finds_real_reflection(self, crawled_assets, live_enforcer):
        # /search is never linked from the homepage, so the crawler can't
        # reach it; the real reflection here comes from Python's own
        # FileNotFoundError/MissingSchema messages echoing the payload back
        # verbatim in /view-doc and /fetch-data's exception handlers.
        findings = XSSScanner(live_enforcer).scan(crawled_assets)
        flagged_params = {f["vulnerable_param"] for f in findings}
        assert {"filename", "url"}.issubset(flagged_params)

    def test_sqli_scanner_finds_real_error(self, crawled_assets, live_enforcer):
        findings = SQLiScanner(live_enforcer).scan(crawled_assets)
        assert any(f["vulnerable_param"] == "id" for f in findings)

    def test_lfi_scanner_finds_real_file_read(self, crawled_assets, live_enforcer):
        findings = LFIScanner(live_enforcer).scan(crawled_assets)
        assert any(f["vulnerable_param"] == "filename" for f in findings)

    def test_ssrf_scanner_finds_server_fetching_itself(self, crawled_assets, live_enforcer):
        findings = SSRFScanner(live_enforcer).scan(crawled_assets)
        assert any(f["type"] == "Server-Side Request Forgery (SSRF)" for f in findings)

    def test_idor_scanner_logs_in_and_finds_real_idor(self, live_server, live_enforcer, crawled_assets):
        scanner = IDORScanner(live_enforcer, "admin", "admin123")
        assert scanner.login(f"{live_server}/") is True
        findings = scanner.scan(crawled_assets)
        assert any(f["type"] == "Insecure Direct Object Reference (IDOR)" for f in findings)

    def test_cookie_scanner_catches_the_real_insecure_session_cookie(self, live_enforcer, crawled_assets):
        scanner = CookieScanner(live_enforcer, "admin", "admin123")
        findings = scanner.scan(crawled_assets)
        session_id_findings = [f for f in findings if f["vulnerable_param"] == "session_id"]
        assert len(session_id_findings) == 3
        assert all(f["severity"] == "HIGH" for f in session_id_findings)
