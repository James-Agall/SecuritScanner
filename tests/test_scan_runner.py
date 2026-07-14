"""
Integration test for scan_runner.run_scan_pipeline - the shared pipeline used
by both the CLI (main.py) and the FastAPI background task. Runs the real
local_target.py app on a real ephemeral port (same pattern as
test_integration.py) and drives the actual function main.py and the API
both call, end to end: crawl -> all 14 scanners -> persistence -> status.
"""
import os
import threading
import urllib.parse

import pytest
from werkzeug.serving import make_server

import database
import scan_runner
from scan_runner import run_scan_pipeline


@pytest.fixture(scope="module")
def live_server(tmp_path_factory):
    workdir = tmp_path_factory.mktemp("live_target_runner")
    original_cwd = os.getcwd()
    os.chdir(workdir)

    (workdir / "welcome.txt").write_text("hello from the scan_runner integration test")

    import local_target
    local_target.init_user_db()
    local_target.app.testing = False

    server = make_server("127.0.0.1", 0, local_target.app, threaded=True)
    port = server.server_port

    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    database.init_db()

    yield f"http://127.0.0.1:{port}"

    server.shutdown()
    thread.join(timeout=5)
    os.chdir(original_cwd)


@pytest.fixture
def roe_config(live_server):
    port = urllib.parse.urlparse(live_server).port
    return {
        "allowed_domains": ["127.0.0.1"],
        "allowed_cidrs": [],
        "allowed_ports": [port],
        "excluded_paths": [],
        "allow_local_testing": True,
        "stealth_mode": False,
        "proxy_url": "",
        "test_username": "admin",
        "test_password": "admin123",
    }


class TestRunScanPipeline:
    def test_full_pipeline_persists_findings_completes_and_writes_report(
        self, live_server, roe_config, monkeypatch
    ):
        monkeypatch.setattr("reporter.generate_pdf_report", lambda html, pdf: None)
        scan_id = database.save_scan(live_server, status="pending")
        assert scan_id is not None

        run_scan_pipeline(scan_id, f"{live_server}/", roe_config, max_pages=20, delay=0, open_browser=False)

        record = database.get_scan(scan_id)
        assert record is not None
        assert record["status"] == "completed"
        assert record["vulnerability_count"] > 0

        vuln_types = {v["type"] for v in database.get_vulnerabilities_for_scan(scan_id)}
        assert any("IDOR" in t for t in vuln_types)
        assert os.path.exists(f"report_{scan_id}.html")

    def test_pipeline_without_credentials_skips_idor(self, live_server, roe_config):
        roe_config = dict(roe_config, test_username=None, test_password=None)
        scan_id = database.save_scan(live_server, status="pending")
        assert scan_id is not None

        run_scan_pipeline(scan_id, f"{live_server}/", roe_config, max_pages=20, delay=0, generate_report=False)

        vulns = database.get_vulnerabilities_for_scan(scan_id)
        assert not any("IDOR" in v["type"] for v in vulns)
        record = database.get_scan(scan_id)
        assert record is not None
        assert record["status"] == "completed"

    def test_phase_transitions_happen_in_order(self, live_server, roe_config, monkeypatch):
        phases: list[str] = []
        monkeypatch.setattr(
            scan_runner, "update_scan_phase", lambda scan_id, phase: phases.append(phase)
        )

        scan_id = database.save_scan(live_server, status="pending")
        assert scan_id is not None

        run_scan_pipeline(scan_id, f"{live_server}/", roe_config, max_pages=20, delay=0, generate_report=False)

        assert phases == [
            "crawling",
            "header_analysis",
            "cookie_scan",
            "xss_scan",
            "sqli_scan",
            "directory_fuzzing",
            "csrf_scan",
            "ssl_scan",
            "command_injection_scan",
            "idor_scan",
            "lfi_scan",
            "ssrf_scan",
            "cors_scan",
            "xxe_scan",
            "open_redirect_scan",
        ]

    def test_pipeline_marks_scan_failed_on_exception(self, live_server, roe_config, monkeypatch):
        def boom(self, assets):
            raise RuntimeError("scanner exploded")

        monkeypatch.setattr(scan_runner.XSSScanner, "scan", boom)

        scan_id = database.save_scan(live_server, status="pending")
        assert scan_id is not None

        with pytest.raises(RuntimeError):
            run_scan_pipeline(scan_id, f"{live_server}/", roe_config, max_pages=20, delay=0, generate_report=False)

        record = database.get_scan(scan_id)
        assert record is not None
        assert record["status"] == "failed"
