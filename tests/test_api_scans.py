"""
Tests the FastAPI layer's routing, validation, and DB wiring in isolation.
The background scan pipeline itself (crawl + 14 scanners against a real
target) is exercised end to end in tests/test_scan_runner.py against a live
server; here `run_scan_pipeline` is stubbed so these tests stay fast and
don't touch the network.
"""
import pytest
from fastapi.testclient import TestClient

import api.routers.scans as scans_module
import database
from api.app import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with TestClient(app) as c:
        yield c


@pytest.fixture
def stub_run_scan_pipeline(monkeypatch):
    """Replaces the real pipeline with one that just marks the scan completed,
    and records what it was called with for assertions."""
    calls = []

    def fake_run(scan_id, target_url, roe_config, *, max_pages=20, delay=0.1, generate_report=True, open_browser=True):
        calls.append({
            "scan_id": scan_id,
            "target_url": target_url,
            "roe_config": roe_config,
            "max_pages": max_pages,
            "generate_report": generate_report,
            "open_browser": open_browser,
        })
        database.update_scan_status(scan_id, "completed")

    monkeypatch.setattr(scans_module, "run_scan_pipeline", fake_run)
    return calls


class TestHealth:
    def test_health_ok(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestCreateScan:
    def test_returns_202_with_pending_status(self, client, stub_run_scan_pipeline):
        response = client.post("/scans", json={"target_url": "https://localhost:5000/"})
        assert response.status_code == 202
        body = response.json()
        assert body["target_url"] == "https://localhost:5000/"
        assert body["status"] == "pending"
        assert body["vulnerability_count"] == 0

        # By the time TestClient returns, the (stubbed) background task has
        # already run and moved the DB row past "pending".
        follow_up = client.get(f"/scans/{body['id']}")
        assert follow_up.json()["status"] == "completed"

    def test_derives_scope_from_target_url_when_not_specified(self, client, stub_run_scan_pipeline):
        client.post("/scans", json={"target_url": "https://localhost:5000/"})
        assert len(stub_run_scan_pipeline) == 1
        roe_config = stub_run_scan_pipeline[0]["roe_config"]
        assert roe_config["allowed_domains"] == ["localhost"]
        assert roe_config["allowed_ports"] == [5000]

    def test_explicit_scope_overrides_derived_defaults(self, client, stub_run_scan_pipeline):
        client.post("/scans", json={
            "target_url": "https://localhost:5000/",
            "allowed_domains": ["localhost", "127.0.0.1"],
            "allowed_ports": [5000, 8443],
        })
        roe_config = stub_run_scan_pipeline[0]["roe_config"]
        assert roe_config["allowed_domains"] == ["localhost", "127.0.0.1"]
        assert roe_config["allowed_ports"] == [5000, 8443]

    def test_max_pages_out_of_range_is_rejected(self, client):
        response = client.post("/scans", json={"target_url": "https://localhost:5000/", "max_pages": 0})
        assert response.status_code == 422

    def test_missing_target_url_is_rejected(self, client):
        response = client.post("/scans", json={})
        assert response.status_code == 422


class TestListAndGetScans:
    def test_list_empty_initially(self, client):
        assert client.get("/scans").json() == []

    def test_list_returns_most_recent_first(self, client, stub_run_scan_pipeline):
        first = client.post("/scans", json={"target_url": "https://a.example.com/"}).json()
        second = client.post("/scans", json={"target_url": "https://b.example.com/"}).json()

        scans = client.get("/scans").json()
        assert [s["id"] for s in scans] == [second["id"], first["id"]]

    def test_get_unknown_scan_is_404(self, client):
        response = client.get("/scans/9999")
        assert response.status_code == 404


class TestDeleteScan:
    def test_deletes_existing_scan(self, client, stub_run_scan_pipeline):
        created = client.post("/scans", json={"target_url": "https://localhost:5000/"}).json()

        response = client.delete(f"/scans/{created['id']}")
        assert response.status_code == 204
        assert client.get(f"/scans/{created['id']}").status_code == 404

    def test_deleting_unknown_scan_is_404(self, client):
        assert client.delete("/scans/9999").status_code == 404


class TestVulnerabilities:
    def test_404_for_unknown_scan(self, client):
        assert client.get("/scans/9999/vulnerabilities").status_code == 404

    def test_empty_list_when_no_findings(self, client, stub_run_scan_pipeline):
        created = client.post("/scans", json={"target_url": "https://localhost:5000/"}).json()
        response = client.get(f"/scans/{created['id']}/vulnerabilities")
        assert response.status_code == 200
        assert response.json() == []

    def test_returns_persisted_findings(self, client, stub_run_scan_pipeline):
        created = client.post("/scans", json={"target_url": "https://localhost:5000/"}).json()
        database.save_vulnerability(created["id"], {
            "type": "Reflected XSS",
            "severity": "HIGH",
            "url": "https://localhost:5000/search?q=1",
            "vulnerable_param": "q",
            "payload_used": "<script>alert(1)</script>",
            "description": "desc",
            "remediation": "fix it",
        })

        response = client.get(f"/scans/{created['id']}/vulnerabilities")
        assert response.status_code == 200
        [vuln] = response.json()
        assert vuln["type"] == "Reflected XSS"
        assert vuln["scan_id"] == created["id"]


class TestDownloadReport:
    def test_404_for_unknown_scan(self, client):
        assert client.get("/scans/9999/report").status_code == 404

    def test_409_while_scan_not_completed(self, client):
        scan_id = database.save_scan("https://localhost:5000", status="running")
        response = client.get(f"/scans/{scan_id}/report")
        assert response.status_code == 409

    def test_html_report_downloads_once_completed(self, client, stub_run_scan_pipeline):
        created = client.post("/scans", json={"target_url": "https://localhost:5000/"}).json()

        response = client.get(f"/scans/{created['id']}/report")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/html")

    def test_pdf_report_503_without_wkhtmltopdf(self, client, stub_run_scan_pipeline, monkeypatch):
        # Mock pdfkit.from_file to raise OSError, simulating the absence of wkhtmltopdf.
        # This validates the 503 error path regardless of whether wkhtmltopdf is
        # actually installed in the environment running the tests.
        import pdfkit

        def fake_from_file(*args, **kwargs):
            raise OSError("No wkhtmltopdf executable found")

        monkeypatch.setattr(pdfkit, "from_file", fake_from_file)

        created = client.post("/scans", json={"target_url": "https://localhost:5000/"}).json()
        response = client.get(f"/scans/{created['id']}/report", params={"format": "pdf"})
        assert response.status_code == 503

    def test_invalid_format_is_rejected(self, client, stub_run_scan_pipeline):
        created = client.post("/scans", json={"target_url": "https://localhost:5000/"}).json()
        response = client.get(f"/scans/{created['id']}/report", params={"format": "docx"})
        assert response.status_code == 422
