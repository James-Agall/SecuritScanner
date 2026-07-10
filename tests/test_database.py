import sqlite3

import pytest

import database


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    """database.py hardcodes the relative path 'scanner.db', so isolate via chdir."""
    monkeypatch.chdir(tmp_path)
    database.init_db()
    return tmp_path / "scanner.db"


class TestInitDb:
    def test_creates_expected_tables(self, isolated_db):
        conn = sqlite3.connect(isolated_db)
        c = conn.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in c.fetchall()}
        conn.close()
        assert {"scans", "vulnerabilities"}.issubset(tables)

    def test_idempotent(self, isolated_db):
        # Calling init_db() twice must not raise (CREATE TABLE IF NOT EXISTS)
        database.init_db()


class TestSaveScan:
    def test_returns_incrementing_id(self, isolated_db):
        first_id = database.save_scan("https://localhost:5000")
        second_id = database.save_scan("https://localhost:5000")
        assert second_id == first_id + 1

    def test_persists_target_url_and_status(self, isolated_db):
        scan_id = database.save_scan("https://example.com")
        conn = sqlite3.connect(isolated_db)
        c = conn.cursor()
        c.execute("SELECT target_url, status FROM scans WHERE id = ?", (scan_id,))
        row = c.fetchone()
        conn.close()
        assert row == ("https://example.com", "Completed")


class TestSaveVulnerability:
    def test_persists_all_fields(self, isolated_db):
        scan_id = database.save_scan("https://localhost:5000")
        vuln = {
            "type": "Reflected XSS",
            "severity": "HIGH",
            "url": "https://localhost:5000/search?q=1",
            "vulnerable_param": "q",
            "payload_used": "<script>alert(1)</script>",
            "description": "desc",
            "remediation": "fix it",
        }
        database.save_vulnerability(scan_id, vuln)

        conn = sqlite3.connect(isolated_db)
        c = conn.cursor()
        c.execute(
            "SELECT scan_id, vuln_type, severity, url, parameter, payload, description, remediation "
            "FROM vulnerabilities WHERE scan_id = ?", (scan_id,)
        )
        row = c.fetchone()
        conn.close()
        assert row == (
            scan_id, "Reflected XSS", "HIGH", "https://localhost:5000/search?q=1",
            "q", "<script>alert(1)</script>", "desc", "fix it",
        )

    def test_missing_optional_fields_default_to_empty_string(self, isolated_db):
        scan_id = database.save_scan("https://localhost:5000")
        vuln = {"type": "Info Disclosure", "severity": "LOW", "url": "https://localhost:5000/"}
        database.save_vulnerability(scan_id, vuln)

        conn = sqlite3.connect(isolated_db)
        c = conn.cursor()
        c.execute("SELECT parameter, payload, description, remediation FROM vulnerabilities WHERE scan_id = ?", (scan_id,))
        row = c.fetchone()
        conn.close()
        assert row == ("", "", "", "")


class TestUpdateScanStatus:
    def test_updates_status(self, isolated_db):
        scan_id = database.save_scan("https://localhost:5000", status="pending")
        database.update_scan_status(scan_id, "running")

        conn = sqlite3.connect(isolated_db)
        c = conn.cursor()
        c.execute("SELECT status FROM scans WHERE id = ?", (scan_id,))
        row = c.fetchone()
        conn.close()
        assert row == ("running",)


class TestGetScan:
    def test_returns_none_for_unknown_id(self, isolated_db):
        assert database.get_scan(9999) is None

    def test_returns_scan_with_vulnerability_count(self, isolated_db):
        scan_id = database.save_scan("https://localhost:5000")
        database.save_vulnerability(scan_id, {
            "type": "XSS", "severity": "HIGH", "url": "https://localhost:5000/",
            "description": "d", "remediation": "r",
        })
        database.save_vulnerability(scan_id, {
            "type": "SQLi", "severity": "CRITICAL", "url": "https://localhost:5000/",
            "description": "d", "remediation": "r",
        })

        record = database.get_scan(scan_id)
        assert record == {
            "id": scan_id,
            "target_url": "https://localhost:5000",
            "start_time": record["start_time"],
            "status": "Completed",
            "vulnerability_count": 2,
        }

    def test_zero_vulnerabilities_counts_as_zero_not_one(self, isolated_db):
        # LEFT JOIN with COUNT(v.id) must not count a phantom NULL row.
        scan_id = database.save_scan("https://localhost:5000")
        record = database.get_scan(scan_id)
        assert record["vulnerability_count"] == 0


class TestGetAllScans:
    def test_empty_when_no_scans(self, isolated_db):
        assert database.get_all_scans() == []

    def test_returns_most_recent_first(self, isolated_db):
        first_id = database.save_scan("https://a.example.com")
        second_id = database.save_scan("https://b.example.com")

        scans = database.get_all_scans()
        assert [s["id"] for s in scans] == [second_id, first_id]


class TestGetVulnerabilitiesForScan:
    def test_empty_for_scan_with_no_findings(self, isolated_db):
        scan_id = database.save_scan("https://localhost:5000")
        assert database.get_vulnerabilities_for_scan(scan_id) == []

    def test_returns_only_this_scans_vulnerabilities(self, isolated_db):
        scan_a = database.save_scan("https://a.example.com")
        scan_b = database.save_scan("https://b.example.com")
        database.save_vulnerability(scan_a, {
            "type": "XSS", "severity": "HIGH", "url": "https://a.example.com/",
            "vulnerable_param": "q", "payload_used": "<script>", "description": "d", "remediation": "r",
        })
        database.save_vulnerability(scan_b, {
            "type": "SQLi", "severity": "CRITICAL", "url": "https://b.example.com/",
            "description": "d", "remediation": "r",
        })

        vulns = database.get_vulnerabilities_for_scan(scan_a)
        assert len(vulns) == 1
        assert vulns[0]["type"] == "XSS"
        assert vulns[0]["scan_id"] == scan_a
        assert vulns[0]["vulnerable_param"] == "q"


class TestDeleteScan:
    def test_returns_false_for_unknown_id(self, isolated_db):
        assert database.delete_scan(9999) is False

    def test_deletes_scan_and_cascades_vulnerabilities(self, isolated_db):
        scan_id = database.save_scan("https://localhost:5000")
        database.save_vulnerability(scan_id, {
            "type": "XSS", "severity": "HIGH", "url": "https://localhost:5000/",
            "description": "d", "remediation": "r",
        })

        assert database.delete_scan(scan_id) is True
        assert database.get_scan(scan_id) is None
        assert database.get_vulnerabilities_for_scan(scan_id) == []

    def test_does_not_delete_other_scans_vulnerabilities(self, isolated_db):
        scan_a = database.save_scan("https://a.example.com")
        scan_b = database.save_scan("https://b.example.com")
        database.save_vulnerability(scan_b, {
            "type": "SQLi", "severity": "CRITICAL", "url": "https://b.example.com/",
            "description": "d", "remediation": "r",
        })

        database.delete_scan(scan_a)

        assert database.get_scan(scan_b) is not None
        assert len(database.get_vulnerabilities_for_scan(scan_b)) == 1
