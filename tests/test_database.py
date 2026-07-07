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
