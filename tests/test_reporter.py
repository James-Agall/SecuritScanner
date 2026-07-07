import os
import sqlite3
import pytest

import database
import reporter


@pytest.fixture
def isolated_scan_db(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    database.init_db()
    return tmp_path


@pytest.fixture(autouse=True)
def no_browser(monkeypatch):
    """Never actually open a browser window during tests."""
    monkeypatch.setattr(reporter.webbrowser, "open", lambda url: None)


class TestGeneratePdfReport:
    def test_calls_pdfkit_with_expected_options(self, monkeypatch, tmp_path):
        captured = {}

        def fake_from_file(html_path, pdf_path, options):
            captured["html_path"] = html_path
            captured["pdf_path"] = pdf_path
            captured["options"] = options

        monkeypatch.setattr(reporter.pdfkit, "from_file", fake_from_file)
        reporter.generate_pdf_report(str(tmp_path / "in.html"), str(tmp_path / "out.pdf"))

        assert captured["options"]["page-size"] == "A4"
        assert captured["options"]["encoding"] == "UTF-8"
        assert "enable-local-file-access" in captured["options"]

    def test_oserror_is_swallowed_not_raised(self, monkeypatch, tmp_path, capsys):
        def raise_oserror(*args, **kwargs):
            raise OSError("wkhtmltopdf not found")

        monkeypatch.setattr(reporter.pdfkit, "from_file", raise_oserror)
        # Must not raise
        reporter.generate_pdf_report(str(tmp_path / "in.html"), str(tmp_path / "out.pdf"))
        captured = capsys.readouterr()
        assert "wkhtmltopdf" in captured.out


class TestGenerateHtmlReport:
    def test_no_scans_prints_message_and_returns(self, isolated_scan_db, capsys):
        reporter.generate_html_report()
        captured = capsys.readouterr()
        assert "No scans found" in captured.out

    def test_writes_html_report_with_vulnerability(self, isolated_scan_db, monkeypatch):
        monkeypatch.setattr(reporter, "generate_pdf_report", lambda html, pdf: None)

        scan_id = database.save_scan("https://localhost:5000")
        database.save_vulnerability(scan_id, {
            "type": "Reflected XSS",
            "severity": "HIGH",
            "url": "https://localhost:5000/search?q=1",
            "vulnerable_param": "q",
            "payload_used": "<script>alert(1)</script>",
            "description": "desc",
            "remediation": "fix it",
        })

        reporter.generate_html_report()

        report_path = isolated_scan_db / f"report_{scan_id}.html"
        assert report_path.exists()
        content = report_path.read_text(encoding="utf-8")
        assert "Reflected XSS" in content
        assert "q" in content
        assert "HIGH" in content

    def test_no_vulnerabilities_shows_clean_message(self, isolated_scan_db, monkeypatch):
        monkeypatch.setattr(reporter, "generate_pdf_report", lambda html, pdf: None)
        scan_id = database.save_scan("https://localhost:5000")

        reporter.generate_html_report()

        report_path = isolated_scan_db / f"report_{scan_id}.html"
        content = report_path.read_text(encoding="utf-8")
        assert "No vulnerabilities were found" in content

    def test_uses_most_recent_scan(self, isolated_scan_db, monkeypatch):
        monkeypatch.setattr(reporter, "generate_pdf_report", lambda html, pdf: None)
        database.save_scan("https://old-target.com")
        newest_id = database.save_scan("https://newest-target.com")

        reporter.generate_html_report()

        report_path = isolated_scan_db / f"report_{newest_id}.html"
        content = report_path.read_text(encoding="utf-8")
        assert "newest-target.com" in content

    def test_pdf_generated_flag_triggers_second_browser_open(self, isolated_scan_db, monkeypatch):
        opened_urls = []
        monkeypatch.setattr(reporter.webbrowser, "open", lambda url: opened_urls.append(url))

        def fake_generate_pdf(html_path, pdf_path):
            # Simulate a successful pdfkit run by actually creating the file.
            with open(pdf_path, "wb") as f:
                f.write(b"%PDF-1.4 fake")

        monkeypatch.setattr(reporter, "generate_pdf_report", fake_generate_pdf)
        database.save_scan("https://localhost:5000")

        reporter.generate_html_report()

        assert any(url.endswith(".pdf") for url in opened_urls)
        assert any(url.endswith(".html") for url in opened_urls)
