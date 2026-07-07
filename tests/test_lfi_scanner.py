import responses as responses_lib

from lfi_scanner import LFIScanner


def make_asset(url):
    return {"url": url, "status_code": 200, "is_html": True, "headers": {}}


class TestLFIScanner:
    @responses_lib.activate
    def test_detects_linux_marker(self, enforcer):
        scanner = LFIScanner(enforcer)
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/view-doc",
            body="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin",
            status=200,
        )
        findings = scanner.scan([make_asset("https://localhost:5000/view-doc?filename=welcome.txt")])
        assert len(findings) == 1
        assert findings[0]["type"] == "Path Traversal / Local File Inclusion (LFI)"
        assert findings[0]["vulnerable_param"] == "filename"
        assert findings[0]["severity"] == "CRITICAL"

    @responses_lib.activate
    def test_detects_windows_marker(self, enforcer):
        scanner = LFIScanner(enforcer)
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/view-doc",
            body="[extensions]\r\nfor 16-bit app support",
            status=200,
        )
        findings = scanner.scan([make_asset("https://localhost:5000/view-doc?filename=welcome.txt")])
        assert len(findings) == 1

    @responses_lib.activate
    def test_clean_response_no_finding(self, enforcer):
        scanner = LFIScanner(enforcer)
        responses_lib.add(responses_lib.GET, "https://localhost:5000/view-doc", body="Welcome to the doc!", status=200)
        findings = scanner.scan([make_asset("https://localhost:5000/view-doc?filename=welcome.txt")])
        assert findings == []

    def test_non_file_param_is_skipped(self, enforcer):
        scanner = LFIScanner(enforcer)
        findings = scanner.scan([make_asset("https://localhost:5000/search?q=hello")])
        assert findings == []

    def test_deduplicates_by_url_and_param(self, enforcer):
        scanner = LFIScanner(enforcer)
        vulns = [
            {"url": "https://localhost:5000/view-doc?filename=a", "vulnerable_param": "filename"},
            {"url": "https://localhost:5000/view-doc?filename=a", "vulnerable_param": "filename"},
        ]
        assert len(scanner._deduplicate(vulns)) == 1
