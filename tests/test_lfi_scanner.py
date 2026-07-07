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

    @responses_lib.activate
    def test_detects_marker_only_reachable_via_deep_traversal(self, enforcer):
        """
        Regression test for a real bug: the scanner used to cap out at 5
        '../' levels, which is nowhere near enough to escape a deeply nested
        working directory (e.g. pytest's tmp_path on Windows sits 8 levels
        under the drive root: C:\\Users\\<user>\\AppData\\Local\\Temp\\
        pytest-of-<user>\\pytest-<N>\\<name>). A server whose win.ini is only
        reachable via 8+ levels of traversal must still be caught.
        """
        scanner = LFIScanner(enforcer)

        def callback(request):
            import urllib.parse
            qs = urllib.parse.urlparse(request.url).query
            filename = urllib.parse.unquote(urllib.parse.parse_qs(qs)["filename"][0])
            depth = filename.count("../") + filename.count("..\\")
            if depth >= 8 and "win.ini" in filename.lower():
                return (200, {}, "[fonts]\r\n[extensions]\r\n[mci extensions]")
            return (200, {}, "No such file or directory")

        responses_lib.add_callback(
            responses_lib.GET, "https://localhost:5000/view-doc", callback=callback,
        )
        findings = scanner.scan([make_asset("https://localhost:5000/view-doc?filename=welcome.txt")])
        assert len(findings) == 1
        payload = findings[0]["payload_used"]
        assert payload.count("../") >= 8 or payload.count("..\\") >= 8

    def test_payload_depths_cover_deeply_nested_working_directories(self, enforcer):
        scanner = LFIScanner(enforcer)
        linux_payloads = [p for p in scanner.payloads if "etc/passwd" in p and "%00" not in p]
        windows_backslash_payloads = [p for p in scanner.payloads if "win.ini" in p and "\\" in p]

        assert max(p.count("../") for p in linux_payloads) >= 8
        assert max(p.count("..\\") for p in windows_backslash_payloads) >= 8
