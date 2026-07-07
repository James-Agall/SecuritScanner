import responses as responses_lib

from xss_scanner import XSSScanner


def make_asset(url):
    return {"url": url, "status_code": 200, "is_html": True, "headers": {}}


class TestXSSScanner:
    @responses_lib.activate
    def test_detects_reflected_payload(self, enforcer):
        assets = [make_asset("https://localhost:5000/search?q=hello")]
        scanner = XSSScanner(enforcer)

        def callback(request):
            import urllib.parse
            qs = urllib.parse.urlparse(request.url).query
            params = urllib.parse.parse_qs(qs)
            q_val = params.get("q", [""])[0]
            return (200, {}, f"<h1>Results for: {q_val}</h1>")

        responses_lib.add_callback(
            responses_lib.GET, "https://localhost:5000/search", callback=callback,
            content_type="text/html",
        )

        findings = scanner.scan(assets)
        assert len(findings) == 1
        assert findings[0]["type"] == "Reflected Cross-Site Scripting (XSS)"
        assert findings[0]["vulnerable_param"] == "q"
        assert findings[0]["severity"] == "HIGH"

    @responses_lib.activate
    def test_no_reflection_no_finding(self, enforcer):
        assets = [make_asset("https://localhost:5000/search?q=hello")]
        scanner = XSSScanner(enforcer)
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/search",
            body="<h1>Nothing dangerous here</h1>", status=200, content_type="text/html",
        )
        findings = scanner.scan(assets)
        assert findings == []

    def test_urls_without_query_params_are_skipped(self, enforcer):
        scanner = XSSScanner(enforcer)
        assets = [make_asset("https://localhost:5000/about")]
        findings = scanner.scan(assets)
        assert findings == []

    @responses_lib.activate
    def test_out_of_scope_param_value_is_skipped(self, enforcer):
        # A payload value that would push the request out of scope should
        # simply be skipped via enforcer.check(), not raise.
        scanner = XSSScanner(enforcer)
        assets = [make_asset("https://evil.com/search?q=hello")]
        findings = scanner.scan(assets)
        assert findings == []

    def test_deduplicates_by_url_and_param(self, enforcer):
        scanner = XSSScanner(enforcer)
        vulns = [
            {"url": "https://localhost:5000/search?q=1", "vulnerable_param": "q", "type": "x"},
            {"url": "https://localhost:5000/search?q=1", "vulnerable_param": "q", "type": "x"},
        ]
        assert len(scanner._deduplicate(vulns)) == 1
