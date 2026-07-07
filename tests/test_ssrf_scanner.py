import responses as responses_lib

from ssrf_scanner import SSRFScanner


def make_asset(url):
    return {"url": url, "status_code": 200, "is_html": True, "headers": {}}


class TestSSRFScanner:
    def test_empty_assets_returns_empty(self, enforcer):
        scanner = SSRFScanner(enforcer)
        assert scanner.scan([]) == []

    @responses_lib.activate
    def test_detects_server_fetching_itself(self, enforcer):
        scanner = SSRFScanner(enforcer)
        assets = [
            make_asset("https://localhost:5000/"),
            make_asset("https://localhost:5000/fetch-data?url=https://example.com"),
        ]
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/fetch-data",
            body="<h1>Welcome to the local target</h1>", status=200,
        )
        findings = scanner.scan(assets)
        assert len(findings) == 1
        assert findings[0]["type"] == "Server-Side Request Forgery (SSRF)"
        assert findings[0]["vulnerable_param"] == "url"
        assert findings[0]["payload_used"] == "https://localhost:5000/"

    @responses_lib.activate
    def test_non_matching_param_name_is_skipped(self, enforcer):
        scanner = SSRFScanner(enforcer)
        assets = [make_asset("https://localhost:5000/search?q=hello")]
        findings = scanner.scan(assets)
        assert findings == []

    @responses_lib.activate
    def test_no_marker_in_response_no_finding(self, enforcer):
        scanner = SSRFScanner(enforcer)
        assets = [make_asset("https://localhost:5000/fetch-data?url=https://example.com")]
        responses_lib.add(responses_lib.GET, "https://localhost:5000/fetch-data", body="some other content", status=200)
        findings = scanner.scan(assets)
        assert findings == []
