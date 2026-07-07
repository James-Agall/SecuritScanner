import responses as responses_lib

from cors_scanner import CORSScanner


def make_asset(url):
    return {"url": url, "status_code": 200, "is_html": True, "headers": {}}


class TestCORSScanner:
    @responses_lib.activate
    def test_reflected_origin_with_credentials_flagged(self, enforcer):
        scanner = CORSScanner(enforcer)
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/api/user-data",
            json={"username": "admin"}, status=200,
            headers={
                "Access-Control-Allow-Origin": "https://evil.com",
                "Access-Control-Allow-Credentials": "true",
            },
        )
        findings = scanner.scan([make_asset("https://localhost:5000/api/user-data")])
        assert len(findings) == 1
        assert findings[0]["type"] == "CORS Misconfiguration - Arbitrary Origin Reflection"
        assert findings[0]["severity"] == "HIGH"

    @responses_lib.activate
    def test_no_credentials_flag_not_flagged(self, enforcer):
        scanner = CORSScanner(enforcer)
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/api/user-data",
            json={}, status=200,
            headers={"Access-Control-Allow-Origin": "https://evil.com"},
        )
        findings = scanner.scan([make_asset("https://localhost:5000/api/user-data")])
        assert findings == []

    @responses_lib.activate
    def test_no_cors_headers_not_flagged(self, enforcer):
        scanner = CORSScanner(enforcer)
        responses_lib.add(responses_lib.GET, "https://localhost:5000/", json={}, status=200)
        findings = scanner.scan([make_asset("https://localhost:5000/")])
        assert findings == []

    def test_out_of_scope_asset_skipped(self, enforcer):
        scanner = CORSScanner(enforcer)
        findings = scanner.scan([make_asset("https://evil.com/")])
        assert findings == []

    def test_deduplicates_by_url(self, enforcer):
        scanner = CORSScanner(enforcer)
        vulns = [{"url": "https://localhost:5000/api"}, {"url": "https://localhost:5000/api"}]
        assert len(scanner._deduplicate(vulns)) == 1
