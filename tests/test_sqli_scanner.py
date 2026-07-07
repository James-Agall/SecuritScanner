import responses as responses_lib

from sqli_scanner import SQLiScanner


def make_asset(url):
    return {"url": url, "status_code": 200, "is_html": True, "headers": {}}


class TestSQLiScanner:
    @responses_lib.activate
    def test_detects_sql_error_in_response(self, enforcer):
        scanner = SQLiScanner(enforcer)
        assets = [make_asset("https://localhost:5000/user?id=1")]
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/user",
            body="near \"'\": syntax error (sqlite3.OperationalError)",
            status=200,
        )
        findings = scanner.scan(assets)
        assert len(findings) == 1
        assert findings[0]["type"] == "Error-Based SQL Injection"
        assert findings[0]["vulnerable_param"] == "id"
        assert findings[0]["severity"] == "CRITICAL"

    @responses_lib.activate
    def test_clean_response_no_finding(self, enforcer):
        scanner = SQLiScanner(enforcer)
        assets = [make_asset("https://localhost:5000/user?id=1")]
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/user",
            body="admin", status=200,
        )
        findings = scanner.scan(assets)
        assert findings == []

    def test_urls_without_query_params_are_skipped(self, enforcer):
        scanner = SQLiScanner(enforcer)
        assets = [make_asset("https://localhost:5000/about")]
        findings = scanner.scan(assets)
        assert findings == []

    @responses_lib.activate
    def test_multiple_params_each_tested(self, enforcer):
        scanner = SQLiScanner(enforcer)
        assets = [make_asset("https://localhost:5000/user?id=1&name=bob")]
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/user",
            body="ok, no error here", status=200,
        )
        findings = scanner.scan(assets)
        # No SQL error keyword in the body, so no findings, but this exercises
        # the multi-param loop without raising.
        assert findings == []

    def test_deduplicates_by_url_and_param(self, enforcer):
        scanner = SQLiScanner(enforcer)
        vulns = [
            {"url": "https://localhost:5000/user?id=1", "vulnerable_param": "id"},
            {"url": "https://localhost:5000/user?id=1", "vulnerable_param": "id"},
        ]
        assert len(scanner._deduplicate(vulns)) == 1
