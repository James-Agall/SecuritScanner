import responses as responses_lib

from idor_scanner import IDORScanner


def make_asset(url):
    return {"url": url, "status_code": 200, "is_html": True, "headers": {}}


class TestIDORScannerLogin:
    @responses_lib.activate
    def test_successful_login_captures_cookies_and_authenticated_url(self, enforcer):
        scanner = IDORScanner(enforcer, "admin", "admin123")
        responses_lib.add(
            responses_lib.POST, "https://localhost:5000/login",
            status=200, headers={"Set-Cookie": "session_id=abc123"},
        )
        ok = scanner.login("https://localhost:5000/")
        assert ok is True
        assert scanner.session_cookies is not None
        assert scanner.authenticated_url == "https://localhost:5000/login"

    @responses_lib.activate
    def test_invalid_credentials_returns_false(self, enforcer):
        scanner = IDORScanner(enforcer, "admin", "wrongpass")
        responses_lib.add(responses_lib.POST, "https://localhost:5000/login", body="Invalid credentials", status=200)
        assert scanner.login("https://localhost:5000/") is False
        assert scanner.session_cookies is None

    def test_blocked_by_scope_returns_false(self, enforcer):
        scanner = IDORScanner(enforcer, "admin", "admin123")
        assert scanner.login("https://evil.com/") is False

    @responses_lib.activate
    def test_network_error_returns_false(self, enforcer):
        scanner = IDORScanner(enforcer, "admin", "admin123")
        # No responses registered -> requests raises ConnectionError
        assert scanner.login("https://localhost:5000/") is False


class TestIDORScannerScan:
    def test_not_logged_in_skips_scan(self, enforcer):
        scanner = IDORScanner(enforcer, "admin", "admin123")
        findings = scanner.scan([make_asset("https://localhost:5000/profile?user_id=1")])
        assert findings == []

    @responses_lib.activate
    def test_detects_accessible_other_user_data(self, enforcer):
        scanner = IDORScanner(enforcer, "admin", "admin123")
        scanner.session_cookies = {"session_id": "abc123"}

        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/profile",
            body="<h1>Profile</h1><p>Username: user1</p>", status=200,
        )
        findings = scanner.scan([make_asset("https://localhost:5000/profile?user_id=1")])
        assert len(findings) == 1
        assert findings[0]["type"] == "Insecure Direct Object Reference (IDOR)"
        assert findings[0]["payload_used"] == "user_id=2"

    @responses_lib.activate
    def test_access_denied_response_not_flagged(self, enforcer):
        scanner = IDORScanner(enforcer, "admin", "admin123")
        scanner.session_cookies = {"session_id": "abc123"}
        responses_lib.add(responses_lib.GET, "https://localhost:5000/profile", body="Access Denied", status=200)

        findings = scanner.scan([make_asset("https://localhost:5000/profile?user_id=1")])
        assert findings == []

    @responses_lib.activate
    def test_non_numeric_param_is_skipped(self, enforcer):
        scanner = IDORScanner(enforcer, "admin", "admin123")
        scanner.session_cookies = {"session_id": "abc123"}
        findings = scanner.scan([make_asset("https://localhost:5000/search?q=hello")])
        assert findings == []

    @responses_lib.activate
    def test_authenticated_url_added_even_without_query_assets(self, enforcer):
        scanner = IDORScanner(enforcer, "admin", "admin123")
        scanner.session_cookies = {"session_id": "abc123"}
        scanner.authenticated_url = "https://localhost:5000/profile?user_id=1"

        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/profile",
            body="<h1>Profile</h1><p>Username: user1</p>", status=200,
        )
        # No assets contain a '?' -> only the authenticated_url should be tested.
        findings = scanner.scan([{"url": "https://localhost:5000/", "status_code": 200, "is_html": True, "headers": {}}])
        assert len(findings) == 1
