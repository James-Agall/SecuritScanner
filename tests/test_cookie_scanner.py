import responses as responses_lib

from cookie_scanner import CookieScanner


def make_asset(url):
    return {"url": url, "status_code": 200, "is_html": True, "headers": {}}


class TestCookieScannerPassive:
    @responses_lib.activate
    def test_missing_all_flags_flagged_as_medium_for_generic_cookie(self, enforcer):
        scanner = CookieScanner(enforcer)
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/",
            status=200,
            headers={"Set-Cookie": "tracking_id=abc123; Path=/"},
        )
        findings = scanner.scan([make_asset("https://localhost:5000/")])
        types = {f["type"] for f in findings}
        assert types == {
            "Cookie Missing 'Secure' Flag",
            "Cookie Missing 'HttpOnly' Flag",
            "Cookie Missing 'SameSite' Attribute",
        }
        assert all(f["severity"] == "MEDIUM" for f in findings)

    @responses_lib.activate
    def test_session_like_cookie_name_upgrades_to_high(self, enforcer):
        scanner = CookieScanner(enforcer)
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/",
            status=200,
            headers={"Set-Cookie": "auth_token=abc123; Path=/"},
        )
        findings = scanner.scan([make_asset("https://localhost:5000/")])
        assert all(f["severity"] == "HIGH" for f in findings)

    @responses_lib.activate
    def test_fully_secured_cookie_not_flagged(self, enforcer):
        scanner = CookieScanner(enforcer)
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/",
            status=200,
            headers={"Set-Cookie": "session_id=abc123; Secure; HttpOnly; SameSite=Strict"},
        )
        findings = scanner.scan([make_asset("https://localhost:5000/")])
        assert findings == []

    @responses_lib.activate
    def test_samesite_none_still_flagged(self, enforcer):
        scanner = CookieScanner(enforcer)
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/",
            status=200,
            headers={"Set-Cookie": "session_id=abc123; Secure; HttpOnly; SameSite=None"},
        )
        findings = scanner.scan([make_asset("https://localhost:5000/")])
        assert len(findings) == 1
        assert findings[0]["type"] == "Cookie Missing 'SameSite' Attribute"

    @responses_lib.activate
    def test_no_cookie_no_findings(self, enforcer):
        scanner = CookieScanner(enforcer)
        responses_lib.add(responses_lib.GET, "https://localhost:5000/", status=200)
        findings = scanner.scan([make_asset("https://localhost:5000/")])
        assert findings == []


class TestCookieScannerActiveLogin:
    @responses_lib.activate
    def test_reproduces_the_reported_bug_exact_cookie(self, enforcer):
        """
        Regression test for the exact scenario reported: POSTing valid
        credentials to /login must yield 3 HIGH findings for the
        deliberately-insecure session_id cookie set on the raw 302 response.
        """
        scanner = CookieScanner(enforcer, "admin", "admin123")
        responses_lib.add(
            responses_lib.POST, "https://localhost:5000/login",
            status=302,
            headers={
                "Location": "/profile?user_id=1",
                "Set-Cookie": "session_id=super_secret_session_token_123; Path=/; SameSite=None",
            },
        )
        findings = scanner.scan([make_asset("https://localhost:5000/login")])

        session_id_findings = [f for f in findings if f["vulnerable_param"] == "session_id"]
        assert len(session_id_findings) == 3
        assert all(f["severity"] == "HIGH" for f in session_id_findings)
        types = {f["type"] for f in session_id_findings}
        assert types == {
            "Cookie Missing 'Secure' Flag",
            "Cookie Missing 'HttpOnly' Flag",
            "Cookie Missing 'SameSite' Attribute",
        }

    @responses_lib.activate
    def test_no_credentials_configured_skips_active_phase(self, enforcer, capsys):
        scanner = CookieScanner(enforcer)  # no username/password
        findings = scanner.scan([make_asset("https://localhost:5000/login")])
        assert findings == []
        assert "No test credentials configured" in capsys.readouterr().out

    def test_login_path_matching_ignores_query_and_trailing_slash(self, enforcer):
        scanner = CookieScanner(enforcer, "admin", "admin123")
        import urllib.parse
        assert urllib.parse.urlparse("https://localhost:5000/login/").path.rstrip('/').lower().endswith('/login')
        assert urllib.parse.urlparse("https://localhost:5000/LOGIN").path.rstrip('/').lower().endswith('/login')


class TestCookieScannerDeduplicate:
    def test_dedupes_by_url_param_and_type(self, enforcer):
        scanner = CookieScanner(enforcer)
        vulns = [
            {"url": "https://localhost:5000/", "vulnerable_param": "session_id", "type": "Cookie Missing 'Secure' Flag"},
            {"url": "https://localhost:5000/", "vulnerable_param": "session_id", "type": "Cookie Missing 'Secure' Flag"},
            {"url": "https://localhost:5000/", "vulnerable_param": "session_id", "type": "Cookie Missing 'HttpOnly' Flag"},
        ]
        assert len(scanner._deduplicate(vulns)) == 2
