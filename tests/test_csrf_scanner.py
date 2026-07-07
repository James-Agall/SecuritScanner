import responses as responses_lib

from csrf_scanner import CSRFScanner


def make_asset(url):
    return {"url": url, "status_code": 200, "is_html": True, "headers": {}}


class TestCSRFScanner:
    @responses_lib.activate
    def test_post_form_without_token_flagged(self, enforcer):
        scanner = CSRFScanner(enforcer)
        html = '<form method="POST" action="/transfer"><input name="amount"></form>'
        responses_lib.add(responses_lib.GET, "https://localhost:5000/transfer", body=html, status=200, content_type="text/html")

        findings = scanner.scan([make_asset("https://localhost:5000/transfer")])
        assert len(findings) == 1
        assert findings[0]["type"] == "Missing CSRF Token on POST Form"
        assert findings[0]["vulnerable_param"] == "/transfer"

    @responses_lib.activate
    def test_post_form_with_token_not_flagged(self, enforcer):
        scanner = CSRFScanner(enforcer)
        html = '''
        <form method="POST" action="/transfer">
            <input type="hidden" name="csrf_token" value="abc123">
            <input name="amount">
        </form>
        '''
        responses_lib.add(responses_lib.GET, "https://localhost:5000/transfer", body=html, status=200, content_type="text/html")

        findings = scanner.scan([make_asset("https://localhost:5000/transfer")])
        assert findings == []

    @responses_lib.activate
    def test_get_form_is_ignored(self, enforcer):
        scanner = CSRFScanner(enforcer)
        html = '<form method="GET" action="/search"><input name="q"></form>'
        responses_lib.add(responses_lib.GET, "https://localhost:5000/search", body=html, status=200, content_type="text/html")

        findings = scanner.scan([make_asset("https://localhost:5000/search")])
        assert findings == []

    def test_non_html_assets_are_skipped(self, enforcer):
        scanner = CSRFScanner(enforcer)
        asset = {"url": "https://localhost:5000/data.json", "is_html": False, "headers": {"Content-Type": "application/json"}}
        findings = scanner.scan([asset])
        assert findings == []

    def test_has_csrf_token_matches_known_hints(self, enforcer):
        from bs4 import BeautifulSoup
        scanner = CSRFScanner(enforcer)
        soup = BeautifulSoup('<form><input type="hidden" name="_token" value="x"></form>', "html.parser")
        form = soup.find("form")
        assert scanner._has_csrf_token(form) is True
