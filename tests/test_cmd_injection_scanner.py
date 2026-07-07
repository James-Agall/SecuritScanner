import responses as responses_lib

from cmd_injection_scanner import CommandInjectionScanner


def make_asset(url):
    return {"url": url, "status_code": 200, "is_html": True, "headers": {}}


class TestCommandInjectionScanner:
    @responses_lib.activate
    def test_detects_marker_in_response(self, enforcer):
        scanner = CommandInjectionScanner(enforcer)
        html = '<form method="POST" action="/ping"><input type="text" name="target" value="127.0.0.1"></form>'
        responses_lib.add(responses_lib.GET, "https://localhost:5000/ping", body=html, status=200)

        def post_callback(request):
            if scanner.MARKER in request.body:
                return (200, {}, f"<pre>{scanner.MARKER}</pre>")
            return (200, {}, "<pre>normal output</pre>")

        responses_lib.add_callback(responses_lib.POST, "https://localhost:5000/ping", callback=post_callback)

        findings = scanner.scan([make_asset("https://localhost:5000/ping")])
        assert len(findings) == 1
        assert findings[0]["type"] == "OS Command Injection"
        assert findings[0]["vulnerable_param"] == "target"
        assert findings[0]["severity"] == "CRITICAL"

    @responses_lib.activate
    def test_no_marker_no_finding(self, enforcer):
        scanner = CommandInjectionScanner(enforcer)
        html = '<form method="POST" action="/ping"><input type="text" name="target" value="127.0.0.1"></form>'
        responses_lib.add(responses_lib.GET, "https://localhost:5000/ping", body=html, status=200)
        responses_lib.add(responses_lib.POST, "https://localhost:5000/ping", body="<pre>normal ping output</pre>", status=200)

        findings = scanner.scan([make_asset("https://localhost:5000/ping")])
        assert findings == []

    @responses_lib.activate
    def test_get_form_is_ignored(self, enforcer):
        scanner = CommandInjectionScanner(enforcer)
        html = '<form method="GET" action="/search"><input type="text" name="q"></form>'
        responses_lib.add(responses_lib.GET, "https://localhost:5000/search", body=html, status=200)

        findings = scanner.scan([make_asset("https://localhost:5000/search")])
        assert findings == []

    def test_build_form_data_preserves_other_fields(self, enforcer):
        from bs4 import BeautifulSoup
        scanner = CommandInjectionScanner(enforcer)
        soup = BeautifulSoup(
            '<form><input name="target" value="127.0.0.1"><input name="extra" value="keep-me"></form>',
            "html.parser",
        )
        form = soup.find("form")
        data = scanner._build_form_data(form, "target", "PAYLOAD")
        assert data == {"target": "PAYLOAD", "extra": "keep-me"}
