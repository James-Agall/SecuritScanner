import responses as responses_lib

from xxe_scanner import XXEScanner


def make_asset(url):
    return {"url": url, "status_code": 200, "is_html": True, "headers": {}}


class TestXXEScanner:
    @responses_lib.activate
    def test_detects_linux_leak(self, enforcer):
        scanner = XXEScanner(enforcer)
        html = '<form method="POST" action="/parse-xml"></form>'
        responses_lib.add(responses_lib.GET, "https://localhost:5000/", body=html, status=200, content_type="text/html")
        responses_lib.add(
            responses_lib.POST, "https://localhost:5000/parse-xml",
            body="root:x:0:0:root:/root:/bin/bash", status=200,
        )
        findings = scanner.scan([make_asset("https://localhost:5000/")])
        assert len(findings) == 1
        assert findings[0]["type"] == "XML External Entity (XXE) Injection"
        assert findings[0]["vulnerable_param"] == "XML Body"
        assert findings[0]["severity"] == "CRITICAL"

    @responses_lib.activate
    def test_no_leak_no_finding(self, enforcer):
        scanner = XXEScanner(enforcer)
        html = '<form method="POST" action="/parse-xml"></form>'
        responses_lib.add(responses_lib.GET, "https://localhost:5000/", body=html, status=200, content_type="text/html")
        responses_lib.add(responses_lib.POST, "https://localhost:5000/parse-xml", body="Hello", status=200)
        findings = scanner.scan([make_asset("https://localhost:5000/")])
        assert findings == []

    @responses_lib.activate
    def test_get_form_is_ignored(self, enforcer):
        scanner = XXEScanner(enforcer)
        html = '<form method="GET" action="/search"></form>'
        responses_lib.add(responses_lib.GET, "https://localhost:5000/", body=html, status=200, content_type="text/html")
        findings = scanner.scan([make_asset("https://localhost:5000/")])
        assert findings == []

    @responses_lib.activate
    def test_same_endpoint_not_tested_twice(self, enforcer):
        scanner = XXEScanner(enforcer)
        html = '''
        <form method="POST" action="/parse-xml"></form>
        <form method="POST" action="/parse-xml"></form>
        '''
        responses_lib.add(responses_lib.GET, "https://localhost:5000/", body=html, status=200, content_type="text/html")
        responses_lib.add(responses_lib.POST, "https://localhost:5000/parse-xml", body="clean", status=200)
        scanner.scan([make_asset("https://localhost:5000/")])
        post_calls = [c for c in responses_lib.calls if c.request.method == "POST"]
        # 2 payloads tried once each (not duplicated for the second identical form)
        assert len(post_calls) == len(scanner.PAYLOADS)
