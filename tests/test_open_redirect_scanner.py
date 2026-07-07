import responses as responses_lib

from open_redirect_scanner import OpenRedirectScanner


def make_asset(url):
    return {"url": url, "status_code": 200, "is_html": True, "headers": {}}


class TestOpenRedirectScannerPhase1:
    @responses_lib.activate
    def test_detects_redirect_to_evil_host(self, enforcer):
        scanner = OpenRedirectScanner(enforcer)
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/redirect",
            status=302, headers={"Location": "https://evil.com"},
        )
        findings = scanner.scan([make_asset("https://localhost:5000/redirect?next=/dashboard")])
        matches = [f for f in findings if f["vulnerable_param"] == "next" and f["url"].endswith("next=/dashboard")]
        assert len(matches) >= 1
        assert matches[0]["type"] == "Open Redirect"
        assert matches[0]["severity"] == "MEDIUM"

    @responses_lib.activate
    def test_internal_redirect_not_flagged(self, enforcer):
        scanner = OpenRedirectScanner(enforcer)
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/redirect",
            status=302, headers={"Location": "/dashboard"},
        )
        findings = scanner.scan([make_asset("https://localhost:5000/redirect?next=/dashboard")])
        assert not any(f["url"].endswith("next=/dashboard") for f in findings)

    @responses_lib.activate
    def test_200_response_not_flagged(self, enforcer):
        scanner = OpenRedirectScanner(enforcer)
        responses_lib.add(responses_lib.GET, "https://localhost:5000/redirect", status=200, body="no redirect here")
        findings = scanner.scan([make_asset("https://localhost:5000/redirect?next=/dashboard")])
        assert findings == []

    def test_non_redirect_param_name_skipped(self, enforcer):
        scanner = OpenRedirectScanner(enforcer)
        findings = scanner.scan([make_asset("https://localhost:5000/search?q=hello")])
        assert findings == []


class TestOpenRedirectScannerPhase2:
    @responses_lib.activate
    def test_phase2_constructs_and_flags_synthetic_urls(self, enforcer):
        scanner = OpenRedirectScanner(enforcer)
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/redirect",
            status=302, headers={"Location": "https://evil.com"},
        )
        # No '?' in this asset, so only phase 2 constructs test URLs for it.
        findings = scanner.scan([make_asset("https://localhost:5000/redirect")])
        assert len(findings) >= 1
        assert all(f["type"] == "Open Redirect" for f in findings)


class TestOpenRedirectScannerHelpers:
    def test_deduplicates_by_url_and_param(self, enforcer):
        scanner = OpenRedirectScanner(enforcer)
        vulns = [
            {"url": "https://localhost:5000/redirect?next=1", "vulnerable_param": "next"},
            {"url": "https://localhost:5000/redirect?next=1", "vulnerable_param": "next"},
        ]
        assert len(scanner._deduplicate(vulns)) == 1
