from analyzer import SecurityHeaderAnalyzer


def make_asset(url, headers):
    return {"url": url, "status_code": 200, "is_html": True, "headers": headers}


class TestSecurityHeaderAnalyzer:
    def test_flags_all_missing_headers(self):
        analyzer = SecurityHeaderAnalyzer()
        assets = [make_asset("https://localhost:5000/", {})]
        findings = analyzer.analyze(assets)
        types = {f["type"] for f in findings}
        for header in SecurityHeaderAnalyzer.REQUIRED_HEADERS:
            assert f"Missing Header: {header}" in types

    def test_no_findings_when_all_headers_present(self):
        analyzer = SecurityHeaderAnalyzer()
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        }
        assets = [make_asset("https://localhost:5000/", headers)]
        findings = analyzer.analyze(assets)
        assert findings == []

    def test_verbose_server_header_flagged(self):
        analyzer = SecurityHeaderAnalyzer()
        assets = [make_asset("https://localhost:5000/", {"Server": "Apache/2.4.41"})]
        findings = analyzer.analyze(assets)
        assert any(f["type"] == "Information Disclosure: Verbose Server Header" for f in findings)

    def test_generic_server_header_not_flagged(self):
        analyzer = SecurityHeaderAnalyzer()
        assets = [make_asset("https://localhost:5000/", {"Server": "nginx"})]
        findings = analyzer.analyze(assets)
        assert not any(f["type"] == "Information Disclosure: Verbose Server Header" for f in findings)

    def test_assets_without_headers_key_are_skipped(self):
        analyzer = SecurityHeaderAnalyzer()
        assets = [{"url": "https://localhost:5000/", "status_code": 200, "is_html": True}]
        findings = analyzer.analyze(assets)
        assert findings == []

    def test_deduplicates_same_missing_header_per_domain(self):
        analyzer = SecurityHeaderAnalyzer()
        assets = [
            make_asset("https://localhost:5000/page1", {}),
            make_asset("https://localhost:5000/page2", {}),
        ]
        findings = analyzer.analyze(assets)
        hsts_findings = [f for f in findings if f["type"] == "Missing Header: Strict-Transport-Security"]
        assert len(hsts_findings) == 1
