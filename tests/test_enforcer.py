import socket

import responses as responses_lib

from enforcer import ScopeEnforcer, safe_http_request


class TestScopeEnforcerDomain:
    def test_exact_domain_allowed(self, enforcer):
        allowed, reason = enforcer.check("https://localhost:5000/foo")
        assert allowed is True
        assert "ALLOWED" in reason

    def test_wildcard_domain_allowed(self, monkeypatch):
        e = ScopeEnforcer({"allowed_domains": ["*.example.com"], "allowed_ports": [443]})
        monkeypatch.setattr(socket, "gethostbyname", lambda h: "93.184.216.34")
        allowed, _ = e.check("https://api.example.com/")
        assert allowed is True

    def test_unlisted_domain_denied(self, enforcer):
        allowed, reason = enforcer.check("https://evil.com/")
        assert allowed is False
        assert "not allowed" in reason

    def test_missing_scheme_or_netloc_denied(self, enforcer):
        allowed, reason = enforcer.check("not-a-url")
        assert allowed is False
        assert "Missing scheme" in reason

    def test_invalid_url_denied(self, enforcer):
        # A control character in the netloc raises inside urlparse
        allowed, reason = enforcer.check("http://[::1")
        assert allowed is False

    def test_malformed_url_with_none_hostname_is_denied(self, enforcer):
        # A netloc of just ":8080" is truthy (so it passes the scheme/netloc
        # check) but urlparse().hostname is None for it - this must be
        # denied cleanly rather than raising when passed to hostname.lower().
        allowed, reason = enforcer.check("http://:8080/")
        assert allowed is False
        assert "malformed URL" in reason


class TestScopeEnforcerPort:
    def test_disallowed_port_denied(self, enforcer):
        allowed, reason = enforcer.check("https://localhost:9999/")
        assert allowed is False
        assert "Port" in reason

    def test_default_https_port_used_when_missing(self):
        e = ScopeEnforcer({"allowed_domains": ["localhost"], "allowed_ports": [443], "allow_local_testing": True})
        allowed, _ = e.check("https://localhost/")
        assert allowed is True


class TestScopeEnforcerPath:
    def test_excluded_path_denied(self):
        e = ScopeEnforcer({
            "allowed_domains": ["localhost"], "allowed_ports": [5000],
            "excluded_paths": ["/admin"], "allow_local_testing": True,
        })
        allowed, reason = e.check("https://localhost:5000/admin")
        assert allowed is False
        assert "excluded" in reason

    def test_excluded_path_with_subpath_denied(self):
        e = ScopeEnforcer({
            "allowed_domains": ["localhost"], "allowed_ports": [5000],
            "excluded_paths": ["/admin"], "allow_local_testing": True,
        })
        allowed, _ = e.check("https://localhost:5000/admin/users")
        assert allowed is False

    def test_non_excluded_path_allowed(self, enforcer):
        allowed, _ = enforcer.check("https://localhost:5000/profile")
        assert allowed is True


class TestScopeEnforcerIPResolution:
    def test_local_testing_allows_loopback(self, enforcer):
        allowed, reason = enforcer.check("https://localhost:5000/")
        assert allowed is True

    def test_unresolvable_host_denied(self, monkeypatch):
        e = ScopeEnforcer({"allowed_domains": ["ghost.invalid"], "allowed_ports": [443]})
        monkeypatch.setattr(socket, "gethostbyname", _raise_gaierror)
        allowed, reason = e.check("https://ghost.invalid/")
        assert allowed is False
        assert "Cannot resolve" in reason

    def test_private_ip_denied_without_local_testing_flag(self, monkeypatch):
        e = ScopeEnforcer({"allowed_domains": ["internal.corp"], "allowed_ports": [443]})
        monkeypatch.setattr(socket, "gethostbyname", lambda h: "10.0.0.5")
        allowed, reason = e.check("https://internal.corp/")
        assert allowed is False
        assert "SSRF Protection" in reason

    def test_public_ip_allowed(self, monkeypatch):
        e = ScopeEnforcer({"allowed_domains": ["public.example"], "allowed_ports": [443]})
        monkeypatch.setattr(socket, "gethostbyname", lambda h: "93.184.216.34")
        allowed, reason = e.check("https://public.example/")
        assert allowed is True
        assert reason == "ALLOWED"

    def test_cidr_match_allowed(self, monkeypatch):
        e = ScopeEnforcer({
            "allowed_domains": ["partner.example"], "allowed_ports": [443],
            "allowed_cidrs": ["203.0.113.0/24"],
        })
        monkeypatch.setattr(socket, "gethostbyname", lambda h: "203.0.113.42")
        allowed, reason = e.check("https://partner.example/")
        assert allowed is True
        assert reason == "ALLOWED"

    def test_cidr_mismatch_denied(self, monkeypatch):
        e = ScopeEnforcer({
            "allowed_domains": ["partner.example"], "allowed_ports": [443],
            "allowed_cidrs": ["203.0.113.0/24"],
        })
        monkeypatch.setattr(socket, "gethostbyname", lambda h: "8.8.8.8")
        allowed, reason = e.check("https://partner.example/")
        assert allowed is False
        assert "outside allowed CIDRs" in reason


class TestSafeHttpRequest:
    def test_blocked_by_scope_returns_none(self, enforcer):
        assert safe_http_request("https://evil.com/", enforcer) is None

    @responses_lib.activate
    def test_successful_request_returns_response(self, enforcer):
        responses_lib.add(responses_lib.GET, "https://localhost:5000/", body="hello", status=200)
        response = safe_http_request("https://localhost:5000/", enforcer)
        assert response is not None
        assert response.status_code == 200
        assert response.text == "hello"

    @responses_lib.activate
    def test_follows_redirect_by_default(self, enforcer):
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/old",
            status=302, headers={"Location": "https://localhost:5000/new"},
        )
        responses_lib.add(responses_lib.GET, "https://localhost:5000/new", body="landed", status=200)
        response = safe_http_request("https://localhost:5000/old", enforcer)
        assert response.status_code == 200
        assert response.text == "landed"

    @responses_lib.activate
    def test_redirect_to_out_of_scope_host_is_blocked(self, enforcer):
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/goaway",
            status=302, headers={"Location": "https://evil.com/"},
        )
        response = safe_http_request("https://localhost:5000/goaway", enforcer)
        assert response is None

    @responses_lib.activate
    def test_allow_redirects_false_returns_raw_redirect(self, enforcer):
        responses_lib.add(
            responses_lib.GET, "https://localhost:5000/old",
            status=302, headers={"Location": "https://localhost:5000/new"},
        )
        response = safe_http_request("https://localhost:5000/old", enforcer, allow_redirects=False)
        assert response.status_code == 302
        assert response.headers["Location"] == "https://localhost:5000/new"

    @responses_lib.activate
    def test_waf_status_code_still_returns_response(self, enforcer):
        responses_lib.add(responses_lib.GET, "https://localhost:5000/blocked", status=403)
        response = safe_http_request("https://localhost:5000/blocked", enforcer)
        assert response.status_code == 403

    def test_network_error_returns_none(self, enforcer):
        # No `responses` registration for this URL -> ConnectionError raised by requests
        with responses_lib.RequestsMock():
            result = safe_http_request("https://localhost:5000/unregistered", enforcer)
        assert result is None

    @responses_lib.activate
    def test_stealth_mode_adds_randomized_headers(self, stealth_enforcer, monkeypatch):
        import evasion
        monkeypatch.setattr(evasion, "apply_stealth_delay", lambda: None)
        responses_lib.add(responses_lib.GET, "https://localhost:5000/", body="ok", status=200)
        response = safe_http_request("https://localhost:5000/", stealth_enforcer)
        assert response.status_code == 200
        sent_ua = responses_lib.calls[0].request.headers.get("User-Agent")
        assert sent_ua in evasion.USER_AGENTS


def _raise_gaierror(hostname):
    raise socket.gaierror("Name or service not known")
