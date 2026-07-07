import time

import evasion


class TestGetRandomHeaders:
    def test_returns_expected_keys(self):
        headers = evasion.get_random_headers()
        assert set(headers.keys()) == {"User-Agent", "Accept", "Accept-Language", "Cache-Control"}

    def test_values_come_from_known_pools(self):
        headers = evasion.get_random_headers()
        assert headers["User-Agent"] in evasion.USER_AGENTS
        assert headers["Accept"] in evasion.ACCEPT_HEADERS
        assert headers["Accept-Language"] in evasion.ACCEPT_LANGUAGES
        assert headers["Cache-Control"] in evasion.CACHE_CONTROLS

    def test_randomizes_across_calls(self):
        # Not flaky: with 6 UAs, 100 draws virtually guarantee at least 2 distinct values.
        seen = {evasion.get_random_headers()["User-Agent"] for _ in range(100)}
        assert len(seen) > 1


class TestApplyStealthDelay:
    def test_sleeps_within_expected_bounds(self, monkeypatch):
        recorded = {}

        def fake_sleep(seconds):
            recorded["seconds"] = seconds

        monkeypatch.setattr(time, "sleep", fake_sleep)
        evasion.apply_stealth_delay()
        assert 0.1 <= recorded["seconds"] <= 0.8


class TestGetProxyDict:
    def test_empty_url_returns_empty_dict(self):
        assert evasion.get_proxy_dict("") == {}
        assert evasion.get_proxy_dict(None) == {}

    def test_proxy_url_maps_both_schemes(self):
        result = evasion.get_proxy_dict("http://127.0.0.1:8080")
        assert result == {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
