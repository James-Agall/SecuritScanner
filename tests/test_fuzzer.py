import responses as responses_lib

from fuzzer import DirectoryFuzzer


class TestDirectoryFuzzer:
    def test_empty_assets_returns_empty(self, enforcer):
        fuzzer = DirectoryFuzzer(enforcer)
        assert fuzzer.scan([]) == []

    @responses_lib.activate
    def test_200_status_flagged_high(self, enforcer):
        fuzzer = DirectoryFuzzer(enforcer)
        for path in fuzzer.wordlist:
            status = 200 if path == ".env" else 404
            responses_lib.add(responses_lib.GET, f"https://localhost:5000/{path}", status=status)

        findings = fuzzer.scan([{"url": "https://localhost:5000/"}])
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
        assert ".env" in findings[0]["type"]

    @responses_lib.activate
    def test_403_status_flagged_medium(self, enforcer):
        fuzzer = DirectoryFuzzer(enforcer)
        for path in fuzzer.wordlist:
            status = 403 if path == "admin" else 404
            responses_lib.add(responses_lib.GET, f"https://localhost:5000/{path}", status=status)

        findings = fuzzer.scan([{"url": "https://localhost:5000/"}])
        assert len(findings) == 1
        assert findings[0]["severity"] == "MEDIUM"

    @responses_lib.activate
    def test_404_status_not_flagged(self, enforcer):
        fuzzer = DirectoryFuzzer(enforcer)
        for path in fuzzer.wordlist:
            responses_lib.add(responses_lib.GET, f"https://localhost:5000/{path}", status=404)

        findings = fuzzer.scan([{"url": "https://localhost:5000/"}])
        assert findings == []

    def test_deduplicates_by_url(self, enforcer):
        fuzzer = DirectoryFuzzer(enforcer)
        vulns = [
            {"url": "https://localhost:5000/.env"},
            {"url": "https://localhost:5000/.env"},
        ]
        assert len(fuzzer._deduplicate(vulns)) == 1
