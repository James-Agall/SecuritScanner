import urllib.parse

from crawler import Asset
from database import Vulnerability
from enforcer import ScopeEnforcer, safe_http_request


class SSRFScanner:
    """
    Actively tests URL parameters for Server-Side Request Forgery (SSRF)
    by pointing them back at the target's own homepage and checking
    whether the server fetched it on our behalf.
    """

    URL_PARAM_HINTS = ["url", "uri", "fetch", "redirect", "webhook", "callback", "link"]
    SUCCESS_MARKER = "Welcome to the local target"

    def __init__(self, enforcer: ScopeEnforcer):
        self.enforcer = enforcer

    def scan(self, assets: list[Asset]) -> list[Vulnerability]:
        print("\n[*] Starting SSRF Scanner...")
        vulnerabilities: list[Vulnerability] = []

        if not assets:
            return vulnerabilities

        parsed_base = urllib.parse.urlparse(assets[0]['url'])
        payload = f"{parsed_base.scheme}://{parsed_base.netloc}/"

        urls_with_params = [a['url'] for a in assets if '?' in a['url']]
        print(f"[*] Found {len(urls_with_params)} URLs with parameters to test.")

        for url in urls_with_params:
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)

            for param_name, original_values in query_params.items():
                if not any(hint in param_name.lower() for hint in self.URL_PARAM_HINTS):
                    continue

                original_val = original_values[0]
                test_query = parsed.query.replace(
                    f"{param_name}={original_val}",
                    f"{param_name}={urllib.parse.quote(payload)}"
                )
                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, test_query, parsed.fragment
                ))

                is_allowed, _ = self.enforcer.check(test_url)
                if not is_allowed:
                    continue

                print(f"    ↳ Testing SSRF on: {param_name} with payload: {payload}")
                response = safe_http_request(test_url, self.enforcer)
                if response is None:
                    continue

                if self.SUCCESS_MARKER in response.text:
                    vulnerabilities.append({
                        "type": "Server-Side Request Forgery (SSRF)",
                        "severity": "CRITICAL",
                        "url": url,
                        "vulnerable_param": param_name,
                        "payload_used": payload,
                        "description": "The application fetches user-supplied URLs without validation, allowing attackers to force the server to make requests to internal networks, cloud metadata services, or bypass firewalls.",
                        "remediation": "Implement a strict allow-list of permitted domains. Block requests to internal IP ranges (127.0.0.1, 10.x.x.x, 192.168.x.x, 169.254.x.x) and disable unnecessary URL schemes (like file:// or gopher://)."
                    })

        print(f"[*] SSRF scan complete. Found {len(vulnerabilities)} vulnerabilities.")
        return self._deduplicate(vulnerabilities)

    def _deduplicate(self, vulns: list[Vulnerability]) -> list[Vulnerability]:
        seen: set[tuple[str, str]] = set()
        unique_vulns: list[Vulnerability] = []
        for v in vulns:
            key = (v['url'], v['vulnerable_param'])
            if key not in seen:
                seen.add(key)
                unique_vulns.append(v)
        return unique_vulns
