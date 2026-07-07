import requests

from crawler import Asset
from database import Vulnerability
from enforcer import ScopeEnforcer


class CORSScanner:
    """
    Sends a spoofed Origin header at each crawled URL and checks whether
    the server reflects it back in Access-Control-Allow-Origin while also
    allowing credentials — a critical CORS misconfiguration.
    """

    EVIL_ORIGIN = "https://evil.com"

    def __init__(self, enforcer: ScopeEnforcer):
        self.enforcer = enforcer

    def scan(self, assets: list[Asset]) -> list[Vulnerability]:
        print("\n[*] Starting CORS Misconfiguration Scanner...")
        vulnerabilities: list[Vulnerability] = []

        for asset in assets:
            url = asset['url']

            is_allowed, _ = self.enforcer.check(url)
            if not is_allowed:
                continue

            print(f"    ↳ Testing CORS on: {url} with Origin: {self.EVIL_ORIGIN}")
            try:
                response = requests.get(
                    url,
                    headers={"Origin": self.EVIL_ORIGIN},
                    timeout=10,
                    verify=False,
                )
            except Exception as e:
                print(f"    ↳ [!] NETWORK ERROR: {e}")
                continue

            acao = response.headers.get('Access-Control-Allow-Origin')
            acac = response.headers.get('Access-Control-Allow-Credentials', '').lower()

            if acao == self.EVIL_ORIGIN and acac == 'true':
                vulnerabilities.append({
                    "type": "CORS Misconfiguration - Arbitrary Origin Reflection",
                    "severity": "HIGH",
                    "url": url,
                    "vulnerable_param": "Origin Header",
                    "payload_used": f"Origin: {self.EVIL_ORIGIN}",
                    "description": "The server reflects arbitrary Origin headers with credentials allowed, enabling attackers to make authenticated cross-origin requests from malicious websites and steal user data.",
                    "remediation": "Implement a strict allow-list of permitted origins. Never reflect the Origin header dynamically. Use specific domain names instead of wildcards when credentials are involved."
                })

        print(f"[*] CORS scan complete. Found {len(vulnerabilities)} vulnerabilities.")
        return self._deduplicate(vulnerabilities)

    def _deduplicate(self, vulns: list[Vulnerability]) -> list[Vulnerability]:
        seen: set[str] = set()
        unique_vulns: list[Vulnerability] = []
        for v in vulns:
            key = v['url']
            if key not in seen:
                seen.add(key)
                unique_vulns.append(v)
        return unique_vulns
