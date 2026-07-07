import urllib.parse

import requests

from crawler import Asset
from database import Vulnerability
from enforcer import ScopeEnforcer


class OpenRedirectScanner:
    """
    Actively tests URL parameters for Open Redirect by injecting payloads
    that point off-site and checking whether the server issues a raw
    redirect (without following it) to the attacker-controlled host.
    """

    REDIRECT_PARAM_HINTS = [
        "url", "next", "redirect", "return", "returnurl", "returnto",
        "goto", "target", "link", "continue", "dest", "destination",
        "redir", "redirect_uri", "callback"
    ]

    PAYLOADS = [
        "https://evil.com",
        "//evil.com",
        "https://localhost:5000@evil.com",
        "%0d%0aLocation: https://evil.com",
    ]

    def __init__(self, enforcer: ScopeEnforcer):
        self.enforcer = enforcer

    def scan(self, assets: list[Asset]) -> list[Vulnerability]:
        print("\n[*] Starting Open Redirect Scanner...")
        vulnerabilities: list[Vulnerability] = []

        # PHASE 1: Test URLs that already have redirect-like parameters
        urls_with_params = [a['url'] for a in assets if '?' in a['url']]
        print(f"[*] Phase 1: Testing {len(urls_with_params)} URLs with existing parameters.")

        for url in urls_with_params:
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)

            for param_name, original_values in query_params.items():
                if not any(hint in param_name.lower() for hint in self.REDIRECT_PARAM_HINTS):
                    continue

                original_val = original_values[0]

                for payload in self.PAYLOADS:
                    test_query = parsed.query.replace(
                        f"{param_name}={original_val}",
                        f"{param_name}={urllib.parse.quote(payload)}"
                    )
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, test_query, parsed.fragment
                    ))

                    if self._test_redirect(test_url, url, param_name, payload, vulnerabilities):
                        break

        # PHASE 2: Construct test URLs by appending redirect parameters to ALL pages
        print(f"[*] Phase 2: Constructing test URLs for {len(assets)} pages.")
        for asset in assets:
            base_url = asset['url'].split('?')[0]  # Remove existing query string
            
            for param_name in ['next', 'url', 'redirect', 'return']:
                for payload in self.PAYLOADS[:2]:  # Only test first 2 payloads to save time
                    test_url = f"{base_url}?{param_name}={urllib.parse.quote(payload)}"
                    
                    if self._test_redirect(test_url, base_url, param_name, payload, vulnerabilities):
                        break

        print(f"[*] Open Redirect scan complete. Found {len(vulnerabilities)} vulnerabilities.")
        return self._deduplicate(vulnerabilities)

    def _test_redirect(self, test_url: str, original_url: str, param_name: str, payload: str, vulnerabilities: list[Vulnerability]) -> bool:
        """Helper method to test a single redirect payload. Returns True if vulnerability found."""
        is_allowed, _ = self.enforcer.check(test_url)
        if not is_allowed:
            return False

        try:
            response = requests.get(
                test_url,
                allow_redirects=False,
                timeout=10,
                verify=False,
            )
        except Exception:
            return False

        location = response.headers.get('Location', '')
        if response.status_code in (301, 302, 303, 307) and "evil.com" in location:
            vulnerabilities.append({
                "type": "Open Redirect",
                "severity": "MEDIUM",
                "url": original_url,
                "vulnerable_param": param_name,
                "payload_used": payload,
                "description": "The application redirects users to arbitrary external URLs without validation, enabling phishing attacks and OAuth bypass vulnerabilities.",
                "remediation": "Validate redirect URLs against an allow-list of permitted domains. Never redirect to user-supplied URLs without verification. Use relative paths for internal redirects."
            })
            print(f"    ↳ [!] FOUND: {param_name}={payload}")
            return True
        return False
    
    def _deduplicate(self, vulns: list[Vulnerability]) -> list[Vulnerability]:
        seen: set[tuple[str, str]] = set()
        unique_vulns: list[Vulnerability] = []
        for v in vulns:
            key = (v['url'], v['vulnerable_param'])
            if key not in seen:
                seen.add(key)
                unique_vulns.append(v)
        return unique_vulns
