import re
import urllib.parse

import requests

from crawler import Asset
from database import Vulnerability
from enforcer import ScopeEnforcer

DENIAL_MARKERS = ["access denied", "unauthorized"]


class IDORScanner:
    """
    Logs in as a test user, then walks crawled URLs looking for numeric
    ID parameters (e.g. user_id=1) and tries incrementing them to see if
    the application leaks other users' data without an ownership check
    (Insecure Direct Object Reference).
    """

    NUMERIC_PARAM_RE = re.compile(r'^(\d+)$')

    def __init__(self, enforcer: ScopeEnforcer, username: str, password: str):
        self.enforcer = enforcer
        self.username = username
        self.password = password
        self.session_cookies: requests.cookies.RequestsCookieJar | None = None
        self.authenticated_url: str | None = None

    def login(self, base_url: str) -> bool:
        parsed_base = urllib.parse.urlparse(base_url)
        login_url = f"{parsed_base.scheme}://{parsed_base.netloc}/login"

        is_allowed, reason = self.enforcer.check(login_url)
        if not is_allowed:
            print(f"    ↳ [!] BLOCKED BY SCOPE: {reason}")
            return False

        print(f"[*] Logging in as '{self.username}' at {login_url}...")
        try:
            response = requests.post(
                login_url,
                data={"username": self.username, "password": self.password},
                timeout=10,
                verify=False,
                allow_redirects=True,
            )
        except Exception as e:
            print(f"    ↳ [!] NETWORK ERROR: {e}")
            return False

        if "Invalid credentials" in response.text:
            print("    ↳ [!] Login failed: invalid credentials.")
            return False

        self.session_cookies = response.cookies
        # The post-login redirect (e.g. /profile?user_id=1) is behind auth and
        # was never seen by the unauthenticated crawler, so remember it here
        # to make sure the IDOR scan has an authenticated URL to test.
        self.authenticated_url = response.url
        print("    ↳ [+] Login successful, session cookie captured.")
        return True

    def scan(self, assets: list[Asset]) -> list[Vulnerability]:
        print("\n[*] Starting IDOR Scanner...")
        vulnerabilities: list[Vulnerability] = []

        if self.session_cookies is None:
            print("    ↳ [!] Not logged in, skipping IDOR scan.")
            return vulnerabilities

        urls_with_params = [a['url'] for a in assets if '?' in a['url']]
        if self.authenticated_url and self.authenticated_url not in urls_with_params:
            urls_with_params.append(self.authenticated_url)
        print(f"[*] Found {len(urls_with_params)} URLs with parameters to test.")

        for url in urls_with_params:
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)

            for param_name, values in query_params.items():
                original_val = values[0]
                match = self.NUMERIC_PARAM_RE.match(original_val)
                if not match:
                    continue

                new_val = str(int(original_val) + 1)
                test_query = parsed.query.replace(
                    f"{param_name}={original_val}",
                    f"{param_name}={new_val}"
                )
                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, test_query, parsed.fragment
                ))

                is_allowed, _ = self.enforcer.check(test_url)
                if not is_allowed:
                    continue

                print(f"    ↳ Testing IDOR on: {param_name} with payload: {param_name}={new_val}")
                try:
                    response = requests.get(
                        test_url,
                        cookies=self.session_cookies,
                        timeout=10,
                        verify=False,
                    )
                except Exception as e:
                    print(f"    ↳ [!] NETWORK ERROR: {e}")
                    continue

                body_lower = response.text.lower()
                if response.status_code == 200 and not any(marker in body_lower for marker in DENIAL_MARKERS):
                    vulnerabilities.append({
                        "type": "Insecure Direct Object Reference (IDOR)",
                        "severity": "HIGH",
                        "url": url,
                        "vulnerable_param": param_name,
                        "payload_used": f"{param_name}={new_val}",
                        "description": "The application allows authenticated users to access data belonging to other users by simply modifying the ID in the URL.",
                        "remediation": "Implement strict access controls. Never rely on client-side input for object references. Verify that the logged-in user has explicit permission to access the requested resource."
                    })

        print(f"[*] IDOR scan complete. Found {len(vulnerabilities)} vulnerabilities.")
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
