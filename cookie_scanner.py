import urllib.parse

import requests

from crawler import Asset
from database import Vulnerability
from enforcer import ScopeEnforcer, safe_http_request


class CookieScanner:
    """
    Inspects Set-Cookie headers for missing Secure/HttpOnly/SameSite
    protections. Passively checks every crawled GET response, then
    actively POSTs test credentials to any discovered /login endpoint
    so the session cookie (only ever set on a successful login) actually
    gets triggered and inspected.
    """

    SESSION_NAME_HINTS = ["session", "sid", "token", "auth", "user", "login"]

    def __init__(self, enforcer: ScopeEnforcer, username: str | None = None, password: str | None = None):
        self.enforcer = enforcer
        self.username = username
        self.password = password

    def scan(self, assets: list[Asset]) -> list[Vulnerability]:
        print("\n[*] Starting Cookie Security Analysis...")
        vulnerabilities: list[Vulnerability] = []

        # Phase 1: passively inspect Set-Cookie headers on every crawled page.
        print(f"[*] Phase 1: Checking cookies on {len(assets)} crawled pages...")
        for asset in assets:
            url = asset['url']

            is_allowed, _ = self.enforcer.check(url)
            if not is_allowed:
                continue

            response = safe_http_request(url, self.enforcer)
            if response is None:
                continue

            self._check_cookies(response, url, vulnerabilities)

        # Phase 2: actively POST test credentials to any /login endpoint.
        # The crawler only issues GET requests, so the session cookie set on
        # a successful login response is never seen unless we trigger it here.
        login_urls = [
            a['url'] for a in assets
            if urllib.parse.urlparse(a['url']).path.rstrip('/').lower().endswith('/login')
        ]
        print(f"[*] Phase 2: Testing {len(login_urls)} login endpoint(s)...")

        if self.username and self.password:
            for login_url in login_urls:
                is_allowed, _ = self.enforcer.check(login_url)
                if not is_allowed:
                    continue

                print(f"    ↳ Testing login: {login_url}")
                try:
                    # safe_http_request only issues GET requests, and the
                    # Set-Cookie header we need lives on the raw 302 redirect
                    # response itself (not the page it points to), so this
                    # must not follow redirects.
                    response = requests.post(
                        login_url,
                        data={"username": self.username, "password": self.password},
                        allow_redirects=False,
                        timeout=10,
                        verify=False,
                    )
                except Exception as e:
                    print(f"    ↳ [!] NETWORK ERROR: {e}")
                    continue

                self._check_cookies(response, login_url, vulnerabilities)
        else:
            print("    ↳ [!] No test credentials configured, skipping active login test.")

        print(f"[*] Cookie analysis complete. Found {len(vulnerabilities)} vulnerabilities.")
        return self._deduplicate(vulnerabilities)

    def _check_cookies(self, response: requests.Response, url: str, vulnerabilities: list[Vulnerability]) -> None:
        """Parse raw Set-Cookie headers for missing security attributes.

        response.headers collapses repeated headers into a single
        comma-joined string, which corrupts cookie parsing (cookie
        attributes like Expires already contain commas). response.raw.headers
        is the underlying urllib3 HTTPHeaderDict, whose getlist() returns
        each Set-Cookie header intact.
        """
        try:
            set_cookie_headers = response.raw.headers.getlist('Set-Cookie')
        except Exception:
            set_cookie_headers = []

        for cookie_str in set_cookie_headers:
            if '=' not in cookie_str:
                continue

            cookie_name = cookie_str.split('=')[0].strip()
            cookie_lower = cookie_str.lower()

            is_session_cookie = any(hint in cookie_name.lower() for hint in self.SESSION_NAME_HINTS)
            severity = "HIGH" if is_session_cookie else "MEDIUM"

            if 'secure' not in cookie_lower:
                vulnerabilities.append({
                    "type": "Cookie Missing 'Secure' Flag",
                    "severity": severity,
                    "url": url,
                    "vulnerable_param": cookie_name,
                    "payload_used": "N/A",
                    "description": f"The cookie '{cookie_name}' is missing the 'Secure' flag, allowing it to be transmitted over unencrypted HTTP connections where it can be intercepted.",
                    "remediation": "Add the 'Secure' flag to ensure the cookie is only transmitted over HTTPS connections."
                })

            if 'httponly' not in cookie_lower:
                vulnerabilities.append({
                    "type": "Cookie Missing 'HttpOnly' Flag",
                    "severity": severity,
                    "url": url,
                    "vulnerable_param": cookie_name,
                    "payload_used": "N/A",
                    "description": f"The cookie '{cookie_name}' is missing the 'HttpOnly' flag, allowing JavaScript to access it. This enables session theft via XSS attacks.",
                    "remediation": "Add the 'HttpOnly' flag to prevent client-side scripts from accessing the cookie."
                })

            if 'samesite' not in cookie_lower or 'samesite=none' in cookie_lower:
                vulnerabilities.append({
                    "type": "Cookie Missing 'SameSite' Attribute",
                    "severity": severity,
                    "url": url,
                    "vulnerable_param": cookie_name,
                    "payload_used": "N/A",
                    "description": f"The cookie '{cookie_name}' is missing the 'SameSite' attribute or is set to 'None', making it vulnerable to Cross-Site Request Forgery (CSRF) attacks.",
                    "remediation": "Set the 'SameSite' attribute to 'Strict' or 'Lax' to prevent the cookie from being sent with cross-site requests."
                })

    def _deduplicate(self, vulns: list[Vulnerability]) -> list[Vulnerability]:
        seen: set[tuple[str, str, str]] = set()
        unique_vulns: list[Vulnerability] = []
        for v in vulns:
            key = (v['url'], v['vulnerable_param'], v['type'])
            if key not in seen:
                seen.add(key)
                unique_vulns.append(v)
        return unique_vulns
