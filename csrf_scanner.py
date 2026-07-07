from bs4 import BeautifulSoup, Tag

from crawler import Asset
from database import Vulnerability
from enforcer import ScopeEnforcer, safe_http_request


class CSRFScanner:
    """
    Inspects HTML forms for missing anti-CSRF tokens on state-changing
    (POST) requests.
    """

    CSRF_TOKEN_HINTS = ["csrf", "token", "_token", "authenticity_token"]

    def __init__(self, enforcer: ScopeEnforcer):
        self.enforcer = enforcer

    def scan(self, assets: list[Asset]) -> list[Vulnerability]:
        print("\n[*] Starting CSRF Token Analysis...")
        vulnerabilities: list[Vulnerability] = []

        html_assets = [
            a for a in assets
            if a.get('is_html') or 'text/html' in a.get('headers', {}).get('Content-Type', '').lower()
        ]
        print(f"[*] Found {len(html_assets)} HTML pages to inspect for forms.")

        for asset in html_assets:
            url = asset['url']

            is_allowed, _ = self.enforcer.check(url)
            if not is_allowed:
                continue

            response = safe_http_request(url, self.enforcer)
            if response is None:
                continue

            try:
                soup = BeautifulSoup(response.text, 'html.parser')
            except Exception:
                continue

            for form in soup.find_all('form'):
                method = (form.get('method') or 'get').strip().lower()  # type: ignore[union-attr]
                if method != 'post':
                    continue

                if not self._has_csrf_token(form):
                    action: str = form.get('action') or "/"  # type: ignore[assignment]
                    vulnerabilities.append({
                        "type": "Missing CSRF Token on POST Form",
                        "severity": "MEDIUM",
                        "url": url,
                        "vulnerable_param": action,
                        "payload_used": "N/A",
                        "description": "The form submits data via POST but lacks an anti-CSRF token, making it vulnerable to Cross-Site Request Forgery attacks where malicious sites can submit forms on behalf of authenticated users.",
                        "remediation": "Implement anti-CSRF tokens in all state-changing forms. Generate a unique token per session, include it as a hidden field in forms, and validate it on the server side before processing the request."
                    })

        print(f"[*] CSRF analysis complete. Found {len(vulnerabilities)} forms without CSRF protection.")
        return self._deduplicate(vulnerabilities)

    def _has_csrf_token(self, form: Tag) -> bool:
        for input_tag in form.find_all('input', {'type': 'hidden'}):
            name = (input_tag.get('name') or '').lower()  # type: ignore[union-attr]
            if any(hint in name for hint in self.CSRF_TOKEN_HINTS):
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
