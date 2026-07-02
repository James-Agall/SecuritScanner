import urllib.parse
import requests
from typing import List, Dict, Any
from bs4 import BeautifulSoup
from enforcer import ScopeEnforcer


class CommandInjectionScanner:
    """
    Submits POST forms with OS command delimiter payloads to detect
    unsanitized shell interpolation (OS Command Injection).
    """

    MARKER = "VULN_CMD_INJECTION_SUCCESS"

    def __init__(self, enforcer: ScopeEnforcer):
        self.enforcer = enforcer
        self.payloads = [
            f"127.0.0.1 & echo {self.MARKER}",
            f"127.0.0.1 | echo {self.MARKER}",
            f"127.0.0.1 && echo {self.MARKER}",
        ]

    def scan(self, assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        print("\n[*] Starting OS Command Injection Scanner...")
        vulnerabilities = []

        html_assets = [
            a for a in assets
            if a.get('is_html') or 'text/html' in a.get('headers', {}).get('Content-Type', '').lower()
        ]
        print(f"[*] Found {len(html_assets)} HTML pages to inspect for forms.")

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
                method = (form.get('method') or 'get').strip().lower()
                if method != 'post':
                    continue

                action = form.get('action') or page_url
                form_url = urllib.parse.urljoin(page_url, action)

                text_inputs = [
                    inp for inp in form.find_all('input')
                    if (inp.get('type') or 'text').lower() == 'text' and inp.get('name')
                ]

                for target_input in text_inputs:
                    if self._test_input(form, form_url, target_input, vulnerabilities):
                        break  # move to the next form once a flaw is found on this one

        print(f"[*] Command Injection scan complete. Found {len(vulnerabilities)} vulnerabilities.")
        return self._deduplicate(vulnerabilities)

    def _test_input(self, form, form_url: str, target_input, vulnerabilities: List[Dict[str, Any]]) -> bool:
        param_name = target_input.get('name')

        for payload in self.payloads:
            is_allowed, _ = self.enforcer.check(form_url)
            if not is_allowed:
                continue

            form_data = self._build_form_data(form, param_name, payload)

            print(f"    ↳ Testing Command Injection on: {param_name} with payload: {payload}")
            try:
                response = requests.post(form_url, data=form_data, timeout=10, verify=False)
            except Exception as e:
                print(f"    ↳ [!] NETWORK ERROR: {e}")
                continue

            if self.MARKER in response.text:
                vulnerabilities.append({
                    "type": "OS Command Injection",
                    "severity": "CRITICAL",
                    "url": form_url,
                    "vulnerable_param": param_name,
                    "payload_used": payload,
                    "description": "The application passes user input directly to the OS shell, allowing arbitrary command execution.",
                    "remediation": "Never pass user input directly to os.system() or subprocess with shell=True. Use subprocess arrays without shell=True, or strict allow-lists for expected input."
                })
                return True

        return False

    def _build_form_data(self, form, target_name: str, payload: str) -> Dict[str, str]:
        form_data = {}
        for inp in form.find_all('input'):
            name = inp.get('name')
            if not name:
                continue
            form_data[name] = payload if name == target_name else (inp.get('value') or '')
        return form_data

    def _deduplicate(self, vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        unique_vulns = []
        for v in vulns:
            key = (v['url'], v['vulnerable_param'])
            if key not in seen:
                seen.add(key)
                unique_vulns.append(v)
        return unique_vulns
