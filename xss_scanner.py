import urllib.parse

from crawler import Asset
from database import Vulnerability
from enforcer import ScopeEnforcer, safe_http_request


class XSSScanner:
    """
    Actively tests URL parameters for Reflected Cross-Site Scripting (XSS).
    """
    
    def __init__(self, enforcer: ScopeEnforcer):
        self.enforcer = enforcer
        # Safe payloads designed to break out of HTML tags and attributes
        self.payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "'-alert(1)-'"
        ]

    def scan(self, assets: list[Asset]) -> list[Vulnerability]:
        print("\n[*] Starting Reflected XSS Scanner...")
        vulnerabilities: list[Vulnerability] = []
        
        # 1. Filter for assets that have query parameters (?key=value)
        urls_with_params = [a['url'] for a in assets if '?' in a['url']]
        print(f"[*] Found {len(urls_with_params)} URLs with parameters to test.")

        for url in urls_with_params:
            # Parse the URL to extract the query string
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)

            # Test every parameter on the URL
            for param_name, original_values in query_params.items():
                for payload in self.payloads:
                    
                    # 2. Inject the payload into the parameter
                    # We must URL-encode the payload so it travels safely over HTTP
                    original_val = original_values[0]
                    test_query = parsed.query.replace(
                        f"{param_name}={original_val}", 
                        f"{param_name}={urllib.parse.quote(payload)}"
                    )
                    
                    # Rebuild the URL with the injected payload
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path, 
                        parsed.params, test_query, parsed.fragment
                    ))

                    # 3. Send the request through our Shield
                    is_allowed, _ = self.enforcer.check(test_url)
                    if not is_allowed:
                        continue

                    print(f"    ↳ Testing XSS on: {param_name} with payload: {payload[:20]}...")
                    response = safe_http_request(test_url, self.enforcer)
                    if response is None:
                        continue

                    # 4. Check for Reflection (Did the server spit our payload back out?)
                    # If the exact payload is in the HTML, it's a potential XSS flaw.
                    if payload in response.text:
                        vulnerabilities.append({
                            "type": "Reflected Cross-Site Scripting (XSS)",
                            "severity": "HIGH",
                            "url": url,
                            "vulnerable_param": param_name,
                            "payload_used": payload,
                            "description": f"The parameter '{param_name}' reflects user input without proper encoding, allowing script execution.",
                            "remediation": "Use Context-Aware Output Encoding. Convert special characters to HTML entities before rendering."
                        })
                        break # Move to the next parameter once a flaw is found

        return self._deduplicate(vulnerabilities)

    def _deduplicate(self, vulns: list[Vulnerability]) -> list[Vulnerability]:
        seen: set[tuple[str, str]] = set()
        unique: list[Vulnerability] = []
        for v in vulns:
            key = (v['url'], v['vulnerable_param'])
            if key not in seen:
                seen.add(key)
                unique.append(v)
        return unique