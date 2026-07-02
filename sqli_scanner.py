from typing import List, Dict, Any
from enforcer import ScopeEnforcer, safe_http_request

class SQLiScanner:
    def __init__(self, enforcer: ScopeEnforcer):
        self.enforcer = enforcer

    def scan(self, assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        print("\n[*] Starting Error-Based SQL Injection Scanner...")
        vulns = []
        
        # Filter for assets that have query parameters
        urls_with_params = [a for a in assets if '?' in a['url']]
        print(f"[*] Found {len(urls_with_params)} URLs with parameters to test.")

        for asset in urls_with_params:
            url = asset['url']
            # Parse parameters
            query_string = url.split('?')[1]
            params = query_string.split('&')
            
            for param in params:
                if '=' in param:
                    key, value = param.split('=', 1)
                    # Inject a single quote to break SQL syntax
                    payload = "'"
                    # Reconstruct URL with payload
                    new_param = f"{key}={payload}"
                    new_query_string = query_string.replace(param, new_param)
                    full_url = url.replace(query_string, new_query_string)
                    
                    print(f"    ↳ Testing SQLi on: {key} with payload: {payload}")
                    response = safe_http_request(full_url, self.enforcer)
                    
                    if response:
                        # Check for database error keywords
                        error_keywords = ['sqlite', 'operationalerror', 'unrecognized token', 'syntax', 'sql', 'unclosed quotation mark', 'mysql', 'ora-']
                        if any(keyword.lower() in response.text.lower() for keyword in error_keywords):
                            vuln = {
                                'type': "Error-Based SQL Injection",
                                'severity': "CRITICAL",
                                'url': url,
                                'vulnerable_param': key,
                                'payload_used': payload,
                                'description': "The application throws a database error when a single quote is injected, indicating unsanitized SQL queries.",
                                'remediation': "Use parameterized queries or prepared statements instead of string concatenation/interpolation."
                            }
                            vulns.append(vuln)
        return self._deduplicate(vulns)

    def _deduplicate(self, vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        unique_vulns = []
        for vuln in vulns:
            key = (vuln['url'], vuln['vulnerable_param'])
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        return unique_vulns