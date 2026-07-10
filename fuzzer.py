import urllib.parse

from crawler import Asset
from database import Vulnerability
from enforcer import ScopeEnforcer, safe_http_request


class DirectoryFuzzer:
    def __init__(self, enforcer: ScopeEnforcer):
        self.enforcer = enforcer
        # A curated list of common sensitive files and directories
        self.wordlist = [
            ".env", ".git/config", ".git/HEAD", "robots.txt",
            "sitemap.xml", "admin", "administrator", "wp-admin",
            "phpmyadmin", "backup.sql", "config.php", "web.config",
            ".DS_Store", "server-status", "api/v1", "swagger.json"
        ]

    def scan(self, assets: list[Asset]) -> list[Vulnerability]:
        print("\n[*] Starting Directory & File Fuzzing...")
        vulns: list[Vulnerability] = []
        
        # Get the base URL from the first crawled asset
        if not assets:
            return vulns
            
        base_url = assets[0]['url']
        parsed_base = urllib.parse.urlparse(base_url)
        # Reconstruct the base URL without any paths or queries
        base_root = f"{parsed_base.scheme}://{parsed_base.netloc}"
        
        print(f"[*] Fuzzing base root: {base_root} with {len(self.wordlist)} paths.")

        for path in self.wordlist:
            # Construct the target URL
            fuzz_url = f"{base_root}/{path}"
            
            # Check scope before sending
            is_allowed, _ = self.enforcer.check(fuzz_url)
            if not is_allowed:
                continue

            print(f"    ↳ Checking: /{path} ...", end="\r") # \r keeps it on the same line
            response = safe_http_request(fuzz_url, self.enforcer)

            # 200 means the file exists and is readable. 403 means it exists but is forbidden.
            if response is not None and response.status_code in [200, 403]:
                status = "Publicly Accessible" if response.status_code == 200 else "Access Forbidden (403)"
                severity = "HIGH" if response.status_code == 200 else "MEDIUM"

                vuln: Vulnerability = {
                    'type': f"Exposed Sensitive Path: /{path}",
                    'severity': severity,
                    'url': fuzz_url,
                    'vulnerable_param': "N/A",
                    'payload_used': f"HTTP {response.status_code}",
                    'description': f"The path '/{path}' returned a {response.status_code} status code. It is {status}.",
                    'remediation': "Remove the file/directory from the web root or configure the web server to deny access to it."
                }
                vulns.append(vuln)

        # Clear the console line after finishing
        print(" " * 50, end="\r")
        print(f"[*] Fuzzing complete. Found {len(vulns)} exposed paths.")

        return self._deduplicate(vulns)

    def _deduplicate(self, vulns: list[Vulnerability]) -> list[Vulnerability]:
        seen: set[str] = set()
        unique_vulns: list[Vulnerability] = []
        for vuln in vulns:
            key = vuln['url']
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        return unique_vulns