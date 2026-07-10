from crawler import Asset
from database import Vulnerability


class SecurityHeaderAnalyzer:
    """
    Analyzes HTTP headers for missing security configurations.
    Based on OWASP Secure Headers Project best practices.
    """

    # The headers we are looking for, and why they matter
    REQUIRED_HEADERS: dict[str, dict[str, str]] = {
        "Strict-Transport-Security": {
            "severity": "HIGH",
            "description": "Prevents protocol downgrade attacks and cookie hijacking (HSTS)."
        },
        "Content-Security-Policy": {
            "severity": "HIGH",
            "description": "Prevents Cross-Site Scripting (XSS) and data injection attacks (CSP)."
        },
        "X-Frame-Options": {
            "severity": "MEDIUM",
            "description": "Prevents Clickjacking attacks by disabling page embedding in iframes."
        },
        "X-Content-Type-Options": {
            "severity": "MEDIUM",
            "description": "Prevents the browser from MIME-sniffing the content type, reducing drive-by download risks."
        },
        "Referrer-Policy": {
            "severity": "LOW",
            "description": "Controls how much referrer information is sent when navigating away from the page."
        }
    }

    def analyze(self, assets: list[Asset]) -> list[Vulnerability]:
        """Scans all discovered assets for missing headers."""
        print("\n[*] Starting Security Header Analysis...")
        vulnerabilities: list[Vulnerability] = []

        # We only care about assets that actually returned headers
        html_assets = [a for a in assets if 'headers' in a]

        for asset in html_assets:
            url = asset['url']
            headers = asset['headers']

            # Check for missing headers
            for header, info in self.REQUIRED_HEADERS.items():
                if header not in headers:
                    vuln: Vulnerability = {
                        "type": f"Missing Header: {header}",
                        "severity": info['severity'],
                        "url": url,
                        "description": info['description'],
                        "remediation": f"Configure your web server to include the '{header}' header in all HTTP responses."
                    }
                    vulnerabilities.append(vuln)

            # Check for Verbose Server Information (Information Disclosure)
            if 'Server' in headers:
                server_val = headers['Server']
                # If the server reveals its exact version (e.g., "Apache/2.4.41"), it's a risk
                if any(char.isdigit() for char in server_val) and '/' in server_val:
                    vuln = {
                        "type": "Information Disclosure: Verbose Server Header",
                        "severity": "LOW",
                        "url": url,
                        "description": f"The server reveals its exact software version: '{server_val}'. Attackers use this to find specific CVEs for your software.",
                        "remediation": "Configure your web server to hide the 'Server' header or remove the version number (e.g., just say 'Apache' instead of 'Apache/2.4.41')."
                    }
                    vulnerabilities.append(vuln)

        # Deduplicate: We don't want to report the same missing header 15 times for the same site
        unique_vulns = self._deduplicate(vulnerabilities)
        print(f"[*] Analysis complete. Found {len(unique_vulns)} unique misconfigurations.")
        return unique_vulns

    def _deduplicate(self, vulns: list[Vulnerability]) -> list[Vulnerability]:
        """Removes duplicate findings so the report is clean."""
        seen: set[tuple[str, str]] = set()
        unique: list[Vulnerability] = []
        for v in vulns:
            # Create a unique key based on the vulnerability type and the domain
            key = (v['type'], v['url'].split('/')[2])
            if key not in seen:
                seen.add(key)
                unique.append(v)
        return unique