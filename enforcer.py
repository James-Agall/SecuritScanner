import urllib.parse
import ipaddress
import socket
import requests
import urllib3
from typing import Dict, Tuple, Any

# Scanners intentionally probe targets with untrusted/self-signed certs (e.g. local_target.py),
# so cert verification is disabled here; suppress the resulting noisy warning.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ScopeEnforcer:
    def __init__(self, scope_config: Dict[str, Any]):
        self.allowed_domains = [d.lower() for d in scope_config.get("allowed_domains", [])]
        self.allowed_cidrs = [ipaddress.ip_network(cidr, strict=False) for cidr in scope_config.get("allowed_cidrs", [])]
        self.allowed_ports = set(scope_config.get("allowed_ports", [80, 443]))
        self.excluded_paths = scope_config.get("excluded_paths", [])
        self.allow_local_testing = scope_config.get("allow_local_testing", False)

    def check(self, url: str) -> Tuple[bool, str]:
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception:
            return False, "DENIED: Invalid URL format."
        if not parsed.scheme or not parsed.netloc:
            return False, "DENIED: Missing scheme or domain."

        domain_ok, domain_reason = self._check_domain(parsed.hostname)
        if not domain_ok: return False, domain_reason

        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        port_ok, port_reason = self._check_port(port)
        if not port_ok: return False, port_reason

        path_ok, path_reason = self._check_path(parsed.path)
        if not path_ok: return False, path_reason

        ip_ok, ip_reason = self._check_ip_resolution(parsed.hostname)
        if not ip_ok: return False, ip_reason

        return True, "ALLOWED"

    def _check_domain(self, hostname: str) -> Tuple[bool, str]:
        hostname = hostname.lower()
        for allowed in self.allowed_domains:
            if allowed == hostname: return True, "Domain exact match."
            if allowed.startswith("*.") and hostname.endswith("." + allowed[2:]): return True, "Domain wildcard match."
        return False, f"DENIED: Domain '{hostname}' not allowed."

    def _check_port(self, port: int) -> Tuple[bool, str]:
        return (True, "Port allowed") if port in self.allowed_ports else (False, f"DENIED: Port {port} blocked.")

    def _check_path(self, path: str) -> Tuple[bool, str]:
        for excluded in self.excluded_paths:
            if path == excluded or path.startswith(excluded + "/") or path.startswith(excluded + "?"):
                return False, f"DENIED: Path '{path}' excluded."
        return True, "Path allowed."

    def _check_ip_resolution(self, hostname: str) -> Tuple[bool, str]:
        try:
            ip_str = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip_str)
        except Exception:
            return False, f"DENIED: Cannot resolve '{hostname}'."

        if self.allowed_cidrs:
            for cidr in self.allowed_cidrs:
                if ip_obj in cidr: return True, "IP in allowed CIDR."
            return False, f"DENIED: IP {ip_str} outside allowed CIDRs."
        
        if self.allow_local_testing and (hostname == "localhost" or hostname == "127.0.0.1"):
            return True, f"IP {ip_str} is allowed for local testing."
        elif ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return False, f"DENIED: IP {ip_str} is internal/private (SSRF Protection)."
        return True, f"IP {ip_str} is public."

def safe_http_request(url: str, enforcer: ScopeEnforcer):
    # 1. Check the scope, but print the reason if it fails!
    is_allowed, reason = enforcer.check(url)
    if not is_allowed: 
        print(f"    ↳ [!] BLOCKED BY SCOPE: {reason}")
        return None
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    }
    
    try:
        # 2. Make the request
        response = requests.get(url, headers=headers, allow_redirects=False, timeout=10, verify=False)
        
        # 3. Handle redirects, but print where we are going!
        if response.status_code in [301, 302, 303, 307, 308]:
            redirect_url = response.headers.get('Location')
            if redirect_url:
                redirect_url = urllib.parse.urljoin(url, redirect_url)
                print(f"    ↳ [i] Following redirect to: {redirect_url}")
                return safe_http_request(redirect_url, enforcer)
                
        # 4. If we got a 403 Forbidden or 406 Not Acceptable, the WAF blocked us!
        if response.status_code in [403, 406, 429]:
            print(f"    ↳ [!] WAF/Bot Protection triggered! Status: {response.status_code}")
            
        return response
        
    except Exception as e:
        # 5. Print the exact network error (Timeout, Connection Refused, etc.)
        print(f"    ↳ [!] NETWORK ERROR: {e}")
        return None
