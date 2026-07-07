import datetime
import socket
import ssl

from database import Vulnerability
from enforcer import ScopeEnforcer

# Note: relies on the `cryptography` library (a dependency of `requests`/`pyOpenSSL`).
# If it's not installed, run: pip install cryptography pyOpenSSL


class SSLScanner:
    """
    Connects to a host/port over TLS and inspects the peer certificate for
    common misconfigurations: self-signed certs, expiry, and cipher strength.
    """

    EXPIRY_WARNING_DAYS = 30

    def __init__(self, enforcer: ScopeEnforcer, hostname: str, port: int = 5000):
        self.enforcer = enforcer
        self.hostname = hostname
        self.port = port

    def scan(self) -> list[Vulnerability]:
        print(f"\n[*] Starting SSL/TLS Analysis on {self.hostname}:{self.port}...")
        vulnerabilities: list[Vulnerability] = []

        is_allowed, reason = self.enforcer.check(f"https://{self.hostname}:{self.port}/")
        if not is_allowed:
            print(f"    ↳ [!] BLOCKED BY SCOPE: {reason}")
            return vulnerabilities

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with (
                socket.create_connection((self.hostname, self.port), timeout=10) as sock,
                context.wrap_socket(sock, server_hostname=self.hostname) as ssock,
            ):
                cert = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()

            vulnerabilities.extend(self._check_cert(cert))  # type: ignore[arg-type]
            vulnerabilities.extend(self._check_cipher(cipher))

        except Exception as e:
            print(f"    ↳ [!] SSL CONNECTION ERROR: {e}")

        print(f"[*] SSL/TLS analysis complete. Found {len(vulnerabilities)} findings.")
        return vulnerabilities

    def _check_cert(self, der_cert: bytes) -> list[Vulnerability]:
        from cryptography import x509

        findings: list[Vulnerability] = []
        cert = x509.load_der_x509_certificate(der_cert)

        if cert.issuer == cert.subject:
            findings.append({
                "type": "Self-Signed SSL Certificate Detected",
                "severity": "MEDIUM",
                "url": f"https://{self.hostname}:{self.port}/",
                "vulnerable_param": "N/A",
                "payload_used": "N/A",
                "description": f"The certificate for {self.hostname} is self-signed (issuer matches subject: {cert.subject}), meaning it is not trusted by a recognized Certificate Authority.",
                "remediation": "Use a certificate issued by a trusted Certificate Authority (e.g. Let's Encrypt) for any publicly accessible service."
            })

        # not_valid_after_utc was added in cryptography 42.0; fall back to the
        # older naive-datetime attribute for earlier installed versions.
        if hasattr(cert, "not_valid_after_utc"):
            not_after = cert.not_valid_after_utc
        else:
            not_after = cert.not_valid_after.replace(tzinfo=datetime.UTC)
        now = datetime.datetime.now(datetime.UTC)
        days_remaining = (not_after - now).days

        if days_remaining < 0:
            findings.append({
                "type": "Expired SSL Certificate",
                "severity": "HIGH",
                "url": f"https://{self.hostname}:{self.port}/",
                "vulnerable_param": "N/A",
                "payload_used": "N/A",
                "description": f"The SSL certificate expired on {not_after.isoformat()}.",
                "remediation": "Renew the SSL certificate immediately to restore secure, trusted connections."
            })
        elif days_remaining <= self.EXPIRY_WARNING_DAYS:
            findings.append({
                "type": "SSL Certificate Expiring Soon",
                "severity": "HIGH",
                "url": f"https://{self.hostname}:{self.port}/",
                "vulnerable_param": "N/A",
                "payload_used": "N/A",
                "description": f"The SSL certificate expires on {not_after.isoformat()} ({days_remaining} day(s) remaining).",
                "remediation": "Renew the SSL certificate before it expires to avoid service disruption and browser trust warnings."
            })

        return findings

    def _check_cipher(self, cipher: tuple[str, str, int] | None) -> list[Vulnerability]:
        if not cipher:
            return []

        cipher_name, tls_version, secret_bits = cipher
        return [{
            "type": "SSL Cipher Suite Information",
            "severity": "LOW",
            "url": f"https://{self.hostname}:{self.port}/",
            "vulnerable_param": "N/A",
            "payload_used": "N/A",
            "description": f"Connection negotiated using {tls_version} with cipher {cipher_name} ({secret_bits}-bit).",
            "remediation": "Verify the negotiated protocol/cipher meet current best practices (TLS 1.2+ with strong AEAD ciphers)."
        }]
