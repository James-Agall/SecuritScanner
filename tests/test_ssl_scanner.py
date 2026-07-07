import datetime
from unittest.mock import MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from ssl_scanner import SSLScanner


def build_self_signed_der(days_valid=365, days_from_now=0):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    now = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=days_from_now)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


class TestSSLScannerCertChecks:
    def test_self_signed_cert_flagged(self, enforcer):
        scanner = SSLScanner(enforcer, "localhost", 5000)
        der = build_self_signed_der(days_valid=365)
        findings = scanner._check_cert(der)
        assert any(f["type"] == "Self-Signed SSL Certificate Detected" for f in findings)

    def test_expiring_soon_flagged_high(self, enforcer):
        scanner = SSLScanner(enforcer, "localhost", 5000)
        der = build_self_signed_der(days_valid=10)
        findings = scanner._check_cert(der)
        expiring = [f for f in findings if f["type"] == "SSL Certificate Expiring Soon"]
        assert len(expiring) == 1
        assert expiring[0]["severity"] == "HIGH"

    def test_healthy_cert_not_flagged_as_expiring(self, enforcer):
        scanner = SSLScanner(enforcer, "localhost", 5000)
        der = build_self_signed_der(days_valid=365)
        findings = scanner._check_cert(der)
        assert not any(f["type"] in ("Expired SSL Certificate", "SSL Certificate Expiring Soon") for f in findings)

    def test_expired_cert_flagged(self, enforcer):
        scanner = SSLScanner(enforcer, "localhost", 5000)
        # Valid window entirely in the past
        der = build_self_signed_der(days_valid=1, days_from_now=-100)
        findings = scanner._check_cert(der)
        assert any(f["type"] == "Expired SSL Certificate" for f in findings)


class TestSSLScannerCipherCheck:
    def test_cipher_info_reported(self, enforcer):
        scanner = SSLScanner(enforcer, "localhost", 5000)
        findings = scanner._check_cipher(("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256))
        assert len(findings) == 1
        assert "TLSv1.3" in findings[0]["description"]

    def test_no_cipher_returns_empty(self, enforcer):
        scanner = SSLScanner(enforcer, "localhost", 5000)
        assert scanner._check_cipher(None) == []


class TestSSLScannerScan:
    def test_blocked_by_scope_returns_empty(self):
        from enforcer import ScopeEnforcer
        e = ScopeEnforcer({"allowed_domains": [], "allowed_ports": [5000]})
        scanner = SSLScanner(e, "localhost", 5000)
        assert scanner.scan() == []

    def test_connection_error_is_caught(self, enforcer):
        scanner = SSLScanner(enforcer, "localhost", 5000)
        with patch("socket.create_connection", side_effect=ConnectionRefusedError("refused")):
            findings = scanner.scan()
        assert findings == []

    def test_successful_scan_combines_cert_and_cipher_findings(self, enforcer):
        scanner = SSLScanner(enforcer, "localhost", 5000)
        der = build_self_signed_der(days_valid=365)

        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = der
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.__enter__.return_value = mock_ssock
        mock_ssock.__exit__.return_value = False

        mock_context = MagicMock()
        mock_context.wrap_socket.return_value = mock_ssock

        mock_sock = MagicMock()
        mock_sock.__enter__.return_value = mock_sock
        mock_sock.__exit__.return_value = False

        with patch("socket.create_connection", return_value=mock_sock), \
             patch("ssl.create_default_context", return_value=mock_context):
            findings = scanner.scan()

        types = {f["type"] for f in findings}
        assert "Self-Signed SSL Certificate Detected" in types
        assert "SSL Cipher Suite Information" in types
