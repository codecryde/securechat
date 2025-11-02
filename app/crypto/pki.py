"""X.509 validation (CA signature, validity, CN)."""
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from datetime import datetime, UTC

def load_certificate(cert_pem: bytes) -> x509.Certificate:
    """Load X.509 certificate from PEM bytes."""
    return x509.load_pem_x509_certificate(cert_pem, default_backend())

def validate_certificate(
    cert_pem: bytes,
    ca_cert_pem: bytes,
    expected_cn: str = None
) -> tuple[bool, str]:
    """
    Validate certificate against CA.
    
    Checks:
    1. Signature chain (issued by CA)
    2. Validity period (not expired)
    3. Common Name (if provided)
    
    Returns: (is_valid, error_message)
    """
    try:
        cert = load_certificate(cert_pem)
        ca_cert = load_certificate(ca_cert_pem)
        
        # Check 1: Verify signature chain
        try:
            ca_public_key = ca_cert.public_key()
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                cert.signature_algorithm_parameters,
                cert.signature_hash_algorithm
            )
        except Exception as e:
            return False, f"BAD_CERT: Invalid signature chain - {str(e)}"
        
        # Check 2: Verify validity period
        now = datetime.now(UTC)
        if now < cert.not_valid_before_utc:
            return False, "BAD_CERT: Certificate not yet valid"
        if now > cert.not_valid_after_utc:
            return False, "BAD_CERT: Certificate expired"
        
        # Check 3: Verify Common Name if provided
        if expected_cn:
            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            if cn != expected_cn:
                return False, f"BAD_CERT: CN mismatch (expected {expected_cn}, got {cn})"
        
        return True, "OK"
        
    except Exception as e:
        return False, f"BAD_CERT: Validation error - {str(e)}"

def extract_common_name(cert_pem: bytes) -> str:
    """Extract Common Name from certificate."""
    cert = load_certificate(cert_pem)
    return cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

def get_certificate_fingerprint(cert_pem: bytes) -> str:
    """Get SHA-256 fingerprint of certificate."""
    cert = load_certificate(cert_pem)
    return cert.fingerprint(hashes.SHA256()).hex()
