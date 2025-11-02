"""Test certificate validation with expired/invalid certs."""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from datetime import datetime, timedelta, UTC
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from app.crypto.pki import validate_certificate

def test_expired_certificate():
    """Test rejection of expired certificate."""
    print("\n=== Test 1: Expired Certificate ===")
    
    # Generate expired certificate
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "expired-client"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org")
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)  # Self-signed
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=365))
        .not_valid_after(datetime.now(UTC) - timedelta(days=1))  # Expired yesterday
        .sign(key, hashes.SHA256())
    )
    
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    
    # Save for inspection
    os.makedirs("certs", exist_ok=True)
    with open("certs/expired.crt.pem", "wb") as f:
        f.write(cert_pem)
    
    # Load CA cert
    with open("certs/ca.crt.pem", "rb") as f:
        ca_cert = f.read()
    
    # Validate (should fail)
    is_valid, error = validate_certificate(cert_pem, ca_cert, "expired-client")
    
    if not is_valid and "expired" in error.lower():
        print(f"✅ PASS: Certificate correctly rejected - {error}")
        return True
    else:
        print(f"❌ FAIL: Expected BAD_CERT (expired), got: is_valid={is_valid}, error={error}")
        return False


def test_self_signed_certificate():
    """Test rejection of self-signed certificate (not issued by CA)."""
    print("\n=== Test 2: Self-Signed Certificate ===")
    
    # Generate self-signed cert
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "self-signed-client"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fake Org")
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)  # Self-signed (not CA)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    
    with open("certs/self-signed.crt.pem", "wb") as f:
        f.write(cert_pem)
    
    with open("certs/ca.crt.pem", "rb") as f:
        ca_cert = f.read()
    
    is_valid, error = validate_certificate(cert_pem, ca_cert, "self-signed-client")
    
    if not is_valid and ("signature" in error.lower() or "issuer" in error.lower()):
        print(f"✅ PASS: Self-signed cert rejected - {error}")
        return True
    else:
        print(f"❌ FAIL: Expected BAD_CERT (invalid signature), got: {error}")
        return False


def test_cn_mismatch():
    """Test rejection when CN doesn't match expected name."""
    print("\n=== Test 3: CN Mismatch ===")
    
    # Use existing client cert but check for wrong CN
    with open("certs/client.crt.pem", "rb") as f:
        client_cert = f.read()
    
    with open("certs/ca.crt.pem", "rb") as f:
        ca_cert = f.read()
    
    # Validate with wrong expected CN
    is_valid, error = validate_certificate(client_cert, ca_cert, "wrong-hostname")
    
    if not is_valid and "mismatch" in error.lower():
        print(f"✅ PASS: CN mismatch detected - {error}")
        return True
    else:
        print(f"❌ FAIL: Expected BAD_CERT (CN mismatch), got: is_valid={is_valid}")
        return False


def test_valid_certificate():
    """Test that valid certificates are accepted."""
    print("\n=== Test 4: Valid Certificate (Control Test) ===")
    
    with open("certs/client.crt.pem", "rb") as f:
        client_cert = f.read()
    
    with open("certs/ca.crt.pem", "rb") as f:
        ca_cert = f.read()
    
    is_valid, error = validate_certificate(client_cert, ca_cert, "client")
    
    if is_valid:
        print(f"✅ PASS: Valid certificate accepted")
        return True
    else:
        print(f"❌ FAIL: Valid certificate rejected - {error}")
        return False


if __name__ == "__main__":
    print("🧪 Running Certificate Validation Tests")
    print("=" * 60)
    
    results = [
        test_expired_certificate(),
        test_self_signed_certificate(),
        test_cn_mismatch(),
        test_valid_certificate()
    ]
    
    passed = sum(results)
    total = len(results)
    
    print("\n" + "=" * 60)
    print(f"📊 Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("✅ All certificate validation tests PASSED")
        sys.exit(0)
    else:
        print(f"❌ {total - passed} test(s) FAILED")
        sys.exit(1)