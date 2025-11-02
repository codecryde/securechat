"""Test message integrity - tamper detection."""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.common.utils import b64e, b64d
from app.crypto.sign import sign_data, verify_signature
from app.crypto.aes import aes_encrypt
import secrets

def test_tamper_ciphertext():
    """Test that tampering with ciphertext invalidates signature."""
    print("\n=== Test 1: Tamper Ciphertext ===")
    
    # Create a test message
    plaintext = b"Hello, SecureChat! This is a test message."
    key = secrets.token_bytes(16)
    
    # Encrypt with AES-ECB
    ciphertext = aes_encrypt(plaintext, key)
    ct_b64 = b64e(ciphertext)
    
    # Sign the ciphertext
    seqno = 1
    ts = 1699000000000
    digest_data = f"{seqno}{ts}{ct_b64}".encode('utf-8')
    
    # Load private key for signing
    with open("certs/client.key.pem", "rb") as f:
        private_key = f.read()
    
    signature = sign_data(digest_data, private_key)
    sig_b64 = b64e(signature)
    
    print(f"   Original ciphertext (first 32 chars): {ct_b64[:32]}...")
    print(f"   Original signature (first 32 chars): {sig_b64[:32]}...")
    
    # Now tamper with ciphertext (flip one bit)
    ct_bytes = bytearray(b64d(ct_b64))
    original_byte = ct_bytes[10]
    ct_bytes[10] ^= 0x01  # Flip bit at position 10
    tampered_ct_b64 = b64e(bytes(ct_bytes))
    
    print(f"   Tampered byte at position 10: {original_byte:02x} -> {ct_bytes[10]:02x}")
    
    # Recompute digest with tampered ciphertext
    tampered_digest = f"{seqno}{ts}{tampered_ct_b64}".encode('utf-8')
    
    # Verify signature with tampered data (should fail)
    with open("certs/client.crt.pem", "rb") as f:
        cert = f.read()
    
    sig_bytes = b64d(sig_b64)
    is_valid = verify_signature(tampered_digest, sig_bytes, cert)
    
    if not is_valid:
        print("✅ PASS: Signature verification correctly failed (SIG_FAIL)")
        return True
    else:
        print("❌ FAIL: Tampered message was incorrectly accepted!")
        return False


def test_tamper_seqno():
    """Test that changing seqno invalidates signature."""
    print("\n=== Test 2: Tamper Sequence Number ===")
    
    plaintext = b"Test message for seqno tampering"
    key = secrets.token_bytes(16)
    ciphertext = aes_encrypt(plaintext, key)
    ct_b64 = b64e(ciphertext)
    
    # Sign with seqno=1
    seqno = 1
    ts = 1699000000000
    digest_data = f"{seqno}{ts}{ct_b64}".encode('utf-8')
    
    with open("certs/client.key.pem", "rb") as f:
        private_key = f.read()
    
    signature = sign_data(digest_data, private_key)
    
    print(f"   Original seqno: {seqno}")
    
    # Change seqno to 99
    tampered_seqno = 99
    tampered_digest = f"{tampered_seqno}{ts}{ct_b64}".encode('utf-8')
    
    print(f"   Tampered seqno: {tampered_seqno}")
    
    with open("certs/client.crt.pem", "rb") as f:
        cert = f.read()
    
    is_valid = verify_signature(tampered_digest, signature, cert)
    
    if not is_valid:
        print("✅ PASS: Signature verification correctly failed for modified seqno")
        return True
    else:
        print("❌ FAIL: Modified seqno was incorrectly accepted!")
        return False


def test_tamper_timestamp():
    """Test that changing timestamp invalidates signature."""
    print("\n=== Test 3: Tamper Timestamp ===")
    
    plaintext = b"Test message for timestamp tampering"
    key = secrets.token_bytes(16)
    ciphertext = aes_encrypt(plaintext, key)
    ct_b64 = b64e(ciphertext)
    
    # Sign with original timestamp
    seqno = 1
    ts = 1699000000000
    digest_data = f"{seqno}{ts}{ct_b64}".encode('utf-8')
    
    with open("certs/client.key.pem", "rb") as f:
        private_key = f.read()
    
    signature = sign_data(digest_data, private_key)
    
    print(f"   Original timestamp: {ts}")
    
    # Change timestamp
    tampered_ts = 1699999999999
    tampered_digest = f"{seqno}{tampered_ts}{ct_b64}".encode('utf-8')
    
    print(f"   Tampered timestamp: {tampered_ts}")
    
    with open("certs/client.crt.pem", "rb") as f:
        cert = f.read()
    
    is_valid = verify_signature(tampered_digest, signature, cert)
    
    if not is_valid:
        print("✅ PASS: Signature verification correctly failed for modified timestamp")
        return True
    else:
        print("❌ FAIL: Modified timestamp was incorrectly accepted!")
        return False


if __name__ == "__main__":
    print("🧪 Running Message Tamper Detection Tests")
    print("=" * 60)
    
    results = [
        test_tamper_ciphertext(),
        test_tamper_seqno(),
        test_tamper_timestamp()
    ]
    
    passed = sum(results)
    total = len(results)
    
    print("\n" + "=" * 60)
    print(f"📊 Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("✅ All tamper detection tests PASSED")
        sys.exit(0)
    else:
        print(f"❌ {total - passed} test(s) FAILED")
        sys.exit(1)