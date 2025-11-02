"""RSA SHA-256 sign/verify (PKCS#1 v1.5)."""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

def sign_data(data: bytes, private_key_pem: bytes) -> bytes:
    """
    Sign data using RSA private key with SHA-256.
    Returns: signature bytes
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )
    
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    return signature

def verify_signature(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    """
    Verify RSA signature using public key.
    Returns: True if valid, False otherwise
    """
    try:
        from cryptography import x509
        
        # Try loading as certificate first, then as public key
        try:
            cert = x509.load_pem_x509_certificate(public_key_pem, default_backend())
            public_key = cert.public_key()
        except:
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
        
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False
