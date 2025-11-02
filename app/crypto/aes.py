"""AES-128-ECB encryption with PKCS#7 padding (as per assignment spec)."""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import hashlib

def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext using AES-128-ECB with PKCS#7 padding.
    
    Args:
        plaintext: Data to encrypt
        key: 16-byte AES key (or will be derived via SHA-256)
    
    Returns:
        Ciphertext bytes (no IV needed for ECB)
    """
    # Ensure key is exactly 16 bytes
    if len(key) != 16:
        key = hashlib.sha256(key).digest()[:16]
    
    # Apply PKCS#7 padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    # Encrypt with AES-128-ECB
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),  # ECB mode as per assignment
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return ciphertext


def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-128-ECB with PKCS#7 padding.
    
    Args:
        ciphertext: Encrypted data
        key: 16-byte AES key
    
    Returns:
        Plaintext bytes
    """
    # Ensure key is exactly 16 bytes
    if len(key) != 16:
        key = hashlib.sha256(key).digest()[:16]
    
    # Decrypt with AES-128-ECB
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS#7 padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext
