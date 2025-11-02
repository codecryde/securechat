"""AES-128-CBC encryption with PKCS#7 padding using cryptography library."""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Apply PKCS#7 padding to data."""
    padder = padding.PKCS7(block_size * 8).padder()
    return padder.update(data) + padder.finalize()

def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """Remove PKCS#7 padding from data."""
    unpadder = padding.PKCS7(block_size * 8).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext using AES-128-CBC.
    Returns: IV (16 bytes) + ciphertext
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires 16-byte key")
    
    # Generate random IV
    iv = os.urandom(16)
    
    # Pad plaintext
    padded = pkcs7_pad(plaintext)
    
    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    
    # Return IV + ciphertext
    return iv + ciphertext

def aes_decrypt(data: bytes, key: bytes) -> bytes:
    """
    Decrypt data using AES-128-CBC.
    Expects: IV (16 bytes) + ciphertext
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires 16-byte key")
    
    if len(data) < 16:
        raise ValueError("Invalid ciphertext: too short")
    
    # Extract IV and ciphertext
    iv = data[:16]
    ciphertext = data[16:]
    
    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    return pkcs7_unpad(padded)
