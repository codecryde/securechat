"""Classic Diffie-Hellman helpers and key derivation."""
import hashlib
import secrets

# Safe 2048-bit prime (RFC 3526 Group 14)
DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)

DH_GENERATOR = 2

def generate_dh_keypair() -> tuple[int, int]:
    """
    Generate DH private and public keys.
    Returns: (private_key, public_key)
    where public_key = g^private_key mod p
    """
    private_key = secrets.randbelow(DH_PRIME - 2) + 1
    public_key = pow(DH_GENERATOR, private_key, DH_PRIME)
    return private_key, public_key

def compute_shared_secret(private_key: int, peer_public_key: int) -> int:
    """
    Compute shared secret from own private key and peer's public key.
    Returns: peer_public_key^private_key mod p
    """
    return pow(peer_public_key, private_key, DH_PRIME)

def derive_aes_key(shared_secret: int) -> bytes:
    """
    Derive 16-byte AES-128 key from shared secret.
    K = Trunc16(SHA256(big-endian(Ks)))
    """
    # Convert shared secret to big-endian bytes
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
    
    # Hash and truncate to 16 bytes
    hash_digest = hashlib.sha256(secret_bytes).digest()
    return hash_digest[:16]
