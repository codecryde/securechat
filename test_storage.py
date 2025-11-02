"""Test script for storage components."""
import secrets
from app.storage.db import UserDB
from app.storage.transcript import Transcript
from app.common.utils import b64e

def test_database():
    """Test database operations."""
    print("\n=== Testing Database ===")
    
    db = UserDB()
    db.connect()
    db.init_tables()
    
    # Test registration
    salt = secrets.token_bytes(16)
    pwd_hash = UserDB.compute_pwd_hash(salt, "TestPassword123!")
    
    success = db.register_user(
        email="test@example.com",
        username="testuser",
        salt=salt,
        pwd_hash=pwd_hash
    )
    print(f"Registration: {'✅' if success else '❌'}")
    
    # Test password verification
    verified = db.verify_password("test@example.com", "TestPassword123!")
    print(f"Password verification: {'✅' if verified else '❌'}")
    
    # Test wrong password
    wrong = db.verify_password("test@example.com", "WrongPassword")
    print(f"Wrong password rejected: {'✅' if not wrong else '❌'}")
    
    db.close()

def test_transcript():
    """Test transcript operations."""
    print("\n=== Testing Transcript ===")
    
    transcript = Transcript("test-session-001", "client")
    
    # Add sample messages
    for i in range(1, 4):
        transcript.append(
            seqno=i,
            timestamp=1699000000000 + i * 1000,
            ciphertext=b64e(f"encrypted_message_{i}".encode()),
            signature=b64e(f"signature_{i}".encode()),
            peer_fingerprint="abc123def456"
        )
    
    # Compute hash
    hash_value = transcript.compute_transcript_hash()
    print(f"Transcript hash: {hash_value[:32]}...")
    
    # Display summary
    transcript.display_summary()
    
    print("✅ Transcript test completed")

if __name__ == "__main__":
    test_database()
    test_transcript()