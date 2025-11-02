"""MySQL user store (salted SHA-256 passwords)."""
import mysql.connector
import hashlib
import os
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

class UserDB:
    """MySQL database handler for user authentication."""
    
    def __init__(self):
        """Initialize database connection."""
        self.config = {
            'host': os.getenv('DB_HOST', 'localhost'),
            'port': int(os.getenv('DB_PORT', 3306)),
            'user': os.getenv('DB_USER', 'scuser'),
            'password': os.getenv('DB_PASSWORD', 'scpass'),
            'database': os.getenv('DB_NAME', 'securechat')
        }
        self.conn = None
        self.cursor = None
    
    def connect(self):
        """Establish database connection."""
        try:
            self.conn = mysql.connector.connect(**self.config)
            self.cursor = self.conn.cursor(dictionary=True)
            print("✅ Connected to MySQL database")
        except mysql.connector.Error as err:
            print(f"❌ Database connection failed: {err}")
            raise
    
    def close(self):
        """Close database connection."""
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()
    
    def init_tables(self):
        """Create users table if not exists."""
        create_table_query = """
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            username VARCHAR(255) UNIQUE NOT NULL,
            salt VARBINARY(16) NOT NULL,
            pwd_hash CHAR(64) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_email (email),
            INDEX idx_username (username)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """
        try:
            self.cursor.execute(create_table_query)
            self.conn.commit()
            print("✅ Users table initialized")
        except mysql.connector.Error as err:
            print(f"❌ Table creation failed: {err}")
            raise
    
    def register_user(self, email: str, username: str, salt: bytes, pwd_hash: str) -> bool:
        """
        Register a new user with salted password hash.
        
        Args:
            email: User email
            username: Unique username
            salt: 16-byte random salt
            pwd_hash: hex(SHA256(salt||password))
        
        Returns:
            True if registration successful, False if user already exists
        """
        insert_query = """
        INSERT INTO users (email, username, salt, pwd_hash)
        VALUES (%s, %s, %s, %s)
        """
        try:
            self.cursor.execute(insert_query, (email, username, salt, pwd_hash))
            self.conn.commit()
            print(f"✅ User registered: {username} ({email})")
            return True
        except mysql.connector.IntegrityError:
            print(f"❌ User already exists: {email} or {username}")
            return False
        except mysql.connector.Error as err:
            print(f"❌ Registration failed: {err}")
            return False
    
    def get_user_by_email(self, email: str) -> Optional[dict]:
        """
        Retrieve user record by email.
        
        Returns:
            dict with keys: id, email, username, salt, pwd_hash, created_at
            or None if not found
        """
        query = "SELECT * FROM users WHERE email = %s"
        try:
            self.cursor.execute(query, (email,))
            return self.cursor.fetchone()
        except mysql.connector.Error as err:
            print(f"❌ Query failed: {err}")
            return None
    
    def verify_password(self, email: str, password: str) -> bool:
        """
        Verify user password using constant-time comparison.
        
        Args:
            email: User email
            password: Plain text password to verify
        
        Returns:
            True if password matches, False otherwise
        """
        user = self.get_user_by_email(email)
        if not user:
            return False
        
        # Recompute hash with stored salt
        salt = user['salt']
        computed_hash = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
        
        # Constant-time comparison to prevent timing attacks
        stored_hash = user['pwd_hash']
        return self._constant_time_compare(computed_hash, stored_hash)
    
    @staticmethod
    def _constant_time_compare(a: str, b: str) -> bool:
        """
        Constant-time string comparison to prevent timing attacks.
        """
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y)
        
        return result == 0
    
    @staticmethod
    def compute_pwd_hash(salt: bytes, password: str) -> str:
        """
        Compute salted password hash.
        
        Returns: hex(SHA256(salt||password))
        """
        return hashlib.sha256(salt + password.encode('utf-8')).hexdigest()


def main():
    """CLI utility for database initialization."""
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--init':
        db = UserDB()
        try:
            db.connect()
            db.init_tables()
            
            # Insert sample user for testing
            import secrets
            sample_salt = secrets.token_bytes(16)
            sample_pwd_hash = UserDB.compute_pwd_hash(sample_salt, "Test@1234")
            
            db.register_user(
                email="alice@example.com",
                username="alice",
                salt=sample_salt,
                pwd_hash=sample_pwd_hash
            )
            
            print("\n✅ Database initialized with sample user:")
            print("   Email: alice@example.com")
            print("   Password: Test@1234")
            
        except Exception as e:
            print(f"❌ Initialization failed: {e}")
            sys.exit(1)
        finally:
            db.close()
    else:
        print("Usage: python -m app.storage.db --init")
        sys.exit(1)


if __name__ == "__main__":
    main()
