"""MySQL user store (salted SHA-256 passwords)."""

from __future__ import annotations
import hashlib
import os
import hmac
from typing import Optional, Dict, Any
from dotenv import load_dotenv

load_dotenv()


class UserDB:
    """MySQL database handler for user authentication."""

    def __init__(self) -> None:
        """Initialize database connection config (connection made with connect())."""
        # Environment defaults
        self.config = {
            "host": os.getenv("DB_HOST", "localhost"),
            "port": int(os.getenv("DB_PORT", "3306")),
            "user": os.getenv("DB_USER", "scuser"),
            "password": os.getenv("DB_PASSWORD", "scpass"),
            "database": os.getenv("DB_NAME", "securechat"),
        }
        self.conn = None
        self.cursor = None

    def connect(self) -> None:
        """Establish database connection."""
        try:
            import mysql.connector
            from mysql.connector import errors as mysql_errors  # type: ignore
        except Exception as err:
            raise RuntimeError(
                "mysql.connector not available — install with `pip install mysql-connector-python`"
            ) from err

        try:
            self.conn = mysql.connector.connect(**self.config)
            # Use dictionary cursor for convenient column access by name
            self.cursor = self.conn.cursor(dictionary=True)
            print("✅ Connected to MySQL database")
        except Exception as err:
            # Re-raise with a clearer message
            raise RuntimeError(f"Database connection failed: {err}") from err

    def close(self) -> None:
        """Close database connection."""
        if self.cursor:
            try:
                self.cursor.close()
            except Exception:
                pass
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass

    def init_tables(self) -> None:
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
        if not self.cursor:
            raise RuntimeError("Database cursor is not available. Call connect() first.")
        try:
            self.cursor.execute(create_table_query)
            self.conn.commit()
            print("✅ Users table initialized")
        except Exception as err:
            raise RuntimeError(f"Table creation failed: {err}") from err

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
        if not self.cursor:
            raise RuntimeError("Database cursor is not available. Call connect() first.")

        insert_query = """
        INSERT INTO users (email, username, salt, pwd_hash)
        VALUES (%s, %s, %s, %s)
        """
        try:
            self.cursor.execute(insert_query, (email, username, salt, pwd_hash))
            self.conn.commit()
            print(f"✅ User registered: {username} ({email})")
            return True
        except Exception as err:
            # best-effort detection of duplicate-entry error (MySQL error 1062)
            errno = getattr(err, "errno", None)
            msg = str(err).lower()
            if errno == 1062 or "duplicate" in msg or "unique" in msg:
                print(f"❌ User already exists: {email} or {username}")
                return False
            print(f"❌ Registration failed: {err}")
            return False

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve user record by email.

        Returns:
            dict with keys: id, email, username, salt, pwd_hash, created_at
            or None if not found
        """
        if not self.cursor:
            raise RuntimeError("Database cursor is not available. Call connect() first.")
        query = "SELECT * FROM users WHERE email = %s"
        try:
            self.cursor.execute(query, (email,))
            return self.cursor.fetchone()
        except Exception as err:
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
        salt = user["salt"]
        if salt is None:
            return False
        computed_hash = UserDB.compute_pwd_hash(salt, password)

        # Constant-time comparison to prevent timing attacks (use hmac.compare_digest)
        stored_hash = user["pwd_hash"]
        return UserDB._constant_time_compare(computed_hash, stored_hash)

    @staticmethod
    def _constant_time_compare(a: str, b: str) -> bool:
        """
        Constant-time string comparison to prevent timing attacks.
        Uses hmac.compare_digest which is safe for secrets.
        """
        try:
            return hmac.compare_digest(a, b)
        except Exception:
            # fallback: ensure same length and do manual compare (rare)
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
        return hashlib.sha256(salt + password.encode("utf-8")).hexdigest()


def main() -> None:
    """CLI utility for database initialization."""
    import sys
    import secrets

    # Slightly friendlier CLI
    if len(sys.argv) > 1 and sys.argv[1] in ("--init", "init"):
        db = UserDB()
        try:
            db.connect()
            db.init_tables()

            # Insert sample user for testing
            sample_salt = secrets.token_bytes(16)
            sample_pwd_hash = UserDB.compute_pwd_hash(sample_salt, "Test@1234")

            ok = db.register_user(
                email="alice@example.com",
                username="alice",
                salt=sample_salt,
                pwd_hash=sample_pwd_hash,
            )

            if ok:
                print("\n✅ Database initialized with sample user:")
                print("   Email: alice@example.com")
                print("   Password: Test@1234")
            else:
                print("\n⚠ Sample user not inserted (it may already exist).")

        except Exception as e:
            print(f"❌ Initialization failed: {e}")
            sys.exit(1)
        finally:
            db.close()
    else:
        print("Usage: python db.py --init    # Initializes DB and inserts a sample user")
        sys.exit(1)


if __name__ == "__main__":
    main()
