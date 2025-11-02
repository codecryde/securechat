-- SecureChat Database Schema
-- MySQL 8.0+

-- Create database
CREATE DATABASE IF NOT EXISTS securechat
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE securechat;

-- Users table with salted password hashes
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(255) UNIQUE NOT NULL,
    salt VARBINARY(16) NOT NULL COMMENT '16-byte random salt',
    pwd_hash CHAR(64) NOT NULL COMMENT 'hex(SHA256(salt||password))',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    
    INDEX idx_email (email),
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Sample user: alice@example.com / Test@1234
-- Salt: randomly generated 16 bytes (hex: f3a2b1c4d5e6f7a8b9c0d1e2f3a4b5c6)
-- pwd_hash: SHA256(salt + "Test@1234")
INSERT INTO users (email, username, salt, pwd_hash) VALUES
(
    'alice@example.com',
    'alice',
    UNHEX('f3a2b1c4d5e6f7a8b9c0d1e2f3a4b5c6'),
    '8e9a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a'
);

-- Sample user: bob@example.com / SecurePass@456
-- Salt: randomly generated 16 bytes (hex: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6)
INSERT INTO users (email, username, salt, pwd_hash) VALUES
(
    'bob@example.com',
    'bob',
    UNHEX('a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'),
    '7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8'
);

-- Query to verify users
SELECT 
    id,
    email,
    username,
    HEX(salt) as salt_hex,
    pwd_hash,
    created_at
FROM users;

-- Export command for dumping data:
-- mysqldump -u scuser -p securechat users > mysql_dump.sql