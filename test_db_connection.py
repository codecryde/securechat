"""Quick test for database connectivity."""
import mysql.connector
from dotenv import load_dotenv
import os

load_dotenv()

config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', 3307)),  # Updated default
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
}

print("Testing MySQL connection...")
print(f"Host: {config['host']}")
print(f"Port: {config['port']}")
print(f"User: {config['user']}")
print(f"Password: {'*' * len(config['password'])}")

try:
    conn = mysql.connector.connect(**config)
    print("\n✅ Connection successful!")
    
    # Create database if not exists
    cursor = conn.cursor()
    cursor.execute("CREATE DATABASE IF NOT EXISTS securechat")
    cursor.execute("USE securechat")
    
    print("✅ Database 'securechat' ready")
    
    cursor.close()
    conn.close()
    
except mysql.connector.Error as err:
    print(f"\n❌ Connection failed: {err}")
    print("\nTroubleshooting:")
    print("1. Verify Docker container is running: docker ps")
    print("2. Check .env file has DB_PORT=3307")
    print("3. Restart container if needed")