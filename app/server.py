"""Server skeleton — plain TCP; no TLS. See assignment spec."""

import os
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def main():
    raise NotImplementedError("students: implement server workflow")

def validate_config():
    """Ensure required files and settings exist."""
    required_files = [
        os.getenv('CA_CERT_PATH'),
        os.getenv('SERVER_CERT_PATH'),
        os.getenv('SERVER_KEY_PATH')
    ]
    for file in required_files:
        if not os.path.exists(file):
            raise FileNotFoundError(f"Required file missing: {file}")

if __name__ == "__main__":
    main()
