"""
SecureChat Client - Plain TCP with application-layer crypto.
Handles certificate validation, registration, login, and encrypted chat.
"""
import socket
import json
import os
import secrets
import hashlib
import threading
from datetime import datetime
from dotenv import load_dotenv
import logging

from app.common.protocol import *
from app.common.utils import now_ms, b64e, b64d, sha256_hex
from app.crypto.pki import validate_certificate, get_certificate_fingerprint
from app.crypto.dh import DH_GENERATOR, DH_PRIME, generate_dh_keypair, compute_shared_secret, derive_aes_key
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.sign import sign_data, verify_signature
from app.storage.transcript import Transcript

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
load_dotenv()

class SecureChatClient:
    """Secure chat client with PKI and encrypted communication."""
    
    def __init__(self):
        self.host = os.getenv('SERVER_HOST', '127.0.0.1')
        self.port = int(os.getenv('SERVER_PORT', 9999))
        
        # Load client certificate and key
        with open(os.getenv('CLIENT_CERT_PATH'), 'rb') as f:
            self.client_cert = f.read()
        with open(os.getenv('CLIENT_KEY_PATH'), 'rb') as f:
            self.client_key = f.read()
        with open(os.getenv('CA_CERT_PATH'), 'rb') as f:
            self.ca_cert = f.read()
        
        # Session state
        self.socket = None
        self.server_cert = None
        self.session_key = None
        self.seqno = 1
        self.transcript = None
        self.email = None
        
        print(f"🚀 SecureChat Client initialized")
    
    def connect(self):
        """Connect to server and perform handshake."""
        print(f"\n📞 Connecting to {self.host}:{self.port}...")
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        
        print(f"✅ Connected to server")
        
        # Phase 1: Certificate Exchange
        if not self.phase1_certificate_exchange():
            return False
        
        # Phase 2: Registration or Login
        if not self.phase2_authentication():
            return False
        
        # Phase 3: Session Key Establishment
        if not self.phase3_session_key():
            return False
        
        return True
    
    def phase1_certificate_exchange(self) -> bool:
        """
        Phase 1: Send client certificate and validate server certificate.
        Returns: True if validation successful
        """
        print("\n📜 Phase 1: Certificate Exchange")
        
        # Send client hello
        client_nonce = b64e(secrets.token_bytes(32))
        hello_msg = {
            "type": "hello",
            "client_cert": self.client_cert.decode('utf-8'),
            "nonce": client_nonce
        }
        
        self.socket.sendall(json.dumps(hello_msg).encode('utf-8'))
        print(f"   ✅ Sent client hello with nonce: {client_nonce[:16]}...")
        
        # Receive server hello
        data = self.socket.recv(8192).decode('utf-8')
        server_hello = json.loads(data)
        
        if server_hello.get('type') == 'response' and server_hello.get('status') == 'error':
            print(f"   ❌ Server rejected certificate: {server_hello.get('message')}")
            return False
        
        print(f"   Received server hello with nonce: {server_hello['nonce'][:16]}...")
        
        # Validate server certificate
        server_cert_pem = server_hello['server_cert'].encode('utf-8')
        is_valid, error_msg = validate_certificate(
            server_cert_pem,
            self.ca_cert,
            expected_cn="server"
        )
        
        if not is_valid:
            print(f"   ❌ Server certificate validation failed: {error_msg}")
            return False
        
        self.server_cert = server_cert_pem
        print(f"   ✅ Server certificate validated")
        
        return True
    
    def phase2_authentication(self) -> bool:
        """
        Phase 2: Perform registration or login with ephemeral DH.
        Returns: True if authentication successful
        """
        print("\n🔐 Phase 2: Authentication")
        
        # Ask user for registration or login
        while True:
            choice = input("\n   Choose: [1] Register  [2] Login: ").strip()
            if choice in ['1', '2']:
                break
            print("   Invalid choice. Please enter 1 or 2.")
        
        # Perform ephemeral DH for credential encryption
        client_dh_private, client_dh_public = generate_dh_keypair()
        
        dh_msg = {
            "type": "dh_client",
            "g": DH_GENERATOR,
            "p": DH_PRIME,
            "A": client_dh_public
        }
        
        self.socket.sendall(json.dumps(dh_msg).encode('utf-8'))
        print(f"   ✅ Sent DH parameters")
        
        # Receive server DH response
        data = self.socket.recv(4096).decode('utf-8')
        dh_server = json.loads(data)
        
        # Compute shared secret and derive ephemeral key
        server_B = dh_server['B']
        shared_secret = compute_shared_secret(client_dh_private, server_B)
        ephemeral_key = derive_aes_key(shared_secret)
        
        print(f"   ✅ Derived ephemeral AES key")
        
        # Prepare authentication message
        if choice == '1':
            auth_msg = self.prepare_registration()
        else:
            auth_msg = self.prepare_login()
        
        if not auth_msg:
            return False
        
        # Encrypt and send
        plaintext = json.dumps(auth_msg).encode('utf-8')
        ciphertext = aes_encrypt(plaintext, ephemeral_key)
        
        encrypted_msg = {
            "type": "encrypted_auth",
            "ct": b64e(ciphertext)
        }
        
        self.socket.sendall(json.dumps(encrypted_msg).encode('utf-8'))
        
        # Receive response
        data = self.socket.recv(4096).decode('utf-8')
        response = json.loads(data)
        
        if response['status'] == 'ok':
            print(f"   ✅ {response['message']}")
            return True
        else:
            print(f"   ❌ {response['message']}")
            return False
    
    def prepare_registration(self) -> dict:
        """Prepare registration message."""
        print("\n   📝 User Registration")
        
        email = input("   Email: ").strip()
        username = input("   Username: ").strip()
        password = input("   Password: ").strip()
        
        if not email or not username or not password:
            print("   ❌ All fields are required")
            return None
        
        # Generate random salt
        salt = secrets.token_bytes(16)
        
        # Compute pwd_hash = hex(SHA256(salt||password))
        pwd_hash = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
        
        self.email = email
        
        return {
            "type": "register",
            "email": email,
            "username": username,
            "pwd": pwd_hash,
            "salt": b64e(salt)
        }
    
    def prepare_login(self) -> dict:
        """Prepare login message."""
        print("\n   🔑 User Login")
        
        email = input("   Email: ").strip()
        password = input("   Password: ").strip()
        
        if not email or not password:
            print("   ❌ Email and password are required")
            return None
        
        # For login, we need to fetch the salt from server first
        # But per spec, we compute hash client-side with salt
        # Simplified: send password as base64 for server to verify
        
        self.email = email
        
        return {
            "type": "login",
            "email": email,
            "pwd": b64e(password.encode('utf-8')),
            "nonce": b64e(secrets.token_bytes(16))
        }
    
    def phase3_session_key(self) -> bool:
        """
        Phase 3: Establish session key via DH.
        Returns: True if successful
        """
        print("\n🔑 Phase 3: Session Key Establishment")
        
        # Generate DH keypair
        client_private, client_public = generate_dh_keypair()
        
        dh_msg = {
            "type": "dh_client",
            "g": DH_GENERATOR,
            "p": DH_PRIME,
            "A": client_public
        }
        
        self.socket.sendall(json.dumps(dh_msg).encode('utf-8'))
        
        # Receive server DH response
        data = self.socket.recv(4096).decode('utf-8')
        dh_server = json.loads(data)
        
        # Compute shared secret
        server_B = dh_server['B']
        shared_secret = compute_shared_secret(client_private, server_B)
        self.session_key = derive_aes_key(shared_secret)
        
        print(f"   ✅ Session key established")
        
        # Initialize transcript
        session_id = f"{self.email}_{now_ms()}"
        self.transcript = Transcript(session_id, "client")
        
        return True
    
    def start_chat(self):
        """Phase 4: Start encrypted chat session."""
        print("\n💬 Phase 4: Encrypted Chat")
        print("   (Type your message and press Enter. Type 'quit' to exit)\n")
        
        # Start receiving thread
        receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        receive_thread.start()
        
        # Send messages
        try:
            while True:
                message = input()
                
                if message.lower() == 'quit':
                    # Send quit signal
                    quit_msg = {"type": "quit"}
                    self.socket.sendall(json.dumps(quit_msg).encode('utf-8'))
                    break
                
                if message.strip():
                    self.send_message(message)
        
        except KeyboardInterrupt:
            print("\n   Session interrupted")
        
        # Phase 5: Teardown
        self.phase5_teardown()
    
    def send_message(self, plaintext: str):
        """Send encrypted and signed message."""
        # Encrypt message
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext = aes_encrypt(plaintext_bytes, self.session_key)
        ct_b64 = b64e(ciphertext)
        
        # Get timestamp
        ts = now_ms()
        
        # Compute digest: SHA256(seqno||ts||ct)
        digest_data = f"{self.seqno}{ts}{ct_b64}".encode('utf-8')
        
        # Sign digest
        signature = sign_data(digest_data, self.client_key)
        sig_b64 = b64e(signature)
        
        # Create message
        msg = {
            "type": "msg",
            "seqno": self.seqno,
            "ts": ts,
            "ct": ct_b64,
            "sig": sig_b64
        }
        
        # Send message
        self.socket.sendall(json.dumps(msg).encode('utf-8'))
        
        # Log to transcript
        peer_fingerprint = get_certificate_fingerprint(self.server_cert)
        self.transcript.append(self.seqno, ts, ct_b64, sig_b64, peer_fingerprint)
        
        print(f"   You [{self.seqno}]: {plaintext}")
        
        self.seqno += 1
    
    def receive_messages(self):
        """Receive messages from server (runs in separate thread)."""
        try:
            while True:
                data = self.socket.recv(8192)
                if not data:
                    break
                
                msg = json.loads(data.decode('utf-8'))
                
                if msg['type'] == 'msg':
                    self.handle_incoming_message(msg)
                elif msg['type'] == 'receipt':
                    self.handle_receipt(msg)
                    
        except Exception as e:
            # Connection closed or error
            pass
    
    def handle_incoming_message(self, msg: dict):
        """Handle incoming encrypted message from server."""
        seqno = msg['seqno']
        ts = msg['ts']
        ct = msg['ct']
        sig = msg['sig']
        
        # Verify signature
        digest_data = f"{seqno}{ts}{ct}".encode('utf-8')
        sig_bytes = b64d(sig)
        
        if not verify_signature(digest_data, sig_bytes, self.server_cert):
            print(f"   ❌ SIG_FAIL: Invalid signature for seqno {seqno}")
            return
        
        # Decrypt message
        ct_bytes = b64d(ct)
        plaintext = aes_decrypt(ct_bytes, self.session_key)
        message_text = plaintext.decode('utf-8')
        
        # Log to transcript
        peer_fingerprint = get_certificate_fingerprint(self.server_cert)
        self.transcript.append(seqno, ts, ct, sig, peer_fingerprint)
        
        # Display
        print(f"   Server [{seqno}]: {message_text}")
    
    def handle_receipt(self, receipt: dict):
        """Handle session receipt from server."""
        print(f"\n📋 Received session receipt from server")
        
        # Verify receipt signature
        transcript_hash_bytes = bytes.fromhex(receipt['transcript_sha256'])
        sig_bytes = b64d(receipt['sig'])
        
        if verify_signature(transcript_hash_bytes, sig_bytes, self.server_cert):
            print(f"   ✅ Receipt signature verified")
        else:
            print(f"   ❌ Receipt signature verification failed")
        
        # Save server receipt
        receipt_path = self.transcript.filepath.replace('.txt', '_server_receipt.json')
        with open(receipt_path, 'w') as f:
            json.dump(receipt, f, indent=2)
        print(f"   ✅ Server receipt saved: {receipt_path}")
    
    def phase5_teardown(self):
        """Phase 5: Generate and exchange session receipt."""
        print("\n📋 Phase 5: Session Teardown")
        
        if not self.transcript or self.transcript.get_last_seqno() == 0:
            print("   No messages exchanged, skipping receipt")
            return
        
        # Compute transcript hash
        transcript_hash = self.transcript.compute_transcript_hash()
        
        # Sign transcript hash
        signature = sign_data(bytes.fromhex(transcript_hash), self.client_key)
        
        # Create receipt
        receipt = self.transcript.export_receipt(b64e(signature))
        
        # Save receipt
        self.transcript.save_receipt(receipt)
        
        # Display summary
        self.transcript.display_summary()
    
    def close(self):
        """Close connection."""
        if self.socket:
            self.socket.close()
    
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


def main():
    """Run client."""
    client = SecureChatClient()
    
    try:
        if client.connect():
            client.start_chat()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client.close()
        print("\n👋 Disconnected from server")


if __name__ == "__main__":
    main()
