"""Append-only transcript + transcript hash computation."""
import os
import hashlib
from datetime import datetime
from typing import List

class Transcript:
    """
    Manages append-only session transcripts for non-repudiation.
    
    Format: seqno | timestamp | ciphertext | signature | peer_cert_fingerprint
    """
    
    def __init__(self, session_id: str, role: str):
        """
        Initialize transcript for a session.
        
        Args:
            session_id: Unique session identifier
            role: "client" or "server"
        """
        self.session_id = session_id
        self.role = role
        self.lines: List[str] = []
        self.filepath = self._get_filepath()
        
        # Create transcripts directory if not exists
        os.makedirs("transcripts", exist_ok=True)
    
    def _get_filepath(self) -> str:
        """Generate transcript file path."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.role}_{self.session_id}_{timestamp}.txt"
        return os.path.join("transcripts", filename)
    
    def append(self, seqno: int, timestamp: int, ciphertext: str, 
               signature: str, peer_fingerprint: str):
        """
        Append a message record to transcript.
        
        Args:
            seqno: Sequence number
            timestamp: Unix timestamp in milliseconds
            ciphertext: Base64 encoded ciphertext
            signature: Base64 encoded RSA signature
            peer_fingerprint: SHA-256 fingerprint of peer certificate
        """
        line = f"{seqno}|{timestamp}|{ciphertext}|{signature}|{peer_fingerprint}"
        self.lines.append(line)
        
        # Write to file immediately (append-only)
        with open(self.filepath, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
    
    def compute_transcript_hash(self) -> str:
        """
        Compute SHA-256 hash of entire transcript.
        
        Returns: Hex digest of transcript hash
        """
        # Concatenate all lines
        transcript_content = '\n'.join(self.lines).encode('utf-8')
        
        # Compute SHA-256
        return hashlib.sha256(transcript_content).hexdigest()
    
    def get_first_seqno(self) -> int:
        """Get first sequence number in transcript."""
        if not self.lines:
            return 0
        return int(self.lines[0].split('|')[0])
    
    def get_last_seqno(self) -> int:
        """Get last sequence number in transcript."""
        if not self.lines:
            return 0
        return int(self.lines[-1].split('|')[0])
    
    def export_receipt(self, signature: str) -> dict:
        """
        Generate session receipt with signed transcript hash.
        
        Args:
            signature: Base64 encoded RSA signature of transcript hash
        
        Returns:
            SessionReceipt dictionary
        """
        return {
            "type": "receipt",
            "peer": self.role,
            "first_seq": self.get_first_seqno(),
            "last_seq": self.get_last_seqno(),
            "transcript_sha256": self.compute_transcript_hash(),
            "sig": signature
        }
    
    def save_receipt(self, receipt: dict):
        """Save session receipt to file."""
        receipt_path = self.filepath.replace('.txt', '_receipt.json')
        
        import json
        with open(receipt_path, 'w', encoding='utf-8') as f:
            json.dump(receipt, f, indent=2)
        
        print(f"✅ Session receipt saved: {receipt_path}")
    
    @staticmethod
    def verify_transcript(transcript_file: str, receipt_file: str, 
                         cert_pem: bytes) -> bool:
        """
        Offline verification of transcript integrity.
        
        Args:
            transcript_file: Path to transcript file
            receipt_file: Path to receipt JSON file
            cert_pem: Certificate PEM bytes for signature verification
        
        Returns:
            True if transcript is valid and matches receipt
        """
        import json
        from app.crypto.sign import verify_signature
        from app.common.utils import b64d
        
        # Load transcript
        with open(transcript_file, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]
        
        # Load receipt
        with open(receipt_file, 'r', encoding='utf-8') as f:
            receipt = json.load(f)
        
        # Recompute transcript hash
        transcript_content = '\n'.join(lines).encode('utf-8')
        computed_hash = hashlib.sha256(transcript_content).hexdigest()
        
        # Check hash match
        if computed_hash != receipt['transcript_sha256']:
            print(f"❌ Transcript hash mismatch!")
            print(f"   Computed: {computed_hash}")
            print(f"   Receipt:  {receipt['transcript_sha256']}")
            return False
        
        # Verify signature
        signature = b64d(receipt['sig'])
        hash_bytes = bytes.fromhex(receipt['transcript_sha256'])
        
        if not verify_signature(hash_bytes, signature, cert_pem):
            print(f"❌ Receipt signature verification failed!")
            return False
        
        print(f"✅ Transcript verification successful")
        print(f"   First seq: {receipt['first_seq']}")
        print(f"   Last seq:  {receipt['last_seq']}")
        print(f"   Hash: {receipt['transcript_sha256'][:32]}...")
        
        return True
    
    def display_summary(self):
        """Display transcript summary."""
        print(f"\n📝 Transcript Summary ({self.role})")
        print(f"   Session ID: {self.session_id}")
        print(f"   Total messages: {len(self.lines)}")
        print(f"   First seqno: {self.get_first_seqno()}")
        print(f"   Last seqno: {self.get_last_seqno()}")
        print(f"   Transcript hash: {self.compute_transcript_hash()[:32]}...")
        print(f"   File: {self.filepath}")
