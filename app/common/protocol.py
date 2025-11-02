"""Pydantic message models for the secure chat protocol."""
from pydantic import BaseModel
from typing import Optional

class HelloMessage(BaseModel):
    """Client hello message with certificate and nonce."""
    type: str = "hello"
    client_cert: str  # PEM format
    nonce: str  # base64 encoded

class ServerHelloMessage(BaseModel):
    """Server hello response with certificate and nonce."""
    type: str = "server_hello"
    server_cert: str  # PEM format
    nonce: str  # base64 encoded

class DHClientMessage(BaseModel):
    """Client DH parameters for key exchange."""
    type: str = "dh_client"
    g: int
    p: int
    A: int  # g^a mod p

class DHServerMessage(BaseModel):
    """Server DH response."""
    type: str = "dh_server"
    B: int  # g^b mod p

class RegisterMessage(BaseModel):
    """User registration message (encrypted)."""
    type: str = "register"
    email: str
    username: str
    pwd: str  # base64(sha256(salt||password))
    salt: str  # base64 encoded salt

class LoginMessage(BaseModel):
    """User login message (encrypted)."""
    type: str = "login"
    email: str
    pwd: str  # base64(sha256(salt||password))
    nonce: str  # base64 encoded

class ChatMessage(BaseModel):
    """Encrypted chat message with signature."""
    type: str = "msg"
    seqno: int
    ts: int  # Unix timestamp in milliseconds
    ct: str  # base64 encoded ciphertext
    sig: str  # base64 encoded RSA signature

class SessionReceipt(BaseModel):
    """Session transcript receipt with signature."""
    type: str = "receipt"
    peer: str  # "client" or "server"
    first_seq: int
    last_seq: int
    transcript_sha256: str  # hex digest
    sig: str  # base64 encoded RSA signature

class ResponseMessage(BaseModel):
    """Generic response message."""
    type: str = "response"
    status: str  # "ok", "error", "BAD_CERT", "SIG_FAIL", "REPLAY"
    message: Optional[str] = None
