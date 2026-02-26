import os
import base64

def generate_salt(length: int = 16) -> bytes:
    """
    Generate a cryptographically secure random salt.
    """
    return os.urandom(length)


def encode_base64(data: bytes) -> str:
    """
    Encode bytes to base64 string.
    """
    return base64.urlsafe_b64encode(data).decode()


def decode_base64(data: str) -> bytes:
    """
    Decode base64 string back to bytes.
    """
    return base64.urlsafe_b64decode(data.encode())
