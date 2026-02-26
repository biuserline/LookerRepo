import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from .utils import generate_salt


class NebulaCrypto:
    """
    Core cryptographic engine for NebulaVault.
    """

    def __init__(self, iterations: int = 200_000):
        # Number of PBKDF2 iterations
        self.iterations = iterations
        self.backend = default_backend()

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive a secure 256-bit key from password using PBKDF2.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=salt,
            iterations=self.iterations,
            backend=self.backend
        )
        return kdf.derive(password.encode())

    def encrypt(self, plaintext: bytes, password: str) -> dict:
        """
        Encrypt plaintext using AES-256-CBC.
        Returns dictionary with ciphertext, salt, and IV.
        """
        salt = generate_salt()
        key = self.derive_key(password, salt)
        iv = os.urandom(16)

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return {
            "salt": salt,
            "iv": iv,
            "ciphertext": ciphertext
        }

    def decrypt(self, encrypted_data: dict, password: str) -> bytes:
        """
        Decrypt AES-256-CBC encrypted data.
        """
        salt = encrypted_data["salt"]
        iv = encrypted_data["iv"]
        ciphertext = encrypted_data["ciphertext"]

        key = self.derive_key(password, salt)

        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext
