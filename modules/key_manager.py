"""
Key Manager Module
Handles RSA Key Pair Generation and Password-Protected PEM serialization.
Uses standard Python cryptography library.
"""

from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class KeyManager:
    """Manages RSA key generation, PEM serialization, and encryption."""

    PUBLIC_EXPONENT = 65537

    @staticmethod
    def generate_key_pair(key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Generates an RSA private/public key pair using public exponent 65537.
        Allowed key sizes: 2048, 3072, 4096.
        """
        if key_size not in (2048, 3072, 4096):
            raise ValueError("Key size must be 2048, 3072, or 4096 bits.")

        private_key = rsa.generate_private_key(
            public_exponent=KeyManager.PUBLIC_EXPONENT,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def export_private_key_pem(private_key: rsa.RSAPrivateKey, password: Optional[str] = None) -> bytes:
        """
        Exports private key to PKCS#8 PEM.
        If password is provided, uses BestAvailableEncryption.
        """
        if password and len(password.strip()) > 0:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode('utf-8'))
        else:
            encryption_algorithm = serialization.NoEncryption()

        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )

    @staticmethod
    def export_public_key_pem(public_key: rsa.RSAPublicKey) -> bytes:
        """Exports public key to SubjectPublicKeyInfo (SPKI) PEM."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def load_private_key_pem(pem_bytes: bytes, password: Optional[str] = None) -> rsa.RSAPrivateKey:
        """Loads a PEM private key, decrypting with password if encrypted."""
        pwd_bytes = password.encode('utf-8') if (password and len(password) > 0) else None
        return serialization.load_pem_private_key(
            pem_bytes,
            password=pwd_bytes,
            backend=default_backend()
        )

    @staticmethod
    def load_public_key_pem(pem_bytes: bytes) -> rsa.RSAPublicKey:
        """Loads a PEM public key."""
        key = serialization.load_pem_public_key(
            pem_bytes,
            backend=default_backend()
        )
        if not isinstance(key, rsa.RSAPublicKey):
            raise TypeError("Loaded key is not an RSA public key.")
        return key
