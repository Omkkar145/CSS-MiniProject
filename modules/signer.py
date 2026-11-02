"""
Signer Module
Handles SHA-256 message hashing and RSA-PSS detached digital signature creation.
"""

import hashlib
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

class Signer:
    """Signs arbitrary binary/text data using RSA-PSS and SHA-256."""

    @staticmethod
    def compute_sha256_hex(data: bytes) -> str:
        """Computes SHA-256 digest in hexadecimal format for educational display."""
        hasher = hashlib.sha256()
        hasher.update(data)
        return hasher.hexdigest()

    @staticmethod
    def sign_data(data: bytes, private_key: rsa.RSAPrivateKey) -> Tuple[bytes, str]:
        """
        Signs the given data bytes using RSA-PSS with SHA-256.
        Returns (signature_bytes, sha256_hex_digest).
        """
        digest_hex = Signer.compute_sha256_hex(data)

        # Standard RSA-PSS padding scheme with MGF1 and maximum salt length
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature, digest_hex
