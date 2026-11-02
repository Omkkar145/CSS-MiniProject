"""
Verifier Module
Verifies detached RSA-PSS signatures against text data and public keys.
Handles InvalidSignature exceptions cleanly with timing metrics.
"""

import time
import hashlib
from typing import Tuple, Dict, Any
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

class Verifier:
    """Verifies RSA digital signatures with educational diagnostic results."""

    @staticmethod
    def verify_signature(
        data: bytes,
        signature: bytes,
        public_key: rsa.RSAPublicKey
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Verifies signature bytes against data bytes using public_key.
        Returns (is_valid, diagnostics_dict).
        """
        start_time = time.perf_counter()
        digest_hex = hashlib.sha256(data).hexdigest()

        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return True, {
                "status": "VALID",
                "title": "DIGITAL SIGNATURE VALID",
                "sha256_hex": digest_hex,
                "timing_ms": elapsed_ms,
                "message": "The digital signature is mathematically authentic and the document has not been altered.",
                "reasons": [
                    "SHA-256 digest decrypted from signature matches document bytes exactly.",
                    "Public key mathematically validates signature origin from the private key.",
                    "Non-repudiation and data integrity verified."
                ]
            }
        except InvalidSignature:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return False, {
                "status": "INVALID",
                "title": "DIGITAL SIGNATURE INVALID",
                "sha256_hex": digest_hex,
                "timing_ms": elapsed_ms,
                "message": "Verification failed: Signature does not match document data or public key.",
                "reasons": [
                    "Recomputed SHA-256 hash does not match decrypted signature digest.",
                    "Document text was modified after signing or wrong public key was provided.",
                    "Integrity check failed: Tampering detected."
                ]
            }
        except Exception as e:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return False, {
                "status": "ERROR",
                "title": "VERIFICATION ERROR",
                "sha256_hex": digest_hex,
                "timing_ms": elapsed_ms,
                "message": f"Cryptographic error: {str(e)}",
                "reasons": [str(e)]
            }
