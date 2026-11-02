"""
Academic Practical Automated Cryptographic Test Suite
Executes all 10 mandatory practical test cases.
"""

import unittest
from modules.key_manager import KeyManager
from modules.signer import Signer
from modules.verifier import Verifier
from modules.file_handler import FileHandler

class TestRSADigitalSignaturePractical(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Test 1: RSA Key Generation
        cls.priv_key, cls.pub_key = KeyManager.generate_key_pair(2048)
        cls.wrong_priv, cls.wrong_pub = KeyManager.generate_key_pair(2048)
        cls.sample_text = FileHandler.get_sample_document().encode('utf-8')

    def test_01_key_generation(self):
        """Test 1: RSA Key Generation (2048 bits, public exponent 65537)"""
        self.assertEqual(self.pub_key.key_size, 2048)
        self.assertEqual(self.pub_key.public_numbers().e, 65537)

    def test_02_signing_original_file(self):
        """Test 2: Signing an original text file generates a valid signature"""
        sig, digest = Signer.sign_data(self.sample_text, self.priv_key)
        self.assertEqual(len(sig), 256) # 2048 bits = 256 bytes
        self.assertEqual(len(digest), 64) # SHA-256 hex string = 64 chars

    def test_03_verification_succeeds(self):
        """Test 3: Verification of original file succeeds"""
        sig, _ = Signer.sign_data(self.sample_text, self.priv_key)
        is_valid, _ = Verifier.verify_signature(self.sample_text, sig, self.pub_key)
        self.assertTrue(is_valid)

    def test_04_tampered_character_fails(self):
        """Test 4: Modifying one single character causes verification to fail"""
        sig, _ = Signer.sign_data(self.sample_text, self.priv_key)
        tampered_text = self.sample_text.replace(b"CS-2024-8891", b"CS-2024-9999")
        is_valid, _ = Verifier.verify_signature(tampered_text, sig, self.pub_key)
        self.assertFalse(is_valid)

    def test_05_wrong_public_key_fails(self):
        """Test 5: Verification with wrong public key fails"""
        sig, _ = Signer.sign_data(self.sample_text, self.priv_key)
        is_valid, _ = Verifier.verify_signature(self.sample_text, sig, self.wrong_pub)
        self.assertFalse(is_valid)

    def test_06_corrupted_signature_fails(self):
        """Test 6: Verification with corrupted signature bytes fails"""
        sig, _ = Signer.sign_data(self.sample_text, self.priv_key)
        corrupted_sig = bytearray(sig)
        corrupted_sig[10] ^= 0xFF
        is_valid, _ = Verifier.verify_signature(self.sample_text, bytes(corrupted_sig), self.pub_key)
        self.assertFalse(is_valid)

    def test_07_password_protection(self):
        """Test 7: Password-protected private key handling"""
        pwd = "PracticalExamPassword2026!"
        pem = KeyManager.export_private_key_pem(self.priv_key, pwd)
        loaded_key = KeyManager.load_private_key_pem(pem, pwd)
        self.assertIsNotNone(loaded_key)
        with self.assertRaises(Exception):
            KeyManager.load_private_key_pem(pem, "WrongPassword")

    def test_08_empty_text_file(self):
        """Test 8: Empty text file signs and verifies correctly"""
        empty_data = b""
        sig, _ = Signer.sign_data(empty_data, self.priv_key)
        is_valid, _ = Verifier.verify_signature(empty_data, sig, self.pub_key)
        self.assertTrue(is_valid)

    def test_09_large_text_file(self):
        """Test 9: Large text file (1 MB) signs and verifies correctly"""
        large_data = b"Digital Signature Practical Test Block\n" * 25000
        sig, _ = Signer.sign_data(large_data, self.priv_key)
        is_valid, _ = Verifier.verify_signature(large_data, sig, self.pub_key)
        self.assertTrue(is_valid)

    def test_10_timing_diagnostics(self):
        """Test 10: Verification produces timing metrics and diagnostic breakdown"""
        sig, _ = Signer.sign_data(self.sample_text, self.priv_key)
        is_valid, diag = Verifier.verify_signature(self.sample_text, sig, self.pub_key)
        self.assertTrue(is_valid)
        self.assertIn("timing_ms", diag)
        self.assertIn("sha256_hex", diag)

if __name__ == '__main__':
    unittest.main()
