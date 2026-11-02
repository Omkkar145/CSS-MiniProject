"""
File Handler Module
Safely reads and writes text documents, PEM key files, and binary .sig files.
Provides standardized academic practical preset documents matching the web preview.
"""

import os
from typing import List, Dict

class FileHandler:
    """Handles local filesystem reading and writing for the practical."""

    PRESET_DOCUMENTS: List[Dict[str, str]] = [
        {
            "name": "Academic_Practical_Report.txt",
            "label": "Academic Practical Report",
            "content": (
                "UNIVERSITY COMPUTER SCIENCE LABORATORY\n"
                "Experiment: RSA Digital Signature Scheme Implementation\n"
                "Student Name: Computer Science Candidate\n"
                "Registration No: CS-2024-8891\n"
                "Standard Protocol: RSA-PSS (2048-bit) + SHA-256 Digest\n"
                "Practical Verification Objective:\n"
                "Demonstrate that a detached digital signature guarantees non-repudiation,\n"
                "data integrity, and sender authenticity for arbitrary text documents.\n"
                "Status: Practical Output Verified & Approved."
            )
        },
        {
            "name": "Student_Grade_Record.txt",
            "label": "Student Grade Record",
            "content": (
                "SEMESTER EXAMINATION TRANSCRIPT\n"
                "Student ID: 2024-CSE-042\n"
                "Subject: Network Security & Applied Cryptography\n"
                "Grade: A+ (Outstanding)\n"
                "Credits: 4.0\n"
                "Marks Obtained: 98/100\n"
                "Authorized By: Department Examination Controller\n"
                "Timestamp: 2026-10-31T09:00:00Z"
            )
        },
        {
            "name": "Financial_Clearance.txt",
            "label": "Financial Clearance Authorization",
            "content": (
                "CAMPUS FINANCIAL CLEARANCE CERTIFICATE\n"
                "Transaction ID: TXN-89472198\n"
                "Account Holder: Student Examination Clearance Office\n"
                "Amount Cleared: $5,000.00 USD\n"
                "Payment Status: Fully Paid & Cleared\n"
                "Authorization Officer: Financial Comptroller"
            )
        }
    ]

    @staticmethod
    def read_text_file(filepath: str) -> str:
        """Reads a UTF-8 text file."""
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()

    @staticmethod
    def write_text_file(filepath: str, content: str, overwrite: bool = False) -> None:
        """Writes text content to a file."""
        if os.path.exists(filepath) and not overwrite:
            raise FileExistsError(f"File '{filepath}' already exists.")
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

    @staticmethod
    def read_binary_file(filepath: str) -> bytes:
        """Reads raw binary file contents (.pem, .sig)."""
        with open(filepath, 'rb') as f:
            return f.read()

    @staticmethod
    def write_binary_file(filepath: str, data: bytes, overwrite: bool = False) -> None:
        """Writes raw binary file contents (.pem, .sig)."""
        if os.path.exists(filepath) and not overwrite:
            raise FileExistsError(f"File '{filepath}' already exists.")
        with open(filepath, 'wb') as f:
            f.write(data)

    @classmethod
    def get_sample_document(cls) -> str:
        """Returns standard default academic practical sample text."""
        return cls.PRESET_DOCUMENTS[0]["content"]

    @classmethod
    def get_preset_documents(cls) -> List[Dict[str, str]]:
        """Returns all preset academic practical documents."""
        return cls.PRESET_DOCUMENTS
