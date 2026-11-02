# RSA Digital Signature Studio (Windows 11)
## Academic Practical: Digital Signature-Based File Signing and Verification Using RSA

### Overview
This is a modern Windows 11 GUI application built using Python 3, PySide6 (Qt for Python), and the official `cryptography` library. It features the **exact same Interactive Studio interface, colors, layout, and functionality as the web preview**:
1. **Interactive Studio (Default Screen)**: Unified 4-stage laboratory workbench executing Key Generation, SHA-256 Hashing, RSA-PSS Signing, and Verification side-by-side.
2. **⚡ 1-Click Complete Classroom Execution**: Automated step-by-step presentation run that executes keygen, document hashing, signing, and verification with animated visual progress.
3. **Real-Time SHA-256 Digest**: Updates live as document text is edited or typed.
4. **Interactive Tampering Sandbox**: Includes "Alter Value" ($5,000 to $9,000) and "+1 Space" buttons showing immediate hash avalanche effect and verification rejection.
5. **Windows 11 Light Mode by Default**: Crisp Segoe UI typography and light theme palette matching the web preview, with instant toggle to Dark Mode via top header.
6. **Dedicated Signature Verification Module**: Take direct input of any detached signature (`.sig`) file and sender's RSA public key (`.pem`) file, browse text documents, view live SHA-256 digests, and display full mathematical verification diagnostics.

---

### Prerequisites
- Windows 10 / 11 (64-bit recommended)
- Python 3.10 or higher

---

### Installation & Execution

1. **Open Command Prompt (cmd) in the Project Folder**:
   ```cmd
   cd RSA_Digital_Signature_Studio
   ```

2. **Create a Virtual Environment (Recommended)**:
   ```cmd
   python -m venv venv
   venv\Scripts\activate
   ```

3. **Install Dependencies**:
   ```cmd
   pip install -r requirements.txt
   ```

4. **Run the Application**:
   ```cmd
   python main.py
   ```
   *Opens in Windows 11 Light Mode by default, displaying the Interactive Studio workbench directly. You can toggle Dark Mode via the top header button or pass `python main.py --dark`.*

5. **Run the Automated Cryptographic Test Suite**:
   ```cmd
   python test_crypto.py
   ```

---

### Building the Standalone Windows 11 Executable (.exe)

To bundle the application into a single portable Windows executable without requiring Python:

```cmd
pip install pyinstaller
pyinstaller rsa_studio.spec
```

The compiled executable will be located in the `dist/RSA_Digital_Signature_Studio/` folder.
Double-click `RSA_Digital_Signature_Studio.exe` to run offline anywhere!

---

### Academic Practical Test Cases
- **Test 1**: RSA key generation (2048-bit with public exponent 65537).
- **Test 2**: Signing an original text file generating a detached `.sig` file.
- **Test 3**: Verification succeeds with matching key and file.
- **Test 4**: Modifying 1 single character causes verification to fail (`InvalidSignature`).
- **Test 5**: Verification with wrong public key safely fails.
- **Test 6**: Verification with corrupted signature safely fails.
- **Test 7**: Password-protected private key handling without crash.
- **Test 8**: Empty text file signs and verifies correctly.
- **Test 9**: Large text file (1 MB) signs and verifies correctly.
- **Test 10**: Verification produces timing metrics and diagnostic breakdown.
