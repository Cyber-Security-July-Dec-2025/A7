# MacCryptoGUI (Qt + Crypto++)

A minimal macOS GUI (Qt6) to perform:

- **RSA key-pair generation**
- **RSA Encryption** (hybrid: RSA-OAEP(SHA-256) wraps an AES-256-GCM key; handles large files)
- **RSA Decryption** (for the hybrid format produced here)
- **DSA Signature Generation**
- **DSA Signature Verification**

**Inputs** are provided via the GUI (file pickers / text inputs).  
**Outputs** are shown in the GUI when small or written to files you select.  
A single **`config.json`** at repo root controls crypto parameters (key sizes, modes).

> Built on macOS with Homebrew-installed Qt6 and Crypto++.

---

## 1) Prerequisites (macOS)
```bash
# Install build tools and libraries
brew install cmake qt cryptopp

# (Optional) make sure CMake can find Qt
export CMAKE_PREFIX_PATH="$(brew --prefix qt)"
```

## 2) Build
```bash
git clone <this_project>   # or unzip the provided archive
cd MacCryptoGUI
mkdir build && cd build
cmake -DCMAKE_PREFIX_PATH="$(brew --prefix qt)" ..
cmake --build . --config Release
./MacCryptoGUI
```

If you prefer an app bundle, you can later package it with `macdeployqt`, but running the binary is fine for development.

---

## 3) Usage

**Operation selector:** choose one of:
- RSA Key-Pair Generation
- RSA Encrypt (Hybrid AES-GCM)
- RSA Decrypt (Hybrid AES-GCM)
- DSA Sign
- DSA Verify

**Upload buttons** open file pickers for inputs (message file, key files, signature file).  
**Process** runs the Crypto++ logic.  
**Open Output** reveals the folder of your last output.  
**Status/Log** displays messages and small results (e.g., signature hex).

### File formats & notes
- **Keys** are stored/loaded as **DER (binary)** serialized keys using Crypto++'s `Save/Load` to a `ByteQueue`.  
  - RSA keys: `.rsa.pub.der`, `.rsa.priv.der`  
  - DSA keys: `.dsa.pub.der`, `.dsa.priv.der`
- **RSA Encryption** uses a hybrid envelope so it scales to large files:
  - Generates random AES-256 key + 96-bit IV (GCM).
  - Encrypts the file with AES-GCM (ciphertext **+ tag** contiguous).
  - Encrypts the AES key with RSA-OAEP(SHA-256).
  - Writes a **binary container**:
    ```
    struct Header {
      char     magic[8]   = "RGHYBRID";
      uint32_t version    = 1;
      uint32_t encKeyLen;    // bytes
      uint32_t ivLen;        // bytes (default 12 for GCM)
      uint64_t cipherLen;    // bytes (ciphertext + tag concatenated)
    };
    [encKey bytes][iv bytes][cipher+tag bytes]
    ```
- **DSA** here uses Crypto++'s DSA (SHA-1 by default). The `config.json` documents this. If you need FIPS 186-4 with SHA-256, consider ECDSA (P-256) or tested DSA-with-SHA-256 support in your stack.

---

## 4) Security caveats
- Example code; not hardened for production. No secure key storage, no password protection for private keys.
- Always protect private keys with filesystem permissions.
- Test with non-sensitive data first.

---

## 5) Troubleshooting
- If CMake can't find Qt: ensure `brew --prefix qt` is exported via `CMAKE_PREFIX_PATH` as shown above.
- If it can't find Crypto++: `brew install cryptopp` and re-run CMake.
- Codesign/notarization is not included; Gatekeeper may require allowing the binary in System Settings.

---
