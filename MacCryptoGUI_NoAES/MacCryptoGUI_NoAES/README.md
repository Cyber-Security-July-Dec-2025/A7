# MacCryptoGUI_NoAES (Qt + Crypto++, macOS)

A minimal GUI for **RSA** and **DSA** only (no AES).

- **RSA Key-Pair Generation**
- **RSA Encrypt (Direct OAEP with SHA-256)** → works **only for small inputs** (e.g., ~190 bytes max for 2048-bit keys).
- **RSA Decrypt (Direct OAEP with SHA-256)**
- **DSA Key-Pair Generation**
- **DSA Signature Generation**
- **DSA Signature Verification**

**All inputs via GUI** (file pickers). **Small outputs** (like signatures) are previewed in hex; otherwise saved to a file.  
Configurable params live in `config.json` (RSA bits, DSA L/N, preview size).

---

## Prerequisites (macOS)
```bash
brew install cmake qt cryptopp
export CMAKE_PREFIX_PATH="$(brew --prefix qt)"
```

## Build & Run
```bash
mkdir -p build && cd build
cmake -DCMAKE_PREFIX_PATH="$(brew --prefix qt)" ..
cmake --build . --config Release
./MacCryptoGUI_NoAES
```

## Notes
- **Direct RSA OAEP** has a hard size limit: for 2048-bit RSA + SHA-256, max plaintext is ~**190 bytes**. Larger files will be rejected by the app.
- DSA in Crypto++ uses SHA-1 internally by default. Keys are saved/loaded as **DER** (binary) via Crypto++ serialization:
  - RSA: `rsa_private.der`, `rsa_public.der`
  - DSA: `dsa_private.der`, `dsa_public.der`

Security caveat: demo-quality. Protect your private keys with file permissions. No password-protection or secure keychain integration is included.
