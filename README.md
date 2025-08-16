# OffCrypt – Secure Message Encryption for Android | Open-source

OffCrypt is encryption and messaging application for Android devices that works in a PGP‑style: it uses public‑key cryptography so messages can be encrypted with a recipient’s public key and decrypted only with their private key. The app combines multiple modern cryptographic algorithms and offers an array of security features to keep your communications private. Built in Kotlin, OffCrypt operates fully offline — no Internet permission is required.
###  Donate
> ☕ **Support my work**  
> If you find my projects useful or interesting, please consider buying me a coffee: [https://ko-fi.com/emptyc0de/tip](https://ko-fi.com/emptyc0de/tip) 🙌

---

## Pictures / Showcase site
https://www.dev-offcode.com/

## 🎯 Key Features

### 🔒 Encryption Methods
- **Password-based encryption:** AES-256-GCM with PBKDF2.
- **RSA-2048:** Asymmetric encryption with digital signatures.
- **RSA-4096:** Maximum-strength asymmetric encryption with SHA-512 signatures.

### 🛡️ Security Features
- Perfect Forward Secrecy (ECDH key exchange).
- Digital signatures for authenticity.
- Message expiration (1 hour to 1 year).
- Burn after reading (self-destruct messages on view).
- HMAC-SHA256 for tamper protection and secure memory wiping.

### 📁 File Operations
- Export encrypted messages to files.
- Import and decrypt encrypted files.
- Import/export RSA public keys.

### 🔑 Key Management
- Automatic RSA key generation (2048- or 4096-bit).
- Encrypted private key storage using AES-256-GCM.
- Cryptographically secure password generator.

### 🧾 System Requirements
- Android 5.0 (API 21) or higher.
- Minimum 50 MB of storage space.
- Operates entirely offline; no Internet permission needed.

---

## 🔧 Installation
1. Download the latest `APK` from the **[Releases page](https://github.com/EmptyCode0x86/Off_crypt1/releases)**.
2. Enable “Install from unknown sources” in your Android settings.
3. Install the APK and grant the requested permissions.

---

## 📚 Usage Guide

### 🔑 Password-Based Encryption
1. Choose *Password* as the encryption type.
2. Enter your message.
3. Choose a password:
   - **Random Password:** Use the generated secure password (recommended).
   - **Custom Password:** Enter your own password.
4. Configure extra options (expiration, burn after reading).
5. Press **Encrypt message** and share the encrypted message and password separately.

### 🔐 RSA Encryption (Asymmetric)
1. Select *RSA‑2048* or *RSA‑4096*.
2. Generate a new key pair (**Generate new key pair**).
3. Share your public key with contacts.
4. Import the recipient’s public key.
5. Enter your message and configure security options.
6. Press **Encrypt message** and send the encrypted message (no password needed).
7. The recipient can decrypt the message without a password; signatures are verified if the sender’s public key is available.

### 📁 File Operations
- **Create encrypted file:** Save messages as encrypted files.
- **Import encrypted file for reading:** Load and decrypt encrypted files.
- **Load public key:** Import RSA public keys from text files.

---

## 🧪 Cryptographic Architecture

| Function                  | Algorithm / Size          | Notes                            |
|---------------------------|---------------------------|----------------------------------|
| Symmetric encryption      | **AES‑256‑GCM**           | Authenticated encryption         |
| Asymmetric encryption     | **RSA‑OAEP** 2048/4096    | SHA‑256 + MGF1 padding           |
| Key derivation            | **PBKDF2‑HMAC‑SHA256**    | 100 000 iterations               |
| Message authentication    | **HMAC‑SHA256**           |                                  |
| Digital signatures        | **RSA‑PSS** 2048/4096     | SHA‑256 / SHA‑512                |
| Perfect forward secrecy   | **ECDH (secp256r1)**      | Ephemeral key exchange           |
| Random number generation  | **SecureRandom**          | Cryptographically secure RNG     |


---

## ⚠️ Security Best Practices
- Never share your private RSA key.
- Always verify recipients’ public keys.
- Use the random password generator whenever possible.
- Back up your RSA keys securely.
- Rotate your keys periodically.

## Pictures / Showcase site
https://www.dev-offcode.com/


---

## 📝 License

**GNU GENERAL PUBLIC LICENSE – Version 3, 29 June 2007 **
               
 OffCrypt - Secure Offline Encryption App  
Copyright (C) 2025 EmptyCode0x86  
Licensed under the GNU General Public License v3.0

See the full license text in the original repository for complete details.

---

Thank you for exploring OffCrypt! If you like the app or find it useful, please consider supporting the project via the Ko‑fi link above ❤️
###  Donate
> ☕ **Support my work**  
> If you find my projects useful or interesting, please consider buying me a coffee: [https://ko-fi.com/emptyc0de/tip](https://ko-fi.com/emptyc0de/tip) 🙌
