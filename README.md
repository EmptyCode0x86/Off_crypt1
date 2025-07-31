☕ Support My Work on Ko-fi
If you find my projects useful or interesting, consider buying me a coffee! Your support helps me keep building and maintaining open-source projects. 🙌

👉 https://ko-fi.com/emptyc0de/tip

Thank you for your support! ❤️

Off_crypt

OffCrypt 🔐 Secure Message Encryption for Android OffCrypt is a professional-grade encryption application for Android devices, designed to provide maximum security for sensitive communications. Built with Kotlin, it combines multiple state-of-the-art cryptographic algorithms and security features to ensure your messages remain private and secure.

🚀 Key Features 🔒 Multiple Encryption Methods

Password-based Encryption: AES-256-GCM with PBKDF2 key derivation RSA-2048 Encryption: Asymmetric public-key cryptography with digital signatures RSA-4096 Encryption: Maximum security asymmetric encryption with SHA-512 signatures

🛡️ Advanced Security Features

Perfect Forward Secrecy (PFS): ECDH key exchange ensures past messages remain secure Digital Signatures: RSA signatures verify message authenticity and sender identity Message Expiration: Auto-expiring messages (1 hour to 1 year) Burn After Reading: Self-destructing messages that delete after viewing Anti-Tampering: HMAC-SHA256 ensures message integrity Memory Security: Aggressive secure memory wiping and garbage collection

🗂️ File Operations

Encrypted File Export: Save encrypted messages to secure files File Import: Load and decrypt encrypted files Public Key Import/Export: Share RSA keys securely

🔑 Key Management

Automatic RSA Key Generation: Generate secure 2048-bit or 4096-bit RSA key pairs Encrypted Key Storage: All private keys encrypted with AES-256-GCM Password Generation: Cryptographically secure random password generation

📱 System Requirements

Android 5.0 (API 21) or higher Minimum 50 MB storage space Internet permission not required (fully offline)

🔧 Installation

Download the APK from the Releases page Enable "Install from Unknown Sources" in Android settings Install the APK file Grant necessary permissions when prompted

📚 Usage Guide 🔐 Password-Based Encryption

Select Password Mode: Choose "🔑 Password" in encryption type selection Write Message: Enter your message in the text area Choose Password Method:

Random Password: Use the generated secure password (recommended) Custom Password: Enter your own password

Configure Security Options:

Enable message expiration if needed Enable "Burn After Reading" for self-destructing messages

Encrypt: Press "🔒 Encrypt message" Share: Copy the encrypted message and password separately

🔑 RSA Encryption (Asymmetric) Setting Up RSA Keys

Select RSA Mode: Choose "🔐 RSA-2048" or "🔐 RSA-4096" Generate Key Pair: Press "🔄 Generate new key pair" Share Public Key: Copy your public key and share it with contacts Import Recipient Key: Paste the recipient's public key in the designated field

Encrypting with RSA

Enter Recipient's Public Key: Paste the public key of the person you're sending to Write Message: Enter your message Configure Security Options: Set expiration and burn-after-reading as needed Encrypt: Press "🔒 Encrypt message" Send: Share only the encrypted message (no password needed!)

Decrypting RSA Messages

Paste Encrypted Message: Put the received encrypted message in the decrypt field Decrypt: Press "🔍 Decrypt message" (no password required) Verify Signature: Check the signature status if sender's public key is available

📁 File Operations

Create Encrypted File: Use "💾 Create encrypted file" to save messages as files Import Encrypted File: Use "📁 Import encrypted file for reading" to load encrypted files Load Public Key: Import RSA public keys from text files

🔒 Security Architecture Cryptographic Algorithms FeatureAlgorithmKey SizeNotesSymmetric EncryptionAES-256-GCM256-bitAuthenticated encryptionAsymmetric EncryptionRSA-OAEP2048/4096-bitSHA-256 + MGF1 paddingKey DerivationPBKDF2-HMAC-SHA256256-bit100,000 iterationsMessage AuthenticationHMAC-SHA256256-bitIntegrity verificationDigital SignaturesRSA-PSS2048/4096-bitSHA-256/SHA-512Perfect Forward SecrecyECDH secp256r1256-bitEphemeral key exchangeRandom GenerationSecureRandom-Cryptographically secure Security Features Overview 🛡️ Cryptographic Security (11 features)

✅ RSA-2048/4096 asymmetric encryption ✅ AES-256-GCM authenticated encryption ✅ PBKDF2 password derivation (100,000 iterations) ✅ HMAC-SHA256 message authentication ✅ SHA-256/SHA-512 cryptographic hashing ✅ SecureRandom number generation ✅ RSA-OAEP with SHA-256 + MGF1 padding ✅ GCM mode for authenticated encryption ✅ Constant-time HMAC verification ✅ Cryptographic nonce/IV generation ✅ Version byte for algorithm identification

🔐 Advanced Security (8 features)

✅ Digital signatures for authenticity ✅ Perfect Forward Secrecy (ECDH) ✅ Message expiration (1h - 1y) ✅ Burn After Reading functionality ✅ Replay attack protection ✅ Data integrity validation ✅ Multi-version format support ✅ Metadata protection

🧠 Memory Safety (7 features)

✅ Sensitive data scrubbing (7-pass overwrite) ✅ CharArray/ByteArray secure wiping ✅ Aggressive garbage collection (3x) ✅ Android logcat clearing ✅ JVM string pool cleanup ✅ Memory barrier synchronization ✅ Lifecycle-based data destruction

📱 UI Security (6 features)

✅ Secure clipboard management ✅ Automatic clipboard clearing (15-60s) ✅ Background data clearing ✅ App lifecycle security ✅ Burn dialog warnings ✅ Secure EditText handling

🚨 Additional Protection (4 features)

✅ App lockout (5 failed attempts) ✅ Complete data wipe functionality ✅ Encrypted key storage ✅ AndroidOpenSSL fallback support

Total: 36+ Active Security Features 🛡️ ⚠️ Security Warnings 🔴 Critical Security Practices

Never share your RSA private key - It's automatically protected, but never export it Verify public keys - Always confirm you have the correct recipient's public key Use strong passwords - For password-based encryption, use the random generator Secure key backup - Back up your RSA keys in a secure location Regular key rotation - Generate new RSA keys periodically for maximum security

🟡 Important Notes

Encrypted RSA keys: All private keys are encrypted with AES-256-GCM using a master password Forward secrecy: Even if keys are compromised, past messages with PFS remain secure Memory clearing: All sensitive data is securely wiped from memory when possible No network access: App works completely offline - no data leaves your device Version compatibility: Different encryption versions are automatically detected

### LICENSE ###

Custom License – Non-Commercial Use Only Copyright (c) 2025 OffCrypt

This software is provided for personal and non-commercial use only. All commercial rights are reserved by the original author. Commercial use, resale, distribution for profit, or incorporation into commercial products or services is strictly prohibited without explicit written permission from the author.

You are allowed to:

    Use, copy, and modify the software for personal, educational, or research purposes
    Share the original or modified version non-commercially, provided that this license text remains intact

You are NOT allowed to:

    Use this software for commercial purposes in any form
    Sell, sublicense, or include it in paid services or apps
    Claim authorship of the original software

DISCLAIMER OF WARRANTY: This software is provided "AS IS", without warranties of any kind. The author makes no guarantees regarding the security, reliability, or functionality of the software. You use this software at your own risk.

NO GUARANTEE OF ENCRYPTION STRENGTH: While this software uses standard cryptographic algorithms, no guarantee is made that its encryption or implementation is unbreakable. The author is not responsible if data is compromised or accessed by unauthorized parties.

NOT FOR CRITICAL OR EMERGENCY USE: This software is not intended for life-critical systems, emergency communications, or safety-relevant applications. It must not be relied upon in situations where failure could result in injury, loss of life, or significant damage.

NO ILLEGAL USE: You may not use this software for illegal, criminal, or malicious purposes. It is your responsibility to comply with all local and international laws applicable to your use of this software.

NO LIABILITY: The author shall not be held liable for any damages, losses, or legal consequences resulting from the use, misuse, or malfunction of this software, including loss of data or messages that cannot be recovered or decrypted.


☕ Support My Work on Ko-fi
If you find my projects useful or interesting, consider buying me a coffee! Your support helps me keep building and maintaining open-source projects. 🙌

👉 https://ko-fi.com/emptyc0de/tip

Thank you for your support! ❤️
