package com.example.OffCrypt1

/**
 * Centralized cryptographic constants to avoid duplication across classes
 * Single source of truth for all crypto parameters
 * VAHVENNETTU: OWASP ASVS 6.2 + NIST SP 800-57 mukaisesti
 */
object CryptoConstants {

    // Version bytes for different encryption methods
    const val VERSION_BYTE_PASSWORD: Byte = 0x01
    const val VERSION_BYTE_RSA: Byte = 0x02
    const val VERSION_BYTE_RSA_EXPIRING: Byte = 0x03
    const val VERSION_BYTE_RSA_SIGNED: Byte = 0x04
    const val VERSION_BYTE_RSA_PFS: Byte = 0x05
    const val VERSION_BYTE_RSA_SIGNED_PFS: Byte = 0x06
    const val VERSION_BYTE_RSA_ALL: Byte = 0x07
    const val VERSION_BYTE_RSA_4096_AES_FULL: Byte = 0x0A
    const val VERSION_BYTE_FILE_ENCRYPTED: Byte = 0x0B
    const val VERSION_BYTE_FILE_MULTI_SALT: Byte = 0x0C
    const val VERSION_BYTE_RSA_ADVANCED: Byte = 0x0D
    const val VERSION_BYTE_MULTI_SALT: Byte = 0x0E  // KORJATTU: 0x05 → 0x0E
    const val VERSION_BYTE_BURN_AFTER_READING: Byte = 0x0F  // KORJATTU: 0x06 → 0x0F

    // VAHVENNETUT kryptografiset parametrit (OWASP 2023 + NIST)
    const val SALT_SIZE = 64 // Nostettu 32→64 tavua kriittisiin käyttöihin
    const val IV_SIZE = 12 // AES-GCM optimaalinen
    const val GCM_IV_LENGTH = 12
    const val KEY_LENGTH = 256
    const val AES_KEY_LENGTH = 256
    const val ITERATION_COUNT = 320_000 // OWASP 2023 suositus (nostettu 100k→320k)
    const val MAC_SIZE = 32
    const val GCM_TAG_LENGTH = 16



    // ECDH-parametrit (vahvennettu)
    const val ECDH_CURVE = "P-256" // NIST P-256, FIPS 186-4
    const val ECDH_KEY_SIZE = 256

    // Key storage constants
    const val KEY_PUBLIC_KEY_2048 = "public_key_2048"
    const val KEY_PRIVATE_KEY_2048 = "private_key_2048"
    const val KEY_PUBLIC_KEY_4096 = "public_key_4096"
    const val KEY_PRIVATE_KEY_4096 = "private_key_4096"

    const val KEY_FAILED_ATTEMPTS = "failed_attempts"

    // VAHVENNETUT turvallisuusparametrit
    const val SECURE_WIPE_ITERATIONS = 35 // DoD 5220.22-M (nostettu 7→35)
    const val CLIPBOARD_CLEAR_DELAY_SENSITIVE = 30_000L // 30s (nostettu turvallisuutta)
    const val CLIPBOARD_CLEAR_DELAY_NORMAL = 30_000L
    const val KEY_ROTATION_INTERVAL = 2_592_000_000L // 30 päivää

    // Hyväksytyt algoritmit (FIPS 140-2 + NIST)-
    val APPROVED_CIPHER_SUITES = listOf(
        "AES/GCM/NoPadding",
        "ChaCha20-Poly1305" // Vaihtoehto mobiilikäyttöön
    )

    val APPROVED_KEY_DERIVATION = listOf(
        "PBKDF2WithHmacSHA256",
        "PBKDF2WithHmacSHA512",
        "Argon2id" // Suositeltu uusissa toteutuksissa
    )

    val APPROVED_SIGNATURE_ALGORITHMS = listOf(
        "SHA256withRSA/PSS",
        "SHA512withRSA/PSS",
        "SHA256withECDSA"
    )

    /**
     * Get human readable description of encryption type
     */
    fun getEncryptionTypeDescription(versionByte: Byte): String {
        return when (versionByte) {
            VERSION_BYTE_PASSWORD -> "password encrypted (320k iterations)"
            VERSION_BYTE_RSA -> "RSA key encrypted"
            VERSION_BYTE_RSA_EXPIRING -> "RSA key encrypted (expiring)"
            VERSION_BYTE_RSA_SIGNED -> "RSA key encrypted (signed)"
            VERSION_BYTE_RSA_PFS -> "RSA key encrypted (PFS P-256+HKDF)"
            VERSION_BYTE_RSA_SIGNED_PFS -> "RSA key encrypted (signed + PFS)"
            VERSION_BYTE_RSA_ALL -> "RSA key encrypted (maximum security)"
            VERSION_BYTE_RSA_4096_AES_FULL -> "RSA-4096 + AES-256-GCM (MAKSIMI TURVA)"
            VERSION_BYTE_FILE_ENCRYPTED -> "File encryption"
            VERSION_BYTE_FILE_MULTI_SALT -> "File multi-salt"
            VERSION_BYTE_RSA_ADVANCED -> "RSA advanced"
            VERSION_BYTE_MULTI_SALT -> "Password multi-salt (64-byte salt)"
            VERSION_BYTE_BURN_AFTER_READING -> "Burn-after-reading"
            else -> "Unknown format (0x${versionByte.toString(16)})"
        }
    }
}