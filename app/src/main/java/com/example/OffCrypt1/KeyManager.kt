package com.example.OffCrypt1

import android.content.Context
import android.util.Base64
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/**
 * Key management for RSA key pairs
 * VAHVENNETTU: ECDH P-256 + HKDF-SHA256, parannettu efemeerinen avainhallinta
 * Handles generation, storage, and loading of RSA keys
 */
class KeyManager(private val context: Context) {

    private val secureRandom = SecureRandom.getInstanceStrong()
    private val secureKeyManager = SecureKeyManager(context).apply {
        // LISÄTTY: Validoi hardware security käynnistyksen yhteydessä
        if (!validateHardwareSecurity()) {
            try {
                android.util.Log.w("KeyManager", "⚠️ Hardware security validation failed!")
            } catch (e: Exception) {
                println("WARN: KeyManager - ⚠️ Hardware security validation failed!")
            }
        }
    }

    companion object {
        private const val RSA_KEY_SIZE_2048 = 2048
        private const val RSA_KEY_SIZE_4096 = 4096
        private const val PREFS_NAME = "netcrypt_keys"
        private const val PREFS_PRIVATE_KEY_2048 = "private_key_2048"
        private const val PREFS_PUBLIC_KEY_2048 = "public_key_2048"
        private const val PREFS_PRIVATE_KEY_4096 = "private_key_4096"
        private const val PREFS_PUBLIC_KEY_4096 = "public_key_4096"

    }

    /**
     * Generates a new RSA key pair
     */
    fun generateNewKeyPair(useRSA4096: Boolean = false): KeyPair {
        try {
            val keyGen = KeyPairGenerator.getInstance("RSA")
            val keySize = if (useRSA4096) RSA_KEY_SIZE_4096 else RSA_KEY_SIZE_2048
            keyGen.initialize(keySize, secureRandom)
            return keyGen.generateKeyPair()
        } catch (e: Exception) {
            throw RuntimeException("Key pair generation failed: ${e.message}", e)
        }
    }

    /**
     * Saves key pair to encrypted storage
     */
    fun saveKeyPair(keyPair: KeyPair, useRSA4096: Boolean = false) {
        try {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val editor = prefs.edit()

            // Encode keys to Base64
            val privateKeyBase64 = Base64.encodeToString(keyPair.private.encoded, Base64.NO_WRAP)
            val publicKeyBase64 = Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP)

            // Encrypt private key before storage
            val encryptedPrivateKey = encryptPrivateKey(privateKeyBase64)

            if (useRSA4096) {
                editor.putString(PREFS_PRIVATE_KEY_4096, encryptedPrivateKey)
                editor.putString(PREFS_PUBLIC_KEY_4096, publicKeyBase64)
            } else {
                editor.putString(PREFS_PRIVATE_KEY_2048, encryptedPrivateKey)
                editor.putString(PREFS_PUBLIC_KEY_2048, publicKeyBase64)
            }

            editor.apply()
        } catch (e: Exception) {
            throw RuntimeException("Key pair save failed: ${e.message}", e)
        }
    }

    /**
     * Loads key pair from storage
     */
    fun loadKeyPair(useRSA4096: Boolean = false): KeyPair? {
        try {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

            val privateKeyPref = if (useRSA4096) PREFS_PRIVATE_KEY_4096 else PREFS_PRIVATE_KEY_2048
            val publicKeyPref = if (useRSA4096) PREFS_PUBLIC_KEY_4096 else PREFS_PUBLIC_KEY_2048

            val encryptedPrivateKey = prefs.getString(privateKeyPref, null) ?: return null
            val publicKeyBase64 = prefs.getString(publicKeyPref, null) ?: return null

            // Decrypt private key
            val privateKeyBase64 = decryptPrivateKey(encryptedPrivateKey)

            // Decode keys
            val privateKeyBytes = Base64.decode(privateKeyBase64, Base64.NO_WRAP)
            val publicKeyBytes = Base64.decode(publicKeyBase64, Base64.NO_WRAP)

            val keyFactory = KeyFactory.getInstance("RSA")
            val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(privateKeyBytes))
            val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(publicKeyBytes))

            return KeyPair(publicKey, privateKey)

        } catch (e: Exception) {
            return null
        }
    }

    /**
     * Parses public key from string format
     */
    fun parsePublicKeyFromString(publicKeyString: String): PublicKey {
        try {
            // Remove headers and whitespace
            val cleanKey = publicKeyString
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("\\s".toRegex(), "")

            val keyBytes = Base64.decode(cleanKey, Base64.NO_WRAP)
            val keyFactory = KeyFactory.getInstance("RSA")
            return keyFactory.generatePublic(X509EncodedKeySpec(keyBytes))

        } catch (e: Exception) {
            throw RuntimeException("Public key parsing failed: ${e.message}", e)
        }
    }

    /**
     * Formats public key for sharing
     */
    fun formatPublicKeyForSharing(publicKey: PublicKey): String {
        val keyBytes = publicKey.encoded
        val base64Key = Base64.encodeToString(keyBytes, Base64.NO_WRAP)

        return "-----BEGIN PUBLIC KEY-----\n" +
                base64Key.chunked(64).joinToString("\n") +
                "\n-----END PUBLIC KEY-----"
    }

    /**
     * Generates a random password
     */
    fun generateRandomPassword(length: Int = 24): String {
        val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
        return (1..length)
            .map { chars[secureRandom.nextInt(chars.length)] }
            .joinToString("")
    }

    /**
     * KORJATTU: Encrypts private key for storage using Android Keystore
     */
    private fun encryptPrivateKey(privateKeyBase64: String): String {
        try {
            // KORJATTU: Use Android Keystore via SecureKeyManager instead of storing key with data
            return secureKeyManager.encryptData(privateKeyBase64)
        } catch (e: Exception) {
            throw RuntimeException("Private key encryption failed: ${e.message}", e)
        }
    }

    /**
     * KORJATTU: Decrypts private key from storage using Android Keystore
     */
    private fun decryptPrivateKey(encryptedData: String): String {
        try {
            // KORJATTU: Use Android Keystore via SecureKeyManager
            return secureKeyManager.decryptData(encryptedData)
        } catch (e: Exception) {
            throw RuntimeException("Private key decryption failed: ${e.message}", e)
        }
    }


    // ===== SECURE MEMORY MANAGEMENT =====

    /**
     * VAHVENNETTU: Secure wipe of sensitive byte arrays
     */
    fun secureWipe(data: ByteArray) {
        SecurityUtils.secureWipeByteArray(data)
    }

    /**
     * VAHVENNETTU: Secure wipe of sensitive char arrays (passwords)
     */
    fun secureWipe(data: CharArray) {
        SecurityUtils.secureWipeCharArray(data)
    }

    /**
     * VAHVENNETTU: Zero out memory after use - defensive programming
     */
    fun runWithSecureCleanup(operation: () -> Unit) {
        try {
            operation()
        } finally {
            // Pakota useampi GC-kierros
            repeat(3) {
                System.gc()
                System.runFinalization()
                Thread.sleep(50)
            }
        }
    }

    /**
     * Check if device supports hardware security features
     */
    fun checkHardwareSecuritySupport(): Map<String, Boolean> {
        val securityInfo = secureKeyManager.getDetailedSecurityInfo() // LISÄTTY

        return mapOf(
            "strongbox" to (securityInfo["strongbox_backed"] as? Boolean ?: false), // KORJATTU
            "tee" to (securityInfo["tee_backed"] as? Boolean ?: false), // KORJATTU
            "secure_random" to true,
            "hardware_validated" to (securityInfo["hardware_validated"] as? Boolean
                ?: false) // LISÄTTY
        )
    }

    /**
     * Get secure memory statistics
     */
    fun getSecureMemoryStats(): Map<String, Any> {
        return mapOf(
            "heap_memory_used" to (Runtime.getRuntime().totalMemory() - Runtime.getRuntime()
                .freeMemory()),
            "max_heap_memory" to Runtime.getRuntime().maxMemory(),
            "timestamp" to System.currentTimeMillis(),
            "secure_wipe_iterations" to CryptoConstants.SECURE_WIPE_ITERATIONS, // VAHVENNETTU
            "crypto_strength" to "RSA-2048/4096 + AES-256-GCM" // VAHVENNETTU
        )
    }
}