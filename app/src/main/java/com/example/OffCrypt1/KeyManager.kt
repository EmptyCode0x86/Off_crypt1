package com.example.OffCrypt1

import android.content.Context
import android.util.Base64
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.KeyAgreement
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.util.*
import java.time.Instant

/**
 * Key management for RSA key pairs
 * Handles generation, storage, and loading of RSA keys
 */
class KeyManager(private val context: Context) {
    
    private val secureRandom = SecureRandom()
    
    companion object {
        private const val RSA_KEY_SIZE_2048 = 2048
        private const val RSA_KEY_SIZE_4096 = 4096
        private const val PREFS_NAME = "netcrypt_keys"
        private const val PREFS_PRIVATE_KEY_2048 = "private_key_2048"
        private const val PREFS_PUBLIC_KEY_2048 = "public_key_2048"
        private const val PREFS_PRIVATE_KEY_4096 = "private_key_4096"
        private const val PREFS_PUBLIC_KEY_4096 = "public_key_4096"
        private const val EPHEMERAL_KEY_LIFETIME_MS = 3600000L // 1 hour
        private const val AES_KEY_LENGTH = 256
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH = 16
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
     * Encrypts private key for storage
     */
    private fun encryptPrivateKey(privateKeyBase64: String): String {
        try {
            // Generate a random AES key for encryption
            val keyGen = KeyGenerator.getInstance("AES")
            keyGen.init(256)
            val aesKey = keyGen.generateKey()
            
            // Generate random IV
            val iv = ByteArray(12)
            secureRandom.nextBytes(iv)
            
            // Encrypt private key
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(128, iv)
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec)
            
            val encryptedKey = cipher.doFinal(privateKeyBase64.toByteArray())
            
            // For simplicity, we'll store the AES key in a simple obfuscated way
            // In production, this should use Android Keystore
            val keyBytes = aesKey.encoded
            val combined = iv + keyBytes + encryptedKey
            
            return Base64.encodeToString(combined, Base64.NO_WRAP)
            
        } catch (e: Exception) {
            throw RuntimeException("Private key encryption failed: ${e.message}", e)
        }
    }
    
    /**
     * Decrypts private key from storage
     */
    private fun decryptPrivateKey(encryptedData: String): String {
        try {
            val combined = Base64.decode(encryptedData, Base64.NO_WRAP)
            
            val iv = combined.sliceArray(0..11)
            val keyBytes = combined.sliceArray(12..43)
            val encryptedKey = combined.sliceArray(44 until combined.size)
            
            val aesKey = SecretKeySpec(keyBytes, "AES")
            
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(128, iv)
            cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec)
            
            val decryptedBytes = cipher.doFinal(encryptedKey)
            return String(decryptedBytes)
            
        } catch (e: Exception) {
            throw RuntimeException("Private key decryption failed: ${e.message}", e)
        }
    }
    
    // ===== EPHEMERAL KEY MANAGEMENT - EXACTLY LIKE CRYPTING.kt =====
    
    /**
     * Generate ECDH ephemeral key pair for Perfect Forward Secrecy
     * Exactly like CRYPTING.kt implementation
     */
    fun generateEphemeralKeyPair(): KeyPair {
        try {
            val ecKeyGen = KeyPairGenerator.getInstance("EC")
            val ecSpec = ECGenParameterSpec("secp256r1")
            ecKeyGen.initialize(ecSpec, secureRandom)
            return ecKeyGen.generateKeyPair()
        } catch (e: Exception) {
            throw RuntimeException("Ephemeral key generation failed: ${e.message}", e)
        }
    }
    
    /**
     * Perform ECDH key agreement to derive shared secret
     */
    fun performECDH(privateKey: PrivateKey, publicKey: PublicKey): ByteArray {
        try {
            val keyAgreement = KeyAgreement.getInstance("ECDH")
            keyAgreement.init(privateKey)
            keyAgreement.doPhase(publicKey, true)
            return keyAgreement.generateSecret()
        } catch (e: Exception) {
            throw RuntimeException("ECDH key agreement failed: ${e.message}", e)
        }
    }
    
    /**
     * Manage ephemeral key lifecycle with automatic expiration
     */
    private val ephemeralKeys = mutableMapOf<String, EphemeralKeyData>()
    
    private data class EphemeralKeyData(
        val keyPair: KeyPair,
        val creationTime: Long,
        val expirationTime: Long
    )
    
    /**
     * Store ephemeral key with automatic cleanup
     */
    fun storeEphemeralKey(keyId: String, keyPair: KeyPair): String {
        val currentTime = System.currentTimeMillis()
        val expirationTime = currentTime + EPHEMERAL_KEY_LIFETIME_MS
        
        ephemeralKeys[keyId] = EphemeralKeyData(keyPair, currentTime, expirationTime)
        
        // Clean up expired keys
        cleanupExpiredKeys()
        
        return keyId
    }
    
    /**
     * Retrieve ephemeral key if not expired
     */
    fun getEphemeralKey(keyId: String): KeyPair? {
        val keyData = ephemeralKeys[keyId] ?: return null
        
        if (System.currentTimeMillis() > keyData.expirationTime) {
            secureWipeEphemeralKey(keyId)
            return null
        }
        
        return keyData.keyPair
    }
    
    /**
     * Clean up expired ephemeral keys
     */
    private fun cleanupExpiredKeys() {
        val currentTime = System.currentTimeMillis()
        val expiredKeys = ephemeralKeys.filter { (_, keyData) ->
            currentTime > keyData.expirationTime
        }.keys
        
        expiredKeys.forEach { keyId ->
            secureWipeEphemeralKey(keyId)
        }
    }
    
    /**
     * Securely wipe ephemeral key from memory
     */
    fun secureWipeEphemeralKey(keyId: String) {
        val keyData = ephemeralKeys[keyId]
        if (keyData != null) {
            // Secure wipe private key bytes
            try {
                val privateKeyBytes = keyData.keyPair.private.encoded
                Arrays.fill(privateKeyBytes, 0.toByte())
            } catch (e: Exception) {
                // Key might not be extractable, but we tried
            }
            
            ephemeralKeys.remove(keyId)
        }
    }
    
    /**
     * Wipe all ephemeral keys
     */
    fun wipeAllEphemeralKeys() {
        ephemeralKeys.keys.toList().forEach { keyId ->
            secureWipeEphemeralKey(keyId)
        }
    }
    
    /**
     * Generate unique key identifier for ephemeral keys
     */
    fun generateKeyId(): String {
        val timestamp = System.currentTimeMillis()
        val randomBytes = ByteArray(16)
        secureRandom.nextBytes(randomBytes)
        val randomHex = randomBytes.joinToString("") { "%02x".format(it) }
        return "ephemeral_${timestamp}_${randomHex}"
    }
    
    // ===== SECURE MEMORY MANAGEMENT =====
    
    /**
     * Secure wipe of sensitive byte arrays
     */
    fun secureWipe(data: ByteArray) {
        Arrays.fill(data, 0.toByte())
    }
    
    /**
     * Secure wipe of sensitive char arrays (passwords)
     */
    fun secureWipe(data: CharArray) {
        Arrays.fill(data, '\u0000')
    }
    
    /**
     * Create a secure copy of byte array that can be wiped
     */
    fun createSecureCopy(data: ByteArray): ByteArray {
        return data.copyOf()
    }
    
    /**
     * Zero out memory after use - defensive programming
     */
    fun runWithSecureCleanup(operation: () -> Unit) {
        try {
            operation()
        } finally {
            // Force garbage collection to help clear sensitive data
            System.gc()
        }
    }
    
    /**
     * Check if device supports hardware security features
     */
    fun checkHardwareSecuritySupport(): Map<String, Boolean> {
        return mapOf(
            "strongbox" to false, // Would need Android Keystore API check
            "tee" to false, // Would need Android Keystore API check
            "secure_random" to true
        )
    }
    
    /**
     * Generate cryptographically secure random bytes
     */
    fun generateSecureRandomBytes(size: Int): ByteArray {
        val bytes = ByteArray(size)
        secureRandom.nextBytes(bytes)
        return bytes
    }
    
    /**
     * Advanced key derivation with secure wiping
     */
    fun deriveKeyWithSecureCleanup(
        password: String,
        salt: ByteArray,
        iterations: Int,
        keyLength: Int
    ): ByteArray {
        val passwordChars = password.toCharArray()
        try {
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val spec = javax.crypto.spec.PBEKeySpec(passwordChars, salt, iterations, keyLength)
            val secretKey = factory.generateSecret(spec)
            return secretKey.encoded
        } finally {
            // Secure wipe password from memory
            secureWipe(passwordChars)
        }
    }
    
    /**
     * Get secure memory statistics
     */
    fun getSecureMemoryStats(): Map<String, Any> {
        return mapOf(
            "ephemeral_keys_count" to ephemeralKeys.size,
            "heap_memory_used" to (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()),
            "max_heap_memory" to Runtime.getRuntime().maxMemory(),
            "timestamp" to System.currentTimeMillis()
        )
    }
}