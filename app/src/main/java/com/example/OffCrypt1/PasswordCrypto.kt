package com.example.OffCrypt1

import android.util.Base64
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.security.spec.KeySpec
import java.time.Instant
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Password-based encryption using AES-256-GCM with PBKDF2 key derivation
 * Provides complete implementation for password-based message encryption
 */
class PasswordCrypto {

    private val secureRandom = SecureRandom()
    private val password2 = Password2()

    companion object {
        private const val AES_KEY_LENGTH = CryptoConstants.AES_KEY_LENGTH
        private const val GCM_IV_LENGTH = CryptoConstants.GCM_IV_LENGTH
        private const val GCM_TAG_LENGTH = CryptoConstants.GCM_TAG_LENGTH
        private const val SALT_SIZE = CryptoConstants.SALT_SIZE
        private const val MAC_SIZE = CryptoConstants.MAC_SIZE
        private const val ITERATION_COUNT = CryptoConstants.ITERATION_COUNT
        private const val VERSION_BYTE = CryptoConstants.VERSION_BYTE_PASSWORD
        private const val VERSION_BYTE_MULTI_SALT = CryptoConstants.VERSION_BYTE_MULTI_SALT
        private const val PBKDF2_ITERATIONS = CryptoConstants.ITERATION_COUNT
    }

    /**
     * Encrypts a message using password-based encryption (no password strength validation)
     */
    fun encryptPasswordBased(message: String, password: String, expirationTime: Long = 0): String {
        try {
            return encryptPasswordBasedMultiSalt(message, password, expirationTime)
        } catch (e: Exception) {
            throw RuntimeException("Password encryption failed: ${e.message}", e)
        }
    }

    /**
     * Advanced password-based encryption with multiple salts and separate HMAC key
     *
     */
    private fun encryptPasswordBasedMultiSalt(
        message: String,
        password: String,
        expirationTime: Long
    ): String {
        try {
            message.toByteArray(Charsets.UTF_8)

            // Generate three separate salts: master, encryption, MAC
            val masterSalt = ByteArray(SALT_SIZE)
            val encryptionSalt = ByteArray(SALT_SIZE)
            val macSalt = ByteArray(SALT_SIZE)
            secureRandom.nextBytes(masterSalt)
            secureRandom.nextBytes(encryptionSalt)
            secureRandom.nextBytes(macSalt)

            // Generate IV
            val iv = ByteArray(GCM_IV_LENGTH)
            secureRandom.nextBytes(iv)

            // Derive separate keys for encryption and MAC
            val encryptionKey =
                password2.generateSecureKey(password, encryptionSalt, ITERATION_COUNT)
            val macKey = password2.generateSecureKey(password, macSalt, ITERATION_COUNT)

            // Create metadata with timestamp and expiration
            val currentTime = Instant.now().epochSecond
            val messageWithMetadata = createAdvancedMetadata(message, currentTime, expirationTime)

            // Encrypt using AES-GCM
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val keySpec = SecretKeySpec(encryptionKey, "AES")
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)

            val encryptedMessage = cipher.doFinal(messageWithMetadata.toByteArray(Charsets.UTF_8))

            // Build data structure: [VERSION][MASTER_SALT][ENCRYPTION_SALT][MAC_SALT][IV][ENCRYPTED_MESSAGE]
            val dataToMac = ByteArrayOutputStream()
            dataToMac.write(VERSION_BYTE_MULTI_SALT.toInt())
            dataToMac.write(masterSalt)
            dataToMac.write(encryptionSalt)
            dataToMac.write(macSalt)
            dataToMac.write(iv)
            dataToMac.write(encryptedMessage)

            val dataToMacArray = dataToMac.toByteArray()

            // Generate HMAC using separate MAC key
            val hmac = generateAdvancedHMAC(dataToMacArray, macKey)

            // Final structure: [DATA][HMAC]
            val finalBuffer = ByteBuffer.allocate(dataToMacArray.size + MAC_SIZE)
            finalBuffer.put(dataToMacArray)
            finalBuffer.put(hmac)

            return Base64.encodeToString(finalBuffer.array(), Base64.NO_WRAP)

        } catch (e: Exception) {
            throw RuntimeException("Multi-salt password encryption failed: ${e.message}", e)
        }
    }

    /**
     * Decrypts a password-based encrypted message with multi-salt support
     */
    fun decryptPasswordBased(encryptedText: String, password: String): String {
        try {
            val encryptedData = Base64.decode(encryptedText, Base64.NO_WRAP)

            if (encryptedData.isEmpty()) {
                throw IllegalArgumentException("Empty encrypted data")
            }

            // Check version to determine decryption method
            val versionByte = encryptedData[0]

            return when (versionByte) {
                VERSION_BYTE -> decryptPasswordBasedLegacy(encryptedData, password)
                VERSION_BYTE_MULTI_SALT -> decryptPasswordBasedMultiSalt(encryptedData, password)
                else -> throw IllegalArgumentException("Unsupported encryption version: $versionByte")
            }

        } catch (e: Exception) {
            throw RuntimeException("Password decryption failed: ${e.message}", e)
        }
    }

    /**
     * Decrypt with multiple salts - exactly like CRYPTING.kt
     */
    private fun decryptPasswordBasedMultiSalt(encryptedData: ByteArray, password: String): String {
        try {
            // Minimum size check: version + 3 salts + IV + MAC + at least some encrypted data
            if (encryptedData.size < 1 + SALT_SIZE * 3 + GCM_IV_LENGTH + MAC_SIZE + GCM_TAG_LENGTH) {
                throw RuntimeException("Invalid encrypted data size")
            }

            var offset = 1 // Skip version byte

            // Extract three salts
            encryptedData.copyOfRange(offset, offset + SALT_SIZE)
            offset += SALT_SIZE

            val encryptionSalt = encryptedData.copyOfRange(offset, offset + SALT_SIZE)
            offset += SALT_SIZE

            val macSalt = encryptedData.copyOfRange(offset, offset + SALT_SIZE)
            offset += SALT_SIZE

            // Extract IV
            val iv = encryptedData.copyOfRange(offset, offset + GCM_IV_LENGTH)
            offset += GCM_IV_LENGTH

            // Extract encrypted content and MAC
            val encryptedContent = encryptedData.copyOfRange(offset, encryptedData.size - MAC_SIZE)
            val receivedMac =
                encryptedData.copyOfRange(encryptedData.size - MAC_SIZE, encryptedData.size)

            // Derive keys
            val encryptionKey = generateSecureKey(password, encryptionSalt, ITERATION_COUNT)
            val macKey = generateSecureKey(password, macSalt, ITERATION_COUNT)

            // Verify HMAC
            val dataToVerify = encryptedData.copyOfRange(0, encryptedData.size - MAC_SIZE)
            if (!verifyAdvancedHMAC(dataToVerify, receivedMac, macKey)) {
                throw RuntimeException("HMAC verification failed - wrong password or corrupted data")
            }

            // Decrypt message
            val keySpec = SecretKeySpec(encryptionKey, "AES")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)

            val decryptedData = cipher.doFinal(encryptedContent)
            val messageWithMetadata = String(decryptedData, Charsets.UTF_8)

            // Parse and extract original message
            return parseAdvancedMetadata(messageWithMetadata)

        } catch (e: Exception) {
            throw RuntimeException("Multi-salt decryption failed: ${e.message}", e)
        }
    }

    /**
     * Legacy decryption for backward compatibility
     */
    private fun decryptPasswordBasedLegacy(encryptedData: ByteArray, password: String): String {
        try {
            if (encryptedData.size < 57) { // Minimum size check
                throw IllegalArgumentException("Invalid encrypted data format")
            }

            val buffer = ByteBuffer.wrap(encryptedData)

            // Extract HMAC
            val storedHmac = ByteArray(32)
            buffer.get(storedHmac)

            // Extract main data
            val mainData = ByteArray(encryptedData.size - 32)
            buffer.get(mainData)

            val mainBuffer = ByteBuffer.wrap(mainData)

            // Verify version
            val version = mainBuffer.get()
            if (version != VERSION_BYTE) {
                throw IllegalArgumentException("Unsupported encryption version")
            }

            // Extract timestamps
            mainBuffer.getLong()
            val expirationTime = mainBuffer.getLong()

            // Check expiration
            if (expirationTime > 0 && Instant.now().epochSecond > expirationTime) {
                throw IllegalArgumentException("Message has expired")
            }

            // Extract salt and IV
            val salt = ByteArray(SALT_SIZE)
            val iv = ByteArray(GCM_IV_LENGTH)
            mainBuffer.get(salt)
            mainBuffer.get(iv)

            // Derive key
            val secretKey = deriveKeyFromPassword(password, salt)

            // Verify HMAC
            val calculatedHmac = generateHMAC(mainData, secretKey)
            if (!verifyHMAC(storedHmac, calculatedHmac)) {
                throw IllegalArgumentException("HMAC verification failed - wrong password or corrupted data")
            }

            // Extract and decrypt message
            val encryptedMessage = ByteArray(mainBuffer.remaining())
            mainBuffer.get(encryptedMessage)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)

            val decryptedBytes = cipher.doFinal(encryptedMessage)
            return String(decryptedBytes, Charsets.UTF_8)

        } catch (e: Exception) {
            throw RuntimeException("Legacy password decryption failed: ${e.message}", e)
        }
    }

    private fun deriveKeyFromPassword(password: String, salt: ByteArray): SecretKey {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec: KeySpec =
            PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, AES_KEY_LENGTH)
        val secretKey = factory.generateSecret(spec)
        return SecretKeySpec(secretKey.encoded, "AES")
    }

    private fun generateHMAC(data: ByteArray, key: SecretKey): ByteArray {
        return SecureCrypto.generateHMAC(data, key.encoded)
    }

    private fun verifyHMAC(stored: ByteArray, calculated: ByteArray): Boolean {
        return SecurityUtils.constantTimeEquals(stored, calculated)
    }

    private fun createMetadata(currentTime: Long, expirationTime: Long): String {
        return "v1:$currentTime:$expirationTime"
    }

    // Delegate missing functions to Password2 / SecureCrypto
    private fun generateSecureKey(password: String, salt: ByteArray, iterations: Int): ByteArray {
        return SecureCrypto.generateSecureKey(password, salt, iterations)
    }

    private fun generateAdvancedHMAC(data: ByteArray, macKey: ByteArray): ByteArray {
        return password2.generateAdvancedHMAC(data, macKey)
    }

    private fun verifyAdvancedHMAC(
        data: ByteArray,
        storedMac: ByteArray,
        macKey: ByteArray
    ): Boolean {
        return password2.verifyAdvancedHMAC(data, storedMac, macKey)
    }

    private fun createAdvancedMetadata(
        message: String,
        timestamp: Long,
        expirationTime: Long
    ): String {
        return password2.createAdvancedMetadata(message, timestamp, expirationTime)
    }

    private fun parseAdvancedMetadata(messageWithMetadata: String): String {
        return password2.parseAdvancedMetadata(messageWithMetadata)
    }
}
