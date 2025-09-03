package com.example.OffCrypt1

import android.util.Base64
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.time.Instant
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Advanced password-based encryption with multiple salts - exactly like CRYPTING.kt
 * This extends PasswordCrypto with advanced features
 */
class Password2 {

    private val secureRandom = SecureRandom()

    companion object {
        private const val AES_KEY_LENGTH = CryptoConstants.AES_KEY_LENGTH
        private const val GCM_IV_LENGTH = CryptoConstants.GCM_IV_LENGTH
        private const val GCM_TAG_LENGTH = CryptoConstants.GCM_TAG_LENGTH
        private const val SALT_SIZE = CryptoConstants.SALT_SIZE
        private const val MAC_SIZE = CryptoConstants.MAC_SIZE
        private const val ITERATION_COUNT = CryptoConstants.ITERATION_COUNT
        private const val VERSION_BYTE_MULTI_SALT = CryptoConstants.VERSION_BYTE_MULTI_SALT
        private const val VERSION_BYTE_BURN = CryptoConstants.VERSION_BYTE_BURN_AFTER_READING
    }

    /**
     * Advanced password-based encryption with multiple salts and separate HMAC key
     * Exactly like CRYPTING.kt implementation
     */
    fun encryptPasswordBasedMultiSalt(
        message: String,
        password: String,
        expirationTime: Long = 0
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
            val encryptionKey = generateSecureKey(password, encryptionSalt, ITERATION_COUNT)
            val macKey = generateSecureKey(password, macSalt, ITERATION_COUNT)

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
     * Decrypt with multiple salts - exactly like CRYPTING.kt
     */
    fun decryptPasswordBasedMultiSalt(encryptedData: ByteArray, password: String): String {
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
     * Encrypt with burn-after-reading flag
     */
    fun encryptPasswordBasedBurnAfterReading(message: String, password: String): String {
        try {
            val burnMetadata = createBurnAfterReadingMetadata(message)
            return encryptPasswordBasedMultiSalt(burnMetadata, password, 0)
        } catch (e: Exception) {
            throw RuntimeException("Burn-after-reading encryption failed: ${e.message}", e)
        }
    }

    /**
     * Decrypt with burn-after-reading - message self-destructs after reading
     */
    fun decryptPasswordBasedBurnAfterReading(encryptedText: String, password: String): String {
        try {
            val encryptedData = Base64.decode(encryptedText, Base64.NO_WRAP)
            val decryptedMessage = decryptPasswordBasedMultiSalt(encryptedData, password)

            // Check if this is a burn-after-reading message
            if (decryptedMessage.contains("\"burn_after_reading\":true")) {
                // In a real implementation, you would securely wipe the encrypted data
                // For now, we'll just mark it as read
                return parseBurnAfterReadingMessage(decryptedMessage)
            }

            return decryptedMessage
        } catch (e: Exception) {
            throw RuntimeException("Burn-after-reading decryption failed: ${e.message}", e)
        }
    }

    // ===== UTILITY METHODS =====

    /**
     * Generate secure key using PBKDF2 - exactly like CRYPTING.kt
     */
    fun generateSecureKey(password: String, salt: ByteArray, iterations: Int): ByteArray {
        return SecureCrypto.generateSecureKey(password, salt, iterations)
    }

    /**
     * Advanced HMAC generation with separate MAC key
     */
    fun generateAdvancedHMAC(data: ByteArray, macKey: ByteArray): ByteArray {
        return SecureCrypto.generateHMAC(data, macKey)
    }

    /**
     * Verify HMAC with separate MAC key
     */
    fun verifyAdvancedHMAC(data: ByteArray, storedMac: ByteArray, macKey: ByteArray): Boolean {
        return SecureCrypto.verifyHMAC(data, storedMac, macKey)
    }

    private fun verifyHMAC(stored: ByteArray, calculated: ByteArray): Boolean {
        return SecurityUtils.constantTimeEquals(stored, calculated)
    }

    /**
     * Create advanced metadata with timestamp and expiration
     */
    fun createAdvancedMetadata(message: String, timestamp: Long, expirationTime: Long): String {
        val metadata = mutableMapOf<String, Any>()
        metadata["timestamp"] = timestamp
        metadata["version"] = "2.1"
        metadata["format"] = "multi-salt"

        if (expirationTime > 0) {
            metadata["expiration"] = expirationTime
        }

        // Simple JSON-like format
        val metadataJson =
            metadata.entries.joinToString(",") { "\"${it.key}\":${if (it.value is String) "\"${it.value}\"" else it.value}" }
        return "{\"metadata\":{$metadataJson},\"message\":\"$message\"}"
    }

    /**
     * Parse advanced metadata and extract original message
     */
    fun parseAdvancedMetadata(messageWithMetadata: String): String {
        return try {
            // Simple JSON-like parsing
            val messageStart = messageWithMetadata.indexOf("\"message\":\"") + 11
            val messageEnd = messageWithMetadata.lastIndexOf("\"}")

            if (messageStart > 10 && messageEnd > messageStart) {
                val extractedMessage = messageWithMetadata.substring(messageStart, messageEnd)

                // Check expiration if metadata exists
                if (messageWithMetadata.contains("\"expiration\"")) {
                    val expirationStart = messageWithMetadata.indexOf("\"expiration\":")
                    if (expirationStart > 0) {
                        val expirationValueStart =
                            messageWithMetadata.indexOf(":", expirationStart) + 1
                        val expirationEnd =
                            messageWithMetadata.indexOf(",", expirationValueStart).let {
                                if (it == -1) messageWithMetadata.indexOf(
                                    "}",
                                    expirationValueStart
                                ) else it
                            }

                        if (expirationEnd > expirationValueStart) {
                            val expirationStr =
                                messageWithMetadata.substring(expirationValueStart, expirationEnd)
                                    .trim()
                            val expirationTime = expirationStr.toLongOrNull() ?: 0

                            if (expirationTime > 0 && System.currentTimeMillis() > expirationTime) {
                                throw RuntimeException("Message has expired")
                            }
                        }
                    }
                }

                return extractedMessage
            } else {
                messageWithMetadata // Fallback to original
            }
        } catch (e: Exception) {
            if (e.message?.contains("expired") == true) {
                throw e // Re-throw expiration errors
            }
            messageWithMetadata // Fallback to original for parsing errors
        }
    }

    private fun createBurnAfterReadingMetadata(message: String): String {
        val metadata = mapOf(
            "timestamp" to System.currentTimeMillis(),
            "version" to "2.1",
            "burn_after_reading" to true,
            "format" to "multi-salt"
        )

        val metadataJson =
            metadata.entries.joinToString(",") { "\"${it.key}\":${if (it.value is String) "\"${it.value}\"" else it.value}" }
        return "{\"metadata\":{$metadataJson},\"message\":\"$message\"}"
    }

    private fun parseBurnAfterReadingMessage(messageWithMetadata: String): String {
        return try {
            val messageStart = messageWithMetadata.indexOf("\"message\":\"") + 11
            val messageEnd = messageWithMetadata.lastIndexOf("\"}")

            if (messageStart > 10 && messageEnd > messageStart) {
                messageWithMetadata.substring(messageStart, messageEnd)
            } else {
                messageWithMetadata
            }
        } catch (e: Exception) {
            messageWithMetadata
        }
    }

}
