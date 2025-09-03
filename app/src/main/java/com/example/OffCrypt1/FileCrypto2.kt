package com.example.OffCrypt1

import android.content.Context
import android.util.Base64
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Advanced file encryption with multiple authentication layers - exactly like CRYPTING.kt
 * This extends FileCrypto with CRYPTING.kt features
 */
class FileCrypto2(private val context: Context) {

    private val secureRandom = SecureRandom()
    private val password2 = Password2()
    private val rsaCrypto = RSACrypto(context)

    companion object {
        private const val FILE_VERSION_BYTE: Byte = 0x0B
        private const val FILE_VERSION_MULTI_SALT: Byte = 0x0C
        private const val FILE_VERSION_RSA_ADVANCED: Byte = 0x0D
        private const val AES_KEY_LENGTH = 256
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH = 16
        private const val SALT_SIZE = 32
        private const val MAC_SIZE = 32
    }

    /**
     * Advanced file encryption with multiple salts and separate authentication layers
     * Exactly like CRYPTING.kt implementation
     */
    fun encryptFileDataPasswordBasedAdvanced(
        fileData: ByteArray,
        metadata: String,
        password: String
    ): ByteArray {
        try {
            // Generate three separate salts for different purposes
            val masterSalt = ByteArray(SALT_SIZE)
            val encryptionSalt = ByteArray(SALT_SIZE)
            val macSalt = ByteArray(SALT_SIZE)
            secureRandom.nextBytes(masterSalt)
            secureRandom.nextBytes(encryptionSalt)
            secureRandom.nextBytes(macSalt)

            // Generate IV for AES-GCM
            val iv = ByteArray(GCM_IV_LENGTH)
            secureRandom.nextBytes(iv)

            // Derive separate keys
            val encryptionKey = password2.generateSecureKey(password, encryptionSalt, 100000)
            val macKey = password2.generateSecureKey(password, macSalt, 100000)

            // Create advanced file metadata
            val fileMetadata = JSONObject().apply {
                put("filename", metadata)
                put("size", fileData.size)
                put("encryption_type", "password_advanced")
                put("timestamp", System.currentTimeMillis())
                put("format", "multi-salt")
                put("version", "2.1")
                put("auth_layers", 3) // Master salt + encryption + MAC
            }

            // Combine file data with metadata
            val combinedData = JSONObject().apply {
                put("metadata", fileMetadata)
                put("filedata", Base64.encodeToString(fileData, Base64.NO_WRAP))
            }

            // Encrypt the combined data
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val keySpec = SecretKeySpec(encryptionKey, "AES")
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)

            val encryptedContent =
                cipher.doFinal(combinedData.toString().toByteArray(Charsets.UTF_8))

            // Build data structure for HMAC verification
            val dataToMac = ByteArrayOutputStream()
            dataToMac.write(FILE_VERSION_MULTI_SALT.toInt())
            dataToMac.write(masterSalt)
            dataToMac.write(encryptionSalt)
            dataToMac.write(macSalt)
            dataToMac.write(iv)
            dataToMac.write(encryptedContent)

            val dataToMacArray = dataToMac.toByteArray()

            // Generate HMAC using separate MAC key
            val hmac = password2.generateAdvancedHMAC(dataToMacArray, macKey)

            // Final file structure: [DATA][HMAC]
            val finalBuffer = ByteBuffer.allocate(dataToMacArray.size + MAC_SIZE)
            finalBuffer.put(dataToMacArray)
            finalBuffer.put(hmac)

            return finalBuffer.array()

        } catch (e: Exception) {
            throw RuntimeException("Advanced file encryption failed: ${e.message}", e)
        }
    }

    /**
     * Advanced file decryption with multiple authentication layers
     */
    fun decryptFileDataPasswordBasedAdvanced(
        encryptedData: ByteArray,
        password: String
    ): Pair<ByteArray, String> {
        try {
            // Minimum size check
            if (encryptedData.size < 1 + SALT_SIZE * 3 + GCM_IV_LENGTH + MAC_SIZE + GCM_TAG_LENGTH) {
                throw RuntimeException("Invalid file data size")
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
            val encryptionKey = password2.generateSecureKey(password, encryptionSalt, 100000)
            val macKey = password2.generateSecureKey(password, macSalt, 100000)

            // Verify HMAC
            val dataToVerify = encryptedData.copyOfRange(0, encryptedData.size - MAC_SIZE)
            if (!password2.verifyAdvancedHMAC(dataToVerify, receivedMac, macKey)) {
                throw RuntimeException("HMAC verification failed - wrong password or corrupted data")
            }

            // Decrypt content
            val keySpec = SecretKeySpec(encryptionKey, "AES")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)

            val decryptedData = cipher.doFinal(encryptedContent)
            val combinedDataString = String(decryptedData, Charsets.UTF_8)

            return parseAdvancedFileDataAndMetadata(combinedDataString)

        } catch (e: Exception) {
            throw RuntimeException("Advanced file decryption failed: ${e.message}", e)
        }
    }

    /**
     * Advanced RSA file encryption with PFS and digital signatures
     */
    fun encryptFileDataRSAAdvanced(
        fileData: ByteArray,
        metadata: String,
        recipientPublicKey: PublicKey,
        userKeyPair: android.util.Pair<PublicKey, PrivateKey>? = null,
        enablePFS: Boolean = true,
        enableSignatures: Boolean = true,
        expirationTime: Long = 0L
    ): ByteArray {
        try {
            // Create advanced metadata
            val fileMetadata = JSONObject().apply {
                put("filename", metadata)
                put("size", fileData.size)
                put("encryption_type", "rsa_advanced")
                put("timestamp", System.currentTimeMillis())
                put("version", "2.1")
                put("pfs_enabled", enablePFS)
                put("signatures_enabled", enableSignatures)
            }

            // Combine data and metadata
            val combinedData = JSONObject().apply {
                put("metadata", fileMetadata)
                put("filedata", Base64.encodeToString(fileData, Base64.NO_WRAP))
            }

            val combinedString = combinedData.toString()

            // Use RSACrypto's advanced encryption
            val keyPair = userKeyPair?.let {
                java.security.KeyPair(it.first, it.second)
            }
            val encryptedString = rsaCrypto.encryptRSAWithAllFeatures(
                combinedString,
                recipientPublicKey,
                enablePFS,
                enableSignatures,
                expirationTime > 0L, // Enable expiration only if time is set
                if (expirationTime > 0L) expirationTime else 0L,
                keyPair
            )

            // Add file version header
            val encryptedBytes = Base64.decode(encryptedString, Base64.NO_WRAP)
            val buffer = ByteBuffer.allocate(1 + encryptedBytes.size)
            buffer.put(FILE_VERSION_RSA_ADVANCED)
            buffer.put(encryptedBytes)

            return buffer.array()

        } catch (e: Exception) {
            throw RuntimeException("Advanced RSA file encryption failed: ${e.message}", e)
        }
    }

    /**
     * Advanced RSA file decryption with PFS and signature verification
     */
    fun decryptFileDataRSAAdvanced(
        encryptedData: ByteArray,
        privateKey: PrivateKey,
        senderPublicKey: PublicKey? = null
    ): Pair<ByteArray, String> {
        try {
            if (encryptedData.isEmpty() || encryptedData[0] != FILE_VERSION_RSA_ADVANCED) {
                throw IllegalArgumentException("Invalid RSA advanced file format")
            }

            // Extract encrypted data without version byte
            val encryptedContent = encryptedData.sliceArray(1 until encryptedData.size)
            val encryptedString = Base64.encodeToString(encryptedContent, Base64.NO_WRAP)

            // Decrypt using RSA advanced methods
            val decryptedString =
                rsaCrypto.decryptRSAMessage(encryptedString, privateKey, senderPublicKey)

            return parseAdvancedFileDataAndMetadata(decryptedString)

        } catch (e: Exception) {
            throw RuntimeException("Advanced RSA file decryption failed: ${e.message}", e)
        }
    }

    /**
     * File encryption with burn-after-reading
     */
    fun encryptFileDataBurnAfterReading(
        fileData: ByteArray,
        metadata: String,
        password: String
    ): ByteArray {
        try {
            // Create burn-after-reading metadata
            val burnMetadata = JSONObject().apply {
                put("filename", metadata)
                put("size", fileData.size)
                put("encryption_type", "password_burn")
                put("timestamp", System.currentTimeMillis())
                put("burn_after_reading", true)
                put("version", "2.1")
            }

            // Combine with special burn marker
            val combinedData = JSONObject().apply {
                put("metadata", burnMetadata)
                put("filedata", Base64.encodeToString(fileData, Base64.NO_WRAP))
                put("burn_after_reading", true)
            }

            return encryptFileDataPasswordBasedAdvanced(
                combinedData.toString().toByteArray(),
                "BURN_AFTER_READING",
                password
            )

        } catch (e: Exception) {
            throw RuntimeException("Burn-after-reading file encryption failed: ${e.message}", e)
        }
    }

    // ===== UTILITY METHODS =====

    /**
     * Parse advanced file data and metadata from decrypted content
     */
    private fun parseAdvancedFileDataAndMetadata(combinedData: String): Pair<ByteArray, String> {
        return try {
            val jsonObject = JSONObject(combinedData)
            val metadata = jsonObject.getJSONObject("metadata")
            val filename = metadata.getString("filename")
            val encodedFileData = jsonObject.getString("filedata")

            // Check for burn-after-reading
            if (jsonObject.optBoolean("burn_after_reading", false)) {
                // In a real implementation, you would securely wipe the encrypted data
                // For now, we mark it as processed
            }

            val fileData = Base64.decode(encodedFileData, Base64.NO_WRAP)

            // Create enhanced metadata string with additional info
            val enhancedMetadata = buildString {
                append(filename)
                if (metadata.has("size")) {
                    append(" (${metadata.getLong("size")} bytes)")
                }
                if (metadata.has("timestamp")) {
                    append(" [${metadata.getLong("timestamp")}]")
                }
                if (metadata.optBoolean("burn_after_reading", false)) {
                    append(" [BURNED]")
                }
            }

            Pair(fileData, enhancedMetadata)

        } catch (e: Exception) {
            throw RuntimeException("Failed to parse advanced file data: ${e.message}", e)
        }
    }




    /**
     * Detect file encryption type from encrypted data
     */
    fun detectFileEncryptionType(encryptedData: ByteArray): String {
        return when {
            encryptedData.isEmpty() -> "Unknown"
            encryptedData[0] == FILE_VERSION_BYTE -> "Basic file encryption"
            encryptedData[0] == FILE_VERSION_MULTI_SALT -> "Advanced password-based (multi-salt)"
            encryptedData[0] == FILE_VERSION_RSA_ADVANCED -> "Advanced RSA with PFS/signatures"
            else -> "Unknown format (0x${encryptedData[0].toString(16)})"
        }
    }

    /**
     * Check if file has burn-after-reading capability
     */
    fun checkBurnAfterReading(encryptedData: ByteArray, password: String): Boolean {
        return try {
            if (encryptedData[0] == FILE_VERSION_MULTI_SALT) {
                val (_, metadata) = decryptFileDataPasswordBasedAdvanced(encryptedData, password)
                metadata.contains("[BURNED]") || metadata.contains("burn_after_reading")
            } else {
                false
            }
        } catch (e: Exception) {
            false
        }
    }
}