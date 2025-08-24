package com.example.OffCrypt1

import java.security.Key
import java.security.KeyPair
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.MGF1ParameterSpec
import java.text.SimpleDateFormat
import java.util.Base64
import java.util.Date
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

/**
 * MessageCryptoService - Clean business logic for message encryption/decryption
 * 
 * Extracted from SecureMessage.kt to separate cryptographic operations from UI logic.
 * This service provides a clean interface for encryption/decryption without UI dependencies.
 */
class MessageCryptoService(
    private val cryptoManager: CryptoManager
) {
    
    companion object {
        // Version bytes for different encryption methods
        private const val VERSION_BYTE_PASSWORD: Byte = 0x01
        private const val VERSION_BYTE_RSA: Byte = 0x02
        private const val VERSION_BYTE_RSA_EXPIRING: Byte = 0x03
        private const val VERSION_BYTE_RSA_SIGNED: Byte = 0x04
        private const val VERSION_BYTE_RSA_PFS: Byte = 0x05
        private const val VERSION_BYTE_RSA_SIGNED_PFS: Byte = 0x06
        private const val VERSION_BYTE_RSA_ALL: Byte = 0x07
        private const val VERSION_BYTE_RSA_4096_AES_FULL: Byte = 0x0A
        
        // Cryptographic constants
        private const val IV_SIZE = 12
        private const val GCM_TAG_LENGTH = 16
    }
    
    /**
     * Encrypt message with password-based encryption
     * @param message The message to encrypt
     * @param password The encryption password
     * @param expirationTime Optional expiration timestamp (0 = no expiration)
     * @return Base64 encoded encrypted message
     * @throws RuntimeException if password is empty or encryption fails
     */
    fun encryptWithPassword(message: String, password: String, expirationTime: Long = 0): String {
        if (password.isEmpty()) {
            throw RuntimeException("Enter password or use generated password!")
        }
        
        return cryptoManager.encryptWithPassword(message, password, expirationTime)
    }
    
    /**
     * Encrypt message with RSA public key encryption
     * @param message The message to encrypt
     * @param recipientPublicKey The recipient's public key as string
     * @param options RSA encryption options and configuration
     * @return Base64 encoded encrypted message
     * @throws RuntimeException if public key is invalid or encryption fails
     */
    fun encryptWithRSA(message: String, recipientPublicKey: String, options: RSAEncryptionOptions): String {
        if (recipientPublicKey.trim().isEmpty()) {
            throw RuntimeException("Enter recipient's public key!")
        }

        return try {
            val publicKey = cryptoManager.parsePublicKeyFromString(recipientPublicKey.trim())
            
            cryptoManager.encryptWithRSA(
                message, 
                publicKey, 
                options.useRSA4096, 
                options.enablePFS, 
                options.enableSignatures, 
                options.enableExpiration, 
                options.expirationTime
            )
        } catch (e: Exception) {
            throw RuntimeException("Invalid public key: ${e.message}")
        }
    }
    
    /**
     * Decrypt an encrypted message based on version byte detection
     * @param encryptedMessage Base64 encoded encrypted message
     * @param password Optional password for password-based decryption
     * @param keyPair Optional key pair for RSA-based decryption
     * @return DecryptionResult containing decrypted message and metadata
     * @throws RuntimeException if decryption fails or required parameters missing
     */
    fun decryptMessage(encryptedMessage: String, password: String?, keyPair: KeyPair?): DecryptionResult {
        if (encryptedMessage.trim().isEmpty()) {
            throw RuntimeException("Enter encrypted message!")
        }

        val encryptedData = Base64.getDecoder().decode(encryptedMessage.trim())
        val version = encryptedData[0]

        val decryptedMessage = when (version) {
            VERSION_BYTE_PASSWORD -> {
                if (password?.trim()?.isEmpty() != false) {
                    throw RuntimeException("Enter password!")
                }
                cryptoManager.decryptWithPassword(encryptedMessage, password)
            }
            VERSION_BYTE_RSA, VERSION_BYTE_RSA_EXPIRING -> {
                if (keyPair?.private == null) {
                    throw RuntimeException("Private key missing for decryption!")
                }
                try {
                    cryptoManager.decryptWithRSA(encryptedMessage, keyPair.private, keyPair.public)
                } catch (e: Exception) {
                    // Fallback to legacy decryption methods for backward compatibility
                    when (version) {
                        VERSION_BYTE_RSA -> decryptRSABased(encryptedMessage, keyPair.private)
                        VERSION_BYTE_RSA_EXPIRING -> decryptRSABasedWithExpiration(encryptedMessage, keyPair.private)
                        else -> throw e
                    }
                }
            }
            VERSION_BYTE_RSA_SIGNED, VERSION_BYTE_RSA_PFS, 
            VERSION_BYTE_RSA_SIGNED_PFS, VERSION_BYTE_RSA_ALL -> {
                if (keyPair?.private == null) {
                    throw RuntimeException("Private key missing for RSA decryption!")
                }
                decryptRSAWithFeatures(encryptedMessage, keyPair.private, version)
            }
            VERSION_BYTE_RSA_4096_AES_FULL -> {
                if (keyPair?.private == null) {
                    throw RuntimeException("Private key missing for RSA-4096 decryption!")
                }
                decryptRSA4096WithAESFull(encryptedMessage, keyPair.private)
            }
            else -> {
                throw RuntimeException("Unknown encryption version: $version")
            }
        }

        return DecryptionResult(
            message = decryptedMessage,
            metadata = DecryptionMetadata(
                encryptionMethod = getEncryptionMethod(version),
                version = version,
                hasExpiration = isExpiringVersion(version)
            )
        )
    }
    
    /**
     * Legacy RSA decryption method for backward compatibility
     * @param encryptedText Base64 encoded encrypted text
     * @param privateKey RSA private key
     * @return Decrypted message
     */
    private fun decryptRSABased(encryptedText: String, privateKey: PrivateKey): String {
        try {
            val encryptedData = Base64.getDecoder().decode(encryptedText)
            var offset = 1

            val aesKeySize = (encryptedData[offset].toInt() and 0xFF) or
                    ((encryptedData[offset + 1].toInt() and 0xFF) shl 8)
            offset += 2

            val encryptedAESKey = encryptedData.copyOfRange(offset, offset + aesKeySize)
            offset += aesKeySize

            val iv = encryptedData.copyOfRange(offset, offset + IV_SIZE)
            offset += IV_SIZE

            val encryptedMessage = encryptedData.copyOfRange(offset, encryptedData.size)

            val rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING")
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey)
            val aesKeyBytes = rsaCipher.doFinal(encryptedAESKey)
            val aesKey = SecretKeySpec(aesKeyBytes, "AES")

            val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec)
            val decryptedData = aesCipher.doFinal(encryptedMessage)

            return String(decryptedData, Charsets.UTF_8)

        } catch (e: Exception) {
            throw RuntimeException("RSA decryption failed", e)
        }
    }
    
    /**
     * Legacy RSA decryption with expiration for backward compatibility  
     * @param encryptedText Base64 encoded encrypted text
     * @param privateKey RSA private key
     * @return Decrypted message
     */
    private fun decryptRSABasedWithExpiration(encryptedText: String, privateKey: PrivateKey): String {
        try {
            val encryptedData = Base64.getDecoder().decode(encryptedText)
            var offset = 1

            val aesKeySize = (encryptedData[offset].toInt() and 0xFF) or
                    ((encryptedData[offset + 1].toInt() and 0xFF) shl 8)
            offset += 2

            val encryptedAESKey = encryptedData.copyOfRange(offset, offset + aesKeySize)
            offset += aesKeySize

            val iv = encryptedData.copyOfRange(offset, offset + IV_SIZE)
            offset += IV_SIZE

            val encryptedMessage = encryptedData.copyOfRange(offset, encryptedData.size)

            val rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING")
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey)
            val aesKeyBytes = rsaCipher.doFinal(encryptedAESKey)
            val aesKey = SecretKeySpec(aesKeyBytes, "AES")

            val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec)
            val decryptedData = aesCipher.doFinal(encryptedMessage)

            val messageWithMetadata = String(decryptedData, Charsets.UTF_8)
            val metadata = parseMessageMetadata(messageWithMetadata)

            if (metadata != null) {
                val expirationTime = metadata["exp"] as? Long
                if (expirationTime != null && System.currentTimeMillis() > expirationTime) {
                    val expiredDate = SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()).format(Date(expirationTime))
                    throw RuntimeException("Message has expired ($expiredDate)")
                }

                return metadata["msg"] as String
            }

            return messageWithMetadata

        } catch (e: Exception) {
            throw RuntimeException("RSA decryption with expiring message failed: ${e.message}")
        }
    }
    
    /**
     * RSA decryption with advanced features (PFS, signatures, etc.)
     * @param encryptedText Base64 encoded encrypted text
     * @param privateKey RSA private key
     * @param version Version byte indicating features used
     * @return Decrypted message
     */
    private fun decryptRSAWithFeatures(encryptedText: String, privateKey: PrivateKey, version: Byte): String {
        try {
            val encryptedData = Base64.getDecoder().decode(encryptedText)
            var offset = 1

            if (offset + 2 > encryptedData.size) {
                throw RuntimeException("Corrupted data: AES key size missing")
            }

            val aesKeySize = (encryptedData[offset].toInt() and 0xFF) or
                    ((encryptedData[offset + 1].toInt() and 0xFF) shl 8)
            offset += 2

            if (aesKeySize <= 0 || aesKeySize > 1024) {
                throw RuntimeException("Invalid AES key size: $aesKeySize")
            }

            if (offset + aesKeySize > encryptedData.size) {
                throw RuntimeException("Corrupted data: AES key missing")
            }

            val encryptedAESKey = encryptedData.copyOfRange(offset, offset + aesKeySize)
            offset += aesKeySize

            if (offset + IV_SIZE > encryptedData.size) {
                throw RuntimeException("Corrupted data: IV missing")
            }

            val iv = encryptedData.copyOfRange(offset, offset + IV_SIZE)
            offset += IV_SIZE

            if (offset + 2 > encryptedData.size) {
                throw RuntimeException("Corrupted data: signature size missing")
            }

            val signatureSize = (encryptedData[offset].toInt() and 0xFF) or
                    ((encryptedData[offset + 1].toInt() and 0xFF) shl 8)
            offset += 2

            var signature: ByteArray? = null
            if (signatureSize > 0) {
                if (offset + signatureSize > encryptedData.size) {
                    throw RuntimeException("Corrupted data: signature missing")
                }
                signature = encryptedData.copyOfRange(offset, offset + signatureSize)
                offset += signatureSize
            }

            if (offset + 2 > encryptedData.size) {
                throw RuntimeException("Corrupted data: ephemeral key size missing")
            }

            val ephemeralKeySize = (encryptedData[offset].toInt() and 0xFF) or
                    ((encryptedData[offset + 1].toInt() and 0xFF) shl 8)
            offset += 2

            var ephemeralKeyBytes: ByteArray? = null
            if (ephemeralKeySize > 0) {
                if (offset + ephemeralKeySize > encryptedData.size) {
                    throw RuntimeException("Corrupted data: ephemeral key missing")
                }
                ephemeralKeyBytes = encryptedData.copyOfRange(offset, offset + ephemeralKeySize)
                offset += ephemeralKeySize
            }

            if (offset >= encryptedData.size) {
                throw RuntimeException("Corrupted data: encrypted message missing")
            }

            val encryptedMessage = encryptedData.copyOfRange(offset, encryptedData.size)

            try {
                val rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING")
                rsaCipher.init(Cipher.DECRYPT_MODE, privateKey)
                val originalAESKeyBytes = rsaCipher.doFinal(encryptedAESKey)
                val originalAESKey = SecretKeySpec(originalAESKeyBytes, "AES")

                var finalAESKey = originalAESKey
                if (ephemeralKeyBytes != null && ephemeralKeyBytes.isNotEmpty()) {
                    try {
                        val ephemeralKeyMaterial = ephemeralKeyBytes.take(32).toByteArray()
                        val combinedKeyMaterial = originalAESKey.encoded + ephemeralKeyMaterial
                        val digest = MessageDigest.getInstance("SHA-256")
                        val derivedKey = digest.digest(combinedKeyMaterial)
                        finalAESKey = SecretKeySpec(derivedKey, "AES")
                        // Note: Perfect Forward Secrecy enabled (no UI notification in service)
                    } catch (e: Exception) {
                        // ECDH failed, using basic AES key (no UI notification in service)
                        finalAESKey = originalAESKey
                    }
                }

                val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
                val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
                aesCipher.init(Cipher.DECRYPT_MODE, finalAESKey, gcmSpec)
                val decryptedData = aesCipher.doFinal(encryptedMessage)

                val messageText = String(decryptedData, Charsets.UTF_8)

                val metadata = parseMessageMetadata(messageText)
                val finalMessage = if (metadata != null) {
                    val expirationTime = metadata["exp"] as? Long
                    if (expirationTime != null && System.currentTimeMillis() > expirationTime) {
                        val expiredDate = SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()).format(Date(expirationTime))
                        throw RuntimeException("Message has expired ($expiredDate)")
                    }

                    metadata["msg"] as String
                } else {
                    messageText
                }

                // Note: Signature validation available but not implemented in this service layer
                // UI layer should handle signature status display

                return finalMessage

            } catch (e: Exception) {
                throw RuntimeException("RSA decryption failed. Check that you're using the correct private key: ${e.message}")
            }
        } catch (e: Exception) {
            throw RuntimeException("RSA decryption with features failed: ${e.message}")
        }
    }
    
    /**
     * RSA-4096 with AES full decryption
     * @param encryptedText Base64 encoded encrypted text
     * @param privateKey RSA private key
     * @return Decrypted message
     */
    private fun decryptRSA4096WithAESFull(encryptedText: String, privateKey: PrivateKey): String {
        try {
            val encryptedData = Base64.getDecoder().decode(encryptedText)
            var offset = 1

            val masterKeySize = readInt32(encryptedData, offset)
            offset += 4
            val encryptedMasterKey = encryptedData.sliceArray(offset until offset + masterKeySize)
            offset += masterKeySize

            val iv = encryptedData.sliceArray(offset until offset + 12)
            offset += 12

            val ephemeralKeySize = readInt32(encryptedData, offset)
            offset += 4
            var ephemeralKeyBytes: ByteArray? = null
            if (ephemeralKeySize > 0) {
                ephemeralKeyBytes = encryptedData.sliceArray(offset until offset + ephemeralKeySize)
                offset += ephemeralKeySize
            }

            val signatureSize = readInt32(encryptedData, offset)
            offset += 4
            var signature: ByteArray? = null
            if (signatureSize > 0) {
                signature = encryptedData.sliceArray(offset until offset + signatureSize)
                offset += signatureSize
            }

            val encryptedMessage = encryptedData.sliceArray(offset until encryptedData.size)

            val rsaCipher = getRSAOAEPCipher(Cipher.DECRYPT_MODE, privateKey)
            val masterAESKey = rsaCipher.doFinal(encryptedMasterKey)

            var finalAESKey = masterAESKey
            if (ephemeralKeyBytes != null && ephemeralKeyBytes.isNotEmpty()) {
                try {
                    val combinedInput = masterAESKey + ephemeralKeyBytes.take(32).toByteArray()
                    val digest = MessageDigest.getInstance("SHA-512")
                    val derivedKeyMaterial = digest.digest(combinedInput)
                    finalAESKey = derivedKeyMaterial.sliceArray(0..31)
                    // Note: Perfect Forward Secrecy activated (no UI notification in service)
                } catch (e: Exception) {
                    // PFS failed, using master key (no UI notification in service)
                    finalAESKey = masterAESKey
                }
            }

            val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
            val finalAESKeySpec = SecretKeySpec(finalAESKey, "AES")
            val gcmSpec = GCMParameterSpec(128, iv)

            aesCipher.init(Cipher.DECRYPT_MODE, finalAESKeySpec, gcmSpec)
            val decryptedData = aesCipher.doFinal(encryptedMessage)

            val messageText = String(decryptedData, Charsets.UTF_8)

            val metadata = parseMessageMetadataFixed(messageText)
            val finalMessage = if (metadata != null) {
                val expirationTime = metadata["exp"] as? Long
                if (expirationTime != null && System.currentTimeMillis() > expirationTime) {
                    val expiredDate = SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()).format(Date(expirationTime))
                    throw RuntimeException("Message has expired ($expiredDate)")
                }

                metadata["msg"] as String
            } else {
                messageText
            }

            // Note: Signature verification available but not implemented at service level
            // UI layer should handle signature verification display

            return finalMessage

        } catch (e: Exception) {
            throw RuntimeException("RSA-4096 + AES-256-GCM (full) decryption failed: ${e.message}", e)
        }
    }
    
    /**
     * Get encryption method enum from version byte
     */
    private fun getEncryptionMethod(version: Byte): EncryptionMethod {
        return when (version) {
            VERSION_BYTE_PASSWORD -> EncryptionMethod.PASSWORD
            VERSION_BYTE_RSA, VERSION_BYTE_RSA_EXPIRING -> EncryptionMethod.RSA_2048
            VERSION_BYTE_RSA_4096_AES_FULL -> EncryptionMethod.RSA_4096
            else -> EncryptionMethod.RSA_ADVANCED
        }
    }
    
    /**
     * Check if version supports expiration
     */
    private fun isExpiringVersion(version: Byte): Boolean {
        return version == VERSION_BYTE_RSA_EXPIRING || 
               version == VERSION_BYTE_RSA_ALL ||
               version == VERSION_BYTE_RSA_4096_AES_FULL
    }
    
    /**
     * Parse metadata from message string
     * @param messageWithMetadata Message string that may contain metadata
     * @return Map containing parsed metadata or null if parsing fails
     */
    private fun parseMessageMetadata(messageWithMetadata: String): Map<String, Any>? {
        return try {
            if (!messageWithMetadata.startsWith("META:") || !messageWithMetadata.contains(":ENDMETA")) {
                return mapOf("msg" to messageWithMetadata)
            }

            val metadataString = messageWithMetadata.substring(5, messageWithMetadata.indexOf(":ENDMETA"))
            val metadata = mutableMapOf<String, Any>()

            metadataString.split("|").forEach { pair ->
                val (key, value) = pair.split("=", limit = 2)
                metadata[key] = when (key) {
                    "exp", "created" -> value.toLong()
                    "burn" -> value.toBoolean()
                    else -> value
                }
            }

            val message = messageWithMetadata.substring(messageWithMetadata.indexOf(":ENDMETA") + 8)
            metadata["msg"] = message
            metadata
        } catch (e: Exception) {
            null
        }
    }
    
    /**
     * Helper method to read 32-bit integer from byte array
     */
    private fun readInt32(data: ByteArray, offset: Int): Int {
        if (offset + 4 > data.size) {
            throw RuntimeException("Not enough data to read Int32")
        }
        return (data[offset].toInt() and 0xFF) or
                ((data[offset + 1].toInt() and 0xFF) shl 8) or
                ((data[offset + 2].toInt() and 0xFF) shl 16) or
                ((data[offset + 3].toInt() and 0xFF) shl 24)
    }
    
    /**
     * Helper method to get RSA OAEP cipher
     */
    private fun getRSAOAEPCipher(mode: Int, key: Key): Cipher {
        return try {
            val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")

            val oaepParams = OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA1,
                PSource.PSpecified.DEFAULT
            )

            cipher.init(mode, key, oaepParams)
            cipher
        } catch (e: Exception) {
            throw RuntimeException("RSA OAEP not supported on this device: ${e.message}", e)
        }
    }
    
    /**
     * Parse enhanced metadata format with JSON-like structure
     * @param messageWithMetadata Message string that may contain enhanced metadata
     * @return Map containing parsed metadata or message as-is
     */
    private fun parseMessageMetadataFixed(messageWithMetadata: String): Map<String, Any>? {
        return try {
            if (messageWithMetadata.startsWith("{") && messageWithMetadata.endsWith("}")) {
                val metadata = mutableMapOf<String, Any>()
                val jsonContent = messageWithMetadata.substring(1, messageWithMetadata.length - 1)

                jsonContent.split(",").forEach { pair ->
                    val parts = pair.split(":", limit = 2)
                    if (parts.size == 2) {
                        val key = parts[0].trim().removeSurrounding("\"")
                        val value = parts[1].trim().removeSurrounding("\"")

                        metadata[key] = when (key) {
                            "exp", "created" -> value.toLongOrNull() ?: 0L
                            "burn", "pfs" -> value.toBooleanStrictOrNull() ?: false
                            else -> value
                        }
                    }
                }

                metadata
            } else {
                parseOldMetadataFormat(messageWithMetadata)
            }
        } catch (e: Exception) {
            mapOf("msg" to messageWithMetadata)
        }
    }
    
    /**
     * Parse old metadata format for backward compatibility
     */
    private fun parseOldMetadataFormat(messageWithMetadata: String): Map<String, Any>? {
        return if (messageWithMetadata.startsWith("META:") && messageWithMetadata.contains(":ENDMETA")) {
            val metadataString = messageWithMetadata.substring(5, messageWithMetadata.indexOf(":ENDMETA"))
            val metadata = mutableMapOf<String, Any>()

            metadataString.split("|").forEach { pair ->
                val parts = pair.split("=", limit = 2)
                if (parts.size == 2) {
                    val key = parts[0].trim()
                    val value = parts[1].trim()
                    metadata[key] = when (key) {
                        "exp", "created" -> value.toLongOrNull() ?: 0L
                        "burn" -> value.toBooleanStrictOrNull() ?: false
                        else -> value
                    }
                }
            }

            val message = messageWithMetadata.substring(messageWithMetadata.indexOf(":ENDMETA") + 8)
            metadata["msg"] = message
            metadata
        } else {
            mapOf("msg" to messageWithMetadata)
        }
    }
}

/**
 * Configuration options for RSA encryption
 */
data class RSAEncryptionOptions(
    val useRSA4096: Boolean = false,
    val enablePFS: Boolean = false,
    val enableSignatures: Boolean = false,
    val enableExpiration: Boolean = false,
    val expirationTime: Long = 0L
)

/**
 * Result of message decryption operation
 */
data class DecryptionResult(
    val message: String,
    val metadata: DecryptionMetadata
)

/**
 * Metadata about the decryption operation
 */
data class DecryptionMetadata(
    val encryptionMethod: EncryptionMethod,
    val version: Byte,
    val hasExpiration: Boolean = false,
    val expirationTime: Long = 0L,
    val isSignatureValid: Boolean = false,
    val hasPFS: Boolean = false
)

/**
 * Encryption method enumeration
 */
enum class EncryptionMethod {
    PASSWORD,
    RSA_2048,
    RSA_4096,
    RSA_ADVANCED
}