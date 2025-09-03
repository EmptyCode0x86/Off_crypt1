package com.example.OffCrypt1

import java.security.Key
import java.security.KeyPair
import java.security.PrivateKey
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
        // Import centralized constants
        private const val VERSION_BYTE_PASSWORD = CryptoConstants.VERSION_BYTE_PASSWORD
        private const val VERSION_BYTE_RSA = CryptoConstants.VERSION_BYTE_RSA
        private const val VERSION_BYTE_RSA_EXPIRING = CryptoConstants.VERSION_BYTE_RSA_EXPIRING
        private const val VERSION_BYTE_RSA_SIGNED = CryptoConstants.VERSION_BYTE_RSA_SIGNED
        private const val VERSION_BYTE_RSA_PFS = CryptoConstants.VERSION_BYTE_RSA_PFS
        private const val VERSION_BYTE_RSA_SIGNED_PFS = CryptoConstants.VERSION_BYTE_RSA_SIGNED_PFS
        private const val VERSION_BYTE_RSA_ALL = CryptoConstants.VERSION_BYTE_RSA_ALL
        private const val VERSION_BYTE_RSA_4096_AES_FULL =
            CryptoConstants.VERSION_BYTE_RSA_4096_AES_FULL

        private const val VERSION_BYTE_MULTI_SALT = CryptoConstants.VERSION_BYTE_MULTI_SALT

        private const val VERSION_BYTE_BURN_AFTER_READING =
            CryptoConstants.VERSION_BYTE_BURN_AFTER_READING

        private const val VERSION_BYTE_FILE_ENCRYPTED = CryptoConstants.VERSION_BYTE_FILE_ENCRYPTED

        private const val VERSION_BYTE_FILE_MULTI_SALT =
            CryptoConstants.VERSION_BYTE_FILE_MULTI_SALT

        private const val VERSION_BYTE_RSA_ADVANCED = CryptoConstants.VERSION_BYTE_RSA_ADVANCED


        // Cryptographic constants
        private const val IV_SIZE = CryptoConstants.IV_SIZE
        private const val GCM_TAG_LENGTH = CryptoConstants.GCM_TAG_LENGTH
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
    fun encryptWithRSA(
        message: String,
        recipientPublicKey: String,
        options: RSAEncryptionOptions
    ): String {
        if (recipientPublicKey.trim().isEmpty()) {
            throw RuntimeException("Enter recipient's public key!")
        }

        return try {
            val publicKey = cryptoManager.parsePublicKeyFromString(recipientPublicKey.trim())

            cryptoManager.encryptWithRSA(
                message,
                publicKey,
                options.useRSA4096,
                options.enablePFS,          // jätetty parametri ennalleen, ei vaikutusta tässä tiedostossa
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
    fun decryptMessage(
        encryptedMessage: String,
        password: String?,
        keyPair: KeyPair?
    ): DecryptionResult {
        if (encryptedMessage.trim().isEmpty()) {
            throw RuntimeException("Enter encrypted message!")
        }

        val encryptedData = Base64.getDecoder().decode(encryptedMessage.trim())
        val version = encryptedData[0]

        val decryptedMessage = when (version) {
            VERSION_BYTE_MULTI_SALT -> {
                if (password?.trim()?.isEmpty() != false) {
                    throw RuntimeException("Enter password!")
                }
                cryptoManager.decryptWithPassword(encryptedMessage, password)
            }

            VERSION_BYTE_BURN_AFTER_READING -> {
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
                        VERSION_BYTE_RSA_EXPIRING -> decryptRSABasedWithExpiration(
                            encryptedMessage,
                            keyPair.private
                        )

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

            VERSION_BYTE_FILE_ENCRYPTED -> {
                throw RuntimeException("File encryption not supported in message decryption. Use file decryption methods instead.")
            }

            VERSION_BYTE_FILE_MULTI_SALT -> {
                throw RuntimeException("File multi-salt encryption not supported in message decryption. Use file decryption methods instead.")
            }

            VERSION_BYTE_RSA_ADVANCED -> {
                throw RuntimeException("RSA advanced encryption not supported in message decryption. This version is reserved for future use.")
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
    private fun decryptRSABasedWithExpiration(
        encryptedText: String,
        privateKey: PrivateKey
    ): String {
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
                    val expiredDate =
                        SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()).format(
                            Date(expirationTime)
                        )
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
     * RSA decryption with advanced features (signatures, etc.). PFS poistettu:
     * mahdolliset ephemeraaliavaimet ohitetaan eikä niistä johdeta avainta.
     * @param encryptedText Base64 encoded encrypted text
     * @param privateKey RSA private key
     * @param version Version byte indicating features used
     * @return Decrypted message
     */
    private fun decryptRSAWithFeatures(
        encryptedText: String,
        privateKey: PrivateKey,
        version: Byte
    ): String {
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

            // Luetaan ja ohitetaan mahdollinen ephemeraaliavainmateriaali (PFS poistettu)
            if (ephemeralKeySize > 0) {
                if (offset + ephemeralKeySize > encryptedData.size) {
                    throw RuntimeException("Corrupted data: ephemeral key missing")
                }
                // skip bytes
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

                // PFS poistettu: käytetään aina alkuperäistä AES-avainta
                val finalAESKey = originalAESKey

                val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
                val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
                aesCipher.init(Cipher.DECRYPT_MODE, finalAESKey, gcmSpec)
                val decryptedData = aesCipher.doFinal(encryptedMessage)

                val messageText = String(decryptedData, Charsets.UTF_8)

                val metadata = parseMessageMetadata(messageText)
                val finalMessage = if (metadata != null) {
                    val expirationTime = metadata["exp"] as? Long
                    if (expirationTime != null && System.currentTimeMillis() > expirationTime) {
                        val expiredDate =
                            SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()).format(
                                Date(expirationTime)
                            )
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
     * RSA-4096 with AES full decryption. PFS poistettu:
     * mahdolliset ephemeraaliavaimet luetaan ja ohitetaan.
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
            if (ephemeralKeySize > 0) {
                // ohitetaan ephemeraaliavain (PFS poistettu)
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

            // PFS poistettu: käytetään aina master-avainta sellaisenaan
            val finalAESKey = masterAESKey

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
                    val expiredDate =
                        SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()).format(
                            Date(expirationTime)
                        )
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
            throw RuntimeException(
                "RSA-4096 + AES-256-GCM (full) decryption failed: ${e.message}",
                e
            )
        }
    }

    /**
     * Get encryption method enum from version byte
     */
    private fun getEncryptionMethod(version: Byte): EncryptionMethod {
        return when (version) {
            VERSION_BYTE_PASSWORD -> EncryptionMethod.PASSWORD
            VERSION_BYTE_MULTI_SALT -> EncryptionMethod.PASSWORD
            VERSION_BYTE_BURN_AFTER_READING -> EncryptionMethod.PASSWORD
            VERSION_BYTE_RSA, VERSION_BYTE_RSA_EXPIRING -> EncryptionMethod.RSA_2048
            VERSION_BYTE_RSA_4096_AES_FULL -> EncryptionMethod.RSA_4096
            VERSION_BYTE_FILE_ENCRYPTED, VERSION_BYTE_FILE_MULTI_SALT -> EncryptionMethod.RSA_ADVANCED
            VERSION_BYTE_RSA_ADVANCED -> EncryptionMethod.RSA_ADVANCED
            else -> EncryptionMethod.RSA_ADVANCED
        }
    }

    /**
     * Check if version supports expiration
     */
    private fun isExpiringVersion(version: Byte): Boolean {
        return version == VERSION_BYTE_RSA_EXPIRING ||
                version == VERSION_BYTE_RSA_ALL ||
                version == VERSION_BYTE_RSA_4096_AES_FULL ||
                version == VERSION_BYTE_BURN_AFTER_READING
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

            val metadataString =
                messageWithMetadata.substring(5, messageWithMetadata.indexOf(":ENDMETA"))
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
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        val params = OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            PSource.PSpecified.DEFAULT
        )
        cipher.init(mode, key, params)
        return cipher
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
            val metadataString =
                messageWithMetadata.substring(5, messageWithMetadata.indexOf(":ENDMETA"))
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
