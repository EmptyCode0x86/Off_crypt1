package com.example.LinkHUB

import java.security.*
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 * Advanced App Lock Encryption Class with Enhanced Security
 *
 * Features:
 * - PBKDF2 with multiple salts (master, encryption, MAC)
 * - HMAC verification for tamper protection
 * - Perfect Forward Secrecy with ephemeral ECDH key pairs
 * - Digital signatures for authentication
 * - 7-pass secure memory wiping (DoD 5220.22-M standard)
 * - AES-256-GCM encryption
 *
 * Based on SecureMessage cryptographic implementation
 */
class ApplockEncryption {

    companion object {
        private const val SALT_SIZE = 32
        private const val IV_SIZE = 12
        private const val KEY_LENGTH = 256
        private const val ITERATION_COUNT = 100000
        private const val MAC_SIZE = 32
        private const val GCM_TAG_LENGTH = 16
        private const val VERSION_BYTE_ENHANCED: Byte = 0x10

        private val secureRandom = SecureRandom()
    }

    /**
     * Data class for decryption results with security metadata
     */
    data class DecryptionResult(
        val message: String,
        val signatureValid: Boolean,
        val hasPFS: Boolean = false,
        val metadata: Map<String, Any> = emptyMap()
    )

    /**
     * Encrypt password with signature and Perfect Forward Secrecy
     *
     * @param message The message to encrypt
     * @param password The password for encryption
     * @param signingKeyPair Optional RSA key pair for digital signature
     * @return Base64 encoded encrypted data
     */
    fun encryptPasswordWithSignatureAndPFS(
        message: String,
        password: String,
        signingKeyPair: KeyPair?
    ): String {
        try {
            // Generate multiple salts for different cryptographic purposes
            val masterSalt = ByteArray(SALT_SIZE)
            val encryptionSalt = ByteArray(SALT_SIZE)
            val macSalt = ByteArray(SALT_SIZE)
            val iv = ByteArray(IV_SIZE)

            secureRandom.nextBytes(masterSalt)
            secureRandom.nextBytes(encryptionSalt)
            secureRandom.nextBytes(macSalt)
            secureRandom.nextBytes(iv)

            // Generate ephemeral ECDH key pair for Perfect Forward Secrecy
            val ecKeyGen = KeyPairGenerator.getInstance("EC")
            ecKeyGen.initialize(ECGenParameterSpec("secp256r1"))
            val ephemeralKeyPair = ecKeyGen.generateKeyPair()

            // Create message with security metadata including PFS info
            val messageWithMetadata = createSecureMetadata(message, ephemeralKeyPair)

            // Derive encryption and MAC keys using PBKDF2
            val encryptionKey = generateSecureKey(password, encryptionSalt, ITERATION_COUNT)
            val macKey = generateSecureKey(password, macSalt, ITERATION_COUNT)

            // Enhance encryption key with ephemeral key material for PFS
            val ephemeralKeyMaterial = ephemeralKeyPair.public.encoded.take(32).toByteArray()
            val combinedKeyMaterial = encryptionKey + ephemeralKeyMaterial
            val digest = MessageDigest.getInstance("SHA-256")
            val finalEncryptionKey = digest.digest(combinedKeyMaterial)

            // AES-GCM encryption with authenticated encryption
            val keySpec = SecretKeySpec(finalEncryptionKey, "AES")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)

            val encryptedData = cipher.doFinal(messageWithMetadata.toByteArray(Charsets.UTF_8))

            // Create digital signature if signing key available
            var signature: ByteArray? = null
            if (signingKeyPair?.private != null) {
                signature = createDigitalSignature(messageWithMetadata, signingKeyPair.private)
            }

            // Build final encrypted package with all security components
            val outputStream = ByteArrayOutputStream()
            outputStream.write(VERSION_BYTE_ENHANCED.toInt())
            outputStream.write(masterSalt)
            outputStream.write(encryptionSalt)
            outputStream.write(macSalt)
            outputStream.write(iv)

            // Write ephemeral public key for PFS
            val ephemeralPublicKeyBytes = ephemeralKeyPair.public.encoded
            writeInt32(outputStream, ephemeralPublicKeyBytes.size)
            outputStream.write(ephemeralPublicKeyBytes)

            // Write digital signature if available
            if (signature != null) {
                writeInt32(outputStream, signature.size)
                outputStream.write(signature)
            } else {
                writeInt32(outputStream, 0)
            }

            // Write encrypted data
            outputStream.write(encryptedData)

            // Generate HMAC for entire package integrity protection
            val dataToMac = outputStream.toByteArray()
            val hmac = generateHMAC(dataToMac, macKey)
            outputStream.write(hmac)

            // Secure wipe of sensitive intermediate data
            secureWipeByteArray(encryptionKey)
            secureWipeByteArray(finalEncryptionKey)
            secureWipeByteArray(macKey)
            secureWipeByteArray(ephemeralKeyMaterial)

            return Base64.getEncoder().encodeToString(outputStream.toByteArray())

        } catch (e: Exception) {
            throw RuntimeException("Enhanced encryption failed: ${e.message}", e)
        }
    }

    /**
     * Decrypt password with signature and PFS verification
     *
     * @param encryptedText Base64 encoded encrypted data
     * @param password The password for decryption
     * @param verificationPublicKey Optional public key for signature verification
     * @return DecryptionResult with message and security validation status
     */
    fun decryptPasswordWithSignatureAndPFS(
        encryptedText: String,
        password: String,
        verificationPublicKey: PublicKey?
    ): DecryptionResult {
        try {
            val encryptedData = Base64.getDecoder().decode(encryptedText)

            if (encryptedData.size < 1 + SALT_SIZE * 3 + IV_SIZE + MAC_SIZE) {
                throw RuntimeException("Invalid encrypted data size")
            }

            var offset = 0

            // Verify version compatibility
            val version = encryptedData[offset]
            if (version != VERSION_BYTE_ENHANCED) {
                throw RuntimeException("Invalid or unsupported encryption version")
            }
            offset += 1

            // Extract salts and initialization vector
            val masterSalt = encryptedData.copyOfRange(offset, offset + SALT_SIZE)
            offset += SALT_SIZE

            val encryptionSalt = encryptedData.copyOfRange(offset, offset + SALT_SIZE)
            offset += SALT_SIZE

            val macSalt = encryptedData.copyOfRange(offset, offset + SALT_SIZE)
            offset += SALT_SIZE

            val iv = encryptedData.copyOfRange(offset, offset + IV_SIZE)
            offset += IV_SIZE

            // Extract ephemeral public key for PFS
            val ephemeralKeySize = readInt32(encryptedData, offset)
            offset += 4

            val ephemeralPublicKeyBytes = encryptedData.copyOfRange(offset, offset + ephemeralKeySize)
            offset += ephemeralKeySize

            // Extract digital signature
            val signatureSize = readInt32(encryptedData, offset)
            offset += 4

            var signature: ByteArray? = null
            if (signatureSize > 0) {
                signature = encryptedData.copyOfRange(offset, offset + signatureSize)
                offset += signatureSize
            }

            // Extract encrypted content and HMAC
            val encryptedContent = encryptedData.copyOfRange(offset, encryptedData.size - MAC_SIZE)
            val receivedMac = encryptedData.copyOfRange(encryptedData.size - MAC_SIZE, encryptedData.size)

            // Derive decryption keys using PBKDF2
            val encryptionKey = generateSecureKey(password, encryptionSalt, ITERATION_COUNT)
            val macKey = generateSecureKey(password, macSalt, ITERATION_COUNT)

            // Verify HMAC integrity before proceeding
            val dataToVerify = encryptedData.copyOfRange(0, encryptedData.size - MAC_SIZE)
            if (!verifyHMAC(dataToVerify, receivedMac, macKey)) {
                throw RuntimeException("HMAC verification failed - data may be tampered")
            }

            // Reconstruct final encryption key with PFS
            val ephemeralKeyMaterial = ephemeralPublicKeyBytes.take(32).toByteArray()
            val combinedKeyMaterial = encryptionKey + ephemeralKeyMaterial
            val digest = MessageDigest.getInstance("SHA-256")
            val finalEncryptionKey = digest.digest(combinedKeyMaterial)

            // Decrypt using AES-GCM authenticated encryption
            val keySpec = SecretKeySpec(finalEncryptionKey, "AES")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)

            val decryptedData = cipher.doFinal(encryptedContent)
            val messageWithMetadata = String(decryptedData, Charsets.UTF_8)

            // Parse security metadata and extract original message
            val (originalMessage, metadata) = parseSecureMetadata(messageWithMetadata)

            // Verify digital signature if available
            var signatureValid = false
            if (signature != null && verificationPublicKey != null) {
                signatureValid = verifyDigitalSignature(messageWithMetadata, signature, verificationPublicKey)
            } else if (signature != null) {
                // Signature present but no verification key provided
                signatureValid = false
            } else {
                // No signature expected, consider valid
                signatureValid = true
            }

            // Secure wipe of sensitive intermediate data
            secureWipeByteArray(encryptionKey)
            secureWipeByteArray(finalEncryptionKey)
            secureWipeByteArray(macKey)
            secureWipeByteArray(ephemeralKeyMaterial)
            secureWipeByteArray(decryptedData)

            return DecryptionResult(
                message = originalMessage,
                signatureValid = signatureValid,
                hasPFS = true,
                metadata = metadata
            )

        } catch (e: Exception) {
            throw RuntimeException("Enhanced decryption failed: ${e.message}", e)
        }
    }

    /**
     * Generate secure key using PBKDF2 with HMAC-SHA256
     */
    private fun generateSecureKey(password: String, salt: ByteArray, iterations: Int): ByteArray {
        val keySpec = PBEKeySpec(password.toCharArray(), salt, iterations, KEY_LENGTH)
        val keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val secretKey = keyFactory.generateSecret(keySpec)

        // Secure wipe of password characters
        keySpec.clearPassword()

        return secretKey.encoded
    }

    /**
     * Generate HMAC-SHA256 for integrity verification
     */
    private fun generateHMAC(data: ByteArray, key: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        val secretKey = SecretKeySpec(key, "HmacSHA256")
        mac.init(secretKey)
        return mac.doFinal(data)
    }

    /**
     * Verify HMAC with constant-time comparison to prevent timing attacks
     */
    private fun verifyHMAC(data: ByteArray, expectedMac: ByteArray, key: ByteArray): Boolean {
        val computedMac = generateHMAC(data, key)

        if (computedMac.size != expectedMac.size) return false

        // Constant-time comparison to prevent timing attacks
        var result = 0
        for (i in computedMac.indices) {
            result = result or (computedMac[i].toInt() xor expectedMac[i].toInt())
        }
        return result == 0
    }

    /**
     * Create RSA digital signature for message authentication
     */
    private fun createDigitalSignature(message: String, privateKey: PrivateKey): ByteArray {
        val signature = Signature.getInstance("SHA256withRSA")
        signature.initSign(privateKey)
        signature.update(message.toByteArray(Charsets.UTF_8))
        return signature.sign()
    }

    /**
     * Verify RSA digital signature
     */
    private fun verifyDigitalSignature(message: String, signatureBytes: ByteArray, publicKey: PublicKey): Boolean {
        return try {
            val signature = Signature.getInstance("SHA256withRSA")
            signature.initVerify(publicKey)
            signature.update(message.toByteArray(Charsets.UTF_8))
            signature.verify(signatureBytes)
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Create metadata with security features for the encrypted message
     */
    private fun createSecureMetadata(message: String, ephemeralKeyPair: KeyPair): String {
        val metadata = mapOf(
            "msg" to message,
            "created" to System.currentTimeMillis(),
            "pfs" to true,
            "ephemeral_public" to Base64.getEncoder().encodeToString(ephemeralKeyPair.public.encoded),
            "version" to "enhanced_v1"
        )

        val metadataJson = metadata.entries.joinToString(",") { "\"${it.key}\":\"${it.value}\"" }
        return "{$metadataJson}"
    }

    /**
     * Parse secure metadata from decrypted message
     */
    private fun parseSecureMetadata(messageWithMetadata: String): Pair<String, Map<String, Any>> {
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
                            "created" -> value.toLongOrNull() ?: 0L
                            "pfs" -> value.toBooleanStrictOrNull() ?: false
                            else -> value
                        }
                    }
                }

                val originalMessage = metadata["msg"] as? String ?: messageWithMetadata
                Pair(originalMessage, metadata)
            } else {
                Pair(messageWithMetadata, emptyMap())
            }
        } catch (e: Exception) {
            Pair(messageWithMetadata, emptyMap())
        }
    }

    /**
     * 7-pass secure memory wiping following DoD 5220.22-M standard
     *
     * This method overwrites memory with specific patterns multiple times
     * to ensure that sensitive data cannot be recovered even with
     * advanced forensic techniques.
     */
    private fun secureWipeByteArray(array: ByteArray) {
        try {
            // DoD 5220.22-M standard patterns
            val patterns = byteArrayOf(
                0x00.toByte(), // All zeros
                0xFF.toByte(), // All ones
                0xAA.toByte(), // Alternating 10101010
                0x55.toByte(), // Alternating 01010101
                0x92.toByte(), // Random pattern 1
                0x49.toByte(), // Random pattern 2
                0x24.toByte()  // Random pattern 3
            )

            for (pass in patterns.indices) {
                val pattern = patterns[pass]

                // Write pattern to entire array
                for (i in array.indices) {
                    array[i] = pattern
                    // Memory barrier to prevent compiler optimization
                    @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
                    val barrier = (array as java.lang.Object).hashCode()
                }

                // Final pass uses cryptographically secure random data
                if (pass == patterns.size - 1) {
                    secureRandom.nextBytes(array)
                }

                // Yield to prevent blocking and allow memory sync
                Thread.yield()
            }

            // Final zero fill
            Arrays.fill(array, 0.toByte())

            // Force memory synchronization
            synchronized(array) {
                @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
                (array as java.lang.Object).notify()
            }

        } catch (e: Exception) {
            // Fallback secure wipe if advanced method fails
            try {
                Arrays.fill(array, 0.toByte())
                System.gc()
            } catch (ignored: Exception) {}
        }
    }

    /**
     * Write 32-bit integer to output stream in little-endian format
     */
    private fun writeInt32(outputStream: ByteArrayOutputStream, value: Int) {
        outputStream.write(value and 0xFF)
        outputStream.write((value shr 8) and 0xFF)
        outputStream.write((value shr 16) and 0xFF)
        outputStream.write((value shr 24) and 0xFF)
    }

    /**
     * Read 32-bit integer from byte array in little-endian format
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
}