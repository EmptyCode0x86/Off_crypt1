package com.example.OffCrypt1

import android.content.Context
import android.util.Base64
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

/**
 * RSA encryption implementation for RSA-2048 and RSA-4096
 * PFS POISTETTU: ei ECDH/HKDF-derivointia
 * Handles RSA operations with OAEP padding, signatures, and expiration
 */
class RSACrypto(private val context: Context) {

    private val secureRandom = SecureRandom.getInstanceStrong()
    private val keyManager = KeyManager(context)

    companion object {
        private const val AES_KEY_SIZE = 256
        private const val IV_SIZE = 12
        private const val GCM_TAG_LENGTH = 16
    }
//Begin 1


    /**
     * Encrypts message with RSA including signatures and expiration
     */
    fun encryptRSAWithAllFeatures(
        message: String,
        recipientPublicKey: PublicKey,
        enablePFS: Boolean,            // ei käytetä tässä toteutuksessa
        enableSignatures: Boolean,
        enableExpiration: Boolean,
        expirationTime: Long,
        userKeyPair: KeyPair? = null
    ): String {
        try {
            return encryptRSAWithAllFeaturesImpl(
                message,
                recipientPublicKey,
                enablePFS,
                enableSignatures,
                enableExpiration,
                expirationTime,
                userKeyPair
            )
        } catch (e: Exception) {
            throw RuntimeException("RSA encryption with all features failed: ${e.message}", e)
        }
    }



    /**
     * Decrypts RSA encrypted message with full feature support
     */
    fun decryptRSAMessage(
        encryptedText: String,
        privateKey: PrivateKey,
        publicKey: PublicKey? = null
    ): String {
        try {
            val encryptedData = Base64.decode(encryptedText, Base64.NO_WRAP)

            if (encryptedData.isEmpty()) {
                throw IllegalArgumentException("Empty encrypted data")
            }

            val versionByte = encryptedData[0]

            return when (versionByte) {
                CryptoConstants.VERSION_BYTE_RSA_ALL -> {
                    decryptRSAWithAllFeatures(encryptedText, privateKey, publicKey)
                }

                else -> {
                    throw IllegalArgumentException("Unsupported RSA version: $versionByte")
                }
            }

        } catch (e: Exception) {
            throw RuntimeException("RSA decryption failed: ${e.message}", e)
        }
    }


    /**
     * Sign data with RSA private key using FIPS 186-4 compliant parameters
     */
    fun signData(data: ByteArray, privateKey: PrivateKey): ByteArray {
        try {
            val signature = Signature.getInstance("SHA256withRSA/PSS")
            val pssSpec = PSSParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                32, // salt length = hash length
                1
            )
            signature.setParameter(pssSpec)
            signature.initSign(privateKey)
            signature.update(data)
            return signature.sign()
        } catch (e: Exception) {
            throw RuntimeException("RSA signing failed: ${e.message}", e)
        }
    }

    /**
     * Verify signature with RSA public key using FIPS 186-4 compliant parameters
     */
    fun verifySignature(data: ByteArray, signatureBytes: ByteArray, publicKey: PublicKey): Boolean {
        return try {
            val signature = Signature.getInstance("SHA256withRSA/PSS")
            val pssSpec = PSSParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                32, // salt length = hash length
                1
            )
            signature.setParameter(pssSpec)
            signature.initVerify(publicKey)
            signature.update(data)
            signature.verify(signatureBytes)
        } catch (e: Exception) {
            android.util.Log.w("RSACrypto", "Signature verification failed: ${e.message}")
            false
        }
    }



    // ===== ADVANCED ENCRYPTION IMPLEMENTATIONS =====


    /**
     * RSA with all advanced features (signatures & expiration)
     */
    private fun encryptRSAWithAllFeaturesImpl(
        plaintext: String,
        recipientPublicKey: PublicKey,
        enablePFS: Boolean,   // ei käytetä
        enableSignatures: Boolean,
        enableExpiration: Boolean,
        expirationTime: Long,
        userKeyPair: KeyPair?
    ): String {
        try {
            // 1. Generate AES key
            val keyGenerator = KeyGenerator.getInstance("AES")
            keyGenerator.init(AES_KEY_SIZE)
            val originalAESKey = keyGenerator.generateKey()
            val finalAESKey = originalAESKey.encoded

            try {
                // 2. Encrypt AES key with RSA
                val rsaCipher = SecurityUtils.getRSAOAEPCipher(true, recipientPublicKey)
                val encryptedAESKey = rsaCipher.doFinal(originalAESKey.encoded)

                // 3. Generate IV
                val iv = SecureCrypto.generateIV()

                // 4. Create message with metadata
                val finalExpirationTime = if (enableExpiration) expirationTime else 0L
                val messageWithMetadata =
                    SecurityUtils.createMessageWithMetadataFixed(plaintext, finalExpirationTime, false)

                // 5. Encrypt message with AES-GCM
                val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
                val finalAESKeySpec = SecretKeySpec(finalAESKey, "AES")
                val gcmSpec = GCMParameterSpec(128, iv)
                aesCipher.init(Cipher.ENCRYPT_MODE, finalAESKeySpec, gcmSpec)
                val encryptedMessage =
                    aesCipher.doFinal(messageWithMetadata.toByteArray(Charsets.UTF_8))

                // 6. Optional signature
                var signature: ByteArray? = null
                if (enableSignatures && userKeyPair?.private != null) {
                    signature = signData(
                        messageWithMetadata.toByteArray(Charsets.UTF_8),
                        userKeyPair.private
                    )
                }

                // 7. Build final data structure
                val outputStream = ByteArrayOutputStream()
                outputStream.write(CryptoConstants.VERSION_BYTE_RSA_ALL.toInt())

                // Write encrypted AES key size and data
                outputStream.write(encryptedAESKey.size and 0xFF)
                outputStream.write((encryptedAESKey.size shr 8) and 0xFF)
                outputStream.write(encryptedAESKey)

                // Write IV
                outputStream.write(iv)

                // Write signature if present
                if (signature != null) {
                    outputStream.write(signature.size and 0xFF)
                    outputStream.write((signature.size shr 8) and 0xFF)
                    outputStream.write(signature)
                } else {
                    outputStream.write(0)
                    outputStream.write(0)
                }

                // Reserved space (unused)
                outputStream.write(0)
                outputStream.write(0)

                // Write encrypted message
                outputStream.write(encryptedMessage)

                return Base64.encodeToString(outputStream.toByteArray(), Base64.NO_WRAP)

            } finally {
                // Pyyhitään vain jos olisi eri viite; tässä samaa puskuria käytetään -> ei erillistä pyyhintää
            }

        } catch (e: Exception) {
            throw RuntimeException("RSA with all features encryption failed: ${e.message}", e)
        }
    }


    /**
     * Decrypt RSA with all features
     */
    private fun decryptRSAWithAllFeatures(
        encryptedText: String,
        privateKey: PrivateKey,
        publicKey: PublicKey?
    ): String {
        try {
            val encryptedData = Base64.decode(encryptedText, Base64.NO_WRAP)
            val buffer = ByteBuffer.wrap(encryptedData)

            // Skip version byte
            buffer.get()

            // Read encrypted AES key
            val encryptedKeySize = (buffer.get().toInt() and 0xFF) or
                    ((buffer.get().toInt() and 0xFF) shl 8)
            val encryptedAESKey = ByteArray(encryptedKeySize)
            buffer.get(encryptedAESKey)

            // Read IV
            val iv = ByteArray(IV_SIZE)
            buffer.get(iv)

            // Read signature (optional)
            val signatureSize = (buffer.get().toInt() and 0xFF) or
                    ((buffer.get().toInt() and 0xFF) shl 8)
            val signature = if (signatureSize > 0) {
                ByteArray(signatureSize).also { buffer.get(it) }
            } else null

            // Read reserved space (unused)
            val reservedSize = (buffer.get().toInt() and 0xFF) or
                    ((buffer.get().toInt() and 0xFF) shl 8)
            if (reservedSize > 0) {
                val skip = ByteArray(reservedSize)
                buffer.get(skip) // skip reserved bytes
            }

            // Read encrypted message
            val encryptedMessage = ByteArray(buffer.remaining())
            buffer.get(encryptedMessage)

            // Decrypt AES key with RSA
            val rsaCipher = SecurityUtils.getRSAOAEPCipher(false, privateKey)
            val originalAESKey = rsaCipher.doFinal(encryptedAESKey)

            try {
                // Decrypt message with AES-GCM
                val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
                val finalAESKeySpec = SecretKeySpec(originalAESKey, "AES")
                val gcmSpec = GCMParameterSpec(128, iv)
                aesCipher.init(Cipher.DECRYPT_MODE, finalAESKeySpec, gcmSpec)

                val decryptedBytes = aesCipher.doFinal(encryptedMessage)
                val messageText = String(decryptedBytes, Charsets.UTF_8)

                // Verify signature if present and public key available
                if (signature != null && publicKey != null) {
                    val verified = verifySignature(
                        messageText.toByteArray(Charsets.UTF_8),
                        signature,
                        publicKey
                    )
                    if (!verified) {
                        throw RuntimeException("Digital signature verification failed")
                    }
                }

                // Parse and return plaintext with expiration handling
                return SecurityUtils.parseMessageMetadataFixed(messageText)?.let { metadata ->
                    SecurityUtils.enforceExpirationAndExtract(metadata)
                } ?: messageText

            } finally {
                // Turvallinen avainten pyyhkiminen
                SecurityUtils.secureWipeByteArray(originalAESKey)
            }

        } catch (e: Exception) {
            throw RuntimeException("RSA all features decryption failed: ${e.message}", e)
        }
    }
}

//End begin 1
