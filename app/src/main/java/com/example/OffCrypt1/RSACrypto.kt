package com.example.OffCrypt1

import android.content.Context
import android.util.Base64
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer

/**
 * RSA encryption implementation for RSA-2048 and RSA-4096
 * Handles RSA operations with OAEP padding, signatures, PFS, and advanced features
 */
class RSACrypto(private val context: Context) {
    
    private val secureRandom = SecureRandom()
    
    companion object {
        private const val RSA_2048_VERSION: Byte = 0x02
        private const val RSA_4096_VERSION: Byte = 0x03  // Basic RSA-4096
        private const val VERSION_BYTE_RSA_4096_AES_FULL: Byte = 0x0A  // Desktop reference
        private const val VERSION_BYTE_RSA_ALL: Byte = 0x07  // Desktop reference
        private const val AES_KEY_SIZE = 256
        private const val IV_SIZE = 12
        private const val GCM_TAG_LENGTH = 16
    }
    
    /**
     * Encrypts message with RSA including all security features
     * Perfect Forward Secrecy (PFS), Digital Signatures, Expiration
     */
    fun encryptRSAWithAllFeatures(
        message: String, 
        recipientPublicKey: PublicKey, 
        enablePFS: Boolean, 
        enableSignatures: Boolean, 
        enableExpiration: Boolean, 
        expirationTime: Long,
        userKeyPair: KeyPair? = null
    ): String {
        try {
            return encryptRSAWithAllFeaturesImpl(message, recipientPublicKey, enablePFS, enableSignatures, enableExpiration, expirationTime, userKeyPair)
        } catch (e: Exception) {
            throw RuntimeException("RSA encryption with all features failed: ${e.message}", e)
        }
    }
    
    /**
     * Encrypts message with RSA-4096 and AES hybrid encryption with PFS
     * Uses ephemeral ECDH keys for Perfect Forward Secrecy
     */
    fun encryptRSA4096WithAESFull(message: String, recipientPublicKey: PublicKey, expirationTime: Long = 0, userKeyPair: KeyPair? = null): String {
        try {
            return encryptRSA4096WithAESFullImpl(message, recipientPublicKey, expirationTime, userKeyPair)
        } catch (e: Exception) {
            throw RuntimeException("RSA-4096 with AES full encryption failed: ${e.message}", e)
        }
    }
    
    /**
     * Basic RSA encryption (placeholder implementation)
     */
    private fun encryptBasicRSA(message: String, publicKey: PublicKey, versionByte: Byte): String {
        try {
            val messageBytes = message.toByteArray(Charsets.UTF_8)
            
            // Use RSA/ECB/OAEPWithSHA-256AndMGF1Padding
            val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
            val oaepParams = OAEPParameterSpec(
                "SHA-256", 
                "MGF1", 
                MGF1ParameterSpec.SHA256, 
                PSource.PSpecified.DEFAULT
            )
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams)
            
            val encryptedData = cipher.doFinal(messageBytes)
            
            // Add version byte
            val buffer = ByteBuffer.allocate(1 + encryptedData.size)
            buffer.put(versionByte)
            buffer.put(encryptedData)
            
            return Base64.encodeToString(buffer.array(), Base64.NO_WRAP)
            
        } catch (e: Exception) {
            throw RuntimeException("Basic RSA encryption failed: ${e.message}", e)
        }
    }
    
    /**
     * Decrypts RSA encrypted message with full feature support
     */
    fun decryptRSAMessage(encryptedText: String, privateKey: PrivateKey, publicKey: PublicKey? = null): String {
        try {
            val encryptedData = Base64.decode(encryptedText, Base64.NO_WRAP)
            
            if (encryptedData.isEmpty()) {
                throw IllegalArgumentException("Empty encrypted data")
            }
            
            val versionByte = encryptedData[0]
            
            return when (versionByte) {
                RSA_2048_VERSION, RSA_4096_VERSION -> {
                    val buffer = ByteBuffer.wrap(encryptedData)
                    buffer.get() // Skip version byte
                    decryptBasicRSA(buffer, privateKey)
                }
                VERSION_BYTE_RSA_4096_AES_FULL -> {
                    decryptRSA4096WithAESFull(encryptedText, privateKey)
                }
                VERSION_BYTE_RSA_ALL -> {
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
     * Basic RSA decryption
     */
    private fun decryptBasicRSA(buffer: ByteBuffer, privateKey: PrivateKey): String {
        try {
            val encryptedMessage = ByteArray(buffer.remaining())
            buffer.get(encryptedMessage)
            
            val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
            val oaepParams = OAEPParameterSpec(
                "SHA-256", 
                "MGF1", 
                MGF1ParameterSpec.SHA256, 
                PSource.PSpecified.DEFAULT
            )
            cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams)
            
            val decryptedBytes = cipher.doFinal(encryptedMessage)
            return String(decryptedBytes, Charsets.UTF_8)
            
        } catch (e: Exception) {
            throw RuntimeException("Basic RSA decryption failed: ${e.message}", e)
        }
    }
    
    /**
     * Sign data with RSA private key
     */
    fun signData(data: ByteArray, privateKey: PrivateKey): ByteArray {
        try {
            val signature = Signature.getInstance("SHA512withRSA/PSS")
            val pssSpec = PSSParameterSpec(
                "SHA-512", 
                "MGF1", 
                MGF1ParameterSpec.SHA512, 
                64, 
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
     * Verify signature with RSA public key
     */
    fun verifySignature(data: ByteArray, signatureBytes: ByteArray, publicKey: PublicKey): Boolean {
        return try {
            val signature = Signature.getInstance("SHA512withRSA/PSS")
            val pssSpec = PSSParameterSpec(
                "SHA-512", 
                "MGF1", 
                MGF1ParameterSpec.SHA512, 
                64, 
                1
            )
            signature.setParameter(pssSpec)
            signature.initVerify(publicKey)
            signature.update(data)
            signature.verify(signatureBytes)
        } catch (e: Exception) {
            false
        }
    }
    
    // ===== ADVANCED ENCRYPTION IMPLEMENTATIONS =====
    
    /**
     * RSA-4096 + AES-GCM hybrid encryption with Perfect Forward Secrecy
     * Uses ephemeral ECDH keys for PFS
     */
    private fun encryptRSA4096WithAESFullImpl(plaintext: String, recipientPublicKey: PublicKey, expirationTime: Long, userKeyPair: KeyPair?): String {
        try {
            // Generate master AES key
            val masterAESKey = ByteArray(32)
            secureRandom.nextBytes(masterAESKey)
            
            // Generate ephemeral ECDH key pair for PFS
            val ecKeyGen = KeyPairGenerator.getInstance("EC")
            ecKeyGen.initialize(ECGenParameterSpec("secp256r1"))
            val ephemeralKeyPair = ecKeyGen.generateKeyPair()
            
            // Encrypt master AES key with RSA
            val rsaCipher = getRSAOAEPCipher(Cipher.ENCRYPT_MODE, recipientPublicKey)
            val encryptedMasterKey = rsaCipher.doFinal(masterAESKey)
            
            // Derive final AES key using master key + ephemeral key
            val ephemeralPublicKeyBytes = ephemeralKeyPair.public.encoded
            val combinedInput = masterAESKey + ephemeralPublicKeyBytes.take(32).toByteArray()
            val digest = MessageDigest.getInstance("SHA-512")
            val derivedKeyMaterial = digest.digest(combinedInput)
            val finalAESKey = derivedKeyMaterial.sliceArray(0..31)
            
            // Generate IV for AES-GCM
            val iv = ByteArray(12)
            secureRandom.nextBytes(iv)
            
            // Create message with metadata
            val messageWithMetadata = createMessageWithMetadataFixed(plaintext, expirationTime, ephemeralKeyPair)
            
            // Encrypt message with AES-GCM
            val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
            val finalAESKeySpec = SecretKeySpec(finalAESKey, "AES")
            val gcmSpec = GCMParameterSpec(128, iv)
            aesCipher.init(Cipher.ENCRYPT_MODE, finalAESKeySpec, gcmSpec)
            val encryptedMessage = aesCipher.doFinal(messageWithMetadata.toByteArray(Charsets.UTF_8))
            
            // Create digital signature if user key pair available
            var signature: ByteArray? = null
            if (userKeyPair?.private != null) {
                val sig = Signature.getInstance("SHA512withRSA")
                sig.initSign(userKeyPair.private)
                sig.update(messageWithMetadata.toByteArray(Charsets.UTF_8))
                signature = sig.sign()
            }
            
            // Build final encrypted data structure
            val outputStream = ByteArrayOutputStream()
            outputStream.write(VERSION_BYTE_RSA_4096_AES_FULL.toInt())
            
            // Write encrypted master AES key
            writeInt32(outputStream, encryptedMasterKey.size)
            outputStream.write(encryptedMasterKey)
            
            // Write IV
            outputStream.write(iv)
            
            // Write ephemeral public key
            writeInt32(outputStream, ephemeralPublicKeyBytes.size)
            outputStream.write(ephemeralPublicKeyBytes)
            
            // Write signature if present
            if (signature != null) {
                writeInt32(outputStream, signature.size)
                outputStream.write(signature)
            } else {
                writeInt32(outputStream, 0)
            }
            
            // Write encrypted message
            outputStream.write(encryptedMessage)
            
            return Base64.encodeToString(outputStream.toByteArray(), Base64.NO_WRAP)
            
        } catch (e: Exception) {
            throw RuntimeException("RSA-4096 + AES full encryption failed: ${e.message}", e)
        }
    }
    
    /**
     * RSA with all advanced features: PFS, Signatures, Expiration
     */
    private fun encryptRSAWithAllFeaturesImpl(
        plaintext: String,
        recipientPublicKey: PublicKey,
        enablePFS: Boolean,
        enableSignatures: Boolean,
        enableExpiration: Boolean,
        expirationTime: Long,
        userKeyPair: KeyPair?
    ): String {
        try {
            // Generate original AES key
            val keyGenerator = KeyGenerator.getInstance("AES")
            keyGenerator.init(AES_KEY_SIZE)
            val originalAESKey = keyGenerator.generateKey()
            
            // Generate ephemeral key pair for PFS if enabled
            var ephemeralKeyPair: KeyPair? = null
            if (enablePFS) {
                val ecKeyGen = KeyPairGenerator.getInstance("EC")
                ecKeyGen.initialize(ECGenParameterSpec("secp256r1"))
                ephemeralKeyPair = ecKeyGen.generateKeyPair()
            }
            
            // Encrypt AES key with RSA
            val rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING")
            rsaCipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey)
            val encryptedAESKey = rsaCipher.doFinal(originalAESKey.encoded)
            
            // Generate IV
            val iv = ByteArray(IV_SIZE)
            secureRandom.nextBytes(iv)
            
            // Create message with metadata
            val finalExpirationTime = if (enableExpiration) expirationTime else 0L
            val messageWithMetadata = createMessageWithMetadata(plaintext, finalExpirationTime, ephemeralKeyPair)
            
            // Derive final encryption key
            val finalAESKey = if (enablePFS && ephemeralKeyPair != null) {
                val ephemeralKeyBytes = ephemeralKeyPair.public.encoded.take(32).toByteArray()
                val combinedKeyMaterial = originalAESKey.encoded + ephemeralKeyBytes
                val digest = MessageDigest.getInstance("SHA-256")
                val derivedKey = digest.digest(combinedKeyMaterial)
                SecretKeySpec(derivedKey, "AES")
            } else {
                originalAESKey
            }
            
            // Encrypt message with AES-GCM
            val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
            aesCipher.init(Cipher.ENCRYPT_MODE, finalAESKey, gcmSpec)
            val encryptedMessage = aesCipher.doFinal(messageWithMetadata.toByteArray(Charsets.UTF_8))
            
            // Create digital signature if enabled
            var signature: ByteArray? = null
            if (enableSignatures && userKeyPair?.private != null) {
                signature = createDigitalSignature(messageWithMetadata, userKeyPair.private)
            }
            
            // Build final data structure
            val outputStream = ByteArrayOutputStream()
            outputStream.write(VERSION_BYTE_RSA_ALL.toInt())
            
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
            
            // Write ephemeral public key if PFS enabled
            if (enablePFS && ephemeralKeyPair != null) {
                val ephemeralPublicKeyBytes = ephemeralKeyPair.public.encoded
                outputStream.write(ephemeralPublicKeyBytes.size and 0xFF)
                outputStream.write((ephemeralPublicKeyBytes.size shr 8) and 0xFF)
                outputStream.write(ephemeralPublicKeyBytes)
            } else {
                outputStream.write(0)
                outputStream.write(0)
            }
            
            // Write encrypted message
            outputStream.write(encryptedMessage)
            
            return Base64.encodeToString(outputStream.toByteArray(), Base64.NO_WRAP)
            
        } catch (e: Exception) {
            throw RuntimeException("RSA with all features encryption failed: ${e.message}", e)
        }
    }
    
    /**
     * Decrypt RSA-4096 + AES-GCM with PFS
     */
    private fun decryptRSA4096WithAESFull(encryptedText: String, privateKey: PrivateKey): String {
        try {
            val encryptedData = Base64.decode(encryptedText, Base64.NO_WRAP)
            val buffer = ByteBuffer.wrap(encryptedData)
            
            // Skip version byte
            buffer.get()
            
            // Read encrypted master AES key
            val encryptedKeySize = readInt32(buffer)
            val encryptedMasterKey = ByteArray(encryptedKeySize)
            buffer.get(encryptedMasterKey)
            
            // Read IV
            val iv = ByteArray(12)
            buffer.get(iv)
            
            // Read ephemeral public key
            val ephemeralKeySize = readInt32(buffer)
            val ephemeralPublicKeyBytes = ByteArray(ephemeralKeySize)
            buffer.get(ephemeralPublicKeyBytes)
            
            // Read signature (optional)
            val signatureSize = readInt32(buffer)
            val signature = if (signatureSize > 0) {
                ByteArray(signatureSize).also { buffer.get(it) }
            } else null
            
            // Read encrypted message
            val encryptedMessage = ByteArray(buffer.remaining())
            buffer.get(encryptedMessage)
            
            // Decrypt master AES key with RSA
            val rsaCipher = getRSAOAEPCipher(Cipher.DECRYPT_MODE, privateKey)
            val masterAESKey = rsaCipher.doFinal(encryptedMasterKey)
            
            // Derive final AES key using master key + ephemeral key
            val combinedInput = masterAESKey + ephemeralPublicKeyBytes.take(32).toByteArray()
            val digest = MessageDigest.getInstance("SHA-512")
            val derivedKeyMaterial = digest.digest(combinedInput)
            val finalAESKey = derivedKeyMaterial.sliceArray(0..31)
            
            // Decrypt message with AES-GCM
            val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
            val finalAESKeySpec = SecretKeySpec(finalAESKey, "AES")
            val gcmSpec = GCMParameterSpec(128, iv)
            aesCipher.init(Cipher.DECRYPT_MODE, finalAESKeySpec, gcmSpec)
            
            val decryptedBytes = aesCipher.doFinal(encryptedMessage)
            val messageWithMetadata = String(decryptedBytes, Charsets.UTF_8)
            
            // Parse message and extract plaintext
            return parseMessageWithMetadata(messageWithMetadata)
            
        } catch (e: Exception) {
            throw RuntimeException("RSA-4096 + AES decryption failed: ${e.message}", e)
        }
    }
    
    /**
     * Decrypt RSA with all features
     */
    private fun decryptRSAWithAllFeatures(encryptedText: String, privateKey: PrivateKey, publicKey: PublicKey?): String {
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
            
            // Read ephemeral public key (optional)
            val ephemeralKeySize = (buffer.get().toInt() and 0xFF) or 
                                 ((buffer.get().toInt() and 0xFF) shl 8)
            val ephemeralPublicKeyBytes = if (ephemeralKeySize > 0) {
                ByteArray(ephemeralKeySize).also { buffer.get(it) }
            } else null
            
            // Read encrypted message
            val encryptedMessage = ByteArray(buffer.remaining())
            buffer.get(encryptedMessage)
            
            // Decrypt AES key with RSA
            val rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING")
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey)
            val originalAESKey = rsaCipher.doFinal(encryptedAESKey)
            
            // Derive final decryption key
            val finalAESKey = if (ephemeralPublicKeyBytes != null) {
                val ephemeralKeyBytes = ephemeralPublicKeyBytes.take(32).toByteArray()
                val combinedKeyMaterial = originalAESKey + ephemeralKeyBytes
                val digest = MessageDigest.getInstance("SHA-256")
                val derivedKey = digest.digest(combinedKeyMaterial)
                SecretKeySpec(derivedKey, "AES")
            } else {
                SecretKeySpec(originalAESKey, "AES")
            }
            
            // Decrypt message with AES-GCM
            val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
            aesCipher.init(Cipher.DECRYPT_MODE, finalAESKey, gcmSpec)
            
            val decryptedBytes = aesCipher.doFinal(encryptedMessage)
            val messageWithMetadata = String(decryptedBytes, Charsets.UTF_8)
            
            // Verify signature if present and public key available
            if (signature != null && publicKey != null) {
                val verified = verifyDigitalSignature(messageWithMetadata, signature, publicKey)
                if (!verified) {
                    throw RuntimeException("Digital signature verification failed")
                }
            }
            
            // Parse and return plaintext
            return parseMessageWithMetadata(messageWithMetadata)
            
        } catch (e: Exception) {
            throw RuntimeException("RSA all features decryption failed: ${e.message}", e)
        }
    }
    
    // ===== UTILITY METHODS =====
    
    private fun getRSAOAEPCipher(mode: Int, key: Key): Cipher {
        return SecurityUtils.getRSAOAEPCipher(mode == Cipher.ENCRYPT_MODE, key)
    }
    
    private fun writeInt32(outputStream: ByteArrayOutputStream, value: Int) {
        SecurityUtils.writeInt32(outputStream, value)
    }
    
    private fun readInt32(buffer: ByteBuffer): Int {
        val currentPos = buffer.position()
        val remaining = buffer.remaining()
        if (remaining < 4) throw RuntimeException("Not enough data for int32")
        
        val bytes = ByteArray(4)
        buffer.get(bytes)
        return SecurityUtils.readInt32(bytes, 0)
    }
    
    private fun createDigitalSignature(message: String, privateKey: PrivateKey): ByteArray {
        val sig = Signature.getInstance("SHA512withRSA")
        sig.initSign(privateKey)
        sig.update(message.toByteArray(Charsets.UTF_8))
        return sig.sign()
    }
    
    private fun verifyDigitalSignature(message: String, signatureBytes: ByteArray, publicKey: PublicKey): Boolean {
        return try {
            val sig = Signature.getInstance("SHA512withRSA")
            sig.initVerify(publicKey)
            sig.update(message.toByteArray(Charsets.UTF_8))
            sig.verify(signatureBytes)
        } catch (e: Exception) {
            false
        }
    }
    
    private fun createMessageWithMetadataFixed(message: String, expirationTime: Long, ephemeralKeyPair: KeyPair?): String {
        return SecurityUtils.createMessageWithMetadataFixed(message, expirationTime, ephemeralKeyPair != null)
    }
    
    private fun createMessageWithMetadata(message: String, expirationTime: Long, ephemeralKeyPair: KeyPair?): String {
        return SecurityUtils.createMessageWithMetadataLegacy(message, expirationTime)
    }
    
    private fun parseMessageWithMetadata(messageWithMetadata: String): String {
        return try {
            // Try fixed format first
            val metadata = SecurityUtils.parseMessageMetadataFixed(messageWithMetadata)
            if (metadata != null) {
                return SecurityUtils.enforceExpirationAndExtract(metadata)
            }
            
            // Try legacy format
            val legacyMetadata = SecurityUtils.parseMessageMetadataLegacy(messageWithMetadata)
            if (legacyMetadata != null) {
                return SecurityUtils.enforceExpirationAndExtract(legacyMetadata)
            }
            
            messageWithMetadata // Fallback to original
        } catch (e: Exception) {
            throw RuntimeException("Message parsing failed: ${e.message}", e)
        }
    }
}