package com.example.OffCrypt1

import android.content.Context
import android.util.Base64
import org.json.JSONObject
import java.security.PublicKey
import java.security.PrivateKey
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.nio.ByteBuffer

/**
 * File encryption and decryption functionality
 * Handles both password-based and RSA file encryption
 */
class FileCrypto(private val context: Context) {
    
    private val secureRandom = SecureRandom()
    private val passwordCrypto = PasswordCrypto()
    private val rsaCrypto = RSACrypto(context)
    private val fileCrypto2 = FileCrypto2(context)
    
    companion object {
        private const val FILE_VERSION_BYTE: Byte = 0x0B
        private const val AES_KEY_LENGTH = 256
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH = 16
    }
    
    /**
     * Encrypts file data using password-based encryption (with advanced features)
     */
    fun encryptFileDataPasswordBased(fileData: ByteArray, metadata: String, password: String): ByteArray {
        return try {
            // Use advanced FileCrypto2 encryption for better security
            fileCrypto2.encryptFileDataPasswordBasedAdvanced(fileData, metadata, password)
        } catch (e: Exception) {
            // Fallback to legacy implementation for compatibility
            try {
                // Create file metadata JSON
                val fileMetadata = JSONObject().apply {
                    put("filename", metadata)
                    put("size", fileData.size)
                    put("encryption_type", "password_legacy")
                    put("timestamp", System.currentTimeMillis())
                }
                
                // Encrypt file data using password crypto
                val encryptedContent = passwordCrypto.encryptPasswordBased(
                    Base64.encodeToString(fileData, Base64.NO_WRAP), 
                    password
                )
                
                // Create final file structure
                val finalData = JSONObject().apply {
                    put("version", "1.0")
                    put("type", "file")
                    put("metadata", fileMetadata)
                    put("encrypted_content", encryptedContent)
                }
                
                // Add file version byte and return
                val jsonBytes = finalData.toString().toByteArray(Charsets.UTF_8)
                val buffer = ByteBuffer.allocate(1 + jsonBytes.size)
                buffer.put(FILE_VERSION_BYTE)
                buffer.put(jsonBytes)
                
                buffer.array()
                
            } catch (legacyE: Exception) {
                throw RuntimeException("Password-based file encryption failed: ${e.message}, Legacy fallback: ${legacyE.message}", e)
            }
        }
    }
    
    /**
     * Encrypts file data using RSA encryption (with advanced features)
     */
    fun encryptFileDataRSA(fileData: ByteArray, metadata: String, recipientPublicKey: PublicKey): ByteArray {
        return try {
            // Use advanced FileCrypto2 encryption with PFS and signatures
            fileCrypto2.encryptFileDataRSAAdvanced(
                fileData, 
                metadata, 
                recipientPublicKey,
                null, // No user key pair for signatures (optional)
                true, // Enable PFS
                false // Disable signatures for basic RSA encryption
            )
        } catch (e: Exception) {
            // Fallback to legacy RSA implementation for compatibility
            try {
                // For large files, use hybrid encryption: AES for file, RSA for AES key
                val aesKey = generateAESKey()
                val iv = ByteArray(GCM_IV_LENGTH)
                secureRandom.nextBytes(iv)
                
                // Encrypt file with AES
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
                cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec)
                val encryptedFileData = cipher.doFinal(fileData)
                
                // Encrypt AES key with RSA
                val rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
                rsaCipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey)
                val encryptedAESKey = rsaCipher.doFinal(aesKey.encoded)
                
                // Create metadata
                val fileMetadata = JSONObject().apply {
                    put("filename", metadata)
                    put("size", fileData.size)
                    put("encryption_type", "rsa_legacy")
                    put("timestamp", System.currentTimeMillis())
                }
                
                // Create final structure
                val finalData = JSONObject().apply {
                    put("version", "1.0")
                    put("type", "file")
                    put("metadata", fileMetadata)
                    put("encrypted_aes_key", Base64.encodeToString(encryptedAESKey, Base64.NO_WRAP))
                    put("iv", Base64.encodeToString(iv, Base64.NO_WRAP))
                    put("encrypted_content", Base64.encodeToString(encryptedFileData, Base64.NO_WRAP))
                }
                
                val jsonBytes = finalData.toString().toByteArray(Charsets.UTF_8)
                val buffer = ByteBuffer.allocate(1 + jsonBytes.size)
                buffer.put(FILE_VERSION_BYTE)
                buffer.put(jsonBytes)
                
                buffer.array()
                
            } catch (legacyE: Exception) {
                throw RuntimeException("RSA file encryption failed: ${e.message}, Legacy fallback: ${legacyE.message}", e)
            }
        }
    }
    
    /**
     * Decrypts password-based encrypted file (supports advanced formats)
     */
    fun decryptFileDataPasswordBased(encryptedData: ByteArray, password: String): Pair<ByteArray, String> {
        // Check if this is advanced FileCrypto2 format
        if (encryptedData.isNotEmpty() && (encryptedData[0] == 0x0C.toByte())) {
            return try {
                fileCrypto2.decryptFileDataPasswordBasedAdvanced(encryptedData, password)
            } catch (e: Exception) {
                throw RuntimeException("Advanced password file decryption failed: ${e.message}", e)
            }
        }
        
        // Legacy format decryption
        try {
            if (encryptedData.isEmpty() || encryptedData[0] != FILE_VERSION_BYTE) {
                throw IllegalArgumentException("Invalid file format")
            }
            
            val jsonData = String(encryptedData.sliceArray(1 until encryptedData.size), Charsets.UTF_8)
            val jsonObject = JSONObject(jsonData)
            
            val metadata = jsonObject.getJSONObject("metadata")
            val filename = metadata.getString("filename")
            val encryptedContent = jsonObject.getString("encrypted_content")
            
            // Decrypt using password crypto
            val decryptedBase64 = passwordCrypto.decryptPasswordBased(encryptedContent, password)
            val decryptedFileData = Base64.decode(decryptedBase64, Base64.NO_WRAP)
            
            return Pair(decryptedFileData, filename)
            
        } catch (e: Exception) {
            throw RuntimeException("Legacy password file decryption failed: ${e.message}", e)
        }
    }
    
    /**
     * Decrypts RSA encrypted file (supports advanced formats)
     */
    fun decryptFileDataRSA(encryptedData: ByteArray, privateKey: PrivateKey): Pair<ByteArray, String> {
        // Check if this is advanced FileCrypto2 format
        if (encryptedData.isNotEmpty() && (encryptedData[0] == 0x0D.toByte())) {
            return try {
                fileCrypto2.decryptFileDataRSAAdvanced(encryptedData, privateKey, null)
            } catch (e: Exception) {
                throw RuntimeException("Advanced RSA file decryption failed: ${e.message}", e)
            }
        }
        
        // Legacy format - basic RSA file decryption
        try {
            if (encryptedData.isEmpty() || encryptedData[0] != FILE_VERSION_BYTE) {
                throw IllegalArgumentException("Invalid file format")
            }
            
            val jsonData = String(encryptedData.sliceArray(1 until encryptedData.size), Charsets.UTF_8)
            val jsonObject = JSONObject(jsonData)
            
            val metadata = jsonObject.getJSONObject("metadata")
            val filename = metadata.getString("filename")
            val encryptedAESKey = jsonObject.getString("encrypted_aes_key")
            val iv = jsonObject.getString("iv")
            val encryptedContent = jsonObject.getString("encrypted_content")
            
            // Decrypt AES key with RSA
            val rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey)
            val aesKeyBytes = rsaCipher.doFinal(Base64.decode(encryptedAESKey, Base64.NO_WRAP))
            
            // Decrypt file with AES
            val aesKey = SecretKeySpec(aesKeyBytes, "AES")
            val ivBytes = Base64.decode(iv, Base64.NO_WRAP)
            val encryptedFileBytes = Base64.decode(encryptedContent, Base64.NO_WRAP)
            
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, ivBytes)
            cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec)
            
            val decryptedFileData = cipher.doFinal(encryptedFileBytes)
            
            return Pair(decryptedFileData, filename)
            
        } catch (e: Exception) {
            throw RuntimeException("Legacy RSA file decryption failed: ${e.message}", e)
        }
    }
    
    private fun generateAESKey(): SecretKeySpec {
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(AES_KEY_LENGTH)
        val secretKey = keyGen.generateKey()
        return SecretKeySpec(secretKey.encoded, "AES")
    }
}