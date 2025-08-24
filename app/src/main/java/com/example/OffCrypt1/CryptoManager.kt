package com.example.OffCrypt1

import android.content.Context
import android.util.Pair as AndroidPair
import java.security.KeyPair
import java.security.PublicKey
import java.security.PrivateKey
import java.time.Instant

/**
 * Main crypto manager that coordinates all cryptographic operations
 * This class serves as the main interface for encryption/decryption operations
 */
class CryptoManager(private val context: Context) {
    
    private val passwordCrypto = PasswordCrypto()
    private val password2 = Password2()
    private val rsaCrypto = RSACrypto(context)
    private val fileCrypto = FileCrypto(context)
    private val fileCrypto2 = FileCrypto2(context)
    private val keyManager = KeyManager(context)
    
    // ===== MESSAGE ENCRYPTION =====
    
    fun encryptWithPassword(message: String, password: String, expirationTime: Long = 0): String {
        return passwordCrypto.encryptPasswordBased(message, password, expirationTime)
    }
    
    fun encryptWithRSA(message: String, recipientPublicKey: PublicKey, useRSA4096: Boolean = false, enablePFS: Boolean = false, enableSignatures: Boolean = false, enableExpiration: Boolean = false, expirationTime: Long = 0): String {
        return if (useRSA4096) {
            // RSA-4096 with expiration support (FIXED)
            rsaCrypto.encryptRSA4096WithAESFull(message, recipientPublicKey, if (enableExpiration) expirationTime else 0L)
        } else {
            rsaCrypto.encryptRSAWithAllFeatures(message, recipientPublicKey, enablePFS, enableSignatures, enableExpiration, expirationTime)
        }
    }
    
    // ===== MESSAGE DECRYPTION =====
    
    fun decryptWithPassword(encryptedText: String, password: String): String {
        return passwordCrypto.decryptPasswordBased(encryptedText, password)
    }
    
    fun decryptWithRSA(encryptedText: String, privateKey: PrivateKey, publicKey: PublicKey? = null): String {
        return rsaCrypto.decryptRSAMessage(encryptedText, privateKey, publicKey)
    }
    
    // ===== FILE ENCRYPTION =====
    
    fun encryptFileWithPassword(fileData: ByteArray, metadata: String, password: String): ByteArray {
        return fileCrypto.encryptFileDataPasswordBased(fileData, metadata, password)
    }
    
    fun encryptFileWithRSA(fileData: ByteArray, metadata: String, recipientPublicKey: PublicKey): ByteArray {
        return fileCrypto.encryptFileDataRSA(fileData, metadata, recipientPublicKey)
    }
    
    // Advanced file encryption methods with expiration support
    fun encryptFileWithPasswordAdvanced(fileData: ByteArray, metadata: String, password: String): ByteArray {
        return fileCrypto2.encryptFileDataPasswordBasedAdvanced(fileData, metadata, password)
    }
    
    fun encryptFileWithRSAAdvanced(
        fileData: ByteArray, 
        metadata: String, 
        recipientPublicKey: PublicKey,
        userKeyPair: java.security.KeyPair? = null,
        enablePFS: Boolean = true,
        enableSignatures: Boolean = true,
        expirationTime: Long = 0L
    ): ByteArray {
        return fileCrypto2.encryptFileDataRSAAdvanced(
            fileData, 
            metadata, 
            recipientPublicKey,
            userKeyPair?.let { android.util.Pair(it.public, it.private) },
            enablePFS,
            enableSignatures,
            expirationTime
        )
    }
    
    // ===== FILE DECRYPTION =====
    
    fun decryptFileWithPassword(encryptedData: ByteArray, password: String): Pair<ByteArray, String> {
        return fileCrypto.decryptFileDataPasswordBased(encryptedData, password)
    }
    
    fun decryptFileWithRSA(encryptedData: ByteArray, privateKey: PrivateKey): Pair<ByteArray, String> {
        // Check format and use appropriate decryption
        if (encryptedData.isNotEmpty() && encryptedData[0] == 0x0D.toByte()) {
            // Advanced RSA format
            return fileCrypto2.decryptFileDataRSAAdvanced(encryptedData, privateKey, null)
        } else {
            // Legacy format 
            return fileCrypto.decryptFileDataRSA(encryptedData, privateKey)
        }
    }
    
    // ===== KEY MANAGEMENT =====
    
    fun generateRSAKeyPair(useRSA4096: Boolean = false): KeyPair {
        return keyManager.generateNewKeyPair(useRSA4096)
    }
    
    fun saveKeyPair(keyPair: KeyPair, useRSA4096: Boolean = false) {
        keyManager.saveKeyPair(keyPair, useRSA4096)
    }
    
    fun loadKeyPair(useRSA4096: Boolean = false): KeyPair? {
        return keyManager.loadKeyPair(useRSA4096)
    }
    
    fun parsePublicKeyFromString(publicKeyString: String): PublicKey {
        return keyManager.parsePublicKeyFromString(publicKeyString)
    }
    
    fun formatPublicKeyForSharing(publicKey: PublicKey): String {
        return keyManager.formatPublicKeyForSharing(publicKey)
    }
    
    // ===== UTILITY METHODS =====
    
    fun generateRandomPassword(length: Int = 24): String {
        return keyManager.generateRandomPassword(length)
    }
    
    fun isValidEncryptedMessage(encryptedText: String): Boolean {
        return try {
            encryptedText.isNotBlank() && encryptedText.length > 50
        } catch (e: Exception) {
            false
        }
    }
    
    fun detectEncryptionType(encryptedData: ByteArray): String {
        return when {
            encryptedData.isEmpty() -> "Unknown"
            encryptedData[0] == 0x01.toByte() -> "Password-based"
            encryptedData[0] == 0x02.toByte() -> "RSA-2048"
            encryptedData[0] == 0x05.toByte() -> "Password multi-salt"
            encryptedData[0] == 0x06.toByte() -> "Burn-after-reading"
            encryptedData[0] == 0x0A.toByte() -> "RSA-4096"
            encryptedData[0] == 0x0B.toByte() -> "File encryption"
            encryptedData[0] == 0x0C.toByte() -> "File multi-salt"
            encryptedData[0] == 0x0D.toByte() -> "RSA advanced"
            else -> "Unknown format (0x${encryptedData[0].toString(16)})"
        }
    }
    
    // ===== PERFECT FORWARD SECRECY (PFS) API - EXACTLY LIKE CRYPTING.kt =====
    
    /**
     * Encrypt message with Perfect Forward Secrecy using ephemeral keys
     * Exactly like CRYPTING.kt implementation
     */
    fun encryptWithPFS(
        message: String, 
        recipientPublicKey: PublicKey,
        senderKeyPair: KeyPair? = null,
        expirationTime: Long = 0
    ): String {
        return rsaCrypto.encryptRSAWithAllFeatures(
            message,
            recipientPublicKey,
            true, // Enable PFS
            senderKeyPair != null, // Enable signatures if sender key provided
            expirationTime > 0, // Enable expiration if time provided
            expirationTime,
            senderKeyPair
        )
    }
    
    /**
     * Encrypt file with Perfect Forward Secrecy
     */
    fun encryptFileWithPFS(
        fileData: ByteArray,
        metadata: String,
        recipientPublicKey: PublicKey,
        senderKeyPair: AndroidPair<PublicKey, PrivateKey>? = null
    ): ByteArray {
        return fileCrypto2.encryptFileDataRSAAdvanced(
            fileData,
            metadata,
            recipientPublicKey,
            senderKeyPair,
            true, // Enable PFS
            senderKeyPair != null // Enable signatures if sender key provided
        )
    }
    
    /**
     * Generate ephemeral key pair for PFS
     */
    fun generateEphemeralKeyPair(): KeyPair {
        return keyManager.generateEphemeralKeyPair()
    }
    
    /**
     * Store ephemeral key with automatic cleanup
     */
    fun storeEphemeralKey(keyPair: KeyPair): String {
        val keyId = keyManager.generateKeyId()
        return keyManager.storeEphemeralKey(keyId, keyPair)
    }
    
    /**
     * Get ephemeral key if not expired
     */
    fun getEphemeralKey(keyId: String): KeyPair? {
        return keyManager.getEphemeralKey(keyId)
    }
    
    /**
     * Securely wipe ephemeral key
     */
    fun wipeEphemeralKey(keyId: String) {
        keyManager.secureWipeEphemeralKey(keyId)
    }
    
    // ===== BURN-AFTER-READING API =====
    
    /**
     * Encrypt message with burn-after-reading feature
     * Message self-destructs after decryption
     */
    fun encryptBurnAfterReading(message: String, password: String): String {
        return password2.encryptPasswordBasedBurnAfterReading(message, password)
    }
    
    /**
     * Decrypt burn-after-reading message
     * WARNING: Message will be destroyed after this operation
     */
    fun decryptBurnAfterReading(encryptedText: String, password: String): String {
        return password2.decryptPasswordBasedBurnAfterReading(encryptedText, password)
    }
    
    /**
     * Encrypt file with burn-after-reading feature
     */
    fun encryptFileBurnAfterReading(fileData: ByteArray, metadata: String, password: String): ByteArray {
        return fileCrypto2.encryptFileDataBurnAfterReading(fileData, metadata, password)
    }
    
    /**
     * Check if encrypted data has burn-after-reading capability
     */
    fun checkBurnAfterReading(encryptedData: ByteArray, password: String): Boolean {
        return fileCrypto2.checkBurnAfterReading(encryptedData, password)
    }
    
    // ===== ADVANCED PASSWORD ENCRYPTION WITH MULTIPLE SALTS =====
    
    /**
     * Encrypt with advanced password-based encryption using multiple salts
     * Exactly like CRYPTING.kt implementation
     */
    fun encryptPasswordAdvanced(
        message: String, 
        password: String, 
        expirationTime: Long = 0
    ): String {
        return password2.encryptPasswordBasedMultiSalt(message, password, expirationTime)
    }
    
    /**
     * Decrypt advanced password-based encryption
     */
    fun decryptPasswordAdvanced(encryptedText: String, password: String): String {
        val encryptedData = android.util.Base64.decode(encryptedText, android.util.Base64.NO_WRAP)
        return password2.decryptPasswordBasedMultiSalt(encryptedData, password)
    }
    
    // ===== ADVANCED FILE ENCRYPTION =====
    
    /**
     * Encrypt file with advanced password-based encryption and multiple authentication layers
     */
    fun encryptFileAdvanced(
        fileData: ByteArray, 
        metadata: String, 
        password: String
    ): ByteArray {
        return fileCrypto2.encryptFileDataPasswordBasedAdvanced(fileData, metadata, password)
    }
    
    /**
     * Decrypt file with advanced password-based encryption
     */
    fun decryptFileAdvanced(encryptedData: ByteArray, password: String): Pair<ByteArray, String> {
        return fileCrypto2.decryptFileDataPasswordBasedAdvanced(encryptedData, password)
    }
    
    /**
     * Decrypt RSA advanced file with PFS and signature verification
     */
    fun decryptFileRSAAdvanced(
        encryptedData: ByteArray,
        privateKey: PrivateKey,
        senderPublicKey: PublicKey? = null
    ): Pair<ByteArray, String> {
        return fileCrypto2.decryptFileDataRSAAdvanced(encryptedData, privateKey, senderPublicKey)
    }
    
    // ===== SECURE MEMORY MANAGEMENT =====
    
    /**
     * Secure wipe of sensitive data
     */
    fun secureWipe(data: ByteArray) {
        keyManager.secureWipe(data)
    }
    
    /**
     * Secure wipe of passwords
     */
    fun secureWipe(data: CharArray) {
        keyManager.secureWipe(data)
    }
    
    /**
     * Wipe all ephemeral keys from memory
     */
    fun wipeAllEphemeralKeys() {
        keyManager.wipeAllEphemeralKeys()
    }
    
    /**
     * Run operation with secure cleanup
     */
    fun runWithSecureCleanup(operation: () -> Unit) {
        keyManager.runWithSecureCleanup(operation)
    }
    
    /**
     * Get security statistics
     */
    fun getSecurityStats(): Map<String, Any> {
        return keyManager.getSecureMemoryStats()
    }
    
    /**
     * Check hardware security support
     */
    fun checkHardwareSecuritySupport(): Map<String, Boolean> {
        return keyManager.checkHardwareSecuritySupport()
    }
    
    // ===== COMPATIBILITY AND DETECTION =====
    
    /**
     * Detect file encryption type with advanced formats
     */
    fun detectFileEncryptionType(encryptedData: ByteArray): String {
        return fileCrypto2.detectFileEncryptionType(encryptedData)
    }
    
    /**
     * Check if message uses legacy or advanced encryption
     */
    fun isAdvancedEncryption(encryptedText: String): Boolean {
        return try {
            val data = android.util.Base64.decode(encryptedText, android.util.Base64.NO_WRAP)
            data.isNotEmpty() && (data[0] == 0x05.toByte() || data[0] == 0x06.toByte())
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Get comprehensive encryption capabilities
     */
    fun getEncryptionCapabilities(): Map<String, Boolean> {
        return mapOf(
            "password_basic" to true,
            "password_multi_salt" to true,
            "password_burn_after_reading" to true,
            "rsa_2048" to true,
            "rsa_4096" to true,
            "rsa_pfs" to true,
            "rsa_digital_signatures" to true,
            "file_encryption" to true,
            "file_advanced" to true,
            "ephemeral_keys" to true,
            "secure_memory_management" to true,
            "security_utils" to true
        )
    }
    
    // ===== DESKTOP REFERENCE COMPATIBILITY =====
    
    /**
     * Get RSA crypto operations (Desktop reference compatibility)
     */
    fun getRSACrypto(): RSACrypto {
        return rsaCrypto
    }
    
    /**
     * Get password crypto operations (Desktop reference compatibility)
     */
    fun getPasswordCrypto(): PasswordCrypto {
        return passwordCrypto
    }
    
    /**
     * Get key manager for direct key operations
     */
    fun getKeyManager(): KeyManager {
        return keyManager
    }
    
    /**
     * Verify digital signature (Desktop reference compatibility)
     */
    fun verifyDigitalSignature(message: String, signature: ByteArray, publicKey: PublicKey): Boolean {
        return rsaCrypto.verifySignature(message.toByteArray(), signature, publicKey)
    }
    
    /**
     * Clean up sensitive data
     */
    fun cleanupSensitiveData() {
        keyManager.wipeAllEphemeralKeys()
        keyManager.runWithSecureCleanup {
            System.gc()
        }
    }
}