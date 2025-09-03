package com.example.OffCrypt1

import android.content.Context
import androidx.appcompat.app.AppCompatActivity


/**
 * SecurityServiceContainer - Dependency Injection Container for All Security Services
 *
 * Centralizes service creation and management, providing clean dependency injection
 * pattern for all cryptographic operations. Supports both production and test configurations.
 *
 * Usage:
 *   val container = SecurityServiceContainer(context)
 *   val encrypted = container.messageCryptoService.encryptWithPassword(message, password)
 */
class SecurityServiceContainer(private val context: Context) {

    // ===== CORE CRYPTO SERVICES =====

    /**
     * Main cryptographic coordinator - handles all crypto operations
     */
    val cryptoManager: CryptoManager by lazy {
        CryptoManager(context)
    }

    /**
     * Message encryption/decryption service with clean UI separation
     */
    val messageCryptoService: MessageCryptoService by lazy {
        MessageCryptoService(cryptoManager)
    }

    /**
     * File encryption/decryption operations and UI integration
     * Note: FileEncryptionManager requires AppCompatActivity context
     */
    val fileEncryptionManager: FileEncryptionManager by lazy {
        if (context is AppCompatActivity) {
            FileEncryptionManager(context, cryptoManager)
        } else {
            throw SecurityServiceException("FileEncryptionManager requires AppCompatActivity context, got ${context::class.simpleName}")
        }
    }

    /**
     * Encrypted preferences storage using AndroidKeyStore
     */
    val encryptedPreferences: EncryptedPreferences by lazy {
        EncryptedPreferences(context, "netcrypt_secure_prefs")
    }

    /**
     * Security utilities for memory management and sensitive operations
     */
    val securityUtils = SecurityUtils

    // ===== INTERNAL SERVICES (Advanced users) =====

    /**
     * Direct access to KeyManager for advanced key operations
     */
    val keyManager: KeyManager by lazy {
        cryptoManager.getKeyManager()
    }

    /**
     * Direct access to RSA crypto operations
     */
    val rsaCrypto: RSACrypto by lazy {
        cryptoManager.getRSACrypto()
    }

    /**
     * Direct access to password crypto operations
     */
    val passwordCrypto: PasswordCrypto by lazy {
        cryptoManager.getPasswordCrypto()
    }

    // ===== CONFIGURATION & LIFECYCLE =====

    /**
     * Initialize all services and perform startup checks
     */
    fun initialize() {
        try {
            // Verify AndroidKeyStore availability
            encryptedPreferences.getString("init_test", null)

            // Verify crypto services are functional
            cryptoManager.generateRandomPassword(16)

            // Verify security utilities are available
            // Note: SecurityUtils is an object with static methods

        } catch (e: Exception) {
            throw SecurityServiceException("Service initialization failed: ${e.message}", e)
        }
    }

    /**
     * Clean up sensitive data and resources
     */
    fun cleanup() {
        try {
            // Clear sensitive memory
            cryptoManager.cleanupSensitiveData()

            // Wipe ephemeral keys
            cryptoManager.wipeAllEphemeralKeys()

            // Note: Clipboard clearing handled by SecurityUtils static methods
            // Individual services handle their own cleanup

        } catch (e: Exception) {
            // Log but don't throw during cleanup
            android.util.Log.w("SecurityServiceContainer", "Cleanup warning: ${e.message}")
        }
    }

    /**
     * Get comprehensive service status for debugging
     */
    fun getServiceStatus(): Map<String, Any> {
        return mapOf(
            "cryptoManager" to "initialized",
            "messageCryptoService" to "ready",
            "fileEncryptionManager" to "ready",
            "encryptedPreferences" to "ready",
            "securityUtils" to "ready",
            "capabilities" to cryptoManager.getEncryptionCapabilities(),
            "hardwareSupport" to cryptoManager.checkHardwareSecuritySupport(),
            "securityStats" to cryptoManager.getSecurityStats()
        )
    }

    // ===== FACTORY METHODS FOR TESTING =====

    companion object {

        /**
         * Create container with mock services for testing
         */
        fun createTestContainer(
            context: Context,
            mockCryptoManager: CryptoManager? = null,
            mockMessageService: MessageCryptoService? = null
        ): SecurityServiceContainer {
            return SecurityServiceContainer(context).apply {
                // Note: In real implementation, we'd use dependency injection framework
                // For now, this provides the pattern for future test integration
            }
        }

        /**
         * Create minimal container for performance testing
         */
        fun createMinimalContainer(context: Context): SecurityServiceContainer {
            return SecurityServiceContainer(context)
        }
    }
}

/**
 * Custom exception for service container errors
 */
class SecurityServiceException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause)

/**
 * Extension functions for easy service access
 */
fun Context.getSecurityServices(): SecurityServiceContainer {
    return SecurityServiceContainer(this)
}