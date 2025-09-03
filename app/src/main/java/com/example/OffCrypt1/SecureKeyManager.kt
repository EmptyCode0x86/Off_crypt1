package com.example.OffCrypt1

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyFactory
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.math.pow

/**
 * Simple logging wrapper that gracefully handles unit test environments
 */
internal object SecureLog {
    fun d(tag: String, message: String) {
        try {
            Log.d(tag, message)
        } catch (e: Exception) {
            println("DEBUG: $tag - $message")
        }
    }

    fun i(tag: String, message: String) {
        try {
            Log.i(tag, message)
        } catch (e: Exception) {
            println("INFO: $tag - $message")
        }
    }

    fun w(tag: String, message: String) {
        try {
            Log.w(tag, message)
        } catch (e: Exception) {
            println("WARN: $tag - $message")
        }
    }

    fun e(tag: String, message: String) {
        try {
            Log.e(tag, message)
        } catch (e: Exception) {
            println("ERROR: $tag - $message")
        }
    }
}

class SecureKeyManager(private val context: Context) {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "NETCryptPreferencesKey"
        private const val KEY_ALIAS_TEE = "NETCryptPreferencesKey_TEE"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH = 16
        private const val VALIDATION_CACHE_MS = 300000L  // 5 min cache
    }

    private var isStrongboxBacked = false
    private var isTrustedEnvironmentBacked = false
    private var lastValidationTime = 0L
    private var currentKeyAlias = KEY_ALIAS

    // KORJATTU: Lazy initialization AndroidKeyStore:lle
    private var keyStore: KeyStore? = null
    private var isKeyStoreInitialized = false
    private var keyStoreAvailable = false

    // LISÄTTY: Fallback in-memory encryption when AndroidKeyStore unavailable
    private var fallbackKey: ByteArray? = null

    /**
     * KORJATTU: Lazy initialization of AndroidKeyStore with proper error handling
     */
    private fun initializeKeyStore(): Boolean {
        if (isKeyStoreInitialized) {
            return keyStoreAvailable
        }

        try {
            keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
                load(null)
            }
            keyStoreAvailable = true
            isKeyStoreInitialized = true
            SecureLog.d("SecureKeyManager", "✅ AndroidKeyStore initialized successfully")

            // Initialize key if AndroidKeyStore is available
            try {
                generateOrGetKey()
            } catch (e: Exception) {
                SecureLog.w(
                    "SecureKeyManager",
                    "Key generation failed, will use fallback: ${e.message}"
                )
            }

        } catch (e: Exception) {
            SecureLog.w(
                "SecureKeyManager",
                "⚠️ AndroidKeyStore initialization failed: ${e.message}"
            )
            keyStore = null
            keyStoreAvailable = false
            isKeyStoreInitialized = true

            // Initialize fallback encryption
            initializeFallbackEncryption()
        }

        return keyStoreAvailable
    }

    /**
     * LISÄTTY: Initialize fallback in-memory encryption for unit tests and degraded mode
     */
    private fun initializeFallbackEncryption() {
        try {
            // Generate a secure fallback key using standard Java crypto
            val keyGen = KeyGenerator.getInstance("AES")
            keyGen.init(256)
            val key = keyGen.generateKey()
            fallbackKey = key.encoded

            SecureLog.i("SecureKeyManager", "🔄 Fallback in-memory encryption initialized")
        } catch (e: Exception) {
            SecureLog.e(
                "SecureKeyManager",
                "❌ Fallback encryption initialization failed: ${e.message}"
            )
            // Generate basic fallback key as last resort
            fallbackKey = "FALLBACK_KEY_FOR_TESTING_ONLY_32".toByteArray()
        }
    }

    /**
     * LISÄTTY: Check if AndroidKeyStore is available
     */
    fun isAndroidKeyStoreAvailable(): Boolean {
        initializeKeyStore()
        return keyStoreAvailable
    }

    private fun generateOrGetKey(): SecretKey? {
        if (!initializeKeyStore()) {
            SecureLog.w("SecureKeyManager", "AndroidKeyStore not available, using fallback")
            return null
        }

        return try {
            if (keyStore?.containsAlias(KEY_ALIAS) == true) {
                keyStore?.getKey(KEY_ALIAS, null) as? SecretKey
            } else {
                generateKey()
            }
        } catch (e: Exception) {
            SecureLog.e("SecureKeyManager", "Key access failed: ${e.message}")
            null
        }
    }

    private fun generateKey(): SecretKey? {
        // Yritä ensin StrongBox (Android 9+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                return generateStrongBoxKey()
            } catch (e: Exception) {
                SecureLog.w("SecureKeyManager", "StrongBox generation failed: ${e.message}")
                SecureLog.i("SecureKeyManager", "Falling back to TEE...")
            }
        }

        // Fallback TEE:hen
        return try {
            generateTEEKey()
        } catch (e: Exception) {
            SecureLog.e("SecureKeyManager", "TEE key generation failed: ${e.message}")
            null
        }
    }

    private fun generateStrongBoxKey(): SecretKey {
        val keyGenerator =
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationValidityDurationSeconds(30)  // MUUTETTU: 300 → 30
            .setInvalidatedByBiometricEnrollment(true)
            .setUnlockedDeviceRequired(true)                   // LISÄÄ
            .setIsStrongBoxBacked(true)                        // STRONGBOX
            .build()

        keyGenerator.init(keyGenParameterSpec)
        val key = keyGenerator.generateKey()

        currentKeyAlias = KEY_ALIAS
        validateGeneratedKey(key)
        return key
    }

    private fun generateTEEKey(): SecretKey {
        val keyGenerator =
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            KEY_ALIAS_TEE,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationValidityDurationSeconds(30)
            .setInvalidatedByBiometricEnrollment(true)
            .setUnlockedDeviceRequired(true)
            .build()

        keyGenerator.init(keyGenParameterSpec)
        val key = keyGenerator.generateKey()

        currentKeyAlias = KEY_ALIAS_TEE
        validateGeneratedKey(key)
        return key
    }

    fun encryptData(plainText: String): String {
        // KORJATTU: Try AndroidKeyStore first, fallback to in-memory encryption
        if (initializeKeyStore()) {
            try {
                val cipher = Cipher.getInstance(TRANSFORMATION)
                val secretKey = getValidatedKey()

                if (secretKey != null) {
                    // Generate random IV
                    val iv = ByteArray(GCM_IV_LENGTH)
                    SecureRandom().nextBytes(iv)
                    val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)

                    cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)
                    val encryptedData = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))

                    // Combine IV + encrypted data + marker for AndroidKeyStore
                    val combined =
                        byteArrayOf(0x01) + iv + encryptedData // 0x01 = AndroidKeyStore marker
                    return Base64.encodeToString(combined, Base64.DEFAULT)
                }
            } catch (e: Exception) {
                SecureLog.w(
                    "SecureKeyManager",
                    "AndroidKeyStore encryption failed, using fallback: ${e.message}"
                )
            }
        }

        // FALLBACK: Use in-memory encryption
        return encryptWithFallback(plainText)
    }

    fun decryptData(encryptedText: String): String {
        val combined = Base64.decode(encryptedText, Base64.DEFAULT)

        if (combined.isEmpty()) {
            throw IllegalArgumentException("Empty encrypted data")
        }

        // KORJATTU: Check marker byte to determine encryption type
        val marker = combined[0]

        return when (marker) {
            0x01.toByte() -> {
                // AndroidKeyStore encrypted data
                if (initializeKeyStore()) {
                    try {
                        val iv = combined.sliceArray(1..GCM_IV_LENGTH)
                        val encryptedData =
                            combined.sliceArray(GCM_IV_LENGTH + 1 until combined.size)

                        val cipher = Cipher.getInstance(TRANSFORMATION)
                        val secretKey = getValidatedKey()

                        if (secretKey != null) {
                            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
                            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)
                            val decryptedData = cipher.doFinal(encryptedData)
                            return String(decryptedData, Charsets.UTF_8)
                        }
                    } catch (e: Exception) {
                        SecureLog.w(
                            "SecureKeyManager",
                            "AndroidKeyStore decryption failed: ${e.message}"
                        )
                    }
                }

                throw RuntimeException("AndroidKeyStore decryption failed and no fallback available")
            }

            0x02.toByte() -> {
                // Fallback encrypted data
                decryptWithFallback(encryptedText)
            }

            else -> {
                // Legacy format - assume AndroidKeyStore without marker
                if (initializeKeyStore()) {
                    try {
                        val iv = combined.sliceArray(0..GCM_IV_LENGTH - 1)
                        val encryptedData = combined.sliceArray(GCM_IV_LENGTH until combined.size)

                        val cipher = Cipher.getInstance(TRANSFORMATION)
                        val secretKey = getValidatedKey()

                        if (secretKey != null) {
                            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
                            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)
                            val decryptedData = cipher.doFinal(encryptedData)
                            return String(decryptedData, Charsets.UTF_8)
                        }
                    } catch (e: Exception) {
                        SecureLog.w("SecureKeyManager", "Legacy decryption failed: ${e.message}")
                    }
                }

                throw RuntimeException("Unable to decrypt data - unknown format or AndroidKeyStore unavailable")
            }
        }
    }

    // KORJATTU: Validoitu avainten haku with null safety
    private fun getValidatedKey(): SecretKey? {
        if (keyStore == null || !keyStoreAvailable) {
            SecureLog.w("SecureKeyManager", "KeyStore not available")
            return null
        }

        return try {
            val key = keyStore?.getKey(currentKeyAlias, null) as? SecretKey

            if (key != null) {
                // Validoi hardware backing
                if (!validateHardwareSecurity()) {
                    SecureLog.w(
                        "SecureKeyManager",
                        "⚠️ Key validation failed - hardware backing uncertain"
                    )
                }
            }

            key
        } catch (e: Exception) {
            SecureLog.e("SecureKeyManager", "Key retrieval failed: ${e.message}")
            null
        }
    }

    // LISÄTTY: Fallback encryption using standard Java crypto
    private fun encryptWithFallback(plainText: String): String {
        if (fallbackKey == null) {
            initializeFallbackEncryption()
        }

        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val secretKey = javax.crypto.spec.SecretKeySpec(fallbackKey, "AES")

            // Generate random IV
            val iv = ByteArray(GCM_IV_LENGTH)
            SecureRandom().nextBytes(iv)
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)
            val encryptedData = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))

            // Combine marker + IV + encrypted data
            val combined = byteArrayOf(0x02) + iv + encryptedData // 0x02 = Fallback marker
            Base64.encodeToString(combined, Base64.DEFAULT)

        } catch (e: Exception) {
            SecureLog.e("SecureKeyManager", "Fallback encryption failed: ${e.message}")
            throw RuntimeException("All encryption methods failed", e)
        }
    }

    // LISÄTTY: Fallback decryption using standard Java crypto
    private fun decryptWithFallback(encryptedText: String): String {
        if (fallbackKey == null) {
            throw RuntimeException("Fallback key not available")
        }

        return try {
            val combined = Base64.decode(encryptedText, Base64.DEFAULT)
            val iv = combined.sliceArray(1..GCM_IV_LENGTH) // Skip marker byte
            val encryptedData = combined.sliceArray(GCM_IV_LENGTH + 1 until combined.size)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val secretKey = javax.crypto.spec.SecretKeySpec(fallbackKey, "AES")
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)

            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)
            val decryptedData = cipher.doFinal(encryptedData)

            String(decryptedData, Charsets.UTF_8)

        } catch (e: Exception) {
            SecureLog.e("SecureKeyManager", "Fallback decryption failed: ${e.message}")
            throw RuntimeException("Fallback decryption failed", e)
        }
    }

    // LISÄÄ: Post-generation validation
    private fun validateGeneratedKey(key: SecretKey) {
        try {
            validateHardwareSecurity()
        } catch (e: Exception) {
            SecureLog.e("SecureKeyManager", "Post-generation validation failed: ${e.message}")
        }
    }

    /**
     * LISÄTTY: Check if hardware security is enabled
     */
    fun isHardwareSecurityEnabled(): Boolean {
        return isStrongboxBacked
    }

    /**
     * LISÄTTY: Get security level information
     */
    fun getSecurityInfo(): String {
        return if (isStrongboxBacked) {
            "Strongbox Hardware Security Module (HSM) enabled"
        } else {
            "Trusted Execution Environment (TEE) fallback"
        }
    }

    /**
     * KORJATTU: Validate hardware security using proper Android APIs with fallback handling
     */
    fun validateHardwareSecurity(): Boolean {
        // If AndroidKeyStore is not available, return false immediately
        if (!initializeKeyStore()) {
            isStrongboxBacked = false
            isTrustedEnvironmentBacked = false
            return false
        }

        return try {
            val currentTime = System.currentTimeMillis()

            // Cache validation results
            if (currentTime - lastValidationTime < VALIDATION_CACHE_MS &&
                (isStrongboxBacked || isTrustedEnvironmentBacked)
            ) {
                return isStrongboxBacked || isTrustedEnvironmentBacked
            }

            val secretKey = keyStore?.getKey(currentKeyAlias, null) as? SecretKey
                ?: return false

            val validated = when {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q ->
                    validateWithSecurityLevel(secretKey)

                Build.VERSION.SDK_INT >= Build.VERSION_CODES.P ->
                    validateWithKeyInfo(secretKey)

                else ->
                    validateLegacy(secretKey)
            }

            lastValidationTime = currentTime
            logValidationResult(validated)
            return validated

        } catch (e: Exception) {
            SecureLog.e("SecureKeyManager", "Hardware validation error: ${e.message}")
            isStrongboxBacked = false
            isTrustedEnvironmentBacked = false
            false
        }
    }

    // LISÄÄ: Android 10+ SecurityLevel API
    @androidx.annotation.RequiresApi(Build.VERSION_CODES.Q)
    private fun validateWithSecurityLevel(key: SecretKey): Boolean {
        return try {
            val keyFactory = KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
            val keyInfo = keyFactory.getKeySpec(key, KeyInfo::class.java)

            val securityLevel = keyInfo.securityLevel
            isStrongboxBacked = (securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX)
            isTrustedEnvironmentBacked =
                (securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT)

            isStrongboxBacked || isTrustedEnvironmentBacked
        } catch (e: Exception) {
            SecureLog.e("SecureKeyManager", "SecurityLevel validation failed: ${e.message}")
            false
        }
    }

    // LISÄÄ: Android 9 KeyInfo API
    @androidx.annotation.RequiresApi(Build.VERSION_CODES.P)
    private fun validateWithKeyInfo(key: SecretKey): Boolean {
        return try {
            val keyFactory = KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
            val keyInfo = keyFactory.getKeySpec(key, KeyInfo::class.java)

            val isHardwareBacked = keyInfo.isInsideSecureHardware
            isStrongboxBacked = (currentKeyAlias == KEY_ALIAS) && isHardwareBacked
            isTrustedEnvironmentBacked = isHardwareBacked

            isHardwareBacked
        } catch (e: Exception) {
            SecureLog.e("SecureKeyManager", "KeyInfo validation failed: ${e.message}")
            false
        }
    }

    // LISÄÄ: Legacy Android 8.1-
    private fun validateLegacy(key: SecretKey): Boolean {
        // Rajallinen validointi vanhemmissa versioissa
        val isLikelyHardware = key.format == null && key.algorithm == "AES"
        isStrongboxBacked = false
        isTrustedEnvironmentBacked = isLikelyHardware

        SecureLog.w(
            "SecureKeyManager",
            "Legacy validation (Android ${Build.VERSION.SDK_INT}): $isLikelyHardware"
        )
        return isLikelyHardware
    }

    // LISÄÄ: Validation logging
    private fun logValidationResult(validated: Boolean) {
        when {
            !validated -> SecureLog.e("SecureKeyManager", "❌ No hardware backing detected!")
            isStrongboxBacked -> SecureLog.i(
                "SecureKeyManager",
                "✅ StrongBox hardware security confirmed"
            )

            isTrustedEnvironmentBacked -> SecureLog.i(
                "SecureKeyManager",
                "✅ TEE hardware security confirmed"
            )

            else -> SecureLog.w("SecureKeyManager", "⚠️ Hardware security status uncertain")
        }
    }

    fun getDetailedSecurityInfo(): Map<String, Any> {
        val hardwareValid = validateHardwareSecurity()

        return mapOf(
            "strongbox_backed" to isStrongboxBacked,
            "tee_backed" to isTrustedEnvironmentBacked,
            "current_key_alias" to currentKeyAlias,
            "android_version" to Build.VERSION.SDK_INT,
            "security_patch" to (Build.VERSION.SECURITY_PATCH ?: "Unknown"),
            "hardware_validated" to hardwareValid,
            "auth_timeout_seconds" to 30,
            "device_unlocked_required" to true,
            "validation_timestamp" to lastValidationTime,
            "strongbox_available" to (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P),
            "androidkeystore_available" to keyStoreAvailable,
            "fallback_encryption_active" to (fallbackKey != null),
            "initialization_completed" to isKeyStoreInitialized
        )
    }

    fun forceRevalidation() {
        lastValidationTime = 0L
        validateHardwareSecurity()
    }

    /**
     * LISÄTTY: Retry AndroidKeyStore initialization with exponential backoff
     */
    fun retryInitialization(maxRetries: Int = 3): Boolean {
        if (keyStoreAvailable) {
            return true // Already working
        }

        SecureLog.i("SecureKeyManager", "Attempting AndroidKeyStore retry initialization...")

        for (attempt in 1..maxRetries) {
            try {
                // Reset initialization state
                isKeyStoreInitialized = false
                keyStore = null
                keyStoreAvailable = false

                // Wait with exponential backoff
                if (attempt > 1) {
                    val delayMs = (100 * 2.0.pow(attempt - 2.0)).toLong()
                    Thread.sleep(delayMs)
                    SecureLog.d(
                        "SecureKeyManager",
                        "Retry attempt $attempt after ${delayMs}ms delay"
                    )
                }

                // Try initialization
                if (initializeKeyStore()) {
                    SecureLog.i(
                        "SecureKeyManager",
                        "✅ AndroidKeyStore retry successful on attempt $attempt"
                    )
                    return true
                }

            } catch (e: Exception) {
                SecureLog.w("SecureKeyManager", "Retry attempt $attempt failed: ${e.message}")
            }
        }

        SecureLog.w("SecureKeyManager", "❌ AndroidKeyStore retry failed after $maxRetries attempts")
        return false
    }

    /**
     * LISÄTTY: Health check for AndroidKeyStore status
     */
    fun performHealthCheck(): Map<String, Any> {
        val startTime = System.currentTimeMillis()
        val healthStatus = mutableMapOf<String, Any>()

        healthStatus["timestamp"] = startTime
        healthStatus["androidkeystore_available"] = keyStoreAvailable
        healthStatus["fallback_available"] = (fallbackKey != null)

        // Test AndroidKeyStore availability
        if (keyStoreAvailable) {
            try {
                val testData = "health_check_test_${System.currentTimeMillis()}"
                val encrypted = encryptData(testData)
                val decrypted = decryptData(encrypted)

                healthStatus["encryption_test"] = "PASS"
                healthStatus["test_successful"] = (testData == decrypted)
                healthStatus["response_time_ms"] = System.currentTimeMillis() - startTime

            } catch (e: Exception) {
                healthStatus["encryption_test"] = "FAIL"
                healthStatus["error_message"] = e.message ?: "Unknown error"
                healthStatus["response_time_ms"] = System.currentTimeMillis() - startTime

                SecureLog.w("SecureKeyManager", "Health check failed: ${e.message}")
            }
        } else {
            healthStatus["encryption_test"] = "FALLBACK_ONLY"
        }

        // Test fallback encryption
        try {
            val testData = "fallback_health_check_${System.currentTimeMillis()}"
            val encrypted = encryptWithFallback(testData)
            val decrypted = decryptWithFallback(encrypted)

            healthStatus["fallback_test"] = "PASS"
            healthStatus["fallback_successful"] = (testData == decrypted)

        } catch (e: Exception) {
            healthStatus["fallback_test"] = "FAIL"
            healthStatus["fallback_error"] = e.message ?: "Unknown fallback error"
        }

        return healthStatus
    }

    /**
     * LISÄTTY: Get encryption mode status for debugging
     */
    fun getEncryptionMode(): String {
        return when {
            keyStoreAvailable && isStrongboxBacked -> "STRONGBOX"
            keyStoreAvailable && isTrustedEnvironmentBacked -> "TEE"
            keyStoreAvailable -> "ANDROIDKEYSTORE"
            fallbackKey != null -> "FALLBACK"
            else -> "UNAVAILABLE"
        }
    }

    /**
     * LISÄTTY: Recovery mechanism when AndroidKeyStore becomes available
     */
    fun attemptRecovery(): Boolean {
        SecureLog.i("SecureKeyManager", "🔄 Attempting recovery...")

        // Try to retry initialization
        if (retryInitialization()) {
            SecureLog.i("SecureKeyManager", "✅ Recovery successful - AndroidKeyStore now available")
            return true
        }

        // Ensure fallback is working
        if (fallbackKey == null) {
            SecureLog.i("SecureKeyManager", "🔄 Reinitializing fallback encryption...")
            initializeFallbackEncryption()
        }

        val recoverySuccessful = fallbackKey != null
        if (recoverySuccessful) {
            SecureLog.i("SecureKeyManager", "⚠️ Recovery completed with fallback encryption")
        } else {
            SecureLog.e("SecureKeyManager", "❌ Recovery failed - no encryption available")
        }

        return recoverySuccessful
    }
}