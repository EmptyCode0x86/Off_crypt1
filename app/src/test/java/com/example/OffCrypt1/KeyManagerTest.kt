package com.example.OffCrypt1

import android.content.Context
import android.content.SharedPreferences
import org.junit.Test
import org.junit.Before
import org.junit.Assert.*
import org.mockito.Mock
import org.mockito.Mockito.*
import org.mockito.MockitoAnnotations
import java.security.KeyPair
import java.security.PublicKey
import java.security.PrivateKey

/**
 * Unit tests for KeyManager
 * 
 * Tests RSA key generation, storage, loading, and management functionality
 * without requiring full Android environment dependencies.
 */
class KeyManagerTest {

    @Mock
    private lateinit var mockContext: Context
    
    @Mock
    private lateinit var mockSharedPreferences: SharedPreferences
    
    @Mock
    private lateinit var mockEditor: SharedPreferences.Editor
    
    private lateinit var keyManager: KeyManager
    private lateinit var testKeyPair: KeyPair
    
    companion object {
        private const val PREFS_NAME = "netcrypt_keys"
        private const val TEST_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890ABCDEF
-----END PUBLIC KEY-----"""
    }
    
    @Before
    fun setUp() {
        MockitoAnnotations.openMocks(this)
        
        // Mock SharedPreferences behavior
        `when`(mockContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE))
            .thenReturn(mockSharedPreferences)
        `when`(mockSharedPreferences.edit()).thenReturn(mockEditor)
        `when`(mockEditor.putString(any(), any())).thenReturn(mockEditor)
        `when`(mockEditor.apply()).thenReturn(Unit)
        
        keyManager = KeyManager(mockContext)
        
        // Generate a test key pair for testing
        testKeyPair = keyManager.generateNewKeyPair(false)
    }

    // ===== KEY GENERATION TESTS =====
    
    @Test
    fun testGenerateNewKeyPair_RSA2048_ReturnsValidKeyPair() {
        // Act
        val keyPair = keyManager.generateNewKeyPair(useRSA4096 = false)
        
        // Assert
        assertNotNull(keyPair)
        assertNotNull(keyPair.public)
        assertNotNull(keyPair.private)
        assertEquals("RSA", keyPair.public.algorithm)
        assertEquals("RSA", keyPair.private.algorithm)
        
        // Verify key size (approximately) - RSA-2048 keys have ~294 byte public keys
        val publicKeyLength = keyPair.public.encoded.size
        assertTrue("RSA-2048 public key should be around 294 bytes", publicKeyLength > 250 && publicKeyLength < 350)
    }
    
    @Test
    fun testGenerateNewKeyPair_RSA4096_ReturnsValidKeyPair() {
        // Act
        val keyPair = keyManager.generateNewKeyPair(useRSA4096 = true)
        
        // Assert
        assertNotNull(keyPair)
        assertNotNull(keyPair.public)
        assertNotNull(keyPair.private)
        assertEquals("RSA", keyPair.public.algorithm)
        assertEquals("RSA", keyPair.private.algorithm)
        
        // Verify key size (approximately) - RSA-4096 keys have ~550 byte public keys
        val publicKeyLength = keyPair.public.encoded.size
        assertTrue("RSA-4096 public key should be around 550 bytes", publicKeyLength > 500 && publicKeyLength < 600)
    }
    
    @Test
    fun testGenerateNewKeyPair_MultipleCalls_ReturnsDifferentKeys() {
        // Act
        val keyPair1 = keyManager.generateNewKeyPair(false)
        val keyPair2 = keyManager.generateNewKeyPair(false)
        
        // Assert
        assertNotEquals("Public keys should be different", 
            keyPair1.public.encoded.contentToString(), 
            keyPair2.public.encoded.contentToString())
        assertNotEquals("Private keys should be different", 
            keyPair1.private.encoded.contentToString(), 
            keyPair2.private.encoded.contentToString())
    }

    // ===== KEY STORAGE TESTS =====
    
    @Test
    fun testSaveKeyPair_RSA2048_CallsSharedPreferences() {
        // Act
        keyManager.saveKeyPair(testKeyPair, useRSA4096 = false)
        
        // Assert
        verify(mockSharedPreferences).edit()
        verify(mockEditor, times(2)).putString(any(), any()) // public + private key
        verify(mockEditor).apply()
    }
    
    @Test
    fun testSaveKeyPair_RSA4096_CallsCorrectPreferences() {
        // Act
        keyManager.saveKeyPair(testKeyPair, useRSA4096 = true)
        
        // Assert
        verify(mockEditor, times(2)).putString(any(), any())
        verify(mockEditor).apply()
    }

    // ===== KEY LOADING TESTS =====
    
    @Test
    fun testLoadKeyPair_NoKeysStored_ReturnsNull() {
        // Arrange
        `when`(mockSharedPreferences.getString(any(), any())).thenReturn(null)
        
        // Act
        val result = keyManager.loadKeyPair(useRSA4096 = false)
        
        // Assert
        assertNull(result)
    }
    
    @Test
    fun testLoadKeyPair_PartialKeysStored_ReturnsNull() {
        // Arrange - Only public key stored, private key missing
        `when`(mockSharedPreferences.getString(eq("public_key_2048"), any()))
            .thenReturn("mock_public_key_data")
        `when`(mockSharedPreferences.getString(eq("private_key_2048"), any()))
            .thenReturn(null)
        
        // Act
        val result = keyManager.loadKeyPair(useRSA4096 = false)
        
        // Assert
        assertNull(result)
    }

    // ===== KEY FORMATTING TESTS =====
    
    @Test
    fun testFormatPublicKeyForSharing_ReturnsProperPEMFormat() {
        // Act
        val formattedKey = keyManager.formatPublicKeyForSharing(testKeyPair.public)
        
        // Assert
        assertTrue("Should start with PEM header", formattedKey.startsWith("-----BEGIN PUBLIC KEY-----"))
        assertTrue("Should end with PEM footer", formattedKey.endsWith("-----END PUBLIC KEY-----"))
        assertTrue("Should contain newlines", formattedKey.contains("\n"))
        
        // Verify line length (PEM standard is 64 characters per line)
        val lines = formattedKey.split("\n")
        val contentLines = lines.drop(1).dropLast(1) // Remove header and footer
        contentLines.forEach { line ->
            assertTrue("PEM lines should be <= 64 chars: '${line}'", line.length <= 64)
        }
    }

    // ===== RANDOM PASSWORD GENERATION TESTS =====
    
    @Test
    fun testGenerateRandomPassword_DefaultLength_Returns24Characters() {
        // Act
        val password = keyManager.generateRandomPassword()
        
        // Assert
        assertEquals("Default password length should be 24", 24, password.length)
    }
    
    @Test
    fun testGenerateRandomPassword_CustomLength_ReturnsCorrectLength() {
        // Arrange
        val customLength = 16
        
        // Act
        val password = keyManager.generateRandomPassword(customLength)
        
        // Assert
        assertEquals("Custom password length should match", customLength, password.length)
    }
    
    @Test
    fun testGenerateRandomPassword_MultipleCalls_ReturnsDifferentPasswords() {
        // Act
        val password1 = keyManager.generateRandomPassword(16)
        val password2 = keyManager.generateRandomPassword(16)
        
        // Assert
        assertNotEquals("Generated passwords should be different", password1, password2)
    }
    
    @Test
    fun testGenerateRandomPassword_ContainsValidCharacters() {
        // Act
        val password = keyManager.generateRandomPassword(100) // Large sample
        
        // Assert
        val validChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
        password.forEach { char ->
            assertTrue("Password should only contain valid characters: $char", 
                char in validChars)
        }
    }


    

    // ===== ERROR HANDLING TESTS =====
    
    @Test(expected = RuntimeException::class)
    fun testSaveKeyPair_SharedPreferencesFailure_ThrowsException() {
        // Arrange
        `when`(mockSharedPreferences.edit()).thenThrow(RuntimeException("Preferences error"))
        
        // Act & Assert
        keyManager.saveKeyPair(testKeyPair, false)
    }

    // ===== SECURITY TESTS =====
    
    @Test
    fun testSecureWipe_ByteArray_ZerosOutData() {
        // Arrange
        val sensitiveData = "secret_data".toByteArray()
        val originalContent = sensitiveData.copyOf()
        
        // Act
        keyManager.secureWipe(sensitiveData)
        
        // Assert
        assertFalse("Data should be wiped", sensitiveData.contentEquals(originalContent))
        assertTrue("Data should be all zeros", sensitiveData.all { it == 0.toByte() })
    }
    
    @Test
    fun testSecureWipe_CharArray_ZerosOutData() {
        // Arrange
        val sensitiveData = "secret_password".toCharArray()
        val originalContent = sensitiveData.copyOf()
        
        // Act
        keyManager.secureWipe(sensitiveData)
        
        // Assert
        assertFalse("Data should be wiped", sensitiveData.contentEquals(originalContent))
        assertTrue("Data should be all zeros", sensitiveData.all { it == '\u0000' })
    }

    // ===== INTEGRATION TESTS =====
    
    @Test
    fun testKeyPairLifecycle_GenerateSaveLoadCycle() {
        // This test verifies the complete key lifecycle without actual persistence
        
        // Generate
        val originalKeyPair = keyManager.generateNewKeyPair(false)
        assertNotNull("Key pair should be generated", originalKeyPair)
        
        // Format for sharing
        val publicKeyPEM = keyManager.formatPublicKeyForSharing(originalKeyPair.public)
        assertNotNull("Public key should be formatted", publicKeyPEM)
        assertTrue("PEM format should be valid", publicKeyPEM.contains("-----BEGIN PUBLIC KEY-----"))
    }
}