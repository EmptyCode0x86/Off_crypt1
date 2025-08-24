package com.example.OffCrypt1

import org.junit.Test
import org.junit.Before
import org.junit.Assert.*
import org.mockito.Mock
import org.mockito.Mockito.*
import org.mockito.MockitoAnnotations
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.PrivateKey

/**
 * Unit tests for MessageCryptoService
 * 
 * Tests the core cryptographic functionality without UI dependencies.
 * Uses mock objects to isolate the service from CryptoManager implementation details.
 */
class MessageCryptoServiceTest {

    @Mock
    private lateinit var mockCryptoManager: CryptoManager
    
    private lateinit var messageCryptoService: MessageCryptoService
    private lateinit var testKeyPair: KeyPair
    
    companion object {
        private const val TEST_MESSAGE = "Hello, World! This is a test message."
        private const val TEST_PASSWORD = "TestPassword123!"
        private const val TEST_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890ABCDEF
-----END PUBLIC KEY-----"""
        private const val MOCK_ENCRYPTED_MESSAGE = "AQACAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8w"
    }
    
    @Before
    fun setUp() {
        MockitoAnnotations.openMocks(this)
        messageCryptoService = MessageCryptoService(mockCryptoManager)
        
        // Generate test RSA key pair
        val keyGen = KeyPairGenerator.getInstance("RSA")
        keyGen.initialize(2048)
        testKeyPair = keyGen.generateKeyPair()
    }

    // ===== PASSWORD ENCRYPTION TESTS =====
    
    @Test
    fun testEncryptWithPassword_ValidInput_ReturnsEncrypted() {
        // Arrange
        `when`(mockCryptoManager.encryptWithPassword(TEST_MESSAGE, TEST_PASSWORD, 0L))
            .thenReturn(MOCK_ENCRYPTED_MESSAGE)
        
        // Act
        val result = messageCryptoService.encryptWithPassword(TEST_MESSAGE, TEST_PASSWORD)
        
        // Assert
        assertEquals(MOCK_ENCRYPTED_MESSAGE, result)
        verify(mockCryptoManager).encryptWithPassword(TEST_MESSAGE, TEST_PASSWORD, 0L)
    }
    
    @Test
    fun testEncryptWithPassword_WithExpiration_PassesExpirationTime() {
        // Arrange
        val expirationTime = System.currentTimeMillis() + 3600000 // 1 hour
        `when`(mockCryptoManager.encryptWithPassword(TEST_MESSAGE, TEST_PASSWORD, expirationTime))
            .thenReturn(MOCK_ENCRYPTED_MESSAGE)
        
        // Act
        val result = messageCryptoService.encryptWithPassword(TEST_MESSAGE, TEST_PASSWORD, expirationTime)
        
        // Assert
        assertEquals(MOCK_ENCRYPTED_MESSAGE, result)
        verify(mockCryptoManager).encryptWithPassword(TEST_MESSAGE, TEST_PASSWORD, expirationTime)
    }
    
    @Test(expected = RuntimeException::class)
    fun testEncryptWithPassword_EmptyPassword_ThrowsException() {
        // Act & Assert
        messageCryptoService.encryptWithPassword(TEST_MESSAGE, "")
    }
    
    @Test(expected = RuntimeException::class)
    fun testEncryptWithPassword_CryptoManagerFailure_ThrowsException() {
        // Arrange
        `when`(mockCryptoManager.encryptWithPassword(any(), any(), any()))
            .thenThrow(RuntimeException("Encryption failed"))
        
        // Act & Assert
        messageCryptoService.encryptWithPassword(TEST_MESSAGE, TEST_PASSWORD)
    }

    // ===== RSA ENCRYPTION TESTS =====
    
    @Test
    fun testEncryptWithRSA_ValidInput_ReturnsEncrypted() {
        // Arrange
        val options = RSAEncryptionOptions()
        `when`(mockCryptoManager.parsePublicKeyFromString(TEST_PUBLIC_KEY))
            .thenReturn(testKeyPair.public)
        `when`(mockCryptoManager.encryptWithRSA(eq(TEST_MESSAGE), eq(testKeyPair.public), eq(false), eq(false), eq(false), eq(false), eq(0L)))
            .thenReturn(MOCK_ENCRYPTED_MESSAGE)
        
        // Act
        val result = messageCryptoService.encryptWithRSA(TEST_MESSAGE, TEST_PUBLIC_KEY, options)
        
        // Assert
        assertEquals(MOCK_ENCRYPTED_MESSAGE, result)
        verify(mockCryptoManager).parsePublicKeyFromString(TEST_PUBLIC_KEY)
        verify(mockCryptoManager).encryptWithRSA(TEST_MESSAGE, testKeyPair.public, false, false, false, false, 0L)
    }
    
    @Test
    fun testEncryptWithRSA_WithRSA4096Option_PassesCorrectParameters() {
        // Arrange
        val options = RSAEncryptionOptions(useRSA4096 = true, enableExpiration = true, expirationTime = 123456789L)
        `when`(mockCryptoManager.parsePublicKeyFromString(TEST_PUBLIC_KEY))
            .thenReturn(testKeyPair.public)
        `when`(mockCryptoManager.encryptWithRSA(any(), any(), eq(true), eq(false), eq(false), eq(true), eq(123456789L)))
            .thenReturn(MOCK_ENCRYPTED_MESSAGE)
        
        // Act
        val result = messageCryptoService.encryptWithRSA(TEST_MESSAGE, TEST_PUBLIC_KEY, options)
        
        // Assert
        assertEquals(MOCK_ENCRYPTED_MESSAGE, result)
        verify(mockCryptoManager).encryptWithRSA(TEST_MESSAGE, testKeyPair.public, true, false, false, true, 123456789L)
    }
    
    @Test(expected = RuntimeException::class)
    fun testEncryptWithRSA_EmptyPublicKey_ThrowsException() {
        // Arrange
        val options = RSAEncryptionOptions()
        
        // Act & Assert
        messageCryptoService.encryptWithRSA(TEST_MESSAGE, "", options)
    }
    
    @Test(expected = RuntimeException::class)
    fun testEncryptWithRSA_InvalidPublicKey_ThrowsException() {
        // Arrange
        val options = RSAEncryptionOptions()
        `when`(mockCryptoManager.parsePublicKeyFromString("invalid-key"))
            .thenThrow(RuntimeException("Invalid key format"))
        
        // Act & Assert
        messageCryptoService.encryptWithRSA(TEST_MESSAGE, "invalid-key", options)
    }

    // ===== DECRYPTION TESTS =====
    
    @Test
    fun testDecryptMessage_PasswordBased_ReturnsDecrypted() {
        // Arrange
        `when`(mockCryptoManager.decryptWithPassword(MOCK_ENCRYPTED_MESSAGE, TEST_PASSWORD))
            .thenReturn(TEST_MESSAGE)
        
        // Act
        val result = messageCryptoService.decryptMessage(MOCK_ENCRYPTED_MESSAGE, TEST_PASSWORD, null)
        
        // Assert
        assertEquals(TEST_MESSAGE, result.message)
        assertEquals(EncryptionMethod.PASSWORD, result.metadata.encryptionMethod)
        verify(mockCryptoManager).decryptWithPassword(MOCK_ENCRYPTED_MESSAGE, TEST_PASSWORD)
    }
    
    @Test
    fun testDecryptMessage_RSABased_ReturnsDecrypted() {
        // Arrange
        val rsaEncryptedMessage = "AgACAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8w" // Version byte 0x02
        `when`(mockCryptoManager.decryptWithRSA(rsaEncryptedMessage, testKeyPair.private, testKeyPair.public))
            .thenReturn(TEST_MESSAGE)
        
        // Act
        val result = messageCryptoService.decryptMessage(rsaEncryptedMessage, null, testKeyPair)
        
        // Assert
        assertEquals(TEST_MESSAGE, result.message)
        assertEquals(EncryptionMethod.RSA_2048, result.metadata.encryptionMethod)
        verify(mockCryptoManager).decryptWithRSA(rsaEncryptedMessage, testKeyPair.private, testKeyPair.public)
    }
    
    @Test(expected = RuntimeException::class)
    fun testDecryptMessage_EmptyMessage_ThrowsException() {
        // Act & Assert
        messageCryptoService.decryptMessage("", TEST_PASSWORD, null)
    }
    
    @Test(expected = RuntimeException::class)
    fun testDecryptMessage_PasswordBasedWithoutPassword_ThrowsException() {
        // Act & Assert
        messageCryptoService.decryptMessage(MOCK_ENCRYPTED_MESSAGE, null, null)
    }
    
    @Test(expected = RuntimeException::class)
    fun testDecryptMessage_RSABasedWithoutKeyPair_ThrowsException() {
        // Arrange
        val rsaEncryptedMessage = "AgACAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8w" // Version byte 0x02
        
        // Act & Assert
        messageCryptoService.decryptMessage(rsaEncryptedMessage, null, null)
    }

    // ===== EDGE CASES AND ERROR HANDLING =====
    
    @Test(expected = RuntimeException::class)
    fun testDecryptMessage_UnknownVersion_ThrowsException() {
        // Arrange - version byte 0xFF (unknown)
        val unknownVersionMessage = "/wACAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8w"
        
        // Act & Assert
        messageCryptoService.decryptMessage(unknownVersionMessage, TEST_PASSWORD, null)
    }
    
    @Test
    fun testRSAEncryptionOptions_DefaultValues_AreCorrect() {
        // Act
        val options = RSAEncryptionOptions()
        
        // Assert
        assertFalse(options.useRSA4096)
        assertFalse(options.enablePFS)
        assertFalse(options.enableSignatures)
        assertFalse(options.enableExpiration)
        assertEquals(0L, options.expirationTime)
    }
    
    @Test
    fun testDecryptionResult_ContainsCorrectMetadata() {
        // Arrange
        `when`(mockCryptoManager.decryptWithPassword(MOCK_ENCRYPTED_MESSAGE, TEST_PASSWORD))
            .thenReturn(TEST_MESSAGE)
        
        // Act
        val result = messageCryptoService.decryptMessage(MOCK_ENCRYPTED_MESSAGE, TEST_PASSWORD, null)
        
        // Assert
        assertNotNull(result.metadata)
        assertEquals(EncryptionMethod.PASSWORD, result.metadata.encryptionMethod)
        assertEquals(1.toByte(), result.metadata.version) // VERSION_BYTE_PASSWORD
        assertFalse(result.metadata.hasExpiration)
    }

    // ===== INTEGRATION-STYLE TESTS (without actual crypto) =====
    
    @Test
    fun testEncryptDecryptFlow_Password_RoundTrip() {
        // Arrange
        `when`(mockCryptoManager.encryptWithPassword(TEST_MESSAGE, TEST_PASSWORD, 0L))
            .thenReturn(MOCK_ENCRYPTED_MESSAGE)
        `when`(mockCryptoManager.decryptWithPassword(MOCK_ENCRYPTED_MESSAGE, TEST_PASSWORD))
            .thenReturn(TEST_MESSAGE)
        
        // Act
        val encrypted = messageCryptoService.encryptWithPassword(TEST_MESSAGE, TEST_PASSWORD)
        val decrypted = messageCryptoService.decryptMessage(encrypted, TEST_PASSWORD, null)
        
        // Assert
        assertEquals(MOCK_ENCRYPTED_MESSAGE, encrypted)
        assertEquals(TEST_MESSAGE, decrypted.message)
    }
    
    @Test
    fun testEncryptDecryptFlow_RSA_RoundTrip() {
        // Arrange
        val options = RSAEncryptionOptions()
        val rsaEncryptedMessage = "AgACAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8w"
        
        `when`(mockCryptoManager.parsePublicKeyFromString(TEST_PUBLIC_KEY))
            .thenReturn(testKeyPair.public)
        `when`(mockCryptoManager.encryptWithRSA(eq(TEST_MESSAGE), eq(testKeyPair.public), any(), any(), any(), any(), any()))
            .thenReturn(rsaEncryptedMessage)
        `when`(mockCryptoManager.decryptWithRSA(rsaEncryptedMessage, testKeyPair.private, testKeyPair.public))
            .thenReturn(TEST_MESSAGE)
        
        // Act
        val encrypted = messageCryptoService.encryptWithRSA(TEST_MESSAGE, TEST_PUBLIC_KEY, options)
        val decrypted = messageCryptoService.decryptMessage(encrypted, null, testKeyPair)
        
        // Assert
        assertEquals(rsaEncryptedMessage, encrypted)
        assertEquals(TEST_MESSAGE, decrypted.message)
    }
}