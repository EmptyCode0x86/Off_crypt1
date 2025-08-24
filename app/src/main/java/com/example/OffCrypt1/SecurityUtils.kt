package com.example.OffCrypt1

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import java.io.ByteArrayOutputStream
import java.security.Key
import java.security.SecureRandom
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/**
 * Security utilities for sensitive data handling, clipboard management, and memory operations
 * Matches Desktop reference implementation exactly
 */
object SecurityUtils {
    
    private const val SECURE_WIPE_ITERATIONS = 7
    private const val CLIPBOARD_CLEAR_DELAY_SENSITIVE = 600_000L
    private const val CLIPBOARD_CLEAR_DELAY_NORMAL = 600_000L
    
    private val secureRandom = SecureRandom()
    
    /**
     * Get RSA OAEP cipher exactly like Desktop reference
     */
    fun getRSAOAEPCipher(encrypt: Boolean, key: Key): Cipher {
        val c = Cipher.getInstance("RSA/ECB/OAEPPadding")
        val oaep = OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA1, // Same as original OAEP path
            PSource.PSpecified.DEFAULT
        )
        c.init(if (encrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE, key, oaep)
        return c
    }
    
    /**
     * Write 32-bit integer to ByteArrayOutputStream
     */
    fun writeInt32(out: ByteArrayOutputStream, v: Int) {
        out.write(v and 0xFF)
        out.write((v ushr 8) and 0xFF)
        out.write((v ushr 16) and 0xFF)
        out.write((v ushr 24) and 0xFF)
    }
    
    /**
     * Read 32-bit integer from byte array
     */
    fun readInt32(data: ByteArray, off: Int): Int {
        require(off + 4 <= data.size) { "Not enough data" }
        return (data[off].toInt() and 0xFF) or
                ((data[off + 1].toInt() and 0xFF) shl 8) or
                ((data[off + 2].toInt() and 0xFF) shl 16) or
                ((data[off + 3].toInt() and 0xFF) shl 24)
    }
    
    /**
     * Create message with metadata (legacy format)
     */
    fun createMessageWithMetadataLegacy(message: String, expirationEpochMs: Long): String {
        val parts = mutableListOf(
            "msg=$message",
            "burn=${false}",
            "created=${System.currentTimeMillis()}"
        )
        if (expirationEpochMs > 0) parts += "exp=$expirationEpochMs"
        return "META:" + parts.joinToString("|") + ":ENDMETA"
    }
    
    /**
     * Create message with metadata (fixed format)
     */
    fun createMessageWithMetadataFixed(message: String, expirationEpochMs: Long, pfs: Boolean): String {
        val kv = linkedMapOf<String, Any>(
            "msg" to message,
            "burn" to false,
            "created" to System.currentTimeMillis()
        )
        if (expirationEpochMs > 0) kv["exp"] = expirationEpochMs
        if (pfs) kv["pfs"] = true
        
        val json = kv.entries.joinToString(",") { "\"${it.key}\":${if (it.value is String) "\"${it.value}\"" else it.value}" }
        return "{$json}"
    }
    
    /**
     * Parse message metadata (legacy format)
     */
    fun parseMessageMetadataLegacy(messageWithMetadata: String): Map<String, String>? {
        return try {
            if (!messageWithMetadata.startsWith("META:") || !messageWithMetadata.endsWith(":ENDMETA")) {
                return mapOf("msg" to messageWithMetadata)
            }
            
            val content = messageWithMetadata.substring(5, messageWithMetadata.length - 8)
            val parts = content.split("|")
            val result = mutableMapOf<String, String>()
            
            for (part in parts) {
                val eq = part.indexOf('=')
                if (eq > 0) {
                    result[part.substring(0, eq)] = part.substring(eq + 1)
                }
            }
            result
        } catch (e: Exception) {
            mapOf("msg" to messageWithMetadata)
        }
    }
    
    /**
     * Parse message metadata (fixed format)
     */
    fun parseMessageMetadataFixed(messageWithMetadata: String): Map<String, Any>? {
        return try {
            if (!messageWithMetadata.startsWith("{") || !messageWithMetadata.endsWith("}")) {
                return mapOf("msg" to messageWithMetadata)
            }
            
            val content = messageWithMetadata.substring(1, messageWithMetadata.length - 1)
            val result = mutableMapOf<String, Any>()
            
            // Simple JSON-like parsing
            val pairs = content.split(",")
            for (pair in pairs) {
                val colonIndex = pair.indexOf(":")
                if (colonIndex > 0) {
                    val key = pair.substring(0, colonIndex).trim().removeSurrounding("\"")
                    val value = pair.substring(colonIndex + 1).trim()
                    
                    result[key] = when {
                        value == "true" -> true
                        value == "false" -> false
                        value.startsWith("\"") && value.endsWith("\"") -> value.removeSurrounding("\"")
                        else -> value.toLongOrNull() ?: value
                    }
                }
            }
            result
        } catch (e: Exception) {
            mapOf("msg" to messageWithMetadata)
        }
    }
    
    /**
     * Enforce expiration and extract message
     */
    fun enforceExpirationAndExtract(metadata: Map<String, Any>): String {
        val expiration = metadata["exp"]?.toString()?.toLongOrNull() ?: 0L
        if (expiration > 0 && System.currentTimeMillis() > expiration) {
            throw RuntimeException("Message has expired")
        }
        return metadata["msg"]?.toString() ?: ""
    }
    
    /**
     * Strip PEM headers from public key
     */
    fun stripPemHeaders(text: String): String {
        return text
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace("-----BEGIN RSA PUBLIC KEY-----", "")
            .replace("-----END RSA PUBLIC KEY-----", "")
    }
    
    /**
     * Parse file data and metadata
     */
    fun parseFileDataAndMetadata(combined: String): Pair<ByteArray, String> {
        return try {
            // Try JSON format first
            if (combined.startsWith("{")) {
                val jsonStart = combined.indexOf("\"filedata\":\"") + 12
                val jsonEnd = combined.lastIndexOf("\"}")
                
                if (jsonStart > 11 && jsonEnd > jsonStart) {
                    val base64Data = combined.substring(jsonStart, jsonEnd)
                    val fileData = android.util.Base64.decode(base64Data, android.util.Base64.NO_WRAP)
                    
                    val metaStart = combined.indexOf("\"filename\":\"") + 12
                    val metaEnd = combined.indexOf("\"", metaStart)
                    val filename = if (metaStart > 11 && metaEnd > metaStart) {
                        combined.substring(metaStart, metaEnd)
                    } else "decrypted_file"
                    
                    return Pair(fileData, filename)
                }
            }
            
            // Fallback to base64 decode
            val fileData = android.util.Base64.decode(combined, android.util.Base64.NO_WRAP)
            Pair(fileData, "decrypted_file")
        } catch (e: Exception) {
            throw RuntimeException("Failed to parse file data: ${e.message}", e)
        }
    }
    
    /**
     * Constant time comparison for security
     */
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var result = 0
        for (i in a.indices) {
            result = result or (a[i].toInt() xor b[i].toInt())
        }
        return result == 0
    }
    
    /**
     * Securely wipe byte array
     */
    fun secureWipeByteArray(array: ByteArray) {
        try {
            // Multiple passes with random data
            for (iteration in 0 until SECURE_WIPE_ITERATIONS) {
                secureRandom.nextBytes(array)
            }
            // Final pass with zeros
            array.fill(0)
        } catch (e: Exception) {
            Log.w("SecurityUtils", "Failed to securely wipe byte array", e)
        }
    }
    
    /**
     * Securely wipe char array
     */
    fun secureWipeCharArray(array: CharArray) {
        try {
            // Multiple passes with random data
            for (iteration in 0 until SECURE_WIPE_ITERATIONS) {
                for (i in array.indices) {
                    array[i] = secureRandom.nextInt(65536).toChar()
                }
            }
            // Final pass with zeros
            array.fill('\u0000')
        } catch (e: Exception) {
            Log.w("SecurityUtils", "Failed to securely wipe char array", e)
        }
    }
}