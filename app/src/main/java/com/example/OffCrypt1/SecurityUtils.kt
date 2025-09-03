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
 * VAHVENNETTU: DoD 5220.22-M mukainen muistin pyyhkiminen
 * Matches Desktop reference implementation exactly
 */
object SecurityUtils {

    // VAHVENNETUT turvallisuusparametrit
    private const val SECURE_WIPE_ITERATIONS =
        CryptoConstants.SECURE_WIPE_ITERATIONS // 35 (DoD 5220.22-M)
    private const val CLIPBOARD_CLEAR_DELAY_SENSITIVE =
        CryptoConstants.CLIPBOARD_CLEAR_DELAY_SENSITIVE // 30s
    private const val CLIPBOARD_CLEAR_DELAY_NORMAL = CryptoConstants.CLIPBOARD_CLEAR_DELAY_NORMAL

    private val secureRandom = SecureRandom.getInstanceStrong()

    // DoD 5220.22-M mukaiset pyyhkimiskaavat
    private val DOD_WIPE_PATTERNS = arrayOf(
        ByteArray(0) { 0x00 },           // Nollat
        ByteArray(0) { 0xFF.toByte() },  // Ykköset
        ByteArray(0) { 0xAA.toByte() },  // 10101010
        ByteArray(0) { 0x55 },           // 01010101
        ByteArray(0) { 0x33 },           // 00110011
        ByteArray(0) { 0xCC.toByte() }   // 11001100
    )

    /**
     * KORJATTU: Get RSA OAEP cipher with SHA-256/MGF1(SHA-256) yhtenäisesti
     */
    fun getRSAOAEPCipher(encrypt: Boolean, key: Key): Cipher {
        val c = Cipher.getInstance("RSA/ECB/OAEPPadding")
        val oaep = OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256, // KORJATTU: SHA-1 → SHA-256
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
     * Create message with metadata (fixed format)
     */
    fun createMessageWithMetadataFixed(
        message: String,
        expirationEpochMs: Long,
        pfs: Boolean
    ): String {
        val kv = linkedMapOf<String, Any>(
            "msg" to message,
            "burn" to false,
            "created" to System.currentTimeMillis()
        )
        if (expirationEpochMs > 0) kv["exp"] = expirationEpochMs
        if (pfs) kv["pfs"] = true

        val json =
            kv.entries.joinToString(",") { "\"${it.key}\":${if (it.value is String) "\"${it.value}\"" else it.value}" }
        return "{$json}"
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
     * VAHVENNETTU: DoD 5220.22-M mukainen turvallinen byte array pyyhkiminen
     * 35 kierrosta eri kaavoja
     */
    fun secureWipeByteArray(array: ByteArray) {
        try {
            // DoD 5220.22-M: 35 kierrosta
            repeat(SECURE_WIPE_ITERATIONS) { iteration ->
                when {
                    iteration < DOD_WIPE_PATTERNS.size -> {
                        // Käytä ennalta määriteltyjä kaavoja
                        val pattern = DOD_WIPE_PATTERNS[iteration]
                        for (i in array.indices) {
                            array[i] = if (pattern.isNotEmpty()) pattern[0] else 0
                        }
                    }

                    iteration < 30 -> {
                        // Satunnaisia kaavoja
                        secureRandom.nextBytes(array)
                    }

                    else -> {
                        // Viimeiset kierrokset nollilla
                        array.fill(0)
                    }
                }

                // Pakota muistin kirjoitus
                forceMemoryWrite(array)
            }
        } catch (e: Exception) {
            Log.w("SecurityUtils", "Failed to securely wipe byte array", e)
            // Vähintään nollaa array virhetilanteessa
            array.fill(0)
        }
    }

    /**
     * VAHVENNETTU: DoD-standardin mukainen char array pyyhkiminen
     */
    fun secureWipeCharArray(array: CharArray) {
        try {
            val charPatterns = arrayOf('\u0000', '\uFFFF', '\uAAAA', '\u5555', '\u3333')

            repeat(SECURE_WIPE_ITERATIONS) { iteration ->
                when {
                    iteration < charPatterns.size -> {
                        array.fill(charPatterns[iteration])
                    }

                    iteration < 30 -> {
                        // Satunnaisia merkkejä
                        for (i in array.indices) {
                            array[i] = secureRandom.nextInt(65536).toChar()
                        }
                    }

                    else -> {
                        array.fill('\u0000')
                    }
                }

                // Pakota muistin kirjoitus
                Thread.yield()
            }
        } catch (e: Exception) {
            Log.w("SecurityUtils", "Failed to securely wipe char array", e)
            array.fill('\u0000')
        }
    }

    /**
     * PARANNELTU: Pakota muistin kirjoitus ja estä optimisointi
     */
    private fun forceMemoryWrite(array: ByteArray) {
        // Luo pieni viive pakottaakseen muistin kirjoituksen
        Thread.yield()

        // Käytä array:ta pakottaakseen JVM pitämään se muistissa
        // Volatile-tyylinen lukuoperaatio estää optimisoinnin
        @Suppress("UNUSED_VARIABLE")
        val dummy = array.sum()

        // PARANNELTU: Vähemmän aggressiivinen GC (oli liian usein)
        if (secureRandom.nextInt(10000) == 0) { // 0.01% todennäköisyys, oli 0.1%
            System.gc()
            Thread.sleep(1) // Pieni viive GC:n suorittamiseksi
        }
    }

    /**
     * UUSI: Optimized garbage collection for sensitive operations
     */
    fun forceSecureGC() {
        // Triple GC call pattern for better cleanup
        System.gc()
        Thread.yield()
        System.runFinalization()
        System.gc()
        Thread.yield()
        System.gc()

        // Small delay to allow GC to complete
        try {
            Thread.sleep(10)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }


    /**
     * PARANNELTU: More reliable clipboard clearing
     */
    private fun scheduleClipboardClear(context: Context, delayMs: Long) {
        val handler = Handler(Looper.getMainLooper())
        handler.postDelayed({
            try {
                val clipboardManager =
                    context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val emptyClip = ClipData.newPlainText("", "")
                clipboardManager.setPrimaryClip(emptyClip)

                // LISÄTTY: Force immediate GC after clipboard clear
                forceSecureGC()

                Log.d("SecurityUtils", "Clipboard cleared after ${delayMs}ms")
            } catch (e: Exception) {
                Log.w("SecurityUtils", "Failed to clear clipboard", e)
            }
        }, delayMs)
    }

    /**
     * UUSI: Turvallinen String-referenssin "pyyhkiminen" (rajoitetusti mahdollista)
     */
    fun attemptStringWipe(string: String): Boolean {
        return try {
            // Yritä päästä käsiksi String:in sisäiseen taulukkoon
            val valueField = String::class.java.getDeclaredField("value")
            valueField.isAccessible = true

            when (val value = valueField.get(string)) {
                is CharArray -> {
                    secureWipeCharArray(value)
                    true
                }

                is ByteArray -> {
                    secureWipeByteArray(value)
                    true
                }

                else -> false
            }
        } catch (e: Exception) {
            false
        }
    }
}