package com.example.OffCrypt1

import android.net.Uri
import android.provider.OpenableColumns
import androidx.appcompat.app.AppCompatActivity
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Manages file encryption and decryption operations
 * Handles both password-based and RSA-based file encryption
 */
class FileEncryptionManager(
    private val activity: AppCompatActivity,
    private val cryptoManager: CryptoManager
) {

    /**
     * Gets file name from URI
     */
    fun getFileName(uri: Uri): String {
        var fileName = "unknown_file"
        val cursor = activity.contentResolver.query(uri, null, null, null, null)
        cursor?.use {
            if (it.moveToFirst()) {
                val displayNameIndex = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (displayNameIndex != -1) {
                    fileName = it.getString(displayNameIndex) ?: fileName
                }
            }
        }
        return fileName
    }

    /**
     * Gets file size from URI
     */
    fun getFileSize(uri: Uri): Long {
        var fileSize = 0L
        val cursor = activity.contentResolver.query(uri, null, null, null, null)
        cursor?.use {
            if (it.moveToFirst()) {
                val sizeIndex = it.getColumnIndex(OpenableColumns.SIZE)
                if (sizeIndex != -1) {
                    fileSize = it.getLong(sizeIndex)
                }
            }
        }
        return fileSize
    }

    /**
     * Formats file size for display
     */
    fun formatFileSize(size: Long): String {
        return when {
            size < 1024 -> "$size B"
            size < 1024 * 1024 -> "${size / 1024} KB"
            size < 1024 * 1024 * 1024 -> "${size / (1024 * 1024)} MB"
            else -> "${size / (1024 * 1024 * 1024)} GB"
        }
    }

    /**
     * Reads file data from URI
     */
    fun readFileData(uri: Uri): ByteArray {
        return activity.contentResolver.openInputStream(uri)?.use { inputStream ->
            inputStream.readBytes()
        } ?: throw RuntimeException("Failed to read file data")
    }

    /**
     * Creates metadata JSON for file
     */
    fun createFileMetadata(fileName: String, fileSize: Long): String {
        val timestamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())
        val fileType = getFileType(fileName)

        return """
        {
            "filename": "$fileName",
            "size": $fileSize,
            "type": "$fileType",
            "encrypted_at": "$timestamp",
            "version": "2.0"
        }
        """.trimIndent()
    }

    /**
     * Determines file type from extension
     */
    private fun getFileType(fileName: String): String {
        return when (fileName.substringAfterLast('.', "").lowercase()) {
            "txt", "md", "log" -> "text"
            "jpg", "jpeg", "png", "gif", "bmp" -> "image"
            "mp4", "avi", "mkv", "mov" -> "video"
            "mp3", "wav", "flac", "ogg" -> "audio"
            "pdf" -> "document"
            "zip", "rar", "7z" -> "archive"
            else -> "binary"
        }
    }



    /**
     * Encrypts file with password and expiration support (ADVANCED METHOD)
     */
    fun encryptFileWithPasswordAdvanced(
        fileData: ByteArray,
        metadata: String,
        password: String
    ): ByteArray {
        return cryptoManager.encryptFileWithPasswordAdvanced(fileData, metadata, password)
    }

    /**
     * Encrypts file with RSA and expiration support (ADVANCED METHOD)
     */
    fun encryptFileWithRSAAdvanced(
        fileData: ByteArray,
        metadata: String,
        recipientPublicKey: PublicKey,
        userKeyPair: KeyPair? = null,
        enablePFS: Boolean = true,
        enableSignatures: Boolean = true,
        expirationTime: Long = 0L
    ): ByteArray {
        return cryptoManager.encryptFileWithRSAAdvanced(
            fileData,
            metadata,
            recipientPublicKey,
            userKeyPair,
            enablePFS,
            enableSignatures,
            expirationTime
        )
    }

    /**
     * Decrypts password-based encrypted file
     */
    fun decryptFileDataPasswordBased(
        encryptedData: ByteArray,
        password: String
    ): Pair<ByteArray, String> {
        return cryptoManager.decryptFileWithPassword(encryptedData, password)
    }

    /**
     * Decrypts RSA-based encrypted file
     */
    fun decryptFileDataRSA(
        encryptedData: ByteArray,
        privateKey: PrivateKey
    ): Pair<ByteArray, String> {
        return cryptoManager.decryptFileWithRSA(encryptedData, privateKey)
    }

    /**
     * Extracts filename from metadata JSON
     */
    fun extractFileNameFromMetadata(metadata: String): String {
        return try {
            val filenameStart = metadata.indexOf("\"filename\": \"") + 13
            val filenameEnd = metadata.indexOf("\"", filenameStart)
            if (filenameStart > 12 && filenameEnd > filenameStart) {
                metadata.substring(filenameStart, filenameEnd)
            } else {
                "decrypted_file"
            }
        } catch (e: Exception) {
            "decrypted_file"
        }
    }

    /**
     * Saves encrypted data to URI
     */
    fun saveEncryptedData(uri: Uri, encryptedData: ByteArray) {
        activity.contentResolver.openOutputStream(uri)?.use { outputStream ->
            outputStream.write(encryptedData)
            outputStream.flush()
        } ?: throw RuntimeException("Failed to save encrypted file")
    }

}