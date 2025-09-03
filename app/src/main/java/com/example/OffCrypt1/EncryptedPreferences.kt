package com.example.OffCrypt1

import android.content.Context
import android.content.SharedPreferences

class EncryptedPreferences(context: Context, name: String) {

    private val secureKeyManager = SecureKeyManager(context)
    private val sharedPreferences: SharedPreferences =
        context.getSharedPreferences(name, Context.MODE_PRIVATE)

    fun putString(key: String, value: String) {
        val encryptedValue = secureKeyManager.encryptData(value)
        sharedPreferences.edit()
            .putString(key, encryptedValue)
            .apply()
    }

    fun getString(key: String, defaultValue: String? = null): String? {
        val encryptedValue = sharedPreferences.getString(key, null)
        return if (encryptedValue != null) {
            try {
                secureKeyManager.decryptData(encryptedValue)
            } catch (e: Exception) {
                // Jos dekryptaus epäonnistuu, palautetaan defaultValue
                defaultValue
            }
        } else {
            defaultValue
        }
    }

    fun putInt(key: String, value: Int) {
        putString(key, value.toString())
    }

    fun getInt(key: String, defaultValue: Int): Int {
        val stringValue = getString(key, defaultValue.toString())
        return try {
            stringValue?.toInt() ?: defaultValue
        } catch (e: NumberFormatException) {
            defaultValue
        }
    }

    fun putLong(key: String, value: Long) {
        putString(key, value.toString())
    }

    fun getLong(key: String, defaultValue: Long): Long {
        val stringValue = getString(key, defaultValue.toString())
        return try {
            stringValue?.toLong() ?: defaultValue
        } catch (e: NumberFormatException) {
            defaultValue
        }
    }

    fun putBoolean(key: String, value: Boolean) {
        putString(key, value.toString())
    }

    fun getBoolean(key: String, defaultValue: Boolean): Boolean {
        val stringValue = getString(key, defaultValue.toString())
        return try {
            stringValue?.toBoolean() ?: defaultValue
        } catch (e: Exception) {
            defaultValue
        }
    }

    fun remove(key: String) {
        sharedPreferences.edit()
            .remove(key)
            .apply()
    }

    fun clear() {
        sharedPreferences.edit()
            .clear()
            .apply()
    }

    fun contains(key: String): Boolean {
        return sharedPreferences.contains(key)
    }

    // Compatibility method for getting SharedPreferences.Editor-like functionality
    fun edit(): EncryptedEditor {
        return EncryptedEditor(this)
    }

    // Editor class for batch operations
    class EncryptedEditor(private val encryptedPrefs: EncryptedPreferences) {
        private val pendingOperations = mutableListOf<() -> Unit>()

        fun putString(key: String, value: String): EncryptedEditor {
            pendingOperations.add { encryptedPrefs.putString(key, value) }
            return this
        }

        fun putInt(key: String, value: Int): EncryptedEditor {
            pendingOperations.add { encryptedPrefs.putInt(key, value) }
            return this
        }

        fun putLong(key: String, value: Long): EncryptedEditor {
            pendingOperations.add { encryptedPrefs.putLong(key, value) }
            return this
        }

        fun putBoolean(key: String, value: Boolean): EncryptedEditor {
            pendingOperations.add { encryptedPrefs.putBoolean(key, value) }
            return this
        }

        fun remove(key: String): EncryptedEditor {
            pendingOperations.add { encryptedPrefs.remove(key) }
            return this
        }

        fun clear(): EncryptedEditor {
            pendingOperations.add { encryptedPrefs.clear() }
            return this
        }

        fun apply() {
            pendingOperations.forEach { it.invoke() }
            pendingOperations.clear()
        }

        fun commit(): Boolean {
            return try {
                apply()
                true
            } catch (e: Exception) {
                false
            }
        }
    }
}