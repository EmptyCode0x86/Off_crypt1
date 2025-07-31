package com.example.OffCrypt

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.widget.*
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import java.io.ByteArrayOutputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

import androidx.appcompat.widget.SwitchCompat
import android.content.SharedPreferences
import androidx.cardview.widget.CardView
import java.text.SimpleDateFormat
import java.util.*
import android.app.AlertDialog
import android.os.Handler
import android.os.Looper
import java.util.Arrays
import javax.crypto.spec.OAEPParameterSpec
import java.security.spec.MGF1ParameterSpec
import javax.crypto.spec.PSource
import android.os.Build
import android.content.ClipDescription
import android.os.PersistableBundle

import javax.crypto.SecretKey
import javax.crypto.interfaces.PBEKey
import android.graphics.Color
import java.security.Key
import android.content.ComponentCallbacks2
import java.io.File


class SecureMessageActivity : AppCompatActivity() {

    companion object {
        private const val SALT_SIZE = 32
        private const val IV_SIZE = 12
        private const val KEY_LENGTH = 256
        private const val ITERATION_COUNT = 100000
        private const val MAC_SIZE = 32
        private const val GCM_TAG_LENGTH = 16
        private const val VERSION_BYTE_PASSWORD: Byte = 0x01
        private const val VERSION_BYTE_RSA: Byte = 0x02
        private const val VERSION_BYTE_RSA_EXPIRING: Byte = 0x03
        private const val VERSION_BYTE_RSA_SIGNED: Byte = 0x04
        private const val VERSION_BYTE_RSA_PFS: Byte = 0x05
        private const val VERSION_BYTE_RSA_SIGNED_PFS: Byte = 0x06
        private const val VERSION_BYTE_RSA_ALL: Byte = 0x07

        private const val VERSION_BYTE_RSA_4096_AES_FULL: Byte = 0x0A

        private const val KEY_PUBLIC_KEY_2048 = "public_key_2048"
        private const val KEY_PRIVATE_KEY_2048 = "private_key_2048"
        private const val KEY_PUBLIC_KEY_4096 = "public_key_4096"
        private const val KEY_PRIVATE_KEY_4096 = "private_key_4096"

        private const val KEY_MASTER_PASSWORD = "rsa_key_master_2024_v2_aes256gcm"
        private const val ENCRYPTED_KEYS_FILE_2048 = "encrypted_rsa_2048.key"
        private const val ENCRYPTED_KEYS_FILE_4096 = "encrypted_rsa_4096.key"

        private const val RSA_KEY_SIZE = 2048
        private const val RSA_KEY_SIZE_MAX = 4096
        private const val AES_KEY_SIZE = 256
        private const val PREFS_NAME = "SecureMessagePrefs"

        private const val KEY_FAILED_ATTEMPTS = "failed_attempts"
        private const val KEY_LAST_ATTEMPT_TIME = "last_attempt_time"
        private const val MAX_FAILED_ATTEMPTS = 5
        private const val LOCKOUT_DURATION = 300000L

        private const val SECURE_WIPE_ITERATIONS = 7
        private const val CLIPBOARD_CLEAR_DELAY_SENSITIVE = 15_000L
        private const val CLIPBOARD_CLEAR_DELAY_NORMAL = 45_000L

        private val secureRandom = SecureRandom()
    }

    private lateinit var editTextMessage: EditText
    private lateinit var textViewPassword: TextView
    private lateinit var buttonCopyPassword: Button
    private lateinit var editTextEncrypted: EditText
    private lateinit var textViewDecrypted: TextView
    private lateinit var buttonEncrypt: Button
    private lateinit var buttonEncryptToFile: Button
    private lateinit var buttonImportEncryptedFile: Button
    private lateinit var buttonCopy: Button
    private lateinit var buttonCopy1: Button
    private lateinit var buttonDecrypt: Button
    private lateinit var buttonClear: Button
    private lateinit var editTextDecryptPassword: EditText
    private lateinit var switchRandomPassword: SwitchCompat
    private lateinit var editTextCustomPassword: EditText
    private lateinit var buttonGenerateNew: Button
    private lateinit var layoutRandomPassword: LinearLayout
    private lateinit var layoutCustomPassword: LinearLayout

    private lateinit var radioGroupEncryptionMode: RadioGroup
    private lateinit var radioPasswordMode: RadioButton
    private lateinit var radioRSAMode: RadioButton
    private lateinit var radioRSA4096Mode: RadioButton
    private lateinit var layoutPasswordEncryption: LinearLayout
    private lateinit var layoutRSAEncryption: CardView
    private lateinit var textViewPublicKey: TextView
    private lateinit var buttonCopyPublicKey: Button
    private lateinit var buttonGenerateKeyPair: Button
    private lateinit var editTextRecipientPublicKey: EditText
    private lateinit var buttonImportPublicKey: Button
    private lateinit var textViewRSAStatus: TextView
    private lateinit var buttonShowRSAHelp: Button
    private lateinit var textViewRSAHelp: TextView

    private lateinit var switchEnableExpiration: SwitchCompat
    private lateinit var layoutExpirationSettings: LinearLayout
    private lateinit var spinnerExpirationTime: Spinner
    private lateinit var switchBurnAfterReading: SwitchCompat
    private lateinit var textViewSignatureStatus: TextView
    private lateinit var buttonShowSecurityFeatures: Button
    private lateinit var textViewSecurityFeatures: TextView

    private var generatedPassword: String = ""
    private lateinit var sharedPreferences: SharedPreferences
    private var keyPair: KeyPair? = null

    private var lastDecryptedMetadata: String? = null
    private val sensitiveStrings = mutableListOf<String>()
    private val clearClipboardHandler = Handler(Looper.getMainLooper())

    private val expirationOptions = arrayOf(
        "1 hour" to 1L,
        "3 hours" to 3L,
        "6 hours" to 6L,
        "12 hours" to 12L,
        "1 day" to 24L,
        "3 days" to 72L,
        "1 week" to 168L,
        "1 month" to 720L,
        "6 months" to 4320L,
        "1 year" to 8760L
    )

    private val createFileLauncher = registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        uri?.let { saveEncryptedFile(it) }
    }

    private val openFileLauncher = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { loadEncryptedFile(it) }
    }

    private val importPublicKeyLauncher = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { importPublicKeyFromFile(it) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        try {
            setContentView(R.layout.activity_secure_message)
            sharedPreferences = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

            initViews()
            setupClickListeners()
            setupExpirationSpinner()

            if (isAppLocked()) {
                showLockoutMessage()
                return
            }

            generateNewPassword()
            loadKeyPairForCurrentMode()

        } catch (e: Exception) {
            showToast("Application startup failed: ${e.message}")
            finish()
        }
    }

    private fun secureWipeString(original: String): String? {
        if (original.isEmpty()) return null

        return try {
            var success = false

            try {
                val valueField = String::class.java.getDeclaredField("value")
                valueField.isAccessible = true

                when (val value = valueField.get(original)) {
                    is CharArray -> {
                        secureWipeCharArray(value)
                        success = true
                    }
                    is ByteArray -> {
                        secureWipeByteArray(value)
                        success = true
                    }
                }
            } catch (e: NoSuchFieldException) {
                try {
                    val charsField = String::class.java.getDeclaredField("chars")
                    charsField.isAccessible = true
                    val chars = charsField.get(original) as CharArray
                    secureWipeCharArray(chars)
                    success = true
                } catch (ignored: Exception) {}
            }

            try {
                val bytes = original.toByteArray(Charsets.UTF_8)
                secureWipeByteArray(bytes)
            } catch (ignored: Exception) {}

            repeat(3) {
                System.gc()
                System.runFinalization()
                Thread.sleep(10)
            }

            null

        } catch (e: Exception) {
            null
        }
    }

    private fun secureWipeByteArray(array: ByteArray) {
        try {
            val size = array.size
            if (size == 0) return

            val patterns = byteArrayOf(
                0x00.toByte(), 0xFF.toByte(), 0xAA.toByte(), 0x55.toByte(),
                0x92.toByte(), 0x49.toByte(), 0x24.toByte()
            )

            val random = SecureRandom()

            for (pass in patterns.indices) {
                val pattern = patterns[pass]

                for (i in array.indices) {
                    array[i] = pattern
                    @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
                    val barrier = (array as java.lang.Object).hashCode()
                }

                if (pass == patterns.size - 1) {
                    random.nextBytes(array)
                }

                Thread.yield()
            }

            Arrays.fill(array, 0.toByte())

            synchronized(array) {
                @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
                (array as java.lang.Object).notify()
            }

        } catch (e: Exception) {
            try {
                Arrays.fill(array, 0.toByte())
                System.gc()
            } catch (ignored: Exception) {}
        }
    }

    private fun secureWipeCharArray(array: CharArray) {
        try {
            val random = SecureRandom()
            val patterns = charArrayOf('\u0000', '\uFFFF', '\uAAAA', '\u5555')

            for (pattern in patterns) {
                for (i in array.indices) {
                    array[i] = pattern
                    Thread.yield()
                }
            }

            repeat(2) {
                for (i in array.indices) {
                    array[i] = random.nextInt(65536).toChar()
                }
            }

            array.fill('\u0000')
        } catch (e: Exception) {
            array.fill('\u0000')
        }
    }

    private fun addToSensitiveList(data: String) {
        if (data.isNotEmpty() && !sensitiveStrings.contains(data)) {
            sensitiveStrings.add(data)
        }
    }

    private fun secureClearAllSensitiveData() {
        try {
            val sensitiveStringsCopy = sensitiveStrings.toList()
            sensitiveStrings.clear()

            sensitiveStringsCopy.forEach { sensitiveString ->
                secureWipeString(sensitiveString)
            }

            lastDecryptedMetadata?.let {
                secureWipeString(it)
                lastDecryptedMetadata = null
            }

            repeat(3) {
                System.gc()
                System.runFinalization()
                Thread.sleep(100)
            }

            try {
                Runtime.getRuntime().exec("logcat -c")
            } catch (e: Exception) {
            }

        } catch (e: Exception) {
        }
    }

    private fun initViews() {
        try {
            editTextMessage = findViewById(R.id.editTextMessage)
            textViewPassword = findViewById(R.id.textViewPassword)
            buttonCopyPassword = findViewById(R.id.buttonCopyPassword)
            editTextEncrypted = findViewById(R.id.editTextEncrypted)
            editTextDecryptPassword = findViewById(R.id.editTextDecryptPassword)
            textViewDecrypted = findViewById(R.id.textViewDecrypted)
            buttonEncrypt = findViewById(R.id.buttonEncrypt)
            buttonEncryptToFile = findViewById(R.id.buttonEncryptToFile)
            buttonImportEncryptedFile = findViewById(R.id.buttonImportEncryptedFile)
            buttonCopy = findViewById(R.id.buttonCopy)
            buttonCopy1 = findViewById(R.id.buttonCopy1)
            buttonDecrypt = findViewById(R.id.buttonDecrypt)
            buttonClear = findViewById(R.id.buttonClear)
            switchRandomPassword = findViewById(R.id.switchRandomPassword)
            editTextCustomPassword = findViewById(R.id.editTextCustomPassword)
            buttonGenerateNew = findViewById(R.id.buttonGenerateNew)
            layoutRandomPassword = findViewById(R.id.layoutRandomPassword)
            layoutCustomPassword = findViewById(R.id.layoutCustomPassword)

            try {
                radioGroupEncryptionMode = findViewById(R.id.radioGroupEncryptionMode)
                radioPasswordMode = findViewById(R.id.radioPasswordMode)
                radioRSAMode = findViewById(R.id.radioRSAMode)
                radioRSA4096Mode = findViewById(R.id.radioRSA4096Mode)
                layoutPasswordEncryption = findViewById(R.id.layoutPasswordEncryption)
                layoutRSAEncryption = findViewById(R.id.layoutRSAEncryption)
                textViewPublicKey = findViewById(R.id.textViewPublicKey)
                buttonCopyPublicKey = findViewById(R.id.buttonCopyPublicKey)
                buttonGenerateKeyPair = findViewById(R.id.buttonGenerateKeyPair)
                editTextRecipientPublicKey = findViewById(R.id.editTextRecipientPublicKey)
                buttonImportPublicKey = findViewById(R.id.buttonImportPublicKey)
                textViewRSAStatus = findViewById(R.id.textViewRSAStatus)
                buttonShowRSAHelp = findViewById(R.id.buttonShowRSAHelp)
                textViewRSAHelp = findViewById(R.id.textViewRSAHelp)

            } catch (e: Exception) {
                showToast("Failed to load RSA components.")
                throw e
            }

            try {
                switchEnableExpiration = findViewById(R.id.switchEnableExpiration)
                layoutExpirationSettings = findViewById(R.id.layoutExpirationSettings)
                spinnerExpirationTime = findViewById(R.id.spinnerExpirationTime)
                switchBurnAfterReading = findViewById(R.id.switchBurnAfterReading)
                textViewSignatureStatus = findViewById(R.id.textViewSignatureStatus)
                buttonShowSecurityFeatures = findViewById(R.id.buttonShowSecurityFeatures)
                textViewSecurityFeatures = findViewById(R.id.textViewSecurityFeatures)
            } catch (e: Exception) {
                showToast("Failed to load security components.")
                throw e
            }

        } catch (e: Exception) {
            showToast("Component loading failed: ${e.message}")
            throw e
        }
    }

    private fun setupExpirationSpinner() {
        val adapter = object : ArrayAdapter<String>(this, android.R.layout.simple_spinner_item, expirationOptions.map { it.first }) {
            override fun getView(position: Int, convertView: View?, parent: android.view.ViewGroup): View {
                val view = super.getView(position, convertView, parent)
                val textView = view as TextView
                textView.setTextColor(android.graphics.Color.BLACK)
                textView.textSize = 14f
                textView.setPadding(12, 12, 12, 12)
                return view
            }

            override fun getDropDownView(position: Int, convertView: View?, parent: android.view.ViewGroup): View {
                val view = super.getDropDownView(position, convertView, parent)
                val textView = view as TextView
                textView.setTextColor(android.graphics.Color.BLACK)
                textView.textSize = 14f
                textView.setPadding(12, 12, 12, 12)
                return view
            }
        }
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        spinnerExpirationTime.adapter = adapter
        spinnerExpirationTime.setSelection(3)
    }

    private fun setupClickListeners() {
        try {
            buttonEncrypt.setOnClickListener { encryptMessage() }
            buttonEncryptToFile.setOnClickListener { encryptMessageToFile() }
            buttonImportEncryptedFile.setOnClickListener { importEncryptedFile() }
            buttonCopyPassword.setOnClickListener { copyPasswordToClipboard() }
            buttonCopy.setOnClickListener { copyToClipboard() }
            buttonCopy1.setOnClickListener { copyDecryptedToClipboard() }
            buttonDecrypt.setOnClickListener { decryptMessage() }
            buttonClear.setOnClickListener { clearAllFields() }
            buttonGenerateNew.setOnClickListener { generateNewPassword() }

            switchRandomPassword.setOnCheckedChangeListener { _, isChecked ->
                togglePasswordMode(isChecked)
            }

            radioGroupEncryptionMode.setOnCheckedChangeListener { _, checkedId ->
                when (checkedId) {
                    R.id.radioPasswordMode -> switchToPasswordMode()
                    R.id.radioRSAMode -> {
                        switchToRSAMode()
                        loadKeyPairForCurrentMode()
                    }
                    R.id.radioRSA4096Mode -> {
                        switchToRSAMode()
                        loadKeyPairForCurrentMode()
                    }
                }
            }

            buttonGenerateKeyPair.setOnClickListener { generateNewKeyPair() }
            buttonCopyPublicKey.setOnClickListener { copyPublicKeyToClipboard() }

            buttonImportPublicKey.setOnClickListener {
                importPublicKeyLauncher.launch(arrayOf("text/plain", "*/*"))
            }

            buttonShowSecurityFeatures.setOnClickListener {
                if (textViewSecurityFeatures.visibility == View.GONE) {
                    textViewSecurityFeatures.visibility = View.VISIBLE
                    buttonShowSecurityFeatures.text = "🔒 Hide security features"
                    buttonShowSecurityFeatures.setCompoundDrawablesWithIntrinsicBounds(android.R.drawable.arrow_up_float, 0, 0, 0)
                } else {
                    textViewSecurityFeatures.visibility = View.GONE
                    buttonShowSecurityFeatures.text = "🔒 Show security features"
                    buttonShowSecurityFeatures.setCompoundDrawablesWithIntrinsicBounds(android.R.drawable.arrow_down_float, 0, 0, 0)
                }
            }

            buttonShowRSAHelp.setOnClickListener {
                if (textViewRSAHelp.visibility == View.GONE) {
                    textViewRSAHelp.visibility = View.VISIBLE
                    buttonShowRSAHelp.text = "❓ Hide RSA help"
                    buttonShowRSAHelp.setCompoundDrawablesWithIntrinsicBounds(android.R.drawable.arrow_up_float, 0, 0, 0)
                } else {
                    textViewRSAHelp.visibility = View.GONE
                    buttonShowRSAHelp.text = "❓ How does RSA encryption work?"
                    buttonShowRSAHelp.setCompoundDrawablesWithIntrinsicBounds(android.R.drawable.arrow_down_float, 0, 0, 0)
                }
            }

            switchEnableExpiration.setOnCheckedChangeListener { _, isChecked ->
                layoutExpirationSettings.visibility = if (isChecked) View.VISIBLE else View.GONE
            }

        } catch (e: Exception) {
            showToast("Click listeners setup failed: ${e.message}")
            throw e
        }
    }

    private fun getCurrentPassword(): String {
        return try {
            if (switchRandomPassword.isChecked) {
                generatedPassword
            } else {
                editTextCustomPassword.text.toString().trim()
            }
        } catch (e: Exception) {
            showToast("Password retrieval failed: ${e.message}")
            ""
        }
    }

    private fun getCurrentPasswordSecurely(): CharArray? {
        return try {
            if (switchRandomPassword.isChecked) {
                generatedPassword.toCharArray()
            } else {
                getPasswordFromEditTextSecurely(editTextCustomPassword)
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun getPasswordFromEditTextSecurely(editText: EditText): CharArray? {
        return try {
            val editable = editText.text
            val length = editable.length

            if (length == 0) return charArrayOf()

            val password = CharArray(length)

            for (i in 0 until length) {
                password[i] = editable[i]
            }

            password
        } catch (e: Exception) {
            null
        }
    }

    private fun clearPasswordFieldSecurely(editText: EditText) {
        try {
            editText.text.clear()

            try {
                val editableClass = editText.text::class.java
                val fields = editableClass.declaredFields

                for (field in fields) {
                    field.isAccessible = true
                    when (val value = field.get(editText.text)) {
                        is CharArray -> secureWipeCharArray(value)
                        is String -> secureWipeString(value)
                        is ByteArray -> secureWipeByteArray(value)
                    }
                }
            } catch (e: Exception) {
            }

            editText.setText("")
            editText.invalidate()

        } catch (e: Exception) {
            editText.setText("")
        }
    }

    private fun isAppLocked(): Boolean {
        val failedAttempts = sharedPreferences.getInt(KEY_FAILED_ATTEMPTS, 0)
        val lastAttemptTime = sharedPreferences.getLong(KEY_LAST_ATTEMPT_TIME, 0)
        val currentTime = System.currentTimeMillis()

        return failedAttempts >= MAX_FAILED_ATTEMPTS &&
                (currentTime - lastAttemptTime) < LOCKOUT_DURATION
    }

    private fun showLockoutMessage() {
        val remainingTime = LOCKOUT_DURATION - (System.currentTimeMillis() - sharedPreferences.getLong(KEY_LAST_ATTEMPT_TIME, 0))
        val minutes = remainingTime / 60000

        AlertDialog.Builder(this)
            .setTitle("🔒 App locked")
            .setMessage("Too many incorrect passwords. App will unlock in ${minutes + 1} minutes.")
            .setPositiveButton("OK") { _, _ -> finish() }
            .setCancelable(false)
            .show()
    }

    private fun recordFailedAttempt() {
        val currentAttempts = sharedPreferences.getInt(KEY_FAILED_ATTEMPTS, 0)
        sharedPreferences.edit()
            .putInt(KEY_FAILED_ATTEMPTS, currentAttempts + 1)
            .putLong(KEY_LAST_ATTEMPT_TIME, System.currentTimeMillis())
            .apply()
    }

    private fun resetFailedAttempts() {
        sharedPreferences.edit()
            .putInt(KEY_FAILED_ATTEMPTS, 0)
            .putLong(KEY_LAST_ATTEMPT_TIME, 0)
            .apply()
    }

    private fun switchToPasswordMode() {
        try {
            layoutPasswordEncryption.visibility = View.VISIBLE
            layoutRSAEncryption.visibility = View.GONE
        } catch (e: Exception) {
            showToast("Mode switch failed: ${e.message}")
        }
    }

    private fun switchToRSAMode() {
        try {
            layoutPasswordEncryption.visibility = View.GONE
            layoutRSAEncryption.visibility = View.VISIBLE
        } catch (e: Exception) {
            showToast("Mode switch failed: ${e.message}")
        }
    }

    private fun generateNewKeyPair() {
        try {
            showToast("Generating key pair... Please wait.")

            Thread {
                try {
                    val keyPairGenerator = if (android.os.Build.VERSION.SDK_INT >= 23) {
                        try {
                            KeyPairGenerator.getInstance("RSA", "AndroidOpenSSL")
                        } catch (e: Exception) {
                            KeyPairGenerator.getInstance("RSA")
                        }
                    } else {
                        KeyPairGenerator.getInstance("RSA")
                    }
                    val keySize = if (radioRSA4096Mode.isChecked) RSA_KEY_SIZE_MAX else RSA_KEY_SIZE
                    keyPairGenerator.initialize(keySize)
                    val newKeyPair = keyPairGenerator.generateKeyPair()

                    runOnUiThread {
                        keyPair = newKeyPair
                        saveKeyPair()
                        updatePublicKeyDisplay()
                        updateRSAStatus()
                        val sizeText = if (radioRSA4096Mode.isChecked) "RSA-4096" else "RSA-2048"
                        showToast("New $sizeText key pair generated successfully!")
                    }
                } catch (e: Exception) {
                    runOnUiThread {
                        showToast("Key pair generation failed: ${e.message}")
                    }
                }
            }.start()

        } catch (e: Exception) {
            showToast("Key pair generation failed: ${e.message}")
        }
    }

    private fun saveKeyPair() {
        try {
            keyPair?.let { kp ->
                val publicKeyString = Base64.getEncoder().encodeToString(kp.public.encoded)
                val privateKeyString = Base64.getEncoder().encodeToString(kp.private.encoded)

                val keyData = mapOf(
                    "public_key" to publicKeyString,
                    "private_key" to privateKeyString,
                    "key_size" to if (radioRSA4096Mode.isChecked) 4096 else 2048,
                    "created" to System.currentTimeMillis(),
                    "version" to "encrypted_v1"
                )
                val keyJson = keyData.entries.joinToString(",") { "\"${it.key}\":\"${it.value}\"" }
                val keyMessage = "{$keyJson}"

                val encryptedKeyData = encryptPasswordBased(keyMessage, KEY_MASTER_PASSWORD)

                val keyFileName = if (radioRSA4096Mode.isChecked) ENCRYPTED_KEYS_FILE_4096 else ENCRYPTED_KEYS_FILE_2048
                val keyFile = File(filesDir, keyFileName)
                keyFile.writeText(encryptedKeyData)

                val modeText = if (radioRSA4096Mode.isChecked) "RSA-4096" else "RSA-2048"
                showToast("🔐 $modeText key pair encrypted with AES-256-GCM")
            }
        } catch (e: Exception) {
            showToast("❌ Key pair encryption failed: ${e.message}")
        }
    }

    private fun loadKeyPair() {
        try {
            val keyFileName = if (radioRSA4096Mode.isChecked) ENCRYPTED_KEYS_FILE_4096 else ENCRYPTED_KEYS_FILE_2048
            val keyFile = File(filesDir, keyFileName)

            if (!keyFile.exists()) {
                keyPair = null
                textViewPublicKey.text = "No ${if (radioRSA4096Mode.isChecked) "RSA-4096" else "RSA-2048"} key generated"
                return
            }

            val encryptedKeyData = keyFile.readText()

            val decryptedKeyMessage = decryptPasswordBased(encryptedKeyData, KEY_MASTER_PASSWORD)

            val keyData = parseSimpleJson(decryptedKeyMessage)
            val publicKeyBytes = Base64.getDecoder().decode(keyData["public_key"] as String)
            val privateKeyBytes = Base64.getDecoder().decode(keyData["private_key"] as String)

            val keyFactory = KeyFactory.getInstance("RSA")
            val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(publicKeyBytes))
            val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(privateKeyBytes))

            keyPair = KeyPair(publicKey, privateKey)
            updatePublicKeyDisplay()

            val modeText = if (radioRSA4096Mode.isChecked) "RSA-4096" else "RSA-2048"
            showToast("✅ $modeText key pair loaded from encrypted file")

        } catch (e: Exception) {
            showToast("❌ Encrypted key pair loading failed: ${e.message}")
            keyPair = null
            textViewPublicKey.text = "Encrypted key pair loading failed"
        }
    }

    private fun loadKeyPairForCurrentMode() {
        try {
            loadKeyPair()
            updateRSAStatus()
        } catch (e: Exception) {
            showToast("Mode switch failed: ${e.message}")
        }
    }

    private fun parseSimpleJson(json: String): Map<String, Any> {
        val result = mutableMapOf<String, Any>()

        try {
            val content = json.substring(1, json.length - 1)

            content.split(",").forEach { pair ->
                val parts = pair.split(":", limit = 2)
                if (parts.size == 2) {
                    val key = parts[0].trim().removeSurrounding("\"")
                    val value = parts[1].trim().removeSurrounding("\"")

                    result[key] = when (key) {
                        "created", "key_size" -> value.toLongOrNull() ?: value
                        else -> value
                    }
                }
            }
        } catch (e: Exception) {
            throw RuntimeException("JSON parsing failed: ${e.message}")
        }

        return result
    }

    private fun updatePublicKeyDisplay() {
        try {
            keyPair?.let { kp ->
                val publicKeyString = Base64.getEncoder().encodeToString(kp.public.encoded)
                val displayKey = if (publicKeyString.length > 100) {
                    publicKeyString.substring(0, 50) + "..." + publicKeyString.substring(publicKeyString.length - 50)
                } else {
                    publicKeyString
                }
                textViewPublicKey.text = displayKey
            }
        } catch (e: Exception) {
            showToast("Public key display failed: ${e.message}")
        }
    }

    private fun updateRSAStatus() {
        try {
            if (keyPair != null) {
                val keySize = if (radioRSA4096Mode.isChecked) "RSA-4096" else "RSA-2048"
                val encryption = "AES-256-GCM"
                val apiLevel = android.os.Build.VERSION.SDK_INT

                textViewRSAStatus.text = "✅ $keySize key pair OK | $encryption (API $apiLevel)"
                textViewRSAStatus.setTextColor(resources.getColor(android.R.color.holo_green_dark, theme))
            } else {
                textViewRSAStatus.text = "⚠️ Generate key pair first for RSA encryption"
                textViewRSAStatus.setTextColor(resources.getColor(android.R.color.holo_orange_dark, theme))
            }

        } catch (e: Exception) {
            showToast("Status update failed: ${e.message}")
        }
    }

    private fun copyPublicKeyToClipboard() {
        try {
            keyPair?.let { kp ->
                val publicKeyString = Base64.getEncoder().encodeToString(kp.public.encoded)
                copyToClipboardSecurely(publicKeyString, "Public key", false)
            } ?: showToast("No public key to copy!")
        } catch (e: Exception) {
            showToast("Copy failed: ${e.message}")
        }
    }

    private fun importPublicKeyFromFile(uri: Uri) {
        try {
            val inputStream: InputStream? = contentResolver.openInputStream(uri)
            val publicKeyString = inputStream?.bufferedReader()?.use { it.readText() }?.trim()

            if (publicKeyString != null && publicKeyString.isNotEmpty()) {
                editTextRecipientPublicKey.setText(publicKeyString)
                showToast("Public key loaded from file!")
            } else {
                showToast("File is empty or invalid!")
            }
        } catch (e: Exception) {
            showToast("Key loading failed: ${e.message}")
        }
    }

    private fun togglePasswordMode(useRandomPassword: Boolean) {
        try {
            if (useRandomPassword) {
                layoutRandomPassword.visibility = View.VISIBLE
                layoutCustomPassword.visibility = View.GONE
                generateNewPassword()
            } else {
                layoutRandomPassword.visibility = View.GONE
                layoutCustomPassword.visibility = View.VISIBLE
            }
        } catch (e: Exception) {
            showToast("Password mode switch failed: ${e.message}")
        }
    }

    private fun encryptMessage() {
        try {
            val message = editTextMessage.text.toString().trim()

            if (message.isEmpty()) {
                showToast("Enter message first!")
                return
            }

            val encryptedMessage = if (radioPasswordMode.isChecked) {
                encryptWithPassword(message)
            } else {
                encryptWithRSA(message)
            }

            editTextEncrypted.setText(encryptedMessage)
            showEncryptionInfo()

        } catch (e: Exception) {
            showToast("Encryption failed: ${e.message}")
        }
    }

    private fun showEncryptionInfo() {
        val features = mutableListOf<String>()

        when {
            radioRSAMode.isChecked -> {
                features.add("RSA-2048")
                features.add("AES-256-GCM")
                features.add("Digital signature")
                features.add("Perfect Forward Secrecy")
            }
            radioRSA4096Mode.isChecked -> {
                features.add("RSA-4096")
                features.add("AES-256-GCM")
                features.add("SHA-512")
                features.add("ECDH secp256r1")
                features.add("Perfect Forward Secrecy")
                features.add("MAXIMUM SECURITY")
            }
            else -> {
                features.add("AES-256")
            }
        }

        if (switchEnableExpiration.isChecked) {
            val selectedExpiration = expirationOptions[spinnerExpirationTime.selectedItemPosition]
            features.add("Expires: ${selectedExpiration.first}")
        }

        if (switchBurnAfterReading.isChecked) {
            features.add("Self-destructing message")
        }

        showToast("Message encrypted: ${features.joinToString(", ")}")
    }

    private fun encryptWithPassword(message: String): String {
        val password = getCurrentPassword()
        if (password.isEmpty()) {
            throw RuntimeException("Enter password or use generated password!")
        }
        return encryptPasswordBased(message, password)
    }

    private fun encryptWithRSA(message: String): String {
        val recipientPublicKeyString = editTextRecipientPublicKey.text.toString().trim()
        if (recipientPublicKeyString.isEmpty()) {
            throw RuntimeException("Enter recipient's public key!")
        }

        try {
            val keyFactory = KeyFactory.getInstance("RSA")
            val publicKeyBytes = Base64.getDecoder().decode(recipientPublicKeyString)
            val recipientPublicKey = keyFactory.generatePublic(X509EncodedKeySpec(publicKeyBytes))

            return if (radioRSA4096Mode.isChecked) {
                encryptRSA4096WithAESFull(message, recipientPublicKey)
            } else {
                encryptRSAWithAllFeatures(message, recipientPublicKey)
            }
        } catch (e: Exception) {
            throw RuntimeException("Invalid public key: ${e.message}")
        }
    }

    private fun encryptRSA4096WithAESFull(plaintext: String, recipientPublicKey: PublicKey): String {
        try {
            val secureRandom = SecureRandom()

            var expirationTime = 0L
            if (switchEnableExpiration.isChecked) {
                val selectedExpiration = expirationOptions[spinnerExpirationTime.selectedItemPosition]
                expirationTime = System.currentTimeMillis() + (selectedExpiration.second * 60 * 60 * 1000)
            }

            val masterAESKey = ByteArray(32)
            secureRandom.nextBytes(masterAESKey)

            val ecKeyGen = KeyPairGenerator.getInstance("EC")
            ecKeyGen.initialize(ECGenParameterSpec("secp256r1"))
            val ephemeralKeyPair = ecKeyGen.generateKeyPair()

            val rsaCipher = getRSAOAEPCipher(Cipher.ENCRYPT_MODE, recipientPublicKey)
            val encryptedMasterKey = rsaCipher.doFinal(masterAESKey)

            val ephemeralPublicKeyBytes = ephemeralKeyPair.public.encoded
            val combinedInput = masterAESKey + ephemeralPublicKeyBytes.take(32).toByteArray()

            val digest = MessageDigest.getInstance("SHA-512")
            val derivedKeyMaterial = digest.digest(combinedInput)
            val finalAESKey = derivedKeyMaterial.sliceArray(0..31)

            val iv = ByteArray(12)
            secureRandom.nextBytes(iv)

            val messageWithMetadata = createMessageWithMetadataFixed(plaintext, expirationTime, ephemeralKeyPair)

            val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
            val finalAESKeySpec = SecretKeySpec(finalAESKey, "AES")
            val gcmSpec = GCMParameterSpec(128, iv)

            aesCipher.init(Cipher.ENCRYPT_MODE, finalAESKeySpec, gcmSpec)
            val encryptedMessage = aesCipher.doFinal(messageWithMetadata.toByteArray(Charsets.UTF_8))

            var signature: ByteArray? = null
            if (keyPair?.private != null) {
                val sig = Signature.getInstance("SHA512withRSA")
                sig.initSign(keyPair!!.private)
                sig.update(messageWithMetadata.toByteArray(Charsets.UTF_8))
                signature = sig.sign()
            }

            val outputStream = ByteArrayOutputStream()

            outputStream.write(VERSION_BYTE_RSA_4096_AES_FULL.toInt())

            writeInt32(outputStream, encryptedMasterKey.size)
            outputStream.write(encryptedMasterKey)

            outputStream.write(iv)

            writeInt32(outputStream, ephemeralPublicKeyBytes.size)
            outputStream.write(ephemeralPublicKeyBytes)

            if (signature != null) {
                writeInt32(outputStream, signature.size)
                outputStream.write(signature)
            } else {
                writeInt32(outputStream, 0)
            }

            outputStream.write(encryptedMessage)

            return Base64.getEncoder().encodeToString(outputStream.toByteArray())

        } catch (e: Exception) {
            throw RuntimeException("RSA-4096 + AES-256-GCM (full) encryption failed: ${e.message}", e)
        }
    }

    private fun encryptRSAWithAllFeatures(plaintext: String, recipientPublicKey: PublicKey): String {
        try {
            val random = SecureRandom()

            var expirationTime = 0L
            if (switchEnableExpiration.isChecked) {
                val selectedExpiration = expirationOptions[spinnerExpirationTime.selectedItemPosition]
                expirationTime = System.currentTimeMillis() + (selectedExpiration.second * 60 * 60 * 1000)
            }

            val keyGenerator = KeyGenerator.getInstance("AES")
            keyGenerator.init(AES_KEY_SIZE)
            val originalAESKey = keyGenerator.generateKey()

            val ecKeyGen = KeyPairGenerator.getInstance("EC")
            ecKeyGen.initialize(ECGenParameterSpec("secp256r1"))
            val ephemeralKeyPair = ecKeyGen.generateKeyPair()

            val rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING")
            rsaCipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey)
            val encryptedAESKey = rsaCipher.doFinal(originalAESKey.encoded)

            val iv = ByteArray(IV_SIZE)
            random.nextBytes(iv)

            val messageWithMetadata = createMessageWithMetadata(plaintext, expirationTime, ephemeralKeyPair)

            val ephemeralKeyBytes = ephemeralKeyPair.public.encoded.take(32).toByteArray()
            val combinedKeyMaterial = originalAESKey.encoded + ephemeralKeyBytes
            val digest = MessageDigest.getInstance("SHA-256")
            val derivedKey = digest.digest(combinedKeyMaterial)
            val finalAESKey = SecretKeySpec(derivedKey, "AES")

            val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
            aesCipher.init(Cipher.ENCRYPT_MODE, finalAESKey, gcmSpec)
            val encryptedMessage = aesCipher.doFinal(messageWithMetadata.toByteArray(Charsets.UTF_8))

            var signature: ByteArray? = null
            if (keyPair?.private != null) {
                signature = createDigitalSignature(messageWithMetadata, keyPair!!.private)
            }

            val outputStream = ByteArrayOutputStream()
            outputStream.write(VERSION_BYTE_RSA_ALL.toInt())
            outputStream.write(encryptedAESKey.size and 0xFF)
            outputStream.write((encryptedAESKey.size shr 8) and 0xFF)
            outputStream.write(encryptedAESKey)
            outputStream.write(iv)

            if (signature != null) {
                outputStream.write(signature.size and 0xFF)
                outputStream.write((signature.size shr 8) and 0xFF)
                outputStream.write(signature)
            } else {
                outputStream.write(0)
                outputStream.write(0)
            }

            val ephemeralPublicKeyBytes = ephemeralKeyPair.public.encoded
            outputStream.write(ephemeralPublicKeyBytes.size and 0xFF)
            outputStream.write((ephemeralPublicKeyBytes.size shr 8) and 0xFF)
            outputStream.write(ephemeralPublicKeyBytes)

            outputStream.write(encryptedMessage)

            return Base64.getEncoder().encodeToString(outputStream.toByteArray())

        } catch (e: Exception) {
            throw RuntimeException("RSA encryption with all features failed: ${e.message}", e)
        }
    }

    private fun getRSAOAEPCipher(mode: Int, key: Key): Cipher {
        return try {
            val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")

            val oaepParams = OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA1,
                PSource.PSpecified.DEFAULT
            )

            cipher.init(mode, key, oaepParams)
            cipher
        } catch (e: Exception) {
            throw RuntimeException("RSA OAEP not supported on this device: ${e.message}", e)
        }
    }

    private fun writeInt32(outputStream: ByteArrayOutputStream, value: Int) {
        outputStream.write(value and 0xFF)
        outputStream.write((value shr 8) and 0xFF)
        outputStream.write((value shr 16) and 0xFF)
        outputStream.write((value shr 24) and 0xFF)
    }

    private fun readInt32(data: ByteArray, offset: Int): Int {
        if (offset + 4 > data.size) {
            throw RuntimeException("Not enough data to read Int32")
        }
        return (data[offset].toInt() and 0xFF) or
                ((data[offset + 1].toInt() and 0xFF) shl 8) or
                ((data[offset + 2].toInt() and 0xFF) shl 16) or
                ((data[offset + 3].toInt() and 0xFF) shl 24)
    }

    private fun createDigitalSignature(message: String, privateKey: PrivateKey): ByteArray {
        val signature = Signature.getInstance("SHA256withRSA")
        signature.initSign(privateKey)
        signature.update(message.toByteArray(Charsets.UTF_8))
        return signature.sign()
    }

    private fun verifyDigitalSignature(message: String, signatureBytes: ByteArray, publicKey: PublicKey): Boolean {
        return try {
            val signature = Signature.getInstance("SHA256withRSA")
            signature.initVerify(publicKey)
            signature.update(message.toByteArray(Charsets.UTF_8))
            signature.verify(signatureBytes)
        } catch (e: Exception) {
            false
        }
    }

    private fun createMessageWithMetadata(message: String, expirationTime: Long, ephemeralKeyPair: KeyPair?): String {
        val metadata = mutableMapOf(
            "msg" to message,
            "burn" to switchBurnAfterReading.isChecked,
            "created" to System.currentTimeMillis()
        )

        if (expirationTime > 0) {
            metadata["exp"] = expirationTime
        }

        if (ephemeralKeyPair != null) {
            metadata["ephemeral_public"] = Base64.getEncoder().encodeToString(ephemeralKeyPair.public.encoded)
        }

        return "META:" + metadata.entries.joinToString("|") { "${it.key}=${it.value}" } + ":ENDMETA"
    }

    private fun createMessageWithMetadataFixed(message: String, expirationTime: Long, ephemeralKeyPair: KeyPair?): String {
        val metadata = mutableMapOf<String, Any>(
            "msg" to message,
            "burn" to switchBurnAfterReading.isChecked,
            "created" to System.currentTimeMillis(),
            "version" to "2.0"
        )

        if (expirationTime > 0) {
            metadata["exp"] = expirationTime
        }

        if (ephemeralKeyPair != null) {
            metadata["pfs"] = true
        }

        val metadataJson = metadata.entries.joinToString(",") { "\"${it.key}\":\"${it.value}\"" }
        return "{$metadataJson}"
    }

    private fun copyPasswordToClipboard() {
        try {
            val password = getCurrentPassword()
            if (password.isNotEmpty()) {
                copyToClipboardSecurely(password, "Password", true)
                addToSensitiveList(password)
            } else {
                showToast("No password to copy!")
            }
        } catch (e: Exception) {
            showToast("Copy failed: ${e.message}")
        }
    }

    private fun copyToClipboard() {
        try {
            val encryptedText = editTextEncrypted.text.toString()
            if (encryptedText.isEmpty()) {
                showToast("No text to copy!")
                return
            }

            copyToClipboardSecurely(encryptedText, "Encrypted message", false)
        } catch (e: Exception) {
            showToast("Copy failed: ${e.message}")
        }
    }

    private fun copyDecryptedToClipboard() {
        try {
            val decryptedText = textViewDecrypted.text.toString()
            if (decryptedText.isEmpty() || decryptedText == "Decryption failed") {
                showToast("No decrypted message to copy!")
                return
            }

            copyToClipboardSecurely(decryptedText, "Decrypted message", true)
            addToSensitiveList(decryptedText)
        } catch (e: Exception) {
            showToast("Copy failed: ${e.message}")
        }
    }

    private fun copyToClipboardSecurely(text: String, label: String, isHighSecurity: Boolean) {
        try {
            val clipData = ClipData.newPlainText(label, text)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                clipData.description.extras = PersistableBundle().apply {
                    putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
                }
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                clipData.description.extras = PersistableBundle().apply {
                    putBoolean("android.content.extra.IS_SENSITIVE", true)
                }
            }

            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.setPrimaryClip(clipData)

            val clearDelay = if (isHighSecurity) CLIPBOARD_CLEAR_DELAY_SENSITIVE else CLIPBOARD_CLEAR_DELAY_NORMAL

            clearClipboardHandler.removeCallbacksAndMessages(null)

            clearClipboardHandler.postDelayed({
                clearClipboardSecurely()
            }, clearDelay)

            val seconds = clearDelay / 1000
            showToast("📋 Copied securely (cleared in ${seconds}s)")

        } catch (e: Exception) {
            showToast("❌ Copy failed: ${e.message}")
        }
    }

    private fun clearClipboardSecurely() {
        try {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager

            val decoyData = generateSecureDecoyData(512)
            val decoyClip = ClipData.newPlainText("", decoyData)
            clipboard.setPrimaryClip(decoyClip)

            clearClipboardHandler.postDelayed({
                try {
                    val emptyClip = ClipData.newPlainText("", "")
                    clipboard.setPrimaryClip(emptyClip)
                    showToast("🧹 Clipboard cleared securely")
                } catch (ignored: Exception) {}
            }, 100)

        } catch (e: Exception) {
            try {
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
            } catch (ignored: Exception) {}
        }
    }

    private fun generateSecureDecoyData(length: Int): String {
        val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
        val random = SecureRandom()
        return (1..length).map { chars[random.nextInt(chars.length)] }.joinToString("")
    }

    private fun decryptMessage() {
        try {
            val encryptedMessage = editTextEncrypted.text.toString().trim()

            if (encryptedMessage.isEmpty()) {
                showToast("Enter encrypted message!")
                return
            }

            val encryptedData = Base64.getDecoder().decode(encryptedMessage)
            val version = encryptedData[0]

            val decryptedMessage = when (version) {
                VERSION_BYTE_PASSWORD -> {
                    val password = editTextDecryptPassword.text.toString().trim()
                    if (password.isEmpty()) {
                        recordFailedAttempt()
                        throw RuntimeException("Enter password!")
                    }
                    try {
                        val result = decryptPasswordBased(encryptedMessage, password)
                        resetFailedAttempts()
                        result
                    } catch (e: Exception) {
                        recordFailedAttempt()
                        throw e
                    }
                }
                VERSION_BYTE_RSA -> {
                    if (keyPair?.private == null) {
                        throw RuntimeException("Private key missing for decryption!")
                    }
                    decryptRSABased(encryptedMessage, keyPair!!.private)
                }
                VERSION_BYTE_RSA_EXPIRING -> {
                    if (keyPair?.private == null) {
                        throw RuntimeException("Private key missing for decryption!")
                    }
                    decryptRSABasedWithExpiration(encryptedMessage, keyPair!!.private)
                }
                VERSION_BYTE_RSA_SIGNED,
                VERSION_BYTE_RSA_PFS,
                VERSION_BYTE_RSA_SIGNED_PFS,
                VERSION_BYTE_RSA_ALL -> {
                    if (keyPair?.private == null) {
                        throw RuntimeException("Private key missing for decryption!")
                    }
                    decryptRSAWithFeatures(encryptedMessage, keyPair!!.private, version)
                }
                VERSION_BYTE_RSA_4096_AES_FULL -> {
                    if (keyPair?.private == null) {
                        throw RuntimeException("Private key missing for decryption!")
                    }
                    decryptRSA4096WithAESFull(encryptedMessage, keyPair!!.private)
                }
                else -> throw RuntimeException("Unknown encryption version: $version")
            }

            textViewDecrypted.text = decryptedMessage
            showToast("Message decrypted successfully!")
        } catch (e: Exception) {
            if (e.message?.contains("expired") == true) {
                showExpiredMessageDialog(e.message!!)
            } else {
                showToast("Decryption failed: ${e.message}")
                textViewDecrypted.text = "Decryption failed"
            }
        }
    }

    private fun decryptRSA4096WithAESFull(encryptedText: String, privateKey: PrivateKey): String {
        try {
            val encryptedData = Base64.getDecoder().decode(encryptedText)
            var offset = 1

            val masterKeySize = readInt32(encryptedData, offset)
            offset += 4
            val encryptedMasterKey = encryptedData.sliceArray(offset until offset + masterKeySize)
            offset += masterKeySize

            val iv = encryptedData.sliceArray(offset until offset + 12)
            offset += 12

            val ephemeralKeySize = readInt32(encryptedData, offset)
            offset += 4
            var ephemeralKeyBytes: ByteArray? = null
            if (ephemeralKeySize > 0) {
                ephemeralKeyBytes = encryptedData.sliceArray(offset until offset + ephemeralKeySize)
                offset += ephemeralKeySize
            }

            val signatureSize = readInt32(encryptedData, offset)
            offset += 4
            var signature: ByteArray? = null
            if (signatureSize > 0) {
                signature = encryptedData.sliceArray(offset until offset + signatureSize)
                offset += signatureSize
            }

            val encryptedMessage = encryptedData.sliceArray(offset until encryptedData.size)

            val rsaCipher = getRSAOAEPCipher(Cipher.DECRYPT_MODE, privateKey)
            val masterAESKey = rsaCipher.doFinal(encryptedMasterKey)

            var finalAESKey = masterAESKey
            if (ephemeralKeyBytes != null && ephemeralKeyBytes.isNotEmpty()) {
                try {
                    val combinedInput = masterAESKey + ephemeralKeyBytes.take(32).toByteArray()
                    val digest = MessageDigest.getInstance("SHA-512")
                    val derivedKeyMaterial = digest.digest(combinedInput)
                    finalAESKey = derivedKeyMaterial.sliceArray(0..31)

                    showToast("✅ Perfect Forward Secrecy activated (RSA-4096 + AES)")
                } catch (e: Exception) {
                    showToast("⚠️ PFS failed, using master key")
                    finalAESKey = masterAESKey
                }
            }

            val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
            val finalAESKeySpec = SecretKeySpec(finalAESKey, "AES")
            val gcmSpec = GCMParameterSpec(128, iv)

            aesCipher.init(Cipher.DECRYPT_MODE, finalAESKeySpec, gcmSpec)
            val decryptedData = aesCipher.doFinal(encryptedMessage)

            val messageText = String(decryptedData, Charsets.UTF_8)
            addToSensitiveList(messageText)

            val metadata = parseMessageMetadataFixed(messageText)
            val finalMessage = if (metadata != null) {
                val expirationTime = metadata["exp"] as? Long
                if (expirationTime != null && System.currentTimeMillis() > expirationTime) {
                    secureClearAllSensitiveData()
                    val expiredDate = SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()).format(Date(expirationTime))
                    throw RuntimeException("Message has expired ($expiredDate)")
                }

                val burnAfterReading = metadata["burn"] as? Boolean ?: false
                if (burnAfterReading) {
                    showBurnAfterReadingDialog()
                }

                val msg = metadata["msg"] as String
                addToSensitiveList(msg)
                msg
            } else {
                messageText
            }

            if (signature != null) {
                verifySignatureRSA4096Fixed(messageText, signature)
            }

            return finalMessage

        } catch (e: Exception) {
            secureClearAllSensitiveData()
            throw RuntimeException("RSA-4096 + AES-256-GCM (full) decryption failed: ${e.message}", e)
        }
    }

    private fun verifySignatureRSA4096Fixed(message: String, signature: ByteArray) {
        try {
            val recipientPublicKeyString = editTextRecipientPublicKey.text.toString().trim()
            if (recipientPublicKeyString.isNotEmpty()) {
                val keyFactory = KeyFactory.getInstance("RSA")
                val publicKeyBytes = Base64.getDecoder().decode(recipientPublicKeyString)
                val senderPublicKey = keyFactory.generatePublic(X509EncodedKeySpec(publicKeyBytes))

                val sig = Signature.getInstance("SHA512withRSA")
                sig.initVerify(senderPublicKey)
                sig.update(message.toByteArray(Charsets.UTF_8))
                val isValid = sig.verify(signature)

                val statusText = if (isValid) {
                    "✅ RSA-4096 + SHA-512 signature OK - MAXIMUM SECURITY"
                } else {
                    "❌ RSA-4096 signature INVALID - possible forgery"
                }

                val backgroundColor = if (isValid) "#2ecc71" else "#e74c3c"
                textViewSignatureStatus.text = statusText
                textViewSignatureStatus.setBackgroundColor(android.graphics.Color.parseColor(backgroundColor))
                textViewSignatureStatus.visibility = View.VISIBLE
            } else {
                textViewSignatureStatus.text = "⚠️ Sender's key missing - cannot verify signature"
                textViewSignatureStatus.setBackgroundColor(android.graphics.Color.parseColor("#f39c12"))
                textViewSignatureStatus.visibility = View.VISIBLE
            }
        } catch (e: Exception) {
            textViewSignatureStatus.text = "❌ Signature verification failed: ${e.message}"
            textViewSignatureStatus.setBackgroundColor(android.graphics.Color.parseColor("#e74c3c"))
            textViewSignatureStatus.visibility = View.VISIBLE
        }
    }

    private fun parseMessageMetadata(messageWithMetadata: String): Map<String, Any>? {
        return try {
            addToSensitiveList(messageWithMetadata)
            lastDecryptedMetadata = messageWithMetadata

            if (!messageWithMetadata.startsWith("META:") || !messageWithMetadata.contains(":ENDMETA")) {
                return mapOf("msg" to messageWithMetadata)
            }

            val metadataString = messageWithMetadata.substring(5, messageWithMetadata.indexOf(":ENDMETA"))
            val metadata = mutableMapOf<String, Any>()

            metadataString.split("|").forEach { pair ->
                val (key, value) = pair.split("=", limit = 2)
                metadata[key] = when (key) {
                    "exp", "created" -> value.toLong()
                    "burn" -> value.toBoolean()
                    else -> value
                }
            }

            addToSensitiveList(metadataString)
            metadata
        } catch (e: Exception) {
            null
        }
    }

    private fun parseMessageMetadataFixed(messageWithMetadata: String): Map<String, Any>? {
        return try {
            addToSensitiveList(messageWithMetadata)
            lastDecryptedMetadata = messageWithMetadata

            if (messageWithMetadata.startsWith("{") && messageWithMetadata.endsWith("}")) {
                val metadata = mutableMapOf<String, Any>()
                val jsonContent = messageWithMetadata.substring(1, messageWithMetadata.length - 1)

                jsonContent.split(",").forEach { pair ->
                    val parts = pair.split(":", limit = 2)
                    if (parts.size == 2) {
                        val key = parts[0].trim().removeSurrounding("\"")
                        val value = parts[1].trim().removeSurrounding("\"")

                        metadata[key] = when (key) {
                            "exp", "created" -> value.toLongOrNull() ?: 0L
                            "burn", "pfs" -> value.toBooleanStrictOrNull() ?: false
                            else -> value
                        }
                    }
                }

                addToSensitiveList(jsonContent)
                metadata
            } else {
                parseOldMetadataFormat(messageWithMetadata)
            }
        } catch (e: Exception) {
            mapOf("msg" to messageWithMetadata)
        }
    }

    private fun parseOldMetadataFormat(messageWithMetadata: String): Map<String, Any>? {
        return if (messageWithMetadata.startsWith("META:") && messageWithMetadata.contains(":ENDMETA")) {
            val metadataString = messageWithMetadata.substring(5, messageWithMetadata.indexOf(":ENDMETA"))
            val metadata = mutableMapOf<String, Any>()

            metadataString.split("|").forEach { pair ->
                val parts = pair.split("=", limit = 2)
                if (parts.size == 2) {
                    val key = parts[0]
                    val value = parts[1]
                    metadata[key] = when (key) {
                        "exp", "created" -> value.toLongOrNull() ?: 0L
                        "burn" -> value.toBooleanStrictOrNull() ?: false
                        else -> value
                    }
                }
            }

            addToSensitiveList(metadataString)
            metadata
        } else {
            mapOf("msg" to messageWithMetadata)
        }
    }

    private fun decryptRSAWithFeatures(encryptedText: String, privateKey: PrivateKey, version: Byte): String {
        try {
            val encryptedData = Base64.getDecoder().decode(encryptedText)
            var offset = 1

            if (offset + 2 > encryptedData.size) {
                throw RuntimeException("Corrupted data: AES key size missing")
            }

            val aesKeySize = (encryptedData[offset].toInt() and 0xFF) or
                    ((encryptedData[offset + 1].toInt() and 0xFF) shl 8)
            offset += 2

            if (aesKeySize <= 0 || aesKeySize > 1024) {
                throw RuntimeException("Invalid AES key size: $aesKeySize")
            }

            if (offset + aesKeySize > encryptedData.size) {
                throw RuntimeException("Corrupted data: AES key missing")
            }

            val encryptedAESKey = encryptedData.copyOfRange(offset, offset + aesKeySize)
            offset += aesKeySize

            if (offset + IV_SIZE > encryptedData.size) {
                throw RuntimeException("Corrupted data: IV missing")
            }

            val iv = encryptedData.copyOfRange(offset, offset + IV_SIZE)
            offset += IV_SIZE

            if (offset + 2 > encryptedData.size) {
                throw RuntimeException("Corrupted data: signature size missing")
            }

            val signatureSize = (encryptedData[offset].toInt() and 0xFF) or
                    ((encryptedData[offset + 1].toInt() and 0xFF) shl 8)
            offset += 2

            var signature: ByteArray? = null
            if (signatureSize > 0) {
                if (offset + signatureSize > encryptedData.size) {
                    throw RuntimeException("Corrupted data: signature missing")
                }
                signature = encryptedData.copyOfRange(offset, offset + signatureSize)
                offset += signatureSize
            }

            if (offset + 2 > encryptedData.size) {
                throw RuntimeException("Corrupted data: ephemeral key size missing")
            }

            val ephemeralKeySize = (encryptedData[offset].toInt() and 0xFF) or
                    ((encryptedData[offset + 1].toInt() and 0xFF) shl 8)
            offset += 2

            var ephemeralKeyBytes: ByteArray? = null
            if (ephemeralKeySize > 0) {
                if (offset + ephemeralKeySize > encryptedData.size) {
                    throw RuntimeException("Corrupted data: ephemeral key missing")
                }
                ephemeralKeyBytes = encryptedData.copyOfRange(offset, offset + ephemeralKeySize)
                offset += ephemeralKeySize
            }

            if (offset >= encryptedData.size) {
                throw RuntimeException("Corrupted data: encrypted message missing")
            }

            val encryptedMessage = encryptedData.copyOfRange(offset, encryptedData.size)

            try {
                val rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING")
                rsaCipher.init(Cipher.DECRYPT_MODE, privateKey)
                val originalAESKeyBytes = rsaCipher.doFinal(encryptedAESKey)
                val originalAESKey = SecretKeySpec(originalAESKeyBytes, "AES")

                var finalAESKey = originalAESKey
                if (ephemeralKeyBytes != null && ephemeralKeyBytes.isNotEmpty()) {
                    try {
                        val ephemeralKeyMaterial = ephemeralKeyBytes.take(32).toByteArray()
                        val combinedKeyMaterial = originalAESKey.encoded + ephemeralKeyMaterial
                        val digest = MessageDigest.getInstance("SHA-256")
                        val derivedKey = digest.digest(combinedKeyMaterial)
                        finalAESKey = SecretKeySpec(derivedKey, "AES")

                        showToast("Perfect Forward Secrecy enabled")
                    } catch (e: Exception) {
                        showToast("ECDH failed, using basic AES key")
                        finalAESKey = originalAESKey
                    }
                }

                val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
                val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
                aesCipher.init(Cipher.DECRYPT_MODE, finalAESKey, gcmSpec)
                val decryptedData = aesCipher.doFinal(encryptedMessage)

                val messageText = String(decryptedData, Charsets.UTF_8)
                addToSensitiveList(messageText)

                val metadata = parseMessageMetadata(messageText)
                val finalMessage = if (metadata != null) {
                    val expirationTime = metadata["exp"] as? Long
                    if (expirationTime != null && System.currentTimeMillis() > expirationTime) {
                        secureClearAllSensitiveData()
                        val expiredDate = SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()).format(Date(expirationTime))
                        throw RuntimeException("Message has expired ($expiredDate)")
                    }

                    val burnAfterReading = metadata["burn"] as? Boolean ?: false
                    if (burnAfterReading) {
                        showBurnAfterReadingDialog()
                    }

                    val msg = metadata["msg"] as String
                    addToSensitiveList(msg)
                    msg
                } else {
                    messageText
                }

                if (signature != null) {
                    showSignatureStatus(messageText, signature)
                }

                return finalMessage

            } catch (e: Exception) {
                throw RuntimeException("RSA decryption failed. Check that you're using the correct private key: ${e.message}")
            }

        } catch (e: Exception) {
            secureClearAllSensitiveData()
            throw RuntimeException("RSA decryption failed: ${e.message}")
        }
    }

    private fun showSignatureStatus(message: String, signature: ByteArray) {
        try {
            val recipientPublicKeyString = editTextRecipientPublicKey.text.toString().trim()
            if (recipientPublicKeyString.isNotEmpty()) {
                val keyFactory = KeyFactory.getInstance("RSA")
                val publicKeyBytes = Base64.getDecoder().decode(recipientPublicKeyString)
                val senderPublicKey = keyFactory.generatePublic(X509EncodedKeySpec(publicKeyBytes))

                val isValid = verifyDigitalSignature(message, signature, senderPublicKey)

                val statusText = if (isValid) {
                    "✅ Signature verified - message is authentic"
                } else {
                    "❌ Signature invalid - message may be forged"
                }

                val backgroundColor = if (isValid) "#27ae60" else "#e74c3c"

                textViewSignatureStatus.text = statusText
                textViewSignatureStatus.setBackgroundColor(android.graphics.Color.parseColor(backgroundColor))
                textViewSignatureStatus.visibility = View.VISIBLE
            } else {
                textViewSignatureStatus.text = "⚠️ No sender key - cannot verify signature"
                textViewSignatureStatus.setBackgroundColor(android.graphics.Color.parseColor("#f39c12"))
                textViewSignatureStatus.visibility = View.VISIBLE
            }
        } catch (e: Exception) {
            textViewSignatureStatus.text = "❌ Signature verification failed"
            textViewSignatureStatus.setBackgroundColor(android.graphics.Color.parseColor("#e74c3c"))
            textViewSignatureStatus.visibility = View.VISIBLE
        }
    }

    private fun decryptRSABasedWithExpiration(encryptedText: String, privateKey: PrivateKey): String {
        try {
            val encryptedData = Base64.getDecoder().decode(encryptedText)
            var offset = 1

            val aesKeySize = (encryptedData[offset].toInt() and 0xFF) or
                    ((encryptedData[offset + 1].toInt() and 0xFF) shl 8)
            offset += 2

            val encryptedAESKey = encryptedData.copyOfRange(offset, offset + aesKeySize)
            offset += aesKeySize

            val iv = encryptedData.copyOfRange(offset, offset + IV_SIZE)
            offset += IV_SIZE

            val encryptedMessage = encryptedData.copyOfRange(offset, encryptedData.size)

            val rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING")
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey)
            val aesKeyBytes = rsaCipher.doFinal(encryptedAESKey)
            val aesKey = SecretKeySpec(aesKeyBytes, "AES")

            val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec)
            val decryptedData = aesCipher.doFinal(encryptedMessage)

            val messageWithMetadata = String(decryptedData, Charsets.UTF_8)
            val metadata = parseMessageMetadata(messageWithMetadata)

            if (metadata != null) {
                val expirationTime = metadata["exp"] as? Long
                if (expirationTime != null && System.currentTimeMillis() > expirationTime) {
                    val expiredDate = SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()).format(Date(expirationTime))
                    throw RuntimeException("Message has expired ($expiredDate)")
                }

                val burnAfterReading = metadata["burn"] as? Boolean ?: false
                if (burnAfterReading) {
                    showBurnAfterReadingDialog()
                }

                return metadata["msg"] as String
            }

            return messageWithMetadata

        } catch (e: Exception) {
            throw RuntimeException("RSA decryption with expiring message failed: ${e.message}")
        }
    }

    private fun decryptRSABased(encryptedText: String, privateKey: PrivateKey): String {
        try {
            val encryptedData = Base64.getDecoder().decode(encryptedText)
            var offset = 1

            val aesKeySize = (encryptedData[offset].toInt() and 0xFF) or
                    ((encryptedData[offset + 1].toInt() and 0xFF) shl 8)
            offset += 2

            val encryptedAESKey = encryptedData.copyOfRange(offset, offset + aesKeySize)
            offset += aesKeySize

            val iv = encryptedData.copyOfRange(offset, offset + IV_SIZE)
            offset += IV_SIZE

            val encryptedMessage = encryptedData.copyOfRange(offset, encryptedData.size)

            val rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING")
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey)
            val aesKeyBytes = rsaCipher.doFinal(encryptedAESKey)
            val aesKey = SecretKeySpec(aesKeyBytes, "AES")

            val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec)
            val decryptedData = aesCipher.doFinal(encryptedMessage)

            return String(decryptedData, Charsets.UTF_8)

        } catch (e: Exception) {
            throw RuntimeException("RSA decryption failed", e)
        }
    }

    private fun encryptPasswordBased(plaintext: String, password: String): String {
        try {
            val random = SecureRandom()

            var expirationTime = 0L
            if (switchEnableExpiration.isChecked) {
                val selectedExpiration = expirationOptions[spinnerExpirationTime.selectedItemPosition]
                expirationTime = System.currentTimeMillis() + (selectedExpiration.second * 60 * 60 * 1000)
            }

            val messageWithMetadata = createMessageWithMetadata(plaintext, expirationTime, null)

            val masterSalt = ByteArray(SALT_SIZE)
            val encryptionSalt = ByteArray(SALT_SIZE)
            val macSalt = ByteArray(SALT_SIZE)
            val iv = ByteArray(IV_SIZE)

            random.nextBytes(masterSalt)
            random.nextBytes(encryptionSalt)
            random.nextBytes(macSalt)
            random.nextBytes(iv)

            val encryptionKey = generateSecureKey(password, encryptionSalt, ITERATION_COUNT)
            val macKey = generateSecureKey(password, macSalt, ITERATION_COUNT)

            val keySpec = SecretKeySpec(encryptionKey, "AES")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)

            val encryptedData = cipher.doFinal(messageWithMetadata.toByteArray(Charsets.UTF_8))

            val outputStream = ByteArrayOutputStream()
            outputStream.write(VERSION_BYTE_PASSWORD.toInt())
            outputStream.write(masterSalt)
            outputStream.write(encryptionSalt)
            outputStream.write(macSalt)
            outputStream.write(iv)
            outputStream.write(encryptedData)

            val dataToMac = outputStream.toByteArray()
            val hmac = generateHMAC(dataToMac, macKey)
            outputStream.write(hmac)

            return Base64.getEncoder().encodeToString(outputStream.toByteArray())

        } catch (e: Exception) {
            throw RuntimeException("Encryption failed", e)
        }
    }

    private fun decryptPasswordBased(encryptedText: String, password: String): String {
        try {
            val encryptedData = Base64.getDecoder().decode(encryptedText)

            if (encryptedData.size < 1 + SALT_SIZE * 3 + IV_SIZE + MAC_SIZE + GCM_TAG_LENGTH) {
                throw RuntimeException("Invalid data size")
            }

            var offset = 0

            val version = encryptedData[offset]
            if (version != VERSION_BYTE_PASSWORD) {
                throw RuntimeException("Wrong version for password-based decryption")
            }
            offset += 1

            val masterSalt = encryptedData.copyOfRange(offset, offset + SALT_SIZE)
            offset += SALT_SIZE

            val encryptionSalt = encryptedData.copyOfRange(offset, offset + SALT_SIZE)
            offset += SALT_SIZE

            val macSalt = encryptedData.copyOfRange(offset, offset + SALT_SIZE)
            offset += SALT_SIZE

            val iv = encryptedData.copyOfRange(offset, offset + IV_SIZE)
            offset += IV_SIZE

            val encryptedContent = encryptedData.copyOfRange(offset, encryptedData.size - MAC_SIZE)
            val receivedMac = encryptedData.copyOfRange(encryptedData.size - MAC_SIZE, encryptedData.size)

            val encryptionKey = generateSecureKey(password, encryptionSalt, ITERATION_COUNT)
            val macKey = generateSecureKey(password, macSalt, ITERATION_COUNT)

            val dataToVerify = encryptedData.copyOfRange(0, encryptedData.size - MAC_SIZE)
            if (!verifyHMAC(dataToVerify, receivedMac, macKey)) {
                throw RuntimeException("HMAC verification failed")
            }

            val keySpec = SecretKeySpec(encryptionKey, "AES")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)

            val decryptedData = cipher.doFinal(encryptedContent)

            val messageWithMetadata = String(decryptedData, Charsets.UTF_8)

            addToSensitiveList(messageWithMetadata)
            addToSensitiveList(password)

            val metadata = parseMessageMetadata(messageWithMetadata)
            if (metadata != null) {
                val expirationTime = metadata["exp"] as? Long
                if (expirationTime != null && System.currentTimeMillis() > expirationTime) {
                    secureClearAllSensitiveData()
                    val expiredDate = SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()).format(Date(expirationTime))
                    throw RuntimeException("Message has expired ($expiredDate)")
                }

                val burnAfterReading = metadata["burn"] as? Boolean ?: false
                if (burnAfterReading) {
                    showBurnAfterReadingDialog()
                }

                val finalMessage = metadata["msg"] as String
                addToSensitiveList(finalMessage)
                return finalMessage
            }

            return messageWithMetadata

        } catch (e: Exception) {
            secureClearAllSensitiveData()
            throw RuntimeException("Decryption failed", e)
        }
    }

    private fun encryptMessageToFile() {
        try {
            val message = editTextMessage.text.toString().trim()

            if (message.isEmpty()) {
                showToast("Enter message first!")
                return
            }

            val timestamp = System.currentTimeMillis()
            val prefix = when {
                radioPasswordMode.isChecked -> "Password"
                radioRSA4096Mode.isChecked -> "RSA4096"
                else -> "RSA"
            }
            val fileName = "${prefix}_encrypted_memo_$timestamp.enc"
            createFileLauncher.launch(fileName)

        } catch (e: Exception) {
            showToast("File creation failed: ${e.message}")
        }
    }

    private fun saveEncryptedFile(uri: Uri) {
        try {
            val message = editTextMessage.text.toString().trim()

            val encryptedMessage = if (radioPasswordMode.isChecked) {
                encryptWithPassword(message)
            } else {
                encryptWithRSA(message)
            }

            contentResolver.openFileDescriptor(uri, "w")?.use { parcelFileDescriptor ->
                FileOutputStream(parcelFileDescriptor.fileDescriptor).use { fileOutputStream ->
                    fileOutputStream.write(encryptedMessage.toByteArray(Charsets.UTF_8))
                }
            }

            val modeText = when {
                radioPasswordMode.isChecked -> "with password"
                radioRSA4096Mode.isChecked -> "RSA-4096 + AES-256-GCM"
                else -> "with RSA keys"
            }
            showToast("Encrypted file saved $modeText!")

        } catch (e: Exception) {
            showToast("File save failed: ${e.message}")
        }
    }

    private fun importEncryptedFile() {
        openFileLauncher.launch(arrayOf("application/octet-stream", "*/*"))
    }

    private fun loadEncryptedFile(uri: Uri) {
        try {
            val inputStream: InputStream? = contentResolver.openInputStream(uri)
            val encryptedContent = inputStream?.bufferedReader()?.use { it.readText() }

            if (encryptedContent != null && encryptedContent.isNotEmpty()) {
                editTextEncrypted.setText(encryptedContent)

                try {
                    val data = Base64.getDecoder().decode(encryptedContent)
                    val version = data[0]
                    val modeText = when (version) {
                        VERSION_BYTE_PASSWORD -> "password encrypted"
                        VERSION_BYTE_RSA -> "RSA key encrypted"
                        VERSION_BYTE_RSA_EXPIRING -> "RSA key encrypted (expiring)"
                        VERSION_BYTE_RSA_SIGNED -> "RSA key encrypted (signed)"
                        VERSION_BYTE_RSA_PFS -> "RSA key encrypted (PFS)"
                        VERSION_BYTE_RSA_SIGNED_PFS -> "RSA key encrypted (signed + PFS)"
                        VERSION_BYTE_RSA_ALL -> "RSA key encrypted (maximum security)"
                        VERSION_BYTE_RSA_4096_AES_FULL -> "RSA-4096 + AES-256-GCM (MAXIMUM)"
                        else -> "unknown"
                    }
                    showToast("$modeText file loaded!")
                } catch (e: Exception) {
                    showToast("File loaded, but type not recognized.")
                }
            } else {
                showToast("File reading failed!")
            }

        } catch (e: Exception) {
            showToast("File load failed: ${e.message}")
        }
    }

    private fun showExpiredMessageDialog(message: String) {
        AlertDialog.Builder(this)
            .setTitle("⏰ Message expired")
            .setMessage(message)
            .setPositiveButton("I understand") { _, _ ->
                textViewDecrypted.text = "❌ MESSAGE HAS EXPIRED"
                editTextEncrypted.text.clear()
            }
            .setCancelable(false)
            .show()
    }

    private fun showBurnAfterReadingDialog() {
        AlertDialog.Builder(this)
            .setTitle("🔥 Self-destructing message")
            .setMessage("This message is marked to be destroyed after reading. The message will be deleted when you close this dialog.")
            .setPositiveButton("I understand") { _, _ ->
                textViewDecrypted.text = "[MESSAGE DESTROYED AFTER READING]"
                editTextEncrypted.text.clear()

                secureClearAllSensitiveData()

                showToast("🔥 All message data securely destroyed")
            }
            .setCancelable(false)
            .show()
    }

    private fun completeDataWipe() {
        try {
            val dialog = AlertDialog.Builder(this)
                .setTitle("⚠️ WARNING: Complete reset")
                .setMessage("This will delete ALL data:\n\n• All RSA keys (2048 & 4096)\n• All passwords\n• All settings\n• All cache\n\nOld messages CANNOT be decrypted anymore!\n\nAre you sure?")
                .setPositiveButton("🗑️ DELETE ALL") { _, _ ->
                    performCompleteWipe()
                }
                .setNegativeButton("Cancel", null)
                .create()

            dialog.setOnShowListener {
                dialog.getButton(AlertDialog.BUTTON_POSITIVE)?.setTextColor(Color.WHITE)
                dialog.getButton(AlertDialog.BUTTON_NEGATIVE)?.setTextColor(Color.WHITE)
            }

            dialog.show()
        } catch (e: Exception) {
            showToast("Reset dialog failed: ${e.message}")
        }
    }

    private fun performCompleteWipe() {
        try {
            showToast("Deleting all data...")

            nuclearSecurityWipe()

            sharedPreferences.edit()
                .remove(KEY_PUBLIC_KEY_2048)
                .remove(KEY_PRIVATE_KEY_2048)
                .remove(KEY_PUBLIC_KEY_4096)
                .remove(KEY_PRIVATE_KEY_4096)
                .remove(KEY_FAILED_ATTEMPTS)
                .remove(KEY_LAST_ATTEMPT_TIME)
                .remove("key_creation_time_2048")
                .remove("key_creation_time_4096")
                .clear()
                .apply()

            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                    val activityManager = getSystemService(Context.ACTIVITY_SERVICE) as android.app.ActivityManager
                    activityManager.clearApplicationUserData()
                }
            } catch (e: Exception) {
            }

            showToast("✅ All data deleted! App will close.")

            Handler(Looper.getMainLooper()).postDelayed({
                finishAffinity()
            }, 2000)

        } catch (e: Exception) {
            showToast("Complete reset failed: ${e.message}")
        }
    }

    private fun clearAllFields() {
        try {
            completeDataWipe()
            editTextMessage.text.clear()
            editTextEncrypted.text.clear()
            clearPasswordFieldSecurely(editTextDecryptPassword)
            clearPasswordFieldSecurely(editTextCustomPassword)
            editTextRecipientPublicKey.text.clear()
            textViewDecrypted.text = ""
            textViewSignatureStatus.visibility = View.GONE

            radioPasswordMode.isChecked = true
            switchToPasswordMode()
            switchRandomPassword.isChecked = true
            togglePasswordMode(true)

            secureClearAllSensitiveData()

        } catch (e: Exception) {
            showToast("Something went wrong: ${e.message}")
        }
    }

    private fun generateNewPassword() {
        try {
            if (generatedPassword.isNotEmpty()) {
                secureWipeString(generatedPassword)
            }

            generatedPassword = generateRandomPassword(24)
            textViewPassword.text = generatedPassword
        } catch (e: Exception) {
            showToast("Password generation failed: ${e.message}")
            generatedPassword = "GENERATION_ERROR"
            textViewPassword.text = generatedPassword
        }
    }

    private fun generateRandomPassword(length: Int): String {
        val chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*"
        val random = SecureRandom()
        return (1..length)
            .map { chars[random.nextInt(chars.length)] }
            .joinToString("")
    }

    private fun generateSecureKey(password: String, salt: ByteArray, iterations: Int): ByteArray {
        val keySpec = PBEKeySpec(password.toCharArray(), salt, iterations, KEY_LENGTH)
        val keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        return keyFactory.generateSecret(keySpec).encoded
    }

    private fun generateHMAC(data: ByteArray, key: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        val secretKey = SecretKeySpec(key, "HmacSHA256")
        mac.init(secretKey)
        return mac.doFinal(data)
    }

    private fun verifyHMAC(data: ByteArray, expectedMac: ByteArray, key: ByteArray): Boolean {
        val computedMac = generateHMAC(data, key)

        if (computedMac.size != expectedMac.size) return false

        var result = 0
        for (i in computedMac.indices) {
            result = result or (computedMac[i].toInt() xor expectedMac[i].toInt())
        }
        return result == 0
    }

    private fun showToast(message: String) {
        try {
            Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            println("Toast failed: $message")
        }
    }

    private fun emergencySecurityWipe() {
        try {
            editTextMessage.text.clear()
            editTextEncrypted.text.clear()
            clearPasswordFieldSecurely(editTextDecryptPassword)
            clearPasswordFieldSecurely(editTextCustomPassword)
            textViewDecrypted.text = ""
            textViewPassword.text = "●●●●●●●●●●●●"

            if (generatedPassword.isNotEmpty()) {
                secureWipeString(generatedPassword)
                generatedPassword = ""
            }

            secureClearAllSensitiveData()

        } catch (e: Exception) {
            try {
                generatedPassword = ""
            } catch (ignored: Exception) {}
        }
    }

    private fun nuclearSecurityWipe() {
        emergencySecurityWipe()

        try {
            keyPair = null

            val allFields = this::class.java.declaredFields

            for (field in allFields) {
                try {
                    field.isAccessible = true
                    when (val value = field.get(this)) {
                        is String -> {
                            if (value.isNotEmpty()) {
                                secureWipeString(value)
                            }
                        }
                        is ByteArray -> secureWipeByteArray(value)
                        is CharArray -> secureWipeCharArray(value)
                        is SecretKey -> {
                            try {
                                if (value is PBEKey) {
                                    val passwordField = value::class.java.getDeclaredField("password")
                                    passwordField.isAccessible = true
                                    val password = passwordField.get(value) as? CharArray
                                    password?.let { secureWipeCharArray(it) }
                                }
                            } catch (ignored: Exception) {}
                        }
                        is KeyPair -> {
                            try {
                                val privateKey = value.private
                                val privateKeyClass = privateKey::class.java
                                val privateKeyFields = privateKeyClass.declaredFields

                                for (keyField in privateKeyFields) {
                                    keyField.isAccessible = true
                                    when (val keyValue = keyField.get(privateKey)) {
                                        is ByteArray -> secureWipeByteArray(keyValue)
                                        is java.math.BigInteger -> {
                                        }
                                    }
                                }

                                field.set(this, null)

                            } catch (ignored: Exception) {}
                        }
                    }
                } catch (e: Exception) {
                }
            }

            try {
                val inputMethodManager = getSystemService(Context.INPUT_METHOD_SERVICE) as? android.view.inputmethod.InputMethodManager
                inputMethodManager?.hideSoftInputFromWindow(currentFocus?.windowToken, 0)
            } catch (e: Exception) {
            }

            repeat(7) {
                System.gc()
                System.runFinalization()
                Thread.sleep(50)
            }

            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                    val activityManager = getSystemService(Context.ACTIVITY_SERVICE) as android.app.ActivityManager
                }
            } catch (e: Exception) {
            }

            try {
                System.gc()
                System.runFinalization()

                try {
                    Runtime.getRuntime().exec(arrayOf("logcat", "-c"))
                } catch (ignored: Exception) {
                }
            } catch (e: Exception) {
            }

        } catch (e: Exception) {
            try {
                keyPair = null
                generatedPassword = ""
                System.gc()
            } catch (ignored: Exception) {}
        }
    }

    override fun onDestroy() {
        super.onDestroy()

        nuclearSecurityWipe()

        clearClipboardHandler.removeCallbacksAndMessages(null)
    }

    override fun onPause() {
        super.onPause()

        emergencySecurityWipe()
    }

    override fun onStop() {
        super.onStop()

        try {
            textViewDecrypted.text = "[HIDDEN FOR SECURITY REASONS]"
            textViewPassword.text = "●●●●●●●●●●●●"

        } catch (e: Exception) {
        }
    }

    override fun onResume() {
        super.onResume()

        try {
            if (isAppLocked()) {
                showLockoutMessage()
                return
            }

            if (keyPair == null) {
                loadKeyPairForCurrentMode()
            }

            updateRSAStatus()
        } catch (e: Exception) {
        }
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)

        when (level) {
            ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN,
            ComponentCallbacks2.TRIM_MEMORY_BACKGROUND,
            ComponentCallbacks2.TRIM_MEMORY_MODERATE,
            ComponentCallbacks2.TRIM_MEMORY_COMPLETE -> {
                emergencySecurityWipe()
            }
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        emergencySecurityWipe()
        super.onBackPressed()
    }

    override fun onUserLeaveHint() {
        super.onUserLeaveHint()
    }
}