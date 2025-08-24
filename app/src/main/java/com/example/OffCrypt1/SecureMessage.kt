package com.example.OffCrypt1

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.text.SpannableString
import android.text.Spanned
import android.text.TextPaint
import android.text.method.LinkMovementMethod
import android.text.style.ClickableSpan
import android.os.Bundle
import android.view.View
import android.widget.*
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.example.OffCrypt1.EncryptedPreferences
import com.example.OffCrypt1.R
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
import com.google.android.material.tabs.TabLayout


class SecureMessage : AppCompatActivity() {

    private lateinit var tabLayoutSecure: com.google.android.material.tabs.TabLayout
    private lateinit var viewEncryptTab: LinearLayout
    private lateinit var viewDecryptTab: LinearLayout
    private lateinit var viewFileEncryptionTab: LinearLayout
    private lateinit var viewInstructionsTab: LinearLayout
    private lateinit var cardViewEncryptedMessage: androidx.cardview.widget.CardView

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
        private const val VERSION_BYTE_FILE_ENCRYPTED: Byte = 0x0B

        private const val KEY_PUBLIC_KEY_2048 = "public_key_2048"
        private const val KEY_PRIVATE_KEY_2048 = "private_key_2048"
        private const val KEY_PUBLIC_KEY_4096 = "public_key_4096"
        private const val KEY_PRIVATE_KEY_4096 = "private_key_4096"

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
        private const val CLIPBOARD_CLEAR_DELAY_SENSITIVE = 600_000L
        private const val CLIPBOARD_CLEAR_DELAY_NORMAL = 600_000L

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

    // File encryption UI elements
    // File encryption password UI elements
    private lateinit var switchFileRandomPassword: SwitchCompat
    // layoutFilePasswordSettings removed - now using cardFilePasswordSettings
    private lateinit var layoutFileRandomPassword: LinearLayout
    private lateinit var layoutFileCustomPassword: LinearLayout
    private lateinit var textViewFilePassword: TextView
    private lateinit var buttonFileCopyPassword: Button
    private lateinit var layoutFileRSAManagement: LinearLayout
    private lateinit var buttonFileGenerateNew: Button
    private lateinit var editTextFileCustomPassword: EditText
    private lateinit var buttonSelectFile: Button
    private lateinit var buttonEncryptFile: Button
    private lateinit var buttonDecryptFile: Button
    private lateinit var textViewSelectedFile: TextView
    private lateinit var textViewFileMessage: TextView
    private lateinit var radioGroupFileEncryptionMode: RadioGroup
    private lateinit var radioFilePasswordMode: RadioButton
    private lateinit var radioFileRSAMode: RadioButton
    private lateinit var radioFileRSA4096Mode: RadioButton
    private lateinit var switchSecureDelete: androidx.appcompat.widget.SwitchCompat
    private lateinit var switchVerifyEncryption: androidx.appcompat.widget.SwitchCompat
    private lateinit var switchStripMetadata: androidx.appcompat.widget.SwitchCompat

    // File Disappear Settings
    private lateinit var switchFileEnableExpiration: androidx.appcompat.widget.SwitchCompat
    private lateinit var layoutFileExpirationSettings: LinearLayout
    private lateinit var spinnerFileExpirationTime: Spinner

    // File Decryption
    private lateinit var buttonSelectEncryptedFile: Button

    // File RSA Management
    private lateinit var buttonFileGenerateKeyPair: Button
    private lateinit var buttonFileCopyPublicKey: Button
    private lateinit var buttonFilePastePublicKey: Button
    private lateinit var buttonFileClearPublicKey: Button
    private lateinit var textViewFilePublicKey: TextView
    private lateinit var textViewFileRSAStatus: TextView
    private lateinit var editTextFileRecipientPublicKey: EditText

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

    private lateinit var switchEnableExpiration: SwitchCompat
    private lateinit var layoutExpirationSettings: LinearLayout
    private lateinit var spinnerExpirationTime: Spinner
    private lateinit var switchBurnAfterReading: SwitchCompat
    private lateinit var textViewSignatureStatus: TextView

    private var generatedPassword: String = ""
    private var keyPair: KeyPair? = null
    private lateinit var securityServices: SecurityServiceContainer
    
    // Easy access properties for frequently used services
    private val encryptedPreferences get() = securityServices.encryptedPreferences
    private val cryptoManager get() = securityServices.cryptoManager
    private val messageCryptoService get() = securityServices.messageCryptoService
    private val fileEncryptionManager get() = securityServices.fileEncryptionManager

    private var lastDecryptedMetadata: String? = null
    private val sensitiveStrings = mutableListOf<String>()
    private val clearClipboardHandler = Handler(Looper.getMainLooper())
    private val delayedClearHandler = Handler(Looper.getMainLooper())
    private var delayedClearRunnable: Runnable? = null
    
    // Debug system
    private val debugMessages = mutableListOf<String>()
    private fun addDebugMessage(message: String) {
        val timestamp = java.text.SimpleDateFormat("HH:mm:ss.SSS", java.util.Locale.getDefault()).format(java.util.Date())
        val logEntry = "[$timestamp] $message"
        debugMessages.add(logEntry)
        android.util.Log.d("OffCrypt-Debug", message)
        
        // Keep only last 100 messages
        if (debugMessages.size > 100) {
            debugMessages.removeAt(0)
        }
    }
    
    private fun showDebugDialog(title: String = "🔍 Debug Information", autoOpen: Boolean = false) {
        val debugText = debugMessages.joinToString("\n")
        
        val builder = android.app.AlertDialog.Builder(this, android.R.style.Theme_Material_Dialog_Alert)
        builder.setTitle(title)
        builder.setMessage(if (debugText.isEmpty()) "No debug messages" else debugText)
        
        builder.setPositiveButton("📋 Copy All") { _, _ ->
            val clipboard = getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
            val clip = android.content.ClipData.newPlainText("NETCrypt Debug", debugText)
            clipboard.setPrimaryClip(clip)
            showToast("Debug messages copied to clipboard!")
        }
        
        builder.setNeutralButton("🗑️ Clear") { _, _ ->
            debugMessages.clear()
            showToast("Debug messages cleared")
        }
        
        builder.setNegativeButton("❌ Close", null)
        
        val dialog = builder.create()
        
        // Make text selectable and scrollable
        dialog.show()
        val messageView = dialog.findViewById<android.widget.TextView>(android.R.id.message)
        messageView?.apply {
            setTextIsSelectable(true)
            maxLines = 20
            scrollBarStyle = android.view.View.SCROLLBARS_INSIDE_INSET
            isVerticalScrollBarEnabled = true
            movementMethod = android.text.method.ScrollingMovementMethod()
        }
    }

    // File encryption variables
    private var selectedFileUri: Uri? = null
    private var currentlyDecryptedMessage: String? = null
    private var burnAfterReadingEnabled = false

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

    // File encryption launchers
    private val selectFileToEncryptLauncher = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let {
            selectedFileUri = it
            updateSelectedFileDisplay()
        }
    }

    private val saveEncryptedFileLauncher = registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        uri?.let { saveEncryptedFileData(it) }
    }

    private val saveDecryptedFileLauncher = registerForActivityResult(ActivityResultContracts.CreateDocument("*/*")) { uri ->
        uri?.let { saveDecryptedFileData(it) }
    }

    private val openEncryptedFileLauncher = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { decryptFileFromUri(it) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        try {
            setContentView(R.layout.activity_secure_message)
            
            // Initialize security services container with dependency injection
            securityServices = SecurityServiceContainer(this)
            securityServices.initialize()

            initViews()
            setupTabNavigation()
            setupClickListeners()
            setupExpirationSpinner()

            if (isAppLocked()) {
                showLockoutMessage()
                return
            }

            generateNewPassword()
            addDebugMessage("🚀 Application started - loading key pair for current mode")
            loadKeyPairForCurrentMode()
            switchToPasswordMode()
            // Initialize file encryption UI state
            updateSelectedFileDisplay()

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

            // Clear burn after reading message if enabled
            if (burnAfterReadingEnabled) {
                currentlyDecryptedMessage?.let { message ->
                    secureWipeString(message)
                    currentlyDecryptedMessage = null
                    textViewDecrypted.text = "[MESSAGE DESTROYED - BURN AFTER READING]"
                    burnAfterReadingEnabled = false
                }
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

            // File encryption UI elements
            // File encryption password elements  
            switchFileRandomPassword = findViewById(R.id.switchFileRandomPassword)
            // layoutFilePasswordSettings removed - now using cardFilePasswordSettings
            layoutFileRandomPassword = findViewById(R.id.layoutFileRandomPassword)
            layoutFileCustomPassword = findViewById(R.id.layoutFileCustomPassword)
            textViewFilePassword = findViewById(R.id.textViewFilePassword)
            buttonFileCopyPassword = findViewById(R.id.buttonFileCopyPassword)
            buttonFileGenerateNew = findViewById(R.id.buttonFileGenerateNew)
            layoutFileRSAManagement = findViewById(R.id.layoutFileRSAManagement)
            buttonSelectFile = findViewById(R.id.buttonSelectFile)
            buttonEncryptFile = findViewById(R.id.buttonEncryptFile)
            buttonDecryptFile = findViewById(R.id.buttonDecryptFile)
            textViewSelectedFile = findViewById(R.id.textViewSelectedFile)
            textViewFileMessage = findViewById(R.id.textViewFileMessage)

            // File Disappear elements
            switchFileEnableExpiration = findViewById(R.id.switchFileEnableExpiration)
            layoutFileExpirationSettings = findViewById(R.id.layoutFileExpirationSettings)
            spinnerFileExpirationTime = findViewById(R.id.spinnerFileExpirationTime)

            // File Decryption
            buttonSelectEncryptedFile = findViewById(R.id.buttonSelectEncryptedFile)

            // File RSA Management
            buttonFileGenerateKeyPair = findViewById(R.id.buttonFileGenerateKeyPair)
            buttonFileCopyPublicKey = findViewById(R.id.buttonFileCopyPublicKey)
            buttonFilePastePublicKey = findViewById(R.id.buttonFilePastePublicKey)
            buttonFileClearPublicKey = findViewById(R.id.buttonFileClearPublicKey)
            textViewFilePublicKey = findViewById(R.id.textViewFilePublicKey)
            textViewFileRSAStatus = findViewById(R.id.textViewFileRSAStatus)
            editTextFileRecipientPublicKey = findViewById(R.id.editTextFileRecipientPublicKey)

            radioGroupFileEncryptionMode = findViewById(R.id.radioGroupFileEncryptionMode)
            radioFilePasswordMode = findViewById(R.id.radioFilePasswordMode)
            radioFileRSAMode = findViewById(R.id.radioFileRSAMode)
            radioFileRSA4096Mode = findViewById(R.id.radioFileRSA4096Mode)
            switchSecureDelete = findViewById(R.id.switchSecureDelete)
            switchVerifyEncryption = findViewById(R.id.switchVerifyEncryption)
            switchStripMetadata = findViewById(R.id.switchStripMetadata)

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

                tabLayoutSecure = findViewById(R.id.tabLayout)
                viewEncryptTab = findViewById(R.id.viewEncryptTab)
                viewDecryptTab = findViewById(R.id.viewDecryptTab)
                viewFileEncryptionTab = findViewById(R.id.viewFileEncryptionTab)
                viewInstructionsTab = findViewById(R.id.viewInstructionsTab)
                cardViewEncryptedMessage = findViewById(R.id.cardViewEncryptedMessage)
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
                textView.setTextColor(android.graphics.Color.WHITE)
                textView.textSize = 14f
                textView.setPadding(12, 12, 12, 12)
                return view
            }

            override fun getDropDownView(position: Int, convertView: View?, parent: android.view.ViewGroup): View {
                val view = super.getDropDownView(position, convertView, parent)
                val textView = view as TextView
                textView.setTextColor(android.graphics.Color.WHITE)
                textView.textSize = 14f
                textView.setPadding(12, 12, 12, 12)
                return view
            }
        }
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        
        // Setup both Encrypt text and File encryption spinners
        spinnerExpirationTime.adapter = adapter
        spinnerExpirationTime.setSelection(3)
        
        spinnerFileExpirationTime.adapter = adapter
        spinnerFileExpirationTime.setSelection(3)
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

            // File encryption click listeners
            buttonSelectFile.setOnClickListener {
                selectFileToEncryptLauncher.launch(arrayOf("*/*", "application/*", "text/*", "image/*"))
            }
            buttonEncryptFile.setOnClickListener {
                encryptSelectedFile()
            }
            buttonSelectEncryptedFile.setOnClickListener {
                openEncryptedFileLauncher.launch(arrayOf("application/octet-stream", "*.enc", "*/*"))
            }
            buttonDecryptFile.setOnClickListener {
                // This will be called after file is selected by buttonSelectEncryptedFile
                showToast("Please select an encrypted file first using 'Select .enc File' button")
            }

            switchRandomPassword.setOnCheckedChangeListener { _, isChecked ->
                togglePasswordMode(isChecked)
            }
            
            // File encryption password listeners
            switchFileRandomPassword.setOnCheckedChangeListener { _, isChecked ->
                toggleFilePasswordMode(isChecked)
            }
            buttonFileGenerateNew.setOnClickListener { generateFilePassword() }

            // File Disappear listener
            switchFileEnableExpiration.setOnCheckedChangeListener { _, isChecked ->
                layoutFileExpirationSettings.visibility = if (isChecked) View.VISIBLE else View.GONE
            }
            
            // File RSA Management listeners (MISSING FUNCTIONALITY FIXED)
            buttonFileGenerateKeyPair.setOnClickListener { generateFileEncryptionKeyPair() }
            buttonFileCopyPublicKey.setOnClickListener { copyFilePublicKeyToClipboard() }
            buttonFilePastePublicKey.setOnClickListener { pasteFileRecipientPublicKey() }
            buttonFileClearPublicKey.setOnClickListener { clearFileRecipientPublicKey() }
            buttonFileCopyPassword.setOnClickListener { copyFilePasswordToClipboard() }
            
            // File encryption mode change listener (UPDATED FOR CARDS)
            radioGroupFileEncryptionMode.setOnCheckedChangeListener { _, checkedId ->
                when (checkedId) {
                    R.id.radioFilePasswordMode -> {
                        // Show Password card, hide RSA card
                        findViewById<androidx.cardview.widget.CardView>(R.id.cardFilePasswordSettings).visibility = View.VISIBLE
                        findViewById<androidx.cardview.widget.CardView>(R.id.cardFileRSAManagement).visibility = View.GONE
                        layoutFileRSAManagement.visibility = View.GONE
                        // Note: layoutFilePasswordSettings now inside cardFilePasswordSettings
                    }
                    R.id.radioFileRSAMode, R.id.radioFileRSA4096Mode -> {
                        // Show RSA card, hide Password card  
                        findViewById<androidx.cardview.widget.CardView>(R.id.cardFilePasswordSettings).visibility = View.GONE
                        findViewById<androidx.cardview.widget.CardView>(R.id.cardFileRSAManagement).visibility = View.VISIBLE
                        layoutFileRSAManagement.visibility = View.VISIBLE
                        // Load key pair for current File RSA mode (RSA-2048 or RSA-4096)
                        loadKeyPairForFileEncryption()
                    }
                }
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
            buttonCopyPublicKey.setOnClickListener { copyPublicKeyToClipboard()

            }

            buttonImportPublicKey.setOnClickListener {
                importPublicKeyLauncher.launch(arrayOf("text/plain", "*/*"))
            }


            switchEnableExpiration.setOnCheckedChangeListener { _, isChecked ->
                layoutExpirationSettings.visibility = if (isChecked) View.VISIBLE else View.GONE
            }


        } catch (e: Exception) {
            showToast("Click listeners setup failed: ${e.message}")
            throw e
        }
    }

    // File encryption methods
    private fun updateSelectedFileDisplay() {
        try {
            selectedFileUri?.let { uri ->
                val fileName = fileEncryptionManager.getFileName(uri)
                val fileSize = fileEncryptionManager.getFileSize(uri)
                val fileSizeText = fileEncryptionManager.formatFileSize(fileSize)
                textViewSelectedFile.text = "📁 $fileName ($fileSizeText)"
                textViewFileMessage.text = "✅ File selected - ready for encryption"
                textViewFileMessage.setTextColor(resources.getColor(android.R.color.holo_green_dark, theme))
                buttonEncryptFile.isEnabled = true
            } ?: run {
                textViewSelectedFile.text = "📁 No file selected"
                textViewFileMessage.text = "Select a file to encrypt"
                textViewFileMessage.setTextColor(resources.getColor(android.R.color.white, theme))
                buttonEncryptFile.isEnabled = false
            }
        } catch (e: Exception) {
            textViewSelectedFile.text = "⚠️ File access failed"
            textViewFileMessage.text = "❌ Error reading file: ${e.message}"
            textViewFileMessage.setTextColor(resources.getColor(android.R.color.holo_red_dark, theme))
            buttonEncryptFile.isEnabled = false
            showToast("File selection failed: ${e.message}")
        }
    }


    private fun encryptSelectedFile() {
        selectedFileUri?.let { uri ->
            // Check encryption mode is selected and necessary keys/passwords are available
            val errorMessage = when {
                radioFilePasswordMode.isChecked && getCurrentPassword().isEmpty() ->
                    "Enter password or use generated password first!"
                (radioFileRSAMode.isChecked || radioFileRSA4096Mode.isChecked) &&
                        editTextRecipientPublicKey.text.toString().trim().isEmpty() ->
                    "Enter recipient's public key first!"
                else -> null
            }

            if (errorMessage != null) {
                showToast(errorMessage)
                return
            }

            try {
                showToast("Encrypting file... Please wait.")
                textViewFileMessage.text = "🔄 Encrypting file..."
                textViewFileMessage.setTextColor(resources.getColor(android.R.color.holo_blue_bright, theme))

                Thread {
                    try {
                        val fileData = fileEncryptionManager.readFileData(uri)
                        val fileName = fileEncryptionManager.getFileName(uri)
                        
                        // Get expiration time from UI (DISAPPEAR FILE FUNCTIONALITY)
                        val expirationTime = getFileExpirationTime()
                        var enhancedMetadata = fileEncryptionManager.createFileMetadata(fileName, fileData.size.toLong())
                        
                        // Add expiration time to metadata if enabled
                        if (expirationTime > 0L) {
                            enhancedMetadata += "\n\"expiration_time\":$expirationTime"
                            addDebugMessage("🕒 File expiration set to: ${java.util.Date(expirationTime)}")
                        }

                        val encryptedData = if (radioFilePasswordMode.isChecked) {
                            // Use advanced password encryption with expiration support
                            fileEncryptionManager.encryptFileWithPasswordAdvanced(fileData, enhancedMetadata, getCurrentPassword())
                        } else {
                            // Advanced RSA file encryption with expiration support
                            val recipientPublicKeyString = editTextRecipientPublicKey.text.toString().trim()
                            if (recipientPublicKeyString.isEmpty()) {
                                throw RuntimeException("Enter recipient's public key!")
                            }
                            val recipientPublicKey = cryptoManager.parsePublicKeyFromString(recipientPublicKeyString)
                            fileEncryptionManager.encryptFileWithRSAAdvanced(
                                fileData, 
                                enhancedMetadata, 
                                recipientPublicKey,
                                keyPair, // Use current user's key pair if available
                                enablePFS = true,
                                enableSignatures = true,
                                expirationTime = expirationTime
                            )
                        }

                        runOnUiThread {
                            val timestamp = System.currentTimeMillis()
                            val prefix = when {
                                radioFilePasswordMode.isChecked -> "Password"
                                radioFileRSA4096Mode.isChecked -> "RSA4096"
                                else -> "RSA"
                            }
                            val expirationSuffix = if (expirationTime > 0L) "_EXPIRES" else ""
                            val encryptedFileName = "${prefix}_encrypted_${fileName}_$timestamp$expirationSuffix.enc"

                            // Save the encrypted data temporarily for the file launcher
                            saveEncryptedDataForLauncher(encryptedData)
                            saveEncryptedFileLauncher.launch(encryptedFileName)
                        }

                    } catch (e: Exception) {
                        runOnUiThread {
                            showToast("File encryption failed: ${e.message}")
                            textViewFileMessage.text = "❌ File encryption failed: ${e.message}"
                            textViewFileMessage.setTextColor(resources.getColor(android.R.color.holo_red_dark, theme))
                        }
                    }
                }.start()

            } catch (e: Exception) {
                showToast("File encryption failed: ${e.message}")
                textViewFileMessage.text = "❌ File encryption failed"
                textViewFileMessage.setTextColor(resources.getColor(android.R.color.holo_red_dark, theme))
            }
        } ?: showToast("Select a file first!")
    }

    private var temporaryEncryptedData: ByteArray? = null

    private fun saveEncryptedDataForLauncher(data: ByteArray) {
        temporaryEncryptedData = data
    }

    private fun saveEncryptedFileData(uri: Uri) {
        temporaryEncryptedData?.let { data ->
            try {
                fileEncryptionManager.saveEncryptedData(uri, data)

                val modeText = when {
                    radioFilePasswordMode.isChecked -> "with password"
                    radioFileRSA4096Mode.isChecked -> "RSA-4096 + AES-256-GCM"
                    else -> "with RSA keys"
                }
                showToast("Encrypted file saved $modeText!")
                textViewFileMessage.text = "✅ File encrypted and saved successfully"
                textViewFileMessage.setTextColor(resources.getColor(android.R.color.holo_green_dark, theme))

                // Reset selection after successful encryption
                selectedFileUri = null
                updateSelectedFileDisplay()

                // Clear temporary data
                secureWipeByteArray(temporaryEncryptedData!!)
                temporaryEncryptedData = null

            } catch (e: Exception) {
                showToast("File save failed: ${e.message}")
            }
        }
    }





    private fun decryptFileFromUri(uri: Uri) {
        try {
            showToast("Decrypting file... Please wait.")

            Thread {
                try {
                    val encryptedData = fileEncryptionManager.readFileData(uri)
                    val version = encryptedData[0]

                    val (fileData, metadata) = when (version) {
                        VERSION_BYTE_FILE_ENCRYPTED -> {
                            val password = editTextDecryptPassword.text.toString().trim()
                            if (password.isEmpty()) {
                                throw RuntimeException("Enter password for file decryption!")
                            }
                            cryptoManager.decryptFileWithPassword(encryptedData, password)
                        }
                        VERSION_BYTE_RSA_ALL, VERSION_BYTE_RSA_4096_AES_FULL -> {
                            if (keyPair?.private == null) {
                                throw RuntimeException("Private key missing for file decryption!")
                            }
                            cryptoManager.decryptFileWithRSA(encryptedData, keyPair!!.private)
                        }
                        else -> throw RuntimeException("Unknown file encryption version: $version")
                    }

                    runOnUiThread {
                        val fileName = fileEncryptionManager.extractFileNameFromMetadata(metadata)
                        textViewFileMessage.text = "✅ File decrypted: $fileName"
                        textViewFileMessage.setTextColor(resources.getColor(android.R.color.holo_green_dark, theme))

                        // Save the decrypted file
                        saveDecryptedDataForLauncher(fileData, fileName)
                        saveDecryptedFileLauncher.launch(fileName)

                        showToast("File decrypted successfully!")
                    }

                } catch (e: Exception) {
                    runOnUiThread {
                        showToast("File decryption failed: ${e.message}")
                        textViewFileMessage.text = "❌ File decryption failed"
                        textViewFileMessage.setTextColor(resources.getColor(android.R.color.holo_red_dark, theme))
                    }
                }
            }.start()

        } catch (e: Exception) {
            showToast("File decryption failed: ${e.message}")
        }
    }

    private var temporaryDecryptedFileData: ByteArray? = null
    private var temporaryDecryptedFileName: String = ""

    private fun saveDecryptedDataForLauncher(data: ByteArray, fileName: String) {
        temporaryDecryptedFileData = data
        temporaryDecryptedFileName = fileName
    }

    private fun saveDecryptedFileData(uri: Uri) {
        temporaryDecryptedFileData?.let { data ->
            try {
                contentResolver.openFileDescriptor(uri, "w")?.use { parcelFileDescriptor ->
                    FileOutputStream(parcelFileDescriptor.fileDescriptor).use { fileOutputStream ->
                        fileOutputStream.write(data)
                    }
                }

                showToast("Decrypted file saved: $temporaryDecryptedFileName")

                // Clear temporary data
                secureWipeByteArray(temporaryDecryptedFileData!!)
                temporaryDecryptedFileData = null
                temporaryDecryptedFileName = ""

            } catch (e: Exception) {
                showToast("File save failed: ${e.message}")
            }
        }
    }

    private fun decryptFileDataPasswordBased(encryptedData: ByteArray, password: String): Pair<ByteArray, String> {
        try {
            if (encryptedData.size < 1 + SALT_SIZE * 3 + IV_SIZE + MAC_SIZE + GCM_TAG_LENGTH) {
                throw RuntimeException("Invalid file data size")
            }

            var offset = 1 // Skip version byte

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
            val combinedDataString = String(decryptedData, Charsets.UTF_8)

            return parseFileDataAndMetadata(combinedDataString)

        } catch (e: Exception) {
            throw RuntimeException("File decryption failed", e)
        }
    }

    private fun decryptFileDataRSA(encryptedData: ByteArray): Pair<ByteArray, String> {
        try {
            val encryptedString = String(encryptedData, Charsets.UTF_8)
            val decryptedString = if (encryptedData[0] == VERSION_BYTE_RSA_4096_AES_FULL) {
                decryptRSA4096WithAESFull(encryptedString, keyPair!!.private)
            } else {
                decryptRSAWithFeatures(encryptedString, keyPair!!.private, encryptedData[0])
            }

            return parseFileDataAndMetadata(decryptedString)

        } catch (e: Exception) {
            throw RuntimeException("RSA file decryption failed: ${e.message}", e)
        }
    }

    private fun parseFileDataAndMetadata(combinedData: String): Pair<ByteArray, String> {
        try {
            // Parse JSON-like structure
            val metadataStart = combinedData.indexOf("\"metadata\":") + 11
            val metadataEnd = combinedData.indexOf(",\"filedata\":")
            val filedataStart = combinedData.indexOf("\"filedata\":\"") + 12
            val filedataEnd = combinedData.lastIndexOf("\"}")

            val metadata = combinedData.substring(metadataStart, metadataEnd)
            val encodedFileData = combinedData.substring(filedataStart, filedataEnd)

            val fileData = Base64.getDecoder().decode(encodedFileData)

            return Pair(fileData, metadata)

        } catch (e: Exception) {
            throw RuntimeException("Failed to parse file data: ${e.message}")
        }
    }


    private fun getCurrentPassword(): String {
        return try {
            // Check if we're in file encryption context
            val isFileEncryption = viewFileEncryptionTab.visibility == View.VISIBLE
            
            if (isFileEncryption) {
                // Use file encryption elements
                if (switchFileRandomPassword.isChecked) {
                    generatedPassword
                } else {
                    editTextFileCustomPassword.text.toString().trim()
                }
            } else {
                // Use text encryption elements (original)
                if (switchRandomPassword.isChecked) {
                    generatedPassword
                } else {
                    editTextCustomPassword.text.toString().trim()
                }
            }
        } catch (e: Exception) {
            showToast("Password retrieval failed: ${e.message}")
            ""
        }
    }

    private fun getCurrentPasswordSecurely(): CharArray? {
        return try {
            // Check if we're in file encryption context
            val isFileEncryption = viewFileEncryptionTab.visibility == View.VISIBLE
            
            if (isFileEncryption) {
                // Use file encryption elements
                if (switchFileRandomPassword.isChecked) {
                    generatedPassword.toCharArray()
                } else {
                    getPasswordFromEditTextSecurely(editTextFileCustomPassword)
                }
            } else {
                // Use text encryption elements (original)
                if (switchRandomPassword.isChecked) {
                    generatedPassword.toCharArray()
                } else {
                    getPasswordFromEditTextSecurely(editTextCustomPassword)
                }
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
        val failedAttempts = encryptedPreferences.getInt(KEY_FAILED_ATTEMPTS, 0)
        val lastAttemptTime = encryptedPreferences.getLong(KEY_LAST_ATTEMPT_TIME, 0)
        val currentTime = System.currentTimeMillis()

        return failedAttempts >= MAX_FAILED_ATTEMPTS &&
                (currentTime - lastAttemptTime) < LOCKOUT_DURATION
    }

    private fun showLockoutMessage() {
        val remainingTime = LOCKOUT_DURATION - (System.currentTimeMillis() - encryptedPreferences.getLong(KEY_LAST_ATTEMPT_TIME, 0))
        val minutes = remainingTime / 60000

        AlertDialog.Builder(this)
            .setTitle("🔒 App locked")
            .setMessage("Too many incorrect passwords. App will unlock in ${minutes + 1} minutes.")
            .setPositiveButton("OK") { _, _ -> finish() }
            .setCancelable(false)
            .show()
    }

    private fun recordFailedAttempt() {
        val currentAttempts = encryptedPreferences.getInt(KEY_FAILED_ATTEMPTS, 0)
        encryptedPreferences.edit()
            .putInt(KEY_FAILED_ATTEMPTS, currentAttempts + 1)
            .putLong(KEY_LAST_ATTEMPT_TIME, System.currentTimeMillis())
            .apply()
    }

    private fun resetFailedAttempts() {
        encryptedPreferences.edit()
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
                    val useRSA4096 = radioRSA4096Mode.isChecked
                    val newKeyPair = cryptoManager.generateRSAKeyPair(useRSA4096)

                    runOnUiThread {
                        keyPair = newKeyPair
                        saveKeyPair()
                        updatePublicKeyDisplay()
                        updateRSAStatus()
                        // Sync to File encryption side
                        updateFileEncryptionPublicKey()
                        val sizeText = if (useRSA4096) "RSA-4096" else "RSA-2048"
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
                val useRSA4096 = radioRSA4096Mode.isChecked
                cryptoManager.saveKeyPair(kp, useRSA4096)

                val modeText = if (useRSA4096) "RSA-4096" else "RSA-2048"
                showToast("🔐 $modeText key pair encrypted with AndroidKeyStore")
            }
        } catch (e: Exception) {
            showToast("❌ Key pair encryption failed: ${e.message}")
        }
    }

    private fun loadKeyPair() {
        addDebugMessage("🔄 Starting loadKeyPair() with KeyManagementService")
        try {
            val useRSA4096 = radioRSA4096Mode.isChecked
            keyPair = cryptoManager.loadKeyPair(useRSA4096)
            
            if (keyPair != null) {
                updatePublicKeyDisplay()
                updateFileEncryptionPublicKey()
                
                val modeText = if (useRSA4096) "RSA-4096" else "RSA-2048"
                addDebugMessage("🎉 $modeText key pair loaded successfully via KeyManagementService!")
                showToast("✅ $modeText key pair loaded from AndroidKeyStore")
            } else {
                addDebugMessage("❌ No key pair found - setting to null")
                textViewPublicKey.text = "No ${if (useRSA4096) "RSA-4096" else "RSA-2048"} key generated"
            }
            
        } catch (e: Exception) {
            val errorMsg = "❌ Key loading failed: ${e.javaClass.simpleName}: ${e.message}"
            addDebugMessage(errorMsg)
            
            showToast("❌ Key pair loading failed: ${e.message}")
            showDebugDialog("❌ RSA Key Loading Error", autoOpen = true)
            
            keyPair = null
            textViewPublicKey.text = "No ${if (radioRSA4096Mode.isChecked) "RSA-4096" else "RSA-2048"} key generated"
        }
    }

    private fun loadKeyPairForCurrentMode() {
        val mode = if (radioRSA4096Mode.isChecked) "RSA-4096" else "RSA-2048"
        addDebugMessage("🔄 Loading key pair for mode: $mode")
        try {
            loadKeyPair()
            updateRSAStatus()
        } catch (e: Exception) {
            addDebugMessage("❌ Mode switch failed: ${e.message}")
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
        addDebugMessage("🖼️ Updating public key display...")
        try {
            keyPair?.let { kp ->
                addDebugMessage("✅ KeyPair exists - formatting public key for display")
                val formattedKey = cryptoManager.formatPublicKeyForSharing(kp.public)
                addDebugMessage("📏 Formatted key length: ${formattedKey.length}")
                addDebugMessage("📄 Key preview: ${formattedKey.take(50)}...")
                
                val displayKey = if (formattedKey.length > 100) {
                    formattedKey.substring(0, 50) + "..." + formattedKey.substring(formattedKey.length - 50)
                } else {
                    formattedKey
                }
                
                textViewPublicKey.text = displayKey
                addDebugMessage("✅ Public key display updated successfully in textViewPublicKey")
            } ?: run {
                addDebugMessage("❌ updatePublicKeyDisplay: keyPair is null")
                textViewPublicKey.text = "No RSA key pair available"
            }
        } catch (e: Exception) {
            val errorMsg = "❌ Public key display failed: ${e.javaClass.simpleName}: ${e.message}"
            addDebugMessage(errorMsg)
            addDebugMessage("📍 Stack trace: ${e.stackTrace.take(3).joinToString { "${it.className}.${it.methodName}:${it.lineNumber}" }}")
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

    // File encryption password toggle (MISSING FUNCTIONALITY FIXED)
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
    
    private fun toggleFilePasswordMode(useRandomPassword: Boolean) {
        try {
            if (useRandomPassword) {
                layoutFileRandomPassword.visibility = View.VISIBLE
                layoutFileCustomPassword.visibility = View.GONE
                generateFilePassword()
            } else {
                layoutFileRandomPassword.visibility = View.GONE
                layoutFileCustomPassword.visibility = View.VISIBLE
            }
        } catch (e: Exception) {
            addDebugMessage("❌ Error toggling file password mode: ${e.message}")
            showToast("Error switching password mode: ${e.message}")
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
        val expirationTime = if (switchEnableExpiration.isChecked) {
            getSelectedExpirationTime()
        } else {
            0L
        }
        
        return messageCryptoService.encryptWithPassword(message, password, expirationTime)
    }
    
    private fun getSelectedExpirationTime(): Long {
        val selectedExpiration = expirationOptions[spinnerExpirationTime.selectedItemPosition]
        return System.currentTimeMillis() + (selectedExpiration.second * 60 * 60 * 1000)
    }

    private fun encryptWithRSA(message: String): String {
        val recipientPublicKeyString = editTextRecipientPublicKey.text.toString().trim()
        
        val useRSA4096 = radioRSA4096Mode.isChecked
        val enablePFS = false // switchEnablePFS.isChecked // Not implemented yet
        val enableSignatures = false // switchEnableSignatures.isChecked // Not implemented yet
        val enableExpiration = switchEnableExpiration.isChecked
        val expirationTime = if (enableExpiration) {
            getSelectedExpirationTime()
        } else {
            0L
        }
        
        val options = RSAEncryptionOptions(
            useRSA4096 = useRSA4096,
            enablePFS = enablePFS,
            enableSignatures = enableSignatures,
            enableExpiration = enableExpiration,
            expirationTime = expirationTime
        )
        
        return messageCryptoService.encryptWithRSA(message, recipientPublicKeyString, options)
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



    private fun readInt32(data: ByteArray, offset: Int): Int {
        if (offset + 4 > data.size) {
            throw RuntimeException("Not enough data to read Int32")
        }
        return (data[offset].toInt() and 0xFF) or
                ((data[offset + 1].toInt() and 0xFF) shl 8) or
                ((data[offset + 2].toInt() and 0xFF) shl 16) or
                ((data[offset + 3].toInt() and 0xFF) shl 24)
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

            // Get password and keyPair for decryption
            val password = editTextDecryptPassword.text.toString().trim().takeIf { it.isNotEmpty() }
            
            val decryptionResult = try {
                // Use MessageCryptoService for clean decryption logic
                val result = messageCryptoService.decryptMessage(encryptedMessage, password, keyPair)
                
                // Reset failed attempts on successful password-based decryption
                if (result.metadata.encryptionMethod == EncryptionMethod.PASSWORD) {
                    resetFailedAttempts()
                }
                
                result
            } catch (e: Exception) {
                // Record failed attempts for password-based decryption
                if (password != null) {
                    recordFailedAttempt()
                }
                throw e
            }

            textViewDecrypted.text = decryptionResult.message
            currentlyDecryptedMessage = decryptionResult.message

            // Check if burn after reading is enabled from the metadata
            burnAfterReadingEnabled = checkIfBurnAfterReadingEnabled(lastDecryptedMetadata)

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

    private fun checkIfBurnAfterReadingEnabled(metadata: String?): Boolean {
        return try {
            metadata?.let {
                if (it.contains("\"burn\":\"true\"") || it.contains("burn=true")) {
                    true
                } else {
                    false
                }
            } ?: false
        } catch (e: Exception) {
            false
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

            // Metadata parsing removed - will be handled in FileEncryptionService later
            val metadata: Map<String, Any>? = null
            val finalMessage = if (metadata != null) {
                val expirationTime = metadata["exp"] as? Long
                if (expirationTime != null && System.currentTimeMillis() > expirationTime) {
                    secureClearAllSensitiveData()
                    val expiredDate = SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()).format(Date(expirationTime))
                    throw RuntimeException("Message has expired ($expiredDate)")
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

                // Metadata parsing removed - will be handled in FileEncryptionService later
                val metadata: Map<String, Any>? = null
                val finalMessage = if (metadata != null) {
                    val expirationTime = metadata["exp"] as? Long
                    if (expirationTime != null && System.currentTimeMillis() > expirationTime) {
                        secureClearAllSensitiveData()
                        val expiredDate = SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()).format(Date(expirationTime))
                        throw RuntimeException("Message has expired ($expiredDate)")
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
                        VERSION_BYTE_FILE_ENCRYPTED -> "encrypted file"
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

            encryptedPreferences.edit()
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
    
    private fun generateFilePassword() {
        try {
            // Use same generated password system
            if (generatedPassword.isNotEmpty()) {
                secureWipeString(generatedPassword)
            }
            
            generatedPassword = generateRandomPassword(24)
            textViewFilePassword.text = generatedPassword
        } catch (e: Exception) {
            showToast("File password generation failed: ${e.message}")
            generatedPassword = "GENERATION_ERROR"
            textViewFilePassword.text = generatedPassword
        }
    }

    private fun copyFilePasswordToClipboard() {
        try {
            val password = if (switchFileRandomPassword.isChecked) {
                generatedPassword
            } else {
                editTextFileCustomPassword.text.toString()
            }
            
            if (password.isNotEmpty()) {
                copyToClipboardSecurely(password, "File password", true)
                addToSensitiveList(password)
            } else {
                showToast("No file password to copy!")
            }
        } catch (e: Exception) {
            showToast("Copy failed: ${e.message}")
            addDebugMessage("❌ File password copy failed: ${e.message}")
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

            // Clear burn after reading message if screen is hidden
            if (burnAfterReadingEnabled && currentlyDecryptedMessage != null) {
                currentlyDecryptedMessage?.let { message ->
                    secureWipeString(message)
                }
                currentlyDecryptedMessage = null
                textViewDecrypted.text = "[MESSAGE DESTROYED - BURN AFTER READING]"
                burnAfterReadingEnabled = false
                showToast("🔥 Self-destructing message destroyed on screen hide")
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
            selectedFileUri = null
            temporaryEncryptedData = null
            temporaryDecryptedFileData = null

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

    private fun startDelayedFieldClearance() {
        // Peruuta aiempi ajastin jos sellainen on
        cancelDelayedFieldClearance()
        
        delayedClearRunnable = Runnable {
            try {
                // Tyhjennä tekstikentät 5 minuutin jälkeen
                editTextMessage.text.clear()
                editTextEncrypted.text.clear()
                clearPasswordFieldSecurely(editTextDecryptPassword)
                clearPasswordFieldSecurely(editTextCustomPassword)
                textViewDecrypted.text = ""
                
                if (generatedPassword.isNotEmpty()) {
                    secureWipeString(generatedPassword)
                    generatedPassword = ""
                    textViewPassword.text = "Generate new password"
                }
                
                secureClearAllSensitiveData()
                
                showToast("🕒 Text fields cleared after 5 minutes of inactivity")
                
            } catch (e: Exception) {
                // Turvallinen virheenkäsittely
            }
        }
        
        // Käynnistä ajastin (5 minuuttia = 300000 millisekuntia)
        delayedClearHandler.postDelayed(delayedClearRunnable!!, 300000)
    }
    
    private fun cancelDelayedFieldClearance() {
        delayedClearRunnable?.let { runnable ->
            delayedClearHandler.removeCallbacks(runnable)
        }
        delayedClearRunnable = null
    }

    override fun onDestroy() {
        super.onDestroy()

        nuclearSecurityWipe()
        
        // Clean up security services
        if (::securityServices.isInitialized) {
            securityServices.cleanup()
        }

        clearClipboardHandler.removeCallbacksAndMessages(null)
        delayedClearHandler.removeCallbacksAndMessages(null)
    }

    override fun onPause() {
        super.onPause()

        // Käynnistä 5 minuutin ajastin tekstikenttien tyhjentämiseen
        startDelayedFieldClearance()
    }

    override fun onStop() {
        super.onStop()

        try {
            // Piilota vain näkyvät kentät, mutta älä tyhjennä niitä
            textViewDecrypted.text = "[HIDDEN FOR SECURITY REASONS]"
            textViewPassword.text = "●●●●●●●●●●●●"

            // Destroy burn after reading message when app goes to background (säilytetään)
            if (burnAfterReadingEnabled && currentlyDecryptedMessage != null) {
                currentlyDecryptedMessage?.let { message ->
                    secureWipeString(message)
                }
                currentlyDecryptedMessage = null
                textViewDecrypted.text = "[MESSAGE DESTROYED - BURN AFTER READING]"
                burnAfterReadingEnabled = false
            }

        } catch (e: Exception) {
        }
    }

    override fun onResume() {
        super.onResume()

        try {
            // Peruuta viivästetty kenttien tyhjennys kun sovellus palaa
            cancelDelayedFieldClearance()
            
            if (isAppLocked()) {
                showLockoutMessage()
                return
            }

            if (keyPair == null) {
                loadKeyPairForCurrentMode()
            }

            // Palauta salasananäyttö jos se on piilotettu
            if (textViewPassword.text == "●●●●●●●●●●●●" && generatedPassword.isNotEmpty()) {
                textViewPassword.text = generatedPassword
            }

            updateRSAStatus()
            updateSelectedFileDisplay()
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

        // Trigger burn after reading when user leaves the app
        if (burnAfterReadingEnabled && currentlyDecryptedMessage != null) {
            currentlyDecryptedMessage?.let { message ->
                secureWipeString(message)
            }
            currentlyDecryptedMessage = null
            textViewDecrypted.text = "[MESSAGE DESTROYED - BURN AFTER READING]"
            burnAfterReadingEnabled = false
            showToast("🔥 Self-destructing message destroyed")
        }
    }

    private fun setupTabNavigation() {
        if (tabLayoutSecure.tabCount == 0) {
            tabLayoutSecure.addTab(tabLayoutSecure.newTab().setText("📚 Instructions"))
            tabLayoutSecure.addTab(tabLayoutSecure.newTab().setText("🔒 Encrypt text"))
            tabLayoutSecure.addTab(tabLayoutSecure.newTab().setText("🔓 Decrypt text"))
            tabLayoutSecure.addTab(tabLayoutSecure.newTab().setText("📁 File encryption"))
        }
        showInstructionsTab()
        tabLayoutSecure.getTabAt(0)?.select()

        tabLayoutSecure.addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
            override fun onTabSelected(tab: TabLayout.Tab) {
                when (tab.position) {
                    0 -> showInstructionsTab()
                    1 -> showEncryptTab()
                    2 -> showDecryptTab()
                    3 -> showFileEncryptionTab()
                }
            }
            override fun onTabUnselected(tab: TabLayout.Tab) { /* no-op */ }
            override fun onTabReselected(tab: TabLayout.Tab) { /* no-op */ }
        })
    }

    private fun showEncryptTab() {
        viewEncryptTab.visibility = View.VISIBLE
        viewDecryptTab.visibility = View.GONE
        viewFileEncryptionTab.visibility = View.GONE
        viewInstructionsTab.visibility = View.GONE
        cardViewEncryptedMessage.visibility = View.VISIBLE
    }

    private fun showDecryptTab() {
        viewEncryptTab.visibility = View.GONE
        viewDecryptTab.visibility = View.VISIBLE
        viewFileEncryptionTab.visibility = View.GONE
        viewInstructionsTab.visibility = View.GONE
        cardViewEncryptedMessage.visibility = View.VISIBLE
    }


    private fun showFileEncryptionTab() {
        viewEncryptTab.visibility = View.GONE
        viewDecryptTab.visibility = View.GONE
        viewFileEncryptionTab.visibility = View.VISIBLE
        viewInstructionsTab.visibility = View.GONE
        cardViewEncryptedMessage.visibility = View.GONE
        
        // Initialize File encryption UI state (UPDATED FOR CARDS)
        if (radioFilePasswordMode.isChecked) {
            findViewById<androidx.cardview.widget.CardView>(R.id.cardFilePasswordSettings).visibility = View.VISIBLE
            findViewById<androidx.cardview.widget.CardView>(R.id.cardFileRSAManagement).visibility = View.GONE
            layoutFileRSAManagement.visibility = View.GONE
        } else {
            findViewById<androidx.cardview.widget.CardView>(R.id.cardFilePasswordSettings).visibility = View.GONE
            findViewById<androidx.cardview.widget.CardView>(R.id.cardFileRSAManagement).visibility = View.VISIBLE
            layoutFileRSAManagement.visibility = View.VISIBLE
        }
        
        // Load and sync RSA key for File Encryption
        if (keyPair == null) {
            loadKeyPairForFileEncryption()
        }
        updateFileEncryptionPublicKey()
    }
    
    private fun loadKeyPairForFileEncryption() {
        val mode = if (radioFileRSA4096Mode.isChecked) "RSA-4096" else "RSA-2048"
        addDebugMessage("🔄 Loading key pair for File Encryption mode: $mode")
        try {
            loadKeyPairForFileMode()
            // Update RSA status and public key display for file encryption
            updateFileEncryptionRSAStatus()
            updateFileEncryptionPublicKey()
        } catch (e: Exception) {
            addDebugMessage("❌ File encryption mode switch failed: ${e.message}")
            showToast("File encryption mode switch failed: ${e.message}")
        }
    }
    
    private fun loadKeyPairForFileMode() {
        addDebugMessage("🔄 Starting loadKeyPairForFileMode()")
        try {
            val useRSA4096 = radioFileRSA4096Mode.isChecked
            val loadedKeyPair = cryptoManager.loadKeyPair(useRSA4096)
            
            if (loadedKeyPair != null) {
                keyPair = loadedKeyPair
                val modeText = if (useRSA4096) "RSA-4096" else "RSA-2048"
                addDebugMessage("✅ $modeText key pair loaded successfully for file encryption!")
                showToast("✅ $modeText key pair loaded for file encryption")
            } else {
                addDebugMessage("❌ No key pair found - setting keyPair to null")
                keyPair = null
                textViewFilePublicKey.text = "No ${if (useRSA4096) "RSA-4096" else "RSA-2048"} key generated"
            }

        } catch (e: Exception) {
            val errorMsg = "❌ File encryption key loading failed: ${e.javaClass.simpleName}: ${e.message}"
            addDebugMessage(errorMsg)
            showToast("❌ File encryption key pair loading failed: ${e.message}")
            
            keyPair = null
            textViewFilePublicKey.text = "No ${if (radioFileRSA4096Mode.isChecked) "RSA-4096" else "RSA-2048"} key generated"
        }
    }
    
    private fun updateFileEncryptionRSAStatus() {
        try {
            keyPair?.let {
                val keySize = if (radioFileRSA4096Mode.isChecked) "RSA-4096" else "RSA-2048"
                textViewFileRSAStatus.text = "✅ $keySize key pair ready"
                textViewFileRSAStatus.setTextColor(resources.getColor(android.R.color.holo_green_dark, theme))
            } ?: run {
                val keySize = if (radioFileRSA4096Mode.isChecked) "RSA-4096" else "RSA-2048"
                textViewFileRSAStatus.text = "⚠ No $keySize key pair - create a key pair first"
                textViewFileRSAStatus.setTextColor(resources.getColor(android.R.color.holo_orange_light, theme))
            }
        } catch (e: Exception) {
            textViewFileRSAStatus.text = "❌ Error updating RSA status: ${e.message}"
            textViewFileRSAStatus.setTextColor(resources.getColor(android.R.color.holo_red_dark, theme))
        }
    }
    
    private fun updateFileEncryptionPublicKey() {
        try {
            keyPair?.let { keyPair ->
                val publicKeyString = Base64.getEncoder().encodeToString(keyPair.public.encoded)
                val formattedKey = publicKeyString.chunked(64).joinToString("\n")
                val displayKey = if (formattedKey.length > 100) {
                    formattedKey.substring(0, 50) + "..." + formattedKey.substring(formattedKey.length - 50)
                } else {
                    formattedKey
                }
                
                textViewFilePublicKey.text = displayKey
                
                val keySize = if (radioFileRSA4096Mode.isChecked) "RSA-4096" else "RSA-2048"
                textViewFileRSAStatus.text = "✅ $keySize key pair ready"
                textViewFileRSAStatus.setTextColor(resources.getColor(android.R.color.holo_green_dark, theme))
                
            } ?: run {
                textViewFilePublicKey.text = "No key generated"
                val keySize = if (radioFileRSA4096Mode.isChecked) "RSA-4096" else "RSA-2048"
                textViewFileRSAStatus.text = "⚠ No $keySize key pair - create a key pair first"
                textViewFileRSAStatus.setTextColor(resources.getColor(android.R.color.holo_orange_light, theme))
            }
        } catch (e: Exception) {
            textViewFilePublicKey.text = "Key display failed"
            textViewFileRSAStatus.text = "❌ Error loading key: ${e.message}"
            textViewFileRSAStatus.setTextColor(resources.getColor(android.R.color.holo_red_dark, theme))
        }
    }

    // File expiration support (MISSING FUNCTIONALITY ADDED)
    private fun getFileExpirationTime(): Long {
        return if (switchFileEnableExpiration.isChecked) {
            val selectedExpiration = expirationOptions[spinnerFileExpirationTime.selectedItemPosition]
            System.currentTimeMillis() + (selectedExpiration.second * 60 * 60 * 1000)
        } else {
            0L // No expiration
        }
    }

    // Clipboard security method (MISSING METHOD ADDED)
    private fun clearClipboardAfterDelay(delayMs: Long) {
        try {
            // Cancel any existing delayed clear operations
            clearClipboardHandler.removeCallbacksAndMessages(null)
            
            // Schedule clipboard clearing after specified delay
            clearClipboardHandler.postDelayed({
                try {
                    val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    val emptyClip = ClipData.newPlainText("", "")
                    clipboard.setPrimaryClip(emptyClip)
                    
                    val seconds = delayMs / 1000
                    showToast("🧹 Clipboard cleared securely after ${seconds}s")
                    addDebugMessage("🧹 Clipboard cleared automatically after ${seconds}s for security")
                } catch (e: Exception) {
                    addDebugMessage("⚠️ Clipboard clear failed: ${e.message}")
                }
            }, delayMs)
            
            val seconds = delayMs / 1000
            addDebugMessage("⏰ Clipboard will be cleared in ${seconds}s for security")
            
        } catch (e: Exception) {
            addDebugMessage("❌ Failed to schedule clipboard clearing: ${e.message}")
        }
    }

    // File RSA Management methods (MISSING FUNCTIONALITY ADDED)
    private fun generateFileEncryptionKeyPair() {
        try {
            addDebugMessage("🔄 Generating File RSA key pair...")
            
            val useRSA4096 = radioFileRSA4096Mode.isChecked
            val newKeyPair = cryptoManager.generateRSAKeyPair(useRSA4096)
            cryptoManager.saveKeyPair(newKeyPair, useRSA4096)
            
            keyPair = newKeyPair
            updateFileEncryptionPublicKey()
            
            val sizeText = if (useRSA4096) "RSA-4096" else "RSA-2048"
            showToast("✅ $sizeText key pair generated successfully!")
            addDebugMessage("✅ File RSA key pair generated successfully!")
            
        } catch (e: Exception) {
            addDebugMessage("❌ File RSA key pair generation failed: ${e.message}")
            showToast("File key pair generation failed: ${e.message}")
        }
    }
    
    private fun copyFilePublicKeyToClipboard() {
        try {
            keyPair?.let { keyPair ->
                val publicKeyString = Base64.getEncoder().encodeToString(keyPair.public.encoded)
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = ClipData.newPlainText("Public Key", publicKeyString)
                clipboard.setPrimaryClip(clip)
                
                val keySize = if (radioFileRSA4096Mode.isChecked) "RSA-4096" else "RSA-2048"
                showToast("📋 $keySize public key copied to clipboard")
                addDebugMessage("📋 File public key copied to clipboard")
                
                clearClipboardAfterDelay(600_000L) // 10 minutes for RSA keys
                
            } ?: run {
                showToast("No key pair available - generate a key pair first")
            }
        } catch (e: Exception) {
            showToast("Failed to copy public key: ${e.message}")
            addDebugMessage("❌ Copy file public key failed: ${e.message}")
        }
    }
    
    private fun pasteFileRecipientPublicKey() {
        try {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            
            if (clipboard.hasPrimaryClip() && 
                clipboard.primaryClipDescription?.hasMimeType(ClipDescription.MIMETYPE_TEXT_PLAIN) == true) {
                
                val item = clipboard.primaryClip?.getItemAt(0)
                val pasteData = item?.text?.toString()
                
                if (!pasteData.isNullOrEmpty()) {
                    editTextFileRecipientPublicKey.setText(pasteData)
                    showToast("📋 Public key pasted from clipboard")
                    addDebugMessage("📋 File recipient public key pasted from clipboard")
                } else {
                    showToast("Clipboard is empty")
                }
            } else {
                showToast("No text data in clipboard")
            }
        } catch (e: Exception) {
            showToast("Failed to paste from clipboard: ${e.message}")
            addDebugMessage("❌ Paste file recipient public key failed: ${e.message}")
        }
    }
    
    private fun clearFileRecipientPublicKey() {
        try {
            editTextFileRecipientPublicKey.setText("")
            showToast("🗑️ Recipient's public key cleared")
            addDebugMessage("🗑️ File recipient public key cleared")
        } catch (e: Exception) {
            showToast("Failed to clear recipient key: ${e.message}")
            addDebugMessage("❌ Clear file recipient public key failed: ${e.message}")
        }
    }

    private fun showInstructionsTab() {
        viewEncryptTab.visibility = View.GONE
        viewDecryptTab.visibility = View.GONE
        viewFileEncryptionTab.visibility = View.GONE
        viewInstructionsTab.visibility = View.VISIBLE
        cardViewEncryptedMessage.visibility = View.GONE
        
        // Enable clickable links in instructions TextView
        val textViewAppOverview = findViewById<TextView>(R.id.textViewAppOverview)
        textViewAppOverview?.let { textView ->
            val text = textView.text.toString()
            val spannableString = SpannableString(text)
            
            val clickableSpan = object : ClickableSpan() {
                override fun onClick(widget: View) {
                    val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://dev-offcode.com"))
                    startActivity(intent)
                }
                
                override fun updateDrawState(ds: TextPaint) {
                    super.updateDrawState(ds)
                    ds.isUnderlineText = true
                    ds.color = Color.parseColor("#4CAF50") // Vihreä väri
                }
            }
            
            val startIndex = text.indexOf("https://dev-offcode.com")
            val endIndex = startIndex + "https://dev-offcode.com".length
            
            if (startIndex != -1) {
                spannableString.setSpan(clickableSpan, startIndex, endIndex, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                textView.text = spannableString
                textView.movementMethod = LinkMovementMethod.getInstance()
            }
        }
    }



}
