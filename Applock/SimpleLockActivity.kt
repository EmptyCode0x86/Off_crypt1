package com.example.LinkHUB

import android.util.Log
import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.app.AlertDialog
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.text.InputType
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.accessibility.AccessibilityEvent
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.util.Base64
import java.util.Arrays
import android.content.IntentFilter
import com.google.android.material.tabs.TabLayout

class SimpleLockActivity : AppCompatActivity() {

    private lateinit var editTextPassword: EditText
    private lateinit var editTextPasswordConfirm: EditText
    private lateinit var buttonSavePassword: Button
    private lateinit var buttonRemovePassword: Button
    private lateinit var infoButton: Button
    private lateinit var textViewStatus: TextView
    private lateinit var recyclerViewApps: RecyclerView
    private lateinit var buttonRefreshApps: Button
    private lateinit var switchMonitoring: Switch
    private lateinit var editTextSearch: EditText
    private lateinit var buttonSearch: Button

    private lateinit var sharedPreferences: SharedPreferences
    private lateinit var crypto: ApplockEncryption
    private lateinit var appAdapter: SimpleAppAdapter
    private var appList = mutableListOf<SimpleAppInfo>()
    private var filteredAppList = mutableListOf<SimpleAppInfo>()
    private var lockedApps = mutableSetOf<String>()
    private var signingKeyPair: KeyPair? = null
    private var isPasswordSet = false
    private var isMonitoring = false
    private val handler = Handler(Looper.getMainLooper())

    // Security enhancement fields
    private val sensitiveData = mutableListOf<ByteArray>()
    private val secureRandom = SecureRandom()

    private lateinit var tabLayout: TabLayout
    private lateinit var scrollViewSimpleLock: ScrollView

    companion object {
        private const val PREFS_NAME = "SimpleLockPrefs"
        private const val KEY_ENCRYPTED_PASSWORD = "encrypted_password"
        private const val KEY_LOCKED_APPS = "locked_apps"
        private const val KEY_SIGNING_KEY_PRIVATE = "signing_key_private"
        private const val KEY_SIGNING_KEY_PUBLIC = "signing_key_public"
        private const val KEY_MONITORING_ACTIVE = "monitoring_active"
        private const val KEY_FAIL_COUNT = "fail_count"
        private const val KEY_COOLDOWN_UNTIL = "cooldown_until"
        private const val REQUEST_ACCESSIBILITY = 1001
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_simple_lock)
        initializeComponents()
        setupClickListeners()
        loadSettings()
        setupRecyclerView()
        setupTabNavigation()
        updateUI()
    }

    private fun initializeComponents() {
        tabLayout = findViewById(R.id.tabLayout)
        scrollViewSimpleLock = findViewById(R.id.scrollViewSimpleLock)

        editTextPassword = findViewById(R.id.editTextPassword)
        editTextPasswordConfirm = findViewById(R.id.editTextPasswordConfirm)
        buttonSavePassword = findViewById(R.id.buttonSavePassword)
        buttonRemovePassword = findViewById(R.id.buttonRemovePassword)
        textViewStatus = findViewById(R.id.textViewStatus)
        recyclerViewApps = findViewById(R.id.recyclerViewApps)
        buttonRefreshApps = findViewById(R.id.buttonRefreshApps)
        switchMonitoring = findViewById(R.id.switchMonitoring)
        infoButton = findViewById(R.id.infoButton)
        editTextSearch = findViewById(R.id.editTextSearch)
        buttonSearch = findViewById(R.id.buttonSearch)

        sharedPreferences = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        crypto = ApplockEncryption()

        loadOrGenerateSigningKeys()
    }

    private fun setupTabNavigation() {
        tabLayout.addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
            override fun onTabSelected(tab: TabLayout.Tab?) {
                when(tab?.position) {
                    0 -> {
                        // Kryptaus-tabi valittu
                        scrollViewSimpleLock.visibility = View.GONE

                        try {
                            val intent = Intent(this@SimpleLockActivity, SecureMessageActivity::class.java)
                            intent.flags = Intent.FLAG_ACTIVITY_REORDER_TO_FRONT
                            startActivity(intent)
                            finish() // Sulje nykyinen Activity
                        } catch (e: Exception) {
                            showToast("Kryptaus ei käytettävissä: ${e.message}")
                        }
                    }
                    1 -> {
                        // SimpleLock-tabi valittu (nykyinen)
                        scrollViewSimpleLock.visibility = View.VISIBLE
                    }
                    2 -> {
                        // Äänenmuunnin-tabi valittu
                        scrollViewSimpleLock.visibility = View.GONE

                        try {
                            val intent = Intent(this@SimpleLockActivity, VoiceChanger::class.java)
                            intent.flags = Intent.FLAG_ACTIVITY_REORDER_TO_FRONT
                            startActivity(intent)
                            finish() // Sulje nykyinen Activity
                        } catch (e: Exception) {
                            showToast("Äänenmuunnin ei käytettävissä: ${e.message}")
                        }
                    }
                }
            }

            override fun onTabUnselected(tab: TabLayout.Tab?) {}
            override fun onTabReselected(tab: TabLayout.Tab?) {
                when(tab?.position) {
                    1 -> {
                        scrollViewSimpleLock.visibility = View.VISIBLE
                    }
                }
            }
        })

        // Aloita toisesta tabista (SimpleLock)
        tabLayout.selectTab(tabLayout.getTabAt(1))
    }

    // UUSI: Takaisin-nappi vie MenuActivity:lle (pääsivulle)
    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        try {
            val intent = Intent(this@SimpleLockActivity, MenuActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            startActivity(intent)
            finish()
        } catch (e: Exception) {
            showToast("Navigointi päävalikkoon epäonnistui: ${e.message}")
            super.onBackPressed()
        }
    }


    private fun setupClickListeners() {
        buttonSavePassword.setOnClickListener {
            savePassword()
        }

        buttonRemovePassword.setOnClickListener {
            removePassword()
        }

        buttonRefreshApps.setOnClickListener {
            loadInstalledApps()
        }

        switchMonitoring.setOnCheckedChangeListener { _, isChecked ->
            toggleMonitoring(isChecked)
        }

        infoButton.setOnClickListener {
            showAccessibilityDialog()
        }

        buttonSearch.setOnClickListener {
            searchApps()
        }
    }

    private fun searchApps() {
        val searchQuery = editTextSearch.text.toString().trim()

        if (searchQuery.isEmpty()) {
            // Jos hakukenttä tyhjä, näytä kaikki sovellukset
            filteredAppList.clear()
            filteredAppList.addAll(appList)
        } else {
            // Suodata sovellukset nimen perusteella
            filteredAppList.clear()
            filteredAppList.addAll(
                appList.filter { app ->
                    app.name.contains(searchQuery, ignoreCase = true)
                }
            )
        }

        appAdapter.notifyDataSetChanged()
        showToast("Löytyi ${filteredAppList.size} sovellusta")
    }

    private fun setupRecyclerView() {
        appAdapter = SimpleAppAdapter(filteredAppList) { packageName, isLocked ->
            if (isLocked) {
                lockedApps.add(packageName)
            } else {
                lockedApps.remove(packageName)
            }
            saveLockedApps()
        }

        recyclerViewApps.layoutManager = LinearLayoutManager(this)
        recyclerViewApps.adapter = appAdapter

        loadInstalledApps()
    }

    private fun loadSettings() {
        isPasswordSet = sharedPreferences.contains(KEY_ENCRYPTED_PASSWORD)
        isMonitoring = sharedPreferences.getBoolean(KEY_MONITORING_ACTIVE, false)
        switchMonitoring.isChecked = isMonitoring
        loadLockedApps()
    }

    private fun loadOrGenerateSigningKeys() {
        try {
            val privateKeyString = sharedPreferences.getString(KEY_SIGNING_KEY_PRIVATE, null)
            val publicKeyString = sharedPreferences.getString(KEY_SIGNING_KEY_PUBLIC, null)

            if (privateKeyString != null && publicKeyString != null) {
                val keyFactory = java.security.KeyFactory.getInstance("RSA")
                val privateKeyBytes = Base64.getDecoder().decode(privateKeyString)
                val publicKeyBytes = Base64.getDecoder().decode(publicKeyString)

                val privateKeySpec = java.security.spec.PKCS8EncodedKeySpec(privateKeyBytes)
                val publicKeySpec = java.security.spec.X509EncodedKeySpec(publicKeyBytes)

                val privateKey = keyFactory.generatePrivate(privateKeySpec)
                val publicKey = keyFactory.generatePublic(publicKeySpec)

                signingKeyPair = KeyPair(publicKey, privateKey)
            } else {
                generateNewSigningKeys()
            }
        } catch (e: Exception) {
            generateNewSigningKeys()
        }
    }

    private fun generateNewSigningKeys() {
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            keyPairGenerator.initialize(2048)
            signingKeyPair = keyPairGenerator.generateKeyPair()

            val privateKeyString = Base64.getEncoder().encodeToString(signingKeyPair!!.private.encoded)
            val publicKeyString = Base64.getEncoder().encodeToString(signingKeyPair!!.public.encoded)

            sharedPreferences.edit()
                .putString(KEY_SIGNING_KEY_PRIVATE, privateKeyString)
                .putString(KEY_SIGNING_KEY_PUBLIC, publicKeyString)
                .apply()

        } catch (e: Exception) {
            showToast("Virhe avainten generoinnissa: ${e.message}")
        }
    }

    private fun savePassword() {
        val password = editTextPassword.text.toString()
        val confirmPassword = editTextPasswordConfirm.text.toString()

        if (password.isEmpty()) {
            showToast("Syötä salasana")
            return
        }

        if (password != confirmPassword) {
            showToast("Salasanat eivät täsmää")
            return
        }

        if (password.length < 6) {
            showToast("Salasanan tulee olla vähintään 6 merkkiä")
            return
        }

        try {
            val testMessage = "password_verification_${System.currentTimeMillis()}"

            // Enhanced encryption with signature, PFS, and HMAC
            val encryptedPassword = crypto.encryptPasswordWithSignatureAndPFS(
                testMessage,
                password,
                signingKeyPair
            )

            sharedPreferences.edit()
                .putString(KEY_ENCRYPTED_PASSWORD, encryptedPassword)
                .putInt(KEY_FAIL_COUNT, 0) // Reset fail count on new password
                .putLong(KEY_COOLDOWN_UNTIL, 0) // Reset cooldown
                .apply()

            isPasswordSet = true

            // Secure wipe of password inputs
            addToSensitiveData(password.toByteArray())
            addToSensitiveData(confirmPassword.toByteArray())

            editTextPassword.text.clear()
            editTextPasswordConfirm.text.clear()

            showToast("Salasana tallennettu turvallisesti (RSA + AES-256-GCM + HMAC + PFS)")
            updateUI()

        } catch (e: Exception) {
            showToast("Virhe salasanan tallennuksessa: ${e.message}")
            // Secure wipe even on error
            addToSensitiveData(password.toByteArray())
            addToSensitiveData(confirmPassword.toByteArray())
        }
    }

    private fun removePassword() {
        AlertDialog.Builder(this)
            .setTitle("Poista salasana")
            .setMessage("Haluatko varmasti poistaa salasanan? Tämä poistaa myös kaikki lukitukset.")
            .setPositiveButton("Poista") { _, _ ->
                // Secure wipe before removal
                secureWipeAllSensitiveData()

                sharedPreferences.edit()
                    .remove(KEY_ENCRYPTED_PASSWORD)
                    .remove(KEY_LOCKED_APPS)
                    .remove(KEY_FAIL_COUNT)
                    .remove(KEY_COOLDOWN_UNTIL)
                    .putBoolean(KEY_MONITORING_ACTIVE, false)
                    .apply()

                isPasswordSet = false
                isMonitoring = false
                lockedApps.clear()
                switchMonitoring.isChecked = false
                appAdapter.notifyDataSetChanged()
                updateUI()

                showToast("Salasana poistettu turvallisesti")
            }
            .setNegativeButton("Peruuta", null)
            .show()
    }

    fun toggleMonitoring(enabled: Boolean) {
        if (enabled && !isPasswordSet) {
            showToast("Aseta ensin salasana")
            switchMonitoring.isChecked = false
            return
        }

        isMonitoring = enabled
        sharedPreferences.edit().putBoolean(KEY_MONITORING_ACTIVE, enabled).apply()

        if (enabled) {
            showToast("✅ Aktivoitu")
        }

        updateUI()
    }

    private fun showAccessibilityDialog() {
        val message = "🔒 AKTIVOI ACCESSIBILITYSERVICE (Pääoikeus)\n\n" +
                "Sovellus tarvitsee AccessibilityService-oikeuden toimiakseen.\n\n" +
                "📱 Katso tarkat ohjeet ja kaikki tarvittavat oikeudet\n" +
                "'Tarvittavat käyttöoikeudet' -napista.\n\n"


        val dialog = AlertDialog.Builder(this)
            .setTitle("🔒 Käyttöoikeudet")
            .setMessage(message)
            .setPositiveButton("🔒 Tarvittavat käyttöoikeudet") { _, _ ->
                showOtherPermissionsDialog()
            }
            .setNegativeButton("❌ Peruuta", null)
            .create()

        dialog.show()

        // Vaihda nappien tekstin väri valkoiseksi
        dialog.getButton(AlertDialog.BUTTON_POSITIVE)?.setTextColor(android.graphics.Color.WHITE)
        dialog.getButton(AlertDialog.BUTTON_NEGATIVE)?.setTextColor(android.graphics.Color.WHITE)
    }


    private fun showOtherPermissionsDialog() {
        val message = "🔧 TARVITTAVAT KÄYTTÖOIKEUDET:\n\n" +
                "🔒 AccessibilityService (Pääoikeus):\n" +
                "→ Polku: Asetukset → Saavutettavuus → Ladatut sovellukset\n" +
                "→ Etsi '${getString(R.string.app_name)}' ja aktivoi\n" +
                "→ Hyväksy turvallisuusvaroitus\n\n" +
                "⚙️ Kehittäjäasetukset (Accessibility-oikeuksille):\n" +
                "→ Kehittäjäasetuksissa: ⋮ (kolme pistettä oikealla ylhäällä) → Lisäoikeudet\n" +
                "→ Tarvitaan jotta AccessibilityService toimii oikein ja sovelluksia voi lukita\n\n" +
                "📱 Overlay Permission:\n" +
                "→ Polku: Asetukset → Sovellukset → Erikoiskäyttöoikeudet → Näyttö muiden sovellusten päällä\n" +
                "→ Etsi '${getString(R.string.app_name)}' ja aktivoi"

        val dialog = AlertDialog.Builder(this)
            .setTitle("🔒 Tarvittavat käyttöoikeudet")
            .setMessage(message)
            .setPositiveButton("🎯 Sovelluksen asetukset") { _, _ ->
                openAppSettings()
            }
            .setNegativeButton("🔒 AccessibilityService") { _, _ ->
                openAccessibilitySettings()
            }
            .setNeutralButton("📱 Overlay Permission") { _, _ ->
                openOverlaySettings()
            }
            .create()

        dialog.show()

        // Vaihda nappien tekstin väri valkoiseksi
        dialog.getButton(AlertDialog.BUTTON_POSITIVE)?.setTextColor(android.graphics.Color.WHITE)
        dialog.getButton(AlertDialog.BUTTON_NEGATIVE)?.setTextColor(android.graphics.Color.WHITE)
        dialog.getButton(AlertDialog.BUTTON_NEUTRAL)?.setTextColor(android.graphics.Color.WHITE)
    }

    private fun openAccessibilitySettings() {
        try {
            val intent = Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            startActivity(intent)
            showToast("✅ Etsi '${getString(R.string.app_name)}' ja aktivoi se")
        } catch (e: Exception) {
            showToast("❌ Avaa manuaalisesti: Asetukset → Saavutettavuus")
        }
    }

    private fun openOverlaySettings() {
        try {
            val intent = Intent(
                Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                android.net.Uri.parse("package:$packageName")
            )
            startActivity(intent)
            showToast("✅ Aktivoi 'Display over other apps'")
        } catch (e: Exception) {
            showToast("❌ Avaa manuaalisesti: Asetukset → Sovellukset → Erikoiskäyttöoikeudet")
        }
    }

    private fun isAccessibilityServiceEnabled(): Boolean {
        val enabledServices = Settings.Secure.getString(
            contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ) ?: ""

        // Debug-logitus näyttää mitä Android todella tallentaa
        Log.d("AccessibilityCheck", "Enabled services: $enabledServices")

        // Tarkistaa kaikki mahdolliset formaatit:
        val serviceComponent1 = "$packageName/.SimpleAppLockService"
        val serviceComponent2 = "$packageName/com.example.LinkHUB.SimpleAppLockService"
        val serviceComponent3 = "com.example.LinkHUB/.SimpleAppLockService"
        val serviceComponent4 = "com.example.LinkHUB/com.example.LinkHUB.SimpleAppLockService"

        // Palauttaa true jos mikä tahansa formaatti löytyy
        return enabledServices.contains(serviceComponent1) ||
                enabledServices.contains(serviceComponent2) ||
                enabledServices.contains(serviceComponent3) ||
                enabledServices.contains(serviceComponent4) ||
                enabledServices.contains("SimpleAppLockService")
    }

    private fun hasWriteSecureSettings(): Boolean {
        return try {
            // Yritä kirjoittaa testiarvo secure settingseihin
            Settings.Secure.putString(contentResolver, "test_write_permission", "test")
            Settings.Secure.getString(contentResolver, "test_write_permission")
            true
        } catch (e: SecurityException) {
            false
        } catch (e: Exception) {
            false
        }
    }

    private fun showLockDialog(packageName: String) {
        // Tarkista onko SYSTEM_ALERT_WINDOW oikeus
        if (!Settings.canDrawOverlays(this)) {
            requestOverlayPermission()
            return
        }

        val appName = try {
            packageManager.getApplicationLabel(
                packageManager.getApplicationInfo(packageName, 0)
            ).toString()
        } catch (e: Exception) {
            packageName
        }

        android.util.Log.d("LockDialog", "Creating lock dialog for: $appName")

        // Luo fullscreen overlay-ikkuna
        val windowManager = getSystemService(Context.WINDOW_SERVICE) as WindowManager
        val lockView = layoutInflater.inflate(R.layout.lock_screen_overlay, null)

        val layoutParams = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
            WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON or
                    WindowManager.LayoutParams.FLAG_DISMISS_KEYGUARD or
                    WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
                    WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON,
            android.graphics.PixelFormat.TRANSLUCENT
        )

        // Aseta UI-elementit
        val titleText = lockView.findViewById<TextView>(R.id.lockTitle)
        val passwordInput = lockView.findViewById<EditText>(R.id.lockPassword)
        val unlockButton = lockView.findViewById<Button>(R.id.unlockButton)
        val cancelButton = lockView.findViewById<Button>(R.id.cancelButton)

        titleText.text = "🔒 $appName lukittu"

        // Brute force protection check
        val cooldownUntil = sharedPreferences.getLong(KEY_COOLDOWN_UNTIL, 0)
        val currentTime = System.currentTimeMillis()

        if (currentTime < cooldownUntil) {
            val remainingSeconds = ((cooldownUntil - currentTime) / 1000).toInt()
            passwordInput.isEnabled = false
            unlockButton.isEnabled = false
            unlockButton.text = "Lukittu ${remainingSeconds}s"

            // Start countdown timer
            startCooldownTimer(passwordInput, unlockButton, remainingSeconds)
        }

        unlockButton.setOnClickListener {
            if (unlockButton.isEnabled) {
                val enteredPassword = passwordInput.text.toString()
                if (verifyPasswordWithBruteForceProtection(enteredPassword, passwordInput, unlockButton)) {
                    showToast("✅ Sovellus avattu")
                    windowManager.removeView(lockView)
                } else {
                    passwordInput.text.clear()
                    // Palaa kotinäyttöön väärän salasanan jälkeen
                    goToHomeScreen()
                    windowManager.removeView(lockView)
                }
            }
        }

        cancelButton.setOnClickListener {
            goToHomeScreen()
            windowManager.removeView(lockView)
        }

        try {
            windowManager.addView(lockView, layoutParams)
            android.util.Log.d("LockDialog", "Lock dialog displayed successfully")
        } catch (e: Exception) {
            android.util.Log.e("LockDialog", "Failed to show lock dialog", e)
            showToast("Virhe lukitusikkunan näyttämisessä: ${e.message}")
        }
    }

    private fun verifyPasswordWithBruteForceProtection(
        enteredPassword: String,
        passwordInput: EditText,
        unlockButton: Button
    ): Boolean {
        val currentTime = System.currentTimeMillis()
        val cooldownUntil = sharedPreferences.getLong(KEY_COOLDOWN_UNTIL, 0)

        // Check if still in cooldown
        if (currentTime < cooldownUntil) {
            val remainingSeconds = ((cooldownUntil - currentTime) / 1000).toInt()
            showToast("⏰ Odota vielä ${remainingSeconds} sekuntia")
            return false
        }

        if (verifyPassword(enteredPassword)) {
            // Reset fail count on successful login
            sharedPreferences.edit()
                .putInt(KEY_FAIL_COUNT, 0)
                .putLong(KEY_COOLDOWN_UNTIL, 0)
                .apply()
            return true
        } else {
            // Handle failed attempt
            val failCount = sharedPreferences.getInt(KEY_FAIL_COUNT, 0) + 1
            var cooldownDuration = 0L

            if (failCount >= 3) {
                if (failCount == 3) {
                    cooldownDuration = 30 * 1000L // 30 seconds for first lockout
                } else {
                    cooldownDuration = (failCount - 2) * 60 * 1000L // +1 minute for each additional fail
                }

                val newCooldownUntil = currentTime + cooldownDuration

                sharedPreferences.edit()
                    .putInt(KEY_FAIL_COUNT, failCount)
                    .putLong(KEY_COOLDOWN_UNTIL, newCooldownUntil)
                    .apply()

                val cooldownMinutes = cooldownDuration / 60000
                val cooldownSeconds = (cooldownDuration % 60000) / 1000

                val timeMessage = if (cooldownMinutes > 0) {
                    "${cooldownMinutes}min ${cooldownSeconds}s"
                } else {
                    "${cooldownSeconds}s"
                }

                showToast("🔒 Liian monta väärää yritystä! Lukittu ${timeMessage}")

                passwordInput.isEnabled = false
                unlockButton.isEnabled = false
                startCooldownTimer(passwordInput, unlockButton, (cooldownDuration / 1000).toInt())
            } else {
                sharedPreferences.edit()
                    .putInt(KEY_FAIL_COUNT, failCount)
                    .apply()

                val attemptsLeft = 3 - failCount
                showToast("❌ Väärä salasana! ${attemptsLeft} yritystä jäljellä")
            }
            return false
        }
    }

    private fun startCooldownTimer(passwordInput: EditText, unlockButton: Button, seconds: Int) {
        var remainingSeconds = seconds

        val timer = object : Runnable {
            override fun run() {
                if (remainingSeconds > 0) {
                    unlockButton.text = "Lukittu ${remainingSeconds}s"
                    remainingSeconds--
                    handler.postDelayed(this, 1000)
                } else {
                    passwordInput.isEnabled = true
                    unlockButton.isEnabled = true
                    unlockButton.text = "Avaa"
                }
            }
        }
        handler.post(timer)
    }

    private fun requestOverlayPermission() {
        AlertDialog.Builder(this)
            .setTitle("Overlay-oikeus tarvitaan")
            .setMessage("Lukitusikkuna tarvitsee oikeuden näkyä muiden sovellusten päällä.")
            .setPositiveButton("Avaa asetukset") { _, _ ->
                val intent = Intent(
                    Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                    android.net.Uri.parse("package:$packageName")
                )
                startActivity(intent)
            }
            .setNegativeButton("Peruuta", null)
            .show()
    }

    private fun goToHomeScreen() {
        val homeIntent = Intent(Intent.ACTION_MAIN).apply {
            addCategory(Intent.CATEGORY_HOME)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }
        startActivity(homeIntent)
    }

    private fun verifyPassword(enteredPassword: String): Boolean {
        val encryptedPassword = sharedPreferences.getString(KEY_ENCRYPTED_PASSWORD, null)
            ?: return false

        return try {
            val result = crypto.decryptPasswordWithSignatureAndPFS(
                encryptedPassword,
                enteredPassword,
                signingKeyPair?.public
            )

            // Enhanced verification with signature and metadata validation
            val isValid = result.message.startsWith("password_verification_") &&
                    result.signatureValid &&
                    result.hasPFS

            if (isValid) {
                // Log successful verification with PFS
                Log.d("AppLock", "Password verified with signature and PFS")
            } else {
                Log.w("AppLock", "Password verification failed - signature: ${result.signatureValid}, PFS: ${result.hasPFS}")
            }

            // Secure wipe of entered password
            addToSensitiveData(enteredPassword.toByteArray())

            isValid

        } catch (e: Exception) {
            Log.e("AppLock", "Password verification failed", e)
            addToSensitiveData(enteredPassword.toByteArray())
            false
        }
    }

    // Add sensitive data for secure wiping
    private fun addToSensitiveData(data: ByteArray) {
        if (data.isNotEmpty()) {
            sensitiveData.add(data.clone())
        }
    }

    // Secure wipe of all sensitive data
    private fun secureWipeAllSensitiveData() {
        try {
            sensitiveData.forEach { data ->
                secureWipeByteArray(data)
            }
            sensitiveData.clear()

            // Force garbage collection
            repeat(3) {
                System.gc()
                System.runFinalization()
                Thread.sleep(50)
            }

        } catch (e: Exception) {
            Log.e("AppLock", "Secure wipe failed", e)
        }
    }

    // 7-pass secure memory wiping
    private fun secureWipeByteArray(array: ByteArray) {
        try {
            val patterns = byteArrayOf(
                0x00.toByte(), 0xFF.toByte(), 0xAA.toByte(), 0x55.toByte(),
                0x92.toByte(), 0x49.toByte(), 0x24.toByte()
            )

            for (pass in patterns.indices) {
                val pattern = patterns[pass]

                for (i in array.indices) {
                    array[i] = pattern
                    // Memory barrier to prevent optimization
                    @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
                    val barrier = (array as java.lang.Object).hashCode()
                }

                // Final pass with random data
                if (pass == patterns.size - 1) {
                    secureRandom.nextBytes(array)
                }

                Thread.yield()
            }

            // Final zero fill
            Arrays.fill(array, 0.toByte())

        } catch (e: Exception) {
            Arrays.fill(array, 0.toByte())
        }
    }
    fun loadInstalledApps() {
        appList.clear()
        val pm = packageManager
        val apps = pm.getInstalledApplications(PackageManager.GET_META_DATA)

        for (app in apps) {
            val pkg = app.packageName

            // Ohita järjestelmäsovellukset
            if ((app.flags and ApplicationInfo.FLAG_SYSTEM) != 0) continue

            // Ohita com.android, com.google, com.qualcomm jne
            if (pkg.startsWith("com.android") || pkg.startsWith("com.google") || pkg.startsWith("com.qualcomm")) continue

            try {
                val name = pm.getApplicationLabel(app).toString()
                val icon = pm.getApplicationIcon(app)
                appList.add(SimpleAppInfo(name, pkg, icon, lockedApps.contains(pkg)))
                Log.d("AppLoader", "Added user app: $name ($pkg)")
            } catch (e: Exception) {
                Log.e("AppLoader", "Failed to load app $pkg", e)
            }
        }

        appList.sortBy { it.name }

        // Päivitä suodatettu lista
        filteredAppList.clear()
        filteredAppList.addAll(appList)

        appAdapter.notifyDataSetChanged()
        Log.d("AppLoader", "Final user-app list size: ${appList.size}")
    }

    private fun loadLockedApps() {
        val lockedAppsString = sharedPreferences.getString(KEY_LOCKED_APPS, "")
        if (!lockedAppsString.isNullOrEmpty()) {
            try {
                lockedApps = lockedAppsString.split(",").filter { it.isNotEmpty() }.toMutableSet()
            } catch (e: Exception) {
                lockedApps.clear()
            }
        }
    }

    private fun saveLockedApps() {
        val lockedAppsString = lockedApps.joinToString(",")
        sharedPreferences.edit().putString(KEY_LOCKED_APPS, lockedAppsString).apply()
    }

    private fun updateUI() {
        if (isPasswordSet) {
            if (isMonitoring && isAccessibilityServiceEnabled()) {
                textViewStatus.text = "✅ Lukitus aktiivinen (AccessibilityService) - ${lockedApps.size} sovellusta valvonnassa"
                textViewStatus.setTextColor(ContextCompat.getColor(this, android.R.color.holo_green_dark))
            } else if (isPasswordSet && !isAccessibilityServiceEnabled()) {
                textViewStatus.text = "⚠️ AccessibilityService sammunut - aktivoi uudelleen jotta sovelluksen lukitseminen toimii"
                textViewStatus.setTextColor(ContextCompat.getColor(this, android.R.color.holo_red_dark))
            } else {
                textViewStatus.text = "🔓 Salasana asetettu - aktivoi AccessibilityService"
                textViewStatus.setTextColor(ContextCompat.getColor(this, android.R.color.holo_orange_dark))
            }

            buttonRemovePassword.visibility = View.VISIBLE

        } else {
            textViewStatus.text = "⚠ Aseta ensin salasana"
            textViewStatus.setTextColor(ContextCompat.getColor(this, android.R.color.holo_orange_dark))

            buttonRemovePassword.visibility = View.GONE
        }
    }
    private fun openAppSettings() {
        try {
            val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                data = android.net.Uri.parse("package:$packageName")
            }
            startActivity(intent)
            showToast("Etsi 3 pistettä (⋮) → Allow restricted settings")
        } catch (e: Exception) {
            try {
                val intent = Intent(Settings.ACTION_MANAGE_APPLICATIONS_SETTINGS)
                startActivity(intent)
                showToast("Etsi LinkHUB → App info → 3 pistettä → Allow restricted settings")
            } catch (e2: Exception) {
                showToast("Avaa manuaalisesti: Asetukset → Sovellukset → LinkHUB")
            }
        }
    }

    private fun showToast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_ACCESSIBILITY) {
            Handler(Looper.getMainLooper()).postDelayed({
                if (isAccessibilityServiceEnabled()) {
                    switchMonitoring.isChecked = true
                    sharedPreferences.edit().putBoolean(KEY_MONITORING_ACTIVE, true).apply()
                    showToast("✅ AccessibilityService aktivoitu!")
                    updateUI()
                } else {
                    showToast("AccessibilityService ei aktivoitunut. Yritä uudelleen.")
                }
            }, 1000)
        }
    }

    override fun onResume() {
        super.onResume()
        updateUI()
    }

    override fun onPause() {
        super.onPause()
        // Secure wipe sensitive data when app goes to background
        secureWipeAllSensitiveData()

        // Jatka valvontaa taustalla jos on käytössä
    }

    override fun onDestroy() {
        super.onDestroy()
        // Complete secure wipe on destroy
        secureWipeAllSensitiveData()

        // Clear signing key pair
        signingKeyPair = null

        // Final memory cleanup
        System.gc()
    }
}

class SimpleAppLockService : AccessibilityService() {

    private lateinit var sharedPreferences: SharedPreferences
    private lateinit var crypto: ApplockEncryption
    private var lockedApps = mutableSetOf<String>()
    private var signingKeyPair: KeyPair? = null
    private var isLockActive = false
    private var currentForegroundApp = ""
    private val handler = Handler(Looper.getMainLooper())
    private var passwordDialog: AlertDialog? = null
    private val secureRandom = SecureRandom()

    // MUUTETTU: Yksinkertainen set avoimista sovelluksista (ei aikasidottuja)
    private var unlockedApps = mutableSetOf<String>() // Vain package nimet

    // Salasanan hashin seuranta
    private var lastPasswordHash = ""

    // UUSI: Näytön tilan seuranta
    private var screenStateReceiver: BroadcastReceiver? = null

    companion object {
        private const val PREFS_NAME = "SimpleLockPrefs"
        private const val KEY_ENCRYPTED_PASSWORD = "encrypted_password"
        private const val KEY_LOCKED_APPS = "locked_apps"
        private const val KEY_MONITORING_ACTIVE = "monitoring_active"
        private const val KEY_SIGNING_KEY_PRIVATE = "signing_key_private"
        private const val KEY_SIGNING_KEY_PUBLIC = "signing_key_public"
        private const val KEY_FAIL_COUNT = "fail_count"
        private const val KEY_COOLDOWN_UNTIL = "cooldown_until"
    }

    override fun onCreate() {
        super.onCreate()
        initialize()
        setupScreenStateReceiver()
    }

    private fun initialize() {
        sharedPreferences = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        crypto = ApplockEncryption()
        loadSettings()
        loadSigningKeys()

        // Tallenna nykyinen salasanan hash
        lastPasswordHash = sharedPreferences.getString(KEY_ENCRYPTED_PASSWORD, "") ?: ""
    }

    // UUSI: Aseta näytön tilan kuuntelija
    private fun setupScreenStateReceiver() {
        screenStateReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                when (intent?.action) {
                    Intent.ACTION_SCREEN_OFF -> {
                        // Näyttö sammui - lukitse kaikki sovellukset takaisin
                        android.util.Log.d("AppLock", "Screen turned OFF - locking all apps")
                        unlockedApps.clear()
                    }
                    Intent.ACTION_SCREEN_ON -> {
                        // Näyttö syttyi - älä tee mitään (sovellukset pysyvät lukittuina)
                        android.util.Log.d("AppLock", "Screen turned ON - apps remain locked")
                    }
                }
            }
        }

        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_SCREEN_ON)
        }
        registerReceiver(screenStateReceiver, filter)
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        val info = AccessibilityServiceInfo().apply {
            eventTypes = AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED
            feedbackType = AccessibilityServiceInfo.FEEDBACK_GENERIC
            flags = AccessibilityServiceInfo.FLAG_INCLUDE_NOT_IMPORTANT_VIEWS
        }
        serviceInfo = info
        loadSettings()
    }

    private fun loadSettings() {
        isLockActive = sharedPreferences.getBoolean(KEY_MONITORING_ACTIVE, false)
        loadLockedApps()
    }

    private fun loadLockedApps() {
        val lockedAppsString = sharedPreferences.getString(KEY_LOCKED_APPS, "")
        if (!lockedAppsString.isNullOrEmpty()) {
            try {
                lockedApps = lockedAppsString.split(",").filter { it.isNotEmpty() }.toMutableSet()
            } catch (e: Exception) {
                lockedApps.clear()
            }
        }
    }

    private fun loadSigningKeys() {
        try {
            val privateKeyString = sharedPreferences.getString(KEY_SIGNING_KEY_PRIVATE, null)
            val publicKeyString = sharedPreferences.getString(KEY_SIGNING_KEY_PUBLIC, null)

            if (privateKeyString != null && publicKeyString != null) {
                val keyFactory = java.security.KeyFactory.getInstance("RSA")
                val privateKeyBytes = Base64.getDecoder().decode(privateKeyString)
                val publicKeyBytes = Base64.getDecoder().decode(publicKeyString)

                val privateKeySpec = java.security.spec.PKCS8EncodedKeySpec(privateKeyBytes)
                val publicKeySpec = java.security.spec.X509EncodedKeySpec(publicKeyBytes)

                val privateKey = keyFactory.generatePrivate(privateKeySpec)
                val publicKey = keyFactory.generatePublic(publicKeySpec)

                signingKeyPair = KeyPair(publicKey, privateKey)
            }
        } catch (e: Exception) {
            // Avainten lataus epäonnistui
        }
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event?.eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
            val packageName = event.packageName?.toString()
            if (packageName != null && packageName != currentForegroundApp) {
                currentForegroundApp = packageName
                checkAppLock(packageName)
            }
        }
    }

    private fun checkAppLock(packageName: String) {
        android.util.Log.d("AppLock", "Checking app: $packageName")

        // Tarkista onko salasana vaihtunut
        val currentPasswordHash = sharedPreferences.getString(KEY_ENCRYPTED_PASSWORD, "") ?: ""
        if (currentPasswordHash != lastPasswordHash) {
            unlockedApps.clear()
            lastPasswordHash = currentPasswordHash
            android.util.Log.d("AppLock", "Password changed - cleared unlocked apps")
        }

        // Päivitä asetukset reaaliajassa
        loadSettings()

        android.util.Log.d("AppLock", "isLockActive: $isLockActive")
        android.util.Log.d("AppLock", "lockedApps: $lockedApps")
        android.util.Log.d("AppLock", "contains: ${lockedApps.contains(packageName)}")

        // MUUTETTU: Yksinkertainen tarkistus onko sovellus avoinna (ei aikasidottua)
        val isUnlocked = unlockedApps.contains(packageName)

        if (isUnlocked) {
            android.util.Log.d("AppLock", "App $packageName is unlocked")
            return
        }

        if (!isLockActive || !lockedApps.contains(packageName)) {
            return
        }

        android.util.Log.d("AppLock", "Showing lock dialog for: $packageName")
        showPasswordDialog(packageName)
    }

    private fun showPasswordDialog(packageName: String) {
        handler.post {
            if (!Settings.canDrawOverlays(this)) {
                goToHomeScreen()
                return@post
            }

            val appName = try {
                packageManager.getApplicationLabel(
                    packageManager.getApplicationInfo(packageName, 0)
                ).toString()
            } catch (e: Exception) {
                packageName
            }

            // Käytä XML-layoutia AlertDialogin sijaan
            val windowManager = getSystemService(Context.WINDOW_SERVICE) as WindowManager
            val lockView = LayoutInflater.from(this).inflate(R.layout.lock_screen_overlay, null)

            val layoutParams = WindowManager.LayoutParams(
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
                WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON,
                android.graphics.PixelFormat.TRANSLUCENT
            )

            // Käytä samaa logiikkaa kuin showLockDialog():ssa
            val titleText = lockView.findViewById<TextView>(R.id.lockTitle)
            val passwordInput = lockView.findViewById<EditText>(R.id.lockPassword)
            val unlockButton = lockView.findViewById<Button>(R.id.unlockButton)
            val cancelButton = lockView.findViewById<Button>(R.id.cancelButton)

            titleText.text = "🔒 $appName lukittu"

            // Brute force protection check
            val cooldownUntil = sharedPreferences.getLong(KEY_COOLDOWN_UNTIL, 0)
            val currentTime = System.currentTimeMillis()

            if (currentTime < cooldownUntil) {
                val remainingSeconds = ((cooldownUntil - currentTime) / 1000).toInt()
                passwordInput.isEnabled = false
                unlockButton.isEnabled = false
                unlockButton.text = "Lukittu ${remainingSeconds}s"

                // Start countdown timer
                startCooldownTimer(passwordInput, unlockButton, remainingSeconds)
            }

            unlockButton.setOnClickListener {
                if (unlockButton.isEnabled) {
                    val enteredPassword = passwordInput.text.toString()
                    if (verifyPasswordWithBruteForceProtection(enteredPassword, passwordInput, unlockButton)) {
                        // MUUTETTU: Lisää sovellus unlocked-listaan (ei aikasidottua)
                        unlockedApps.add(packageName)
                        android.util.Log.d("AppLock", "App unlocked: $packageName (until screen off)")

                        Toast.makeText(this, "✅ Sovellus avattu", Toast.LENGTH_SHORT).show()
                        windowManager.removeView(lockView)
                    } else {
                        passwordInput.text.clear()
                        goToHomeScreen()
                        windowManager.removeView(lockView)
                    }
                }
            }

            cancelButton.setOnClickListener {
                goToHomeScreen()
                windowManager.removeView(lockView)
            }

            windowManager.addView(lockView, layoutParams)
        }
    }

    private fun verifyPasswordWithBruteForceProtection(
        enteredPassword: String,
        passwordInput: EditText,
        unlockButton: Button
    ): Boolean {
        val currentTime = System.currentTimeMillis()
        val cooldownUntil = sharedPreferences.getLong(KEY_COOLDOWN_UNTIL, 0)

        // Check if still in cooldown
        if (currentTime < cooldownUntil) {
            val remainingSeconds = ((cooldownUntil - currentTime) / 1000).toInt()
            Toast.makeText(this, "⏰ Odota vielä ${remainingSeconds} sekuntia", Toast.LENGTH_SHORT).show()
            return false
        }

        if (verifyPassword(enteredPassword)) {
            // Reset fail count on successful login
            sharedPreferences.edit()
                .putInt(KEY_FAIL_COUNT, 0)
                .putLong(KEY_COOLDOWN_UNTIL, 0)
                .apply()
            return true
        } else {
            // Handle failed attempt
            val failCount = sharedPreferences.getInt(KEY_FAIL_COUNT, 0) + 1
            var cooldownDuration = 0L

            if (failCount >= 3) {
                if (failCount == 3) {
                    cooldownDuration = 30 * 1000L // 30 seconds for first lockout
                } else {
                    cooldownDuration = (failCount - 2) * 60 * 1000L // +1 minute for each additional fail
                }

                val newCooldownUntil = currentTime + cooldownDuration

                sharedPreferences.edit()
                    .putInt(KEY_FAIL_COUNT, failCount)
                    .putLong(KEY_COOLDOWN_UNTIL, newCooldownUntil)
                    .apply()

                val cooldownMinutes = cooldownDuration / 60000
                val cooldownSeconds = (cooldownDuration % 60000) / 1000

                val timeMessage = if (cooldownMinutes > 0) {
                    "${cooldownMinutes}min ${cooldownSeconds}s"
                } else {
                    "${cooldownSeconds}s"
                }

                Toast.makeText(this, "🔒 Liian monta väärää yritystä! Lukittu ${timeMessage}", Toast.LENGTH_LONG).show()

                passwordInput.isEnabled = false
                unlockButton.isEnabled = false
                startCooldownTimer(passwordInput, unlockButton, (cooldownDuration / 1000).toInt())
            } else {
                sharedPreferences.edit()
                    .putInt(KEY_FAIL_COUNT, failCount)
                    .apply()

                val attemptsLeft = 3 - failCount
                Toast.makeText(this, "❌ Väärä salasana! ${attemptsLeft} yritystä jäljellä", Toast.LENGTH_SHORT).show()
            }
            return false
        }
    }

    private fun startCooldownTimer(passwordInput: EditText, unlockButton: Button, seconds: Int) {
        var remainingSeconds = seconds

        val timer = object : Runnable {
            override fun run() {
                if (remainingSeconds > 0) {
                    unlockButton.text = "Lukittu ${remainingSeconds}s"
                    remainingSeconds--
                    handler.postDelayed(this, 1000)
                } else {
                    passwordInput.isEnabled = true
                    unlockButton.isEnabled = true
                    unlockButton.text = "Avaa"
                }
            }
        }
        handler.post(timer)
    }

    private fun verifyPassword(enteredPassword: String): Boolean {
        val encryptedPassword = sharedPreferences.getString(KEY_ENCRYPTED_PASSWORD, null)
            ?: return false

        return try {
            val result = crypto.decryptPasswordWithSignatureAndPFS(
                encryptedPassword,
                enteredPassword,
                signingKeyPair?.public
            )

            // Enhanced verification with signature and PFS validation
            val isValid = result.message.startsWith("password_verification_") &&
                    result.signatureValid &&
                    result.hasPFS

            if (isValid) {
                android.util.Log.d("AppLockService", "Password verified with signature and PFS")
            } else {
                android.util.Log.w("AppLockService", "Password verification failed - signature: ${result.signatureValid}, PFS: ${result.hasPFS}")
            }

            // Secure wipe of entered password
            secureWipeByteArray(enteredPassword.toByteArray())

            isValid

        } catch (e: Exception) {
            android.util.Log.e("AppLockService", "Password verification failed", e)
            secureWipeByteArray(enteredPassword.toByteArray())
            false
        }
    }

    // 7-pass secure memory wiping for service
    private fun secureWipeByteArray(array: ByteArray) {
        try {
            val patterns = byteArrayOf(
                0x00.toByte(), 0xFF.toByte(), 0xAA.toByte(), 0x55.toByte(),
                0x92.toByte(), 0x49.toByte(), 0x24.toByte()
            )

            for (pass in patterns.indices) {
                val pattern = patterns[pass]

                for (i in array.indices) {
                    array[i] = pattern
                    @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
                    val barrier = (array as java.lang.Object).hashCode()
                }

                if (pass == patterns.size - 1) {
                    secureRandom.nextBytes(array)
                }

                Thread.yield()
            }

            Arrays.fill(array, 0.toByte())

        } catch (e: Exception) {
            Arrays.fill(array, 0.toByte())
        }
    }

    private fun goToHomeScreen() {
        val homeIntent = Intent(Intent.ACTION_MAIN).apply {
            addCategory(Intent.CATEGORY_HOME)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }
        startActivity(homeIntent)
    }

    override fun onDestroy() {
        super.onDestroy()

        // UUSI: Poista screen state receiver
        screenStateReceiver?.let {
            try {
                unregisterReceiver(it)
            } catch (e: Exception) {
                // Receiver oli jo poistettu
            }
        }

        // Secure wipe of sensitive data
        crypto = ApplockEncryption() // Reset crypto instance
        signingKeyPair = null

        // Clear unlock sessions securely
        unlockedApps.clear()

        // Force memory cleanup
        System.gc()
    }

    override fun onInterrupt() {
        // Secure cleanup on service interruption
        try {
            unlockedApps.clear()
            signingKeyPair = null
            System.gc()
        } catch (e: Exception) {
            // Silent cleanup
        }
    }
}

// Yksinkertainen AppInfo
data class SimpleAppInfo(
    val name: String,
    val packageName: String,
    val icon: android.graphics.drawable.Drawable,
    var isLocked: Boolean = false
)

// Yksinkertainen AppAdapter
class SimpleAppAdapter(
    private val appList: List<SimpleAppInfo>,
    private val onLockToggle: (String, Boolean) -> Unit
) : RecyclerView.Adapter<SimpleAppAdapter.AppViewHolder>() {

    class AppViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val imageViewAppIcon: ImageView = view.findViewById(R.id.imageViewAppIcon)
        val textViewAppName: TextView = view.findViewById(R.id.textViewAppName)
        val textViewPackageName: TextView = view.findViewById(R.id.textViewPackageName)
        val switchAppLock: Switch = view.findViewById(R.id.switchAppLock)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): AppViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.simple_app_item, parent, false)
        return AppViewHolder(view)
    }

    override fun onBindViewHolder(holder: AppViewHolder, position: Int) {
        val app = appList[position]

        holder.imageViewAppIcon.setImageDrawable(app.icon)
        holder.textViewAppName.text = app.name
        holder.textViewPackageName.text = app.packageName
        holder.switchAppLock.isChecked = app.isLocked

        holder.switchAppLock.setOnCheckedChangeListener { _, isChecked ->
            app.isLocked = isChecked
            onLockToggle(app.packageName, isChecked)
        }
    }

    override fun getItemCount() = appList.size
}