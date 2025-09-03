plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.example.OffCrypt1"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.example.OffCrypt1"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "2.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        create("release") {
            storeFile = file(project.property("RELEASE_STORE_FILE") as String)
            storePassword = project.property("RELEASE_STORE_PASSWORD") as String
            keyAlias = project.property("RELEASE_KEY_ALIAS") as String
            keyPassword = project.property("RELEASE_KEY_PASSWORD") as String
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            signingConfig = signingConfigs.getByName("release")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    kotlinOptions {
        jvmTarget = "11"
    }

    buildFeatures {
        compose = true
        viewBinding = true
    }

    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.3" // Replace with the correct version
    }

    // Lint configuration to fix crashes
    lint {
        disable += "NullSafeMutableLiveData"
        checkReleaseBuilds = false
        abortOnError = false
        warningsAsErrors = false
    }

    // Lisää tämä mahdollisten manifest-konfliktien ratkaisemiseksi
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    // Core AndroidX
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.activity)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.androidx.lifecycle.livedata.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.ktx)

    // Compose (jos käytät Composea)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation("androidx.compose.material3:material3")

    // Material Design (Traditional Views)
    implementation("com.google.android.material:material:1.12.0")

    implementation("androidx.appcompat:appcompat:1.7.1")

    // RecyclerView (tarvitaan sovelluslistalle)
    implementation("androidx.recyclerview:recyclerview:1.4.0")

    // CardView (käytetään layoutissa)
    implementation("androidx.cardview:cardview:1.0.0")

    // Gson (JSON-käsittelyyn, mutta voidaan käyttää ilmankin)
    implementation("com.google.code.gson:gson:2.13.1")
    implementation(libs.browser)

    // TST Server compatibility dependencies
    // Retrofit for HTTP networking - downgraded for Kotlin 2.0.21 compatibility
    implementation("com.squareup.retrofit2:retrofit:2.9.0")
    implementation("com.squareup.retrofit2:converter-gson:2.9.0")
    implementation("com.squareup.okhttp3:logging-interceptor:4.12.0")
    
    // Coroutines for async operations
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    
    // Security and encryption dependencies
    // KORJATTU: androidx.security deprecated 2024-2025, käytä natiivi AndroidKeyStore
    // implementation("androidx.security:security-crypto:1.1.0-alpha06")
    
    // Biometric authentication for AndroidKeyStore integration
    implementation("androidx.biometric:biometric:1.4.0-alpha04")

    // Testing
    testImplementation(libs.junit)
    testImplementation("org.mockito:mockito-core:5.19.0")
    testImplementation("org.mockito:mockito-inline:5.2.0") 
    testImplementation("org.mockito.kotlin:mockito-kotlin:6.0.0")
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.ui.test.junit4)

    // Debug
    debugImplementation(libs.androidx.ui.tooling)
    debugImplementation(libs.androidx.ui.test.manifest)
}