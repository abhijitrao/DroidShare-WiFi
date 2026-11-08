plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

val githubDevKeystorePath = System.getenv("ANDROID_DEV_KEYSTORE_PATH")
val githubDevStorePassword = System.getenv("ANDROID_DEV_STORE_PASSWORD")
val githubDevKeyAlias = System.getenv("ANDROID_DEV_KEY_ALIAS")
val githubDevKeyPassword = System.getenv("ANDROID_DEV_KEY_PASSWORD")

val githubDevSigningValues = listOf(
    githubDevKeystorePath,
    githubDevStorePassword,
    githubDevKeyAlias,
    githubDevKeyPassword
)
val useGithubDevSigning = githubDevSigningValues.all { !it.isNullOrBlank() }

if (githubDevSigningValues.any { !it.isNullOrBlank() } && !useGithubDevSigning) {
    throw GradleException("GitHub development signing is partially configured. Provide all ANDROID_DEV_* signing environment variables.")
}

android {
    namespace = "com.droidshare.wifi"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.droidshare.wifi"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }
    signingConfigs {
        if (useGithubDevSigning) {
            create("githubDevelopment") {
                storeFile = file(githubDevKeystorePath!!)
                storePassword = githubDevStorePassword!!
                keyAlias = githubDevKeyAlias!!
                keyPassword = githubDevKeyPassword!!
            }
        }
    }
    buildTypes {
        getByName("debug") {
            if (useGithubDevSigning) {
                signingConfig = signingConfigs.getByName("githubDevelopment")
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { compose = true }
}
dependencies {
    implementation(platform("androidx.compose:compose-bom:2025.02.00"))
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
