plugins {
    id("com.android.application") version "8.10.0"
    kotlin("android") version "2.0.21"
}

android {
    namespace = "dev.wispers.connect.example"
    compileSdk = 34

    defaultConfig {
        applicationId = "dev.wispers.connect.example"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"

        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

// Wire Rust build into the Android build
tasks.whenTaskAdded {
    if (name == "mergeReleaseNativeLibs" || name == "mergeReleaseJniLibFolders") {
        dependsOn(":buildRustRelease")
    }
    if (name == "mergeDebugNativeLibs" || name == "mergeDebugJniLibFolders") {
        dependsOn(":buildRustDebug")
    }
}

dependencies {
    implementation(project(":wispers-connect"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
}
