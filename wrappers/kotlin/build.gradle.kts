plugins {
    id("com.android.library")
    kotlin("android")
    id("com.vanniktech.maven.publish")
    signing
}

android {
    namespace = "dev.wispers.connect"
    compileSdk = 34

    defaultConfig {
        minSdk = 23
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("proguard-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
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

dependencies {
    implementation("net.java.dev.jna:jna:5.17.0@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.7.3")
    testImplementation("org.mockito:mockito-core:5.8.0")
    testImplementation("org.mockito.kotlin:mockito-kotlin:5.2.1")

    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test:runner:1.5.2")
}

// Build the native library for Android ABIs and bundle into the AAR.
// Only runs when explicitly invoked (e.g. before publishing).
val jniLibsDir = file("src/main/jniLibs")

val cargoHome = System.getenv("CARGO_HOME") ?: "${System.getProperty("user.home")}/.cargo"
val cargo = "$cargoHome/bin/cargo"
val clientDir = file("../..")

val ndkHome: String? by lazy {
    System.getenv("ANDROID_NDK_HOME") ?: run {
        val androidHome = System.getenv("ANDROID_HOME")
            ?: "${System.getProperty("user.home")}/Library/Android/sdk"
        val ndkDir = file("$androidHome/ndk")
        if (ndkDir.isDirectory) {
            ndkDir.listFiles()?.filter { it.isDirectory }?.maxByOrNull { it.name }?.absolutePath
        } else null
    }
}

val buildNativeLibs by tasks.registering(Exec::class) {
    group = "build"
    description = "Build libwispers_connect.so for Android ABIs via cargo-ndk"
    workingDir = clientDir
    environment("ANDROID_NDK_HOME", ndkHome ?: "")
    commandLine(
        cargo, "ndk",
        "--target", "arm64-v8a",
        "--target", "armeabi-v7a",
        "--target", "x86_64",
        "--output-dir", jniLibsDir.absolutePath,
        "build", "--release", "-p", "wispers-connect"
    )
    onlyIf { ndkHome != null }
}

val cleanNativeLibs by tasks.registering(Delete::class) {
    delete(jniLibsDir)
}


signing {
    useGpgCmd()
}

mavenPublishing {
    publishToMavenCentral(
        com.vanniktech.maven.publish.SonatypeHost.CENTRAL_PORTAL,
        automaticRelease = true,
    )
    signAllPublications()

    coordinates("dev.wispers", "connect", findProperty("VERSION_NAME") as String? ?: "0.8.1-rc2")

    pom {
        name.set("Wispers Connect")
        description.set("Android wrapper for the Wispers Connect peer-to-peer connectivity library")
        url.set("https://wispers.dev")

        licenses {
            license {
                name.set("MIT License")
                url.set("https://github.com/s-te-ch/wispers-client/blob/main/LICENSE")
            }
        }

        developers {
            developer {
                id.set("mbs")
                name.set("Matthias Scheidegger")
                email.set("mbs@s-te.ch")
            }
        }

        scm {
            url.set("https://github.com/s-te-ch/wispers-client")
            connection.set("scm:git:git://github.com/s-te-ch/wispers-client.git")
            developerConnection.set("scm:git:ssh://github.com/s-te-ch/wispers-client.git")
        }
    }
}
