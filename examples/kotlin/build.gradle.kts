// Declare AGP and Kotlin so the :wispers-connect library module can apply
// them without hardcoding versions.
plugins {
    id("com.android.application") version "8.10.0" apply false
    id("com.android.library") version "8.10.0" apply false
    kotlin("android") version "2.0.21" apply false
}

// Root project - just the Rust native library build tasks.
//
// Prerequisites (one-time setup):
//   rustup target add aarch64-linux-android x86_64-linux-android
//   cargo install cargo-ndk
//   NDK installed via Android Studio's SDK Manager

val cargoHome = System.getenv("CARGO_HOME") ?: "${System.getProperty("user.home")}/.cargo"
val cargo = "$cargoHome/bin/cargo"
val jniLibsDir = file("app/src/main/jniLibs")

// Auto-detect ANDROID_NDK_HOME from env, local.properties, or default SDK path
val ndkHome: String by lazy {
    System.getenv("ANDROID_NDK_HOME") ?: run {
        val androidHome = System.getenv("ANDROID_HOME")
            ?: file("local.properties").takeIf { it.exists() }?.readLines()
                ?.firstOrNull { it.startsWith("sdk.dir=") }?.substringAfter("sdk.dir=")
            ?: "${System.getProperty("user.home")}/Library/Android/sdk"
        val ndkDir = file("$androidHome/ndk")
        if (ndkDir.isDirectory) {
            ndkDir.listFiles()?.filter { it.isDirectory }?.maxByOrNull { it.name }?.absolutePath
                ?: error("NDK directory exists but is empty: $ndkDir")
        } else {
            val bundle = file("$androidHome/ndk-bundle")
            if (bundle.isDirectory) bundle.absolutePath
            else error("Cannot find Android NDK. Install it via Android Studio SDK Manager or set ANDROID_NDK_HOME.")
        }
    }
}

fun ExecSpec.cargoNdkEnv() {
    environment("ANDROID_NDK_HOME", ndkHome)
}

val connectClientDir = file("../..")

val buildRustRelease by tasks.registering(Exec::class) {
    group = "build"
    description = "Build libwispers_connect.so for Android via cargo-ndk"
    workingDir = connectClientDir
    cargoNdkEnv()
    commandLine(
        cargo, "ndk",
        "--target", "arm64-v8a",
        "--target", "x86_64",
        "--output-dir", jniLibsDir.absolutePath,
        "build", "--release", "-p", "wispers-connect"
    )

    inputs.dir(connectClientDir.resolve("wispers-connect/src"))
    inputs.file(connectClientDir.resolve("wispers-connect/Cargo.toml"))
    inputs.file(connectClientDir.resolve("wispers-connect/build.rs"))
    inputs.file(connectClientDir.resolve("Cargo.toml"))
    outputs.dir(jniLibsDir)
}

val buildRustDebug by tasks.registering(Exec::class) {
    group = "build"
    description = "Build libwispers_connect.so for Android (debug) via cargo-ndk"
    workingDir = connectClientDir
    cargoNdkEnv()
    commandLine(
        cargo, "ndk",
        "--target", "arm64-v8a",
        "--target", "x86_64",
        "--output-dir", jniLibsDir.absolutePath,
        "build", "-p", "wispers-connect"
    )

    inputs.dir(connectClientDir.resolve("wispers-connect/src"))
    inputs.file(connectClientDir.resolve("wispers-connect/Cargo.toml"))
    inputs.file(connectClientDir.resolve("wispers-connect/build.rs"))
    inputs.file(connectClientDir.resolve("Cargo.toml"))
    outputs.dir(jniLibsDir)
}
