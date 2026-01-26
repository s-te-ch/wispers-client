use std::env;
use std::path::{Path, PathBuf};

type BuildResult<T> = Result<T, Box<dyn std::error::Error>>;

fn main() -> BuildResult<()> {
    compile_protos()?;
    build_libjuice()?;
    Ok(())
}

fn compile_protos() -> BuildResult<()> {
    tonic_build::configure()
        .build_server(true) // Enable server for integration tests
        .compile_protos(
            &["../proto/hub.proto", "../proto/roster.proto"],
            &["../proto"],
        )?;
    Ok(())
}

fn build_libjuice() -> BuildResult<()> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    // libjuice is in third_party/libjuice (git submodule)
    let libjuice_dir = manifest_dir.join("../third_party/libjuice");
    let header = libjuice_dir.join("include/juice/juice.h");

    if !libjuice_dir.exists() {
        return Err(format!(
            "libjuice not found at {}. Run: git submodule update --init --recursive",
            libjuice_dir.display()
        ).into());
    }

    println!("cargo:rerun-if-changed={}", header.display());

    build_libjuice_native(&libjuice_dir)?;
    generate_libjuice_bindings(&libjuice_dir, &header)?;

    Ok(())
}

fn build_libjuice_native(libjuice_dir: &Path) -> BuildResult<()> {
    let dst = cmake::Config::new(libjuice_dir)
        .define("BUILD_SHARED_LIBS", "OFF")
        .define("NO_TESTS", "ON")
        .define("WARNINGS_AS_ERRORS", "OFF")
        .build();

    let lib_dir = dst.join("lib");
    let link_dir = if lib_dir.exists() { lib_dir } else { dst };
    println!("cargo:rustc-link-search=native={}", link_dir.display());
    println!("cargo:rustc-link-lib=static=juice");

    if cfg!(target_os = "windows") {
        println!("cargo:rustc-link-lib=dylib=ws2_32");
        println!("cargo:rustc-link-lib=dylib=bcrypt");
    } else if cfg!(target_os = "macos") {
        // macOS doesn't need extra libs
    } else {
        // Linux
        println!("cargo:rustc-link-lib=pthread");
    }

    Ok(())
}

fn generate_libjuice_bindings(libjuice_dir: &Path, header: &Path) -> BuildResult<()> {
    let header_str = header.to_str().ok_or("non-utf8 path to libjuice header")?;

    let bindings = bindgen::Builder::default()
        .header(header_str)
        .allowlist_type("juice_.*")
        .allowlist_function("juice_.*")
        .allowlist_var("JUICE_.*")
        .clang_arg(format!("-I{}", libjuice_dir.join("include").display()))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()?;

    let out_path = PathBuf::from(env::var("OUT_DIR")?);
    bindings.write_to_file(out_path.join("juice_bindings.rs"))?;

    Ok(())
}
