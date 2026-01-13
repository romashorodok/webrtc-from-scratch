use std::path::PathBuf;

extern crate bindgen;

fn main() {
    // 1. Build Opus C library using CMake
    build_opus_library();

    // 2. Generate Rust bindings using bindgen
    generate_bindings();
}

fn build_opus_library() {
    const OPUS_DIR: &str = "opus";

    let mut cmake = cmake::Config::new(OPUS_DIR);

    // Configure CMake (minimal build, no examples/docs)
    cmake
        .define("OPUS_INSTALL_PKG_CONFIG_MODULE", "OFF")
        .define("OPUS_INSTALL_CMAKE_CONFIG_MODULE", "OFF")
        .define("CMAKE_INSTALL_BINDIR", "bin")
        .define("CMAKE_INSTALL_MANDIR", "man")
        .define("CMAKE_INSTALL_INCLUDEDIR", "include")
        .define("CMAKE_INSTALL_OLDINCLUDEDIR", "include")
        .define("CMAKE_INSTALL_LIBDIR", "lib")
        .define("CMAKE_TRY_COMPILE_TARGET_TYPE", "STATIC_LIBRARY")
        // Disable unnecessary features for WebRTC use case
        .define("OPUS_BUILD_PROGRAMS", "OFF")
        .define("OPUS_BUILD_TESTING", "OFF");

    // Use Ninja if available (faster builds)
    if std::process::Command::new("ninja")
        .arg("--version")
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        cmake.generator("Ninja");
    }

    // Link statically
    println!("cargo:rustc-link-lib=static=opus");

    let mut out_dir = cmake.build();
    out_dir.push("lib");

    println!("cargo:rustc-link-search=native={}", out_dir.display());

    #[cfg(target_os = "linux")]
    {
        out_dir.pop();
        out_dir.push("lib64");
        println!("cargo:rustc-link-search=native={}", out_dir.display());
    }

    // Rerun if Opus source changes
    println!("cargo:rerun-if-changed=opus/");
}

fn generate_bindings() {
    #[derive(Debug)]
    struct ParseCallbacks;

    impl bindgen::callbacks::ParseCallbacks for ParseCallbacks {
        fn int_macro(&self, name: &str, _value: i64) -> Option<bindgen::callbacks::IntKind> {
            // Treat all OPUS_* constants as i32
            if name.starts_with("OPUS") {
                Some(bindgen::callbacks::IntKind::Int)
            } else {
                None
            }
        }
    }

    const PREPEND_LIB: &str = "";

    let out_path = PathBuf::from("src").join("libopus.rs");

    let bindings = bindgen::Builder::default()
        .header("src/wrapper.h")
        .raw_line(PREPEND_LIB)
        .parse_callbacks(Box::new(ParseCallbacks))
        .generate_comments(false)
        .layout_tests(false)
        .ctypes_prefix("libc")
        // Allowlist only Opus API (not internal structs)
        .allowlist_type("Opus.*")
        .allowlist_function("opus_.*")
        .allowlist_var("OPUS_.*")
        .generate()
        .expect("Unable to generate Opus bindings");

    bindings
        .write_to_file(out_path)
        .expect("Couldn't write bindings to src/libopus.rs");
}
