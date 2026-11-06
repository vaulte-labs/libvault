use std::collections::hash_map::DefaultHasher;
use std::env;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;

/// What a person sees the broker called, such as in a Touch ID prompt.
const PRODUCT: &str = "Vaulte";

// Enclave ML-KEM and ML-DSA arrived in macOS 26 and iOS 26, and CryptoKit is Swift-only.
const MACOS_TARGET: &str = "macos26.0";
const IOS_TARGET: &str = "ios26.0";

fn hash_sources(folder: &Path, hasher: &mut DefaultHasher) {
    let mut entries: Vec<PathBuf> = fs::read_dir(folder).expect("src is readable").flatten().map(|entry| entry.path()).collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            hash_sources(&path, hasher);
        } else {
            fs::read(&path).expect("sources are readable").hash(hasher);
        }
    }
}

fn main() {
    println!("cargo:rerun-if-changed=enclave");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src");

    // What a client and a broker compare. Two copies of one build are one build wherever they sit,
    // and two builds of different code differ even with the same version number.
    let mut hasher = DefaultHasher::new();
    hash_sources(Path::new("src"), &mut hasher);
    hash_sources(Path::new("enclave"), &mut hasher);
    println!("cargo:rustc-env=LV_BUILD={}-{:016x}", env::var("CARGO_PKG_VERSION").expect("cargo sets the version"), hasher.finish());

    let os = env::var("CARGO_CFG_TARGET_OS").expect("cargo sets the target OS");
    if os != "macos" && os != "ios" {
        return;
    }
    let simulator = env::var("CARGO_CFG_TARGET_ABI").as_deref() == Ok("sim");
    let (triple_os, sdk_name) = match (os.as_str(), simulator) {
        ("macos", _) => (MACOS_TARGET.to_owned(), "macosx"),
        (_, false) => (IOS_TARGET.to_owned(), "iphoneos"),
        (_, true) => (format!("{IOS_TARGET}-simulator"), "iphonesimulator"),
    };

    let out = PathBuf::from(env::var("OUT_DIR").expect("cargo sets OUT_DIR"));

    if os == "macos" {
        // Touch ID names the program asking, which for a bare `lvd` is its file name. An Info.plist
        // inside the binary gives it the product's name instead.
        let plist = out.join("lvd-Info.plist");
        let version = env::var("CARGO_PKG_VERSION").expect("cargo sets the version");
        fs::write(
            &plist,
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\
                 <key>CFBundleIdentifier</key><string>dev.vaulty.lvd</string>\
                 <key>CFBundleName</key><string>{PRODUCT}</string>\
                 <key>CFBundleDisplayName</key><string>{PRODUCT}</string>\
                 <key>CFBundleShortVersionString</key><string>{version}</string>\
                 </dict></plist>\n"
            ),
        )
        .expect("OUT_DIR is writable");
        println!("cargo:rustc-link-arg-bin=lvd=-Wl,-sectcreate,__TEXT,__info_plist,{}", plist.display());
    }
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64",
        Ok("x86_64") => "x86_64",
        other => panic!("unsupported Apple architecture: {other:?}"),
    };
    let sdk = Command::new("xcrun").args(["--sdk", sdk_name, "--show-sdk-path"]).output().expect("xcrun is required to build for Apple systems");
    let sdk_path = String::from_utf8(sdk.stdout).expect("SDK path is UTF-8");
    let status = Command::new("swiftc")
        .args(["-emit-library", "-static", "-parse-as-library", "-O"])
        .args(["-module-name", "LvEnclave"])
        .args(["-target", &format!("{arch}-apple-{triple_os}")])
        .args(["-sdk", sdk_path.trim()])
        .arg("-o")
        .arg(out.join("libLvEnclave.a"))
        .args(["enclave/Enclave.swift", "enclave/Caller.swift"])
        .status()
        .expect("swiftc is required to build for Apple systems");
    assert!(status.success(), "swiftc failed");

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=LvEnclave");
    println!("cargo:rustc-link-search=native={}/usr/lib/swift", sdk_path.trim());
    println!("cargo:rustc-link-search=native=/usr/lib/swift");
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
    for framework in ["CoreGraphics", "CryptoKit", "Foundation", "LocalAuthentication", "Security"] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
}
