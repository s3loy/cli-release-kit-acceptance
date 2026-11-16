use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};
fn collect(path: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(path).expect("read engine source") {
        let path = entry.expect("source entry").path();
        if path.is_dir() {
            collect(&path, files);
        } else if path.is_file() {
            files.push(path);
        }
    }
}
fn main() {
    println!(
        "cargo:rustc-env=KIT_ENGINE_TARGET={}",
        std::env::var("TARGET").expect("Cargo build target")
    );
    let mut files = vec![
        PathBuf::from("Cargo.toml"),
        PathBuf::from("Cargo.lock"),
        PathBuf::from("build.rs"),
    ];
    collect(Path::new("src"), &mut files);
    files.sort();
    println!("cargo:rerun-if-changed=src");
    let mut digest = Sha256::new();
    digest.update(b"cli-release-kit-engine-source/v1\0");
    for path in files {
        println!("cargo:rerun-if-changed={}", path.display());
        let name = path.to_string_lossy().replace('\\', "/");
        let bytes = fs::read(&path).expect("source bytes");
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name.as_bytes());
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    println!(
        "cargo:rustc-env=KIT_ENGINE_SOURCE_ID={:x}",
        digest.finalize()
    );
}
