use std::path::{Path, PathBuf};
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    emit_display_version();
    println!("cargo:rerun-if-changed=proto/pipe.proto");
    // Vendor protoc so builds work without a system-installed protoc
    let _protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc not found");
    std::env::set_var("PROTOC", &_protoc);
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(&["proto/pipe.proto"], &["proto"])?;
    Ok(())
}

fn emit_display_version() {
    let cargo_version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string());
    let display_version = match git_short_hash() {
        Some(hash) => format!("{cargo_version} ({hash})"),
        None => cargo_version,
    };
    println!("cargo:rustc-env=STATUS_DISPLAY_VERSION={display_version}");

    if let Some(git_dir) = git_dir() {
        emit_git_rerun_paths(&git_dir);
    }
}

fn git_short_hash() -> Option<String> {
    git_output(&["rev-parse", "--short=7", "HEAD"])
}

fn git_dir() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").ok()?);
    let git_dir = git_output(&["rev-parse", "--git-dir"])?;
    let path = PathBuf::from(git_dir);
    Some(if path.is_absolute() {
        path
    } else {
        manifest_dir.join(path)
    })
}

fn emit_git_rerun_paths(git_dir: &Path) {
    let head_path = git_dir.join("HEAD");
    println!("cargo:rerun-if-changed={}", head_path.display());

    let packed_refs = git_dir.join("packed-refs");
    println!("cargo:rerun-if-changed={}", packed_refs.display());

    if let Ok(head_contents) = std::fs::read_to_string(&head_path) {
        if let Some(reference) = head_contents.strip_prefix("ref: ") {
            let ref_path = git_dir.join(reference.trim());
            println!("cargo:rerun-if-changed={}", ref_path.display());
        }
    }
}

fn git_output(args: &[&str]) -> Option<String> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let output = Command::new("git")
        .args(args)
        .current_dir(manifest_dir)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let value = String::from_utf8(output.stdout).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
