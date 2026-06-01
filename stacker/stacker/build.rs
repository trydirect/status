use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    emit_git_short_hash();

    let proto_includes = collect_proto_include_paths();

    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile(&["proto/pipe.proto"], &proto_includes)?;
    Ok(())
}

fn collect_proto_include_paths() -> Vec<PathBuf> {
    let mut includes = vec![PathBuf::from("proto")];

    for candidate in [
        PathBuf::from("/usr/include"),
        PathBuf::from("/usr/local/include"),
        PathBuf::from("/opt/homebrew/include"),
    ] {
        if candidate.join("google/protobuf/struct.proto").exists() {
            includes.push(candidate);
        }
    }

    includes
}

fn emit_git_short_hash() {
    println!("cargo:rerun-if-env-changed=STACKER_GIT_SHORT_HASH");

    if let Some(hash) = env::var("STACKER_GIT_SHORT_HASH")
        .ok()
        .and_then(|value| normalize_hash(&value))
    {
        println!("cargo:rustc-env=STACKER_GIT_SHORT_HASH={hash}");
        return;
    }

    if let Some(git_dir) = resolve_git_dir() {
        emit_git_rerun_hints(&git_dir);
    }

    if let Some(hash) =
        run_git(&["rev-parse", "--short=7", "HEAD"]).and_then(|value| normalize_hash(&value))
    {
        println!("cargo:rustc-env=STACKER_GIT_SHORT_HASH={hash}");
    }
}

fn normalize_hash(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    Some(trimmed.to_string())
}

fn resolve_git_dir() -> Option<PathBuf> {
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").map(PathBuf::from)?;
    let git_dir = run_git(&["rev-parse", "--git-dir"])?;
    let git_dir = PathBuf::from(git_dir);

    Some(if git_dir.is_absolute() {
        git_dir
    } else {
        manifest_dir.join(git_dir)
    })
}

fn emit_git_rerun_hints(git_dir: &Path) {
    let head_path = git_dir.join("HEAD");
    println!("cargo:rerun-if-changed={}", head_path.display());

    if let Ok(head_contents) = fs::read_to_string(&head_path) {
        if let Some(reference) = head_contents.trim().strip_prefix("ref: ") {
            println!(
                "cargo:rerun-if-changed={}",
                git_dir.join(reference.trim()).display()
            );
        }
    }
}

fn run_git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }

    String::from_utf8(output.stdout)
        .ok()
        .and_then(|value| normalize_hash(&value))
}
