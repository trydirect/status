use crate::cli::error::CliError;
use crate::console::commands::CallableTrait;
use crate::helpers::fs::write_atomic;
use flate2::read::GzDecoder;
use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;

const DEFAULT_CHANNEL: &str = "stable";
const VALID_CHANNELS: &[&str] = &["stable", "beta"];
const GITHUB_API_RELEASES: &str = "https://api.github.com/repos/trydirect/stacker/releases";
const RELEASES_URL_ENV: &str = "STACKER_UPDATE_RELEASES_URL";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Parse and validate a release channel string.
pub fn parse_channel(channel: Option<&str>) -> Result<String, CliError> {
    let ch = channel.unwrap_or(DEFAULT_CHANNEL).to_lowercase();
    if VALID_CHANNELS.contains(&ch.as_str()) {
        Ok(ch)
    } else {
        Err(CliError::ConfigValidation(format!(
            "Unknown channel '{}'. Valid channels: {}",
            ch,
            VALID_CHANNELS.join(", ")
        )))
    }
}

/// Detect the current platform's asset suffix used in GitHub release filenames.
/// Format: `stacker-v{VERSION}-{arch}-{os}.tar.gz`
fn detect_asset_suffix() -> String {
    let os = if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    };
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };
    format!("{}-{}", arch, os)
}

#[derive(Debug, serde::Deserialize)]
struct GithubRelease {
    tag_name: String,
    prerelease: bool,
    assets: Vec<GithubAsset>,
}

#[derive(Debug, serde::Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

/// Fetch the latest release from GitHub that matches the channel.
/// - "stable" → non-prerelease releases
/// - "beta"   → prerelease releases
///
/// Returns `Ok(None)` when the GitHub API is unreachable or rate-limited so
/// that the update command exits 0 instead of failing the CLI.
fn releases_api_url() -> String {
    env::var(RELEASES_URL_ENV).unwrap_or_else(|_| GITHUB_API_RELEASES.to_string())
}
fn fetch_latest_release(
    channel: &str,
) -> Result<Option<GithubRelease>, Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::builder()
        .user_agent(format!("stacker-cli/{}", CURRENT_VERSION))
        .build()?;

    let response = client.get(releases_api_url()).send()?;

    if !response.status().is_success() {
        eprintln!(
            "Warning: could not check for updates (GitHub API returned {}). \
             Try again later or set a GITHUB_TOKEN environment variable.",
            response.status()
        );
        return Ok(None);
    }

    let releases: Vec<GithubRelease> = response.json()?;

    let want_prerelease = channel == "beta";
    let release = releases
        .into_iter()
        .find(|r| r.prerelease == want_prerelease || (!want_prerelease && !r.prerelease));

    Ok(release)
}

/// Compare two semver strings (major.minor.patch) — returns true if `latest` > `current`.
fn is_newer(current: &str, latest: &str) -> bool {
    let parse = |v: &str| -> Option<(u64, u64, u64)> {
        let v = v.trim_start_matches('v');
        let parts: Vec<&str> = v.splitn(3, '.').collect();
        if parts.len() < 3 {
            return None;
        }
        Some((
            parts[0].parse().ok()?,
            parts[1].parse().ok()?,
            parts[2].split('-').next()?.parse().ok()?,
        ))
    };
    match (parse(current), parse(latest)) {
        (Some(c), Some(l)) => l > c,
        _ => false,
    }
}

/// Download `url` into a temporary file and return its path.
fn download_to_tempfile(url: &str) -> Result<tempfile::NamedTempFile, Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::builder()
        .user_agent(format!("stacker-cli/{}", CURRENT_VERSION))
        .build()?;
    let mut resp = client.get(url).send()?.error_for_status()?;
    let mut tmp = tempfile::NamedTempFile::new()?;
    io::copy(&mut resp, &mut tmp)?;
    Ok(tmp)
}

/// Extract the `stacker` binary from a `.tar.gz` archive and return its bytes.
fn extract_binary_from_targz(
    tmp: &tempfile::NamedTempFile,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let file = fs::File::open(tmp.path())?;
    let gz = GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz);
    for entry in archive.entries()? {
        let mut entry: tar::Entry<GzDecoder<fs::File>> = entry?;
        let path = entry.path()?.to_path_buf();
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if name == "stacker" {
            let mut buf = Vec::new();
            io::copy(&mut entry, &mut buf)?;
            return Ok(buf);
        }
    }
    Err("stacker binary not found in archive".into())
}

/// Replace the running executable with `new_bytes`.
fn replace_current_exe(new_bytes: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    let current_exe: PathBuf = env::current_exe()?;
    write_atomic(&current_exe, &new_bytes, 0o755)?;
    Ok(())
}

/// `stacker update [--channel stable|beta]`
///
/// Checks for updates and self-updates the stacker binary.
pub struct UpdateCommand {
    pub channel: Option<String>,
}

impl UpdateCommand {
    pub fn new(channel: Option<String>) -> Self {
        Self { channel }
    }
}

impl CallableTrait for UpdateCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let channel = parse_channel(self.channel.as_deref())?;
        eprintln!("Checking for updates on '{}' channel...", channel);

        let release = match fetch_latest_release(&channel)? {
            Some(r) => r,
            None => {
                eprintln!("No releases found on '{}' channel.", channel);
                return Ok(());
            }
        };

        let latest_version = release.tag_name.trim_start_matches('v');

        if !is_newer(CURRENT_VERSION, latest_version) {
            eprintln!("You are running the latest version (v{}).", CURRENT_VERSION);
            return Ok(());
        }

        eprintln!(
            "New version available: v{} (you have v{}). Updating...",
            latest_version, CURRENT_VERSION
        );

        let suffix = detect_asset_suffix();
        let asset_name = format!("stacker-v{}-{}.tar.gz", latest_version, suffix);
        let asset = release
            .assets
            .iter()
            .find(|a| a.name == asset_name)
            .ok_or_else(|| format!("No release asset found for your platform: {}", asset_name))?;

        eprintln!("Downloading {}...", asset.name);
        let tmp = download_to_tempfile(&asset.browser_download_url)?;

        eprintln!("Extracting...");
        let new_bytes = extract_binary_from_targz(&tmp)?;

        eprintln!("Installing...");
        replace_current_exe(new_bytes)?;

        eprintln!(
            "✅ Updated to v{}. Run 'stacker --version' to confirm.",
            latest_version
        );
        Ok(())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_channel_defaults_to_stable() {
        assert_eq!(parse_channel(None).unwrap(), "stable");
    }

    #[test]
    fn test_parse_channel_accepts_beta() {
        assert_eq!(parse_channel(Some("beta")).unwrap(), "beta");
    }

    #[test]
    fn test_parse_channel_case_insensitive() {
        assert_eq!(parse_channel(Some("STABLE")).unwrap(), "stable");
    }

    #[test]
    fn test_parse_channel_rejects_unknown() {
        assert!(parse_channel(Some("nightly")).is_err());
    }

    #[test]
    fn test_is_newer_detects_update() {
        assert!(is_newer("0.2.4", "0.2.5"));
        assert!(is_newer("0.2.4", "0.3.0"));
        assert!(is_newer("0.2.4", "1.0.0"));
    }

    #[test]
    fn test_is_newer_no_update_needed() {
        assert!(!is_newer("0.2.5", "0.2.5"));
        assert!(!is_newer("0.2.5", "0.2.4"));
    }

    #[test]
    fn test_is_newer_handles_v_prefix() {
        assert!(is_newer("0.2.4", "v0.2.5"));
        assert!(!is_newer("v0.2.5", "v0.2.5"));
    }

    #[test]
    fn test_releases_api_url_uses_env_override() {
        std::env::set_var(RELEASES_URL_ENV, "http://localhost/releases");
        assert_eq!(releases_api_url(), "http://localhost/releases");
        std::env::remove_var(RELEASES_URL_ENV);
    }
}
