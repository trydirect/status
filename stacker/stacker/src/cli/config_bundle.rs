use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tar::{Builder, Header};
use zstd::stream::write::Encoder;

use crate::cli::error::CliError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigBundleFile {
    pub source_path: String,
    pub destination_path: String,
    pub mode: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigBundleManifest {
    pub version: u32,
    pub environment: String,
    pub files: Vec<ConfigBundleFile>,
}

#[derive(Debug, Clone)]
pub struct ConfigBundleArtifacts {
    pub environment: String,
    pub manifest_path: PathBuf,
    pub archive_path: PathBuf,
    pub remote_compose_path: PathBuf,
    pub manifest: ConfigBundleManifest,
    pub config_files: Vec<serde_json::Value>,
}

impl ConfigBundleArtifacts {
    pub fn artifact_metadata(&self) -> serde_json::Value {
        let files: Vec<serde_json::Value> = self
            .manifest
            .files
            .iter()
            .map(|file| {
                json!({
                    "source_path": file.source_path,
                    "destination_path": file.destination_path,
                    "mode": file.mode,
                    "size": file.size,
                    "sha256": file.sha256,
                    "content_hidden": is_secret_like_path(&file.source_path),
                })
            })
            .collect();

        json!({
            "environment": self.environment,
            "manifest_path": self.manifest_path.to_string_lossy(),
            "archive_path": self.archive_path.to_string_lossy(),
            "remote_compose_path": self.remote_compose_path.to_string_lossy(),
            "config_files": files,
        })
    }
}

pub fn build_config_bundle(
    project_dir: &Path,
    environment: &str,
    compose_path: &Path,
    env_file: Option<&Path>,
) -> Result<ConfigBundleArtifacts, CliError> {
    validate_environment_name(environment)?;

    let project_root = project_dir.canonicalize()?;
    let compose_canonical = compose_path.canonicalize()?;
    ensure_inside_project(&project_root, &compose_canonical)?;
    let compose_dir = compose_canonical
        .parent()
        .ok_or_else(|| validation_error("compose file must have a parent directory"))?;

    let output_dir = project_root.join(".stacker/deploy").join(environment);
    std::fs::create_dir_all(&output_dir)?;
    let manifest_path = output_dir.join("config-bundle.manifest.json");
    let archive_path = output_dir.join("config-bundle.tar.zst");
    let remote_compose_path = output_dir.join("docker-compose.remote.yml");

    let compose_content = std::fs::read_to_string(&compose_canonical)?;
    let mut compose_yaml: serde_yaml::Value = serde_yaml::from_str(&compose_content)?;
    let mut collected = BTreeMap::<PathBuf, CollectedFile>::new();

    let selected_env_file = if let Some(env_file) = env_file {
        let resolved = resolve_reference_path(&project_root, &project_root, env_file)?;
        collect_file(&project_root, environment, resolved.clone(), &mut collected)?;
        Some(resolved)
    } else {
        None
    };

    rewrite_compose_references(
        &project_root,
        compose_dir,
        environment,
        &mut compose_yaml,
        &mut collected,
    )?;

    let rewritten_compose = serde_yaml::to_string(&compose_yaml)
        .map_err(|err| validation_error(format!("failed to write remote compose: {err}")))?;
    std::fs::write(&remote_compose_path, &rewritten_compose)?;

    let mut files: Vec<ConfigBundleFile> = collected
        .values()
        .map(|file| ConfigBundleFile {
            source_path: file.source_path.clone(),
            destination_path: file.destination_path.clone(),
            mode: file.mode.clone(),
            size: file.bytes.len() as u64,
            sha256: sha256_hex(&file.bytes),
        })
        .collect();
    files.sort_by(|left, right| left.source_path.cmp(&right.source_path));
    validate_relative_destinations(&files)?;

    let manifest = ConfigBundleManifest {
        version: 1,
        environment: environment.to_string(),
        files,
    };
    let manifest_json = serde_json::to_string_pretty(&manifest)
        .map_err(|err| validation_error(format!("failed to serialize manifest: {err}")))?;
    std::fs::write(&manifest_path, manifest_json)?;
    write_archive(&archive_path, collected.values())?;

    let mut config_files = Vec::new();
    config_files.push(json!({
        "name": "docker-compose.yml",
        "content": rewritten_compose,
        "content_type": "application/x-yaml",
        "destination_path": "docker-compose.yml",
        "file_mode": "0644",
        "owner": "root",
        "group": "root"
    }));

    if let Some(selected_env_file) = selected_env_file.as_ref() {
        let canonical = selected_env_file.canonicalize()?;
        let collected_env_file = collected
            .get(&canonical)
            .expect("selected env file should be present in collected bundle");
        let compose_env_content =
            String::from_utf8(collected_env_file.bytes.clone()).map_err(|_| {
                validation_error(format!(
                    "config file '{}' must be UTF-8 text to upload in the deploy payload",
                    collected_env_file.source_path
                ))
            })?;
        config_files.push(json!({
            "name": ".env",
            "content": compose_env_content,
            "content_type": "text/plain",
            "destination_path": ".env",
            "file_mode": collected_env_file.mode,
            "owner": "root",
            "group": "root"
        }));
    }

    for file in collected.values() {
        let content = String::from_utf8(file.bytes.clone()).map_err(|_| {
            validation_error(format!(
                "config file '{}' must be UTF-8 text to upload in the deploy payload",
                file.source_path
            ))
        })?;
        config_files.push(json!({
            "name": Path::new(&file.source_path)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(file.source_path.as_str()),
            "content": content,
            "content_type": "text/plain",
            "destination_path": file.destination_path,
            "file_mode": file.mode,
            "owner": "root",
            "group": "root"
        }));
    }

    Ok(ConfigBundleArtifacts {
        environment: environment.to_string(),
        manifest_path,
        archive_path,
        remote_compose_path,
        manifest,
        config_files,
    })
}

#[derive(Debug, Clone)]
struct CollectedFile {
    source_path: String,
    destination_path: String,
    mode: String,
    bytes: Vec<u8>,
}

fn rewrite_compose_references(
    project_root: &Path,
    compose_dir: &Path,
    environment: &str,
    compose_yaml: &mut serde_yaml::Value,
    collected: &mut BTreeMap<PathBuf, CollectedFile>,
) -> Result<(), CliError> {
    let Some(services) = mapping_mut(compose_yaml)
        .and_then(|root| root.get_mut(serde_yaml::Value::String("services".to_string())))
        .and_then(mapping_mut)
    else {
        return Ok(());
    };

    for service in services.values_mut() {
        let Some(service_map) = mapping_mut(service) else {
            continue;
        };

        if let Some(env_file_value) =
            service_map.get_mut(serde_yaml::Value::String("env_file".to_string()))
        {
            rewrite_env_file(
                project_root,
                compose_dir,
                environment,
                env_file_value,
                collected,
            )?;
        }

        if let Some(volumes_value) =
            service_map.get_mut(serde_yaml::Value::String("volumes".to_string()))
        {
            rewrite_volumes(
                project_root,
                compose_dir,
                environment,
                volumes_value,
                collected,
            )?;
        }
    }

    Ok(())
}

fn rewrite_env_file(
    project_root: &Path,
    compose_dir: &Path,
    environment: &str,
    value: &mut serde_yaml::Value,
    collected: &mut BTreeMap<PathBuf, CollectedFile>,
) -> Result<(), CliError> {
    match value {
        serde_yaml::Value::String(path) => {
            let remote =
                collect_reference(project_root, compose_dir, environment, path, collected)?;
            *path = remote;
        }
        serde_yaml::Value::Sequence(values) => {
            for item in values {
                if let serde_yaml::Value::String(path) = item {
                    let remote =
                        collect_reference(project_root, compose_dir, environment, path, collected)?;
                    *path = remote;
                }
            }
        }
        _ => {}
    }

    Ok(())
}

fn rewrite_volumes(
    project_root: &Path,
    compose_dir: &Path,
    environment: &str,
    value: &mut serde_yaml::Value,
    collected: &mut BTreeMap<PathBuf, CollectedFile>,
) -> Result<(), CliError> {
    let serde_yaml::Value::Sequence(volumes) = value else {
        return Ok(());
    };

    for volume in volumes {
        let serde_yaml::Value::String(volume_spec) = volume else {
            continue;
        };
        let Some((source, rest)) = parse_bind_mount(volume_spec) else {
            continue;
        };
        let remote = collect_reference(project_root, compose_dir, environment, source, collected)?;
        *volume_spec = format!("{remote}:{rest}");
    }

    Ok(())
}

fn parse_bind_mount(volume_spec: &str) -> Option<(&str, &str)> {
    let (source, rest) = volume_spec.split_once(':')?;
    if source.starts_with('.')
        || source.starts_with('/')
        || source.starts_with('~')
        || source.contains(std::path::MAIN_SEPARATOR)
    {
        Some((source, rest))
    } else {
        None
    }
}

fn collect_reference(
    project_root: &Path,
    base_dir: &Path,
    environment: &str,
    reference: &str,
    collected: &mut BTreeMap<PathBuf, CollectedFile>,
) -> Result<String, CliError> {
    let resolved = resolve_reference_path(project_root, base_dir, Path::new(reference))?;
    let collected_file = collect_file(project_root, environment, resolved, collected)?;
    Ok(collected_file.destination_path.clone())
}

fn collect_file<'a>(
    project_root: &Path,
    _environment: &str,
    path: PathBuf,
    collected: &'a mut BTreeMap<PathBuf, CollectedFile>,
) -> Result<&'a CollectedFile, CliError> {
    let canonical = path.canonicalize().map_err(|err| {
        validation_error(format!(
            "config bundle referenced file does not exist or cannot be read: {} ({})",
            path.display(),
            err
        ))
    })?;
    ensure_inside_project(project_root, &canonical)?;

    if canonical.is_dir() {
        return Err(validation_error(format!(
            "directory mounts are not supported in config bundles: {}",
            display_project_path(project_root, &canonical)
        )));
    }

    if !canonical.is_file() {
        return Err(validation_error(format!(
            "config bundle path is not a file: {}",
            canonical.display()
        )));
    }

    if !collected.contains_key(&canonical) {
        let source_path = display_project_path(project_root, &canonical);
        let destination_path = source_path.replace('\\', "/");
        collected.insert(
            canonical.clone(),
            CollectedFile {
                source_path,
                destination_path,
                mode: "0644".to_string(),
                bytes: std::fs::read(&canonical).map_err(|err| {
                    validation_error(format!(
                        "failed to read config bundle file {}: {}",
                        display_project_path(project_root, &canonical),
                        err
                    ))
                })?,
            },
        );
    }

    Ok(collected
        .get(&canonical)
        .expect("collected file was inserted"))
}

fn validate_relative_destinations(files: &[ConfigBundleFile]) -> Result<(), CliError> {
    for file in files {
        if Path::new(&file.destination_path).is_absolute() {
            return Err(validation_error(format!(
                "config bundle destination must be project-relative: {} -> {}",
                file.source_path, file.destination_path
            )));
        }
    }

    Ok(())
}

fn write_archive<'a>(
    archive_path: &Path,
    files: impl IntoIterator<Item = &'a CollectedFile>,
) -> Result<(), CliError> {
    let archive_file = File::create(archive_path)?;
    let encoder = Encoder::new(archive_file, 0)
        .map_err(|err| validation_error(format!("failed to create zstd archive: {err}")))?;
    let mut tar = Builder::new(encoder);

    for file in files {
        let mut header = Header::new_gnu();
        header.set_size(file.bytes.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        tar.append_data(&mut header, &file.source_path, file.bytes.as_slice())?;
    }

    let encoder = tar.into_inner()?;
    encoder
        .finish()
        .map_err(|err| validation_error(format!("failed to finish zstd archive: {err}")))?;
    Ok(())
}

fn resolve_reference_path(
    project_root: &Path,
    base_dir: &Path,
    reference: &Path,
) -> Result<PathBuf, CliError> {
    if reference.is_absolute() {
        return Ok(reference.to_path_buf());
    }

    if reference.starts_with("~") {
        return Err(validation_error(format!(
            "home-relative config paths are not supported: {}",
            reference.display()
        )));
    }

    let base = if reference
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        let joined = base_dir.join(reference);
        joined.canonicalize().map_err(|err| {
            validation_error(format!(
                "config bundle referenced file does not exist or cannot be read: {} ({})",
                joined.display(),
                err
            ))
        })?
    } else {
        base_dir.join(reference)
    };

    let canonical = base.canonicalize().map_err(|err| {
        validation_error(format!(
            "config bundle referenced file does not exist or cannot be read: {} ({})",
            base.display(),
            err
        ))
    })?;
    ensure_inside_project(project_root, &canonical)?;
    Ok(canonical)
}

fn ensure_inside_project(project_root: &Path, path: &Path) -> Result<(), CliError> {
    if path.starts_with(project_root) {
        return Ok(());
    }

    Err(validation_error(format!(
        "config bundle path must stay inside the project directory: {}",
        path.display()
    )))
}

fn display_project_path(project_root: &Path, path: &Path) -> String {
    path.strip_prefix(project_root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn validate_environment_name(environment: &str) -> Result<(), CliError> {
    if !environment.is_empty()
        && environment
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
    {
        return Ok(());
    }

    Err(validation_error(format!(
        "environment name must contain only letters, digits, '-' or '_': {environment}"
    )))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn is_secret_like_path(path: &str) -> bool {
    let file_name = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path)
        .to_ascii_lowercase();

    file_name == ".env"
        || file_name.ends_with(".env")
        || file_name.contains("secret")
        || file_name.contains("password")
        || file_name.contains("private")
        || file_name.ends_with(".key")
}

fn mapping_mut(value: &mut serde_yaml::Value) -> Option<&mut serde_yaml::Mapping> {
    match value {
        serde_yaml::Value::Mapping(mapping) => Some(mapping),
        _ => None,
    }
}

fn validation_error(message: impl Into<String>) -> CliError {
    CliError::ConfigValidation(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn build_config_bundle_collects_env_file_and_file_mounts_for_environment() {
        let dir = TempDir::new().unwrap();
        let compose_dir = dir.path().join("docker/production");
        std::fs::create_dir_all(&compose_dir).unwrap();
        std::fs::write(compose_dir.join(".env"), "RUST_LOG=warning\n").unwrap();
        std::fs::write(compose_dir.join("nginx.conf"), "events {}\n").unwrap();
        std::fs::write(
            compose_dir.join("compose.yml"),
            r#"
services:
  api:
    image: device-api:latest
    env_file:
      - .env
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
"#,
        )
        .unwrap();

        let artifacts = build_config_bundle(
            dir.path(),
            "production",
            &compose_dir.join("compose.yml"),
            Some(&compose_dir.join(".env")),
        )
        .expect("bundle should be built");

        assert_eq!(artifacts.environment, "production");
        assert!(artifacts
            .manifest_path
            .ends_with(".stacker/deploy/production/config-bundle.manifest.json"));
        assert!(artifacts
            .archive_path
            .ends_with(".stacker/deploy/production/config-bundle.tar.zst"));
        assert!(artifacts
            .remote_compose_path
            .ends_with(".stacker/deploy/production/docker-compose.remote.yml"));
        assert!(artifacts.manifest_path.exists());
        assert!(artifacts.archive_path.exists());
        assert!(artifacts.remote_compose_path.exists());

        let sources: Vec<&str> = artifacts
            .manifest
            .files
            .iter()
            .map(|file| file.source_path.as_str())
            .collect();
        assert!(sources.contains(&"docker/production/.env"));
        assert!(sources.contains(&"docker/production/nginx.conf"));

        let remote_compose = std::fs::read_to_string(&artifacts.remote_compose_path).unwrap();
        assert!(remote_compose.contains("docker/production/.env"));
        assert!(remote_compose.contains("docker/production/nginx.conf:/etc/nginx/nginx.conf:ro"));

        let names: Vec<&str> = artifacts
            .config_files
            .iter()
            .filter_map(|file| file.get("name").and_then(|name| name.as_str()))
            .collect();
        assert!(names.contains(&"docker-compose.yml"));
        assert!(names.contains(&".env"));
        assert!(names.contains(&"nginx.conf"));

        let root_env = artifacts
            .config_files
            .iter()
            .find(|file| {
                file.get("destination_path")
                    .and_then(|value| value.as_str())
                    == Some(".env")
            })
            .expect("selected env file should also be uploaded as compose root .env");
        assert_eq!(root_env["content"], "RUST_LOG=warning\n");
    }

    #[test]
    fn build_config_bundle_keeps_root_compose_env_file_project_relative() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".env"), "APP_ENV=production\n").unwrap();
        std::fs::write(
            dir.path().join("docker-compose.yml"),
            r#"
services:
  web:
    image: nginx:latest
    env_file:
      - .env
"#,
        )
        .unwrap();

        let artifacts = build_config_bundle(
            dir.path(),
            "production",
            &dir.path().join("docker-compose.yml"),
            None,
        )
        .expect("bundle should be built");

        let remote_compose = std::fs::read_to_string(&artifacts.remote_compose_path).unwrap();
        assert!(remote_compose.contains(".env"));
        assert!(!remote_compose.contains("/opt/stacker/deployments"));

        assert!(artifacts.config_files.iter().any(|file| {
            file.get("destination_path")
                .and_then(|value| value.as_str())
                == Some(".env")
        }));
    }

    #[test]
    fn validate_relative_destinations_rejects_absolute_paths() {
        let err = validate_relative_destinations(&[ConfigBundleFile {
            source_path: ".env".to_string(),
            destination_path: "/opt/stacker/deployments/production/files/.env".to_string(),
            mode: "0644".to_string(),
            size: 12,
            sha256: "abc".to_string(),
        }])
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("config bundle destination must be project-relative"));
    }

    #[test]
    fn build_config_bundle_rejects_directory_mounts() {
        let dir = TempDir::new().unwrap();
        let compose_dir = dir.path().join("docker/production");
        std::fs::create_dir_all(compose_dir.join("config")).unwrap();
        std::fs::write(
            compose_dir.join("compose.yml"),
            r#"
services:
  api:
    image: device-api:latest
    volumes:
      - ./config:/app/config:ro
"#,
        )
        .unwrap();

        let err = build_config_bundle(
            dir.path(),
            "production",
            &compose_dir.join("compose.yml"),
            None,
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("directory mounts are not supported"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn build_config_bundle_reports_missing_env_file_path() {
        let dir = TempDir::new().unwrap();
        let compose_dir = dir.path().join("docker/production");
        std::fs::create_dir_all(&compose_dir).unwrap();
        std::fs::write(
            compose_dir.join("compose.yml"),
            r#"
services:
  upload:
    image: syncopia/upload:latest
    env_file:
      - upload.env
"#,
        )
        .unwrap();

        let err = build_config_bundle(
            dir.path(),
            "production",
            &compose_dir.join("compose.yml"),
            None,
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("docker/production/upload.env")
                || err.to_string().contains("docker/production\\upload.env"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn artifact_metadata_marks_secret_like_files_hidden() {
        let manifest = ConfigBundleManifest {
            version: 1,
            environment: "production".to_string(),
            files: vec![
                ConfigBundleFile {
                    source_path: "docker/production/.env".to_string(),
                    destination_path: "docker/production/.env".to_string(),
                    mode: "0644".to_string(),
                    size: 12,
                    sha256: "abc".to_string(),
                },
                ConfigBundleFile {
                    source_path: "docker/production/nginx.conf".to_string(),
                    destination_path: "docker/production/nginx.conf".to_string(),
                    mode: "0644".to_string(),
                    size: 10,
                    sha256: "def".to_string(),
                },
            ],
        };
        let artifacts = ConfigBundleArtifacts {
            environment: "production".to_string(),
            manifest_path: PathBuf::from(".stacker/deploy/production/config-bundle.manifest.json"),
            archive_path: PathBuf::from(".stacker/deploy/production/config-bundle.tar.zst"),
            remote_compose_path: PathBuf::from(
                ".stacker/deploy/production/docker-compose.remote.yml",
            ),
            manifest,
            config_files: vec![],
        };

        let metadata = artifacts.artifact_metadata();
        assert_eq!(metadata["environment"], "production");
        assert_eq!(metadata["config_files"][0]["content_hidden"], true);
        assert_eq!(metadata["config_files"][1]["content_hidden"], false);
        assert!(metadata["config_files"][0].get("content").is_none());
    }
}
