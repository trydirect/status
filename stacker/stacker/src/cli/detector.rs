use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use crate::cli::config_parser::AppType;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ProjectDetection — result of scanning a project directory
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectDetection {
    pub app_type: AppType,
    pub has_dockerfile: bool,
    pub has_compose: bool,
    pub has_env_file: bool,
    pub detected_files: Vec<String>,
}

impl Default for ProjectDetection {
    fn default() -> Self {
        Self {
            app_type: AppType::Custom,
            has_dockerfile: false,
            has_compose: false,
            has_env_file: false,
            detected_files: Vec::new(),
        }
    }
}

/// Convert a detection result into the detected AppType.
impl From<&ProjectDetection> for AppType {
    fn from(detection: &ProjectDetection) -> Self {
        detection.app_type
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredApp {
    pub name: String,
    pub path: PathBuf,
    pub app_type: AppType,
    pub has_dockerfile: bool,
    pub dockerfile: Option<PathBuf>,
    pub detected_files: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposeStack {
    pub path: PathBuf,
    pub services: Vec<String>,
    pub detected_services: Vec<DetectedComposeService>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedComposeService {
    pub name: String,
    pub image: Option<String>,
    pub ports: Vec<String>,
    pub environment: HashMap<String, String>,
    pub volumes: Vec<String>,
    pub depends_on: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkspaceDetection {
    pub root: ProjectDetection,
    pub apps: Vec<DiscoveredApp>,
    pub compose_stacks: Vec<ComposeStack>,
    pub recommended_compose_file: Option<PathBuf>,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// FileSystem trait — abstraction for testability (DIP)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub trait FileSystem: Send + Sync {
    fn exists(&self, path: &Path) -> bool;
    fn list_dir(&self, path: &Path) -> Result<Vec<String>, std::io::Error>;
    fn read_to_string(&self, path: &Path) -> Result<String, std::io::Error>;
}

/// Production filesystem using std::fs.
pub struct RealFileSystem;

impl FileSystem for RealFileSystem {
    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn list_dir(&self, path: &Path) -> Result<Vec<String>, std::io::Error> {
        let entries = std::fs::read_dir(path)?
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        Ok(entries)
    }

    fn read_to_string(&self, path: &Path) -> Result<String, std::io::Error> {
        std::fs::read_to_string(path)
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Detection markers — which files map to which app type
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

struct DetectionMarker {
    filename: &'static str,
    app_type: AppType,
    priority: u8, // higher = stronger signal
}

/// Ordered list of detection markers. Higher priority takes precedence.
const DETECTION_MARKERS: &[DetectionMarker] = &[
    DetectionMarker {
        filename: "Cargo.toml",
        app_type: AppType::Rust,
        priority: 10,
    },
    DetectionMarker {
        filename: "go.mod",
        app_type: AppType::Go,
        priority: 10,
    },
    DetectionMarker {
        filename: "composer.json",
        app_type: AppType::Php,
        priority: 10,
    },
    DetectionMarker {
        filename: "package.json",
        app_type: AppType::Node,
        priority: 9,
    },
    DetectionMarker {
        filename: "pyproject.toml",
        app_type: AppType::Python,
        priority: 9,
    },
    DetectionMarker {
        filename: "requirements.txt",
        app_type: AppType::Python,
        priority: 8,
    },
    DetectionMarker {
        filename: "index.html",
        app_type: AppType::Static,
        priority: 5,
    },
];

/// Infrastructure files to detect alongside app type.
const DOCKERFILE_NAMES: &[&str] = &["Dockerfile", "dockerfile"];
const COMPOSE_NAMES: &[&str] = &[
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
];
const ENV_FILE_NAMES: &[&str] = &[".env"];
const IGNORED_DIR_NAMES: &[&str] = &[
    ".git",
    ".github",
    ".idea",
    ".stacker",
    ".vscode",
    "coverage",
    "dist",
    "build",
    "docs",
    "node_modules",
    "target",
    "vendor",
];

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// detect_project — scan a directory to identify project type
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Detect the project type and infrastructure files in a directory.
pub fn detect_project(project_path: &Path, fs: &dyn FileSystem) -> ProjectDetection {
    let files = match fs.list_dir(project_path) {
        Ok(f) => f,
        Err(_) => return ProjectDetection::default(),
    };

    let mut detection = ProjectDetection::default();
    let mut best_priority: u8 = 0;

    for filename in &files {
        // Check app type markers
        for marker in DETECTION_MARKERS {
            if filename == marker.filename && marker.priority > best_priority {
                detection.app_type = marker.app_type;
                best_priority = marker.priority;
                if !detection.detected_files.contains(filename) {
                    detection.detected_files.push(filename.clone());
                }
            }
        }

        // Check infrastructure files
        if DOCKERFILE_NAMES.iter().any(|n| n == filename) {
            detection.has_dockerfile = true;
            detection.detected_files.push(filename.clone());
        }

        if COMPOSE_NAMES.iter().any(|n| n == filename) {
            detection.has_compose = true;
            detection.detected_files.push(filename.clone());
        }

        if ENV_FILE_NAMES.iter().any(|n| n == filename) {
            detection.has_env_file = true;
        }
    }

    detection
}

pub fn detect_workspace(project_path: &Path, fs: &dyn FileSystem) -> WorkspaceDetection {
    let root = detect_project(project_path, fs);
    let mut detection = WorkspaceDetection {
        root,
        ..Default::default()
    };
    let mut compose_seen = BTreeSet::new();
    walk_workspace(
        project_path,
        project_path,
        0,
        fs,
        &mut detection,
        &mut compose_seen,
    );

    detection
        .apps
        .sort_by(|left, right| left.path.cmp(&right.path));
    detection
        .compose_stacks
        .sort_by(|left, right| left.path.cmp(&right.path));
    detection.recommended_compose_file = detection
        .compose_stacks
        .iter()
        .max_by_key(|stack| {
            (
                has_include(&project_path.join(&stack.path), fs),
                stack.services.len(),
                std::cmp::Reverse(stack.path.components().count()),
            )
        })
        .map(|stack| stack.path.clone());
    detection
}

fn walk_workspace(
    base_path: &Path,
    current_path: &Path,
    depth: usize,
    fs: &dyn FileSystem,
    detection: &mut WorkspaceDetection,
    compose_seen: &mut BTreeSet<PathBuf>,
) {
    if depth > 5 {
        return;
    }

    let entries = match fs.list_dir(current_path) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    if current_path != base_path {
        let project = detect_project(current_path, fs);
        if let Some(app) = build_discovered_app(base_path, current_path, &project) {
            detection.apps.push(app);
        }
    }

    for entry in entries {
        let child_path = current_path.join(&entry);

        if is_compose_file_name(&entry) {
            let relative = relative_path(base_path, &child_path);
            if compose_seen.insert(relative.clone()) {
                let (services, detected_services) =
                    parse_compose_services(&child_path, base_path, fs);
                detection.compose_stacks.push(ComposeStack {
                    path: relative,
                    services,
                    detected_services,
                });
            }
            continue;
        }

        if should_skip_dir(&entry) {
            continue;
        }

        if fs.list_dir(&child_path).is_ok() {
            walk_workspace(
                base_path,
                &child_path,
                depth + 1,
                fs,
                detection,
                compose_seen,
            );
        }
    }
}

fn build_discovered_app(
    base_path: &Path,
    current_path: &Path,
    project: &ProjectDetection,
) -> Option<DiscoveredApp> {
    if project.app_type == AppType::Custom && !project.has_dockerfile {
        return None;
    }

    let relative = relative_path(base_path, current_path);
    let name = current_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("app")
        .to_string();
    let dockerfile = project.has_dockerfile.then(|| relative.join("Dockerfile"));

    Some(DiscoveredApp {
        name,
        path: relative,
        app_type: if project.has_dockerfile {
            AppType::Custom
        } else {
            project.app_type
        },
        has_dockerfile: project.has_dockerfile,
        dockerfile,
        detected_files: project.detected_files.clone(),
    })
}

fn relative_path(base: &Path, target: &Path) -> PathBuf {
    normalize_path(target)
        .strip_prefix(base)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| target.to_path_buf())
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }

    normalized
}

fn should_skip_dir(entry: &str) -> bool {
    entry.starts_with('.') || IGNORED_DIR_NAMES.iter().any(|name| name == &entry)
}

fn is_compose_file_name(entry: &str) -> bool {
    COMPOSE_NAMES.iter().any(|name| name == &entry)
}

fn has_include(compose_path: &Path, fs: &dyn FileSystem) -> bool {
    fs.read_to_string(compose_path)
        .ok()
        .and_then(|content| serde_yaml::from_str::<serde_yaml::Value>(&content).ok())
        .and_then(|value| value.get("include").cloned())
        .is_some()
}

fn parse_compose_services(
    compose_path: &Path,
    base_path: &Path,
    fs: &dyn FileSystem,
) -> (Vec<String>, Vec<DetectedComposeService>) {
    let mut local = BTreeMap::new();
    let mut visited = BTreeSet::new();
    parse_compose_services_recursive(compose_path, base_path, fs, &mut visited, &mut local);
    let services: Vec<DetectedComposeService> = local.into_values().collect();
    let names = services
        .iter()
        .map(|service| service.name.clone())
        .collect();
    (names, services)
}

fn parse_compose_services_recursive(
    compose_path: &Path,
    base_path: &Path,
    fs: &dyn FileSystem,
    visited: &mut BTreeSet<PathBuf>,
    local: &mut BTreeMap<String, DetectedComposeService>,
) {
    let relative = relative_path(base_path, compose_path);
    if !visited.insert(relative) {
        return;
    }

    let content = match fs.read_to_string(compose_path) {
        Ok(content) => content,
        Err(_) => return,
    };
    let parsed = match serde_yaml::from_str::<serde_yaml::Value>(&content) {
        Ok(parsed) => parsed,
        Err(_) => return,
    };

    if let Some(services) = parsed.get("services").and_then(|value| value.as_mapping()) {
        for (service_name, service_value) in services {
            let Some(service_name) = service_name.as_str() else {
                continue;
            };
            local.insert(
                service_name.to_string(),
                parse_compose_service(service_name, service_value),
            );
        }
    }

    if let Some(include_value) = parsed.get("include") {
        let include_paths: Vec<String> = match include_value {
            serde_yaml::Value::String(value) => vec![value.clone()],
            serde_yaml::Value::Sequence(items) => items
                .iter()
                .filter_map(|item| item.as_str().map(ToOwned::to_owned))
                .collect(),
            _ => Vec::new(),
        };

        for include in include_paths {
            let include_path = compose_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(include);
            let include_path = normalize_path(&include_path);
            parse_compose_services_recursive(&include_path, base_path, fs, visited, local);
        }
    }
}

fn parse_compose_service(name: &str, service_value: &serde_yaml::Value) -> DetectedComposeService {
    let Some(service_map) = service_value.as_mapping() else {
        return DetectedComposeService {
            name: name.to_string(),
            image: None,
            ports: Vec::new(),
            environment: HashMap::new(),
            volumes: Vec::new(),
            depends_on: Vec::new(),
        };
    };

    let image = service_map
        .get(serde_yaml::Value::String("image".to_string()))
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned);
    let ports = service_map
        .get(serde_yaml::Value::String("ports".to_string()))
        .map(parse_string_list)
        .unwrap_or_default();
    let environment = service_map
        .get(serde_yaml::Value::String("environment".to_string()))
        .map(parse_environment)
        .unwrap_or_default();
    let volumes = service_map
        .get(serde_yaml::Value::String("volumes".to_string()))
        .map(parse_string_list)
        .unwrap_or_default();
    let depends_on = service_map
        .get(serde_yaml::Value::String("depends_on".to_string()))
        .map(parse_depends_on)
        .unwrap_or_default();

    DetectedComposeService {
        name: name.to_string(),
        image,
        ports,
        environment,
        volumes,
        depends_on,
    }
}

fn parse_string_list(value: &serde_yaml::Value) -> Vec<String> {
    match value {
        serde_yaml::Value::Sequence(items) => items
            .iter()
            .filter_map(|item| match item {
                serde_yaml::Value::String(text) => Some(text.clone()),
                serde_yaml::Value::Number(number) => Some(number.to_string()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn parse_environment(value: &serde_yaml::Value) -> HashMap<String, String> {
    match value {
        serde_yaml::Value::Mapping(entries) => entries
            .iter()
            .filter_map(|(key, value)| {
                Some((key.as_str()?.to_string(), yaml_scalar_to_string(value)?))
            })
            .collect(),
        serde_yaml::Value::Sequence(items) => items
            .iter()
            .filter_map(|item| {
                let text = item.as_str()?;
                let (key, value) = text.split_once('=')?;
                Some((key.to_string(), value.to_string()))
            })
            .collect(),
        _ => HashMap::new(),
    }
}

fn parse_depends_on(value: &serde_yaml::Value) -> Vec<String> {
    match value {
        serde_yaml::Value::Sequence(items) => items
            .iter()
            .filter_map(|item| item.as_str().map(ToOwned::to_owned))
            .collect(),
        serde_yaml::Value::Mapping(entries) => entries
            .keys()
            .filter_map(|key| key.as_str().map(ToOwned::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

fn yaml_scalar_to_string(value: &serde_yaml::Value) -> Option<String> {
    match value {
        serde_yaml::Value::String(text) => Some(text.clone()),
        serde_yaml::Value::Bool(flag) => Some(flag.to_string()),
        serde_yaml::Value::Number(number) => Some(number.to_string()),
        serde_yaml::Value::Null => Some(String::new()),
        _ => None,
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Tests — Phase 2
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory mock filesystem for deterministic testing without I/O.
    struct MockFileSystem {
        dirs: std::collections::HashMap<PathBuf, Vec<String>>,
        contents: std::collections::HashMap<PathBuf, String>,
    }

    impl MockFileSystem {
        fn with_dir(path: &str, files: &[&str]) -> Self {
            let mut dirs = std::collections::HashMap::new();
            dirs.insert(
                PathBuf::from(path),
                files.iter().map(|value| value.to_string()).collect(),
            );

            Self {
                dirs,
                contents: std::collections::HashMap::new(),
            }
        }

        fn add_dir(mut self, path: &str, files: &[&str]) -> Self {
            self.dirs.insert(
                PathBuf::from(path),
                files.iter().map(|value| value.to_string()).collect(),
            );
            self
        }

        fn add_file(mut self, path: &str, content: &str) -> Self {
            self.contents
                .insert(PathBuf::from(path), content.to_string());
            self
        }
    }

    impl FileSystem for MockFileSystem {
        fn exists(&self, path: &Path) -> bool {
            self.contents.contains_key(path) || self.dirs.contains_key(path)
        }

        fn list_dir(&self, path: &Path) -> Result<Vec<String>, std::io::Error> {
            self.dirs
                .get(path)
                .cloned()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "missing dir"))
        }

        fn read_to_string(&self, path: &Path) -> Result<String, std::io::Error> {
            self.contents.get(path).cloned().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "missing file contents")
            })
        }
    }

    fn detect_with(files: &[&str]) -> ProjectDetection {
        let fs = MockFileSystem::with_dir("/test", files);
        detect_project(Path::new("/test"), &fs)
    }

    #[test]
    fn test_detect_static_html() {
        let det = detect_with(&["index.html", "style.css"]);
        assert_eq!(det.app_type, AppType::Static);
    }

    #[test]
    fn test_detect_node_project() {
        let det = detect_with(&["package.json", "src"]);
        assert_eq!(det.app_type, AppType::Node);
    }

    #[test]
    fn test_detect_python_requirements() {
        let det = detect_with(&["requirements.txt", "app.py"]);
        assert_eq!(det.app_type, AppType::Python);
    }

    #[test]
    fn test_detect_python_pyproject() {
        let det = detect_with(&["pyproject.toml"]);
        assert_eq!(det.app_type, AppType::Python);
    }

    #[test]
    fn test_detect_rust_project() {
        let det = detect_with(&["Cargo.toml", "src"]);
        assert_eq!(det.app_type, AppType::Rust);
    }

    #[test]
    fn test_detect_go_project() {
        let det = detect_with(&["go.mod", "main.go"]);
        assert_eq!(det.app_type, AppType::Go);
    }

    #[test]
    fn test_detect_php_composer() {
        let det = detect_with(&["composer.json", "public"]);
        assert_eq!(det.app_type, AppType::Php);
    }

    #[test]
    fn test_detect_empty_directory() {
        let det = detect_with(&[]);
        assert_eq!(det.app_type, AppType::Custom);
    }

    #[test]
    fn test_detect_priority_node_over_static() {
        let det = detect_with(&["package.json", "index.html"]);
        assert_eq!(
            det.app_type,
            AppType::Node,
            "package.json (priority 9) should beat index.html (priority 5)"
        );
    }

    #[test]
    fn test_detect_existing_dockerfile_flag() {
        let det = detect_with(&["Dockerfile", "package.json"]);
        assert!(det.has_dockerfile);
        assert_eq!(det.app_type, AppType::Node);
    }

    #[test]
    fn test_detect_existing_compose_flag() {
        let det = detect_with(&["docker-compose.yml", "index.html"]);
        assert!(det.has_compose);
    }

    #[test]
    fn test_detect_env_file_flag() {
        let det = detect_with(&[".env", "index.html"]);
        assert!(det.has_env_file);
    }

    #[test]
    fn test_detect_workspace_finds_nested_apps_and_compose_services() {
        let fs =
            MockFileSystem::with_dir("/repo", &["device-api", "upload", "docker", "README.md"])
                .add_dir("/repo/device-api", &["Cargo.toml", "Dockerfile", "docker"])
                .add_dir("/repo/upload", &["Cargo.toml", "Dockerfile", "docker"])
            .add_dir("/repo/docker", &["local"])
            .add_dir("/repo/docker/local", &["compose.yml"])
            .add_file(
                "/repo/docker/local/compose.yml",
                "include:\n  - ../../device-api/docker/local/compose.yml\n  - ../../upload/docker/local/compose.yml\n",
            )
            .add_dir("/repo/device-api/docker", &["local"])
            .add_dir("/repo/device-api/docker/local", &["compose.yml"])
            .add_file(
                "/repo/device-api/docker/local/compose.yml",
                "services:\n  device-api:\n    build: .\n",
            )
            .add_dir("/repo/upload/docker", &["local"])
            .add_dir("/repo/upload/docker/local", &["compose.yml"])
            .add_file(
                "/repo/upload/docker/local/compose.yml",
                "services:\n  upload:\n    build: .\n  redis:\n    image: redis:7\n    ports:\n      - \"6379:6379\"\n    environment:\n      REDIS_PASSWORD: secret\n",
            );

        let detection = detect_workspace(Path::new("/repo"), &fs);

        assert_eq!(detection.apps.len(), 2);
        assert_eq!(
            detection
                .apps
                .iter()
                .map(|app| app.name.as_str())
                .collect::<Vec<_>>(),
            vec!["device-api", "upload"]
        );
        assert_eq!(
            detection.recommended_compose_file,
            Some(PathBuf::from("docker/local/compose.yml"))
        );
        assert_eq!(detection.compose_stacks.len(), 3);
        let root_stack = detection
            .compose_stacks
            .iter()
            .find(|stack| stack.path == PathBuf::from("docker/local/compose.yml"))
            .unwrap();
        assert_eq!(root_stack.services, vec!["device-api", "redis", "upload"]);
        let redis = root_stack
            .detected_services
            .iter()
            .find(|service| service.name == "redis")
            .unwrap();
        assert_eq!(redis.image.as_deref(), Some("redis:7"));
        assert_eq!(redis.ports, vec!["6379:6379"]);
        assert_eq!(
            redis
                .environment
                .get("REDIS_PASSWORD")
                .map(|value| value.as_str()),
            Some("secret")
        );
    }

    #[test]
    fn test_detection_to_app_type_via_from() {
        let detection = ProjectDetection {
            app_type: AppType::Node,
            ..Default::default()
        };
        let app_type = AppType::from(&detection);
        assert_eq!(app_type, AppType::Node);
    }
}
