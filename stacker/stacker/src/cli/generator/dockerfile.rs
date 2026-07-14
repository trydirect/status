use std::fmt;
use std::path::Path;

use crate::cli::config_parser::AppType;
use crate::cli::error::CliError;
use serde::Deserialize;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DockerfileBuilder — generates Dockerfiles from AppType
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// A fluent builder for producing multi-stage Dockerfile contents.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DockerfileBuilder {
    base_image: String,
    work_dir: String,
    copy_sources: Vec<(String, String)>,
    run_commands: Vec<String>,
    expose_ports: Vec<u16>,
    cmd: Vec<String>,
    entrypoint: Option<Vec<String>>,
    env_vars: Vec<(String, String)>,
    labels: Vec<(String, String)>,
    stages: Vec<Stage>,
}

/// A named build stage for multi-stage builds.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct Stage {
    name: String,
    base_image: String,
    commands: Vec<String>,
}

impl Default for DockerfileBuilder {
    fn default() -> Self {
        Self {
            base_image: "alpine:3.18".to_string(),
            work_dir: "/app".to_string(),
            copy_sources: Vec::new(),
            run_commands: Vec::new(),
            expose_ports: Vec::new(),
            cmd: Vec::new(),
            entrypoint: None,
            env_vars: Vec::new(),
            labels: Vec::new(),
            stages: Vec::new(),
        }
    }
}

/// Create a `DockerfileBuilder` pre-configured with sensible defaults for a given
/// `AppType`. This is the primary entry point for generating Dockerfiles.
impl From<AppType> for DockerfileBuilder {
    fn from(app_type: AppType) -> Self {
        match app_type {
            AppType::Static => Self::default()
                .base_image("nginx:alpine")
                .copy(".", "/usr/share/nginx/html")
                .expose(80),

            AppType::Node => Self::default()
                .base_image("node:20-alpine")
                .work_dir("/app")
                .copy("package*.json", "./")
                .run("npm ci --production")
                .copy(".", ".")
                .expose(3000)
                .cmd_str("node server.js"),

            AppType::Python => Self::default()
                .base_image("python:3.12-slim")
                .work_dir("/app")
                .copy("requirements.txt", "./")
                .run("pip install --no-cache-dir -r requirements.txt")
                .copy(".", ".")
                .expose(8000)
                .cmd_str("python -m uvicorn main:app --host 0.0.0.0 --port 8000"),

            AppType::Rust => Self::default()
                .base_image("rust:1.77-alpine")
                .work_dir("/app")
                .run("apk add --no-cache musl-dev")
                .copy(".", ".")
                .run("cargo build --release")
                .expose(8080)
                .cmd_str("./target/release/app"),

            AppType::Go => Self::default()
                .base_image("golang:1.22-alpine")
                .work_dir("/app")
                .copy("go.mod", "./")
                .copy("go.sum", "./")
                .run("go mod download")
                .copy(".", ".")
                .run("go build -o /app/server .")
                .expose(8080)
                .cmd_str("/app/server"),

            AppType::Php => Self::default()
                .base_image("php:8.3-fpm-alpine")
                .work_dir("/var/www/html")
                .run("docker-php-ext-install pdo pdo_mysql")
                .copy(".", ".")
                .expose(9000),

            AppType::Custom => Self::default(),
        }
    }
}

impl DockerfileBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn for_project(project_dir: &Path, app_type: AppType) -> Self {
        match app_type {
            AppType::Node => {
                Self::for_node_project(project_dir).unwrap_or_else(|| Self::from(app_type))
            }
            _ => Self::from(app_type),
        }
    }

    fn for_node_project(project_dir: &Path) -> Option<Self> {
        let package_json = std::fs::read_to_string(project_dir.join("package.json")).ok()?;
        let manifest: NodePackageManifest = serde_json::from_str(&package_json).ok()?;
        let has_next_dependency = manifest.dependencies.contains_key("next")
            || manifest.dev_dependencies.contains_key("next");
        let has_build_script = manifest.scripts.contains_key("build");
        let has_start_script = manifest.scripts.contains_key("start");

        if has_next_dependency && has_build_script && has_start_script {
            return Some(
                Self::default()
                    .base_image("node:20-alpine")
                    .work_dir("/app")
                    .env("NEXT_TELEMETRY_DISABLED", "1")
                    .copy("package*.json", "./")
                    .run("npm ci")
                    .copy(".", ".")
                    .run("npm run build")
                    .expose(3000)
                    .cmd(vec!["npm".into(), "run".into(), "start".into()]),
            );
        }

        None
    }

    pub fn base_image<S: Into<String>>(mut self, image: S) -> Self {
        self.base_image = image.into();
        self
    }

    pub fn work_dir<S: Into<String>>(mut self, dir: S) -> Self {
        self.work_dir = dir.into();
        self
    }

    pub fn copy<S: Into<String>>(mut self, src: S, dest: S) -> Self {
        self.copy_sources.push((src.into(), dest.into()));
        self
    }

    pub fn run<S: Into<String>>(mut self, cmd: S) -> Self {
        self.run_commands.push(cmd.into());
        self
    }

    pub fn expose(mut self, port: u16) -> Self {
        self.expose_ports.push(port);
        self
    }

    pub fn cmd(mut self, parts: Vec<String>) -> Self {
        self.cmd = parts;
        self
    }

    /// Convenience: sets CMD from a simple string, splitting by whitespace.
    pub fn cmd_str<S: Into<String>>(mut self, cmd: S) -> Self {
        self.cmd = cmd
            .into()
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        self
    }

    pub fn entrypoint(mut self, parts: Vec<String>) -> Self {
        self.entrypoint = Some(parts);
        self
    }

    pub fn env<K: Into<String>, V: Into<String>>(mut self, key: K, value: V) -> Self {
        self.env_vars.push((key.into(), value.into()));
        self
    }

    pub fn label<K: Into<String>, V: Into<String>>(mut self, key: K, value: V) -> Self {
        self.labels.push((key.into(), value.into()));
        self
    }

    /// Render the Dockerfile contents as a `String`.
    pub fn build(&self) -> String {
        let mut lines: Vec<String> = Vec::new();

        // FROM
        lines.push(format!("FROM {}", self.base_image));
        lines.push(String::new());

        // LABELS
        for (k, v) in &self.labels {
            lines.push(format!("LABEL {}=\"{}\"", k, v));
        }
        if !self.labels.is_empty() {
            lines.push(String::new());
        }

        // WORKDIR
        if self.work_dir != "/" {
            lines.push(format!("WORKDIR {}", self.work_dir));
            lines.push(String::new());
        }

        // ENV
        for (k, v) in &self.env_vars {
            lines.push(format!("ENV {}={}", k, v));
        }
        if !self.env_vars.is_empty() {
            lines.push(String::new());
        }

        // Interleaved COPY and RUN in order
        //
        // We track the order: first emit copy_sources and run_commands by
        // recording the insertion order. For simplicity in the builder we
        // output all COPYs first, then all RUNs, followed by EXPOSE/CMD.
        for (src, dest) in &self.copy_sources {
            lines.push(format!("COPY {} {}", src, dest));
        }
        if !self.copy_sources.is_empty() {
            lines.push(String::new());
        }

        for cmd in &self.run_commands {
            lines.push(format!("RUN {}", cmd));
        }
        if !self.run_commands.is_empty() {
            lines.push(String::new());
        }

        // EXPOSE
        for port in &self.expose_ports {
            lines.push(format!("EXPOSE {}", port));
        }
        if !self.expose_ports.is_empty() {
            lines.push(String::new());
        }

        // ENTRYPOINT
        if let Some(ep) = &self.entrypoint {
            let quoted: Vec<String> = ep.iter().map(|p| format!("\"{}\"", p)).collect();
            lines.push(format!("ENTRYPOINT [{}]", quoted.join(", ")));
        }

        // CMD
        if !self.cmd.is_empty() {
            let quoted: Vec<String> = self.cmd.iter().map(|p| format!("\"{}\"", p)).collect();
            lines.push(format!("CMD [{}]", quoted.join(", ")));
        }

        // Trim trailing blank lines
        while lines.last().map_or(false, |l| l.is_empty()) {
            lines.pop();
        }

        lines.push(String::new()); // final newline
        lines.join("\n")
    }

    /// Write Dockerfile to a path. Returns error if file already exists.
    pub fn write_to(&self, path: &std::path::Path, overwrite: bool) -> Result<(), CliError> {
        if !overwrite && path.exists() {
            return Err(CliError::DockerfileExists {
                path: path.to_path_buf(),
            });
        }
        let content = self.build();
        std::fs::write(path, content)?;
        Ok(())
    }
}

#[derive(Debug, Default, Deserialize)]
struct NodePackageManifest {
    #[serde(default)]
    scripts: std::collections::BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    dependencies: std::collections::BTreeMap<String, serde_json::Value>,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: std::collections::BTreeMap<String, serde_json::Value>,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Display — pretty-print Dockerfile to stdout
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

impl fmt::Display for DockerfileBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.build())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_dockerfile_from_app_type() {
        let builder = DockerfileBuilder::from(AppType::Static);
        let content = builder.build();
        assert!(content.contains("FROM nginx:alpine"));
        assert!(content.contains("COPY . /usr/share/nginx/html"));
        assert!(content.contains("EXPOSE 80"));
    }

    #[test]
    fn test_node_dockerfile_from_app_type() {
        let builder = DockerfileBuilder::from(AppType::Node);
        let content = builder.build();
        assert!(content.contains("FROM node:20-alpine"));
        assert!(content.contains("COPY package*.json ./"));
        assert!(content.contains("RUN npm ci --production"));
        assert!(content.contains("EXPOSE 3000"));
        assert!(content.contains("CMD [\"node\", \"server.js\"]"));
    }

    #[test]
    fn test_python_dockerfile_from_app_type() {
        let builder = DockerfileBuilder::from(AppType::Python);
        let content = builder.build();
        assert!(content.contains("FROM python:3.12-slim"));
        assert!(content.contains("RUN pip install"));
        assert!(content.contains("EXPOSE 8000"));
    }

    #[test]
    fn test_rust_dockerfile_from_app_type() {
        let builder = DockerfileBuilder::from(AppType::Rust);
        let content = builder.build();
        assert!(content.contains("FROM rust:1.77-alpine"));
        assert!(content.contains("RUN cargo build --release"));
        assert!(content.contains("EXPOSE 8080"));
    }

    #[test]
    fn test_go_dockerfile_from_app_type() {
        let builder = DockerfileBuilder::from(AppType::Go);
        let content = builder.build();
        assert!(content.contains("FROM golang:1.22-alpine"));
        assert!(content.contains("RUN go build"));
        assert!(content.contains("EXPOSE 8080"));
    }

    #[test]
    fn test_php_dockerfile_from_app_type() {
        let builder = DockerfileBuilder::from(AppType::Php);
        let content = builder.build();
        assert!(content.contains("FROM php:8.3-fpm-alpine"));
        assert!(content.contains("EXPOSE 9000"));
    }

    #[test]
    fn test_custom_dockerfile_is_bare() {
        let builder = DockerfileBuilder::from(AppType::Custom);
        let content = builder.build();
        assert!(content.contains("FROM alpine:3.18"));
        // Custom has no COPY/RUN/CMD by default
        assert!(!content.contains("COPY"));
        assert!(!content.contains("RUN"));
        assert!(!content.contains("CMD"));
    }

    #[test]
    fn test_builder_fluent_chaining() {
        let content = DockerfileBuilder::new()
            .base_image("ubuntu:22.04")
            .work_dir("/opt/app")
            .env("APP_ENV", "production")
            .copy("src", "/opt/app/src")
            .run("apt-get update && apt-get install -y curl")
            .expose(8443)
            .cmd_str("./start.sh")
            .build();

        assert!(content.contains("FROM ubuntu:22.04"));
        assert!(content.contains("WORKDIR /opt/app"));
        assert!(content.contains("ENV APP_ENV=production"));
        assert!(content.contains("COPY src /opt/app/src"));
        assert!(content.contains("RUN apt-get update"));
        assert!(content.contains("EXPOSE 8443"));
        assert!(content.contains("CMD [\"./start.sh\"]"));
    }

    #[test]
    fn test_builder_label() {
        let content = DockerfileBuilder::new()
            .label("maintainer", "team@example.com")
            .build();
        assert!(content.contains("LABEL maintainer=\"team@example.com\""));
    }

    #[test]
    fn test_builder_entrypoint() {
        let content = DockerfileBuilder::new()
            .entrypoint(vec!["./run.sh".into(), "--flag".into()])
            .build();
        assert!(content.contains("ENTRYPOINT [\"./run.sh\", \"--flag\"]"));
    }

    #[test]
    fn test_display_trait_matches_build() {
        let builder = DockerfileBuilder::from(AppType::Static);
        assert_eq!(format!("{}", builder), builder.build());
    }

    #[test]
    fn test_write_to_refuses_overwrite_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Dockerfile");
        std::fs::write(&path, "existing").unwrap();

        let builder = DockerfileBuilder::from(AppType::Static);
        let result = builder.write_to(&path, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_to_allows_overwrite_when_flag_set() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Dockerfile");
        std::fs::write(&path, "old").unwrap();

        let builder = DockerfileBuilder::from(AppType::Static);
        builder.write_to(&path, true).unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("FROM nginx:alpine"));
    }

    #[test]
    fn test_write_to_creates_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Dockerfile");

        let builder = DockerfileBuilder::from(AppType::Node);
        builder.write_to(&path, false).unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("FROM node:20-alpine"));
    }

    #[test]
    fn test_project_aware_nextjs_node_dockerfile() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{
              "scripts": {
                "build": "next build",
                "start": "next start -H 0.0.0.0 -p ${PORT:-3000}"
              },
              "dependencies": {
                "next": "16.2.6"
              }
            }"#,
        )
        .unwrap();

        let content = DockerfileBuilder::for_project(dir.path(), AppType::Node).build();
        assert!(content.contains("RUN npm ci"));
        assert!(content.contains("RUN npm run build"));
        assert!(content.contains("CMD [\"npm\", \"run\", \"start\"]"));
        assert!(content.contains("ENV NEXT_TELEMETRY_DISABLED=1"));
        assert!(!content.contains("CMD [\"node\", \"server.js\"]"));
    }

    #[test]
    fn test_project_aware_node_falls_back_without_nextjs_hints() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{
              "scripts": {
                "start": "node index.js"
              },
              "dependencies": {
                "express": "^5.0.0"
              }
            }"#,
        )
        .unwrap();

        let content = DockerfileBuilder::for_project(dir.path(), AppType::Node).build();
        assert!(content.contains("RUN npm ci --production"));
        assert!(content.contains("CMD [\"node\", \"server.js\"]"));
    }

    #[test]
    fn test_multiple_expose_ports() {
        let content = DockerfileBuilder::new().expose(80).expose(443).build();
        assert!(content.contains("EXPOSE 80"));
        assert!(content.contains("EXPOSE 443"));
    }
}
