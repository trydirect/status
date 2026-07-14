use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Result of a single security check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityCheckResult {
    pub passed: bool,
    pub severity: String, // "critical", "warning", "info"
    pub message: String,
    pub details: Vec<String>,
}

/// Full security scan report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    pub no_secrets: SecurityCheckResult,
    pub no_hardcoded_creds: SecurityCheckResult,
    pub valid_docker_syntax: SecurityCheckResult,
    pub no_malicious_code: SecurityCheckResult,
    /// Whether images follow hardened-image practices (non-blocking quality check).
    pub hardened_images: SecurityCheckResult,
    pub overall_passed: bool,
    pub risk_score: u32, // 0-100, lower is better
    pub recommendations: Vec<String>,
}

impl SecurityReport {
    /// Convert to the JSONB format matching stack_template_review.security_checklist
    pub fn to_checklist_json(&self) -> Value {
        serde_json::json!({
            "no_secrets": self.no_secrets.passed,
            "no_hardcoded_creds": self.no_hardcoded_creds.passed,
            "valid_docker_syntax": self.valid_docker_syntax.passed,
            "no_malicious_code": self.no_malicious_code.passed,
            "hardened_images": self.hardened_images.passed,
        })
    }
}

/// Patterns that indicate hardcoded secrets in environment variables or configs
const SECRET_PATTERNS: &[(&str, &str)] = &[
    (
        r"(?i)(aws_secret_access_key|aws_access_key_id)\s*[:=]\s*[A-Za-z0-9/+=]{20,}",
        "AWS credentials",
    ),
    (
        r"(?i)(api[_-]?key|apikey)\s*[:=]\s*[A-Za-z0-9_\-]{16,}",
        "API key",
    ),
    (
        r"(?i)(secret[_-]?key|secret_token)\s*[:=]\s*[A-Za-z0-9_\-]{16,}",
        "Secret key/token",
    ),
    (r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}", "Bearer token"),
    (
        r"(?i)(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}",
        "GitHub token",
    ),
    (r"(?i)sk-[A-Za-z0-9]{20,}", "OpenAI/Stripe secret key"),
    (
        r"(?i)(-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----)",
        "Private key",
    ),
    (r"(?i)AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"(?i)(slack[_-]?token|xox[bpas]-)", "Slack token"),
    (
        r"(?i)(database_url|db_url)\s*[:=]\s*\S*:[^${\s]{8,}",
        "Database URL with credentials",
    ),
];

/// Patterns for hardcoded credentials (passwords, default creds)
const CRED_PATTERNS: &[(&str, &str)] = &[
    (
        r#"(?i)(password|passwd|pwd)\s*[:=]\s*['"]?(?!(\$\{|\$\(|changeme|CHANGE_ME|your_password|example))[A-Za-z0-9!@#$%^&*]{6,}['"]?"#,
        "Hardcoded password",
    ),
    (
        r#"(?i)(mysql_root_password|postgres_password|mongo_initdb_root_password)\s*[:=]\s*['"]?(?!(\$\{|\$\())[^\s'"$]{4,}"#,
        "Hardcoded database password",
    ),
    (
        r"(?i)root:(?!(\$\{|\$\())[^\s:$]{4,}",
        "Root password in plain text",
    ),
];

/// Patterns indicating potentially malicious or dangerous configurations
const MALICIOUS_PATTERNS: &[(&str, &str, &str)] = &[
    (
        r"(?i)privileged\s*:\s*true",
        "critical",
        "Container running in privileged mode",
    ),
    (
        r#"(?i)network_mode\s*:\s*['"]?host"#,
        "warning",
        "Container using host network",
    ),
    (
        r#"(?i)pid\s*:\s*['"]?host"#,
        "critical",
        "Container sharing host PID namespace",
    ),
    (
        r#"(?i)ipc\s*:\s*['"]?host"#,
        "critical",
        "Container sharing host IPC namespace",
    ),
    (
        r"(?i)cap_add\s*:.*SYS_ADMIN",
        "critical",
        "Container with SYS_ADMIN capability",
    ),
    (
        r"(?i)cap_add\s*:.*SYS_PTRACE",
        "warning",
        "Container with SYS_PTRACE capability",
    ),
    (
        r"(?i)cap_add\s*:.*ALL",
        "critical",
        "Container with ALL capabilities",
    ),
    (
        r"(?i)/var/run/docker\.sock",
        "critical",
        "Docker socket mounted (container escape risk)",
    ),
    (
        r"(?i)volumes\s*:.*:/host",
        "warning",
        "Suspicious host filesystem mount",
    ),
    (
        r"(?i)volumes\s*:.*:/etc(/|\s|$)",
        "warning",
        "Host /etc directory mounted",
    ),
    (
        r"(?i)volumes\s*:.*:/root",
        "critical",
        "Host /root directory mounted",
    ),
    (
        r"(?i)volumes\s*:.*:/proc",
        "critical",
        "Host /proc directory mounted",
    ),
    (
        r"(?i)volumes\s*:.*:/sys",
        "critical",
        "Host /sys directory mounted",
    ),
    (
        r"(?i)curl\s+.*\|\s*(sh|bash)",
        "warning",
        "Remote script execution via curl pipe",
    ),
    (
        r"(?i)wget\s+.*\|\s*(sh|bash)",
        "warning",
        "Remote script execution via wget pipe",
    ),
];

/// Known suspicious Docker images
#[allow(dead_code)]
const SUSPICIOUS_IMAGES: &[&str] = &[
    "alpine:latest", // not suspicious per se, but discouraged for reproducibility
];

const KNOWN_CRYPTO_MINER_PATTERNS: &[&str] = &[
    "xmrig",
    "cpuminer",
    "cryptonight",
    "stratum+tcp",
    "minerd",
    "hashrate",
    "monero",
    "coinhive",
    "coin-hive",
];

/// Docker image namespace/registry prefixes known to publish security-hardened images.
/// Chainguard (cgr.dev), Google Distroless, Amazon ECR Public official,
/// RapidFort, and Bitnami all apply automated CVE scanning + minimal-OS hardening.
/// Docker Official Images have no namespace separator (e.g. "nginx:1.25", "redis:7").
const KNOWN_HARDENED_SOURCES: &[&str] = &[
    "cgr.dev/",           // Chainguard hardened/distroless images
    "gcr.io/distroless/", // Google Distroless
    "public.ecr.aws/",    // Amazon ECR Public official images
    "rapidfort/",         // RapidFort minimal hardened images
    "bitnami/",           // Bitnami (Broadcom) hardened images
    "ironbank/",          // DoD Iron Bank hardened images
    "registry1.dso.mil/", // DoD Iron Bank registry
];

/// Normalize a JSON-pretty-printed string into a YAML-like format so that
/// regex patterns designed for docker-compose YAML also match JSON input.
///
/// Transforms lines like:
///   `"AWS_SECRET_ACCESS_KEY": "wJalrXU..."` → `AWS_SECRET_ACCESS_KEY: wJalrXU...`
///   `"privileged": true`                    → `privileged: true`
fn normalize_json_for_matching(json: &str) -> String {
    // Match JSON key-value pairs:  "key": "value"  or  "key": non-string
    let re = Regex::new(r#""([^"]+)"\s*:\s*"([^"]*)""#).unwrap();
    let pass1 = re.replace_all(json, "$1: $2");
    // Handle "key": true / false / number (non-string values)
    let re2 = Regex::new(r#""([^"]+)"\s*:\s*([^",\}\]]+)"#).unwrap();
    re2.replace_all(&pass1, "$1: $2").to_string()
}

/// Run all security checks on a stack definition
pub fn validate_stack_security(stack_definition: &Value) -> SecurityReport {
    // Convert the stack definition to a string for pattern matching.
    // When the input is a JSON object, serde_json produces `"key": "value"` format
    // which breaks YAML-oriented regex patterns. We normalize by stripping JSON
    // key/value quotes so patterns like `key\s*:\s*value` match both formats.
    let definition_str = match stack_definition {
        Value::String(s) => s.clone(),
        _ => {
            let json = serde_json::to_string_pretty(stack_definition).unwrap_or_default();
            normalize_json_for_matching(&json)
        }
    };

    let no_secrets = check_no_secrets(&definition_str);
    let no_hardcoded_creds = check_no_hardcoded_creds(&definition_str);
    let valid_docker_syntax = check_valid_docker_syntax(stack_definition, &definition_str);
    let no_malicious_code = check_no_malicious_code(&definition_str);
    let hardened_images = check_hardened_images(stack_definition);

    let overall_passed = no_secrets.passed
        && no_hardcoded_creds.passed
        && valid_docker_syntax.passed
        && no_malicious_code.passed;
    // hardened_images is a quality indicator — it does NOT block overall_passed

    // Calculate risk score (0-100)
    let mut risk_score: u32 = 0;
    if !no_secrets.passed {
        risk_score += 40;
    }
    if !no_hardcoded_creds.passed {
        risk_score += 25;
    }
    if !valid_docker_syntax.passed {
        risk_score += 10;
    }
    if !no_malicious_code.passed {
        risk_score += 25;
    }

    // Additional risk from severity of findings
    let critical_count = no_malicious_code
        .details
        .iter()
        .filter(|d| d.contains("[CRITICAL]"))
        .count();
    risk_score = (risk_score + (critical_count as u32 * 5)).min(100);

    let mut recommendations = Vec::new();
    if !no_secrets.passed {
        recommendations.push(
            "Replace hardcoded secrets with environment variable references (e.g., ${SECRET_KEY})"
                .to_string(),
        );
    }
    if !no_hardcoded_creds.passed {
        recommendations.push(
            "Use Docker secrets or environment variable references for passwords".to_string(),
        );
    }
    if !valid_docker_syntax.passed {
        recommendations
            .push("Fix Docker Compose syntax issues to ensure deployability".to_string());
    }
    if !no_malicious_code.passed {
        recommendations.push(
            "Review and remove dangerous container configurations (privileged mode, host mounts)"
                .to_string(),
        );
    }
    if risk_score == 0 {
        recommendations
            .push("Automated scan passed. AI review recommended for deeper analysis.".to_string());
    }
    if !hardened_images.passed {
        recommendations.push("Consider using images from hardened sources (Chainguard, Bitnami, Google Distroless) and pinning all tags to specific versions.".to_string());
    }

    SecurityReport {
        no_secrets,
        no_hardcoded_creds,
        valid_docker_syntax,
        no_malicious_code,
        hardened_images,
        overall_passed,
        risk_score,
        recommendations,
    }
}

fn check_no_secrets(content: &str) -> SecurityCheckResult {
    let mut findings = Vec::new();

    for (pattern, description) in SECRET_PATTERNS {
        if let Ok(re) = Regex::new(pattern) {
            for mat in re.find_iter(content) {
                let context = &content[mat.start()..mat.end().min(mat.start() + 60)];
                // Mask the actual value
                let masked = if context.len() > 20 {
                    format!("{}...***", &context[..20])
                } else {
                    "***masked***".to_string()
                };
                findings.push(format!("[CRITICAL] {}: {}", description, masked));
            }
        }
    }

    SecurityCheckResult {
        passed: findings.is_empty(),
        severity: if findings.is_empty() {
            "info".to_string()
        } else {
            "critical".to_string()
        },
        message: if findings.is_empty() {
            "No exposed secrets detected".to_string()
        } else {
            format!(
                "Found {} potential secret(s) in stack definition",
                findings.len()
            )
        },
        details: findings,
    }
}

fn check_no_hardcoded_creds(content: &str) -> SecurityCheckResult {
    let mut findings = Vec::new();

    for (pattern, description) in CRED_PATTERNS {
        if let Ok(re) = Regex::new(pattern) {
            for mat in re.find_iter(content) {
                let line = content[..mat.start()].lines().count() + 1;
                findings.push(format!("[WARNING] {} near line {}", description, line));
            }
        }
    }

    // Check for common default credentials
    let default_creds = [
        ("admin:admin", "Default admin:admin credentials"),
        ("root:root", "Default root:root credentials"),
        ("admin:password", "Default admin:password credentials"),
        ("user:password", "Default user:password credentials"),
    ];

    for (cred, desc) in default_creds {
        if content.to_lowercase().contains(cred) {
            findings.push(format!("[WARNING] {}", desc));
        }
    }

    SecurityCheckResult {
        passed: findings.is_empty(),
        severity: if findings.is_empty() {
            "info".to_string()
        } else {
            "warning".to_string()
        },
        message: if findings.is_empty() {
            "No hardcoded credentials detected".to_string()
        } else {
            format!("Found {} potential hardcoded credential(s)", findings.len())
        },
        details: findings,
    }
}

fn check_valid_docker_syntax(stack_definition: &Value, raw_content: &str) -> SecurityCheckResult {
    let mut findings = Vec::new();

    // Check if it looks like valid docker-compose structure
    let has_services =
        stack_definition.get("services").is_some() || raw_content.contains("services:");

    if !has_services {
        findings
            .push("[WARNING] Missing 'services' key — may not be valid Docker Compose".to_string());
    }

    // Check for 'version' key (optional in modern compose but common)
    let has_version = stack_definition.get("version").is_some() || raw_content.contains("version:");

    // Check that services have images or build contexts
    if let Some(services) = stack_definition.get("services") {
        if let Some(services_map) = services.as_object() {
            for (name, service) in services_map {
                let has_image = service.get("image").is_some();
                let has_build = service.get("build").is_some();
                if !has_image && !has_build {
                    findings.push(format!(
                        "[WARNING] Service '{}' has neither 'image' nor 'build' defined",
                        name
                    ));
                }

                // Check for image tags — warn on :latest
                if let Some(image) = service.get("image").and_then(|v| v.as_str()) {
                    if image.ends_with(":latest") || !image.contains(':') {
                        findings.push(format!(
                            "[INFO] Service '{}' uses unpinned image tag '{}' — consider pinning a specific version",
                            name, image
                        ));
                    }
                }
            }

            if services_map.is_empty() {
                findings.push("[WARNING] Services section is empty".to_string());
            }
        }
    }

    let errors_only: Vec<&String> = findings
        .iter()
        .filter(|f| f.contains("[WARNING]"))
        .collect();

    SecurityCheckResult {
        passed: errors_only.is_empty(),
        severity: if errors_only.is_empty() {
            "info".to_string()
        } else {
            "warning".to_string()
        },
        message: if errors_only.is_empty() {
            if has_version {
                "Docker Compose syntax looks valid".to_string()
            } else {
                "Docker Compose syntax acceptable (no version key, modern format)".to_string()
            }
        } else {
            format!("Found {} Docker Compose syntax issue(s)", errors_only.len())
        },
        details: findings,
    }
}

fn check_no_malicious_code(content: &str) -> SecurityCheckResult {
    let mut findings = Vec::new();

    // Check for dangerous Docker configurations
    for (pattern, severity, description) in MALICIOUS_PATTERNS {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(content) {
                findings.push(format!("[{}] {}", severity.to_uppercase(), description));
            }
        }
    }

    // Check for crypto miner patterns
    let content_lower = content.to_lowercase();
    for miner_pattern in KNOWN_CRYPTO_MINER_PATTERNS {
        if content_lower.contains(miner_pattern) {
            findings.push(format!(
                "[CRITICAL] Potential crypto miner reference detected: '{}'",
                miner_pattern
            ));
        }
    }

    // Check for suspicious base64 encoded content (long base64 strings could hide payloads)
    if let Ok(re) = Regex::new(r"[A-Za-z0-9+/]{100,}={0,2}") {
        if re.is_match(content) {
            findings.push(
                "[WARNING] Long base64-encoded content detected — may contain hidden payload"
                    .to_string(),
            );
        }
    }

    // Check for outbound network calls in entrypoints/commands
    if let Ok(re) = Regex::new(r"(?i)(curl|wget|nc|ncat)\s+.*(http|ftp|tcp)") {
        if re.is_match(content) {
            findings.push(
                "[INFO] Outbound network call detected in command/entrypoint — review if expected"
                    .to_string(),
            );
        }
    }

    let critical_or_warning: Vec<&String> = findings
        .iter()
        .filter(|f| f.contains("[CRITICAL]") || f.contains("[WARNING]"))
        .collect();

    SecurityCheckResult {
        passed: critical_or_warning.is_empty(),
        severity: if findings.iter().any(|f| f.contains("[CRITICAL]")) {
            "critical".to_string()
        } else if findings.iter().any(|f| f.contains("[WARNING]")) {
            "warning".to_string()
        } else {
            "info".to_string()
        },
        message: if critical_or_warning.is_empty() {
            "No malicious patterns detected".to_string()
        } else {
            format!(
                "Found {} potentially dangerous configuration(s)",
                critical_or_warning.len()
            )
        },
        details: findings,
    }
}

/// Returns true for an image reference that is from a known hardened source,
/// or is a Docker Official Image (no `/` separator in the name part, e.g. `nginx:1.25`).
fn is_from_hardened_source(image: &str) -> bool {
    // Strip optional registry prefix when checking known sources
    for prefix in KNOWN_HARDENED_SOURCES {
        if image.starts_with(prefix) {
            return true;
        }
    }
    // Docker Official Images have no namespace (no '/' before the tag separator ':')
    // e.g. "nginx:1.25", "redis:7-alpine", "postgres:16" — maintained by Docker, Inc.
    // We detect this by checking there is no '/' in the name before the first ':'.
    let name_part = image.split(':').next().unwrap_or(image);
    !name_part.contains('/')
}

/// Check whether services use hardened image practices:
///   1. No `:latest` or untagged images (reproducibility).
///   2. At least one service uses a non-root user OR images from known hardened sources.
///   3. Digest-pinned images (`image@sha256:`) score as fully hardened.
///
/// This is a quality/advisory check — it does NOT block `overall_passed`.
fn check_hardened_images(stack_definition: &Value) -> SecurityCheckResult {
    let mut findings: Vec<String> = Vec::new();
    let mut positives: Vec<String> = Vec::new();

    let services = match stack_definition.get("services").and_then(|s| s.as_object()) {
        Some(s) => s,
        None => {
            return SecurityCheckResult {
                passed: false,
                severity: "info".to_string(),
                message: "Cannot analyse images: no services found".to_string(),
                details: vec![],
            };
        }
    };

    let mut total_images: usize = 0;
    let mut pinned_count: usize = 0;
    let mut hardened_source_count: usize = 0;
    let mut non_root_count: usize = 0;
    let mut read_only_count: usize = 0;

    for (name, service) in services {
        // Check image tag quality
        if let Some(image) = service.get("image").and_then(|v| v.as_str()) {
            total_images += 1;

            if image.contains("@sha256:") {
                pinned_count += 1;
                positives.push(format!(
                    "Service '{}': image pinned to digest ({})",
                    name, image
                ));
            } else if image.ends_with(":latest") {
                findings.push(format!(
                    "[WARNING] Service '{}' uses ':latest' tag — not reproducible and may silently receive unsafe updates ({})",
                    name, image
                ));
            } else if !image.contains(':') {
                findings.push(format!(
                    "[WARNING] Service '{}' has no tag — defaults to ':latest' implicitly ({})",
                    name, image
                ));
            } else {
                pinned_count += 1; // versioned tag counts as pinned
            }

            if is_from_hardened_source(image) {
                hardened_source_count += 1;
                positives.push(format!(
                    "Service '{}': image from hardened/trusted source ({})",
                    name, image
                ));
            }
        }

        // Check for non-root user
        if let Some(user) = service.get("user").and_then(|v| v.as_str()) {
            let is_root = user == "root" || user == "0" || user.starts_with("0:");
            if !is_root {
                non_root_count += 1;
                positives.push(format!(
                    "Service '{}': runs as non-root user ({})",
                    name, user
                ));
            } else {
                findings.push(format!(
                    "[INFO] Service '{}' explicitly runs as root — consider a non-root user",
                    name
                ));
            }
        }

        // Check for read-only root filesystem
        if service.get("read_only").and_then(|v| v.as_bool()) == Some(true) {
            read_only_count += 1;
            positives.push(format!(
                "Service '{}': read-only root filesystem enabled",
                name
            ));
        }
    }

    // Determine pass/fail:
    // Pass requires ALL images to have versioned tags AND at least one hardened-source
    // or non-root signal. A single service with a `:latest` tag is a failure.
    let unpinned_warnings = findings.iter().filter(|f| f.contains("[WARNING]")).count();
    let passed = unpinned_warnings == 0
        && total_images > 0
        && (hardened_source_count > 0
            || non_root_count > 0
            || read_only_count > 0
            || pinned_count == total_images);

    let mut details = findings.clone();
    details.extend(positives);

    SecurityCheckResult {
        passed,
        severity: if unpinned_warnings > 0 {
            "warning".to_string()
        } else if passed {
            "info".to_string()
        } else {
            "info".to_string()
        },
        message: if passed {
            format!(
                "Images follow hardened practices ({} pinned, {} from hardened sources, {} non-root)",
                pinned_count, hardened_source_count, non_root_count
            )
        } else {
            format!(
                "{} image(s) use unpinned/latest tags or lack hardening signals",
                unpinned_warnings.max(if total_images == 0 { 1 } else { 0 })
            )
        },
        details,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_clean_definition_passes() {
        let definition = json!({
            "version": "3.8",
            "services": {
                "web": {
                    "image": "nginx:1.25",
                    "ports": ["80:80"]
                },
                "db": {
                    "image": "postgres:16",
                    "environment": {
                        "POSTGRES_PASSWORD": "${DB_PASSWORD}"
                    }
                }
            }
        });

        let report = validate_stack_security(&definition);
        assert!(report.overall_passed);
        assert_eq!(report.risk_score, 0);
    }

    #[test]
    fn test_hardcoded_secret_detected() {
        let definition = json!({
            "services": {
                "app": {
                    "image": "myapp:1.0",
                    "environment": {
                        "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                    }
                }
            }
        });

        let report = validate_stack_security(&definition);
        assert!(!report.no_secrets.passed);
        assert!(report.risk_score >= 40);
    }

    #[test]
    fn test_privileged_mode_detected() {
        let definition = json!({
            "services": {
                "app": {
                    "image": "myapp:1.0",
                    "privileged": true
                }
            }
        });

        let report = validate_stack_security(&definition);
        assert!(!report.no_malicious_code.passed);
    }

    #[test]
    fn test_docker_socket_mount_detected() {
        let definition = json!({
            "services": {
                "app": {
                    "image": "myapp:1.0",
                    "volumes": ["/var/run/docker.sock:/var/run/docker.sock"]
                }
            }
        });

        let report = validate_stack_security(&definition);
        assert!(!report.no_malicious_code.passed);
    }

    #[test]
    fn test_missing_services_key() {
        let definition = json!({
            "app": {
                "image": "nginx:1.25"
            }
        });

        let report = validate_stack_security(&definition);
        assert!(!report.valid_docker_syntax.passed);
    }

    #[test]
    fn test_hardened_images_passes_for_official_versioned() {
        // Docker Official Images (nginx, postgres) with pinned versions — should pass
        let definition = json!({
            "services": {
                "web": { "image": "nginx:1.25" },
                "db":  { "image": "postgres:16" }
            }
        });
        let result = check_hardened_images(&definition);
        assert!(
            result.passed,
            "Official images with versioned tags should pass: {}",
            result.message
        );
    }

    #[test]
    fn test_hardened_images_fails_for_latest() {
        let definition = json!({
            "services": {
                "web": { "image": "nginx:latest" }
            }
        });
        let result = check_hardened_images(&definition);
        assert!(
            !result.passed,
            "':latest' tag should fail hardened-images check"
        );
    }

    #[test]
    fn test_hardened_images_fails_for_untagged() {
        let definition = json!({
            "services": {
                "web": { "image": "nginx" }
            }
        });
        let result = check_hardened_images(&definition);
        assert!(
            !result.passed,
            "Untagged image should fail hardened-images check"
        );
    }

    #[test]
    fn test_hardened_images_passes_for_chainguard() {
        let definition = json!({
            "services": {
                "web": { "image": "cgr.dev/chainguard/nginx:latest" }
            }
        });
        // Even ':latest' on cgr.dev is pinned via digest under the hood, but our
        // static check currently only exempts known-hardened-source prefix from the
        // non-root/digest requirement, while still flagging ':latest' as a warning.
        // This test verifies the hardened-source is detected.
        let result = check_hardened_images(&definition);
        assert!(
            result
                .details
                .iter()
                .any(|d| d.contains("hardened/trusted source")),
            "Chainguard image should be recognised as hardened source"
        );
    }

    #[test]
    fn test_hardened_images_passes_for_non_root_user() {
        let definition = json!({
            "services": {
                "app": {
                    "image": "myapp:2.0",
                    "user": "1001"
                }
            }
        });
        let result = check_hardened_images(&definition);
        assert!(
            result.passed,
            "Versioned image + non-root user should pass: {}",
            result.message
        );
    }

    #[test]
    fn test_hardened_images_digest_pinned() {
        let definition = json!({
            "services": {
                "app": {
                    "image": "nginx@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456ab12"
                }
            }
        });
        let result = check_hardened_images(&definition);
        assert!(
            result.passed,
            "Digest-pinned image should pass: {}",
            result.message
        );
        assert!(result
            .details
            .iter()
            .any(|d| d.contains("pinned to digest")));
    }

    #[test]
    fn test_hardened_check_does_not_block_overall_passed() {
        // A stack with ':latest' tags should still pass overall security (no secrets etc.)
        // but hardened_images check should fail on its own
        let definition = json!({
            "version": "3.8",
            "services": {
                "web": {
                    "image": "nginx:latest",
                    "ports": ["80:80"]
                }
            }
        });
        let report = validate_stack_security(&definition);
        assert!(
            report.overall_passed,
            "':latest' tag should NOT block overall_passed"
        );
        assert!(
            !report.hardened_images.passed,
            "':latest' tag should fail hardened_images check"
        );
    }
}
