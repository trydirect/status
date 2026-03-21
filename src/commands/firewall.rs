use anyhow::{bail, Result};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::process::Stdio;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::process::Command as TokioCommand;
use tracing::{debug, error, info, warn};

use crate::transport::{Command as AgentCommand, CommandError, CommandResult};

/// Comment prefix used to tag all stacker-managed rules
const STACKER_COMMENT_PREFIX: &str = "stacker:";

// ---------------------------------------------------------------------------
// Protected services — hardcoded minimum set that cannot be overridden
// ---------------------------------------------------------------------------

struct ProtectedService {
    port: u16,
    protocol: &'static str, // "tcp", "udp", or "any" (matches both)
    reason: &'static str,
}

/// Hardcoded services that must never be managed by the firewall module.
/// These cannot be overridden or removed via configuration.
const PROTECTED_SERVICES: &[ProtectedService] = &[
    ProtectedService {
        port: 22,
        protocol: "tcp",
        reason: "SSH",
    },
    ProtectedService {
        port: 53,
        protocol: "any",
        reason: "DNS",
    },
    ProtectedService {
        port: 68,
        protocol: "udp",
        reason: "DHCP client",
    },
    ProtectedService {
        port: 123,
        protocol: "udp",
        reason: "NTP",
    },
];

/// Check whether a port+protocol combination is protected.
/// Returns `Some(reason)` if the port must not be managed, `None` otherwise.
/// Also checks `extra_protected_ports` from config and an optional API port.
fn is_protected(port: u16, protocol: &str, policy: &FirewallPolicy) -> Option<String> {
    // 1. Hardcoded minimum set
    for svc in PROTECTED_SERVICES {
        if svc.port == port && (svc.protocol == "any" || svc.protocol == protocol) {
            return Some(svc.reason.to_string());
        }
    }
    // 2. API port auto-protection
    if let Some(api_port) = policy.api_port {
        if port == api_port {
            return Some("Status Panel API port".to_string());
        }
    }
    // 3. Extra protected ports from config
    if policy.extra_protected_ports.contains(&port) {
        return Some("Custom protected port (config)".to_string());
    }
    None
}

/// Check whether a port is allowed by the optional whitelist.
/// Returns `Ok(())` if allowed, or `Err(message)` if blocked.
fn check_allowed(port: u16, policy: &FirewallPolicy) -> Result<(), String> {
    if let Some(ref allowed) = policy.allowed_ports {
        if !allowed.contains(&port) {
            return Err(format!("Port {} is not in the allowed ports list", port));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Firewall policy — runtime-resolved from config + API port
// ---------------------------------------------------------------------------

/// Runtime policy passed into the firewall handler.
/// Combines config-driven settings with runtime context (API port).
#[derive(Debug, Clone, Default)]
pub struct FirewallPolicy {
    /// Ports from config `firewall.extra_protected_ports`
    pub extra_protected_ports: Vec<u16>,
    /// If set, only these ports can be managed (whitelist)
    pub allowed_ports: Option<Vec<u16>>,
    /// The status panel's own serve port (auto-protected)
    pub api_port: Option<u16>,
}

impl FirewallPolicy {
    /// Build a policy from the agent config and an optional API serve port.
    pub fn from_config(config: &crate::agent::config::Config, api_port: Option<u16>) -> Self {
        let fw = config.firewall.as_ref();
        Self {
            extra_protected_ports: fw
                .map(|f| f.extra_protected_ports.clone())
                .unwrap_or_default(),
            allowed_ports: fw.and_then(|f| f.allowed_ports.clone()),
            api_port,
        }
    }
}

// ---------------------------------------------------------------------------
// Firewall rate limiter — module-level singleton, 10 ops / 60s
// ---------------------------------------------------------------------------

const FIREWALL_RATE_LIMIT: usize = 10;
const FIREWALL_RATE_WINDOW_SECS: u64 = 60;

struct FirewallRateLimiter {
    window: Duration,
    limit: usize,
    timestamps: Mutex<VecDeque<Instant>>,
}

impl FirewallRateLimiter {
    const fn new() -> Self {
        Self {
            window: Duration::from_secs(FIREWALL_RATE_WINDOW_SECS),
            limit: FIREWALL_RATE_LIMIT,
            timestamps: Mutex::new(VecDeque::new()),
        }
    }

    fn allow(&self) -> bool {
        let now = Instant::now();
        let mut ts = self.timestamps.lock().unwrap_or_else(|e| e.into_inner());
        // purge expired entries
        while let Some(&front) = ts.front() {
            if now.duration_since(front) > self.window {
                ts.pop_front();
            } else {
                break;
            }
        }
        if ts.len() < self.limit {
            ts.push_back(now);
            true
        } else {
            false
        }
    }
}

fn firewall_rate_limiter() -> &'static FirewallRateLimiter {
    static INSTANCE: OnceLock<FirewallRateLimiter> = OnceLock::new();
    INSTANCE.get_or_init(FirewallRateLimiter::new)
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct ConfigureFirewallCommand {
    #[serde(default)]
    pub deployment_hash: String,
    #[serde(default)]
    pub app_code: Option<String>,
    /// One of: "add", "remove", "list", "flush"
    pub action: String,
    #[serde(default)]
    pub public_ports: Vec<FirewallPortRule>,
    #[serde(default)]
    pub private_ports: Vec<FirewallPortRule>,
    #[serde(default = "default_true")]
    pub persist: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FirewallPortRule {
    pub port: u16,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default = "default_source")]
    pub source: String,
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FirewallRuleResult {
    pub port: u16,
    pub protocol: String,
    pub source: String,
    pub applied: bool,
    pub message: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_protocol() -> String {
    "tcp".to_string()
}

fn default_source() -> String {
    "0.0.0.0/0".to_string()
}

// ---------------------------------------------------------------------------
// Normalize / validate
// ---------------------------------------------------------------------------

impl ConfigureFirewallCommand {
    pub fn normalize(mut self) -> Self {
        self.deployment_hash = self.deployment_hash.trim().to_string();
        self.app_code = self.app_code.map(|s| {
            let t = s.trim().to_string();
            if t.is_empty() {
                return t;
            }
            t
        });
        self.action = self.action.trim().to_lowercase();

        for rule in self
            .public_ports
            .iter_mut()
            .chain(self.private_ports.iter_mut())
        {
            rule.protocol = rule.protocol.trim().to_lowercase();
            if rule.protocol.is_empty() {
                rule.protocol = "tcp".to_string();
            }
            rule.source = rule.source.trim().to_string();
            if rule.source.is_empty() {
                rule.source = "0.0.0.0/0".to_string();
            }
        }

        self
    }

    pub fn with_command_context(mut self, agent_cmd: &AgentCommand) -> Self {
        if self.deployment_hash.is_empty() {
            if let Some(hash) = &agent_cmd.deployment_hash {
                self.deployment_hash = hash.clone();
            }
        }
        if self.app_code.is_none() || self.app_code.as_deref() == Some("") {
            self.app_code = agent_cmd.app_code.clone();
        }
        self
    }

    pub fn validate(&self) -> Result<()> {
        if !["add", "remove", "list", "flush"].contains(&self.action.as_str()) {
            bail!(
                "action must be one of: add, remove, list, flush (got '{}')",
                self.action
            );
        }

        let needs_ports = self.action == "add" || self.action == "remove";
        if needs_ports && self.public_ports.is_empty() && self.private_ports.is_empty() {
            bail!("{} action requires at least one port rule", self.action);
        }

        for rule in self.public_ports.iter().chain(self.private_ports.iter()) {
            if rule.port == 0 {
                bail!("port must be between 1 and 65535");
            }
            if !["tcp", "udp"].contains(&rule.protocol.as_str()) {
                bail!("protocol must be tcp or udp (got '{}')", rule.protocol);
            }
            validate_source_cidr(&rule.source)?;
        }

        Ok(())
    }
}

/// Validate that a source string is a valid IP or CIDR notation.
fn validate_source_cidr(source: &str) -> Result<()> {
    if source == "0.0.0.0/0" {
        return Ok(());
    }
    // Try parsing as CIDR (ip/prefix)
    if let Some((ip_part, prefix_part)) = source.split_once('/') {
        let ip: IpAddr = ip_part
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid IP in source CIDR: {}", source))?;
        let prefix: u8 = prefix_part
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid prefix length in source CIDR: {}", source))?;
        let (max_prefix, ip_family) = match ip {
            IpAddr::V4(_) => (32, "IPv4"),
            IpAddr::V6(_) => (128, "IPv6"),
        };
        if prefix > max_prefix {
            bail!("invalid {} CIDR prefix length: {}", ip_family, prefix);
        }
    } else {
        // Plain IP address
        let _ip: IpAddr = source
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid source IP: {}", source))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

pub async fn handle_configure_firewall(
    agent_cmd: &AgentCommand,
    data: &ConfigureFirewallCommand,
    policy: &FirewallPolicy,
) -> Result<CommandResult> {
    let app_code_str = data.app_code.as_deref().unwrap_or("unknown");
    let mut result = CommandResult {
        command_id: agent_cmd.command_id.clone(),
        status: "success".into(),
        result: None,
        error: None,
        completed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        deployment_hash: Some(data.deployment_hash.clone()),
        app_code: Some(app_code_str.to_string()),
        command_type: Some("configure_firewall".to_string()),
        ..CommandResult::default()
    };

    // Rate limiting: 10 operations per minute
    if !firewall_rate_limiter().allow() {
        warn!(
            action = %data.action,
            app_code = app_code_str,
            "Firewall operation rate limited"
        );
        let error = CommandError {
            code: "rate_limited".to_string(),
            message: "Firewall operations rate limited (max 10/min)".to_string(),
            details: None,
        };
        result.status = "failed".into();
        result.error = Some(error.message.clone());
        result.errors = Some(vec![error]);
        result.result = Some(json!({
            "type": "configure_firewall",
            "deployment_hash": data.deployment_hash,
            "app_code": app_code_str,
            "status": "failed",
            "rules": [],
            "errors": [{"code": "rate_limited", "message": "Firewall operations rate limited (max 10/min)"}],
        }));
        return Ok(result);
    }

    // Port authorization for mutating actions (add/remove)
    if data.action == "add" || data.action == "remove" {
        for rule in data.public_ports.iter().chain(data.private_ports.iter()) {
            // Protected port check
            if let Some(reason) = is_protected(rule.port, &rule.protocol, policy) {
                warn!(
                    port = rule.port,
                    protocol = %rule.protocol,
                    reason = %reason,
                    action = %data.action,
                    app_code = app_code_str,
                    "Blocked: port is protected"
                );
                let error = CommandError {
                    code: "protected_port".to_string(),
                    message: format!(
                        "Port {}/{} is protected ({}) and cannot be managed",
                        rule.port, rule.protocol, reason
                    ),
                    details: None,
                };
                result.status = "failed".into();
                result.error = Some(error.message.clone());
                result.errors = Some(vec![error]);
                result.result = Some(json!({
                    "type": "configure_firewall",
                    "deployment_hash": data.deployment_hash,
                    "app_code": app_code_str,
                    "status": "failed",
                    "rules": [],
                    "errors": [{"code": "protected_port", "message": result.error}],
                }));
                return Ok(result);
            }
            // Allowed-ports whitelist check
            if let Err(msg) = check_allowed(rule.port, policy) {
                warn!(
                    port = rule.port,
                    protocol = %rule.protocol,
                    action = %data.action,
                    app_code = app_code_str,
                    "Blocked: port not in allowed list"
                );
                let error = CommandError {
                    code: "port_not_allowed".to_string(),
                    message: msg,
                    details: None,
                };
                result.status = "failed".into();
                result.error = Some(error.message.clone());
                result.errors = Some(vec![error]);
                result.result = Some(json!({
                    "type": "configure_firewall",
                    "deployment_hash": data.deployment_hash,
                    "app_code": app_code_str,
                    "status": "failed",
                    "rules": [],
                    "errors": [{"code": "port_not_allowed", "message": result.error}],
                }));
                return Ok(result);
            }
        }
    }

    // Check iptables availability
    if let Err(e) = check_iptables_available().await {
        let error = CommandError {
            code: "iptables_unavailable".to_string(),
            message: e.to_string(),
            details: None,
        };
        result.status = "failed".into();
        result.error = Some(error.message.clone());
        result.errors = Some(vec![error]);
        result.result = Some(json!({
            "type": "configure_firewall",
            "deployment_hash": data.deployment_hash,
            "app_code": app_code_str,
            "status": "failed",
            "rules": [],
            "errors": [{"code": "iptables_unavailable", "message": e.to_string()}],
        }));
        return Ok(result);
    }

    match data.action.as_str() {
        "add" => handle_add(&mut result, data, app_code_str).await,
        "remove" => handle_remove(&mut result, data, app_code_str).await,
        "list" => handle_list(&mut result, data, app_code_str).await,
        "flush" => handle_flush(&mut result, data, app_code_str).await,
        _ => {
            result.status = "failed".into();
            result.error = Some(format!("Unknown action: {}", data.action));
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Action: add
// ---------------------------------------------------------------------------

async fn handle_add(result: &mut CommandResult, data: &ConfigureFirewallCommand, app_code: &str) {
    let mut rule_results = Vec::new();
    let mut errors = Vec::new();

    // Detect whether Docker is managing iptables (DOCKER-USER chain exists)
    let has_docker = docker_user_chain_exists().await;
    if has_docker {
        info!("DOCKER-USER chain detected — private port rules will also be applied there");
    }

    let all_rules: Vec<(&FirewallPortRule, bool)> = data
        .public_ports
        .iter()
        .map(|r| (r, true))
        .chain(data.private_ports.iter().map(|r| (r, false)))
        .collect();

    for (rule, is_public) in &all_rules {
        let comment = build_comment(app_code, rule);

        // --- INPUT chain (covers host-bound services) ---
        // Idempotency: check if rule already exists
        let input_already_exists = rule_exists(rule, &comment).await.unwrap_or(false);
        if input_already_exists {
            info!(port = rule.port, protocol = %rule.protocol, "INPUT rule already exists, skipping");
        } else {
            match add_rule(rule, &comment).await {
                Ok(()) => {
                    info!(port = rule.port, protocol = %rule.protocol, source = %rule.source, "INPUT rule added");
                }
                Err(e) => {
                    error!(port = rule.port, error = %e, "Failed to add INPUT rule");
                    let err = CommandError {
                        code: "rule_add_failed".to_string(),
                        message: format!("Failed to add INPUT rule for port {}: {}", rule.port, e),
                        details: None,
                    };
                    errors.push(err);
                    rule_results.push(FirewallRuleResult {
                        port: rule.port,
                        protocol: rule.protocol.clone(),
                        source: rule.source.clone(),
                        applied: false,
                        message: Some(e.to_string()),
                    });
                    continue;
                }
            }
        }

        // --- DOCKER-USER chain (covers Docker-published ports) ---
        // Private ports need explicit ACCEPT + default DROP in DOCKER-USER
        // to actually restrict access to Docker containers.
        // Public ports don't need DOCKER-USER rules because Docker's default
        // is RETURN (allow) for all forwarded traffic.
        if has_docker && !is_public {
            let docker_ok = add_docker_user_rules(rule, &comment, &mut errors).await;
            if !docker_ok {
                warn!(
                    port = rule.port,
                    "DOCKER-USER rule failed; INPUT rule was applied"
                );
            }
            if !docker_ok {
                let msg = "INPUT rule applied but DOCKER-USER rule failed".to_string();
                rule_results.push(FirewallRuleResult {
                    port: rule.port,
                    protocol: rule.protocol.clone(),
                    source: rule.source.clone(),
                    applied: false,
                    message: Some(msg),
                });
                continue;
            }
        }

        let msg = if input_already_exists {
            Some("Rule already exists".to_string())
        } else {
            None
        };
        rule_results.push(FirewallRuleResult {
            port: rule.port,
            protocol: rule.protocol.clone(),
            source: rule.source.clone(),
            applied: true,
            message: msg,
        });
    }

    if data.persist {
        if let Err(e) = persist_rules().await {
            warn!(error = %e, "Failed to persist iptables rules");
            errors.push(CommandError {
                code: "persist_failed".to_string(),
                message: format!("Rules applied but persistence failed: {}", e),
                details: None,
            });
        }
    }

    let status = determine_status(&rule_results, &errors);
    result.status = map_command_status(status.as_str());
    if !errors.is_empty() {
        result.errors = Some(errors.clone());
    }
    result.result = Some(json!({
        "type": "configure_firewall",
        "deployment_hash": data.deployment_hash,
        "app_code": app_code,
        "status": status,
        "rules": rule_results,
        "errors": errors.iter().map(|e| json!({"code": e.code, "message": e.message})).collect::<Vec<_>>(),
    }));
}

// ---------------------------------------------------------------------------
// Action: remove
// ---------------------------------------------------------------------------

async fn handle_remove(
    result: &mut CommandResult,
    data: &ConfigureFirewallCommand,
    app_code: &str,
) {
    let mut rule_results = Vec::new();
    let mut errors = Vec::new();

    let has_docker = docker_user_chain_exists().await;

    // Track which rules are private (need DOCKER-USER cleanup)
    let all_rules: Vec<(&FirewallPortRule, bool)> = data
        .public_ports
        .iter()
        .map(|r| (r, true))
        .chain(data.private_ports.iter().map(|r| (r, false)))
        .collect();

    for (rule, is_public) in &all_rules {
        let comment = build_comment(app_code, rule);

        // Remove INPUT rule
        match remove_rule(rule, &comment).await {
            Ok(removed) => {
                if removed {
                    info!(port = rule.port, protocol = %rule.protocol, "INPUT rule removed");
                } else {
                    debug!(port = rule.port, protocol = %rule.protocol, "INPUT rule not found, nothing to remove");
                }
                rule_results.push(FirewallRuleResult {
                    port: rule.port,
                    protocol: rule.protocol.clone(),
                    source: rule.source.clone(),
                    applied: true,
                    message: if removed {
                        None
                    } else {
                        Some("Rule not found".to_string())
                    },
                });
            }
            Err(e) => {
                error!(port = rule.port, error = %e, "Failed to remove INPUT rule");
                let err = CommandError {
                    code: "rule_remove_failed".to_string(),
                    message: format!("Failed to remove rule for port {}: {}", rule.port, e),
                    details: None,
                };
                errors.push(err);
                rule_results.push(FirewallRuleResult {
                    port: rule.port,
                    protocol: rule.protocol.clone(),
                    source: rule.source.clone(),
                    applied: false,
                    message: Some(e.to_string()),
                });
            }
        }

        // Also remove DOCKER-USER rules for private ports
        if has_docker && !is_public {
            remove_docker_user_rules(rule, &comment, &mut errors).await;
        }
    }

    if data.persist {
        if let Err(e) = persist_rules().await {
            warn!(error = %e, "Failed to persist iptables rules");
            errors.push(CommandError {
                code: "persist_failed".to_string(),
                message: format!("Rules removed but persistence failed: {}", e),
                details: None,
            });
        }
    }

    let status = determine_status(&rule_results, &errors);
    result.status = map_command_status(status.as_str());
    if !errors.is_empty() {
        result.errors = Some(errors.clone());
    }
    result.result = Some(json!({
        "type": "configure_firewall",
        "deployment_hash": data.deployment_hash,
        "app_code": app_code,
        "status": status,
        "rules": rule_results,
        "errors": errors.iter().map(|e| json!({"code": e.code, "message": e.message})).collect::<Vec<_>>(),
    }));
}

// ---------------------------------------------------------------------------
// Action: list
// ---------------------------------------------------------------------------

async fn handle_list(result: &mut CommandResult, data: &ConfigureFirewallCommand, app_code: &str) {
    let input_output = run_iptables(&["-L", "INPUT", "-n", "-v", "--line-numbers"]).await;
    let docker_user_output = if docker_user_chain_exists().await {
        run_iptables(&["-L", DOCKER_USER_CHAIN, "-n", "-v", "--line-numbers"])
            .await
            .ok()
    } else {
        None
    };

    match input_output {
        Ok(output) => {
            let mut body = json!({
                "type": "configure_firewall",
                "deployment_hash": data.deployment_hash,
                "app_code": app_code,
                "status": "ok",
                "action": "list",
                "raw_rules": output,
                "rules": [],
                "errors": [],
            });
            if let Some(docker_output) = docker_user_output {
                body["docker_user_rules"] = json!(docker_output);
            }
            result.result = Some(body);
        }
        Err(e) => {
            let err = CommandError {
                code: "list_failed".to_string(),
                message: format!("Failed to list iptables rules: {}", e),
                details: None,
            };
            result.status = "failed".into();
            result.error = Some(err.message.clone());
            result.errors = Some(vec![err]);
            result.result = Some(json!({
                "type": "configure_firewall",
                "deployment_hash": data.deployment_hash,
                "app_code": app_code,
                "status": "failed",
                "rules": [],
                "errors": [{"code": "list_failed", "message": e.to_string()}],
            }));
        }
    }
}

// ---------------------------------------------------------------------------
// Action: flush (only stacker-managed rules)
// ---------------------------------------------------------------------------

async fn handle_flush(result: &mut CommandResult, data: &ConfigureFirewallCommand, app_code: &str) {
    let mut errors = Vec::new();
    let mut removed_count: u32 = 0;

    // Get current rules with line numbers
    let list_output = match run_iptables(&["-L", "INPUT", "-n", "--line-numbers"]).await {
        Ok(output) => output,
        Err(e) => {
            let err = CommandError {
                code: "flush_list_failed".to_string(),
                message: format!("Failed to list rules for flush: {}", e),
                details: None,
            };
            result.status = "failed".into();
            result.error = Some(err.message.clone());
            result.errors = Some(vec![err]);
            result.result = Some(json!({
                "type": "configure_firewall",
                "deployment_hash": data.deployment_hash,
                "app_code": app_code,
                "status": "failed",
                "removed_count": 0,
                "errors": [{"code": "flush_list_failed", "message": e.to_string()}],
            }));
            return;
        }
    };

    // Parse line numbers of stacker-managed rules (delete in reverse order to keep indices valid)
    let mut line_numbers: Vec<u32> = Vec::new();
    for line in list_output.lines() {
        if line.contains(STACKER_COMMENT_PREFIX) {
            // Line format: "NUM  ... /* stacker:app:comment */ ..."
            // Or listing format: "1    ACCEPT  tcp ... /* stacker:nginx:HTTP */"
            if let Some(num_str) = line.split_whitespace().next() {
                if let Ok(num) = num_str.parse::<u32>() {
                    line_numbers.push(num);
                }
            }
        }
    }

    // Delete in reverse order so line numbers stay valid
    line_numbers.sort_unstable();
    line_numbers.reverse();

    for line_num in &line_numbers {
        match run_iptables(&["-D", "INPUT", &line_num.to_string()]).await {
            Ok(_) => {
                removed_count += 1;
                debug!(line_num, "Flushed stacker rule");
            }
            Err(e) => {
                error!(line_num, error = %e, "Failed to flush rule");
                errors.push(CommandError {
                    code: "flush_rule_failed".to_string(),
                    message: format!("Failed to delete rule at line {}: {}", line_num, e),
                    details: None,
                });
            }
        }
    }

    // Also flush stacker rules from DOCKER-USER chain
    let docker_removed = flush_docker_user_chain(&mut errors).await;
    removed_count += docker_removed;

    if data.persist && removed_count > 0 {
        if let Err(e) = persist_rules().await {
            warn!(error = %e, "Failed to persist after flush");
            errors.push(CommandError {
                code: "persist_failed".to_string(),
                message: format!("Flush completed but persistence failed: {}", e),
                details: None,
            });
        }
    }

    info!(
        removed_count,
        total_found = line_numbers.len(),
        "Flush completed"
    );

    let status = if errors.is_empty() {
        "ok"
    } else if removed_count > 0 {
        "partial_success"
    } else if line_numbers.is_empty() {
        "ok"
    } else {
        "failed"
    };

    result.status = map_command_status(status);
    if !errors.is_empty() {
        result.errors = Some(errors.clone());
    }
    result.result = Some(json!({
        "type": "configure_firewall",
        "deployment_hash": data.deployment_hash,
        "app_code": app_code,
        "status": status,
        "action": "flush",
        "removed_count": removed_count,
        "errors": errors.iter().map(|e| json!({"code": e.code, "message": e.message})).collect::<Vec<_>>(),
    }));
}

// ---------------------------------------------------------------------------
// iptables helpers
// ---------------------------------------------------------------------------

/// Build the iptables comment for a rule: `stacker:{app_code}:{description}`
///
/// The resulting string is sanitized to remove control characters (including
/// newlines) and truncated to a safe maximum length to avoid iptables
/// rejecting the rule or misinterpreting the comment.
fn build_comment(app_code: &str, rule: &FirewallPortRule) -> String {
    let desc = rule.comment.as_deref().unwrap_or(&rule.protocol);
    let raw = format!("{}{}:{}", STACKER_COMMENT_PREFIX, app_code, desc);
    sanitize_iptables_comment(&raw)
}

/// Sanitize an iptables comment string by stripping control characters
/// (including newlines) and truncating to a safe maximum length.
fn sanitize_iptables_comment(text: &str) -> String {
    // Remove all control characters to prevent iptables from rejecting
    // the rule or interpreting embedded newlines/tabs.
    let cleaned: String = text.chars().filter(|c| !c.is_control()).collect();

    // Truncate to a conservative maximum length; iptables itself allows
    // longer comments, but overly long comments can still cause issues.
    const MAX_COMMENT_LEN: usize = 255;

    if cleaned.chars().count() > MAX_COMMENT_LEN {
        cleaned.chars().take(MAX_COMMENT_LEN).collect()
    } else {
        cleaned
    }
}
/// Check if iptables is available on the system.
async fn check_iptables_available() -> Result<()> {
    let output = TokioCommand::new("iptables")
        .arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("iptables not found or not executable: {}", e))?;

    if !output.status.success() {
        bail!("iptables returned non-zero exit code");
    }
    Ok(())
}

/// Run an iptables command and return stdout.
async fn run_iptables(args: &[&str]) -> Result<String> {
    debug!(args = ?args, "Running iptables");

    let output = TokioCommand::new("iptables")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to execute iptables: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("iptables failed: {}", stderr.trim());
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Check whether a specific rule already exists in the given chain (`iptables -C`).
async fn rule_exists_in_chain(
    chain: &str,
    rule: &FirewallPortRule,
    action: &str,
    comment: &str,
) -> Result<bool> {
    let port_string = rule.port.to_string();

    let args: Vec<&str> = vec![
        "-C",
        chain,
        "-p",
        &rule.protocol,
        "--dport",
        &port_string,
        "-j",
        action,
    ]
    .into_iter()
    .chain(if rule.source != "0.0.0.0/0" {
        vec!["-s", rule.source.as_str()]
    } else {
        vec![]
    })
    .chain(vec!["-m", "comment", "--comment", comment])
    .collect();

    let output = TokioCommand::new("iptables")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to check iptables rule: {}", e))?;

    Ok(output.status.success())
}

/// Shorthand: check INPUT chain ACCEPT rule.
async fn rule_exists(rule: &FirewallPortRule, comment: &str) -> Result<bool> {
    rule_exists_in_chain("INPUT", rule, "ACCEPT", comment).await
}

/// Insert a single iptables rule into the given chain.
/// Uses `-I` (insert at top) for DOCKER-USER, `-A` (append) for INPUT.
async fn add_rule_to_chain(
    chain: &str,
    rule: &FirewallPortRule,
    action: &str,
    comment: &str,
) -> Result<()> {
    let port_string = rule.port.to_string();
    let op = if chain == DOCKER_USER_CHAIN {
        "-I"
    } else {
        "-A"
    };

    let args: Vec<&str> = vec![
        op,
        chain,
        "-p",
        &rule.protocol,
        "--dport",
        &port_string,
        "-j",
        action,
    ]
    .into_iter()
    .chain(if rule.source != "0.0.0.0/0" {
        vec!["-s", rule.source.as_str()]
    } else {
        vec![]
    })
    .chain(vec!["-m", "comment", "--comment", comment])
    .collect();

    run_iptables(&args).await?;
    Ok(())
}

/// Shorthand: append ACCEPT rule to INPUT chain.
async fn add_rule(rule: &FirewallPortRule, comment: &str) -> Result<()> {
    add_rule_to_chain("INPUT", rule, "ACCEPT", comment).await
}

/// Remove a single iptables rule from the given chain. Returns true if removed.
async fn remove_rule_from_chain(
    chain: &str,
    rule: &FirewallPortRule,
    action: &str,
    comment: &str,
) -> Result<bool> {
    match rule_exists_in_chain(chain, rule, action, comment).await {
        Ok(false) => return Ok(false),
        Err(e) => {
            debug!(error = %e, chain, "Could not check rule existence, attempting delete anyway");
        }
        Ok(true) => {}
    }

    let port_string = rule.port.to_string();

    let args: Vec<&str> = vec![
        "-D",
        chain,
        "-p",
        &rule.protocol,
        "--dport",
        &port_string,
        "-j",
        action,
    ]
    .into_iter()
    .chain(if rule.source != "0.0.0.0/0" {
        vec!["-s", rule.source.as_str()]
    } else {
        vec![]
    })
    .chain(vec!["-m", "comment", "--comment", comment])
    .collect();

    run_iptables(&args).await?;
    Ok(true)
}

/// Shorthand: remove ACCEPT rule from INPUT chain.
async fn remove_rule(rule: &FirewallPortRule, comment: &str) -> Result<bool> {
    remove_rule_from_chain("INPUT", rule, "ACCEPT", comment).await
}

// ---------------------------------------------------------------------------
// DOCKER-USER chain helpers
// ---------------------------------------------------------------------------

/// The chain Docker provides for user-defined filtering of container traffic.
const DOCKER_USER_CHAIN: &str = "DOCKER-USER";

/// Check whether the DOCKER-USER chain exists (i.e. Docker is managing iptables).
async fn docker_user_chain_exists() -> bool {
    run_iptables(&["-L", DOCKER_USER_CHAIN, "-n"]).await.is_ok()
}

/// Find the line number of the default RETURN rule in DOCKER-USER, if present.
async fn docker_user_return_line() -> Result<Option<u32>> {
    let output = run_iptables(&["-L", DOCKER_USER_CHAIN, "-n", "--line-numbers"]).await?;
    for line in output.lines() {
        let mut parts = line.split_whitespace();
        let num_str = match parts.next() {
            Some(value) => value,
            None => continue,
        };
        let line_num = match num_str.parse::<u32>() {
            Ok(value) => value,
            Err(_) => continue,
        };
        if let Some(target) = parts.next() {
            if target == "RETURN" {
                return Ok(Some(line_num));
            }
        }
    }
    Ok(None)
}

/// Add DOCKER-USER rules for a private port:
///   1. ACCEPT from the allowed source  (inserted at top)
///   2. DROP   from all others          (inserted before RETURN, acts as default-deny)
///
/// Both rules carry the stacker comment so flush can find them.
async fn add_docker_user_rules(
    rule: &FirewallPortRule,
    comment: &str,
    errors: &mut Vec<CommandError>,
) -> bool {
    let drop_comment = format!("{}-drop", comment);

    // 1. ACCEPT from allowed source
    let accept_exists = rule_exists_in_chain(DOCKER_USER_CHAIN, rule, "ACCEPT", comment)
        .await
        .unwrap_or(false);
    if !accept_exists {
        if let Err(e) = add_rule_to_chain(DOCKER_USER_CHAIN, rule, "ACCEPT", comment).await {
            errors.push(CommandError {
                code: "docker_user_add_failed".into(),
                message: format!(
                    "Failed to add DOCKER-USER ACCEPT for port {}: {}",
                    rule.port, e
                ),
                details: None,
            });
            return false;
        }
    }

    // 2. DROP from all sources for this port (default-deny)
    let drop_rule = FirewallPortRule {
        port: rule.port,
        protocol: rule.protocol.clone(),
        source: "0.0.0.0/0".into(),
        comment: rule.comment.clone(),
    };
    let drop_exists = rule_exists_in_chain(DOCKER_USER_CHAIN, &drop_rule, "DROP", &drop_comment)
        .await
        .unwrap_or(false);
    if !drop_exists {
        let port_string = rule.port.to_string();
        let return_line = match docker_user_return_line().await {
            Ok(value) => value,
            Err(e) => {
                warn!(
                    error = %e,
                    "Failed to locate DOCKER-USER RETURN rule; appending DROP"
                );
                None
            }
        };
        let mut args = Vec::new();
        match return_line {
            Some(line_num) => {
                args.push("-I".to_string());
                args.push(DOCKER_USER_CHAIN.to_string());
                args.push(line_num.to_string());
            }
            None => {
                args.push("-A".to_string());
                args.push(DOCKER_USER_CHAIN.to_string());
            }
        }
        args.extend(
            vec![
                "-p",
                rule.protocol.as_str(),
                "--dport",
                port_string.as_str(),
                "-j",
                "DROP",
                "-m",
                "comment",
                "--comment",
                drop_comment.as_str(),
            ]
            .into_iter()
            .map(str::to_string),
        );
        let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
        if let Err(e) = run_iptables(&args_ref).await {
            errors.push(CommandError {
                code: "docker_user_drop_failed".into(),
                message: format!(
                    "Failed to add DOCKER-USER DROP for port {}: {}",
                    rule.port, e
                ),
                details: None,
            });
            return false;
        }
    }

    info!(
        port = rule.port,
        source = %rule.source,
        "DOCKER-USER rules added (ACCEPT source + DROP default)"
    );
    true
}

/// Remove DOCKER-USER rules for a port (both ACCEPT and DROP).
async fn remove_docker_user_rules(
    rule: &FirewallPortRule,
    comment: &str,
    _errors: &mut Vec<CommandError>,
) {
    let drop_comment = format!("{}-drop", comment);

    // Remove ACCEPT
    if let Err(e) = remove_rule_from_chain(DOCKER_USER_CHAIN, rule, "ACCEPT", comment).await {
        debug!(port = rule.port, error = %e, "Failed to remove DOCKER-USER ACCEPT (may not exist)");
    }

    // Remove DROP
    let drop_rule = FirewallPortRule {
        port: rule.port,
        protocol: rule.protocol.clone(),
        source: "0.0.0.0/0".into(),
        comment: rule.comment.clone(),
    };
    if let Err(e) =
        remove_rule_from_chain(DOCKER_USER_CHAIN, &drop_rule, "DROP", &drop_comment).await
    {
        debug!(port = rule.port, error = %e, "Failed to remove DOCKER-USER DROP (may not exist)");
    }

    // Check: if there are no more stacker ACCEPT rules for this port in DOCKER-USER,
    // don't leave an orphaned DROP. (Already handled above, but log for clarity.)
    info!(port = rule.port, "DOCKER-USER rules removed");
}

/// Flush all stacker-managed rules from the DOCKER-USER chain.
async fn flush_docker_user_chain(errors: &mut Vec<CommandError>) -> u32 {
    if !docker_user_chain_exists().await {
        return 0;
    }

    let list_output = match run_iptables(&["-L", DOCKER_USER_CHAIN, "-n", "--line-numbers"]).await {
        Ok(output) => output,
        Err(e) => {
            errors.push(CommandError {
                code: "docker_user_flush_list_failed".into(),
                message: format!("Failed to list DOCKER-USER for flush: {}", e),
                details: None,
            });
            return 0;
        }
    };

    let mut line_numbers: Vec<u32> = Vec::new();
    for line in list_output.lines() {
        if line.contains(STACKER_COMMENT_PREFIX) {
            if let Some(num_str) = line.split_whitespace().next() {
                if let Ok(num) = num_str.parse::<u32>() {
                    line_numbers.push(num);
                }
            }
        }
    }

    line_numbers.sort_unstable();
    line_numbers.reverse();

    let mut removed: u32 = 0;
    for line_num in &line_numbers {
        match run_iptables(&["-D", DOCKER_USER_CHAIN, &line_num.to_string()]).await {
            Ok(_) => {
                removed += 1;
            }
            Err(e) => {
                errors.push(CommandError {
                    code: "docker_user_flush_failed".into(),
                    message: format!(
                        "Failed to delete DOCKER-USER rule at line {}: {}",
                        line_num, e
                    ),
                    details: None,
                });
            }
        }
    }

    if removed > 0 {
        info!(removed, "Flushed stacker rules from DOCKER-USER");
    }
    removed
}

/// Persist iptables rules to survive reboots.
/// Tries multiple methods depending on the distro.
///
/// **Docker compatibility:** A raw `iptables-save` dumps ALL tables/chains,
/// including Docker-managed ones (DOCKER, DOCKER-ISOLATION-*, nat MASQUERADE,
/// etc.).  Restoring that dump on boot before dockerd starts causes stale NAT
/// entries and broken container networking.  We therefore filter the output of
/// `iptables-save` to strip Docker-owned chains before writing.
async fn persist_rules() -> Result<()> {
    // Try netfilter-persistent first (Debian/Ubuntu with iptables-persistent)
    // netfilter-persistent runs iptables-save internally — same Docker concern,
    // but many Docker-aware setups configure it correctly already.
    if try_command("netfilter-persistent", &["save"]).await.is_ok() {
        info!("Rules persisted via netfilter-persistent");
        return Ok(());
    }

    // Try iptables-save (Docker-filtered) to Debian/Ubuntu path
    if try_persist_to_file("/etc/iptables/rules.v4").await.is_ok() {
        info!("Rules persisted to /etc/iptables/rules.v4");
        return Ok(());
    }

    // Try RHEL/CentOS/Rocky path
    if try_persist_to_file("/etc/sysconfig/iptables").await.is_ok() {
        info!("Rules persisted to /etc/sysconfig/iptables");
        return Ok(());
    }

    bail!("Could not persist iptables rules: no supported persistence method found")
}

async fn try_command(cmd: &str, args: &[&str]) -> Result<()> {
    let output = TokioCommand::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{} failed: {}", cmd, stderr.trim())
    }
}

/// Docker-managed chain names that must NOT be persisted.
/// Docker recreates these on every daemon start; saving them leads to stale /
/// duplicate rules and broken container networking after reboot.
const DOCKER_CHAINS: &[&str] = &[
    "DOCKER",
    "DOCKER-ISOLATION-STAGE-1",
    "DOCKER-ISOLATION-STAGE-2",
    "DOCKER-USER",
];

/// Run `iptables-save`, strip Docker-managed chains/rules, and write the
/// filtered output to `path`.
async fn try_persist_to_file(path: &str) -> Result<()> {
    const ALLOWED_PATHS: &[&str] = &["/etc/iptables/rules.v4", "/etc/sysconfig/iptables"];
    if !ALLOWED_PATHS.contains(&path) {
        bail!("Refusing to write to unexpected path: {}", path);
    }

    let save_output = TokioCommand::new("iptables-save")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    if !save_output.status.success() {
        let stderr = String::from_utf8_lossy(&save_output.stderr);
        bail!("iptables-save failed: {}", stderr.trim());
    }

    let raw = String::from_utf8_lossy(&save_output.stdout);
    let filtered = filter_docker_rules(&raw);

    tokio::fs::write(path, filtered.as_bytes())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to write {}: {}", path, e))?;

    Ok(())
}

/// Remove Docker-managed chains and rules from `iptables-save` output.
///
/// `iptables-save` emits lines like:
///   `:DOCKER - [0:0]`                              ← chain declaration
///   `-A FORWARD -j DOCKER-USER`                    ← jump into Docker chain
///   `-A DOCKER -d 172.17.0.2/32 ! -i docker0 ...` ← rule inside Docker chain
///   `-A DOCKER-ISOLATION-STAGE-1 ...`
///   `-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE` ← Docker NAT
///
/// We also strip the entire `*nat` table when it only contains Docker-generated
/// MASQUERADE / DNAT rules, because Docker recreates them from scratch.
fn filter_docker_rules(dump: &str) -> String {
    let mut output = String::with_capacity(dump.len());
    let mut skip_table = false; // true while inside a table we want to drop entirely
    let mut in_nat_table = false;
    let mut nat_lines: Vec<&str> = Vec::new();

    for line in dump.lines() {
        // Detect table boundaries
        if line.starts_with('*') {
            // Starting a new table
            if line == "*nat" {
                in_nat_table = true;
                nat_lines.clear();
                nat_lines.push(line);
                continue;
            }
            in_nat_table = false;
            skip_table = false;
        }

        // Accumulate nat table lines for deferred decision
        if in_nat_table {
            nat_lines.push(line);
            if line == "COMMIT" {
                // Decide: keep nat table only if it has non-Docker rules
                let has_non_docker = nat_lines.iter().any(|l| {
                    if l.starts_with("-A") {
                        !is_docker_rule(l)
                    } else {
                        false
                    }
                });
                if has_non_docker {
                    // Keep nat table but strip Docker rules within it
                    for nat_line in &nat_lines {
                        if nat_line.starts_with("-A") && is_docker_rule(nat_line) {
                            continue;
                        }
                        if nat_line.starts_with(':') && is_docker_chain_decl(nat_line) {
                            continue;
                        }
                        output.push_str(nat_line);
                        output.push('\n');
                    }
                }
                // else: entire nat table is Docker-only, drop it
                in_nat_table = false;
            }
            continue;
        }

        if skip_table {
            if line == "COMMIT" {
                skip_table = false;
            }
            continue;
        }

        // Filter chain declarations for Docker chains  (:DOCKER - [0:0])
        if line.starts_with(':') && is_docker_chain_decl(line) {
            continue;
        }

        // Filter rules that reference Docker chains (-A DOCKER ..., -A FORWARD -j DOCKER-USER)
        if line.starts_with("-A") && is_docker_rule(line) {
            continue;
        }

        output.push_str(line);
        output.push('\n');
    }

    output
}

/// Check if a chain declaration line (`:NAME ...`) declares a Docker chain.
fn is_docker_chain_decl(line: &str) -> bool {
    let name = line
        .trim_start_matches(':')
        .split_whitespace()
        .next()
        .unwrap_or("");
    DOCKER_CHAINS.contains(&name)
}

/// Check if a rule line (`-A ...`) belongs to or targets a Docker chain.
fn is_docker_rule(line: &str) -> bool {
    // "-A DOCKER ..." or "-A DOCKER-ISOLATION-STAGE-1 ..." (rule inside Docker chain)
    // "-A FORWARD -j DOCKER-USER" (jump into Docker chain)
    // "-A POSTROUTING -s 172.17.0.0/16 ... -j MASQUERADE" (Docker NAT masquerade)
    let parts: Vec<&str> = line.split_whitespace().collect();

    // Rule is inside a Docker chain (second token is the chain name)
    if parts.len() >= 2 && DOCKER_CHAINS.contains(&parts[1]) {
        return true;
    }

    // Rule jumps into a Docker chain (-j DOCKER, -j DOCKER-USER, etc.)
    for (i, part) in parts.iter().enumerate() {
        if *part == "-j" || *part == "--jump" {
            if let Some(target) = parts.get(i + 1) {
                if DOCKER_CHAINS.contains(target) {
                    return true;
                }
            }
        }
    }

    // Docker interface references in POSTROUTING/PREROUTING (docker0, br-*)
    if line.contains("docker0") || line.contains("br-") {
        return true;
    }

    false
}

// ---------------------------------------------------------------------------
// Status determination
// ---------------------------------------------------------------------------

fn determine_status(rules: &[FirewallRuleResult], errors: &[CommandError]) -> String {
    if errors.is_empty() && rules.iter().all(|r| r.applied) {
        // All rules applied successfully, no errors: overall command is a success.
        "success".to_string()
    } else if rules.iter().any(|r| r.applied) {
        // At least one rule applied, but not all or there were errors: still report
        // a successful command execution at the outer level (`CommandResult.status`),
        // while callers can encode "partial" details inside the payload.
        "success".to_string()
    } else if rules.is_empty() && errors.is_empty() {
        // Nothing to do and no errors: treat as a successful no-op.
        "success".to_string()
    } else {
        // No rules applied and there were errors: overall failure.
        "failed".to_string()
    }
}

fn map_command_status(detailed_status: &str) -> String {
    if detailed_status == "failed" {
        "failed".to_string()
    } else {
        "success".to_string()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_agent_cmd() -> AgentCommand {
        AgentCommand {
            id: "test-id".into(),
            command_id: "cmd-123".into(),
            name: "configure_firewall".into(),
            params: serde_json::json!({}),
            deployment_hash: Some("hash-abc".into()),
            app_code: Some("nginx".into()),
        }
    }

    #[test]
    fn test_normalize_trims_fields() {
        let cmd = ConfigureFirewallCommand {
            deployment_hash: " abc123 ".into(),
            app_code: Some(" nginx ".into()),
            action: "  ADD ".into(),
            public_ports: vec![FirewallPortRule {
                port: 80,
                protocol: " TCP ".into(),
                source: " 0.0.0.0/0 ".into(),
                comment: Some("HTTP".into()),
            }],
            private_ports: vec![],
            persist: true,
        };

        let normalized = cmd.normalize();
        assert_eq!(normalized.deployment_hash, "abc123");
        assert_eq!(normalized.app_code.as_deref(), Some("nginx"));
        assert_eq!(normalized.action, "add");
        assert_eq!(normalized.public_ports[0].protocol, "tcp");
        assert_eq!(normalized.public_ports[0].source, "0.0.0.0/0");
    }

    #[test]
    fn test_validate_valid_add() {
        let cmd = ConfigureFirewallCommand {
            deployment_hash: "hash".into(),
            app_code: Some("nginx".into()),
            action: "add".into(),
            public_ports: vec![FirewallPortRule {
                port: 80,
                protocol: "tcp".into(),
                source: "0.0.0.0/0".into(),
                comment: Some("HTTP".into()),
            }],
            private_ports: vec![],
            persist: true,
        };
        assert!(cmd.validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_action() {
        let cmd = ConfigureFirewallCommand {
            deployment_hash: "hash".into(),
            app_code: Some("nginx".into()),
            action: "destroy".into(),
            public_ports: vec![],
            private_ports: vec![],
            persist: true,
        };
        let err = cmd.validate().unwrap_err();
        assert!(err.to_string().contains("action must be one of"));
    }

    #[test]
    fn test_validate_add_needs_ports() {
        let cmd = ConfigureFirewallCommand {
            deployment_hash: "hash".into(),
            app_code: Some("nginx".into()),
            action: "add".into(),
            public_ports: vec![],
            private_ports: vec![],
            persist: true,
        };
        let err = cmd.validate().unwrap_err();
        assert!(err.to_string().contains("requires at least one port rule"));
    }

    #[test]
    fn test_validate_list_no_ports_needed() {
        let cmd = ConfigureFirewallCommand {
            deployment_hash: "hash".into(),
            app_code: Some("nginx".into()),
            action: "list".into(),
            public_ports: vec![],
            private_ports: vec![],
            persist: false,
        };
        assert!(cmd.validate().is_ok());
    }

    #[test]
    fn test_validate_flush_no_ports_needed() {
        let cmd = ConfigureFirewallCommand {
            deployment_hash: String::new(),
            app_code: None,
            action: "flush".into(),
            public_ports: vec![],
            private_ports: vec![],
            persist: true,
        };
        assert!(cmd.validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_protocol() {
        let cmd = ConfigureFirewallCommand {
            deployment_hash: "hash".into(),
            app_code: Some("nginx".into()),
            action: "add".into(),
            public_ports: vec![FirewallPortRule {
                port: 80,
                protocol: "icmp".into(),
                source: "0.0.0.0/0".into(),
                comment: None,
            }],
            private_ports: vec![],
            persist: true,
        };
        let err = cmd.validate().unwrap_err();
        assert!(err.to_string().contains("protocol must be tcp or udp"));
    }

    #[test]
    fn test_validate_zero_port() {
        let cmd = ConfigureFirewallCommand {
            deployment_hash: "hash".into(),
            app_code: Some("nginx".into()),
            action: "add".into(),
            public_ports: vec![FirewallPortRule {
                port: 0,
                protocol: "tcp".into(),
                source: "0.0.0.0/0".into(),
                comment: None,
            }],
            private_ports: vec![],
            persist: true,
        };
        let err = cmd.validate().unwrap_err();
        assert!(err.to_string().contains("port must be between 1 and 65535"));
    }

    #[test]
    fn test_validate_source_cidr() {
        assert!(validate_source_cidr("0.0.0.0/0").is_ok());
        assert!(validate_source_cidr("10.0.0.0/8").is_ok());
        assert!(validate_source_cidr("192.168.1.1").is_ok());
        assert!(validate_source_cidr("192.168.1.0/24").is_ok());
        assert!(validate_source_cidr("10.0.0.0/64").is_err());
        assert!(validate_source_cidr("2001:db8::/64").is_ok());
        assert!(validate_source_cidr("2001:db8::/129").is_err());
        assert!(validate_source_cidr("not_an_ip").is_err());
        assert!(validate_source_cidr("999.999.999.999").is_err());
    }

    #[test]
    fn test_build_comment() {
        let rule = FirewallPortRule {
            port: 80,
            protocol: "tcp".into(),
            source: "0.0.0.0/0".into(),
            comment: Some("HTTP".into()),
        };
        assert_eq!(build_comment("nginx", &rule), "stacker:nginx:HTTP");
    }

    #[test]
    fn test_build_comment_no_description() {
        let rule = FirewallPortRule {
            port: 5432,
            protocol: "tcp".into(),
            source: "10.0.0.0/8".into(),
            comment: None,
        };
        assert_eq!(build_comment("postgres", &rule), "stacker:postgres:tcp");
    }

    #[test]
    fn test_with_command_context_fills_missing() {
        let agent_cmd = make_agent_cmd();
        let cmd = ConfigureFirewallCommand {
            deployment_hash: String::new(),
            app_code: None,
            action: "list".into(),
            public_ports: vec![],
            private_ports: vec![],
            persist: false,
        };
        let cmd = cmd.with_command_context(&agent_cmd);
        assert_eq!(cmd.deployment_hash, "hash-abc");
        assert_eq!(cmd.app_code.as_deref(), Some("nginx"));
    }

    #[test]
    fn test_with_command_context_preserves_existing() {
        let agent_cmd = make_agent_cmd();
        let cmd = ConfigureFirewallCommand {
            deployment_hash: "my-hash".into(),
            app_code: Some("redis".into()),
            action: "list".into(),
            public_ports: vec![],
            private_ports: vec![],
            persist: false,
        };
        let cmd = cmd.with_command_context(&agent_cmd);
        assert_eq!(cmd.deployment_hash, "my-hash");
        assert_eq!(cmd.app_code.as_deref(), Some("redis"));
    }

    #[test]
    fn test_determine_status_all_ok() {
        let rules = vec![
            FirewallRuleResult {
                port: 80,
                protocol: "tcp".into(),
                source: "0.0.0.0/0".into(),
                applied: true,
                message: None,
            },
            FirewallRuleResult {
                port: 443,
                protocol: "tcp".into(),
                source: "0.0.0.0/0".into(),
                applied: true,
                message: None,
            },
        ];
        assert_eq!(determine_status(&rules, &[]), "ok");
    }

    #[test]
    fn test_determine_status_partial() {
        let rules = vec![
            FirewallRuleResult {
                port: 80,
                protocol: "tcp".into(),
                source: "0.0.0.0/0".into(),
                applied: true,
                message: None,
            },
            FirewallRuleResult {
                port: 443,
                protocol: "tcp".into(),
                source: "0.0.0.0/0".into(),
                applied: false,
                message: Some("err".into()),
            },
        ];
        let errors = vec![CommandError {
            code: "x".into(),
            message: "y".into(),
            details: None,
        }];
        assert_eq!(determine_status(&rules, &errors), "partial_success");
    }

    #[test]
    fn test_determine_status_all_failed() {
        let rules = vec![FirewallRuleResult {
            port: 80,
            protocol: "tcp".into(),
            source: "0.0.0.0/0".into(),
            applied: false,
            message: Some("err".into()),
        }];
        let errors = vec![CommandError {
            code: "x".into(),
            message: "y".into(),
            details: None,
        }];
        assert_eq!(determine_status(&rules, &errors), "failed");
    }

    #[test]
    fn test_deserialize_from_json() {
        let json = serde_json::json!({
            "action": "add",
            "app_code": "nginx",
            "public_ports": [
                {"port": 80, "protocol": "tcp", "source": "0.0.0.0/0", "comment": "HTTP"},
                {"port": 443, "protocol": "tcp", "source": "0.0.0.0/0", "comment": "HTTPS"}
            ],
            "private_ports": [
                {"port": 5432, "protocol": "tcp", "source": "10.0.0.0/8", "comment": "PostgreSQL"}
            ],
            "persist": true
        });

        let cmd: ConfigureFirewallCommand = serde_json::from_value(json).unwrap();
        assert_eq!(cmd.action, "add");
        assert_eq!(cmd.public_ports.len(), 2);
        assert_eq!(cmd.private_ports.len(), 1);
        assert_eq!(cmd.private_ports[0].port, 5432);
        assert_eq!(cmd.private_ports[0].source, "10.0.0.0/8");
        assert!(cmd.persist);
    }

    #[test]
    fn test_deserialize_minimal_json() {
        let json = serde_json::json!({
            "action": "list"
        });

        let cmd: ConfigureFirewallCommand = serde_json::from_value(json).unwrap();
        assert_eq!(cmd.action, "list");
        assert!(cmd.public_ports.is_empty());
        assert!(cmd.private_ports.is_empty());
        assert!(cmd.persist); // defaults to true
    }

    // -----------------------------------------------------------------------
    // Docker-filtering tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_filter_docker_rules_preserves_user_input_rules() {
        let dump = "\
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 80 -j ACCEPT -m comment --comment \"stacker:nginx:HTTP\"
COMMIT
";
        let filtered = filter_docker_rules(dump);
        assert!(filtered.contains("-A INPUT -p tcp --dport 22"));
        assert!(filtered.contains("stacker:nginx:HTTP"));
        assert!(filtered.contains(":INPUT ACCEPT"));
    }

    #[test]
    fn test_filter_docker_rules_strips_docker_chains() {
        let dump = "\
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:DOCKER - [0:0]
:DOCKER-ISOLATION-STAGE-1 - [0:0]
:DOCKER-ISOLATION-STAGE-2 - [0:0]
:DOCKER-USER - [0:0]
-A INPUT -p tcp --dport 80 -j ACCEPT
-A FORWARD -j DOCKER-USER
-A FORWARD -j DOCKER-ISOLATION-STAGE-1
-A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -o docker0 -j DOCKER
-A DOCKER -d 172.17.0.2/32 ! -i docker0 -o docker0 -p tcp -m tcp --dport 8080 -j ACCEPT
-A DOCKER-ISOLATION-STAGE-1 -i docker0 ! -o docker0 -j DOCKER-ISOLATION-STAGE-2
-A DOCKER-ISOLATION-STAGE-2 -o docker0 -j DROP
-A DOCKER-USER -j RETURN
COMMIT
";
        let filtered = filter_docker_rules(dump);
        // User rule kept
        assert!(filtered.contains("-A INPUT -p tcp --dport 80"));
        // Docker chains stripped
        assert!(!filtered.contains(":DOCKER "));
        assert!(!filtered.contains(":DOCKER-ISOLATION"));
        assert!(!filtered.contains(":DOCKER-USER"));
        // Docker rules stripped
        assert!(!filtered.contains("-A DOCKER "));
        assert!(!filtered.contains("-A DOCKER-ISOLATION"));
        assert!(!filtered.contains("-A DOCKER-USER"));
        assert!(!filtered.contains("-j DOCKER-USER"));
        assert!(!filtered.contains("-j DOCKER-ISOLATION"));
        // docker0 interface rules stripped
        assert!(!filtered.contains("docker0"));
    }

    #[test]
    fn test_filter_docker_rules_strips_docker_only_nat_table() {
        let dump = "\
*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 443 -j ACCEPT
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:DOCKER - [0:0]
-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
-A DOCKER -i docker0 -j RETURN
COMMIT
";
        let filtered = filter_docker_rules(dump);
        // filter table kept
        assert!(filtered.contains("-A INPUT -p tcp --dport 443"));
        // Docker-only nat table entirely dropped
        assert!(!filtered.contains("*nat"));
        assert!(!filtered.contains("MASQUERADE"));
    }

    #[test]
    fn test_filter_docker_rules_keeps_user_nat_rules() {
        let dump = "\
*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:DOCKER - [0:0]
-A PREROUTING -p tcp --dport 8080 -j REDIRECT --to-port 80
-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
-A DOCKER -i docker0 -j RETURN
COMMIT
";
        let filtered = filter_docker_rules(dump);
        // User NAT rule kept
        assert!(filtered.contains("-A PREROUTING -p tcp --dport 8080 -j REDIRECT --to-port 80"));
        // Docker NAT rules stripped
        assert!(!filtered.contains("MASQUERADE"));
        assert!(!filtered.contains(":DOCKER"));
    }

    #[test]
    fn test_is_docker_chain_decl() {
        assert!(is_docker_chain_decl(":DOCKER - [0:0]"));
        assert!(is_docker_chain_decl(":DOCKER-ISOLATION-STAGE-1 - [0:0]"));
        assert!(is_docker_chain_decl(":DOCKER-USER - [0:0]"));
        assert!(!is_docker_chain_decl(":INPUT ACCEPT [0:0]"));
        assert!(!is_docker_chain_decl(":FORWARD DROP [0:0]"));
    }

    #[test]
    fn test_is_docker_rule() {
        assert!(is_docker_rule(
            "-A DOCKER -d 172.17.0.2/32 -p tcp --dport 80 -j ACCEPT"
        ));
        assert!(is_docker_rule("-A FORWARD -j DOCKER-USER"));
        assert!(is_docker_rule("-A FORWARD -j DOCKER-ISOLATION-STAGE-1"));
        assert!(is_docker_rule("-A FORWARD -o docker0 -j ACCEPT"));
        assert!(is_docker_rule("-A DOCKER-USER -j RETURN"));
        assert!(!is_docker_rule("-A INPUT -p tcp --dport 80 -j ACCEPT"));
        assert!(!is_docker_rule(
            "-A INPUT -p tcp --dport 80 -j ACCEPT -m comment --comment \"stacker:nginx:HTTP\""
        ));
    }

    // -----------------------------------------------------------------------
    // Protected services & policy tests
    // -----------------------------------------------------------------------

    fn default_policy() -> FirewallPolicy {
        FirewallPolicy::default()
    }

    #[test]
    fn test_is_protected_ssh() {
        let policy = default_policy();
        let reason = is_protected(22, "tcp", &policy);
        assert!(reason.is_some());
        assert_eq!(reason.unwrap(), "SSH");
    }

    #[test]
    fn test_is_protected_dns_tcp() {
        let policy = default_policy();
        assert!(is_protected(53, "tcp", &policy).is_some());
    }

    #[test]
    fn test_is_protected_dns_udp() {
        let policy = default_policy();
        assert!(is_protected(53, "udp", &policy).is_some());
    }

    #[test]
    fn test_is_protected_dhcp() {
        let policy = default_policy();
        let reason = is_protected(68, "udp", &policy);
        assert!(reason.is_some());
        assert_eq!(reason.unwrap(), "DHCP client");
    }

    #[test]
    fn test_is_protected_ntp() {
        let policy = default_policy();
        let reason = is_protected(123, "udp", &policy);
        assert!(reason.is_some());
        assert_eq!(reason.unwrap(), "NTP");
    }

    #[test]
    fn test_is_protected_ntp_tcp_not_protected() {
        // NTP is only protected on UDP
        let policy = default_policy();
        assert!(is_protected(123, "tcp", &policy).is_none());
    }

    #[test]
    fn test_is_protected_regular_port() {
        let policy = default_policy();
        assert!(is_protected(80, "tcp", &policy).is_none());
        assert!(is_protected(443, "tcp", &policy).is_none());
        assert!(is_protected(8080, "tcp", &policy).is_none());
    }

    #[test]
    fn test_is_protected_api_port() {
        let policy = FirewallPolicy {
            api_port: Some(5000),
            ..Default::default()
        };
        let reason = is_protected(5000, "tcp", &policy);
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("API port"));
    }

    #[test]
    fn test_is_protected_extra_ports() {
        let policy = FirewallPolicy {
            extra_protected_ports: vec![2222, 8443],
            ..Default::default()
        };
        assert!(is_protected(2222, "tcp", &policy).is_some());
        assert!(is_protected(8443, "tcp", &policy).is_some());
        assert!(is_protected(9999, "tcp", &policy).is_none());
    }

    #[test]
    fn test_check_allowed_no_whitelist() {
        let policy = default_policy();
        // No allowed_ports = everything allowed
        assert!(check_allowed(80, &policy).is_ok());
        assert!(check_allowed(9999, &policy).is_ok());
    }

    #[test]
    fn test_check_allowed_whitelist_allows() {
        let policy = FirewallPolicy {
            allowed_ports: Some(vec![80, 443, 8080]),
            ..Default::default()
        };
        assert!(check_allowed(80, &policy).is_ok());
        assert!(check_allowed(443, &policy).is_ok());
        assert!(check_allowed(8080, &policy).is_ok());
    }

    #[test]
    fn test_check_allowed_whitelist_rejects() {
        let policy = FirewallPolicy {
            allowed_ports: Some(vec![80, 443]),
            ..Default::default()
        };
        let result = check_allowed(8080, &policy);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in the allowed ports"));
    }

    // -----------------------------------------------------------------------
    // Rate limiter tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let limiter = FirewallRateLimiter::new();
        for _ in 0..FIREWALL_RATE_LIMIT {
            assert!(limiter.allow(), "Should allow within limit");
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let limiter = FirewallRateLimiter::new();
        // Exhaust the limit
        for _ in 0..FIREWALL_RATE_LIMIT {
            assert!(limiter.allow());
        }
        // 11th should be blocked
        assert!(!limiter.allow(), "Should block over limit");
    }

    // -----------------------------------------------------------------------
    // FirewallPolicy::from_config tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_policy_from_config_no_firewall_section() {
        let config = crate::agent::config::Config {
            domain: None,
            subdomains: None,
            apps_info: None,
            reqdata: crate::agent::config::ReqData {
                email: "test@test.com".into(),
            },
            ssl: None,
            compose_agent_enabled: false,
            control_plane: None,
            firewall: None,
        };
        let policy = FirewallPolicy::from_config(&config, Some(5000));
        assert!(policy.extra_protected_ports.is_empty());
        assert!(policy.allowed_ports.is_none());
        assert_eq!(policy.api_port, Some(5000));
    }

    #[test]
    fn test_policy_from_config_with_firewall_section() {
        use crate::agent::config::FirewallConfig;
        let config = crate::agent::config::Config {
            domain: None,
            subdomains: None,
            apps_info: None,
            reqdata: crate::agent::config::ReqData {
                email: "test@test.com".into(),
            },
            ssl: None,
            compose_agent_enabled: false,
            control_plane: None,
            firewall: Some(FirewallConfig {
                allowed_ports: Some(vec![80, 443]),
                extra_protected_ports: vec![2222],
            }),
        };
        let policy = FirewallPolicy::from_config(&config, None);
        assert_eq!(policy.extra_protected_ports, vec![2222]);
        assert_eq!(policy.allowed_ports, Some(vec![80, 443]));
        assert_eq!(policy.api_port, None);
    }
}
