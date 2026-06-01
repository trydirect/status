use crate::cli::progress;
use crate::cli::runtime::CliRuntime;
use crate::console::commands::CallableTrait;
use std::fmt::Write as _;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// list projects
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// `stacker list projects [--json]`
///
/// Lists all projects on the Stacker server for the authenticated user.
pub struct ListProjectsCommand {
    pub json: bool,
}

impl ListProjectsCommand {
    pub fn new(json: bool) -> Self {
        Self { json }
    }
}

impl CallableTrait for ListProjectsCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let json = self.json;
        let ctx = CliRuntime::new("list projects")?;

        ctx.block_on(async {
            let projects = ctx.client.list_projects().await?;

            if projects.is_empty() {
                eprintln!("No projects found.");
                return Ok(());
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&projects)?);
            } else {
                // Table header
                println!(
                    "{:<6} {:<30} {:<26} {:<26}",
                    "ID", "NAME", "CREATED", "UPDATED"
                );
                println!("{}", "─".repeat(90));

                for p in &projects {
                    println!(
                        "{:<6} {:<30} {:<26} {:<26}",
                        p.id,
                        truncate(&p.name, 28),
                        &p.created_at,
                        &p.updated_at,
                    );
                }

                eprintln!("\n{} project(s) total.", projects.len());
            }

            Ok(())
        })
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// list servers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// `stacker list servers [--json]`
///
/// Lists all servers on the Stacker server for the authenticated user.
pub struct ListServersCommand {
    pub json: bool,
}

impl ListServersCommand {
    pub fn new(json: bool) -> Self {
        Self { json }
    }
}

impl CallableTrait for ListServersCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let json = self.json;
        let ctx = CliRuntime::new("list servers")?;

        ctx.block_on(async {
            let servers = ctx.client.list_servers().await?;

            if servers.is_empty() {
                eprintln!("No servers found.");
                return Ok(());
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&servers)?);
            } else {
                println!(
                    "{:<6} {:<20} {:<16} {:<10} {:<10} {:<10} {:<12} {:<10}",
                    "ID", "NAME", "IP", "CLOUD", "REGION", "SIZE", "KEY STATUS", "MODE"
                );
                println!("{}", "─".repeat(100));

                for s in &servers {
                    println!(
                        "{:<6} {:<20} {:<16} {:<10} {:<10} {:<10} {:<12} {:<10}",
                        s.id,
                        truncate(&s.name.clone().unwrap_or_else(|| "-".to_string()), 18),
                        s.srv_ip.clone().unwrap_or_else(|| "-".to_string()),
                        s.cloud.clone().unwrap_or_else(|| "-".to_string()),
                        truncate(&s.region.clone().unwrap_or_else(|| "-".to_string()), 8),
                        truncate(&s.server.clone().unwrap_or_else(|| "-".to_string()), 8),
                        &s.key_status,
                        &s.connection_mode,
                    );
                }

                eprintln!("\n{} server(s) total.", servers.len());
            }

            Ok(())
        })
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// list deployments
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// `stacker list deployments [--project <id>] [--limit <n>] [--json]`
///
/// Lists deployments for the authenticated user.
pub struct ListDeploymentsCommand {
    pub json: bool,
    pub project_id: Option<i32>,
    pub limit: Option<i64>,
}

impl ListDeploymentsCommand {
    pub fn new(json: bool, project_id: Option<i32>, limit: Option<i64>) -> Self {
        Self {
            json,
            project_id,
            limit,
        }
    }
}

impl CallableTrait for ListDeploymentsCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let json = self.json;
        let ctx = CliRuntime::new("list deployments")?;

        let project_id = self.project_id;
        let limit = self.limit;

        ctx.block_on(async {
            let deployments = ctx.client.list_deployments(project_id, limit).await?;

            if deployments.is_empty() {
                eprintln!("No deployments found.");
                return Ok(());
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&deployments)?);
            } else {
                print!("{}", render_deployments_table(&deployments));
                eprintln!("\n{} deployment(s) total.", deployments.len());
            }

            Ok(())
        })
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// list ssh-keys
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// `stacker list ssh-keys [--json]`
///
/// Lists all servers and their SSH key status. SSH keys are managed
/// per-server, so this command shows each server's key state.
pub struct ListSshKeysCommand {
    pub json: bool,
}

impl ListSshKeysCommand {
    pub fn new(json: bool) -> Self {
        Self { json }
    }
}

impl CallableTrait for ListSshKeysCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let json = self.json;
        let ctx = CliRuntime::new("list ssh-keys")?;

        ctx.block_on(async {
            let servers = ctx.client.list_servers().await?;

            if servers.is_empty() {
                eprintln!("No servers found (SSH keys are managed per-server).");
                return Ok(());
            }

            if json {
                // Output a focused JSON view with just SSH key info
                let ssh_info: Vec<serde_json::Value> = servers
                    .iter()
                    .map(|s| {
                        serde_json::json!({
                            "server_id": s.id,
                            "server_name": s.name,
                            "srv_ip": s.srv_ip,
                            "ssh_port": s.ssh_port,
                            "ssh_user": s.ssh_user,
                            "key_status": s.key_status,
                            "connection_mode": s.connection_mode,
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&ssh_info)?);
            } else {
                println!(
                    "{:<6} {:<20} {:<16} {:<8} {:<10} {:<12} {:<10}",
                    "ID", "SERVER", "IP", "PORT", "USER", "KEY STATUS", "MODE"
                );
                println!("{}", "─".repeat(84));

                let mut active_count = 0;
                for s in &servers {
                    let status_icon = match s.key_status.as_str() {
                        "active" => {
                            active_count += 1;
                            "✓ active"
                        }
                        "pending" => "◷ pending",
                        "failed" => "✗ failed",
                        _ => "  none",
                    };
                    println!(
                        "{:<6} {:<20} {:<16} {:<8} {:<10} {:<12} {:<10}",
                        s.id,
                        truncate(&s.name.clone().unwrap_or_else(|| "-".to_string()), 18),
                        s.srv_ip.clone().unwrap_or_else(|| "-".to_string()),
                        s.ssh_port
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "22".to_string()),
                        s.ssh_user.clone().unwrap_or_else(|| "root".to_string()),
                        status_icon,
                        &s.connection_mode,
                    );
                }

                eprintln!(
                    "\n{} server(s), {} with active SSH keys.",
                    servers.len(),
                    active_count
                );
            }

            Ok(())
        })
    }
}

// ── helpers ──────────────────────────────────────────

/// Truncate a string to `max_len` characters, adding "…" if truncated.
fn truncate(s: &str, max_len: usize) -> String {
    if s.chars().count() > max_len {
        let truncated: String = s.chars().take(max_len.saturating_sub(1)).collect();
        format!("{}…", truncated)
    } else {
        s.to_string()
    }
}

fn render_deployments_table(
    deployments: &[crate::cli::stacker_client::DeploymentStatusInfo],
) -> String {
    let mut table = String::new();
    let _ = writeln!(
        &mut table,
        "{:<6} {:<10} {:<16} {:<47} {:<20}",
        "ID", "PROJECT", "STATUS", "DEPLOYMENT HASH", "CREATED"
    );
    let _ = writeln!(&mut table, "{}", "─".repeat(104));

    for deployment in deployments {
        let _ = writeln!(
            &mut table,
            "{:<6} {:<10} {:<16} {:<47} {:<20}",
            deployment.id,
            deployment.project_id,
            format!(
                "{} {}",
                progress::status_icon(&deployment.status),
                deployment.status
            ),
            deployment.deployment_hash,
            deployment.created_at,
        );
    }

    table
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// list clouds
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// `stacker list clouds [--json]`
///
/// Lists all saved cloud credentials for the authenticated user.
/// Shows ID, name, and provider. Tokens are masked for security.
pub struct ListCloudsCommand {
    pub json: bool,
}

impl ListCloudsCommand {
    pub fn new(json: bool) -> Self {
        Self { json }
    }
}

impl CallableTrait for ListCloudsCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let json = self.json;
        let ctx = CliRuntime::new("list clouds")?;

        ctx.block_on(async {
            let clouds = ctx.client.list_clouds().await?;

            if clouds.is_empty() {
                eprintln!("No saved cloud credentials found.");
                eprintln!(
                    "Cloud credentials are saved automatically when you deploy with env vars,"
                );
                eprintln!(
                    "or via: stacker deploy --target cloud (with HCLOUD_TOKEN, DIGITALOCEAN_TOKEN, LINODE_TOKEN, VULTR_API_KEY, or AWS credentials exported)."
                );
                return Ok(());
            }

            if json {
                // Mask sensitive fields for JSON output
                let safe: Vec<serde_json::Value> = clouds
                    .iter()
                    .map(|c| {
                        serde_json::json!({
                            "id": c.id,
                            "name": c.name,
                            "provider": c.provider,
                            "has_token": c.cloud_token.is_some(),
                            "has_key": c.cloud_key.is_some(),
                            "has_secret": c.cloud_secret.is_some(),
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&safe)?);
            } else {
                println!(
                    "{:<6} {:<24} {:<12} {:<10} {:<10} {:<10}",
                    "ID", "NAME", "PROVIDER", "TOKEN", "KEY", "SECRET"
                );
                println!("{}", "─".repeat(74));

                for c in &clouds {
                    let has_token = if c.cloud_token.is_some() { "✓" } else { "-" };
                    let has_key = if c.cloud_key.is_some() { "✓" } else { "-" };
                    let secret_indicator = "*";
                    println!(
                        "{:<6} {:<24} {:<12} {:<10} {:<10} {:<10}",
                        c.id,
                        truncate(&c.name, 22),
                        &c.provider,
                        has_token,
                        has_key,
                        secret_indicator,
                    );
                }

                eprintln!("\n{} cloud credential(s) total.", clouds.len());
                eprintln!("Use with: stacker deploy --key <NAME> or --key-id <ID>");
            }

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::stacker_client::DeploymentStatusInfo;

    #[test]
    fn render_deployments_table_keeps_full_status_and_timestamp() {
        let deployments = vec![DeploymentStatusInfo {
            id: 114,
            project_id: 229,
            deployment_hash: "deployment_5cc15f7d-8c87-464a-a7c5-ee6116201f22".to_string(),
            status: "completed".to_string(),
            status_message: Some("done".to_string()),
            created_at: "2026-05-06 00:35:31".to_string(),
            updated_at: "2026-05-06 00:36:31".to_string(),
        }];

        let rendered = render_deployments_table(&deployments);

        assert!(rendered.contains("✓ completed"));
        assert!(rendered.contains("2026-05-06 00:35:31"));
        assert!(rendered.contains("deployment_5cc15f7d-8c87-464a-a7c5-ee6116201f22"));
        assert!(!rendered.contains("comple…"));
        assert!(!rendered.contains("2026-05-0…"));
    }
}
