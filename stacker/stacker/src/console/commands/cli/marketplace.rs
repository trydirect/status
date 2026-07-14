use crate::cli::credentials::CredentialsManager;
use crate::cli::error::CliError;
use crate::cli::stacker_client::StackerClient;
use crate::console::commands::CallableTrait;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// marketplace status
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// `stacker marketplace status [name] [--json]`
///
/// Check submission status for the user's marketplace templates.
/// If a name is provided, shows detail for that template only.
pub struct MarketplaceStatusCommand {
    name: Option<String>,
    json: bool,
}

impl MarketplaceStatusCommand {
    pub fn new(name: Option<String>, json: bool) -> Self {
        Self { name, json }
    }
}

impl CallableTrait for MarketplaceStatusCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let json = self.json;

        let cred_manager = CredentialsManager::with_default_store();
        let creds = cred_manager.require_valid_token("marketplace status")?;
        let base_url = crate::cli::install_runner::normalize_stacker_server_url(
            crate::cli::stacker_client::DEFAULT_STACKER_URL,
        );

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                CliError::ConfigValidation(format!("Failed to create async runtime: {}", e))
            })?;

        let name = self.name.clone();

        rt.block_on(async {
            let client = StackerClient::new(&base_url, &creds.access_token);
            let templates = client.marketplace_list_mine().await?;

            if let Some(ref name) = name {
                // Filter to matching template
                let template = templates
                    .iter()
                    .find(|t| t.name == *name || t.slug == *name);
                match template {
                    Some(t) => {
                        if json {
                            println!("{}", serde_json::to_string_pretty(&t)?);
                        } else {
                            println!(
                                "Stack:      {} v{}",
                                t.name,
                                t.version.as_deref().unwrap_or("?")
                            );
                            println!("Status:     {}", t.status);
                            println!(
                                "Submitted:  {}",
                                t.created_at.as_deref().unwrap_or("\u{2014}")
                            );
                            if let Some(ref reason) = t.review_reason {
                                println!("Reason:     {}", reason);
                            }
                        }
                    }
                    None => {
                        eprintln!("No submission found for '{}'", name);
                        std::process::exit(1);
                    }
                }
            } else {
                if json {
                    println!("{}", serde_json::to_string_pretty(&templates)?);
                } else {
                    if templates.is_empty() {
                        println!("No marketplace submissions found.");
                        println!("Submit your first stack with: stacker submit");
                        return Ok(());
                    }
                    println!(
                        "{:<25} {:<10} {:<15} {:<20}",
                        "STACK", "VERSION", "STATUS", "SUBMITTED"
                    );
                    println!("{}", "\u{2500}".repeat(72));
                    for t in &templates {
                        println!(
                            "{:<25} {:<10} {:<15} {:<20}",
                            truncate(&t.name, 23),
                            t.version.as_deref().unwrap_or("\u{2014}"),
                            t.status,
                            t.created_at.as_deref().unwrap_or("\u{2014}"),
                        );
                    }
                    eprintln!("\n{} submission(s) total.", templates.len());
                }
            }
            Ok(())
        })
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// marketplace logs
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// `stacker marketplace logs <name> [--json]`
///
/// Show review comments and history for a marketplace submission.
pub struct MarketplaceLogsCommand {
    name: String,
    json: bool,
}

impl MarketplaceLogsCommand {
    pub fn new(name: String, json: bool) -> Self {
        Self { name, json }
    }
}

impl CallableTrait for MarketplaceLogsCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let json = self.json;

        let cred_manager = CredentialsManager::with_default_store();
        let creds = cred_manager.require_valid_token("marketplace logs")?;
        let base_url = crate::cli::install_runner::normalize_stacker_server_url(
            crate::cli::stacker_client::DEFAULT_STACKER_URL,
        );

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                CliError::ConfigValidation(format!("Failed to create async runtime: {}", e))
            })?;

        let name = self.name.clone();

        rt.block_on(async {
            let client = StackerClient::new(&base_url, &creds.access_token);

            // First, find the template by name to get its ID
            let templates = client.marketplace_list_mine().await?;
            let template = templates.iter().find(|t| t.name == name || t.slug == name);

            let template = match template {
                Some(t) => t,
                None => {
                    eprintln!("No submission found for '{}'", name);
                    std::process::exit(1);
                }
            };

            let reviews = client.marketplace_reviews(&template.id).await?;

            if json {
                println!("{}", serde_json::to_string_pretty(&reviews)?);
            } else {
                println!(
                    "Review history for: {} v{}",
                    template.name,
                    template.version.as_deref().unwrap_or("?")
                );
                println!("Current status: {}", template.status);
                println!();

                if reviews.is_empty() {
                    println!("No reviews yet.");
                    return Ok(());
                }

                println!(
                    "{:<12} {:<20} {:<20} {}",
                    "DECISION", "SUBMITTED", "REVIEWED", "REASON"
                );
                println!("{}", "\u{2500}".repeat(80));
                for r in &reviews {
                    println!(
                        "{:<12} {:<20} {:<20} {}",
                        r.decision,
                        r.submitted_at.as_deref().unwrap_or("\u{2014}"),
                        r.reviewed_at.as_deref().unwrap_or("\u{2014}"),
                        r.review_reason.as_deref().unwrap_or(""),
                    );
                }
                eprintln!("\n{} review(s) total.", reviews.len());
            }
            Ok(())
        })
    }
}

// ── helpers ──────────────────────────────────────────

/// Truncate a string to `max_len` characters, adding "..." if truncated.
fn truncate(s: &str, max_len: usize) -> String {
    if s.chars().count() > max_len {
        let truncated: String = s.chars().take(max_len.saturating_sub(1)).collect();
        format!("{}\u{2026}", truncated)
    } else {
        s.to_string()
    }
}
