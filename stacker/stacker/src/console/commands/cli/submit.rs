use std::path::Path;

use crate::cli::config_parser::StackerConfig;
use crate::cli::credentials::CredentialsManager;
use crate::cli::error::CliError;
use crate::cli::stacker_client::StackerClient;
use crate::console::commands::CallableTrait;

/// Default config filename.
const DEFAULT_CONFIG_FILE: &str = "stacker.yml";

/// `stacker submit`
///
/// Packages the current stack project and submits it to the marketplace for
/// review. Reads stacker.yml for project metadata, creates or updates the
/// template on the server, then submits it for review.
pub struct SubmitCommand {
    file: Option<String>,
    version: Option<String>,
    description: Option<String>,
    category: Option<String>,
    plan_type: Option<String>,
    price: Option<f64>,
}

impl SubmitCommand {
    pub fn new(
        file: Option<String>,
        version: Option<String>,
        description: Option<String>,
        category: Option<String>,
        plan_type: Option<String>,
        price: Option<f64>,
    ) -> Self {
        Self {
            file,
            version,
            description,
            category,
            plan_type,
            price,
        }
    }
}

impl CallableTrait for SubmitCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        // 1. Load credentials
        let cred_manager = CredentialsManager::with_default_store();
        let creds = cred_manager.require_valid_token("submit")?;
        let base_url = crate::cli::install_runner::normalize_stacker_server_url(
            crate::cli::stacker_client::DEFAULT_STACKER_URL,
        );

        // 2. Read and parse stacker.yml
        let project_dir = std::env::current_dir()?;
        let config_path = match &self.file {
            Some(f) => Path::new(f).to_path_buf(),
            None => project_dir.join(DEFAULT_CONFIG_FILE),
        };

        let config = StackerConfig::from_file(&config_path)?;
        let name = config.name.clone();
        let version = self
            .version
            .clone()
            .or_else(|| config.version.clone())
            .unwrap_or_else(|| "1.0.0".to_string());

        // Read the raw YAML content to send as the stack definition
        let raw_yaml = std::fs::read_to_string(&config_path)?;
        let stack_definition: serde_json::Value =
            serde_json::to_value(&serde_yaml::from_str::<serde_yaml::Value>(&raw_yaml)?)?;

        // Derive slug from project name (lowercase, hyphens)
        let slug = name
            .to_lowercase()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c
                } else {
                    '-'
                }
            })
            .collect::<String>()
            .split('-')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("-");

        // Build the template body
        let mut body = serde_json::json!({
            "name": name,
            "slug": slug,
            "version": version,
            "stack_definition": stack_definition,
        });

        if let Some(ref desc) = self.description {
            body["short_description"] = serde_json::json!(desc);
        }
        if let Some(ref cat) = self.category {
            body["category_code"] = serde_json::json!(cat);
        }

        let plan_type = self.plan_type.as_deref().unwrap_or("free");
        body["plan_type"] = serde_json::json!(plan_type);

        if let Some(price) = self.price {
            body["price"] = serde_json::json!(price);
        }

        // 3. Create async runtime and execute
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                CliError::ConfigValidation(format!("Failed to create async runtime: {}", e))
            })?;

        rt.block_on(async {
            let client = StackerClient::new(&base_url, &creds.access_token);

            // Create or update the template on the server
            eprintln!("Creating/updating template '{}'...", name);
            let template = client.marketplace_create_or_update(body).await?;

            // Submit for review
            eprintln!("Submitting for marketplace review...");
            client.marketplace_submit(&template.id).await?;

            // Success message
            println!();
            println!("Submitted '{}' v{} for marketplace review.", name, version);
            println!(
                "Your stack will be published automatically once accepted by the review team."
            );
            println!("Check status with: stacker marketplace status {}", name);

            Ok(())
        })
    }
}
