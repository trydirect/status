//! CI/CD pipeline export commands.
//!
//! ```text
//! stacker ci export --platform github   # writes .github/workflows/stacker-deploy.yml
//! stacker ci export --platform gitlab   # writes .gitlab-ci.yml
//! stacker ci export --platform bitbucket # writes bitbucket-pipelines.yml
//! stacker ci export --platform jenkins  # writes Jenkinsfile
//! stacker ci validate --platform github # checks pipeline is in sync with stacker.yml
//! ```

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::cli::ci_export::CiExporter;
use crate::cli::config_parser::StackerConfig;
use crate::cli::error::CliError;
use crate::console::commands::CallableTrait;

const DEFAULT_CONFIG_FILE: &str = "stacker.yml";

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ci export
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// `stacker ci export --platform <github|gitlab|bitbucket|jenkins> [--file stacker.yml]`
pub struct CiExportCommand {
    pub platform: String,
    pub file: Option<String>,
}

impl CiExportCommand {
    pub fn new(platform: String, file: Option<String>) -> Self {
        Self { platform, file }
    }
}

impl CallableTrait for CiExportCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config_path = self.file.as_deref().unwrap_or(DEFAULT_CONFIG_FILE);
        let path = Path::new(config_path);

        if !path.exists() {
            return Err(Box::new(CliError::ConfigNotFound {
                path: path.to_path_buf(),
            }));
        }

        let config = StackerConfig::from_file(path)?.with_resolved_deploy_target(None)?;
        let exporter = CiExporter::new(config);

        let (output_content, output_path) = match self.platform.to_lowercase().as_str() {
            "github" | "github-actions" | "gha" => {
                let content = exporter.generate_github()?;
                let out = PathBuf::from(".github/workflows/stacker-deploy.yml");
                (content, out)
            }
            "gitlab" | "gitlab-ci" => {
                let content = exporter.generate_gitlab()?;
                let out = PathBuf::from(".gitlab-ci.yml");
                (content, out)
            }
            "bitbucket" | "bitbucket-pipelines" | "bb" => {
                let content = exporter.generate_bitbucket()?;
                let out = PathBuf::from("bitbucket-pipelines.yml");
                (content, out)
            }
            "jenkins" | "jenkinsfile" => {
                let content = exporter.generate_jenkins()?;
                let out = PathBuf::from("Jenkinsfile");
                (content, out)
            }
            other => {
                return Err(Box::new(CliError::ConfigValidation(format!(
                    "Unknown platform '{other}'. Supported: github, gitlab, bitbucket, jenkins"
                ))));
            }
        };

        // Ask before overwriting
        if output_path.exists() {
            eprint!(
                "  {} already exists. Overwrite? [y/N] ",
                output_path.display()
            );
            std::io::stderr().flush().ok();
            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer)?;
            if !answer.trim().eq_ignore_ascii_case("y") {
                println!("Aborted.");
                return Ok(());
            }
        }

        // Create parent directories if needed
        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        std::fs::write(&output_path, &output_content)?;
        println!("✓ Generated {}", output_path.display());

        match self.platform.to_lowercase().as_str() {
            "github" | "github-actions" | "gha" => {
                println!();
                println!("Next steps:");
                println!("  1. Add STACKER_TOKEN to your GitHub repository secrets");
                println!("     (Settings → Secrets and variables → Actions)");
                println!("  2. Commit and push the workflow file:");
                println!(
                    "     git add {} && git commit -m 'ci: add stacker deploy workflow'",
                    output_path.display()
                );
            }
            "gitlab" | "gitlab-ci" => {
                println!();
                println!("Next steps:");
                println!("  1. Add STACKER_TOKEN to your GitLab CI/CD variables");
                println!("     (Settings → CI/CD → Variables)");
                println!("  2. Commit and push the pipeline file:");
                println!(
                    "     git add {} && git commit -m 'ci: add stacker deploy pipeline'",
                    output_path.display()
                );
            }
            "bitbucket" | "bitbucket-pipelines" | "bb" => {
                println!();
                println!("Next steps:");
                println!("  1. Add STACKER_TOKEN to your Bitbucket repository variables");
                println!("     (Repository settings → Pipelines → Repository variables)");
                println!("  2. Commit and push the pipeline file:");
                println!(
                    "     git add {} && git commit -m 'ci: add stacker deploy pipeline'",
                    output_path.display()
                );
            }
            "jenkins" | "jenkinsfile" => {
                println!();
                println!("Next steps:");
                println!("  1. Add STACKER_TOKEN to your Jenkins job environment or credentials");
                println!("     (for example, as a job parameter or injected secret text)");
                println!("  2. Commit and push the pipeline file:");
                println!(
                    "     git add {} && git commit -m 'ci: add stacker deploy pipeline'",
                    output_path.display()
                );
            }
            _ => {}
        }

        Ok(())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ci validate
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// `stacker ci validate --platform <github|gitlab|bitbucket|jenkins>`
///
/// Checks that the existing pipeline file was generated for the current
/// `stacker.yml` (i.e., the project name in the pipeline matches).
pub struct CiValidateCommand {
    pub platform: String,
}

impl CiValidateCommand {
    pub fn new(platform: String) -> Self {
        Self { platform }
    }
}

impl CallableTrait for CiValidateCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config = StackerConfig::from_file(Path::new(DEFAULT_CONFIG_FILE))?
            .with_resolved_deploy_target(None)?;

        let pipeline_path = match self.platform.to_lowercase().as_str() {
            "github" | "github-actions" | "gha" => {
                PathBuf::from(".github/workflows/stacker-deploy.yml")
            }
            "gitlab" | "gitlab-ci" => PathBuf::from(".gitlab-ci.yml"),
            "bitbucket" | "bitbucket-pipelines" | "bb" => PathBuf::from("bitbucket-pipelines.yml"),
            "jenkins" | "jenkinsfile" => PathBuf::from("Jenkinsfile"),
            other => {
                return Err(Box::new(CliError::ConfigValidation(format!(
                    "Unknown platform '{other}'. Supported: github, gitlab, bitbucket, jenkins"
                ))));
            }
        };

        if !pipeline_path.exists() {
            eprintln!("✗ Pipeline file not found: {}", pipeline_path.display());
            eprintln!("  Run: stacker ci export --platform {}", self.platform);
            return Err(Box::new(CliError::ConfigValidation(format!(
                "Pipeline file not found: {}",
                pipeline_path.display()
            ))));
        }

        let pipeline_content = std::fs::read_to_string(&pipeline_path)?;

        // Basic check: does the pipeline mention the project name?
        if pipeline_content.contains(&config.name) {
            println!("✓ Pipeline {} looks up-to-date", pipeline_path.display());
            Ok(())
        } else {
            eprintln!(
                "✗ Pipeline {} does not reference project name '{}'",
                pipeline_path.display(),
                config.name
            );
            eprintln!(
                "  Re-generate with: stacker ci export --platform {}",
                self.platform
            );
            Err(Box::new(CliError::ConfigValidation(
                "Pipeline may be out of sync with stacker.yml".to_string(),
            )))
        }
    }
}
