use std::io::{self, IsTerminal};

use crate::cli::credentials::{login, CredentialsManager, HttpOAuthClient, LoginRequest};
use crate::console::commands::CallableTrait;
use dialoguer::Password;

/// `stacker login [--org <name>] [--domain <domain>] [--auth-url <url>]`
///
/// Authenticates with the TryDirect platform via OAuth2 and stores
/// credentials in `~/.config/stacker/credentials.json`.
///
/// Prompts for email on stdin and masks password input when interactive.
pub struct LoginCommand {
    pub org: Option<String>,
    pub domain: Option<String>,
    pub auth_url: Option<String>,
    pub server_url: Option<String>,
}

impl LoginCommand {
    pub fn new(
        org: Option<String>,
        domain: Option<String>,
        auth_url: Option<String>,
        server_url: Option<String>,
    ) -> Self {
        Self {
            org,
            domain,
            auth_url,
            server_url,
        }
    }

    /// Read a line from stdin (used for email/password prompts).
    fn read_line(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
        eprint!("{}", prompt);
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        Ok(input.trim().to_string())
    }

    fn read_password(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
        if io::stdin().is_terminal() {
            let cleaned = prompt.trim().trim_end_matches(':').trim();
            let input = Password::new()
                .with_prompt(cleaned)
                .interact()
                .map_err(|e| format!("Failed to read password: {}", e))?;
            Ok(input.trim().to_string())
        } else {
            Self::read_line(prompt)
        }
    }
}

impl CallableTrait for LoginCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let email = Self::read_line("Email: ")?;
        if email.is_empty() {
            return Err("Email cannot be empty".into());
        }

        let password = Self::read_password("Password: ")?;
        if password.is_empty() {
            return Err("Password cannot be empty".into());
        }

        let request = LoginRequest {
            email,
            password,
            auth_url: self.auth_url.clone(),
            server_url: self.server_url.clone(),
            org: self.org.clone(),
            domain: self.domain.clone(),
        };

        let manager = CredentialsManager::with_default_store();
        let oauth = HttpOAuthClient;

        let creds = login(&manager, &oauth, &request)?;

        eprintln!("✓ {}", creds);
        if let Some(org) = &creds.org {
            eprintln!("  Organization: {}", org);
        }
        if let Some(domain) = &creds.domain {
            eprintln!("  Domain: {}", domain);
        }
        if let Some(server_url) = &creds.server_url {
            eprintln!("  Stacker API: {}", server_url);
        }

        Ok(())
    }
}
