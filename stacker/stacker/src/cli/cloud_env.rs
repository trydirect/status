pub const HETZNER_TOKEN_ENV_VARS: &[&str] = &[
    "STACKER_CLOUD_TOKEN",
    "STACKER_HETZNER_TOKEN",
    "HCLOUD_TOKEN",
];
pub const DIGITALOCEAN_TOKEN_ENV_VARS: &[&str] = &[
    "STACKER_CLOUD_TOKEN",
    "STACKER_DIGITALOCEAN_TOKEN",
    "DIGITALOCEAN_TOKEN",
];
pub const LINODE_TOKEN_ENV_VARS: &[&str] = &[
    "STACKER_CLOUD_TOKEN",
    "STACKER_LINODE_TOKEN",
    "LINODE_TOKEN",
];
pub const VULTR_TOKEN_ENV_VARS: &[&str] = &[
    "STACKER_CLOUD_TOKEN",
    "STACKER_VULTR_TOKEN",
    "VULTR_API_KEY",
];

pub const AWS_KEY_ENV_VARS: &[&str] = &["STACKER_CLOUD_KEY", "AWS_ACCESS_KEY_ID"];
pub const AWS_SECRET_ENV_VARS: &[&str] = &["STACKER_CLOUD_SECRET", "AWS_SECRET_ACCESS_KEY"];

pub const CONTABO_CLIENT_ID_ENV_VARS: &[&str] = &["STACKER_CONTABO_CLIENT_ID"];
pub const CONTABO_CLIENT_SECRET_ENV_VARS: &[&str] = &["STACKER_CONTABO_CLIENT_SECRET"];
pub const CONTABO_API_USER_ENV_VARS: &[&str] = &["STACKER_CONTABO_API_USER"];
pub const CONTABO_API_PASSWORD_ENV_VARS: &[&str] = &["STACKER_CONTABO_API_PASSWORD"];

pub fn token_env_vars(provider_code: &str) -> &'static [&'static str] {
    match provider_code {
        "htz" => HETZNER_TOKEN_ENV_VARS,
        "do" => DIGITALOCEAN_TOKEN_ENV_VARS,
        "lo" => LINODE_TOKEN_ENV_VARS,
        "vu" => VULTR_TOKEN_ENV_VARS,
        _ => &[],
    }
}

pub fn key_env_vars(provider_code: &str) -> &'static [&'static str] {
    match provider_code {
        "aws" => AWS_KEY_ENV_VARS,
        _ => &[],
    }
}

pub fn secret_env_vars(provider_code: &str) -> &'static [&'static str] {
    match provider_code {
        "aws" => AWS_SECRET_ENV_VARS,
        _ => &[],
    }
}

pub fn provider_cli_example(provider_code: &str) -> &'static str {
    match provider_code {
        "htz" => "HCLOUD_TOKEN=<token> stacker deploy --target cloud",
        "do" => "DIGITALOCEAN_TOKEN=<token> stacker deploy --target cloud",
        "lo" => "LINODE_TOKEN=<token> stacker deploy --target cloud",
        "vu" => "VULTR_API_KEY=<key> stacker deploy --target cloud",
        "aws" => {
            "AWS_ACCESS_KEY_ID=<key> AWS_SECRET_ACCESS_KEY=<secret> stacker deploy --target cloud"
        }
        "cnt" => {
            "STACKER_CONTABO_CLIENT_ID=<id> STACKER_CONTABO_CLIENT_SECRET=<secret> STACKER_CONTABO_API_USER=<user> STACKER_CONTABO_API_PASSWORD=<password> stacker deploy --target cloud"
        }
        _ => "stacker deploy --target cloud",
    }
}

pub fn provider_missing_credentials_hint(provider_code: &str) -> &'static str {
    match provider_code {
        "htz" => {
            "Set HCLOUD_TOKEN (or STACKER_CLOUD_TOKEN / STACKER_HETZNER_TOKEN), or save a Hetzner cloud credential first with `stacker deploy --target cloud` while that token is exported."
        }
        "do" => {
            "Set DIGITALOCEAN_TOKEN (or STACKER_CLOUD_TOKEN / STACKER_DIGITALOCEAN_TOKEN), or save a DigitalOcean cloud credential first."
        }
        "lo" => {
            "Set LINODE_TOKEN (or STACKER_CLOUD_TOKEN / STACKER_LINODE_TOKEN), or save a Linode cloud credential first."
        }
        "vu" => {
            "Set VULTR_API_KEY (or STACKER_CLOUD_TOKEN / STACKER_VULTR_TOKEN), or save a Vultr cloud credential first."
        }
        "aws" => {
            "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY (or STACKER_CLOUD_KEY / STACKER_CLOUD_SECRET), or save AWS cloud credentials first."
        }
        "cnt" => {
            "Set STACKER_CONTABO_CLIENT_ID, STACKER_CONTABO_CLIENT_SECRET, STACKER_CONTABO_API_USER, and STACKER_CONTABO_API_PASSWORD, or save a Contabo cloud credential first."
        }
        _ => "Set the required provider credential env vars, or save a cloud credential first.",
    }
}

pub fn provider_env_summary(provider_code: &str) -> &'static str {
    match provider_code {
        "htz" => "STACKER_CLOUD_TOKEN, STACKER_HETZNER_TOKEN, HCLOUD_TOKEN",
        "do" => {
            "STACKER_CLOUD_TOKEN, STACKER_DIGITALOCEAN_TOKEN, DIGITALOCEAN_TOKEN"
        }
        "lo" => "STACKER_CLOUD_TOKEN, STACKER_LINODE_TOKEN, LINODE_TOKEN",
        "vu" => "STACKER_CLOUD_TOKEN, STACKER_VULTR_TOKEN, VULTR_API_KEY",
        "aws" => {
            "STACKER_CLOUD_KEY, AWS_ACCESS_KEY_ID, STACKER_CLOUD_SECRET, AWS_SECRET_ACCESS_KEY"
        }
        "cnt" => {
            "STACKER_CONTABO_CLIENT_ID, STACKER_CONTABO_CLIENT_SECRET, STACKER_CONTABO_API_USER, STACKER_CONTABO_API_PASSWORD"
        }
        _ => "provider-specific cloud credential env vars",
    }
}
