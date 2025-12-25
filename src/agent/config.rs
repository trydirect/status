use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReqData {
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub domain: Option<String>,
    pub subdomains: Option<serde_json::Value>,
    pub apps_info: Option<Vec<AppInfo>>, // normalized
    pub reqdata: ReqData,
    pub ssl: Option<String>,
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self> {
        let raw = fs::read_to_string(path).context("reading config file")?;
        let mut cfg: serde_json::Value = serde_json::from_str(&raw).context("parsing JSON")?;
        let apps_info = cfg.get("apps_info").and_then(|v| v.as_str()).map(|s| {
            s.split(',')
                .filter_map(|item| {
                    let mut parts = item.split('-');
                    let name = parts.next()?;
                    let version = parts.next().unwrap_or("");
                    Some(AppInfo {
                        name: name.to_string(),
                        version: version.to_string(),
                    })
                })
                .collect::<Vec<_>>()
        });
        if let Some(v) = apps_info.clone() {
            cfg["apps_info"] = serde_json::to_value(v).unwrap_or(serde_json::Value::Null);
        }
        let mut typed: Config = serde_json::from_value(cfg).context("mapping to Config")?;
        typed.apps_info = apps_info;
        Ok(typed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_config_parsing() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"{{
                "domain": "example.com",
                "apps_info": "app1-1.0,app2-2.0",
                "reqdata": {{"email": "test@example.com"}},
                "ssl": "letsencrypt"
            }}"#
        )
        .unwrap();

        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        assert_eq!(config.domain, Some("example.com".to_string()));
        assert_eq!(config.reqdata.email, "test@example.com");
        assert_eq!(config.ssl, Some("letsencrypt".to_string()));

        let apps = config.apps_info.unwrap();
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0].name, "app1");
        assert_eq!(apps[0].version, "1.0");
        assert_eq!(apps[1].name, "app2");
        assert_eq!(apps[1].version, "2.0");
    }

    #[test]
    fn test_config_missing_file() {
        let result = Config::from_file("/nonexistent/path/config.json");
        assert!(result.is_err());
    }

    #[test]
    fn test_config_invalid_json() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{{invalid json").unwrap();

        let result = Config::from_file(file.path().to_str().unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn test_apps_info_parsing() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"{{
                "apps_info": "nginx-latest,postgres-14.5,redis-7.0",
                "reqdata": {{"email": "test@test.com"}}
            }}"#
        )
        .unwrap();

        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        let apps = config.apps_info.unwrap();

        assert_eq!(apps.len(), 3);
        assert_eq!(apps[0].name, "nginx");
        assert_eq!(apps[0].version, "latest");
        assert_eq!(apps[2].name, "redis");
        assert_eq!(apps[2].version, "7.0");
    }
}
