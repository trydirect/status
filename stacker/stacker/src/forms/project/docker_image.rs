use crate::helpers::dockerhub::DockerHub;
use serde::{Deserialize, Serialize};
use serde_valid::Validate;
use std::fmt;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
pub struct DockerImage {
    // #[validate(min_length = 3)]
    #[validate(max_length = 50)]
    // @todo conditional check, if not empty
    // #[validate(pattern = r"^[a-z0-9]+([-_.][a-z0-9]+)*$")]
    pub dockerhub_user: Option<String>,
    // #[validate(min_length = 3)]
    #[validate(max_length = 50)]
    // @todo conditional check, if not empty
    // #[validate(pattern = r"^[a-z0-9]+([-_.][a-z0-9]+)*$")]
    pub dockerhub_name: Option<String>,
    // #[validate(min_length = 3)]
    #[validate(max_length = 100)]
    pub dockerhub_image: Option<String>,
    pub dockerhub_password: Option<String>,
}

impl fmt::Display for DockerImage {
    // dh_image = trydirect/postgres:latest
    // dh_nmsp = trydirect, dh_repo_name=postgres
    // dh_nmsp = trydirect dh_repo_name=postgres:v8
    // namespace/repo_name/tag
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let dh_image = self.dockerhub_image.as_deref().unwrap_or("");
        let dh_nmspc = self.dockerhub_user.as_deref().unwrap_or("");
        let dh_repo_name = self.dockerhub_name.as_deref().unwrap_or("");

        write!(
            f,
            "{}{}{}",
            if !dh_nmspc.is_empty() {
                format!("{}/", dh_nmspc)
            } else {
                String::new()
            },
            if !dh_repo_name.is_empty() {
                dh_repo_name
            } else {
                dh_image
            },
            if !dh_repo_name.contains(":") && dh_image.is_empty() {
                ":latest".to_string()
            } else {
                String::new()
            },
        )
    }
}

impl DockerImage {
    #[tracing::instrument(name = "is_active", skip_all)]
    pub async fn is_active(&self) -> Result<bool, String> {
        DockerHub::try_from(self)?.is_active().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_full_image() {
        let img = DockerImage {
            dockerhub_user: Some("trydirect".to_string()),
            dockerhub_name: Some("postgres:v8".to_string()),
            dockerhub_image: None,
            dockerhub_password: None,
        };
        assert_eq!(format!("{}", img), "trydirect/postgres:v8");
    }

    #[test]
    fn test_display_image_only() {
        let img = DockerImage {
            dockerhub_user: None,
            dockerhub_name: None,
            dockerhub_image: Some("nginx:latest".to_string()),
            dockerhub_password: None,
        };
        assert_eq!(format!("{}", img), "nginx:latest");
    }

    #[test]
    fn test_display_name_without_tag_adds_latest() {
        let img = DockerImage {
            dockerhub_user: Some("myuser".to_string()),
            dockerhub_name: Some("myapp".to_string()),
            dockerhub_image: None,
            dockerhub_password: None,
        };
        assert_eq!(format!("{}", img), "myuser/myapp:latest");
    }

    #[test]
    fn test_display_name_with_tag_no_latest() {
        let img = DockerImage {
            dockerhub_user: Some("myuser".to_string()),
            dockerhub_name: Some("myapp:v2".to_string()),
            dockerhub_image: None,
            dockerhub_password: None,
        };
        assert_eq!(format!("{}", img), "myuser/myapp:v2");
    }

    #[test]
    fn test_display_no_user_with_name() {
        let img = DockerImage {
            dockerhub_user: None,
            dockerhub_name: Some("redis".to_string()),
            dockerhub_image: None,
            dockerhub_password: None,
        };
        assert_eq!(format!("{}", img), "redis:latest");
    }

    #[test]
    fn test_display_all_empty() {
        let img = DockerImage::default();
        assert_eq!(format!("{}", img), ":latest");
    }

    #[test]
    fn test_display_image_takes_precedence_when_name_empty() {
        let img = DockerImage {
            dockerhub_user: None,
            dockerhub_name: None,
            dockerhub_image: Some("custom/image:tag".to_string()),
            dockerhub_password: None,
        };
        assert_eq!(format!("{}", img), "custom/image:tag");
    }

    #[test]
    fn test_docker_image_serialization() {
        let img = DockerImage {
            dockerhub_user: Some("user".to_string()),
            dockerhub_name: Some("app".to_string()),
            dockerhub_image: Some("user/app:1.0".to_string()),
            dockerhub_password: None,
        };
        let json = serde_json::to_string(&img).unwrap();
        let deserialized: DockerImage = serde_json::from_str(&json).unwrap();
        assert_eq!(img, deserialized);
    }
}
