use serde::{Deserialize, Serialize};

#[derive(sqlx::Type, Serialize, Deserialize, Debug, Clone, Copy)]
#[sqlx(rename_all = "lowercase", type_name = "rate_category")]
pub enum RateCategory {
    Application, // app, feature, extension
    Cloud,       // is user satisfied working with this cloud
    Project,     // app project
    DeploymentSpeed,
    Documentation,
    Design,
    TechSupport,
    Price,
    MemoryUsage,
}

impl Into<String> for RateCategory {
    fn into(self) -> String {
        format!("{:?}", self)
    }
}

impl Default for RateCategory {
    fn default() -> Self {
        RateCategory::Application
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_category_into_string() {
        let s: String = RateCategory::Application.into();
        assert_eq!(s, "Application");
    }

    #[test]
    fn test_rate_category_all_variants() {
        let variants = vec![
            (RateCategory::Application, "Application"),
            (RateCategory::Cloud, "Cloud"),
            (RateCategory::Project, "Project"),
            (RateCategory::DeploymentSpeed, "DeploymentSpeed"),
            (RateCategory::Documentation, "Documentation"),
            (RateCategory::Design, "Design"),
            (RateCategory::TechSupport, "TechSupport"),
            (RateCategory::Price, "Price"),
            (RateCategory::MemoryUsage, "MemoryUsage"),
        ];
        for (cat, expected) in variants {
            let s: String = cat.into();
            assert_eq!(s, expected);
        }
    }

    #[test]
    fn test_rate_category_default() {
        let cat = RateCategory::default();
        let s: String = cat.into();
        assert_eq!(s, "Application");
    }
}
