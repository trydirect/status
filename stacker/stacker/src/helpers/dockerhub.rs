use crate::forms::project::DockerImage;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;
use serde_valid::Validate;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
pub struct DockerHubToken {
    pub token: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
pub struct DockerHubCreds<'a> {
    pub(crate) username: &'a str,
    pub(crate) password: &'a str,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
pub struct Image {
    architecture: String,
    digest: Option<String>,
    features: Option<String>,
    last_pulled: Option<String>,
    last_pushed: Option<String>,
    os: String,
    os_features: Option<String>,
    os_version: Option<String>,
    size: i64,
    status: String,
    variant: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
pub struct Tag {
    pub content_type: String,
    pub creator: i64,
    pub digest: Option<String>,
    pub full_size: i64,
    pub id: i64,
    pub images: Vec<Image>,
    pub last_updated: String,
    pub last_updater: i64,
    pub last_updater_username: String,
    pub media_type: String,
    pub name: String,
    pub repository: i64,
    pub tag_last_pulled: Option<String>,
    pub tag_last_pushed: Option<String>,
    pub tag_status: String,
    pub v2: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
struct TagResult {
    pub count: Option<i64>,
    next: Option<Value>,
    previous: Option<Value>,
    results: Vec<Tag>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
pub struct RepoResults {
    pub count: Option<i64>,
    pub next: Option<Value>,
    pub previous: Option<Value>,
    pub results: Vec<RepoResult>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
pub struct OfficialRepoResults {
    pub count: Option<i64>,
    pub next: Option<Value>,
    pub previous: Option<Value>,
    pub results: Vec<Tag>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepoResult {
    pub name: String,
    pub namespace: Option<String>,
    pub repository_type: Option<String>,
    pub status: Option<i64>,
    pub status_description: Option<String>,
    pub description: Option<String>,
    pub is_private: Option<bool>,
    pub star_count: Option<i64>,
    pub pull_count: Option<i64>,
    pub last_updated: String,
    pub date_registered: Option<String>,
    pub affiliation: Option<String>,
    pub media_types: Option<Vec<String>>,
    pub content_types: Option<Vec<String>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Validate)]
pub struct DockerHub<'a> {
    pub(crate) creds: DockerHubCreds<'a>,
    //#[validate(pattern = r"^[^:]+(:[^:]*)?$")]
    #[validate(pattern = r"^([a-z-_0-9]+)(:[a-z-_0-9\.]+)?$")]
    pub(crate) repos: String,
    pub(crate) image: String,
    pub(crate) tag: Option<String>,
}

impl<'a> DockerHub<'a> {
    #[tracing::instrument(name = "Dockerhub login.")]
    pub async fn login(&'a self) -> Result<String, String> {
        if self.creds.password.is_empty() {
            return Err("Password is empty".to_string());
        }

        if self.creds.username.is_empty() {
            return Err("Username is empty".to_string());
        }

        let url = "https://hub.docker.com/v2/users/login";
        reqwest::Client::new()
            .post(url)
            .json(&self.creds)
            .send()
            .await
            .map_err(|err| format!("{:?}", err))?
            .json::<DockerHubToken>()
            .await
            .map(|docker_hub_token| docker_hub_token.token)
            .map_err(|err| format!("🟥 {:?}", err))
    }

    #[tracing::instrument(name = "Lookup public repos")]
    pub async fn lookup_public_repos(&'a self) -> Result<bool, String> {
        if !self.creds.username.is_empty() {
            return Ok(false);
        }
        let url = format!("https://hub.docker.com/v2/repositories/{}", self.repos);
        let client = reqwest::Client::new()
            .get(&url)
            .header("Accept", "application/json");

        client
            .send()
            .await
            .map_err(|err| {
                let msg = format!("🟥Error response {:?}", err);
                tracing::debug!(msg);
                msg
            })?
            .json::<RepoResults>()
            .await
            .map_err(|err| {
                let msg = format!("🟥Error on getting results:: {} url: {}", &err, &url);
                tracing::error!(msg);
                msg
            })
            .map(|repositories| {
                tracing::debug!(
                    "Get public image repo {:?} response {:?}",
                    &url,
                    repositories
                );
                if repositories.count.unwrap_or(0) > 0 {
                    // let's find at least one active repo
                    let active = repositories
                        .results
                        .into_iter()
                        .any(|repo| repo.status == Some(1));
                    tracing::debug!("✅ Public repository is active. url: {:?}", &url);
                    active
                } else {
                    tracing::debug!("🟥 Public repository is not active, url: {:?}", &url);
                    false
                }
            })
    }

    #[tracing::instrument(name = "Lookup official repos")]
    pub async fn lookup_official_repos(&'a self) -> Result<bool, String> {
        let t = match self.tag.clone() {
            Some(s) if !s.is_empty() => s,
            _ => String::from("latest"),
        };
        let url = format!(
            "https://hub.docker.com/v2/repositories/library/{}/tags?name={}&page_size=100",
            self.repos, t
        );
        let client = reqwest::Client::new()
            .get(url)
            .header("Accept", "application/json");

        client
            .send()
            .await
            .map_err(|err| format!("🟥{}", err))?
            .json::<OfficialRepoResults>()
            .await
            .map_err(|err| {
                tracing::debug!("🟥Error response {:?}", err);
                format!("{}", err)
            })
            .map(|tags| {
                tracing::debug!("Validate official image response {:?}", tags);
                if tags.count.unwrap_or(0) > 0 {
                    // let's find at least one active tag
                    let result = tags.results.into_iter().any(|tag| {
                        tracing::debug!(
                            "🟨 check official tag.name {:?} tag.tag_status: {:?} t={:?}",
                            tag.name,
                            tag.tag_status,
                            t
                        );
                        "active".to_string() == tag.tag_status
                    });
                    tracing::debug!("🟨 Official image is active? {:?}", result);
                    result
                } else {
                    tracing::debug!("🟥 Official image tag is not active");
                    false
                }
            })
    }

    #[tracing::instrument(name = "Lookup vendor's public repos")]
    pub async fn lookup_vendor_public_repos(&'a self) -> Result<bool, String> {
        let t = match self.tag.clone() {
            Some(s) if !s.is_empty() => s,
            _ => String::from("latest"),
        };
        // get exact tag name
        let url = format!(
            "https://hub.docker.com/v2/namespaces/{}/repositories/{}/tags?name={}&page_size=100",
            &self.creds.username, &self.repos, &t
        );

        tracing::debug!("Search vendor's public repos {:?}", url);
        let client = reqwest::Client::new()
            .get(url)
            .header("Accept", "application/json");

        client
            .send()
            .await
            .map_err(|err| format!("🟥{}", err))?
            .json::<TagResult>()
            .await
            .map_err(|err| {
                tracing::debug!("🟥Error response {:?}", err);
                format!("{}", err)
            })
            .map(|tags| {
                tracing::debug!("Validate vendor's public image response {:?}", tags);
                if tags.count.unwrap_or(0) > 0 {
                    // let's find at least one active tag
                    let t = match self.tag.clone() {
                        Some(s) if !s.is_empty() => s,
                        _ => String::from("latest"),
                    };
                    tracing::debug!("🟥 🟥 🟥 t={:?}", t);

                    let active = tags
                        .results
                        .into_iter()
                        .any(|tag| tag.tag_status.contains("active") && tag.name.eq(&t));
                    return active;
                } else {
                    tracing::debug!("🟥 Image tag is not active");
                    false
                }
            })
    }
    #[tracing::instrument(name = "Lookup private repos")]
    pub async fn lookup_private_repo(&'a self) -> Result<bool, String> {
        let token = self.login().await?;
        let t = match self.tag.clone() {
            Some(s) if !s.is_empty() => s,
            _ => String::from("latest"),
        };

        let url = format!(
            "https://hub.docker.com/v2/namespaces/{}/repositories/{}/tags?name={}&page_size=100",
            &self.creds.username, &self.repos, t
        );

        tracing::debug!("Search private repos {:?}", url);
        let client = reqwest::Client::new()
            .get(url)
            .header("Accept", "application/json");

        client
            .bearer_auth(token)
            .send()
            .await
            .map_err(|err| format!("🟥{}", err))?
            .json::<TagResult>()
            .await
            .map_err(|err| {
                tracing::debug!("🟥Error response {:?}", err);
                format!("{}", err)
            })
            .map(|tags| {
                tracing::debug!("Validate private image response {:?}", tags);
                if tags.count.unwrap_or(0) > 0 {
                    // let's find at least one active tag
                    let t = match self.tag.clone() {
                        Some(s) if !s.is_empty() => s,
                        _ => String::from("latest"),
                    };

                    let active = tags
                        .results
                        .into_iter()
                        .any(|tag| tag.tag_status.contains("active") && tag.name.eq(&t));
                    return active;
                } else {
                    tracing::debug!("🟥 Image tag is not active");
                    false
                }
            })
    }

    pub async fn is_active(&'a self) -> Result<bool, String> {
        // if namespace/user is not set change endpoint and return a different response
        tokio::select! {
            Ok(true) = self.lookup_official_repos() => {
                    tracing::debug!("official: true");
                    println!("official: true");
                    return Ok(true);
                }

            Ok(true) = self.lookup_public_repos()  => {
                tracing::debug!("public: true");
                println!("public: true");
                return Ok(true);
            }

            Ok(true) = self.lookup_vendor_public_repos()  => {
                tracing::debug!("public: true");
                println!("public: true");
                return Ok(true);
            }

            Ok(true) = self.lookup_private_repo() => {
                tracing::debug!("private: true");
                println!("private: true");
                return Ok(true);
            }

            else => { return Ok(false); }
        }
    }
}

impl<'a> TryFrom<&'a DockerImage> for DockerHub<'a> {
    type Error = String;

    fn try_from(image: &'a DockerImage) -> Result<Self, Self::Error> {
        let username = match image.dockerhub_user {
            Some(ref username) => username,
            None => "",
        };
        let password = match image.dockerhub_password {
            Some(ref password) => password,
            None => "",
        };

        let name = image.dockerhub_name.clone().unwrap_or("".to_string());
        let n = name
            .split(':')
            .map(|x| x.to_string())
            .collect::<Vec<String>>();

        let (name, tag) = match n.len() {
            1 => (n.first().unwrap().into(), Some("".to_string())),
            2 => (
                n.first().unwrap().to_string(),
                n.last().map(|s| s.to_string()),
            ),
            _ => {
                return Err("Wrong format of repository name".to_owned());
            }
        };

        let hub = DockerHub {
            creds: DockerHubCreds {
                username: username,
                password: password,
            },
            repos: name,
            image: format!("{}", image),
            tag: tag,
        };

        if let Err(errors) = hub.validate() {
            let msg = "DockerHub image properties are not valid. Please verify repository name";
            tracing::debug!("{:?} {:?}", msg, errors);
            return Err(format!("{:?}", msg));
        }

        Ok(hub)
    }
}
