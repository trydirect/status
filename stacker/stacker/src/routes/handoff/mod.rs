use actix_web::{post, web, Responder, Result};
use chrono::{DateTime, Duration, TimeZone, Utc};
use sqlx::PgPool;
use std::sync::Arc;

use crate::cli::deployment_lock::DeploymentLock;
use crate::cli::stacker_client::DEFAULT_STACKER_URL;
use crate::configuration::Settings;
use crate::db;
use crate::handoff::{
    DeploymentHandoffAgent, DeploymentHandoffCloud, DeploymentHandoffCredentials,
    DeploymentHandoffDeployment, DeploymentHandoffKind, DeploymentHandoffLink,
    DeploymentHandoffMintRequest, DeploymentHandoffMintResponse, DeploymentHandoffPayload,
    DeploymentHandoffProject, DeploymentHandoffResolveRequest, DeploymentHandoffServer,
};
use crate::helpers::JsonResponse;
use crate::models;
use crate::routes::legacy_installations::{
    infer_legacy_target, legacy_target_name, resolve_owned_deployment_for_handoff, OwnedDeployment,
};
use crate::services::InMemoryHandoffStore;

const HANDOFF_TTL_HOURS: i64 = 2;

#[post("/mint")]
pub async fn mint_handler(
    request: web::Json<DeploymentHandoffMintRequest>,
    user: web::ReqData<Arc<models::User>>,
    pg_pool: web::Data<PgPool>,
    handoff_store: web::Data<Arc<InMemoryHandoffStore>>,
    settings: web::Data<Settings>,
    http_request: actix_web::HttpRequest,
) -> Result<impl Responder> {
    let expires_at = Utc::now() + Duration::hours(HANDOFF_TTL_HOURS);
    let payload = match resolve_owned_deployment_for_handoff(
        pg_pool.get_ref(),
        settings.get_ref(),
        user.as_ref(),
        request.deployment_id.map(i64::from),
        request.deployment_hash.as_deref(),
    )
    .await?
    {
        OwnedDeployment::Native(deployment) => {
            let project = db::project::fetch(pg_pool.get_ref(), deployment.project_id)
                .await
                .map_err(JsonResponse::<String>::internal_server_error)?
                .ok_or_else(|| JsonResponse::<String>::not_found("Project not found"))?;

            let server = db::server::fetch_by_project(pg_pool.get_ref(), project.id)
                .await
                .map_err(JsonResponse::<String>::internal_server_error)?
                .into_iter()
                .next();

            build_payload(
                &http_request,
                user.as_ref(),
                &project,
                &deployment,
                server.as_ref(),
                expires_at,
            )
        }
        OwnedDeployment::Legacy(installation) => {
            build_legacy_payload(&http_request, user.as_ref(), &installation, expires_at)
        }
    };
    let token = handoff_store.insert(payload);
    let base_url = resolve_public_base_url(&http_request);
    let link = DeploymentHandoffLink {
        token: token.clone(),
        url: format!("{}/handoff#{}", base_url.trim_end_matches('/'), token),
        expires_at,
    };

    Ok(JsonResponse::build()
        .set_item(DeploymentHandoffMintResponse {
            command: format!("stacker connect --handoff {}", token),
            token: link.token,
            url: link.url,
            expires_at: link.expires_at,
        })
        .ok("CLI handoff minted"))
}

#[post("/mint/account")]
pub async fn mint_account_handler(
    user: web::ReqData<Arc<models::User>>,
    handoff_store: web::Data<Arc<InMemoryHandoffStore>>,
    http_request: actix_web::HttpRequest,
) -> Result<impl Responder> {
    let expires_at = Utc::now() + Duration::hours(HANDOFF_TTL_HOURS);
    let payload = build_account_payload(&http_request, user.as_ref(), expires_at);
    let token = handoff_store.insert(payload);
    let base_url = resolve_public_base_url(&http_request);
    let link = DeploymentHandoffLink {
        token: token.clone(),
        url: format!("{}/handoff#{}", base_url.trim_end_matches('/'), token),
        expires_at,
    };

    Ok(JsonResponse::build()
        .set_item(DeploymentHandoffMintResponse {
            command: format!("stacker connect --handoff {}", token),
            token: link.token,
            url: link.url,
            expires_at: link.expires_at,
        })
        .ok("CLI account handoff minted"))
}

#[post("/resolve")]
pub async fn resolve_handler(
    request: web::Json<DeploymentHandoffResolveRequest>,
    handoff_store: web::Data<Arc<InMemoryHandoffStore>>,
) -> Result<impl Responder> {
    let payload = handoff_store
        .resolve_once(&request.token)
        .ok_or_else(|| JsonResponse::<String>::not_found("Handoff token not found"))?;

    Ok(JsonResponse::build()
        .set_item(payload)
        .ok("CLI handoff resolved"))
}

fn build_payload(
    http_request: &actix_web::HttpRequest,
    user: &models::User,
    project: &models::Project,
    deployment: &models::Deployment,
    server: Option<&models::Server>,
    expires_at: chrono::DateTime<Utc>,
) -> DeploymentHandoffPayload {
    let target = infer_target(server);
    let ssh_user = server
        .and_then(|srv| srv.ssh_user.clone())
        .filter(|value| !value.trim().is_empty())
        .or_else(|| match target.as_str() {
            "cloud" | "server" => Some("root".to_string()),
            _ => None,
        });
    let ssh_port = server
        .and_then(|srv| srv.ssh_port)
        .map(|value| value as u16)
        .or_else(|| match target.as_str() {
            "cloud" | "server" => Some(22),
            _ => None,
        });

    let lockfile = serde_json::to_value(DeploymentLock {
        target: target.clone(),
        server_ip: server.and_then(|srv| srv.srv_ip.clone()),
        ssh_user: ssh_user.clone(),
        ssh_port,
        server_name: server.and_then(|srv| srv.name.clone().or_else(|| srv.server.clone())),
        deployment_id: Some(deployment.id as i64),
        project_id: Some(project.id as i64),
        cloud_id: server.and_then(|srv| srv.cloud_id),
        project_name: Some(project.name.clone()),
        stacker_email: Some(user.email.clone()),
        deployed_at: deployment.updated_at.to_rfc3339(),
    })
    .unwrap_or_else(|_| serde_json::json!({}));

    let base_url = resolve_public_base_url(http_request);
    DeploymentHandoffPayload {
        kind: DeploymentHandoffKind::Deployment,
        version: 1,
        expires_at,
        project: DeploymentHandoffProject {
            id: project.id,
            name: project.name.clone(),
            identity: Some(project.name.clone()),
        },
        deployment: DeploymentHandoffDeployment {
            id: deployment.id,
            hash: deployment.deployment_hash.clone(),
            target,
            status: deployment.status.clone(),
        },
        server: server.map(|srv| DeploymentHandoffServer {
            ip: srv.srv_ip.clone(),
            ssh_user,
            ssh_port,
            name: srv.name.clone().or_else(|| srv.server.clone()),
        }),
        cloud: server.and_then(|srv| {
            srv.cloud_id.map(|cloud_id| DeploymentHandoffCloud {
                id: cloud_id,
                provider: None,
                region: srv.region.clone(),
            })
        }),
        lockfile,
        stacker_yml: Some(render_stacker_yml(project, deployment, server)),
        agent: server.and_then(|srv| {
            let server_ip = srv.srv_ip.clone()?;
            Some(DeploymentHandoffAgent {
                base_url: format!("http://{}:8080", server_ip),
                deployment_hash: deployment.deployment_hash.clone(),
            })
        }),
        credentials: build_handoff_credentials(user, expires_at, base_url),
    }
}

fn build_legacy_payload(
    http_request: &actix_web::HttpRequest,
    user: &models::User,
    installation: &crate::connectors::user_service::install::InstallationDetails,
    expires_at: chrono::DateTime<Utc>,
) -> DeploymentHandoffPayload {
    let target = infer_legacy_target(installation);
    let installation_id = installation
        .id
        .and_then(|value| i32::try_from(value).ok())
        .unwrap_or_default();
    let deployment_hash = installation.deployment_hash.clone().unwrap_or_default();
    let project_name = legacy_target_name(installation);
    let server_ip = installation
        .server_ip
        .clone()
        .filter(|value| !value.trim().is_empty());

    let lockfile = serde_json::to_value(DeploymentLock {
        target: target.clone(),
        server_ip: server_ip.clone(),
        ssh_user: server_ip.as_ref().map(|_| "root".to_string()),
        ssh_port: server_ip.as_ref().map(|_| 22),
        server_name: installation
            .domain
            .clone()
            .or_else(|| installation.stack_code.clone()),
        deployment_id: None,
        project_id: None,
        cloud_id: None,
        project_name: Some(project_name.clone()),
        stacker_email: Some(user.email.clone()),
        deployed_at: installation
            .updated_at
            .clone()
            .unwrap_or_else(|| Utc::now().to_rfc3339()),
    })
    .unwrap_or_else(|_| serde_json::json!({}));

    let base_url = resolve_public_base_url(http_request);
    DeploymentHandoffPayload {
        kind: DeploymentHandoffKind::Deployment,
        version: 1,
        expires_at,
        project: DeploymentHandoffProject {
            id: installation_id,
            name: project_name.clone(),
            identity: Some(project_name.clone()),
        },
        deployment: DeploymentHandoffDeployment {
            id: installation_id,
            hash: deployment_hash.clone(),
            target: target.clone(),
            status: installation
                .status
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
        },
        server: server_ip.clone().map(|ip| DeploymentHandoffServer {
            ip: Some(ip),
            ssh_user: Some("root".to_string()),
            ssh_port: Some(22),
            name: installation
                .domain
                .clone()
                .or_else(|| installation.stack_code.clone()),
        }),
        cloud: installation
            .cloud
            .as_ref()
            .map(|provider| DeploymentHandoffCloud {
                id: 0,
                provider: Some(provider.clone()),
                region: None,
            }),
        lockfile,
        stacker_yml: Some(render_legacy_stacker_yml(
            &project_name,
            &deployment_hash,
            &target,
            installation,
        )),
        agent: server_ip.map(|ip| DeploymentHandoffAgent {
            base_url: format!("http://{}:8080", ip),
            deployment_hash,
        }),
        credentials: build_handoff_credentials(user, expires_at, base_url),
    }
}

fn build_account_payload(
    http_request: &actix_web::HttpRequest,
    user: &models::User,
    expires_at: DateTime<Utc>,
) -> DeploymentHandoffPayload {
    let base_url = resolve_public_base_url(http_request);

    DeploymentHandoffPayload {
        kind: DeploymentHandoffKind::Account,
        version: 1,
        expires_at,
        project: DeploymentHandoffProject {
            id: 0,
            name: user.email.clone(),
            identity: Some(user.email.clone()),
        },
        deployment: DeploymentHandoffDeployment {
            id: 0,
            hash: String::new(),
            target: "account".to_string(),
            status: "ready".to_string(),
        },
        server: None,
        cloud: None,
        lockfile: serde_json::json!({}),
        stacker_yml: None,
        agent: None,
        credentials: build_handoff_credentials(user, expires_at, base_url),
    }
}

fn build_handoff_credentials(
    user: &models::User,
    handoff_expires_at: DateTime<Utc>,
    server_url: String,
) -> Option<DeploymentHandoffCredentials> {
    user.access_token
        .clone()
        .map(|access_token| DeploymentHandoffCredentials {
            expires_at: infer_access_token_expiry(&access_token).unwrap_or(handoff_expires_at),
            access_token,
            token_type: "Bearer".to_string(),
            email: Some(user.email.clone()),
            server_url: Some(server_url),
        })
}

fn infer_access_token_expiry(token: &str) -> Option<DateTime<Utc>> {
    #[derive(serde::Deserialize)]
    struct JwtExpiryClaims {
        exp: i64,
    }

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let payload = token.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: JwtExpiryClaims = serde_json::from_slice(&decoded).ok()?;
    Utc.timestamp_opt(claims.exp, 0).single()
}

fn infer_target(server: Option<&models::Server>) -> String {
    match server {
        Some(srv) if srv.cloud_id.is_some() => "cloud".to_string(),
        Some(_) => "server".to_string(),
        None => "local".to_string(),
    }
}

fn render_stacker_yml(
    project: &models::Project,
    deployment: &models::Deployment,
    server: Option<&models::Server>,
) -> String {
    let target = infer_target(server);
    let mut lines = vec![
        format!("name: {}", quote_yaml(&project.name)),
        "project:".to_string(),
        format!("  identity: {}", quote_yaml(&project.name)),
        "deploy:".to_string(),
        format!("  target: {}", quote_yaml(&target)),
        format!(
            "  deployment_hash: {}",
            quote_yaml(&deployment.deployment_hash)
        ),
    ];

    if let Some(srv) = server {
        if target == "server" {
            lines.push("  server:".to_string());
            if let Some(host) = srv.srv_ip.as_ref() {
                lines.push(format!("    host: {}", quote_yaml(host)));
            }
            if let Some(user) = srv.ssh_user.as_ref() {
                lines.push(format!("    user: {}", quote_yaml(user)));
            }
            if let Some(port) = srv.ssh_port {
                lines.push(format!("    port: {}", port));
            }
        } else if target == "cloud" {
            lines.push("  cloud:".to_string());
            if let Some(server_name) = srv.name.as_ref().or(srv.server.as_ref()) {
                lines.push(format!("    server: {}", quote_yaml(server_name)));
            }
        }
    }

    lines.join("\n") + "\n"
}

fn render_legacy_stacker_yml(
    project_name: &str,
    deployment_hash: &str,
    target: &str,
    installation: &crate::connectors::user_service::install::InstallationDetails,
) -> String {
    let mut lines = vec![
        format!("name: {}", quote_yaml(project_name)),
        "project:".to_string(),
        format!("  identity: {}", quote_yaml(project_name)),
        "deploy:".to_string(),
        format!("  target: {}", quote_yaml(target)),
        format!("  deployment_hash: {}", quote_yaml(deployment_hash)),
    ];

    if target == "server" {
        lines.push("  server:".to_string());
        if let Some(host) = installation.server_ip.as_ref() {
            lines.push(format!("    host: {}", quote_yaml(host)));
        }
        lines.push("    user: root".to_string());
        lines.push("    port: 22".to_string());
    }

    lines.join("\n") + "\n"
}

fn quote_yaml(value: &str) -> String {
    serde_yaml::to_string(value)
        .map(|yaml| yaml.trim().to_string())
        .unwrap_or_else(|_| format!("{:?}", value))
}

fn resolve_public_base_url(request: &actix_web::HttpRequest) -> String {
    let connection_info = request.connection_info();
    let scheme = connection_info.scheme();
    let host = connection_info.host();
    if !host.is_empty() {
        format!("{}://{}", scheme, host)
    } else {
        DEFAULT_STACKER_URL.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use serde_json::json;

    fn test_user_with_token(token: &str) -> models::User {
        models::User {
            id: "user-1".to_string(),
            first_name: "Test".to_string(),
            last_name: "User".to_string(),
            email: "user@example.com".to_string(),
            role: "group_user".to_string(),
            email_confirmed: true,
            mfa_verified: false,
            access_token: Some(token.to_string()),
        }
    }

    fn create_test_jwt(exp: i64) -> String {
        let header = json!({"alg": "HS256", "typ": "JWT"});
        let payload = json!({"sub": "user-1", "email": "user@example.com", "exp": exp});
        format!(
            "{}.{}.signature",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(payload.to_string()),
        )
    }

    #[test]
    fn infers_access_token_expiry_from_jwt_exp_claim() {
        let expected = Utc::now() + Duration::hours(6);
        let token = create_test_jwt(expected.timestamp());

        let inferred = infer_access_token_expiry(&token).expect("jwt expiry should be inferred");

        assert_eq!(inferred.timestamp(), expected.timestamp());
    }

    #[test]
    fn account_payload_is_marked_account_scoped() {
        let request = TestRequest::default()
            .insert_header(("host", "stacker.try.direct"))
            .to_http_request();
        let expires_at = Utc::now() + Duration::hours(2);
        let payload =
            build_account_payload(&request, &test_user_with_token("opaque-token"), expires_at);

        assert!(payload.is_account_scoped());
        assert_eq!(payload.deployment.target, "account");
        assert_eq!(
            payload.project.identity.as_deref(),
            Some("user@example.com")
        );
        assert_eq!(payload.lockfile, json!({}));
        assert!(payload.stacker_yml.is_none());
    }
}
