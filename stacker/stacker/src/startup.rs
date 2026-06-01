use crate::configuration::Settings;
use crate::connectors;
use crate::health::{HealthChecker, HealthMetrics};
use crate::helpers;
use crate::helpers::AgentPgPool;
use crate::mcp;
use crate::middleware;
use crate::routes;
use crate::services::InMemoryHandoffStore;
use actix_cors::Cors;
use actix_web::middleware::Compress;
use actix_web::{dev::Server, error, http, web, App, HttpServer};
use sqlx::{Pool, Postgres};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;
use tracing_actix_web::TracingLogger;

fn project_scope(path: &str) -> actix_web::Scope {
    web::scope(path)
        .service(crate::routes::project::deploy::item)
        .service(crate::routes::project::deploy::saved_item)
        .service(crate::routes::project::deploy::rollback)
        .service(crate::routes::project::member::add)
        .service(crate::routes::project::member::list)
        .service(crate::routes::project::member::delete)
        .service(crate::routes::project::compose::add)
        .service(crate::routes::project::get::list)
        .service(crate::routes::project::get::shared_list)
        .service(crate::routes::project::get::item)
        .service(crate::routes::project::add::item)
        .service(crate::routes::project::update::item)
        .service(crate::routes::project::delete::item)
        .service(crate::routes::project::app::list_apps)
        .service(crate::routes::project::app::create_app)
        .service(crate::routes::project::app::get_app)
        .service(crate::routes::project::app::delete_app)
        .service(crate::routes::project::app::get_app_config)
        .service(crate::routes::project::app::get_env_vars)
        .service(crate::routes::project::app::update_env_vars)
        .service(crate::routes::project::app::delete_env_var)
        .service(crate::routes::project::secret::list)
        .service(crate::routes::project::secret::item)
        .service(crate::routes::project::secret::upsert)
        .service(crate::routes::project::secret::delete)
        .service(crate::routes::project::app::update_ports)
        .service(crate::routes::project::app::update_domain)
        .service(crate::routes::project::discover::discover_containers)
        .service(crate::routes::project::discover::import_containers)
}

fn build_oauth_http_client(settings: &Settings) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .pool_idle_timeout(Duration::from_secs(90))
        .timeout(Duration::from_secs(settings.auth_request_timeout_secs))
        .connect_timeout(Duration::from_secs(settings.auth_connect_timeout_secs))
        .build()
}

pub async fn run(
    listener: TcpListener,
    api_pool: Pool<Postgres>,
    agent_pool: AgentPgPool,
    settings: Settings,
) -> Result<Server, std::io::Error> {
    let settings_arc = Arc::new(settings.clone());
    let api_pool_arc = Arc::new(api_pool.clone());

    // Initialize Prometheus metrics (registers all counters/gauges/histograms)
    crate::metrics::init();

    let settings = web::Data::new(settings);
    let api_pool = web::Data::new(api_pool);
    let agent_pool = web::Data::new(agent_pool);

    let mq_manager = helpers::MqManager::try_new(settings.amqp.connection_string())?;
    let mq_manager = web::Data::new(mq_manager);

    let vault_client = helpers::VaultClient::new(&settings.vault);
    let vault_client = web::Data::new(vault_client);

    let oauth_http_client = build_oauth_http_client(&settings).map_err(std::io::Error::other)?;
    let oauth_http_client = web::Data::new(oauth_http_client);

    let oauth_cache = web::Data::new(middleware::authentication::OAuthCache::new(
        Duration::from_secs(60),
    ));

    // Initialize MCP tool registry
    let mcp_registry = Arc::new(mcp::ToolRegistry::new());
    let mcp_registry = web::Data::new(mcp_registry);

    // Initialize health checker and metrics
    let health_checker = Arc::new(HealthChecker::new(
        api_pool_arc.clone(),
        settings_arc.clone(),
    ));
    let health_checker = web::Data::new(health_checker);

    let health_metrics = Arc::new(HealthMetrics::new(1000));
    let health_metrics = web::Data::new(health_metrics);
    let handoff_store = web::Data::new(Arc::new(InMemoryHandoffStore::new()));

    // Initialize external service connectors (plugin pattern)
    // Connector handles category sync on startup
    let user_service_connector =
        connectors::init_user_service(&settings.connectors, api_pool.clone());
    let dockerhub_connector = connectors::init_dockerhub(&settings.connectors).await;
    let install_service_connector = connectors::init_install_service(&settings.connectors);

    let authorization =
        middleware::authorization::try_new(settings.database.connection_string()).await?;
    let json_config = web::JsonConfig::default().error_handler(|err, _req| {
        //todo
        let msg: String = match err {
            error::JsonPayloadError::Deserialize(err) => format!(
                "{{\"kind\":\"deserialize\",\"line\":{}, \"column\":{}, \"msg\":\"{}\"}}",
                err.line(),
                err.column(),
                err
            ),
            _ => format!("{{\"kind\":\"other\",\"msg\":\"{}\"}}", err),
        };
        error::InternalError::new(msg, http::StatusCode::BAD_REQUEST).into()
    });
    let server = HttpServer::new(move || {
        App::new()
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allow_any_method()
                    .allowed_headers(vec![
                        http::header::AUTHORIZATION,
                        http::header::CONTENT_TYPE,
                        http::header::ACCEPT,
                        http::header::ORIGIN,
                        http::header::HeaderName::from_static("x-requested-with"),
                    ])
                    .expose_any_header()
                    .max_age(3600),
            )
            .wrap(TracingLogger::default())
            .wrap(authorization.clone())
            .wrap(middleware::authentication::Manager::new())
            .wrap(Compress::default())
            .wrap(middleware::prometheus::PrometheusMetrics)
            .app_data(health_checker.clone())
            .app_data(health_metrics.clone())
            .app_data(handoff_store.clone())
            .app_data(oauth_http_client.clone())
            .app_data(oauth_cache.clone())
            .service(
                web::scope("/health_check")
                    .service(routes::health_check)
                    .service(routes::health_metrics),
            )
            .service(
                web::scope("/metrics")
                    .service(routes::prometheus_metrics),
            )
            .service(
                web::scope("/client")
                    .service(routes::client::add_handler)
                    .service(routes::client::update_handler)
                    .service(routes::client::enable_handler)
                    .service(routes::client::disable_handler),
            )
            .service(
                web::scope("/test")
                    .service(routes::test::deploy::handler)
                    .service(routes::test::stack_view::test_stack_view),
            )
            .service(
                web::scope("/rating")
                    .service(routes::rating::anonymous_get_handler)
                    .service(routes::rating::anonymous_list_handler)
                    .service(routes::rating::user_add_handler)
                    .service(routes::rating::user_delete_handler)
                    .service(routes::rating::user_edit_handler),
            )
            .service(project_scope("/project"))
            .service(project_scope("/api/v1/project"))
            .service(
                web::scope("/dockerhub")
                    .service(crate::routes::dockerhub::search_namespaces)
                    .service(crate::routes::dockerhub::list_repositories)
                    .service(crate::routes::dockerhub::list_tags)
                    .service(crate::routes::dockerhub::log_event),
            )
            .service(
                web::scope("/admin")
                    .service(
                        web::scope("/rating")
                            .service(routes::rating::admin_get_handler)
                            .service(routes::rating::admin_list_handler)
                            .service(routes::rating::admin_edit_handler)
                            .service(routes::rating::admin_delete_handler),
                    )
                    .service(
                        web::scope("/project")
                            .service(crate::routes::project::get::admin_list)
                            .service(crate::routes::project::compose::admin),
                    )
                    .service(
                        web::scope("/client")
                            .service(routes::client::admin_enable_handler)
                            .service(routes::client::admin_update_handler)
                            .service(routes::client::admin_disable_handler),
                    )
                    .service(
                        web::scope("/agreement")
                            .service(routes::agreement::admin_add_handler)
                            .service(routes::agreement::admin_update_handler)
                            .service(routes::agreement::get_handler),
                    ),
            )
            .service(
                web::scope("/api")
                    .service(
                        web::scope("/agreement")
                            .service(crate::routes::agreement::user_add_handler)
                            .service(crate::routes::agreement::get_handler)
                            .service(crate::routes::agreement::accept_handler),
                    )
                    .service(crate::routes::marketplace::categories::list_handler)
                             .service(
                                  web::scope("/templates")
                                      .service(crate::routes::marketplace::public::list_handler)
                                      .service(crate::routes::marketplace::creator::mine_handler)
                                      .service(crate::routes::marketplace::creator::analytics_handler)
                                      .service(
                                          crate::routes::marketplace::creator::self_vendor_profile_handler,
                                      )
                                     .service(
                                         crate::routes::marketplace::creator::create_onboarding_link_handler,
                                     )
                                     .service(
                                         crate::routes::marketplace::creator::complete_onboarding_handler,
                                     )
                                     .service(crate::routes::marketplace::creator::my_reviews_handler)
                                     .service(
                                         crate::routes::marketplace::creator::vendor_profile_status_handler,
                                     )
                                      .service(crate::routes::marketplace::creator::create_handler)
                                      .service(crate::routes::marketplace::creator::update_handler)
                                      .service(
                                          crate::routes::marketplace::creator::presign_asset_upload_handler,
                                      )
                                      .service(
                                          crate::routes::marketplace::creator::finalize_asset_upload_handler,
                                      )
                                      .service(
                                          crate::routes::marketplace::creator::presign_asset_download_handler,
                                      )
                                      .service(crate::routes::marketplace::creator::submit_handler)
                                      .service(crate::routes::marketplace::creator::resubmit_handler)
                                     .service(crate::routes::marketplace::public::detail_handler)
                                     .service(crate::routes::marketplace::public::increment_view_count_handler)
                                     .service(crate::routes::marketplace::public::increment_deploy_count_handler),
                    )
                    .service(
                        web::scope("/v1/agent")
                            .service(routes::agent::register_handler)
                            .service(routes::agent::enqueue_handler)
                            .service(routes::agent::wait_handler)
                            .service(routes::agent::report_handler)
                            .service(routes::agent::notifications_handler)
                            .service(routes::agent::snapshot_handler)
                            .service(routes::agent::project_snapshot_handler)
                            .service(routes::agent::login_handler)
                            .service(routes::agent::link_handler)
                            .service(routes::agent::agent_audit_ingest_handler)
                            .service(routes::agent::agent_audit_query_handler),
                    )
                    .service(
                        web::scope("/v1/templates")
                            .service(crate::routes::marketplace::creator::presign_asset_upload_handler)
                            .service(crate::routes::marketplace::creator::finalize_asset_upload_handler)
                            .service(
                                crate::routes::marketplace::creator::presign_asset_download_handler,
                            )
                            .service(crate::routes::marketplace::public::detail_handler),
                    )
                    .service(
                        web::scope("/v1/marketplace")
                            .service(crate::routes::marketplace::public::install_script_handler)
                            .service(crate::routes::marketplace::public::download_stack_handler)
                            .service(crate::routes::marketplace::public::deploy_complete_handler)
                            .service(web::scope("/agents").service(
                                crate::routes::marketplace::agent::register_marketplace_agent_handler,
                            )),
                    )
                    .service(
                        web::scope("/v1/deployments")
                            .service(routes::deployment::capabilities_handler)
                            .service(routes::deployment::events_handler)
                            .service(routes::deployment::list_handler)
                            .service(routes::deployment::plan_handler)
                            .service(routes::deployment::state_handler)
                            .service(routes::deployment::status_by_hash_handler)
                            .service(routes::deployment::status_handler)
                            .service(routes::deployment::status_by_project_handler)
                            .service(routes::deployment::force_complete_handler),
                    )
                    .service(
                        web::scope("/v1/handoff")
                            .service(routes::handoff::mint_handler)
                            .service(routes::handoff::mint_account_handler)
                            .service(routes::handoff::resolve_handler),
                    )
                    .service(
                        web::scope("/v1/commands")
                            .service(routes::command::create_handler)
                            .service(routes::command::list_handler)
                            .service(routes::command::get_handler)
                            .service(routes::command::cancel_handler),
                    )
                    .service(
                        web::scope("/v1/pipes")
                            .service(routes::pipe::create_template_handler)
                            .service(routes::pipe::create_instance_handler)
                            .service(routes::pipe::list_templates_handler)
                            .service(routes::pipe::list_local_instances_handler)
                            .service(routes::pipe::list_instances_handler)
                            .service(routes::pipe::get_template_handler)
                            .service(routes::pipe::get_instance_handler)
                            .service(routes::pipe::delete_template_handler)
                            .service(routes::pipe::delete_instance_handler)
                            .service(routes::pipe::update_instance_status_handler)
                            .service(routes::pipe::deploy_pipe_handler)
                            .service(routes::pipe::list_executions_handler)
                            .service(routes::pipe::get_execution_handler)
                            .service(routes::pipe::replay_execution_handler)
                            .service(routes::pipe::dag::add_step_handler)
                            .service(routes::pipe::dag::list_steps_handler)
                            .service(routes::pipe::dag::get_step_handler)
                            .service(routes::pipe::dag::update_step_handler)
                            .service(routes::pipe::dag::delete_step_handler)
                            .service(routes::pipe::dag::add_edge_handler)
                            .service(routes::pipe::dag::list_edges_handler)
                            .service(routes::pipe::dag::delete_edge_handler)
                            .service(routes::pipe::dag::validate_dag_handler)
                            .service(routes::pipe::dag::execute_dag_handler)
                            .service(routes::pipe::dag::list_step_executions_handler)
                            // Streaming: SSE execution stream
                            .service(routes::pipe::stream::execution_stream_handler)
                            // Field matching
                            .service(routes::pipe::field_match_handler)
                            // Resilience: DLQ + Circuit Breaker
                            .service(routes::pipe::resilience::list_dlq_handler)
                            .service(routes::pipe::resilience::create_dlq_handler)
                            .service(routes::pipe::resilience::get_dlq_handler)
                            .service(routes::pipe::resilience::retry_dlq_handler)
                            .service(routes::pipe::resilience::discard_dlq_handler)
                            .service(routes::pipe::resilience::get_circuit_breaker_handler)
                            .service(routes::pipe::resilience::update_circuit_breaker_handler)
                            .service(routes::pipe::resilience::record_failure_handler)
                            .service(routes::pipe::resilience::record_success_handler)
                            .service(routes::pipe::resilience::reset_circuit_breaker_handler),
                    )
                    .service(
                        web::scope("/admin")
                            .service(
                                web::scope("/templates")
                                    .service(
                                        crate::routes::marketplace::admin::list_submitted_handler,
                                    )
                                     .service(crate::routes::marketplace::admin::detail_handler)
                                     .service(crate::routes::marketplace::admin::approve_handler)
                                     .service(crate::routes::marketplace::admin::reject_handler)
                                     .service(
                                         crate::routes::marketplace::admin::needs_changes_handler,
                                     )
                                     .service(crate::routes::marketplace::admin::unapprove_handler)
                                     .service(crate::routes::marketplace::admin::security_scan_handler)
                                     .service(crate::routes::marketplace::admin::pricing_handler)
                                     .service(crate::routes::marketplace::admin::update_verifications_handler)
                                     .service(crate::routes::marketplace::admin::update_vendor_profile_handler),
                             )
                             .service(
                                 web::scope("/marketplace")
                                     .service(crate::routes::marketplace::admin::list_plans_handler),
                             ),
                    ),
            )
            .service(
                web::scope("/cloud")
                    .service(crate::routes::cloud::get::item)
                    .service(crate::routes::cloud::get::list)
                    .service(crate::routes::cloud::add::add)
                    .service(crate::routes::cloud::update::item)
                    .service(crate::routes::cloud::delete::item),
            )
            .service(
                web::scope("/server")
                    .service(crate::routes::server::get::item)
                    .service(crate::routes::server::get::list)
                    .service(crate::routes::server::get::list_by_project)
                    .service(crate::routes::server::update::item)
                    .service(crate::routes::server::delete::delete_preview)
                    .service(crate::routes::server::delete::item)
                    .service(crate::routes::server::secret::list)
                    .service(crate::routes::server::secret::item)
                    .service(crate::routes::server::secret::upsert)
                    .service(crate::routes::server::secret::delete)
                    .service(crate::routes::server::cloud_firewall::configure)
                    .service(crate::routes::server::ssh_key::generate_key)
                    .service(crate::routes::server::ssh_key::upload_key)
                    .service(crate::routes::server::ssh_key::get_public_key)
                    .service(crate::routes::server::ssh_key::authorize_public_key)
                    .service(crate::routes::server::ssh_key::validate_key)
                    .service(crate::routes::server::ssh_key::delete_key),
            )
            .service(
                web::scope("/agreement")
                    .service(crate::routes::agreement::user_add_handler)
                    .service(crate::routes::agreement::get_handler)
                    .service(crate::routes::agreement::accept_handler),
            )
            .service(
                web::scope("/chat")
                    .service(crate::routes::chat::get::item)
                    .service(crate::routes::chat::upsert::item)
                    .service(crate::routes::chat::delete::item),
            )
            .service(web::resource("/mcp").route(web::get().to(mcp::mcp_websocket)))
            .service(
                actix_files::Files::new("/editor", "./web/dist")
                    .index_file("index.html"),
            )
            .app_data(json_config.clone())
            .app_data(api_pool.clone())
            .app_data(agent_pool.clone())
            .app_data(mq_manager.clone())
            .app_data(vault_client.clone())
            .app_data(mcp_registry.clone())
            .app_data(web::Data::new(authorization.clone()))
            .app_data(user_service_connector.clone())
            .app_data(install_service_connector.clone())
            .app_data(dockerhub_connector.clone())
            .app_data(settings.clone())
    })
    .listen(listener)?
    .run();

    Ok(server)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{web, App, HttpResponse, HttpServer};
    use std::net::TcpListener;

    async fn slow_ok() -> HttpResponse {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        HttpResponse::Ok().finish()
    }

    #[tokio::test]
    async fn oauth_http_client_respects_configured_request_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind port");
        let port = listener.local_addr().unwrap().port();
        let address = format!("http://127.0.0.1:{port}/slow");

        let server = HttpServer::new(|| App::new().route("/slow", web::get().to(slow_ok)))
            .listen(listener)
            .unwrap()
            .run();

        let _server = tokio::spawn(server);

        let settings = Settings {
            auth_url: address.clone(),
            auth_request_timeout_secs: 1,
            auth_connect_timeout_secs: 1,
            ..Settings::default()
        };

        let client = build_oauth_http_client(&settings).expect("build oauth client");
        let started_at = std::time::Instant::now();
        let err = client
            .get(&address)
            .send()
            .await
            .expect_err("request should time out");

        assert!(err.is_timeout(), "expected timeout, got: {err}");
        assert!(
            started_at.elapsed() < Duration::from_millis(1400),
            "client timeout should fail before upstream responds"
        );
    }
}
