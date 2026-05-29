use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use stacker::banner;
use stacker::configuration::get_configuration;
use stacker::helpers::AgentPgPool;
use stacker::startup::run;
use stacker::telemetry::{get_subscriber, init_subscriber};
use std::net::TcpListener;
use std::time::Duration;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Display banner
    banner::print_banner();

    let subscriber = get_subscriber("stacker".into(), "info".into());
    init_subscriber(subscriber);

    let settings = get_configuration().expect("Failed to read configuration.");

    tracing::info!(
        db_host = %settings.database.host,
        db_port = settings.database.port,
        db_name = %settings.database.database_name,
        "Connecting to PostgreSQL"
    );

    let connect_options = PgConnectOptions::new()
        .host(&settings.database.host)
        .port(settings.database.port)
        .username(&settings.database.username)
        .password(&settings.database.password)
        .database(&settings.database.database_name)
        .ssl_mode(PgSslMode::Disable);

    // API Pool: For regular user requests (authentication, projects, etc.)
    // Moderate size, fast timeout - these should be quick queries
    let api_pool = PgPoolOptions::new()
        .max_connections(30)
        .min_connections(5)
        .acquire_timeout(Duration::from_secs(5)) // Fail fast if pool exhausted
        .idle_timeout(Duration::from_secs(600))
        .max_lifetime(Duration::from_secs(1800))
        .connect_with(connect_options.clone())
        .await
        .expect("Failed to connect to database (API pool).");

    tracing::info!(
        max_connections = 30,
        min_connections = 5,
        acquire_timeout_secs = 5,
        "API connection pool initialized"
    );

    // Agent Pool: For agent long-polling and command operations
    // Higher capacity to handle many concurrent agent connections
    let agent_pool_raw = PgPoolOptions::new()
        .max_connections(100) // Higher capacity for agent polling
        .min_connections(10)
        .acquire_timeout(Duration::from_secs(15)) // Slightly longer for agent ops
        .idle_timeout(Duration::from_secs(300)) // Shorter idle timeout
        .max_lifetime(Duration::from_secs(1800))
        .connect_with(connect_options)
        .await
        .expect("Failed to connect to database (Agent pool).");

    let agent_pool = AgentPgPool::new(agent_pool_raw);

    tracing::info!(
        max_connections = 100,
        min_connections = 10,
        acquire_timeout_secs = 15,
        "Agent connection pool initialized"
    );

    let address = format!("{}:{}", settings.app_host, settings.app_port);
    banner::print_startup_info(&settings.app_host, settings.app_port);
    tracing::info!("Start server at {:?}", &address);
    let listener = TcpListener::bind(address)
        .unwrap_or_else(|_| panic!("failed to bind to {}", settings.app_port));

    run(listener, api_pool, agent_pool, settings).await?.await
}
