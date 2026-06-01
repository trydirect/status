use actix_casbin_auth::{
    casbin::{function_map::key_match2, CoreApi, DefaultModel},
    CasbinService,
};
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx_adapter::SqlxAdapter;
use std::io::{Error, ErrorKind};
use tokio::time::{timeout, Duration};
use tracing::{debug, warn};

pub async fn try_new(db_connection_address: String) -> Result<CasbinService, Error> {
    let m = DefaultModel::from_file("access_control.conf")
        .await
        .map_err(|err| Error::new(ErrorKind::Other, format!("{err:?}")))?;
    let a = SqlxAdapter::new(db_connection_address.clone(), 8)
        .await
        .map_err(|err| Error::new(ErrorKind::Other, format!("{err:?}")))?;

    let policy_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&db_connection_address)
        .await
        .map_err(|err| Error::new(ErrorKind::Other, format!("{err:?}")))?;

    let casbin_service = CasbinService::new(m, a)
        .await
        .map_err(|err| Error::new(ErrorKind::Other, format!("{err:?}")))?;

    casbin_service
        .write()
        .await
        .get_role_manager()
        .write()
        .matching_fn(Some(key_match2), None);

    if std::env::var("STACKER_CASBIN_RELOAD_ENABLED")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE"))
        .unwrap_or(true)
    {
        let interval = std::env::var("STACKER_CASBIN_RELOAD_INTERVAL_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(10);
        start_policy_reloader(
            casbin_service.clone(),
            policy_pool,
            Duration::from_secs(interval),
        );
    }

    Ok(casbin_service)
}
fn start_policy_reloader(
    casbin_service: CasbinService,
    policy_pool: PgPool,
    reload_interval: Duration,
) {
    // Reload Casbin policies only when the underlying rules change.
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(reload_interval);
        let mut last_fingerprint: Option<(i64, i64)> = None;
        loop {
            ticker.tick().await;
            match fetch_policy_fingerprint(&policy_pool).await {
                Ok(fingerprint) => {
                    if last_fingerprint.map_or(true, |prev| prev != fingerprint) {
                        match casbin_service.try_write() {
                            Ok(mut guard) => {
                                match timeout(Duration::from_millis(500), guard.load_policy()).await
                                {
                                    Ok(Ok(())) => {
                                        guard
                                            .get_role_manager()
                                            .write()
                                            .matching_fn(Some(key_match2), None);
                                        debug!("Casbin policies reloaded");
                                        last_fingerprint = Some(fingerprint);
                                    }
                                    Ok(Err(err)) => {
                                        warn!("Failed to reload Casbin policies: {err:?}");
                                    }
                                    Err(_) => {
                                        warn!("Casbin policy reload timed out");
                                    }
                                }
                            }
                            Err(_) => {
                                warn!("Casbin policy reload skipped (write lock busy)");
                            }
                        }
                    }
                }
                Err(err) => warn!("Failed to check Casbin policies: {err:?}"),
            }
        }
    });
}

async fn fetch_policy_fingerprint(pool: &PgPool) -> Result<(i64, i64), sqlx::Error> {
    let max_id: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(id), 0)::bigint FROM casbin_rule")
        .fetch_one(pool)
        .await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM casbin_rule")
        .fetch_one(pool)
        .await?;
    Ok((max_id, count))
}
