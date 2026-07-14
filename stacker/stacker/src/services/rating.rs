// use crate::models::rating::Rating;
// use tracing::Instrument;
// use tracing_subscriber::fmt::format;

// impl Rating {
// pub async fn filter_by(query_string: &str, pool: PgPool) -> Result<()> {
//
//     let url = Url::parse(query_string)?;
//     tracing::debug!("parsed url {:?}", url);
//
//     let query_span = tracing::info_span!("Search for rate by {}.", filter);
//     let r = match sqlx::query_as!(
//         models::Rating,
//         r"SELECT * FROM rating WHERE id=$1 LIMIT 1",
//         filter)
//         .fetch(pool.get_ref())
//         .instrument(query_span)
//         .await;
// }
// }
