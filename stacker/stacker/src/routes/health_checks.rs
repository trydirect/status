use crate::health::{HealthChecker, HealthMetrics};
use actix_web::{get, web, HttpResponse};
use std::sync::Arc;

#[get("")]
pub async fn health_check(checker: web::Data<Arc<HealthChecker>>) -> HttpResponse {
    let health_response = checker.check_all().await;

    if health_response.is_operational() {
        HttpResponse::Ok().json(health_response)
    } else {
        HttpResponse::ServiceUnavailable().json(health_response)
    }
}

#[get("/metrics")]
pub async fn health_metrics(metrics: web::Data<Arc<HealthMetrics>>) -> HttpResponse {
    let stats = metrics.get_all_stats().await;
    HttpResponse::Ok().json(stats)
}

#[get("")]
pub async fn prometheus_metrics() -> HttpResponse {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    let body = String::from_utf8(buffer).unwrap();

    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4; charset=utf-8")
        .body(body)
}
