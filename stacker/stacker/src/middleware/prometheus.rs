use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use futures_util::future::{ok, LocalBoxFuture, Ready};
use std::task::{Context, Poll};

use crate::metrics::{HTTP_REQUESTS_TOTAL, HTTP_REQUEST_DURATION};

pub struct PrometheusMetrics;

impl<S, B> Transform<S, ServiceRequest> for PrometheusMetrics
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Transform = PrometheusMetricsMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(PrometheusMetricsMiddleware { service })
    }
}

pub struct PrometheusMetricsMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for PrometheusMetricsMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let method = req.method().to_string();
        // Normalize path to avoid high-cardinality labels (replace UUIDs with {id})
        let path = normalize_path(req.path());
        let timer = HTTP_REQUEST_DURATION
            .with_label_values(&[&method, &path])
            .start_timer();

        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;
            let status = res.status().as_u16().to_string();
            timer.observe_duration();
            HTTP_REQUESTS_TOTAL
                .with_label_values(&[&method, &path, &status])
                .inc();
            Ok(res)
        })
    }
}

/// Replace UUID segments with `{id}` to prevent label explosion.
fn normalize_path(path: &str) -> String {
    let uuid_re = regex::Regex::new(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    )
    .expect("invalid regex");
    let numeric_re = regex::Regex::new(r"/\d+(/|$)").expect("invalid regex");

    let result = uuid_re.replace_all(path, "{id}");
    let result = numeric_re.replace_all(&result, "/{id}$1");
    result.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_uuid_path() {
        assert_eq!(
            normalize_path("/api/v1/pipes/550e8400-e29b-41d4-a716-446655440000/dag/steps"),
            "/api/v1/pipes/{id}/dag/steps"
        );
    }

    #[test]
    fn test_normalize_numeric_path() {
        assert_eq!(
            normalize_path("/api/v1/projects/42/deploy"),
            "/api/v1/projects/{id}/deploy"
        );
    }

    #[test]
    fn test_normalize_no_ids() {
        assert_eq!(normalize_path("/health_check"), "/health_check");
    }
}
