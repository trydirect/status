use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

pub fn init() {
    let fmt_layer = fmt::layer().with_target(false);
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();
}
