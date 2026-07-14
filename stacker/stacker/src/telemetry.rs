use tracing::subscriber::set_global_default;
use tracing::Subscriber;
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_log::LogTracer;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Registry};

pub fn get_subscriber(
    name: String,
    env_filter: String, // Subscriber is a trait for our spans, Send - trait for thread safety to send to another thread, Sync - trait for thread safety share between trheads
) -> impl Subscriber + Send + Sync {
    // when tracing_subscriber is used, env_logger is not needed
    // env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(env_filter));
    let formatting_layer = BunyanFormattingLayer::new(
        name,
        // Output the formatted spans to stdout.
        std::io::stdout,
    );
    // the with method is provided by the SubscriberExt trait for Subscriber exposed by tracing_subscriber
    Registry::default()
        .with(env_filter)
        .with(JsonStorageLayer)
        .with(formatting_layer)
}

pub fn init_subscriber(subscriber: impl Subscriber + Send + Sync) {
    // set_global_default
    //redirect all log's events to the tracing subscriber
    LogTracer::init().expect("Failed to set logger.");
    // Result<Server, std::io::Error>

    set_global_default(subscriber).expect("Failed to set subscriber.");
}
