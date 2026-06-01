//! Terminal progress helpers — spinners and status indicators.
//!
//! Uses `indicatif` to show animated spinners during long-running
//! operations (deploy, health checks, status polling).

use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

// ── Spinner presets ──────────────────────────────────

/// Braille dots — clean, modern feel.
const TICK_CHARS: &str = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏";

/// Create an animated spinner with the given message.
///
/// Call `spinner.finish_with_message(...)` or one of the helpers
/// (`finish_success`, `finish_error`) when done.
pub fn spinner(message: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_chars(TICK_CHARS)
            .template("{spinner:.cyan} {msg}")
            .expect("invalid spinner template"),
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

/// Create a spinner for a deploy phase (prefixed with step info).
pub fn deploy_spinner(phase: &str) -> ProgressBar {
    spinner(&format!("Deploy: {}", phase))
}

// ── Finish helpers ───────────────────────────────────

/// Finish a spinner with a green check-mark.
pub fn finish_success(pb: &ProgressBar, msg: &str) {
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("  {msg}")
            .expect("invalid template"),
    );
    pb.finish_with_message(format!("✓ {}", msg));
}

/// Finish a spinner with a red cross.
pub fn finish_error(pb: &ProgressBar, msg: &str) {
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("  {msg}")
            .expect("invalid template"),
    );
    pb.finish_with_message(format!("✗ {}", msg));
}

/// Finish a spinner with a warning marker.
pub fn finish_warning(pb: &ProgressBar, msg: &str) {
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("  {msg}")
            .expect("invalid template"),
    );
    pb.finish_with_message(format!("⚠ {}", msg));
}

/// Update the spinner message without stopping it.
pub fn update_message(pb: &ProgressBar, msg: &str) {
    pb.set_message(msg.to_string());
    pb.tick();
}

// ── Status icons ─────────────────────────────────────

/// Return a status icon for a deployment status string.
pub fn status_icon(status: &str) -> &'static str {
    match status {
        "completed" | "confirmed" => "✓",
        "failed" | "error" | "cancelled" => "✗",
        "in_progress" => "⟳",
        "pending" | "wait_start" => "◷",
        "paused" | "wait_resume" => "⏸",
        _ => "?",
    }
}

// ── Health-check status bar ──────────────────────────

/// Create progress display for container health checks.
pub fn health_spinner(total_services: usize) -> ProgressBar {
    spinner(&format!(
        "Checking container health (0/{} running)...",
        total_services
    ))
}

/// Update health check progress.
pub fn update_health(pb: &ProgressBar, running: usize, total: usize) {
    pb.set_message(format!("Container health: {}/{} running", running, total));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_icon_mapping() {
        assert_eq!(status_icon("completed"), "✓");
        assert_eq!(status_icon("failed"), "✗");
        assert_eq!(status_icon("in_progress"), "⟳");
        assert_eq!(status_icon("pending"), "◷");
        assert_eq!(status_icon("paused"), "⏸");
        assert_eq!(status_icon("unknown_status"), "?");
    }
}
