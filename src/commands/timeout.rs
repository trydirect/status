use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Multi-phase timeout strategy for command execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutStrategy {
    /// Base timeout duration in seconds
    pub base_timeout_secs: u64,

    /// Soft timeout multiplier (default 0.8) - warning phase
    #[serde(default = "default_soft_multiplier")]
    pub soft_multiplier: f64,

    /// Hard timeout multiplier (default 0.9) - SIGTERM phase
    #[serde(default = "default_hard_multiplier")]
    pub hard_multiplier: f64,

    /// Kill timeout multiplier (default 1.0) - SIGKILL phase
    #[serde(default = "default_kill_multiplier")]
    pub kill_multiplier: f64,

    /// Interval for progress reports in seconds
    #[serde(default = "default_progress_interval")]
    pub progress_interval_secs: u64,

    /// Time without progress before considering command stalled (seconds)
    #[serde(default = "default_stall_threshold")]
    pub stall_threshold_secs: u64,

    /// Allow graceful termination with SIGTERM before SIGKILL
    #[serde(default = "default_true")]
    pub allow_graceful_termination: bool,

    /// Enable checkpoint support for resumable operations
    #[serde(default)]
    pub enable_checkpoints: bool,
}

fn default_soft_multiplier() -> f64 {
    0.8
}
fn default_hard_multiplier() -> f64 {
    0.9
}
fn default_kill_multiplier() -> f64 {
    1.0
}
fn default_progress_interval() -> u64 {
    30
}
fn default_stall_threshold() -> u64 {
    300
}
fn default_true() -> bool {
    true
}

impl Default for TimeoutStrategy {
    fn default() -> Self {
        Self {
            base_timeout_secs: 300,
            soft_multiplier: 0.8,
            hard_multiplier: 0.9,
            kill_multiplier: 1.0,
            progress_interval_secs: 30,
            stall_threshold_secs: 300,
            allow_graceful_termination: true,
            enable_checkpoints: false,
        }
    }
}

impl TimeoutStrategy {
    /// Create strategy for backup operations (longer soft phase)
    pub fn backup_strategy(base_timeout_secs: u64) -> Self {
        Self {
            base_timeout_secs,
            soft_multiplier: 0.7,
            hard_multiplier: 0.85,
            kill_multiplier: 1.0,
            progress_interval_secs: 60,
            stall_threshold_secs: 600,
            allow_graceful_termination: true,
            enable_checkpoints: true,
        }
    }

    /// Create strategy for quick operations
    pub fn quick_strategy(base_timeout_secs: u64) -> Self {
        Self {
            base_timeout_secs,
            soft_multiplier: 0.8,
            hard_multiplier: 0.95,
            kill_multiplier: 1.0,
            progress_interval_secs: 5,
            stall_threshold_secs: 60,
            allow_graceful_termination: false,
            enable_checkpoints: false,
        }
    }

    /// Get soft timeout duration
    pub fn soft_timeout(&self) -> Duration {
        Duration::from_secs((self.base_timeout_secs as f64 * self.soft_multiplier) as u64)
    }

    /// Get hard timeout duration
    pub fn hard_timeout(&self) -> Duration {
        Duration::from_secs((self.base_timeout_secs as f64 * self.hard_multiplier) as u64)
    }

    /// Get kill timeout duration
    pub fn kill_timeout(&self) -> Duration {
        Duration::from_secs((self.base_timeout_secs as f64 * self.kill_multiplier) as u64)
    }

    /// Get progress interval
    pub fn progress_interval(&self) -> Duration {
        Duration::from_secs(self.progress_interval_secs)
    }

    /// Get stall threshold
    pub fn stall_threshold(&self) -> Duration {
        Duration::from_secs(self.stall_threshold_secs)
    }
}

/// Current phase of command execution timeout
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeoutPhase {
    /// Normal execution (0-80% of timeout)
    Normal,
    /// Warning phase - command taking longer than expected (80-90%)
    Warning,
    /// Hard termination phase - attempting graceful shutdown (90-100%)
    HardTermination,
    /// Force kill phase - command must be terminated immediately (>100%)
    ForceKill,
}

/// Tracks timeout state for a running command
#[derive(Debug)]
pub struct TimeoutTracker {
    strategy: TimeoutStrategy,
    start_time: Instant,
    last_progress: Instant,
    current_phase: TimeoutPhase,
}

impl TimeoutTracker {
    /// Create a new timeout tracker
    pub fn new(strategy: TimeoutStrategy) -> Self {
        let now = Instant::now();
        Self {
            strategy,
            start_time: now,
            last_progress: now,
            current_phase: TimeoutPhase::Normal,
        }
    }

    /// Report progress (resets stall detection)
    pub fn report_progress(&mut self) {
        self.last_progress = Instant::now();
    }

    /// Get current phase based on elapsed time
    pub fn current_phase(&mut self) -> TimeoutPhase {
        let elapsed = self.start_time.elapsed();

        let phase = if elapsed >= self.strategy.kill_timeout() {
            TimeoutPhase::ForceKill
        } else if elapsed >= self.strategy.hard_timeout() {
            TimeoutPhase::HardTermination
        } else if elapsed >= self.strategy.soft_timeout() {
            TimeoutPhase::Warning
        } else {
            TimeoutPhase::Normal
        };

        // Update internal state if phase changed
        if phase != self.current_phase {
            self.current_phase = phase;
        }

        phase
    }

    /// Check if command has stalled (no progress within threshold)
    pub fn is_stalled(&self) -> bool {
        self.last_progress.elapsed() >= self.strategy.stall_threshold()
    }

    /// Get elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Get time remaining until next phase
    pub fn time_to_next_phase(&self) -> Option<Duration> {
        let elapsed = self.start_time.elapsed();

        match self.current_phase {
            TimeoutPhase::Normal => {
                let soft = self.strategy.soft_timeout();
                if elapsed < soft {
                    Some(soft - elapsed)
                } else {
                    None
                }
            }
            TimeoutPhase::Warning => {
                let hard = self.strategy.hard_timeout();
                if elapsed < hard {
                    Some(hard - elapsed)
                } else {
                    None
                }
            }
            TimeoutPhase::HardTermination => {
                let kill = self.strategy.kill_timeout();
                if elapsed < kill {
                    Some(kill - elapsed)
                } else {
                    None
                }
            }
            TimeoutPhase::ForceKill => None,
        }
    }

    /// Get the timeout strategy
    pub fn strategy(&self) -> &TimeoutStrategy {
        &self.strategy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_strategy() {
        let strategy = TimeoutStrategy::default();
        assert_eq!(strategy.base_timeout_secs, 300);
        assert_eq!(strategy.soft_multiplier, 0.8);
        assert_eq!(strategy.soft_timeout(), Duration::from_secs(240));
        assert_eq!(strategy.hard_timeout(), Duration::from_secs(270));
        assert_eq!(strategy.kill_timeout(), Duration::from_secs(300));
    }

    #[test]
    fn test_backup_strategy() {
        let strategy = TimeoutStrategy::backup_strategy(3600);
        assert_eq!(strategy.base_timeout_secs, 3600);
        assert_eq!(strategy.soft_multiplier, 0.7);
        assert!(strategy.enable_checkpoints);
        assert_eq!(strategy.soft_timeout(), Duration::from_secs(2520)); // 70% of 3600
    }

    #[test]
    fn test_quick_strategy() {
        let strategy = TimeoutStrategy::quick_strategy(60);
        assert_eq!(strategy.base_timeout_secs, 60);
        assert!(!strategy.allow_graceful_termination);
        assert!(!strategy.enable_checkpoints);
    }

    #[test]
    fn test_timeout_tracker_phases() {
        let strategy = TimeoutStrategy {
            base_timeout_secs: 10,
            soft_multiplier: 0.5,
            hard_multiplier: 0.8,
            kill_multiplier: 1.0,
            ..Default::default()
        };

        let mut tracker = TimeoutTracker::new(strategy);
        assert_eq!(tracker.current_phase(), TimeoutPhase::Normal);

        // Note: In real tests, we'd need to mock time or use sleeps
        // This just tests the logic structure
    }

    #[test]
    fn test_progress_reporting() {
        let strategy = TimeoutStrategy::default();
        let mut tracker = TimeoutTracker::new(strategy);

        std::thread::sleep(Duration::from_millis(10));
        tracker.report_progress();

        // Progress should be recent
        assert!(!tracker.is_stalled());
    }

    #[test]
    fn test_time_to_next_phase() {
        let strategy = TimeoutStrategy {
            base_timeout_secs: 100,
            soft_multiplier: 0.8,
            hard_multiplier: 0.9,
            kill_multiplier: 1.0,
            ..Default::default()
        };

        let tracker = TimeoutTracker::new(strategy);
        let time_to_warning = tracker.time_to_next_phase();
        assert!(time_to_warning.is_some());
        // Should be approximately 80 seconds (soft timeout)
        let secs = time_to_warning.unwrap().as_secs();
        assert!(secs >= 79 && secs <= 80);
    }
}
