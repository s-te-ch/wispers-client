//! Client-hub round-trip time estimation.
//!
//! Every unary RPC and every serving-stream open yields one sample: observed
//! wall time minus the processing time the hub reports for itself (the
//! `wispers-server-time-usec` response header, or
//! `Welcome.server_side_init_latency_usec` on the stream).
//!
//! The estimate is the minimum over a sample window limited by both time and
//! sample size.

use std::collections::VecDeque;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

const MAX_SAMPLES: usize = 8;
const MAX_AGE: Duration = Duration::from_secs(5 * 60);

/// Windowed-minimum RTT estimator, shared between `HubClient` instances to get
/// more samples.
#[derive(Default)]
pub(crate) struct RttEstimator {
    samples: Mutex<VecDeque<(Instant, Duration)>>,
}

impl RttEstimator {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The current estimate, or `None` if there are no samples yet.
    pub(crate) fn estimate(&self) -> Option<Duration> {
        let now = Instant::now();
        let samples = self.samples.lock().unwrap_or_else(PoisonError::into_inner);
        let get_rtt = |(_, rtt): &(Instant, Duration)| *rtt;

        // Use the minimum from the allowed time window, except if it's empty.
        // In that case, use the minimum from the samples we still have - it's
        // still a better estimate than None even if stale.
        let mut estimate = samples
            .iter()
            .filter(|(t, _)| now.duration_since(*t) < MAX_AGE)
            .map(get_rtt)
            .min();
        if estimate.is_none() {
            estimate = samples.iter().map(get_rtt).min()
        }
        estimate
    }

    /// Adds a sample to the window.
    pub(crate) fn observe(&self, sample: Duration) {
        let now = Instant::now();
        let mut samples = self.samples.lock().unwrap_or_else(PoisonError::into_inner);
        samples.retain(|(t, _)| now.duration_since(*t) < MAX_AGE);
        if samples.len() == MAX_SAMPLES {
            samples.pop_front();
        }
        samples.push_back((now, sample));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_before_first_sample() {
        assert_eq!(RttEstimator::new().estimate(), None);
    }

    #[test]
    fn estimate_is_window_minimum() {
        let rtt = RttEstimator::new();
        for ms in [40, 25, 60] {
            rtt.observe(Duration::from_millis(ms));
        }
        assert_eq!(rtt.estimate(), Some(Duration::from_millis(25)));
    }

    #[test]
    fn old_samples_fall_out_of_the_window() {
        let rtt = RttEstimator::new();
        rtt.observe(Duration::from_millis(1));
        for _ in 0..MAX_SAMPLES {
            rtt.observe(Duration::from_millis(50));
        }
        assert_eq!(rtt.estimate(), Some(Duration::from_millis(50)));
    }
}
