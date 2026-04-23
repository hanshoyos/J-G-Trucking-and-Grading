use std::collections::VecDeque;

use chrono::{DateTime, Duration, Utc};

// ─────────────────────────────────────────────────────────────
//  TimeWindow
// ─────────────────────────────────────────────────────────────

/// A sliding time window that tracks (timestamp, event_id) pairs.
///
/// Events outside the window age (`window_secs`) are evicted on each
/// `push` and on explicit `evict_old` calls.
pub struct TimeWindow {
    pub window_secs: u64,
    /// Ordered oldest-first: (event_timestamp, event_id).
    events: VecDeque<(DateTime<Utc>, String)>,
}

impl TimeWindow {
    /// Create a new empty window with the given age limit.
    pub fn new(window_secs: u64) -> Self {
        Self {
            window_secs,
            events: VecDeque::new(),
        }
    }

    /// Push a new (ts, event_id) pair, then evict stale entries.
    pub fn push(&mut self, ts: DateTime<Utc>, event_id: String) {
        self.events.push_back((ts, event_id));
        self.evict_old(Utc::now());
    }

    /// Remove all entries whose timestamp is older than `now - window_secs`.
    pub fn evict_old(&mut self, now: DateTime<Utc>) {
        let cutoff = now - Duration::seconds(self.window_secs as i64);
        while let Some((ts, _)) = self.events.front() {
            if *ts < cutoff {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }

    /// Number of events currently in the window.
    pub fn count(&self) -> usize {
        self.events.len()
    }

    /// Snapshot of all event IDs currently in the window.
    pub fn event_ids(&self) -> Vec<String> {
        self.events.iter().map(|(_, id)| id.clone()).collect()
    }

    /// Earliest event timestamp in the window, if any.
    pub fn first_seen(&self) -> Option<DateTime<Utc>> {
        self.events.front().map(|(ts, _)| *ts)
    }

    /// Latest event timestamp in the window, if any.
    pub fn last_seen(&self) -> Option<DateTime<Utc>> {
        self.events.back().map(|(ts, _)| *ts)
    }

    /// `true` when the window holds no events.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_and_evict() {
        let mut w = TimeWindow::new(60);
        let old_ts = Utc::now() - Duration::seconds(120);
        let new_ts = Utc::now();

        w.push(old_ts, "old-event".to_string());
        w.push(new_ts, "new-event".to_string());

        // evict_old with "now" should remove the old entry
        w.evict_old(Utc::now());
        assert_eq!(w.count(), 1);
        assert_eq!(w.event_ids(), vec!["new-event"]);
    }
}
