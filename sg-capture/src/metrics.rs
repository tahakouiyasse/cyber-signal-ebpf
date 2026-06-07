//! `metrics.rs` — Lock-free telemetry counters for the vacuum pipeline.
//!
//! # Design constraints (CONTROLLER.md §3, INV-01)
//! * All counters are `AtomicU64` — no `Mutex`, no heap allocation on update.
//! * The reporting thread reads counters with `Relaxed` ordering (same-thread
//!   monotonicity is sufficient for a 1-second telemetry window).
//! * Drop-rate calculation uses integer-only arithmetic — no floating point in
//!   the hot path, no `f64` division that could generate NaN in edge cases.
//! * The reporter is a single dedicated `std::thread` (not a Tokio task) so
//!   that it does not compete with the async executor or the vacuum threads.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use log::info;

/// Flat array of per-CPU counters.
///
/// Each vacuum thread writes to its own index without synchronisation overhead.
/// The reporting thread reads all indices; a slightly stale read is acceptable
/// for a 1-second window telemetry snapshot.
const NCPU_MAX: usize = sg_common::NCPU;

/// Global metrics structure shared between vacuum threads and the reporter.
///
/// Allocated once during init (`Arc::new`); after that the heap profile is flat.
pub struct Metrics {
    /// Frames successfully validated and dispatched, per CPU.
    pub frames_ok: [AtomicU64; NCPU_MAX],
    /// Frames that failed ABI validation (size or monotonicity), per CPU.
    pub frames_dropped: [AtomicU64; NCPU_MAX],
    /// Ring buffer entries that were available but skipped due to a full
    /// dispatch channel (backpressure events), per CPU.
    pub channel_full: [AtomicU64; NCPU_MAX],
}

impl Metrics {
    /// Construct a zeroed metrics block.
    ///
    /// `AtomicU64` does not implement `Copy`, so we use a macro-generated
    /// const initialiser rather than `Default`.
    pub fn new() -> Self {
        // SAFETY: `AtomicU64::new(0)` is `const` in all stable/nightly versions
        // we target.  The macro expands to an array literal with no heap use.
        macro_rules! zero_array {
            ($n:expr) => {{
                // `std::array::from_fn` takes a closure; the closure captures
                // no state and runs at init time only.
                std::array::from_fn(|_| AtomicU64::new(0))
            }};
        }
        Self {
            frames_ok: zero_array!(NCPU_MAX),
            frames_dropped: zero_array!(NCPU_MAX),
            channel_full: zero_array!(NCPU_MAX),
        }
    }

    /// Increment `frames_ok` for `cpu_id`.  Called on the vacuum hot path.
    ///
    /// `Relaxed` ordering is correct here: the reporting thread does not need
    /// to observe a happens-before relationship; it only needs an approximate
    /// count within the reporting window.
    #[inline(always)]
    pub fn record_ok(&self, cpu_id: usize) {
        if cpu_id < NCPU_MAX {
            self.frames_ok[cpu_id].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Increment `frames_dropped` for `cpu_id`.  Called on the cold error path.
    #[inline(always)]
    pub fn record_drop(&self, cpu_id: usize) {
        if cpu_id < NCPU_MAX {
            self.frames_dropped[cpu_id].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Increment `channel_full` for `cpu_id`.  Called when the dispatch channel
    /// is at capacity and the frame must be discarded.
    #[inline(always)]
    pub fn record_channel_full(&self, cpu_id: usize) {
        if cpu_id < NCPU_MAX {
            self.channel_full[cpu_id].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Aggregate totals across all CPUs (reporting thread only).
    fn totals(&self) -> (u64, u64, u64) {
        let ok = self
            .frames_ok
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum();
        let drop = self
            .frames_dropped
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum();
        let full = self
            .channel_full
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum();
        (ok, drop, full)
    }

    /// Compute drop rate in basis points (1 bp = 0.01%) using integer division.
    ///
    /// Returns `0` when no frames have been processed to avoid divide-by-zero.
    /// Basis points give two decimal places of precision without floating point.
    fn drop_rate_bps(ok: u64, drop: u64) -> u64 {
        let total = ok.saturating_add(drop);
        if total == 0 {
            return 0;
        }
        // Multiply numerator by 10_000 before dividing → basis points.
        drop.saturating_mul(10_000) / total
    }
}

/// Spawn the 1-second telemetry reporter thread.
///
/// The reporter holds an `Arc<Metrics>` and logs a summary line every second.
/// It runs until `shutdown_rx` is closed (the sender is dropped on shutdown).
///
/// # Why `std::thread` and not `tokio::spawn`
/// The reporter must never compete with the vacuum threads for CPU time on the
/// pinned cores.  A `std::thread` scheduled by the OS onto an unpinned core is
/// the correct isolation strategy.  Tokio tasks share the multi-thread executor
/// pool and would introduce jitter.
pub fn spawn_reporter(metrics: Arc<Metrics>, shutdown_rx: tokio::sync::watch::Receiver<bool>) {
    std::thread::Builder::new()
        .name("sg-metrics".into())
        .spawn(move || {
            // Snapshot counters from the previous interval for delta calculation.
            let mut prev_ok: u64 = 0;
            let mut prev_drop: u64 = 0;

            loop {
                // Block for 1 second or until the shutdown watch flips.
                // Using `std::thread::sleep` is appropriate here; this thread
                // does not participate in the async executor.
                std::thread::sleep(Duration::from_secs(1));

                // Check shutdown signal.
                if *shutdown_rx.borrow() {
                    break;
                }

                let (ok, drop, full) = metrics.totals();
                let delta_ok = ok.saturating_sub(prev_ok);
                let delta_drop = drop.saturating_sub(prev_drop);
                let drop_bps = Metrics::drop_rate_bps(delta_ok, delta_drop);

                // Integer display: drop_bps / 100 = whole percent,
                //                  drop_bps % 100 = fractional hundredths.
                info!(
                    "METRICS | frames/s={delta_ok} drops/s={delta_drop} \
                     drop_rate={}.{:02}% channel_full={full}",
                    drop_bps / 100,
                    drop_bps % 100,
                );

                prev_ok = ok;
                prev_drop = drop;
            }

            info!("Metrics reporter thread exiting cleanly");
        })
        .expect("failed to spawn sg-metrics reporter thread");
}
