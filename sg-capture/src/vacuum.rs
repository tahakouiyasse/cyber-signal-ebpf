//! `vacuum.rs` — High-frequency channel processing loop.
//!
//! # Architecture
//! Following the Distributor pattern, vacuum workers no longer poll the kernel's
//! mmap layer directly. Instead, each worker consumes pre-parsed, ABI-validated
//! `SignalFrame`s from a dedicated, lock-free RAM channel populated by the
//! coordinator thread.
//!
//! # Zero-Jitter invariants
//! | Invariant | Mechanism |
//! |-----------|-----------|
//! | No heap allocation post-init | `ArrayVec<SignalFrame, BATCH_SIZE>` on stack |
//! | No `unwrap()` in data path | Strict explicit matching on channel states |
//! | No raw memory pointers | Zero-copy casting moved entirely to Distributor |
//! | No `println!` in poll loop | `log::warn!` / `log::error!` are rate-limited |
//! | No `Mutex`/`RwLock` on hot path | Exclusive ownership of the channel Receiver |
//! | Smart Backoff on Idle | Thread yields when the inbound RAM channel is empty |

use arrayvec::ArrayVec;
use crossbeam_channel::TryRecvError;
use log::warn;
use sg_common::SignalFrame;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::task;

use crate::dispatch::{try_dispatch, DispatchReceiver, DispatchSender};
use crate::metrics::Metrics;

/// Number of frames drained from the channel per processing iteration.
///
/// CONTROLLER.md §10: `BATCH_SIZE = 256`. Must equal this value exactly.
pub const BATCH_SIZE: usize = 256;

/// Nanoseconds of monotonic timestamp allowed to decrease between consecutive
/// frames from the *same* CPU before we classify it as a clock anomaly.
const TIMESTAMP_SLACK_NS: u64 = 0;

/// State passed into the spawn_blocking closure.
///
/// Refactored to accept a `DispatchReceiver` instead of an Aya `RingBuf`.
pub struct VacuumWorkerConfig {
    pub cpu_id: usize,
    pub tx: DispatchSender,   // Outbound pipeline / Telemetry
    pub rx: DispatchReceiver, // Inbound pipeline from Distributor
    pub metrics: Arc<Metrics>,
    pub shutdown: Arc<AtomicBool>,
}

/// Entry point for a single per-CPU vacuum worker.
/// Spawns a dedicated thread that performs CPU pinning to ensure cache-local processing.
pub fn spawn_vacuum_worker(config: VacuumWorkerConfig) -> task::JoinHandle<()> {
    task::spawn_blocking(move || {
        // Attempt to pin the worker to its designated CPU to eliminate cross-core cache invalidation.
        // If pinning fails (e.g., due to OS restrictions), we issue a warning but continue execution.
        let core_ids = core_affinity::get_core_ids().unwrap_or_default();
        if let Some(core) = core_ids.get(config.cpu_id) {
            if !core_affinity::set_for_current(*core) {
                warn!(
                    "Failed to pin vacuum worker to CPU {}. Running with standard OS scheduler.",
                    config.cpu_id
                );
            }
        }

        vacuum_entry(config);
    })
}

/// Synchronous vacuum entry point — called inside `spawn_blocking`.
fn vacuum_entry(config: VacuumWorkerConfig) {
    let VacuumWorkerConfig {
        cpu_id,
        tx,
        rx,
        metrics,
        shutdown,
    } = config;

    // -------------------------------------------------------------------------
    // CPU PINNING — Strict isolation requirement.
    // -------------------------------------------------------------------------
    let core_id = core_affinity::CoreId { id: cpu_id };
    if !core_affinity::set_for_current(core_id) {
        panic!(
            "FATAL: failed to pin vacuum worker to CPU {cpu_id}. \
             Aborting to prevent cross-core cache invalidation."
        );
    }
    log::info!("Vacuum worker processing shard live on CPU {cpu_id}");

    // Stack-allocated batch accumulator. Inline storage, zero heap allocation.
    let mut batch: ArrayVec<SignalFrame, BATCH_SIZE> = ArrayVec::new();
    let mut last_ts_ns: u64 = 0;

    // -------------------------------------------------------------------------
    // Processing Pool Hot Path
    // -------------------------------------------------------------------------
    loop {
        if shutdown.load(Ordering::Relaxed) {
            log::info!("Vacuum worker {cpu_id}: shutdown signal observed, draining batch");
            break;
        }

        batch.clear(); // O(1) reset of internal pointer

        // --- Drain up to BATCH_SIZE frames from the RAM channel -------------
        for _ in 0..BATCH_SIZE {
            match rx.try_recv() {
                Ok(frame) => {
                    // ---------------------------------------------------------
                    // ABI Validation: Monotonic timestamp check
                    // ---------------------------------------------------------
                    let ts = frame.timestamp_ns;
                    if ts < last_ts_ns.saturating_sub(TIMESTAMP_SLACK_NS) {
                        warn!(
                            "CPU {cpu_id}: chronological regression detected \
                             (prev={last_ts_ns} ns, curr={ts} ns) — frame dropped"
                        );
                        metrics.record_drop(cpu_id);
                        continue;
                    }
                    last_ts_ns = ts;

                    // Push is guaranteed infallible due to BATCH_SIZE constraints
                    let _ = batch.try_push(frame);
                }
                Err(TryRecvError::Empty) => {
                    // Channel is temporarily dry, flush whatever we managed to batch
                    break;
                }
                Err(TryRecvError::Disconnected) => {
                    // Upstream distributor has closed down. Terminate immediately.
                    log::warn!(
                        "CPU {cpu_id}: Upstream distributor disconnected. Shuting down worker."
                    );
                    break;
                }
            }
        }

        // --- Guard: If no data was received, yield CPU execution to avoid spinning
        if batch.is_empty() {
            std::thread::yield_now();
            continue;
        }

        // --- Dispatch validated batch to the scoring/arena layers -----------
        for frame in batch.drain(..) {
            if try_dispatch(&tx, frame, cpu_id, &metrics) {
                metrics.record_ok(cpu_id);
            }
        }
    }

    log::info!("Vacuum worker {cpu_id}: pipeline drained cleanly, thread exiting");
}
