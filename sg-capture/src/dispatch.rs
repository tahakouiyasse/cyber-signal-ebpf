//! `dispatch.rs` — High-performance, lock-free routing fabric for Ghost-Hunter.
//!
//! # Pipeline Topology
//! 1. `Kernel RingBuf` $\rightarrow$ `Distributor Thread` (Main)
//! 2. `Distributor Thread` $\rightarrow$ [**Inbound Channel**] $\rightarrow$ `Vacuum Workers` (Per-CPU)
//! 3. `Vacuum Workers` $\rightarrow$ [**Outbound Channel**] $\rightarrow$ `sg-arena` shards
//!
//! # Zero-Jitter Design
//! Both channels utilize `crossbeam_channel::bounded` to guarantee zero heap allocation 
//! post-initialization and O(1) wait-free execution on the hot path via `try_send`.

use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};
use sg_common::SignalFrame;
use crate::metrics::Metrics;
use crate::vacuum::BATCH_SIZE;

/// Capacity for the outbound channel toward sg-arena.
/// Sized to absorb 4 full processing batches: 4 × 256 = 1024.
pub const DISPATCH_CAPACITY: usize = BATCH_SIZE * 4;

/// Capacity for the inbound channel from Distributor to Vacuum Workers.
/// Sized slightly larger (8 batches) to prevent XDP drops during heavy network bursts.
pub const INBOUND_CAPACITY: usize = BATCH_SIZE * 8;

pub type DispatchSender = Sender<SignalFrame>;
pub type DispatchReceiver = Receiver<SignalFrame>;

/// Creates an Inbound channel pair used to route frames from the Distributor to a specific Worker.
pub fn inbound_channel() -> (DispatchSender, DispatchReceiver) {
    bounded(INBOUND_CAPACITY)
}

/// Creates an Outbound channel pair used to hand off validated frames from a Worker to `sg-arena`.
pub fn dispatch_channel() -> (DispatchSender, DispatchReceiver) {
    bounded(DISPATCH_CAPACITY)
}

/// Attempt to send a frame into a pipeline segment; records metrics on backpressure.
///
/// Lock-free, allocation-free, and guaranteed non-blocking.
#[inline(always)]
pub fn try_dispatch(
    tx:      &DispatchSender,
    frame:   SignalFrame,
    cpu_id:  usize,
    metrics: &Metrics,
) -> bool {
    match tx.try_send(frame) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) => {
            // Arena or Worker queue is lagging. Drop frame immediately to preserve line rate.
            metrics.record_channel_full(cpu_id);
            false
        }
        Err(TrySendError::Disconnected(_)) => {
            // Downstream consumer has terminated. Silent drop to avoid logging overhead on hot path.
            false
        }
    }
}