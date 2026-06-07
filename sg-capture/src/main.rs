//! `sg-capture` — CYBER-SIGNAL userspace vacuum engine.
//!
//! # Architecture: The Distributor Pattern
//! The eBPF kernel space operates via a single global `BPF_MAP_TYPE_RINGBUF` to 
//! ensure strict chronological ordering and avoid array-of-maps complexity.
//! To achieve NCPU horizontal scaling in userspace without FD-cloning violations:
//! 
//! 1. **The Distributor Thread:** A singular, high-priority thread owns the unique 
//!    RingBuf handle. It drains the kernel buffer at line-rate and demultiplexes 
//!    the `SignalFrame`s into lock-free RAM channels based on `frame.cpu_id`.
//! 2. **The Worker Pool:** N independent threads consume from these bounded RAM 
//!    channels, executing the heavy entropy/quantum algorithms in parallel 
//!    without causing back-pressure on the kernel's XDP hook.

use std::env;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use log::{info, error, debug};
use sg_common::{NCPU, SignalFrame};
use tokio::signal::unix::{signal, SignalKind};

mod dispatch;
mod loader;
mod metrics;
mod vacuum;

use dispatch::{inbound_channel, dispatch_channel};
use loader::{detach, load_and_attach};
use metrics::{spawn_reporter, Metrics};
use vacuum::{spawn_vacuum_worker, VacuumWorkerConfig};

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Telemetry sink initialisation
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // 2. Parse CLI
    let iface = env::args()
        .nth(1)
        .context("Usage: sg-capture <interface> [optional-worker-count]")?;

    let worker_count: usize = env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(NCPU)
        .min(NCPU);

    // CRITICAL SECURITY: Prevent modulo-by-zero panic in the distributor loop
    ensure!(worker_count > 0, "Fatal: worker_count must be at least 1");

    info!("sg-capture initializing | iface={iface} | workers={worker_count} | NCPU={NCPU}");

    // 3. Load eBPF object & attach XDP
    let (probe, mut ring_handles) = load_and_attach(&iface)
        .with_context(|| format!("failed to attach eBPF probe on `{iface}`"))?;

    // 4. Extract exclusive ownership of the hardware RingBuf (Slot 0)
    let mut global_ring = ring_handles[0]
        .take()
        .context("Architectural Violation: Global SIGNAL_RING handle is missing from Slot 0")?;

    // Shared state
    let metrics  = Arc::new(Metrics::new());
    let shutdown = Arc::new(AtomicBool::new(false));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let mut join_handles = Vec::with_capacity(worker_count);
    let mut worker_tx_channels = Vec::with_capacity(worker_count);

    // 5. Spawn the independent processing pool (Isolated execution cores)
    info!("Provisioning lock-free pipeline shards...");
    for cpu_id in 0..worker_count {
        // Each worker receives its own dedicated inbound channel to eliminate cache-line contention
        let (dist_tx, worker_rx) = inbound_channel();
        worker_tx_channels.push(dist_tx);

        // Establish a shard-isolated outbound channel toward the sg-arena layer
        let (worker_tx, _arena_rx) = dispatch_channel();

        let handle = spawn_vacuum_worker(VacuumWorkerConfig {
            cpu_id,
            tx: worker_tx,  // Outbound path targeting the arena consumer shards
            rx: worker_rx,  // Inbound path fed exclusively by the distributor thread
            metrics: Arc::clone(&metrics),
            shutdown: Arc::clone(&shutdown),
        });
        
        join_handles.push(handle);
        debug!("Pipeline shard {cpu_id} isolated and ready");
    }

    // 6. Spawn the High-Speed Kernel Distributor
    // This thread acts as the bridge between Kernel space and the multi-core Userspace.
    let dist_shutdown = Arc::clone(&shutdown);
    let dist_metrics  = Arc::clone(&metrics);
    
    let distributor_handle = std::thread::Builder::new()
        .name("sg-distributor".to_string())
        .spawn(move || -> Result<()> {
            info!("Distributor thread live — intercepting XDP frames");
            
            // Local backoff counter to prevent L1 cache thrashing during dead network periods
            let mut idle_spins = 0;

            while !dist_shutdown.load(Ordering::Relaxed) {
                // Synchronous, zero-copy drain from shared memory via Aya's RingBuf
                match global_ring.next() {
                    Some(item) => {
                        idle_spins = 0; // Immediate reset of the thread's thermal backoff
                        let raw: &[u8] = &item;

                        if raw.len() == std::mem::size_of::<SignalFrame>() {
                            // High-speed extraction via unaligned pointer read (ensures safety on ring wrap-around)
                            let frame: SignalFrame = unsafe {
                                core::ptr::read_unaligned(raw.as_ptr() as *const SignalFrame)
                            };
                            
                            // Deterministic routing via modulo to distribute load across workers
                            let target_worker = (frame.cpu_id as usize) % worker_count;
                            
                            if let Some(target_tx) = worker_tx_channels.get(target_worker) {
                                // Non-blocking try_send to guarantee zero backpressure on the kernel hook
                                if target_tx.try_send(frame).is_err() {
                                    dist_metrics.record_drop(target_worker);
                                } else {
                                    dist_metrics.record_ok(target_worker);
                                }
                            }
                        } else {
                            // Corrupted frame or anomalous payload size received from XDP
                            dist_metrics.record_drop(0);
                        }
                    }
                    None => {
                        // ANTI-JITTER BACKOFF STRATEGY
                        // Prevents 100% CPU lockup and core thrashing during periods of idle network traffic
                        idle_spins += 1;
                        if idle_spins < 128 {
                            std::hint::spin_loop(); // Ultra-low-latency spin-wait (HFT style)
                        } else if idle_spins < 2048 {
                            std::thread::yield_now(); // Cooperatively yield execution slice to the OS scheduler
                        } else {
                            std::thread::sleep(Duration::from_micros(20)); // Micro-calibrated sleep window
                        }
                    }
                }
            }
            info!("Distributor thread clean exit verified");
            Ok(())
        })
        .context("Failed to spawn the core distributor thread")?;

    // 7. Initialize Metrics Watcher
    spawn_reporter(Arc::clone(&metrics), shutdown_rx);

    // 8. Graceful Shutdown orchestration via Tokio
    let mut sigint  = signal(SignalKind::interrupt()).context("SIGINT hook failed")?;
    let mut sigterm = signal(SignalKind::terminate()).context("SIGTERM hook failed")?;

    tokio::select! {
        _ = sigint.recv()  => { info!("SIGINT received — terminating Ghost-Hunter protocol"); }
        _ = sigterm.recv() => { info!("SIGTERM received — terminating Ghost-Hunter protocol"); }
    }

    info!("Initiating graceful shutdown sequence...");
    shutdown.store(true, Ordering::Release);
    let _ = shutdown_tx.send(true);

    // Barrier: wait for distributor to finish draining
    if let Err(e) = distributor_handle.join() {
        error!("Distributor thread panicked during shutdown: {e:?}");
    }

    // Barrier: wait for all vacuum shards to process remaining queue
    for handle in join_handles {
        if let Err(e) = handle.await {
            error!("Vacuum worker panicked during shutdown: {e:?}");
        }
    }
    info!("All thread shards joined cleanly");

    // Detach eBPF to restore standard NIC behavior
    detach(probe).context(format!("CRITICAL: XDP detach on `{iface}` failed. Run `ip link set {iface} xdp off` manually."))?;

    info!("sg-capture offline. Connection closed.");
    Ok(())
}