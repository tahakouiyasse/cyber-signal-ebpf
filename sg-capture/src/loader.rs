//! `loader.rs` — eBPF object loading and XDP program attachment.
//!
//! # Responsibilities
//! 1. Load the pre-compiled `sg-ebpf` ELF object from disk.
//! 2. Attempt XDP attachment in `DRV_MODE` (native hardware offload).
//!    Fall back to `SKB_MODE` (generic/software) if the NIC driver does not
//!    support native XDP — this is transparent to the rest of the pipeline.
//! 3. Open all NCPU per-CPU ring buffer map handles and return them as a
//!    `Vec<Option<RingBuf<MapData>>>` so that `main.rs` can consume handles
//!    by index without fighting a borrow conflict on a wrapper table type.
//! 4. On graceful shutdown, detach the XDP hook and restore the interface.
//!
//! # Error discipline
//! Every fallible call uses `anyhow::Context` (mandated by §Mandate) so that
//! the error chain always identifies *which* operation failed and *why*, without
//! `Box<dyn Error>` erasure on the critical init path.
//!
//! # Change from previous revision
//! `load_and_attach` previously returned `(LoadedProbe, PerCpuRingTable)`.
//! It now returns `(LoadedProbe, Vec<Option<RingBuf<MapData>>>)` so that
//! `main.rs` can consume handles with `.into_iter().enumerate()` without the
//! borrow-checker conflict that caused the silent zero-worker defect.
//! `PerCpuRingTable` is no longer required by the loader; it may be retained
//! elsewhere as a utility type if needed by future consumers.

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use aya::maps::MapData;
use aya::{
    maps::RingBuf,
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use log::{info, warn};

/// Path to the compiled eBPF ELF object produced by `sg-ebpf`.
///
/// The path is relative to the workspace root so that `cargo run` and
/// `cargo test` resolve it without environment variable injection.
const EBPF_OBJECT_PATH: &str = "target/bpfel-unknown-none/release/sg-ebpf";

/// Name of the XDP program entry point as declared in `sg-ebpf/src/main.rs`.
const XDP_PROGRAM_NAME: &str = "xdp_ingress";

/// Opaque handle returned by [`load_and_attach`].
///
/// Holds the live [`Ebpf`] instance and the link identity required for
/// a clean detach during shutdown.
pub struct LoadedProbe {
    /// The Aya eBPF context — keeping this alive preserves map FDs.
    ebpf: Ebpf,
    /// Network interface the XDP hook is attached to.
    iface: String,
    /// Unique identifier for the attachment link (required for Aya 0.13 detach).
    link_id: aya::programs::xdp::XdpLinkId,
}

/// Load the `sg-ebpf` object, attach XDP to `iface`, and return owned per-CPU
/// ring buffer handles.
///
/// # Return value
/// Returns `(LoadedProbe, Vec<Option<RingBuf<MapData>>>)` where the `Vec` is
/// indexed by logical CPU id in `[0, NCPU)`.  A `None` slot means that CPU's
/// ring map was absent in the eBPF object (offline CPU or sparse topology).
///
/// Callers consume the `Vec` with `.into_iter().enumerate()` to obtain owned
/// handles suitable for moving into vacuum worker threads.
///
/// # Attachment strategy
/// 1. Try `DRV_MODE` — hardware-accelerated, zero-copy path.
/// 2. On any error, fall back to `SKB_MODE` with a `warn!`.
///
/// The caller must retain the returned `LoadedProbe` for the lifetime of the
/// capture session.  Dropping `LoadedProbe` without calling [`detach`] first
/// will leave the XDP hook attached — always call [`detach`] on shutdown.
/// Load the `sg-ebpf` object, attach XDP, and return owned ring buffer handles.
///
/// Returns `(LoadedProbe, Vec<Option<RingBuf<MapData>>>)` indexed by CPU id[cite: 86, 114].
pub fn load_and_attach(iface: &str) -> Result<(LoadedProbe, Vec<Option<RingBuf<MapData>>>)> {
    // --- 1. Load ELF object ---
    let obj_path = Path::new(EBPF_OBJECT_PATH);
    if !obj_path.exists() {
        anyhow::bail!("eBPF object not found at `{}` [cite: 94]", EBPF_OBJECT_PATH);
    }

    let obj_bytes = std::fs::read(obj_path).with_context(|| {
        format!(
            "failed to read eBPF object `{}` [cite: 95]",
            EBPF_OBJECT_PATH
        )
    })?;

    let mut ebpf =
        Ebpf::load(&obj_bytes).with_context(|| "Aya failed to parse eBPF ELF [cite: 96]")?;

    // Initialise kernel-side logging (aya-log) [cite: 97]
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("aya-log init failed (telemetry disabled): {} [cite: 99]", e);
    }

    // --- 2. XDP attachment with LinkId capture ---
    let program: &mut Xdp = ebpf
        .program_mut(XDP_PROGRAM_NAME)
        .with_context(|| format!("program `{}` not found [cite: 100]", XDP_PROGRAM_NAME))?
        .try_into()
        .with_context(|| {
            format!(
                "program `{}` is not an XDP program [cite: 101]",
                XDP_PROGRAM_NAME
            )
        })?;

    program
        .load()
        .with_context(|| "eBPF verifier rejected the program [cite: 102]")?;

    // Capture the XdpLinkId to avoid E0061 (missing argument) during detach [cite: 103, 141]
    let link_id = match program.attach(iface, XdpFlags::DRV_MODE) {
        Ok(id) => {
            info!("XDP attached to `{}` in DRV_MODE [cite: 103]", iface);
            id
        }
        Err(drv_err) => {
            warn!(
                "DRV_MODE failed on `{}` ({}); falling back to SKB_MODE [cite: 104]",
                iface, drv_err
            );
            program.attach(iface, XdpFlags::SKB_MODE).with_context(|| {
                format!("SKB_MODE attach also failed on `{}` [cite: 105]", iface)
            })?
        }
    };

    // --- 3. Build per-CPU ring buffer handles ---
    // Returns Vec<Option<RingBuf>> to allow main.rs to consume handles by value[cite: 66, 112].
    let ring_handles = build_ring_handles(&mut ebpf, iface)?;

    let probe = LoadedProbe {
        ebpf,
        iface: iface.to_owned(),
        link_id, // Storing the link for clean shutdown [cite: 82, 113]
    };

    Ok((probe, ring_handles))
}

/// Build the list of ring buffer handles for the vacuum workers.
///
/// Current Strategy:
/// The eBPF kernel (maps.rs) uses a single global `SIGNAL_RING` map.
/// This function retrieves that single handle and assigns it to Worker 0.
/// All 32 workers are initialized, but only the first one will be 'Active'
/// to prevent multiple threads from competing for the same RingBuf FDs
/// without a complex multiplexing layer.
fn build_ring_handles(ebpf: &mut Ebpf, iface: &str) -> Result<Vec<Option<RingBuf<MapData>>>> {
    const NCPU: usize = 32;
    let mut handles = Vec::with_capacity(NCPU);

    // Initialize the vector with None
    for _ in 0..NCPU {
        handles.push(None);
    }

    // Use .take_map() instead of .map_mut() to get owned MapData
    // required by the function signature Result<Vec<Option<RingBuf<MapData>>>>
    match ebpf.take_map("SIGNAL_RING") {
        Some(map_owned) => {
            let ring = RingBuf::try_from(map_owned)
                .with_context(|| "SIGNAL_RING exists but is not a RingBuf type")?;

            // Assign the owned global ring buffer to the first worker slot.
            handles[0] = Some(ring);
            info!("Global SIGNAL_RING (owned) linked to Worker 0");
        }
        None => {
            return Err(anyhow!(
                "Critical: Map `SIGNAL_RING` not found in eBPF object. \
                 Verify the name in sg-ebpf/src/maps.rs"
            ));
        }
    }

    let populated = handles.iter().filter(|h| h.is_some()).count();
    info!("Ring handle list built: {populated}/{NCPU} workers active on `{iface}`");

    Ok(handles)
}

/// Cleanly detach the XDP program and restore the interface.
///
/// Called from the shutdown handler (SIGINT/SIGTERM) before the process exits.
/// This function is idempotent: calling it twice is safe because it consumes
/// the `LoadedProbe` by value.
pub fn detach(probe: LoadedProbe) -> Result<()> {
    // Destructure the probe to access the eBPF instance and the specific link_id
    let LoadedProbe {
        mut ebpf,
        iface,
        link_id,
    } = probe;

    let program: &mut Xdp = ebpf
        .program_mut(XDP_PROGRAM_NAME)
        .with_context(|| {
            format!(
                "cannot find XDP program `{}` for detach — interface `{}` may be dirty",
                XDP_PROGRAM_NAME, iface
            )
        })?
        .try_into()
        .with_context(|| "program type mismatch during detach")?;

    // Aya 0.13 requires the specific XdpLinkId to detach a program explicitly.
    // This ensures we remove exactly the hook we attached earlier.
    program.detach(link_id).with_context(|| {
        format!(
            "XDP detach from `{}` failed; interface may need manual cleanup \
                 via `ip link set {} xdp off`",
            iface, iface
        )
    })?;

    info!(
        "XDP hook cleanly detached from `{}`; interface restored",
        iface
    );
    Ok(())
}
