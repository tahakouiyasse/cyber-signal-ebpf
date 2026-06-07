// Map key constants shared between the eBPF loader (sg-capture) and the
// kernel program (sg-ebpf). Both sides must agree on these values at compile
// time — there is no negotiation protocol at runtime.
//
// EVENTS_PIN is a BPF filesystem path, not a socket address. It must be a
// &'static str so it can be passed to aya's ProgramFd::pin without an
// allocation. String is forbidden in no_std; &'static str is the only option.
//
// DENY_MAP_ID is the BPF map file descriptor index as pinned by the loader.
// It is a const u32, not a static mut, because the value never changes after
// the loader completes initialization and mutability would permit data races
// in multi-threaded userspace without a synchronization primitive.

/// BPF filesystem pin path for the per-CPU signal ring buffers.
/// Pinning makes the map visible to hot-reload without dropping live traffic.
pub const EVENTS_PIN: &str = "/sys/fs/bpf/cyber_signals";

/// Stable numeric identifier for the deny-list hash map.
/// The eBPF program uses this to locate the map via bpf_map_lookup_elem.
pub const DENY_MAP_ID: u32 = 1;