// sg-ebpf/src/filter.rs
// Phase 2.5 — Agent 2 submission (hardened)
//
// WHY explicit match instead of ? operator on get_ptr_mut:
//   The `?` operator desugars to a call into core::ops::Try::branch(), which
//   under build-std on bpfel-unknown-none may pull in a panic_fmt symbol via
//   the NoneError path even when the None arm only returns None. Explicit
//   match { Some(x) => x, None => return None } produces a direct conditional
//   branch with no trait dispatch and no panic symbol emission.
use aya_ebpf::macros::map;
use aya_ebpf::maps::PerCpuArray;
use crate::maps;
use crate::proto_view::ProtoView;

/// Canonical PPS threshold. Matches CONTROLLER.md §10 exactly.
/// Defined locally because this constant is eBPF-internal; it does not cross
/// the ABI boundary and does not belong in sg-common.
const MAXPPS_THRESHOLD: u64 = 1_000_000;

/// Accepted packet descriptor returned to main.rs.
pub struct FilterResult {
    pub flow_hash: u64,
    pub pps_delta: u32,
}

/// Per-CPU packet rate counter. Single slot — PerCpuArray is inherently
/// per-CPU; the kernel presents a different memory location per CPU.
/// No atomic operations needed: the BPF program is non-preemptible on a
/// given CPU — only one execution context writes this slot at a time.
#[map]
static PPS_COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Evaluate a parsed packet against the deny list and PPS rate limit.
///
/// Evaluation order (non-negotiable per CONTROLLER.md §5.2):
///   1. Hash the 5-tuple (murmur3, unrolled, zero panic paths).
///   2. Deny check — denied flows never increment the PPS counter.
///   3. PPS threshold check — rate-limited flows return None immediately.
///   4. PPS counter increment (saturating — no overflow panic path).
///   5. Return FilterResult.
///
/// WHY #[inline(always)]:
///   Same verifier-pass argument as proto_view::inspect — inlining keeps all
///   map accesses in the xdp_ingress instruction stream so the verifier proves
///   them in a single pass.
#[inline(always)]
pub fn select(view: &ProtoView) -> Option<FilterResult> {
    let flow_hash = murmur3_13(
        view.src_ip,
        view.dst_ip,
        view.src_port,
        view.dst_port,
        view.proto,
    ) as u64;

    // Deny check before PPS counter read.
    // WHY before PPS: a denied flow touching the PPS counter would corrupt the
    // rate-limit signal for legitimate traffic sharing the same counter slot.
    if maps::deny_check(flow_hash) {
        return None;
    }

    // PPS counter access.
    //
    // WHY get_ptr_mut(0) and not get(0):
    //   get() returns &T (immutable). We need to write back the incremented
    //   value in the same pointer dereference cycle to avoid a read-modify-write
    //   race with ourselves on the same CPU (not a real race — BPF is
    //   non-preemptible — but the verifier requires a single pointer for the
    //   write, not a re-lookup).
    //
    // WHY explicit match instead of `?`:
    //   See file-level comment. Explicit match eliminates the Try trait path.
    let ctr: *mut u64 = match PPS_COUNTERS.get_ptr_mut(0) {
        Some(p) => p,
        // None here means the map entry does not exist — impossible for index 0
        // in a pre-allocated PerCpuArray with max_entries=1, but the verifier
        // requires us to handle it. Treat as rate-limit exceeded (safe default).
        None    => return None,
    };

    // SAFETY: get_ptr_mut(0) returned Some — the pointer is valid, non-null,
    // aligned to u64, and CPU-local. No other execution context on this CPU
    // can preempt an XDP program to alias this pointer.
    let val = unsafe { *ctr };

    if val >= MAXPPS_THRESHOLD {
        return None;
    }

    // WHY saturating_add and not wrapping_add or plain `+`:
    //   Plain `+` on u64 in release mode does not panic, but saturating_add
    //   is semantically correct: if somehow val reaches u64::MAX (impossible
    //   given the MAXPPS_THRESHOLD guard above, but defensive against future
    //   threshold removal), we stall at MAX rather than wrapping to 0 and
    //   opening the gate.
    // SAFETY: same pointer validity guarantee as the read above.
    unsafe { *ctr = val.saturating_add(1) };

    // WHY min(u32::MAX) before as u32:
    //   val < MAXPPS_THRESHOLD (1_000_000) here, so the cast is safe — 1_000_000
    //   fits in u32. The .min() is a compile-time-visible guard that lets LLVM
    //   prove the cast is non-truncating, eliminating any residual overflow check
    //   the codegen might otherwise emit for the `as` cast.
    let pps_delta = val.min(u32::MAX as u64) as u32;

    Some(FilterResult { flow_hash, pps_delta })
}

/// Murmur3-32 over a 13-byte 5-tuple (seed = 0), fully unrolled.
///
/// Input layout (matches standard murmur3 byte ordering):
///   Block 1 [0..4):  src_ip  (u32, treated as LE word)
///   Block 2 [4..8):  dst_ip  (u32, treated as LE word)
///   Block 3 [8..12): src_port | (dst_port << 16)  (synthetic LE word)
///   Tail   [12):     proto   (1 byte)
///
/// WHY unrolled instead of a loop:
///   A loop over 3 blocks would require a loop bound the verifier can prove.
///   An unrolled sequence has no back-edges — the verifier accepts it
///   unconditionally and the loop-bound check instruction overhead is zero.
///   Three blocks * ~6 instructions = 18 instructions: negligible.
///
/// WHY wrapping_mul / rotate_left instead of plain ops:
///   Murmur3 intentionally overflows. Plain `*` on u32 in Rust is defined to
///   wrap in release mode but LLVM may emit an overflow-check residual in
///   some codegen configurations. wrapping_mul is semantically explicit and
///   guarantees zero overflow-check emission regardless of codegen flags.
#[inline(always)]
fn murmur3_13(
    src_ip:   u32,
    dst_ip:   u32,
    src_port: u16,
    dst_port: u16,
    proto:    u8,
) -> u32 {
    const C1:  u32 = 0xcc9e2d51;
    const C2:  u32 = 0x1b873593;
    const LEN: u32 = 13;

    let mut h1: u32 = 0; // seed

    // Block 1: src_ip
    let mut k1 = src_ip;
    k1 = k1.wrapping_mul(C1);
    k1 = k1.rotate_left(15);
    k1 = k1.wrapping_mul(C2);
    h1 ^= k1;
    h1 = h1.rotate_left(13);
    h1 = h1.wrapping_mul(5).wrapping_add(0xe6546b64);

    // Block 2: dst_ip
    let mut k2 = dst_ip;
    k2 = k2.wrapping_mul(C1);
    k2 = k2.rotate_left(15);
    k2 = k2.wrapping_mul(C2);
    h1 ^= k2;
    h1 = h1.rotate_left(13);
    h1 = h1.wrapping_mul(5).wrapping_add(0xe6546b64);

    // Block 3: src_port | (dst_port << 16)
    //
    // WHY little-endian assembly of the port word:
    //   Murmur3 processes data as little-endian 32-bit words. Placing src_port
    //   in the low 16 bits and dst_port in the high 16 bits matches the byte
    //   order the reference implementation would see if it read 4 bytes from
    //   a little-endian memory layout of [src_port_lo, src_port_hi,
    //   dst_port_lo, dst_port_hi]. This is the canonical port-word encoding
    //   used by other murmur3-over-5tuple implementations for cross-language
    //   hash consistency.
    let ports_word = (src_port as u32) | ((dst_port as u32) << 16);
    let mut k3 = ports_word;
    k3 = k3.wrapping_mul(C1);
    k3 = k3.rotate_left(15);
    k3 = k3.wrapping_mul(C2);
    h1 ^= k3;
    h1 = h1.rotate_left(13);
    h1 = h1.wrapping_mul(5).wrapping_add(0xe6546b64);

    // Tail: proto (byte 12; 13 % 4 == 1 remaining byte)
    let mut kt = proto as u32;
    kt = kt.wrapping_mul(C1);
    kt = kt.rotate_left(15);
    kt = kt.wrapping_mul(C2);
    h1 ^= kt;

    // Finalization: length mix + fmix32 avalanche
    h1 ^= LEN;
    fmix32(h1)
}

/// Murmur3-32 finalizer — full avalanche via XOR-shift-multiply sequence.
/// Constants and shift widths from the reference implementation (Austin
/// Appleby, SMHasher). No loops, no branches, no panic paths.
#[inline(always)]
fn fmix32(mut h: u32) -> u32 {
    h ^= h >> 16;
    h = h.wrapping_mul(0x85ebca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2ae35);
    h ^= h >> 16;
    h
}