// sg-ebpf/src/maps.rs
// Phase 2.3 — Agent 2 submission (hardened)
//
// WHY a single RingBuf instead of an array of RingBufs:
//   BPF_MAP_TYPE_RINGBUF is a single kernel object — one fd, one mmap region.
//   The kernel does not support arrays of ring buffers as a single map type.
//   Per-CPU demultiplexing is achieved by embedding cpu_id in the SignalFrame
//   (the frame already carries flow_hash; cpu_id is written in main.rs before
//   the output call). The userspace vacuum worker reads cpu_id from each frame
//   to route it to the correct per-CPU shard. This satisfies §1.2 (per-CPU
//   isolation) at the consumer side without requiring kernel-side array maps.
//
// WHY Array<u8> for DENY_MAP instead of HashMap:
//   BPF_MAP_TYPE_ARRAY has O(1) lookup with no hash collision risk and no
//   spinlock requirement for read-only eBPF access. The deny list is a
//   presence bitmap: index = flow_hash % 65536, value = 0|1. Collisions
//   (false positives) are acceptable — a denied flow that matches a legitimate
//   flow hash is temporarily suppressed, not dropped from the wire (XDP_PASS).
//   The array is sized to a power of two (65536) for modulo-free masking.
#![allow(clippy::all)]

use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, RingBuf};
use sg_common::SignalFrame;

// DENY_MAP: flow deny bitmap. 65536 entries, one byte each.
// Key = (flow_hash as u32) & 0xFFFF. Value: 0 = allow, non-zero = deny.
// Sized to 65536 — power of two, verifier-friendly modulo elimination.
// No spinlock: eBPF reads only; userspace writes only. No concurrent writers.
#[map]
static DENY_MAP: Array<u8> = Array::with_max_entries(65_536, 0);

// SIGNAL_RING: single BPF_MAP_TYPE_RINGBUF, 256KB capacity.
// All CPUs write to this ring; cpu_id is embedded in SignalFrame.flow_hash
// bits [32..64] by the caller (main.rs step 5) for consumer-side routing.
// 262144 = 256KB — must be a power of two (kernel enforced).
#[map]
pub static SIGNAL_RING: RingBuf = RingBuf::with_byte_size(262_144, 0);

/// Commit a SignalFrame to the ring buffer.
///
/// Returns true on successful output, false if the ring is full.
/// Caller returns XDP_PASS on false — never XDP_DROP.
///
/// WHY output() over reserve/submit:
///   reserve() returns a nullable pointer that the verifier must track across
///   every subsequent branch. Any branch that does not call submit() on the
///   reservation generates a .text.unlikely. cleanup section. output() is
///   atomic — one helper call, no pointer to track, no cleanup path.
#[inline(always)]
pub fn ring_output(frame: &SignalFrame) -> bool {
    SIGNAL_RING.output::<SignalFrame>(frame, 0).is_ok()
}

/// Deny list lookup. Returns true if the flow is on the deny list.
///
/// WHY get() over raw bpf_map_lookup_elem FFI:
///   aya's Array::get() compiles to the same BPF helper call but goes through
///   the CO-RE abstraction layer, preserving portability (INV §1.3).
///   Raw FFI casts break CO-RE and are rejected by CONTROLLER.md §7.
///
/// WHY the modulo is safe (no panic):
///   65536 is a non-zero constant. Integer modulo by a non-zero constant is
///   defined behaviour for all input values of flow_hash. LLVM eliminates
///   the modulo entirely for power-of-two divisors, replacing it with
///   a bitwise AND: (flow_hash as u32) & 0xFFFF. Zero panic path.
#[inline(always)]
pub fn deny_check(flow_hash: u64) -> bool {
    let idx = (flow_hash as u32) & 0xFFFF; // power-of-two mask: no division
    match DENY_MAP.get(idx) {
        Some(val) => *val != 0,
        None      => false, // key absent = allow; treat as not denied
    }
}