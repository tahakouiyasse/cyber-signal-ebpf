// SignalFrame is the sole data structure crossing the kernel/userspace ABI
// boundary. Its layout is frozen at 64 bytes, cache-line-aligned, with every
// byte accounted for. The padding field _pad is explicit and zero-initialized
// by construction — never left to the compiler to insert silently, because
// the compiler would insert nothing (repr(C) already forbids reordering) but
// an explicit _pad documents intent and prevents future fields from silently
// shifting offsets.
//
// Do not add fields. Do not remove _pad. Do not change repr.
// A one-byte misalignment = silent data corruption at 100 Mpps.

use static_assertions::const_assert_eq;

#[repr(C, align(64))]
pub struct SignalFrame {
    /// Murmur3 hash of the 5-tuple (src_ip, dst_ip, src_port, dst_port, proto).
    /// Written once by the eBPF program; never mutated by userspace.
    pub flow_hash: u64,

    /// ktime_get_ns() at XDP ingress. Monotonic, nanosecond resolution.
    pub timestamp_ns: u64,

    /// Raw 20-byte IPv4 header, no options. Copied verbatim from the packet.
    /// Userspace decodes fields via byte-offset arithmetic, not field access,
    /// because the kernel may have written a partial header on truncation.
    pub l3_hdr: [u8; 20],

    /// TCP flags (low 9 bits) | protocol (bits 16–23) | reserved.
    /// Encoding is defined in sg-ebpf/src/proto_view.rs and must not be
    /// reinterpreted here — sg-common is layout-only.
    pub l4_flags: u32,

    /// Packets-per-second delta since last SignalFrame for this flow.
    /// Saturates at u32::MAX; overflow is reported via SignalError::PpsOverflow.
    pub pps_delta: u32,
    
    pub cpu_id: u32,
    /// Explicit padding to reach 64 bytes. Always zero. Never repurposed
    /// without a spec delta approved by Agent 0 (CONTROLLER.md §9).
    pub _pad: [u8; 16],
}

// Safety fence: these assertions are the only runtime-independent guarantee
// that the struct matches the canonical layout. If any of them fails to
// compile, the ABI is broken and the build must not proceed.
const_assert_eq!(core::mem::size_of::<SignalFrame>(), 64);
const_assert_eq!(core::mem::align_of::<SignalFrame>(), 64);
const_assert_eq!(core::mem::offset_of!(SignalFrame, flow_hash), 0);
const_assert_eq!(core::mem::offset_of!(SignalFrame, timestamp_ns), 8);
const_assert_eq!(core::mem::offset_of!(SignalFrame, l3_hdr), 16);
const_assert_eq!(core::mem::offset_of!(SignalFrame, l4_flags), 36);
const_assert_eq!(core::mem::offset_of!(SignalFrame, pps_delta), 40);

// NEW: Phase 2.3 CPU routing field
const_assert_eq!(core::mem::offset_of!(SignalFrame, cpu_id), 44);

// UPDATED: _pad now starts after cpu_id (44 + 4 bytes)
const_assert_eq!(core::mem::offset_of!(SignalFrame, _pad), 48);

impl SignalFrame {
    /// Construct a zero-initialized SignalFrame.
    /// The eBPF program calls this before populating fields so that _pad is
    /// guaranteed zero regardless of stack garbage. Userspace should never
    /// construct a SignalFrame — it only reads from the ring buffer.
    #[inline(always)]
    pub const fn zeroed() -> Self {
        Self {
            flow_hash: 0,
            timestamp_ns: 0,
            l3_hdr: [0u8; 20],
            l4_flags: 0,
            pps_delta: 0,
            cpu_id: 0,        // ADDED: For Phase 2.3 Per-CPU routing
            _pad: [0u8; 16],  // UPDATED: Shrunk from 20 to 16 to maintain 64B size
        }
    }
}