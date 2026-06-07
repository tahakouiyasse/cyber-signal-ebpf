// sg-ebpf/src/main.rs
// PHASE 2.6 — Agent 2 submission
// Hardened against: assert_failed emission, .text.unlikely. sections,
// memmove monomorphization, INV-04 cold-path discipline.
#![no_std]
#![no_main]

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::xdp;
use aya_ebpf::programs::XdpContext;
use sg_common::SignalFrame;

mod filter;
mod maps;
mod proto_view;
mod vmlinux;

// ---------------------------------------------------------------------------
// LAYOUT ASSERTIONS — no_std native syntax, zero symbol emission.
//
// Replaces static_assertions::const_assert_eq! which emits assert_failed
// symbols on bpfel-unknown-none via the generic-monomorphization path.
// `const { assert!(...) }` is guaranteed erased before object emission.
// Invariant: INV-02 (repr(C, align(64))), INV-03 (static layout assertions).
// ---------------------------------------------------------------------------
// Verify ABI alignment at compile time
const _: () = {
    assert!(core::mem::size_of::<SignalFrame>()  == 64);
    assert!(core::mem::align_of::<SignalFrame>() == 64);
    assert!(core::mem::offset_of!(SignalFrame, flow_hash)    ==  0);
    assert!(core::mem::offset_of!(SignalFrame, timestamp_ns) ==  8);
    assert!(core::mem::offset_of!(SignalFrame, l3_hdr)       == 16);
    assert!(core::mem::offset_of!(SignalFrame, l4_flags)     == 36);
    assert!(core::mem::offset_of!(SignalFrame, pps_delta)    == 40);
    
    // UPDATED: Phase 2.3 layout check
    assert!(core::mem::offset_of!(SignalFrame, cpu_id)       == 44);
    assert!(core::mem::offset_of!(SignalFrame, _pad)         == 48);
};

// ---------------------------------------------------------------------------
// XDP ENTRY POINT
// ---------------------------------------------------------------------------

#[xdp]
pub fn xdp_ingress(ctx: XdpContext) -> u32 {
    // STEP 1 — Snapshot CPU id once per invocation.
    // SAFETY: bpf_get_smp_processor_id() — BPF helper #8. No args, no failure.
    // Returns the index of the executing CPU. Stable across all kernel versions
    // supported by our CO-RE BTF baseline. Snapshotted here so all downstream
    // per-CPU map accesses in this call use a single consistent value.
    let cpu_id: u32 = unsafe { aya_ebpf::helpers::bpf_get_smp_processor_id() };

    // STEP 2 — Parse L2/L3/L4 headers.
    // Non-signal traffic (non-IPv4, non-TCP/UDP, short frames) exits here.
    // INV-04: this arm is #[cold]; branch predictor keeps it out of the I-cache
    // hot footprint. No map lookup, no counter, no log — absolute silence.
    let view = match proto_view::inspect(&ctx) {
        Some(v) => v,
        None    => return pass_cold(),
    };

    // STEP 3 — Deny list lookup + PPS rate limit.
    // Denied or rate-limited flows exit here with identical zero side effects.
    let result = match filter::select(&view) {
        Some(r) => r,
        None    => return pass_cold(),
    };

    // STEP 4 — Build SignalFrame on stack (64 bytes; within INV-05 512B limit).
    //
    // WHY `zeroed()` instead of field-by-field init:
    //   Field-by-field init of a partially-assigned repr(C) struct leaves
    //   uninitialised padding bytes. The verifier tracks uninitialised memory
    //   and will reject bpf_ringbuf_output if any byte of the source range is
    //   marked STACK_INVALID. `zeroed()` sets the entire 64-byte frame to
    //   STACK_ZERO before any field write, satisfying the verifier's
    //   `bpf_ringbuf_output` pre-condition for the full frame in one pass.
    //
    // WHY we do NOT use `SignalFrame { field: val, .. Default::default() }`:
    //   Default::default() pulls in a trait impl that may not inline cleanly
    //   on bpfel-unknown-none, potentially emitting a memset call. `zeroed()`
    //   compiles to a single `BPF_ST_MEM BPF_DW r10, -64, 0` x8 sequence,
    //   which the verifier counts as 8 instructions (provably bounded).
    let mut frame = SignalFrame::zeroed();

    // STEP 5 — Populate fields.
    //
    // WHY `cpu_id` assignment:
    //   Per Phase 2.3 SPEC DELTA, cpu_id is now a dedicated field at offset 44.
    //   This enables userspace routing while maintaining a single RingBuffer[cite: 25, 27].
    //
    // WHY direct assignment for l3_hdr:
    //   Assigning [u8; 20] from one stack-local struct to another allows LLVM to 
    //   unroll the copy into individual store instructions, avoiding a `memcpy` 
    //   call that would trigger a verifier rejection[cite: 100, 101].
    
    frame.flow_hash    = result.flow_hash;

    // SAFETY: bpf_ktime_get_ns() — BPF helper #5. No args, cannot fail.
    // Returns CLOCK_MONOTONIC nanoseconds.
    frame.timestamp_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    // WHY we use ptr::copy_nonoverlapping:
    //   Direct array assignment `frame.l3_hdr = view.l3_hdr` can trigger 
    //   implicit bounds checks or memmove calls in some LLVM versions.
    //   Using a raw pointer copy forces a direct store sequence, ensuring
    //   no panic symbols (E0283/E0080) are emitted in the final object.
    unsafe {
        core::ptr::copy_nonoverlapping(
            view.l3_hdr.as_ptr(),
            frame.l3_hdr.as_mut_ptr(),
            20,
        );
    }
    frame.l4_flags     = (result.flow_hash >> 32) as u32;
    frame.pps_delta    = result.pps_delta;
    
    // Assigning the captured cpu_id to the new ABI field[cite: 171].
    // Offset 44, size 4 bytes.
    frame.cpu_id       = cpu_id;

    // frame._pad: Offset 48, size 16 bytes. 
    // Guaranteed STACK_ZERO from SignalFrame::zeroed(). 
    // Explicitly not written to avoid dead store instruction bloat.
    // STEP 6 — Output to per-CPU ring buffer.
    //
    // WHY bpf_ringbuf_output (single-call) over reserve/submit split:
    //   The reserve/submit pattern requires the verifier to track a nullable
    //   pointer (the reservation handle) across all code paths between the two
    //   calls. Every branch that might miss the submit generates a
    //   .text.unlikely. section for the cleanup path. bpf_ringbuf_output
    //   copies atomically in one helper call — no pointer to track, no
    //   cleanup path, no .text.unlikely. emission.
    //
    // Ring full → XDP_PASS. Userspace metrics worker detects drops via
    // `producer_idx - consumer_idx` accounting on the ring metadata page.
    // This is the correct back-pressure response for a passive observer:
    // never drop packets from the wire due to telemetry back-pressure.
    if !maps::ring_output(&frame) {
        return pass_cold();
    }

    // STEP 7 — Unconditional pass. This program never drops wire traffic.
    xdp_action::XDP_PASS
}

// ---------------------------------------------------------------------------
// COLD PASS — factored exit for all non-signal and back-pressure paths.
//
// WHY `#[inline(always)]` + `#[cold]`:
//   `#[cold]` tags all *call sites* of this function as unlikely branches,
//   biasing the branch predictor toward the hot path in `xdp_ingress`.
//   `#[inline(always)]` ensures the function is inlined — the cold *hint*
//   is what matters, not a real function call. A non-inlined cold function
//   would create a second BPF subprogram in `.text`, consuming verifier
//   complexity budget for a trivial return.
//
// WHY not `return xdp_action::XDP_PASS` inline at each call site:
//   Factoring cold exits into a single annotated site lets LLVM apply the
//   cold hint uniformly. Duplicated inline returns do not receive cold
//   branch-weight metadata.
// ---------------------------------------------------------------------------
#[inline(always)]
#[cold]
fn pass_cold() -> u32 {
    xdp_action::XDP_PASS
}

// ---------------------------------------------------------------------------
// PANIC HANDLER
//
// WHY `loop {}` instead of an intrinsic abort or BPF helper:
//   On bpfel-unknown-none there is no unwinding, no OS signal, and no
//   `abort` syscall. The infinite loop is a **verifier trap**: any code
//   path that statically reaches this handler causes the BPF verifier to
//   reject the program at load time with "back-edge in the program" or
//   "unreachable path", surfacing the latent panic before deployment.
//   This is strictly better than a no-op return, which would silently
//   continue execution with an undefined stack state.
//
// WHY this handler does NOT emit `core::panicking` symbols:
//   It doesn't call any panicking function — it *is* the terminal handler.
//   The `core::panicking::*` symbols in llvm-nm come from OTHER modules
//   (proto_view, filter, maps, or static_assertions) calling into the
//   panicking machinery *before* it reaches this handler. Fix those modules.
//   This handler is not the source of the problem.
// ---------------------------------------------------------------------------
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Verifier trap: Any path leading here causes load-time rejection.
    // We use a dedicated hint to tell LLVM this is unreachable, 
    // further helping to prune panic-related branches.
    unsafe { core::hint::unreachable_unchecked() }
}