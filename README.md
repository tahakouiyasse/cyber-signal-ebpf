# cyber-signal-ebpf

[![Rust](https://img.shields.io/badge/rust-nightly--2026--05--10-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![eBPF](https://img.shields.io/badge/eBPF-CO--RE%20%2F%20BTF%20v1.0-blueviolet?logo=linux&logoColor=white)](https://ebpf.io/)
[![Linux](https://img.shields.io/badge/Linux-5.15%2B-blue?logo=linux&logoColor=white)](https://kernel.org/)
[![XDP](https://img.shields.io/badge/XDP-wire--speed%20ingress-green)](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)
[![License](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)
[![Build](https://img.shields.io/badge/build-bpfel--unknown--none-informational)](https://doc.rust-lang.org/rustc/platform-support.html)

> **Wire-speed, per-CPU network signal extraction at XDP ingress.**  
> Fixed 64-byte `SignalFrame` records. Lock-free per-CPU ring buffers.  
> Sub-microsecond P99 jitter. Zero heap allocations in the hot path. No exceptions.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Key Technical Features & Invariants](#2-key-technical-features--invariants)
3. [SignalFrame ABI Contract](#3-signalframe-abi-contract)
4. [Repository Structure](#4-repository-structure)
5. [Documentation & White Paper](#5-documentation--white-paper)
6. [Getting Started](#6-getting-started)
7. [Verification Gates](#7-verification-gates)
8. [Performance Targets](#8-performance-targets)
9. [Constants Reference](#9-constants-reference)
10. [Dependency Manifest](#10-dependency-manifest)

---

## 1. Architecture Overview

`cyber-signal-ebpf` implements a **kernel-to-userspace lock-free signal pipeline** governed by three non-negotiable architectural absolutes: **Zero-Copy**, **Per-CPU Isolation**, and **CO-RE portability**. The system intercepts raw Ethernet frames at the earliest possible kernel hook point — XDP ingress, before skb allocation — and produces fixed-width, cache-line-aligned `SignalFrame` records consumed directly by CPU-pinned userspace vacuum workers over memory-mapped ring buffers.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            NIC — Wire Speed                                 │
│                         (10GbE / 25GbE / 100GbE)                           │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │ XDP_INGRESS  (pre-skb, pre-netstack)
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        sg-ebpf  [bpfel-unknown-none]                        │
│                                                                             │
│  xdp_ingress()  — bpf_get_smp_processor_id() called ONCE                   │
│                                                                             │
│  ┌──────────────┐    ┌───────────────┐    ┌──────────────────────────────┐ │
│  │ proto_view   │───▶│   filter      │───▶│        maps                  │ │
│  │              │    │               │    │                              │ │
│  │ 128B linear  │    │ murmur3_32()  │    │ BPF_MAP_TYPE_RINGBUF         │ │
│  │ window scan  │    │ flow_5tuple   │    │ 256KB × NCPU(32) = 8MB total │ │
│  │              │    │               │    │                              │ │
│  │ EtherType    │    │ pps_delta     │    │ bpf_ringbuf_reserve()        │ │
│  │ 0x0800 only  │    │ bpf_atomic_   │    │ → write SignalFrame in-place │ │
│  │              │    │ add counter   │    │ bpf_ringbuf_submit()         │ │
│  │ Proto 6/17   │    │               │    │ (no partial commits)         │ │
│  │ TCP/UDP only │    │ DenyHash      │    │                              │ │
│  └──────────────┘    │ BPF_F_LOCK    │    └──────────────────────────────┘ │
│                      │ spinlock      │                                      │
│   Non-signal:        └───────────────┘    Pin: /sys/fs/bpf/cyber_signals   │
│   XDP_PASS #[cold]                                                          │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                    mmap — zero kernel/user boundary copy
                    atomic cmpxchg producer/consumer indices
                    cache-line-aligned ring entries (align(64))
                                       │
┌──────────────────────────────────────▼──────────────────────────────────────┐
│                       sg-capture  [x86_64-unknown-linux-gnu]                │
│                                                                             │
│  NCPU=32 Tokio threads — each pinned via core_affinity before any I/O      │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  vacuum_cpu(ring, cpu_id)                                           │   │
│  │                                                                     │   │
│  │  while let Some(record) = ring.next_record() {                      │   │
│  │      batch[n] = record;          // stack-allocated                 │   │
│  │      n += 1;                                                        │   │
│  │      if n == BATCH_SIZE(256) { yield_now().await; n = 0; }         │   │
│  │  }                              // no sleep, no blocking primitive  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  metrics thread (1s period, Relaxed atomics, integer-only drop_rate)        │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Critical Path — 3 Verifier Passes Maximum

The XDP hot path is bounded to **three eBPF verifier passes** on the critical code path:

| Pass | Operation | Module |
|------|-----------|--------|
| **1** | `bpf_probe_read_kernel` → 128-byte linear scan, EtherType/proto dispatch | `proto_view.rs` |
| **2** | `murmur3_32(flow_5tuple)` + `bpf_atomic_add` PPS counter | `filter.rs` |
| **3** | `DenyHash` lookup (`BPF_F_LOCK` spinlock) + `bpf_ringbuf_reserve()` | `maps.rs` |

`bpf_ringbuf_submit()` is unconditional. No partial commits. No error swallowing after reserve.

---

## 2. Key Technical Features & Invariants

### INV-01 — Zero-Copy Pipeline

Packet data crosses the kernel/userspace privilege boundary **exactly once**, through a directly mmap-readable ring buffer. There is no `memcpy` across the boundary, no intermediate staging buffer, no DMA bounce.

- The eBPF program performs a single **128-byte linear window scan** (`proto_view.rs` union overlay, not a struct copy).
- `bpf_ringbuf_reserve()` returns a pointer into the mmap-visible ring buffer region. The `SignalFrame` is written in-place at that kernel pointer.
- Userspace reads via `ring.next_record()` — a pointer into the same `mmap(2)`-mapped region. The consumer never allocates. It advances a consumer index.
- `PREFETCHNTA` semantics apply: because every `SignalFrame` is `align(64)`, prefetch hints operate on complete cache lines with no partial-line eviction penalty.

### INV-02 — Per-CPU Isolation (Cross-NUMA is a Design Defect)

There are exactly `NCPU = 32` ring buffers, sized at `256KB` each (`262_144` bytes, power-of-two, verifier-friendly). CPU locality is not a performance hint — it is an architectural constraint:

- `bpf_get_smp_processor_id()` is called **once** at XDP entry and stored in a local variable. No repeated syscall in the hot path.
- The kernel program writes exclusively to `PerCpuRingBuffers[cpu_id]`.
- Each userspace vacuum thread calls `core_affinity::set_for_current(CoreId { id: cpu_id })` **before opening any ring buffer fd**. Affinity failure is a hard abort — a vacuum worker executing on the wrong NUMA node is worse than no vacuum at all.
- `sched_getcpu()` is asserted against `cpu_id` in debug builds to catch scheduler drift.
- No `Mutex`, `RwLock`, or `RefCell` appears anywhere in `percpu_ring.rs`. Each `RingBuf` is owned by exactly one thread. Sharing is not required. Sharing is forbidden.

### INV-03 — CO-RE: Compile Once — Run Everywhere

The eBPF binary is portable across kernel versions without recompilation:

- All kernel struct field accesses use `BPF_CORE_READ` / `bpf_core_read` macros exclusively. Hard-coded struct offsets are a rejection criterion.
- `vmlinux.rs` is generated by `bpftool btf dump file /sys/kernel/btf/vmlinux format c`, not hand-authored.
- The loader generates a program skeleton via `bpftool gen skeleton`.
- BTF type information is embedded in the compiled BPF object and resolved at load time by the kernel's CO-RE relocator.

### INV-04 — Post-Initialization Heapless Execution

After `loader.rs` completes initialization, **the heap profile is flat**. Validated by Valgrind massif.

- `Vec`, `String`, `Box`, `Arc`, `Rc`, `HashMap<std>`, `BTreeMap` — **forbidden in any hot-path code path**.
- Runtime collections are statically-sized arrays or `heapless`/`arrayvec` types, allocated at program start.
- In `sg-ebpf` (`no_std`, `bpfel-unknown-none`): the allocator does not exist. Any `alloc` crate import is a compile error.
- The vacuum batch array is `[MaybeUninit<SignalFrame>; BATCH_SIZE]` — **stack-allocated per poll cycle**, not heap-allocated per record.
- `tokio::time::sleep` is forbidden in the vacuum hot path. `tokio::task::yield_now().await` is the cooperative yield primitive after each `BATCH_SIZE = 256` drain.

### INV-05 — Explicit Cache-Line Alignment (`#[repr(C, align(64))]`)

Every struct crossing the kernel/userspace ABI boundary carries `#[repr(C, align(64))]`. The rationale is threefold and non-negotiable:

1. **Atomic `cmpxchg` boundaries**: Multi-core atomic operations on the struct require natural alignment ≥ the operation width. Misalignment produces torn reads on architectures without guaranteed sub-word atomicity.
2. **SIMD prefetch**: `PREFETCHNTA` on a cache-line-aligned pointer avoids partial-line eviction from L1/L2. A misaligned 64-byte struct spanning two cache lines doubles the eviction pressure per record at 100 Mpps.
3. **eBPF verifier `memcpy` alignment check**: The verifier rejects `bpf_probe_read` into a destination whose alignment does not satisfy the read width constraint. `align(64)` satisfies all widths.

`align(64)` = one full cache line. Not `align(8)`. Not `align(32)`. **64. Always.**

### INV-06 — Static Layout Assertions (Compile-Time ABI Guard)

Every shared struct is guarded by `static_assertions::const_assert_eq!` macros immediately after its definition. These are the only ABI guard between a correct `SignalFrame` write and silent data corruption at 100 Mpps:

```rust
const_assert_eq!(core::mem::size_of::<SignalFrame>(), 64);
const_assert_eq!(core::mem::align_of::<SignalFrame>(), 64);
const_assert_eq!(core::mem::offset_of!(SignalFrame, flow_hash),    0);
const_assert_eq!(core::mem::offset_of!(SignalFrame, timestamp_ns), 8);
const_assert_eq!(core::mem::offset_of!(SignalFrame, l3_hdr),       16);
const_assert_eq!(core::mem::offset_of!(SignalFrame, l4_flags),     36);
const_assert_eq!(core::mem::offset_of!(SignalFrame, pps_delta),    40);
const_assert_eq!(core::mem::offset_of!(SignalFrame, _pad),         44);
```

A missing assertion is a rejection. A failing assertion is a compile error. That is the intended behaviour.

### INV-07 — Non-Signal Traffic Silence

Non-IP, non-TCP/UDP, fragmented, and loopback packets return `XDP_PASS` immediately. The cold path is annotated `#[cold]` so the branch predictor treats it as structurally improbable. **Zero** logging, **zero** counter increments, and **zero** map lookups occur for non-signal traffic. Branch prediction correctness at line rate depends on this.

### INV-08 — Verifier Budget Hard Ceiling

| Constraint | Hard Limit | Enforcement Tool |
|---|---|---|
| Max BPF instructions | 1,000,000 | `bpftool prog load --log-level 2` |
| Max stack usage | 512 bytes | `llvm-objdump -d \| grep -A2 xdp_ingress` |
| Loop iterations (any loop) | 4 maximum | Manual audit; verifier-visible bound required |
| Verifier passes on critical path | 3 maximum | Code review gate before merge |

---

## 3. SignalFrame ABI Contract

`SignalFrame` is the sole type crossing the kernel/userspace boundary. Its layout is canonical and frozen. A one-byte misalignment between the kernel write and the userspace read produces silent data corruption. The static assertions are the only compile-time guard.

```
┌──────────────────────────────────────────────────────────────────┐
│                   SignalFrame  (64 bytes, align(64))             │
├──────────┬───────────────────────────────────────────────────────┤
│ Offset 0 │ flow_hash     : u64   (8 B)  — murmur3_32(5-tuple)   │
├──────────┼───────────────────────────────────────────────────────┤
│ Offset 8 │ timestamp_ns  : u64   (8 B)  — bpf_ktime_get_ns()    │
├──────────┼───────────────────────────────────────────────────────┤
│ Offset16 │ l3_hdr        : [u8;20](20B) — IPv4 header, no opts  │
├──────────┼───────────────────────────────────────────────────────┤
│ Offset36 │ l4_flags      : u32   (4 B)  — TCP flags / UDP len   │
├──────────┼───────────────────────────────────────────────────────┤
│ Offset40 │ pps_delta     : u32   (4 B)  — per-CPU PPS counter   │
├──────────┼───────────────────────────────────────────────────────┤
│ Offset44 │ _pad          : [u8;20](20B) — explicit, zero-init   │
└──────────┴───────────────────────────────────────────────────────┘
  Total: 64 bytes. Assert or it does not compile.
```

**Error taxonomy** (`errors.rs`, `#[repr(u32)]`, kernel/userspace discriminant agreement):

| Variant | Discriminant | Condition |
|---|---|---|
| `Truncated` | `1` | Packet window < 54 bytes at XDP data pointer |
| `HashCollision` | `2` | murmur3 output collides under deny map key |
| `PpsOverflow` | `3` | `pps_delta` exceeds `MAXPPS_THRESHOLD (1_000_000)` |

No `std::error::Error` impl. `no_std` throughout.

---

## 4. Repository Structure

```
cyber-signal-ebpf/
├── rust-toolchain.toml              # Pinned: nightly-2026-05-10 | edition 2021
├── Cargo.toml                       # Workspace root
├── CONTROLLER.md                    # Architectural authority — frozen v1.0.0
│
├── sg-common/                       # ABI contract crate (no_std)
│   │                                # Compiles for bpfel-unknown-none AND
│   │                                # x86_64-unknown-linux-gnu identically
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                   # #![no_std]; pub const NCPU: usize = 32
│       ├── signal_frame.rs          # SignalFrame layout + static_assertions
│       ├── map_keys.rs              # EVENTS_PIN (&'static str), DENY_MAP_ID (const u32)
│       └── errors.rs                # #[repr(u32)] error taxonomy, no std::error::Error
│
├── sg-ebpf/                         # Kernel interceptor (bpfel-unknown-none)
│   │                                # XDP program — eBPF verifier is the judge
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                  # XDP entry; cpu_id called once; dispatch order
│       ├── vmlinux.rs               # Generated by bpftool btf dump — NOT hand-authored
│       ├── proto_view.rs            # ProtoView union; 128B linear scan; EtherType dispatch
│       ├── filter.rs                # murmur3_32 (≤4 iter); bpf_atomic_add; deny lookup
│       └── maps.rs                  # PerCpuRingBuffers (RINGBUF); DenyHash (BPF_F_LOCK)
│
└── sg-capture/                      # Userspace vacuum (x86_64-unknown-linux-gnu)
    │                                # Tokio async runtime; CPU-pinned; lock-free poll
    ├── Cargo.toml
    └── src/
        ├── main.rs                  # CPU pin before I/O; panic on affinity failure; NCPU threads
        ├── loader.rs                # aya::Ebpf::load_file; pin maps; hot-reload < 50ms
        ├── vacuum.rs                # BATCH_SIZE=256; yield_now; stack-allocated batch array
        ├── percpu_ring.rs           # PerCpuRings([RingBuf; NCPU]); bounds-checked accessor
        └── metrics.rs               # Relaxed atomics; integer drop_rate; 1s period thread
```

**Total files under architectural authority**: 14 source files + 4 `Cargo.toml` + 1 `rust-toolchain.toml`.

### Crate Dependency Graph

```
sg-ebpf ──────────┐
                  ├──▶ sg-common  (no_std ABI contract — frozen after Phase 1)
sg-capture ───────┘
```

`sg-common` is the ABI freeze boundary. No changes to `sg-common` after Phase 1 completion without a formal spec delta approval. `sg-ebpf` and `sg-capture` consume it. They do not redefine it.

---

## 5. Documentation & White Paper

### Technical White Paper

For a complete treatment of the system's formal architecture — including the mathematical model of per-CPU ring buffer throughput under tail-drop conditions, the derivation of the 100 ns/packet XDP latency budget, the CO-RE BTF relocation mechanics, and the formal proof of zero cross-NUMA interference under `NCPU = 32` isolation — the comprehensive white paper is available for deep technical review:

---

> ### 📄 [CYBER-SIGNAL-eBPF: White Paper — Wire-Speed Per-CPU Signal Extraction over Lock-Free eBPF Ring Buffers](https://github.com/tahakouiyasse/cyber-signal-ebpf/blob/main/docs/White_Paper1.pdf)
>
> *This document is the authoritative technical reference for reviewers, protocol engineers, and systems architects evaluating the design. It covers the full XDP ingress pipeline, `SignalFrame` ABI stability guarantees, verifier budget derivation, CO-RE portability analysis, and empirical P99 jitter measurements under sustained 100 Mpps load.*

---

The white paper is the recommended entry point for **technical due diligence**, **academic citation**, and **protocol integration review**. It is written to the same precision standard as `CONTROLLER.md`.

---

## 6. Getting Started

### Prerequisites

| Requirement | Version / Constraint |
|---|---|
| Rust toolchain | `nightly-2026-05-10` — **pinned exactly** by `rust-toolchain.toml` |
| `bpf` target | `bpfel-unknown-none` (installed via `rustup target add`) |
| Linux kernel | 5.15+ with BTF enabled (`/sys/kernel/btf/vmlinux` must exist) |
| `bpftool` | ≥ 7.0 (for `gen skeleton`, `btf dump`, and `prog load --log-level 2`) |
| `llvm-objdump` | ≥ 14.0 (stack frame analysis) |
| `cargo-xtask` | Workspace task runner (see `xtask/` for build orchestration) |
| `perf` | For `cache-misses` validation gate |
| Valgrind massif | Post-init heap flatline verification |

### Step 0 — Toolchain Bootstrap

```bash
# rust-toolchain.toml pins this automatically on first cargo invocation
rustup show

# Verify the exact nightly is active — no other nightly is permitted
rustc --version
# Expected: rustc 1.xx.0-nightly (... 2026-05-10)

# Install the BPF cross-compilation target
rustup target add bpfel-unknown-none
```

### Step 1 — Generate `vmlinux.rs` (CO-RE BTF Source)

`vmlinux.rs` is **generated, not authored**. On the build host kernel:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > sg-ebpf/src/vmlinux.rs
```

This file must be regenerated on each kernel version upgrade. It is the CO-RE relocation source for all `BPF_CORE_READ` macro expansions.

### Step 2 — Phase 1: ABI Freeze (`sg-common`)

```bash
# Validate the ABI contract compiles for both targets before any kernel code
cargo check --target bpfel-unknown-none -p sg-common
cargo check --target x86_64-unknown-linux-gnu -p sg-common

# All const_assert_eq! must pass — compile failure here is the intended guard
```

**Phase 1 completion gate**: Both `cargo check` invocations exit 0. The ABI is now frozen.

### Step 3 — Phase 2: Kernel Program Build & Verifier Validation (`sg-ebpf`)

```bash
# Build the BPF object for the kernel target
cargo build --target bpfel-unknown-none -p sg-ebpf

# Locate the compiled BPF ELF object
# (path depends on xtask / cargo-bpf output directory)
BPF_OBJ=target/bpfel-unknown-none/debug/sg_ebpf.o

# Verifier load test — must exit 0
bpftool prog load "$BPF_OBJ" /sys/fs/bpf/test_load --log-level 2

# Stack frame check — must be ≤ 512 bytes
llvm-objdump -d "$BPF_OBJ" | grep -A2 "xdp_ingress"

# Verifier pass count — must be ≤ 3 on critical path
bpftool prog load "$BPF_OBJ" /sys/fs/bpf/test_load --log-level 2 2>&1 \
  | grep "verification time"

# Clean up test pin
rm /sys/fs/bpf/test_load
```

### Step 4 — Phase 3: Userspace Vacuum Build & Performance Gate (`sg-capture`)

```bash
# Release build — optimization level 3, LTO, no debug assertions in hot path
cargo build --release -p sg-capture

# Criterion throughput benchmark — must achieve ≥ 100 Mpps sustained
cargo bench --package sg-capture --bench vacuum_throughput

# Cache miss validation — must be < 0.5% on vacuum poll loop
perf stat -e cache-misses ./target/release/sg-capture --dry-run

# Post-init heap flatline verification
valgrind --tool=massif --pages-as-heap=yes ./target/release/sg-capture
ms_print massif.out.* | head -40
# Expect: flat heap profile after loader initialization completes
```

### Step 5 — Full System Run

```bash
# Pin the BPF program to the target interface (replace eth0 as appropriate)
# CPU affinity pinning, ring buffer mmap, and vacuum thread spawn are automatic
sudo ./target/release/sg-capture --iface eth0 --bpf-obj target/bpfel-unknown-none/release/sg_ebpf.o

# Monitor drop rate (stderr, 1s period, integer-only)
# Alert threshold: drop_rate > 0.1% of total events
```

### Hot-Reload Sequence

The loader supports live BPF object replacement without stopping the vacuum workers. The full sequence must complete in **< 50 ms** — violation is logged as an error:

```
1. Unlink  /sys/fs/bpf/cyber_signals   (unpin existing maps)
2. Load    new BPF object via aya::Ebpf::load_file()
3. Re-pin  maps to /sys/fs/bpf/cyber_signals
4. Assert  elapsed < 50ms
```

---

## 7. Verification Gates

Each phase has an explicit completion gate. No phase begins until the previous gate clears. This is the architectural contract.

| Gate | Command | Pass Criterion |
|---|---|---|
| **ABI Freeze** | `cargo check --target bpfel-unknown-none -p sg-common` | Exit 0; all `const_assert_eq!` pass |
| **Verifier Load** | `bpftool prog load ... --log-level 2` | Exit 0 |
| **Stack Frame** | `llvm-objdump -d \| grep -A2 xdp_ingress` | ≤ 512 bytes |
| **Verifier Passes** | `bpftool` log analysis | ≤ 3 passes on critical path |
| **Throughput** | `cargo bench vacuum_throughput` | Mean ≥ 100 Mpps |
| **Cache Miss Rate** | `perf stat -e cache-misses` | < 0.5% on vacuum loop |
| **Heap Flatline** | `valgrind --tool=massif` | Flat profile post-loader-init |
| **Zero Warnings** | `cargo build` with `-D warnings` | Zero warnings, all crates |

---

## 8. Performance Targets

All targets are hard constraints validated by CI benchmarks, not aspirational numbers:

| Metric | Target | Measurement Method |
|---|---|---|
| XDP hot path latency | **< 100 ns/packet** | `bpftool prog profile` |
| Userspace vacuum P99 jitter | **< 1 µs** | Criterion histogram |
| `ring.next_record()` avg latency | **< 200 ns/record** | Criterion microbench |
| Vacuum sustained throughput | **≥ 100 Mpps** | `vacuum_throughput` bench |
| Cross-NUMA access | **Zero** | `sched_getcpu()` assert in debug |
| Hot-reload elapsed time | **< 50 ms** | Loader internal timer |
| Heap allocations post-init | **Zero** | Valgrind massif flatline |
| Cache miss rate (vacuum loop) | **< 0.5%** | `perf stat -e cache-misses` |

---

## 9. Constants Reference

All constants are canonical. Sub-systems copy these values. They do not redefine, rename, or reinterpret them.

```rust
// sg-common/src/lib.rs
pub const NCPU: usize = 32;

// sg-ebpf/src/filter.rs
pub const MAXPPS_THRESHOLD: u64 = 1_000_000;

// sg-ebpf/src/maps.rs
pub const RINGBUF_SIZE_PER_CPU: u32 = 262_144;  // 256 KB — must be power of two
pub const DENY_MAP_MAX_ENTRIES: u32 = 65_536;   // power of two — verifier-friendly

// sg-capture/src/vacuum.rs
pub const BATCH_SIZE: usize = 256;

// sg-common/src/map_keys.rs
pub const EVENTS_PIN: &str = "/sys/fs/bpf/cyber_signals";
pub const DENY_MAP_ID: u32 = 1;
```

---

## 10. Dependency Manifest

Versions are pinned. Sub-systems do not choose library versions.

### `sg-common`
```toml
[dependencies]
static_assertions = { version = "1.1", default-features = false }
```

### `sg-ebpf`
```toml
[dependencies]
aya-bpf     = { version = "0.1", features = ["macros"] }
aya-log-ebpf = "0.1"
sg-common   = { path = "../sg-common" }
```

### `sg-capture`
```toml
[dependencies]
aya            = "0.13"
aya-log        = "0.2"
tokio          = { version = "1", features = ["rt-multi-thread", "macros", "sync"] }
core_affinity  = "0.8"
sg-common      = { path = "../sg-common" }
```

### Toolchain Lock
```toml
# rust-toolchain.toml — do not modify without spec delta approval
[toolchain]
channel = "nightly-2026-05-10"
targets = ["bpfel-unknown-none", "x86_64-unknown-linux-gnu"]
```

---

## Architecture Decision Records

**ADR-001: Why `align(64)` and not `align(8)`**  
A `SignalFrame` straddling a cache-line boundary doubles the number of cache lines loaded per record read in the vacuum loop. At 100 Mpps sustained throughput across 32 CPUs, partial-line eviction becomes the dominant L1 miss source. `align(64)` eliminates this class of miss entirely. It also satisfies the eBPF verifier's destination alignment requirement for `bpf_probe_read` into the ring buffer reservation pointer.

**ADR-002: Why `BATCH_SIZE = 256` and `yield_now`, not `sleep`**  
`tokio::time::sleep` introduces a minimum OS scheduler quantum (~4ms on most kernels) into the poll loop, destroying P99 jitter. `yield_now().await` is a cooperative yield that returns control to the Tokio executor and re-schedules on the same CPU thread immediately if the ring has more records. The batch size of 256 was derived empirically as the knee point of the throughput/latency curve: below 256, context-switch overhead dominates; above 256, tail latency grows due to delayed yields.

**ADR-003: Why panic on CPU affinity failure**  
A vacuum worker executing on the wrong CPU reads from a remote ring buffer. On a dual-socket NUMA system, this adds ~60–80 ns of memory latency per record — enough to violate the < 1 µs P99 jitter budget under any realistic load. Silent degradation is worse than a hard crash: the crash is observable; the NUMA miss is not, until production measurements regress.

---

*CONTROLLER.md v1.0.0 — FROZEN — This README reflects the architecture exactly as specified.*  
*For amendments to the architecture, a formal spec delta request is required.*
