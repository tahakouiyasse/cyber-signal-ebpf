# cyber-signal-ebpf
High-performance, zero-copy L2–L4 network signal extractor built with Rust &amp; eBPF(CO-RE). Captures packets via XDP ingress, transforms data into 64byte frames, and delivers to userspace via lock-free per-CPU ring buffers with sub-microsecond jitter. Designed for 100 Mpps line-rate critical protocols. Post-init heapless, multi-threaded architecture.
