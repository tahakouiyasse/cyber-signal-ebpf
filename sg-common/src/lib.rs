#![no_std]

// NCPU is the canonical per-CPU ring buffer count.
// It is a const generic seed — downstream crates index arrays with this.
// Changing it is a full ABI break; consult CONTROLLER.md §9 before touching.
pub const NCPU: usize = 32;

pub mod errors;
pub mod map_keys;
pub mod signal_frame;

pub use errors::SignalError;
pub use map_keys::{DENY_MAP_ID, EVENTS_PIN};
pub use signal_frame::SignalFrame;