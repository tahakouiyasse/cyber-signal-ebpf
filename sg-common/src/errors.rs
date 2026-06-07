// SignalError is a repr(u32) enum so that discriminant values are identical
// in the eBPF program and in userspace. The kernel writes a u32 error code
// into a side-channel map; userspace reads it and reconstructs the variant
// via transmute (after bounds-checking the raw value). If the discriminants
// drifted, silent misclassification would occur — wrong alert, wrong counter.
//
// No std::error::Error impl: the trait is not available in no_std. Userspace
// callers can match on the variant directly. core::fmt::Display is provided
// for diagnostic formatting in userspace without pulling in std.

/// Errors that the eBPF program can signal to userspace via the error map.
/// Discriminants are canonical and must not be renumbered without a spec delta.
#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum SignalError {
    /// Ring buffer reserve returned NULL: the consumer is too slow and the
    /// producer has lapped it. One or more SignalFrames were lost.
    Truncated = 1,

    /// Two distinct 5-tuples produced the same Murmur3 hash bucket.
    /// The frame was discarded rather than silently overwrite a live entry.
    HashCollision = 2,

    /// pps_delta saturated u32::MAX. The flow is pathological or the counter
    /// window is misconfigured. The frame is emitted with pps_delta = u32::MAX.
    PpsOverflow = 3,
}

impl SignalError {
    /// Reconstruct a SignalError from its raw u32 discriminant.
    /// Returns None for values not defined in this version of the ABI so that
    /// a future kernel with a new error code does not panic old userspace.
    #[inline]
    pub const fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Truncated),
            2 => Some(Self::HashCollision),
            3 => Some(Self::PpsOverflow),
            _ => None,
        }
    }

    /// Return the canonical discriminant value.
    /// Prefer this over `as u32` at call sites so that refactors are caught
    /// by the type system rather than silent integer coercion.
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

// Discriminant assertions: the numeric values are load-bearing ABI.
// If the compiler ever reorders them (it cannot with repr(u32), but we assert
// anyway so a future refactor cannot silently break the contract).
use static_assertions::const_assert_eq;
const_assert_eq!(SignalError::Truncated as u32, 1);
const_assert_eq!(SignalError::HashCollision as u32, 2);
const_assert_eq!(SignalError::PpsOverflow as u32, 3);

impl core::fmt::Display for SignalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => f.write_str("SignalError::Truncated(ring buffer overrun; frames dropped)"),
            Self::HashCollision => f.write_str("SignalError::HashCollision(5-tuple hash bucket collision; frame discarded)"),
            Self::PpsOverflow => f.write_str("SignalError::PpsOverflow(pps_delta saturated u32::MAX)"),
        }
    }
}