//! Kernel side error results.
//!
//! Every syscall that touches a kernel object goes through capability
//! resolution, and every way that resolution can fail is one of these variants.
//! A denial is not a panic. It is a value the kernel records and returns, just
//! as a real microkernel returns an error code to a misbehaving task.

use crate::capability::{CapSlot, ObjectRef, Rights};
use std::fmt;

/// The reason a syscall was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelError {
    /// The slot is not present in the caller capability table. This covers a
    /// fabricated index, a guessed index, and a slot that was revoked. From the
    /// core's point of view they are indistinguishable, which is exactly the
    /// unforgeability property: there is no such capability.
    NoSuchCapability { slot: CapSlot },
    /// The slot holds a capability, but for a different kind of object than the
    /// syscall needs. A memory capability cannot be used to send on an endpoint.
    WrongObject { slot: CapSlot, expected: &'static str },
    /// The capability exists and names the right object, but does not carry the
    /// permission the operation requires. This is an escalation attempt and it
    /// is denied.
    MissingRight { slot: CapSlot, needed: Rights },
    /// A memory access fell outside the bounds of the region.
    OutOfBounds {
        object: ObjectRef,
        offset: usize,
        len: usize,
    },
    /// A reply was attempted but no reply capability was received.
    NoReplyCapability,
    /// A referenced task or thread does not exist.
    NoSuchObject { object: ObjectRef },
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KernelError::NoSuchCapability { slot } => {
                write!(f, "denied: no capability in slot {slot}")
            }
            KernelError::WrongObject { slot, expected } => {
                write!(f, "denied: slot {slot} is not a capability of kind {expected}")
            }
            KernelError::MissingRight { slot, needed } => {
                write!(f, "denied: slot {slot} lacks right {needed}")
            }
            KernelError::OutOfBounds {
                object,
                offset,
                len,
            } => write!(
                f,
                "denied: offset {offset} out of bounds for {object} of length {len}"
            ),
            KernelError::NoReplyCapability => {
                write!(f, "denied: no reply capability available")
            }
            KernelError::NoSuchObject { object } => {
                write!(f, "denied: object {object} does not exist")
            }
        }
    }
}

impl std::error::Error for KernelError {}
