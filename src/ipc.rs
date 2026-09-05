//! Synchronous IPC: endpoints and messages.
//!
//! IPC in Seedcore is a blocking rendezvous, the same shape as seL4 style
//! synchronous message passing. A send and a receive on the same endpoint must
//! meet. Whichever side arrives first blocks and waits for the other. When they
//! meet the message is copied exactly once from sender to receiver and both
//! sides become runnable again. No message is ever lost, duplicated, or
//! delivered without a matching receive.
//!
//! A message can carry a capability. When it does, the capability is moved out
//! of the sender table at send time and installed into the receiver table on
//! delivery. This is how authority travels between tasks, and it is the only way
//! a task ever gains a capability it was not given at creation.

use crate::capability::CapSlot;
use crate::{EndpointId, ThreadId};
use std::collections::VecDeque;

/// A message as described by a sending program, before the kernel resolves it.
///
/// The `transfer` field names a slot in the sender own table whose capability
/// should travel with the message. The kernel removes it from the sender and
/// installs it in the receiver, which is capability transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgSpec {
    /// A small integer tag, like a message label or method selector.
    pub label: u64,
    /// The payload bytes.
    pub bytes: Vec<u8>,
    /// An optional capability slot to transfer with the message.
    pub transfer: Option<CapSlot>,
}

impl MsgSpec {
    /// A message with a label and payload and no capability transfer.
    pub fn new(label: u64, bytes: Vec<u8>) -> MsgSpec {
        MsgSpec {
            label,
            bytes,
            transfer: None,
        }
    }

    /// A message that also transfers the capability in `slot`.
    pub fn with_cap(label: u64, bytes: Vec<u8>, slot: CapSlot) -> MsgSpec {
        MsgSpec {
            label,
            bytes,
            transfer: Some(slot),
        }
    }
}

/// An IPC endpoint kernel object.
///
/// The endpoint holds two queues of waiting threads. At most one queue is ever
/// non empty at a time, because as soon as a sender and a receiver are both
/// present the kernel pairs them off immediately. Keeping both queues makes the
/// invariant easy to assert in tests.
#[derive(Debug, Clone, Default)]
pub struct Endpoint {
    /// Threads blocked trying to send.
    pub senders: VecDeque<ThreadId>,
    /// Threads blocked trying to receive.
    pub receivers: VecDeque<ThreadId>,
}

impl Endpoint {
    /// A fresh endpoint with empty queues.
    pub fn new() -> Endpoint {
        Endpoint::default()
    }
}

/// The identifier form used when queueing. Kept as a thin alias for clarity at
/// call sites that pass endpoint ids around.
pub type EndpointRef = EndpointId;
