//! The execution trace.
//!
//! Every observable effect the kernel produces is appended to a trace as an
//! [`Event`]. The trace is the ground truth of a run. Determinism is defined in
//! terms of it: two runs from the same seed must produce identical traces. The
//! command line tool prints the trace, and the correctness tests assert over it.

use crate::capability::{CapSlot, ObjectRef, Rights};
use crate::{EndpointId, RegionId, TaskId, ThreadId};
use std::fmt;

/// A single recorded effect, in order of occurrence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The scheduler dispatched a thread at a tick.
    Dispatch {
        tick: u64,
        thread: ThreadId,
        task: TaskId,
    },
    /// A thread consumed compute cycles.
    Compute { thread: ThreadId, cycles: u32 },
    /// A thread blocked waiting to send.
    BlockSend {
        thread: ThreadId,
        endpoint: EndpointId,
    },
    /// A thread blocked waiting to receive.
    BlockRecv {
        thread: ThreadId,
        endpoint: EndpointId,
    },
    /// A send and a receive met and a message crossed the endpoint.
    Rendezvous {
        sender: ThreadId,
        receiver: ThreadId,
        endpoint: EndpointId,
        label: u64,
        bytes: usize,
    },
    /// A capability was moved from one task to another inside a message.
    CapTransfer {
        from: TaskId,
        to: TaskId,
        object: ObjectRef,
        rights: Rights,
        new_slot: CapSlot,
    },
    /// A thread read a byte from a region.
    MemRead {
        thread: ThreadId,
        region: RegionId,
        offset: usize,
        value: u8,
    },
    /// A thread wrote a byte to a region.
    MemWrite {
        thread: ThreadId,
        region: RegionId,
        offset: usize,
        value: u8,
    },
    /// A syscall was denied. This is the visible face of capability enforcement.
    Denied {
        thread: ThreadId,
        syscall: &'static str,
        reason: String,
    },
    /// A thread finished.
    Exit { thread: ThreadId },
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::Dispatch { tick, thread, task } => {
                write!(f, "[t{tick:>3}] dispatch thread#{thread} (task#{task})")
            }
            Event::Compute { thread, cycles } => {
                write!(f, "        thread#{thread} compute {cycles} cycles")
            }
            Event::BlockSend { thread, endpoint } => {
                write!(f, "        thread#{thread} blocks on send endpoint#{endpoint}")
            }
            Event::BlockRecv { thread, endpoint } => {
                write!(f, "        thread#{thread} blocks on recv endpoint#{endpoint}")
            }
            Event::Rendezvous {
                sender,
                receiver,
                endpoint,
                label,
                bytes,
            } => write!(
                f,
                "        IPC endpoint#{endpoint}: thread#{sender} -> thread#{receiver} label={label} ({bytes} bytes)"
            ),
            Event::CapTransfer {
                from,
                to,
                object,
                rights,
                new_slot,
            } => write!(
                f,
                "        cap transfer {object} [{rights}] task#{from} -> task#{to} into slot {new_slot}"
            ),
            Event::MemRead {
                thread,
                region,
                offset,
                value,
            } => write!(
                f,
                "        thread#{thread} read region#{region}[{offset}] = {value:#04x}"
            ),
            Event::MemWrite {
                thread,
                region,
                offset,
                value,
            } => write!(
                f,
                "        thread#{thread} write region#{region}[{offset}] = {value:#04x}"
            ),
            Event::Denied {
                thread,
                syscall,
                reason,
            } => write!(f, "        thread#{thread} {syscall} DENIED: {reason}"),
            Event::Exit { thread } => write!(f, "        thread#{thread} exit"),
        }
    }
}
