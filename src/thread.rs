//! Threads and the tiny program they run.
//!
//! A real microkernel context switches register state. Seedcore has no
//! registers. Instead each thread carries a small program: a list of [`Op`]
//! values, each of which is one syscall level step. The kernel is the
//! interpreter. It dispatches a thread, executes one op, accounts for the cost,
//! and moves on. An op that blocks (a send or receive with no partner yet)
//! parks the thread until IPC wakes it, and execution resumes at the next op.
//!
//! Modelling execution as an explicit instruction stream is what makes the whole
//! simulator deterministic and inspectable. There is no hidden state inside a
//! task, only its program, its program counter, and its capabilities.

use crate::capability::CapSlot;
use crate::ipc::MsgSpec;
use crate::{EndpointId, TaskId};

/// One step of a thread program. Each variant is a syscall the task asks the
/// kernel to perform on its behalf, named by capability slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// Burn compute cycles. Models useful work between syscalls and feeds the
    /// context switch accounting.
    Compute(u32),
    /// Send a message on the endpoint named by capability slot `ep`. Requires
    /// [`crate::Rights::SEND`]. Blocks until a receiver is ready.
    Send { ep: CapSlot, msg: MsgSpec },
    /// Receive a message on the endpoint named by `ep`. Requires
    /// [`crate::Rights::RECV`]. Blocks until a sender is ready.
    Recv { ep: CapSlot },
    /// Reply to the most recently received message, using the reply capability
    /// that arrived with it. This is how a user space service answers a client
    /// without holding a standing capability back to every client.
    Reply { msg: MsgSpec },
    /// Read one byte from the region named by memory capability `mem` at
    /// `offset`. Requires [`crate::Rights::READ`].
    Read { mem: CapSlot, offset: usize },
    /// Write one byte to the region named by `mem`. Requires
    /// [`crate::Rights::WRITE`].
    Write {
        mem: CapSlot,
        offset: usize,
        value: u8,
    },
    /// Terminate the thread.
    Exit,
}

/// The runtime state of a thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    /// Runnable and waiting for the scheduler.
    Ready,
    /// Currently running (held only transiently during a dispatch).
    Running,
    /// Parked waiting to send on an endpoint.
    BlockedSend(EndpointId),
    /// Parked waiting to receive on an endpoint.
    BlockedRecv(EndpointId),
    /// Finished.
    Exited,
}

/// A capability captured out of a sender at send time, waiting to be installed
/// into a receiver at delivery. Holding the resolved capability rather than a
/// slot is what makes the move atomic: the sender has already lost it.
#[derive(Debug, Clone)]
pub(crate) struct PendingCap {
    pub object: crate::capability::ObjectRef,
    pub rights: crate::capability::Rights,
    /// The derivation identity, preserved so the capability stays the same one
    /// after the move and remains reachable by transitive revocation.
    pub id: crate::capability::CapId,
}

/// A message that a blocked sender is holding, fully resolved.
#[derive(Debug, Clone)]
pub(crate) struct PendingMsg {
    pub label: u64,
    pub bytes: Vec<u8>,
    pub cap: Option<PendingCap>,
}

/// A thread of execution belonging to a task.
#[derive(Debug, Clone)]
pub struct Thread {
    /// Thread identifier.
    pub id: crate::ThreadId,
    /// The owning task.
    pub task: TaskId,
    /// A human readable name.
    pub name: String,
    /// Scheduling state.
    pub state: ThreadState,
    /// The program this thread runs.
    pub program: Vec<Op>,
    /// The program counter, an index into `program`.
    pub pc: usize,
    /// Scheduling priority, smaller is more urgent.
    pub priority: u8,
    /// Total compute cycles consumed.
    pub cycles: u64,
    /// Number of times this thread was dispatched.
    pub dispatches: u64,
    /// A message held while blocked on a send.
    pub(crate) pending: Option<PendingMsg>,
    /// The endpoint to reply on, set when a received message carried a reply
    /// capability.
    pub(crate) reply_to: Option<EndpointId>,
}

impl Thread {
    /// Build a ready thread.
    pub fn new(
        id: crate::ThreadId,
        task: TaskId,
        name: impl Into<String>,
        priority: u8,
        program: Vec<Op>,
    ) -> Thread {
        Thread {
            id,
            task,
            name: name.into(),
            state: ThreadState::Ready,
            program,
            pc: 0,
            priority,
            cycles: 0,
            dispatches: 0,
            pending: None,
            reply_to: None,
        }
    }

    /// The op at the program counter, if any remain.
    pub fn current_op(&self) -> Option<&Op> {
        self.program.get(self.pc)
    }

    /// Whether the thread has finished or run off the end of its program.
    pub fn is_done(&self) -> bool {
        matches!(self.state, ThreadState::Exited) || self.pc >= self.program.len()
    }
}
