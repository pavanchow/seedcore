//! Seedcore: a deterministic microkernel simulator in pure std.
//!
//! Seedcore models the microkernel philosophy. A tiny privileged core provides
//! only four things: threads with a scheduler, address spaces, synchronous IPC,
//! and capabilities. Everything else (a memory pager, a filesystem, a console
//! driver) runs as an unprivileged user space service reached only through IPC.
//!
//! This is a teaching accurate model, not a bootable kernel. There is no
//! assembly, no hardware, no real context switch. Instead every task runs a
//! small deterministic program of syscall level operations, the core interprets
//! them, and every effect is recorded in a trace so the behaviour can be
//! inspected and asserted over.
//!
//! The security spine is capability based access control. A task can only touch
//! a kernel object (an endpoint, a memory region, a thread) when it holds a
//! capability for that object with the right permission. Capabilities are just
//! integer slots into a per task table. A task can never fabricate one: a slot
//! it was never granted, a guessed index, or a revoked slot all resolve to a
//! denial. Capabilities move between tasks only by explicit transfer inside an
//! IPC message.
//!
//! ```
//! use seedcore::prelude::*;
//!
//! let mut k = Kernel::new(42);
//! let server = k.create_task("server");
//! let client = k.create_task("client");
//! let ep = k.create_endpoint();
//!
//! // The client may send on the endpoint, the server may receive on it.
//! let c_send = k.grant(client, ObjectRef::Endpoint(ep), Rights::SEND);
//! let s_recv = k.grant(server, ObjectRef::Endpoint(ep), Rights::RECV);
//!
//! k.spawn_thread(server, "srv", 0, vec![Op::Recv { ep: s_recv }]);
//! k.spawn_thread(client, "cli", 0, vec![Op::Send {
//!     ep: c_send,
//!     msg: MsgSpec::new(1, b"ping".to_vec()),
//! }]);
//!
//! let report = k.run(64);
//! assert!(report.rendezvous >= 1);
//! ```

#![warn(clippy::pedantic)]
// A teaching simulator of small, bounded objects. The lints below are silenced
// deliberately, not because a finding was hard to fix:
//   - the accessors are tiny and pervasive, so must_use on every one is noise,
//   - Rights combinators return Self by value as value types are meant to,
//   - every width cast is on a value bounded by the simulation size, never user
//     input, so truncation and sign loss cannot actually occur,
//   - the op interpreter is one cohesive match that reads best in one place, and
//   - the internal unwraps encode kernel invariants: a panic there is a kernel
//     bug, not a caller error, so documenting it as an API panic would mislead.
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::missing_panics_doc)]

pub mod capability;
pub mod error;
pub mod ipc;
pub mod kernel;
pub mod memory;
pub mod prng;
pub mod scenario;
pub mod scheduler;
pub mod thread;
pub mod trace;

pub use capability::{CapEntry, CapId, CapSlot, CapTable, Capability, ObjectRef, Rights};
pub use error::KernelError;
pub use ipc::{Endpoint, MsgSpec};
pub use kernel::{Kernel, RunReport};
pub use memory::Region;
pub use prng::Prng;
pub use scheduler::{Policy, Scheduler};
pub use thread::{Op, Thread, ThreadState};
pub use trace::Event;

/// Common identifier aliases used across the kernel.
pub type TaskId = u32;
/// Identifier of a thread of execution inside a task.
pub type ThreadId = u32;
/// Identifier of an IPC endpoint kernel object.
pub type EndpointId = u32;
/// Identifier of a memory region kernel object.
pub type RegionId = u32;

/// The everyday imports for building and running a scenario.
pub mod prelude {
    pub use crate::capability::{CapId, CapSlot, Capability, ObjectRef, Rights};
    pub use crate::error::KernelError;
    pub use crate::ipc::MsgSpec;
    pub use crate::kernel::{Kernel, RunReport};
    pub use crate::scheduler::Policy;
    pub use crate::thread::{Op, ThreadState};
    pub use crate::trace::Event;
    pub use crate::{EndpointId, RegionId, TaskId, ThreadId};
}
