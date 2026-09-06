//! The microkernel core.
//!
//! This is the privileged part, and it is deliberately small. It provides only
//! four services: it creates and schedules threads, it owns address spaces and
//! memory regions, it carries synchronous IPC between threads, and it mints and
//! resolves capabilities. It does not know what a filesystem is, or a pager, or
//! a console. Those are ordinary tasks that happen to answer IPC. That split,
//! mechanism in the core and policy in user space, is the whole idea of a
//! microkernel.
//!
//! Every syscall a task issues is named by a capability slot, and the first
//! thing the core does is resolve that slot. If the slot is empty, the wrong
//! kind, or missing a right, the syscall is denied. There is no code path that
//! reaches a kernel object except through a resolved capability, which is what
//! makes the security properties hold by construction rather than by careful
//! checking scattered everywhere.

use crate::capability::{CapId, CapSlot, CapTable, Capability, ObjectRef, Rights};
use crate::error::KernelError;
use crate::ipc::{Endpoint, MsgSpec};
use crate::memory::Region;
use crate::prng::Prng;
use crate::scheduler::{Policy, Scheduler};
use crate::thread::{Op, PendingCap, PendingMsg, Thread, ThreadState};
use crate::trace::Event;
use crate::{EndpointId, RegionId, TaskId, ThreadId};
use std::collections::{BTreeMap, BTreeSet};

/// A task: an address space, a capability table, and its threads.
///
/// The address space is expressed entirely through the capability table. A task
/// can reach exactly the regions it holds a memory capability for, and nothing
/// else. There is no ambient authority.
#[derive(Debug, Clone)]
pub struct Task {
    /// Task identifier.
    pub id: TaskId,
    /// Human readable name.
    pub name: String,
    /// The capability table, the task view of the world.
    pub caps: CapTable,
    /// The threads belonging to this task.
    pub threads: Vec<ThreadId>,
}

/// What happened during one dispatched step, used by the run loop to decide
/// whether to put the thread back on the ready queue.
enum Outcome {
    /// The thread advanced and is still runnable.
    Advanced,
    /// The thread parked on IPC.
    Blocked,
    /// The thread finished.
    Exited,
}

/// A summary of a completed run, derived from the trace.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunReport {
    /// Number of ops executed.
    pub ops_executed: u64,
    /// Number of scheduler dispatches (context switches).
    pub context_switches: u64,
    /// Number of successful IPC rendezvous.
    pub rendezvous: u64,
    /// Number of capabilities transferred over IPC.
    pub cap_transfers: u64,
    /// Number of denied syscalls.
    pub denials: u64,
    /// Number of memory reads.
    pub mem_reads: u64,
    /// Number of memory writes.
    pub mem_writes: u64,
    /// Final simulator tick.
    pub final_tick: u64,
    /// True when the run stopped because every remaining thread was blocked and
    /// none could make progress.
    pub deadlocked: bool,
}

/// The microkernel.
#[derive(Debug, Clone)]
pub struct Kernel {
    tasks: BTreeMap<TaskId, Task>,
    threads: BTreeMap<ThreadId, Thread>,
    endpoints: BTreeMap<EndpointId, Endpoint>,
    regions: BTreeMap<RegionId, Region>,
    scheduler: Scheduler,
    prng: Prng,
    clock: u64,
    trace: Vec<Event>,
    next_task: TaskId,
    next_thread: ThreadId,
    next_endpoint: EndpointId,
    next_region: RegionId,
    next_cap_id: CapId,
    /// The capability derivation tree: each minted capability maps to the parent
    /// it was derived from, or `None` for a root capability created by a grant.
    /// Revoking a capability walks this tree to reach every descendant.
    cdt: BTreeMap<CapId, Option<CapId>>,
}

impl Kernel {
    /// A kernel seeded for determinism, using the round robin policy.
    pub fn new(seed: u64) -> Kernel {
        Kernel::with_policy(seed, Policy::RoundRobin)
    }

    /// A kernel with an explicit scheduling policy.
    pub fn with_policy(seed: u64, policy: Policy) -> Kernel {
        Kernel {
            tasks: BTreeMap::new(),
            threads: BTreeMap::new(),
            endpoints: BTreeMap::new(),
            regions: BTreeMap::new(),
            scheduler: Scheduler::new(policy),
            prng: Prng::new(seed),
            clock: 0,
            trace: Vec::new(),
            next_task: 0,
            next_thread: 0,
            next_endpoint: 0,
            next_region: 0,
            next_cap_id: 0,
            cdt: BTreeMap::new(),
        }
    }

    /// Allocate a fresh globally unique capability identity and record its parent
    /// in the derivation tree.
    fn mint_id(&mut self, parent: Option<CapId>) -> CapId {
        let id = self.next_cap_id;
        self.next_cap_id += 1;
        self.cdt.insert(id, parent);
        id
    }

    // -- object creation, all kernel privileged ------------------------------

    /// Create a task with an empty capability table.
    pub fn create_task(&mut self, name: impl Into<String>) -> TaskId {
        let id = self.next_task;
        self.next_task += 1;
        self.tasks.insert(
            id,
            Task {
                id,
                name: name.into(),
                caps: CapTable::new(),
                threads: Vec::new(),
            },
        );
        id
    }

    /// Create an IPC endpoint.
    pub fn create_endpoint(&mut self) -> EndpointId {
        let id = self.next_endpoint;
        self.next_endpoint += 1;
        self.endpoints.insert(id, Endpoint::new());
        id
    }

    /// Create a zeroed memory region owned by a task. Creating a region does not
    /// by itself grant access. The owner still needs a capability, minted with
    /// [`Kernel::grant`], to touch it.
    pub fn create_region(&mut self, owner: TaskId, len: usize) -> RegionId {
        let id = self.next_region;
        self.next_region += 1;
        self.regions.insert(id, Region::new(id, owner, len));
        id
    }

    /// Mint a capability into a task table and return its slot. This is the only
    /// operation that creates authority from nothing, and it is available only
    /// to whoever drives the kernel, never to a task from inside its program.
    pub fn grant(&mut self, task: TaskId, object: ObjectRef, rights: Rights) -> CapSlot {
        let id = self.mint_id(None);
        let table = &mut self
            .tasks
            .get_mut(&task)
            .expect("grant into a real task")
            .caps;
        table.install(Capability::new(object, rights), id)
    }

    /// Mint a derived capability from one a task already holds, with rights no
    /// stronger than the source, and install it into a target task. This is
    /// capability delegation: authority flows downward and can only ever narrow.
    /// `drop_mask` names the rights to strip, so the child carries
    /// `source.rights.minus(drop_mask)` and never more. The child is recorded as
    /// a descendant of the source in the derivation tree, so revoking the source
    /// later revokes this child too. Returns the new slot and the rights it
    /// actually carries.
    ///
    /// Minting is a privileged operation exposed to whoever drives the kernel,
    /// modelling a task asking the core to delegate. A task can never mint from a
    /// capability it does not hold: an absent source slot is a denial.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::NoSuchObject`] if either task does not exist, and
    /// [`KernelError::NoSuchCapability`] if the source slot is empty, fabricated,
    /// or revoked.
    pub fn mint(
        &mut self,
        from: TaskId,
        src_slot: CapSlot,
        to: TaskId,
        drop_mask: Rights,
    ) -> Result<(CapSlot, Rights), KernelError> {
        let src = self
            .tasks
            .get(&from)
            .ok_or(KernelError::NoSuchObject {
                object: ObjectRef::Task(from),
            })?
            .caps
            .entry(src_slot)
            .ok_or(KernelError::NoSuchCapability { slot: src_slot })?;
        let child_rights = src.cap.rights.minus(drop_mask);
        let id = self.mint_id(Some(src.id));
        let slot = self
            .tasks
            .get_mut(&to)
            .ok_or(KernelError::NoSuchObject {
                object: ObjectRef::Task(to),
            })?
            .caps
            .install(Capability::new(src.cap.object, child_rights), id);
        Ok((slot, child_rights))
    }

    /// Revoke a single capability slot from a task. A revoked slot is gone for
    /// good and any later use of that slot number is denied. This does not touch
    /// capabilities derived from it. For transitive revocation use
    /// [`Kernel::revoke_tree`].
    pub fn revoke(&mut self, task: TaskId, slot: CapSlot) -> Option<Capability> {
        self.tasks.get_mut(&task).and_then(|t| t.caps.remove(slot))
    }

    /// The derivation identity of the capability held at a task slot, if any.
    pub fn cap_id(&self, task: TaskId, slot: CapSlot) -> Option<CapId> {
        self.tasks.get(&task).and_then(|t| t.caps.id_of(slot))
    }

    /// Transitively revoke a capability and everything ever derived from it,
    /// wherever those descendants now live. This walks the derivation tree from
    /// the named slot, collects the whole subtree of identities, and removes
    /// every matching capability from every task table in the system. It is the
    /// operation that makes delegation safe: handing out a minted capability
    /// never costs the granter the ability to take it all back at once. Returns
    /// the number of capabilities removed.
    pub fn revoke_tree(&mut self, task: TaskId, slot: CapSlot) -> usize {
        let Some(root) = self.cap_id(task, slot) else {
            return 0;
        };
        // Collect the root and all its transitive descendants.
        let mut doomed: BTreeSet<CapId> = BTreeSet::new();
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            if !doomed.insert(id) {
                continue;
            }
            for (&child, &parent) in &self.cdt {
                if parent == Some(id) {
                    stack.push(child);
                }
            }
        }
        // Remove every capability whose identity is doomed, from every task.
        let mut removed = 0usize;
        for t in self.tasks.values_mut() {
            let hit: Vec<CapSlot> = t
                .caps
                .iter_entries()
                .filter(|(_, e)| doomed.contains(&e.id))
                .map(|(s, _)| s)
                .collect();
            for s in hit {
                t.caps.remove(s);
                removed += 1;
            }
        }
        // Drop the revoked identities from the tree so it cannot grow without
        // bound and so a stale id can never be revoked twice.
        for id in &doomed {
            self.cdt.remove(id);
        }
        removed
    }

    /// Spawn a thread in a task and make it ready to run.
    pub fn spawn_thread(
        &mut self,
        task: TaskId,
        name: impl Into<String>,
        priority: u8,
        program: Vec<Op>,
    ) -> ThreadId {
        let id = self.next_thread;
        self.next_thread += 1;
        let thread = Thread::new(id, task, name, priority, program);
        if let Some(t) = self.tasks.get_mut(&task) {
            t.threads.push(id);
        }
        self.threads.insert(id, thread);
        self.scheduler.enqueue(id, priority);
        id
    }

    // -- capability resolution -----------------------------------------------

    /// Resolve a slot in a task table to an object reference, checking the object
    /// kind and the required rights. Every failure mode is a denial: an absent
    /// slot (fabricated, guessed, or revoked), a wrong object kind, or a missing
    /// right. This single function is the choke point for all authority in the
    /// system.
    ///
    /// # Errors
    ///
    /// Returns a [`KernelError`] describing the denial: the task or slot is
    /// absent, the capability names the wrong kind of object, or it lacks a
    /// required right.
    pub fn resolve(
        &self,
        task: TaskId,
        slot: CapSlot,
        want_kind: &'static str,
        needed: Rights,
    ) -> Result<ObjectRef, KernelError> {
        let table = &self
            .tasks
            .get(&task)
            .ok_or(KernelError::NoSuchObject {
                object: ObjectRef::Task(task),
            })?
            .caps;
        let cap = table
            .get(slot)
            .ok_or(KernelError::NoSuchCapability { slot })?;
        if cap.object.kind() != want_kind {
            return Err(KernelError::WrongObject {
                slot,
                expected: want_kind,
            });
        }
        if !cap.rights.contains(needed) {
            return Err(KernelError::MissingRight { slot, needed });
        }
        Ok(cap.object)
    }

    // -- memory syscalls, non blocking ---------------------------------------

    /// Read one byte through a memory capability. Denied unless the calling
    /// thread task holds a region capability with the read right for the target.
    ///
    /// # Errors
    ///
    /// Returns a [`KernelError`] if the capability does not resolve to a readable
    /// region or the offset is out of bounds.
    pub fn sys_read(
        &self,
        thread: ThreadId,
        mem: CapSlot,
        offset: usize,
    ) -> Result<u8, KernelError> {
        let task = self.task_of(thread)?;
        let object = self.resolve(task, mem, "region", Rights::READ)?;
        let ObjectRef::Region(rid) = object else {
            unreachable!("resolve guaranteed a region")
        };
        let region = self.regions.get(&rid).ok_or(KernelError::NoSuchObject {
            object: ObjectRef::Region(rid),
        })?;
        region.read(offset)
    }

    /// Write one byte through a memory capability. Denied unless the calling
    /// thread task holds a region capability with the write right for the target.
    ///
    /// # Errors
    ///
    /// Returns a [`KernelError`] if the capability does not resolve to a writable
    /// region or the offset is out of bounds.
    pub fn sys_write(
        &mut self,
        thread: ThreadId,
        mem: CapSlot,
        offset: usize,
        value: u8,
    ) -> Result<(), KernelError> {
        let task = self.task_of(thread)?;
        let object = self.resolve(task, mem, "region", Rights::WRITE)?;
        let ObjectRef::Region(rid) = object else {
            unreachable!("resolve guaranteed a region")
        };
        let region = self.regions.get_mut(&rid).ok_or(KernelError::NoSuchObject {
            object: ObjectRef::Region(rid),
        })?;
        region.write(offset, value)
    }

    fn task_of(&self, thread: ThreadId) -> Result<TaskId, KernelError> {
        self.threads
            .get(&thread)
            .map(|t| t.task)
            .ok_or(KernelError::NoSuchObject {
                object: ObjectRef::Thread(thread),
            })
    }

    // -- the run loop --------------------------------------------------------

    /// Run the simulation until either no thread is ready or `max_ops` ops have
    /// executed, whichever comes first. Returns a summary derived from the trace.
    pub fn run(&mut self, max_ops: u64) -> RunReport {
        let trace_start = self.trace.len();
        let mut ops = 0u64;
        while ops < max_ops {
            let Some(tid) = self.scheduler.dispatch() else {
                break;
            };
            self.clock += 1;
            let task = self.threads[&tid].task;
            {
                let t = self.threads.get_mut(&tid).unwrap();
                t.state = ThreadState::Running;
                t.dispatches += 1;
            }
            self.trace.push(Event::Dispatch {
                tick: self.clock,
                thread: tid,
                task,
            });
            let outcome = self.step(tid);
            ops += 1;
            match outcome {
                Outcome::Advanced => {
                    let (state, prio) = {
                        let t = &self.threads[&tid];
                        (t.state, t.priority)
                    };
                    if matches!(state, ThreadState::Running) {
                        self.threads.get_mut(&tid).unwrap().state = ThreadState::Ready;
                        self.scheduler.enqueue(tid, prio);
                    }
                }
                Outcome::Blocked | Outcome::Exited => {}
            }
        }
        self.build_report(trace_start, ops)
    }

    /// Execute the current op of a running thread.
    fn step(&mut self, tid: ThreadId) -> Outcome {
        let Some(op) = self.threads.get(&tid).and_then(|t| t.current_op()).cloned() else {
            self.threads.get_mut(&tid).unwrap().state = ThreadState::Exited;
            self.trace.push(Event::Exit { thread: tid });
            return Outcome::Exited;
        };
        match op {
            Op::Compute(cycles) => {
                let t = self.threads.get_mut(&tid).unwrap();
                t.cycles += cycles as u64;
                t.pc += 1;
                self.trace.push(Event::Compute {
                    thread: tid,
                    cycles,
                });
                Outcome::Advanced
            }
            Op::Read { mem, offset } => {
                match self.sys_read(tid, mem, offset) {
                    Ok(value) => {
                        let region = self.region_id(tid, mem);
                        self.trace.push(Event::MemRead {
                            thread: tid,
                            region,
                            offset,
                            value,
                        });
                    }
                    Err(e) => self.deny(tid, "read", e),
                }
                self.threads.get_mut(&tid).unwrap().pc += 1;
                Outcome::Advanced
            }
            Op::Write { mem, offset, value } => {
                match self.sys_write(tid, mem, offset, value) {
                    Ok(()) => {
                        let region = self.region_id(tid, mem);
                        self.trace.push(Event::MemWrite {
                            thread: tid,
                            region,
                            offset,
                            value,
                        });
                    }
                    Err(e) => self.deny(tid, "write", e),
                }
                self.threads.get_mut(&tid).unwrap().pc += 1;
                Outcome::Advanced
            }
            Op::Send { ep, msg } => self.do_send(tid, ep, msg, false),
            Op::Reply { msg } => {
                if let Some(slot) = self.threads[&tid].reply_to {
                    self.do_send(tid, slot, msg, true)
                } else {
                    self.deny(tid, "reply", KernelError::NoReplyCapability);
                    self.threads.get_mut(&tid).unwrap().pc += 1;
                    Outcome::Advanced
                }
            }
            Op::Recv { ep } => self.do_recv(tid, ep),
            Op::Exit => {
                self.threads.get_mut(&tid).unwrap().state = ThreadState::Exited;
                self.trace.push(Event::Exit { thread: tid });
                Outcome::Exited
            }
        }
    }

    /// A send, shared by [`Op::Send`] and [`Op::Reply`]. When `consume_reply` is
    /// set the endpoint slot is a one shot reply capability that is destroyed
    /// after use.
    fn do_send(&mut self, tid: ThreadId, ep_slot: CapSlot, msg: MsgSpec, consume_reply: bool) -> Outcome {
        let task = self.threads[&tid].task;
        let ep_id = match self.resolve(task, ep_slot, "endpoint", Rights::SEND) {
            Ok(ObjectRef::Endpoint(id)) => id,
            Ok(_) => unreachable!("resolve guaranteed an endpoint"),
            Err(e) => {
                self.deny(tid, "send", e);
                self.threads.get_mut(&tid).unwrap().pc += 1;
                return Outcome::Advanced;
            }
        };

        // Resolve and move out the transferred capability, if any. Transfer
        // requires the grant right: a task cannot delegate authority it was not
        // permitted to delegate, and it cannot transfer a slot it does not hold.
        let pending_cap = match msg.transfer {
            None => None,
            Some(slot) => match self.tasks.get(&task).and_then(|t| t.caps.entry(slot)) {
                Some(entry) if entry.cap.rights.contains(Rights::GRANT) => {
                    self.tasks.get_mut(&task).unwrap().caps.remove(slot);
                    Some(PendingCap {
                        object: entry.cap.object,
                        rights: entry.cap.rights,
                        id: entry.id,
                    })
                }
                Some(_) => {
                    self.deny(
                        tid,
                        "send",
                        KernelError::MissingRight {
                            slot,
                            needed: Rights::GRANT,
                        },
                    );
                    self.threads.get_mut(&tid).unwrap().pc += 1;
                    return Outcome::Advanced;
                }
                None => {
                    self.deny(tid, "send", KernelError::NoSuchCapability { slot });
                    self.threads.get_mut(&tid).unwrap().pc += 1;
                    return Outcome::Advanced;
                }
            },
        };

        if consume_reply {
            self.tasks.get_mut(&task).unwrap().caps.remove(ep_slot);
            self.threads.get_mut(&tid).unwrap().reply_to = None;
        }

        let pending = PendingMsg {
            label: msg.label,
            bytes: msg.bytes,
            cap: pending_cap,
        };

        let waiting_receiver = self
            .endpoints
            .get_mut(&ep_id)
            .and_then(|ep| ep.receivers.pop_front());
        if let Some(receiver) = waiting_receiver {
            self.deliver(tid, receiver, ep_id, pending, receiver);
            self.threads.get_mut(&tid).unwrap().pc += 1;
            Outcome::Advanced
        } else {
            self.endpoints.get_mut(&ep_id).unwrap().senders.push_back(tid);
            let t = self.threads.get_mut(&tid).unwrap();
            t.state = ThreadState::BlockedSend(ep_id);
            t.pending = Some(pending);
            self.trace.push(Event::BlockSend {
                thread: tid,
                endpoint: ep_id,
            });
            Outcome::Blocked
        }
    }

    fn do_recv(&mut self, tid: ThreadId, ep_slot: CapSlot) -> Outcome {
        let task = self.threads[&tid].task;
        let ep_id = match self.resolve(task, ep_slot, "endpoint", Rights::RECV) {
            Ok(ObjectRef::Endpoint(id)) => id,
            Ok(_) => unreachable!("resolve guaranteed an endpoint"),
            Err(e) => {
                self.deny(tid, "recv", e);
                self.threads.get_mut(&tid).unwrap().pc += 1;
                return Outcome::Advanced;
            }
        };

        let waiting_sender = self
            .endpoints
            .get_mut(&ep_id)
            .and_then(|ep| ep.senders.pop_front());
        if let Some(sender) = waiting_sender {
            let pending = self
                .threads
                .get_mut(&sender)
                .unwrap()
                .pending
                .take()
                .expect("a blocked sender always holds its pending message");
            self.deliver(sender, tid, ep_id, pending, sender);
            self.threads.get_mut(&tid).unwrap().pc += 1;
            Outcome::Advanced
        } else {
            self.endpoints.get_mut(&ep_id).unwrap().receivers.push_back(tid);
            let t = self.threads.get_mut(&tid).unwrap();
            t.state = ThreadState::BlockedRecv(ep_id);
            self.trace.push(Event::BlockRecv {
                thread: tid,
                endpoint: ep_id,
            });
            Outcome::Blocked
        }
    }

    /// Complete a rendezvous: copy the message, move any capability, wake the
    /// partner that was blocked, and record it. `blocked_partner` is the thread
    /// that was parked and must be returned to the ready queue. The other thread
    /// is the running dispatch and is requeued by the run loop.
    fn deliver(
        &mut self,
        sender: ThreadId,
        receiver: ThreadId,
        ep_id: EndpointId,
        pending: PendingMsg,
        blocked_partner: ThreadId,
    ) {
        let sender_task = self.threads[&sender].task;
        let receiver_task = self.threads[&receiver].task;

        self.trace.push(Event::Rendezvous {
            sender,
            receiver,
            endpoint: ep_id,
            label: pending.label,
            bytes: pending.bytes.len(),
        });

        if let Some(cap) = pending.cap {
            let new_slot = self
                .tasks
                .get_mut(&receiver_task)
                .unwrap()
                .caps
                .install(Capability::new(cap.object, cap.rights), cap.id);
            self.trace.push(Event::CapTransfer {
                from: sender_task,
                to: receiver_task,
                object: cap.object,
                rights: cap.rights,
                new_slot,
            });
            if let ObjectRef::Endpoint(_) = cap.object {
                if cap.rights.contains(Rights::SEND) {
                    self.threads.get_mut(&receiver).unwrap().reply_to = Some(new_slot);
                }
            }
        }

        // Advance the blocked partner past its own IPC op and re-ready it.
        {
            let partner = self.threads.get_mut(&blocked_partner).unwrap();
            partner.pc += 1;
            partner.state = ThreadState::Ready;
            let prio = partner.priority;
            self.scheduler.enqueue(blocked_partner, prio);
        }
    }

    fn deny(&mut self, tid: ThreadId, syscall: &'static str, err: KernelError) {
        self.trace.push(Event::Denied {
            thread: tid,
            syscall,
            reason: err.to_string(),
        });
    }

    fn region_id(&self, tid: ThreadId, mem: CapSlot) -> RegionId {
        let task = self.threads[&tid].task;
        match self.tasks[&task].caps.get(mem).map(|c| c.object) {
            Some(ObjectRef::Region(id)) => id,
            _ => u32::MAX,
        }
    }

    fn build_report(&self, trace_start: usize, ops: u64) -> RunReport {
        let mut report = RunReport {
            ops_executed: ops,
            context_switches: self.scheduler.context_switches,
            final_tick: self.clock,
            ..RunReport::default()
        };
        for event in &self.trace[trace_start..] {
            match event {
                Event::Rendezvous { .. } => report.rendezvous += 1,
                Event::CapTransfer { .. } => report.cap_transfers += 1,
                Event::Denied { .. } => report.denials += 1,
                Event::MemRead { .. } => report.mem_reads += 1,
                Event::MemWrite { .. } => report.mem_writes += 1,
                _ => {}
            }
        }
        let all_done = self
            .threads
            .values()
            .all(|t| matches!(t.state, ThreadState::Exited) || t.is_done());
        report.deadlocked = !self.scheduler.has_ready() && !all_done && ops < u64::MAX;
        report
    }

    // -- read only accessors for the CLI and tests ---------------------------

    /// The full event trace so far.
    pub fn trace(&self) -> &[Event] {
        &self.trace
    }

    /// Look up a task.
    pub fn task(&self, id: TaskId) -> Option<&Task> {
        self.tasks.get(&id)
    }

    /// Look up a thread.
    pub fn thread(&self, id: ThreadId) -> Option<&Thread> {
        self.threads.get(&id)
    }

    /// Look up a region.
    pub fn region(&self, id: RegionId) -> Option<&Region> {
        self.regions.get(&id)
    }

    /// Iterate tasks in id order.
    pub fn tasks(&self) -> impl Iterator<Item = &Task> {
        self.tasks.values()
    }

    /// Iterate threads in id order.
    pub fn threads(&self) -> impl Iterator<Item = &Thread> {
        self.threads.values()
    }

    /// The current simulator tick.
    pub fn clock(&self) -> u64 {
        self.clock
    }

    /// Mutable access to the seeded generator, for scenario construction.
    pub fn prng(&mut self) -> &mut Prng {
        &mut self.prng
    }
}
