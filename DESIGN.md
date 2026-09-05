# Seedcore design

This document describes the model Seedcore implements and why each correctness
gate proves what it claims. Seedcore is a deterministic simulator, so every
statement here is about a model of a microkernel, not about hardware. The model
is chosen to be faithful to how a real capability microkernel behaves at the
level of objects, authority, and message passing.

## The microkernel split

A microkernel keeps the privileged core as small as possible and moves policy
into unprivileged user space. Seedcore's core provides exactly four mechanisms.

1. Threads and a scheduler.
2. Address spaces expressed through memory regions.
3. Synchronous IPC over endpoints.
4. Capabilities that gate access to every object.

There is no filesystem, pager, or driver in the core. Those are ordinary tasks.
A task becomes a service simply by receiving on an endpoint and answering. The
core cannot tell a service apart from any other task, which is the point. Policy
lives entirely in user space, and the core only carries mechanism.

Execution is modelled as an instruction stream. Each thread carries a program of
operations (`Compute`, `Send`, `Recv`, `Reply`, `Read`, `Write`, `Exit`). The
core dispatches a thread, executes one operation, accounts for its cost, and
records the effect. There is no hidden state inside a task beyond its program
counter and its capability table, which is what keeps the whole system
inspectable and reproducible.

## Capabilities and unforgeability

A capability is a pair of an object reference and a set of rights. Tasks never
hold a capability value. They hold an integer slot into a per task capability
table, and only the core can turn a slot into an object. This indirection is the
whole security story.

Three design choices make a capability unforgeable.

- A task can name any integer, but only integers that index a live table entry
  resolve to anything. Naming an integer is not authority.
- Slots come from a counter that only ever increases and are never reused. A
  revoked slot stays dead forever, so a task cannot guess or replay an old slot
  to reach a freed object or a successor object.
- The only operation that creates a capability from nothing is the kernel side
  grant, which models boot time authority distribution. No task operation mints
  authority.

Authority moves between tasks by explicit transfer inside a message, and only if
the capability carries the grant right. The core removes the capability from the
sender and installs it in the receiver. That is the sole path by which a task
gains a capability it did not start with.

Every syscall resolves its target slot through one function that checks three
things in order: the slot is present, the object is of the expected kind, and the
capability carries the required rights. A failure at any step is a denial, not a
panic. Because this is the only path to any object, the security properties hold
by construction rather than by scattered checks.

Why gate 1 proves this. The capability gate builds randomized scenarios and
drives the core with a mixture of real, fabricated, and revoked slots. It keeps
an independent shadow model of who was granted what, and asserts that a syscall
succeeds if and only if the shadow says the caller holds a matching capability
with the required right. Fabricated and revoked slots are always denied, and a
read only capability never permits a write. The success condition is checked
against an external model, not against the core's own answer, so the test cannot
be satisfied by a core that simply agrees with itself.

## Synchronous IPC

IPC is a blocking rendezvous. A send and a receive on the same endpoint must
meet. Whichever arrives first blocks. When they meet the message is copied once
and both sides become runnable. An endpoint holds a queue of blocked senders and
a queue of blocked receivers, and at most one queue is ever non empty because the
core pairs a sender and a receiver as soon as both are present.

A message can carry a capability. On delivery the capability is installed into
the receiver table, and if it is an endpoint capability with the send right the
core records it as the receiver's reply capability. A service answers a client
with `Reply`, which sends over that one shot reply capability and then destroys
it. This is the seL4 style reply pattern, and it means a service does not need a
standing capability back to every client it ever serves.

Why gate 2 proves this. The IPC gate runs many producer and consumer pairs with
bursts of messages, in both arrival orders, and asserts that the number of
rendezvous equals the number of messages sent, with no denials and no thread
left blocked. Exactly once delivery is the equality of sent and received counts
across randomized, seeded runs. A separate case forces the receiver to arrive
first and asserts it blocked before delivery. Two more cases assert that a
transferred capability leaves the sender and appears in the receiver, and that a
transfer without the grant right is denied while the sender keeps the capability.

## Address space isolation

Each task has its own address space. In this model an address space is the set of
regions the task holds a memory capability for. A region is a kernel object of a
fixed length of bytes. There is no flat global memory a task could walk off the
end of into a neighbour, so isolation is total by construction. The only way to
touch a region is a memory capability, and the only way to get one is a grant or
a transfer.

Two tasks share memory when, and only when, they both hold a capability for the
same region. That models a shared buffer or a pager backed page. Everything else
is private. A read only sharing is expressed by granting the read right without
the write right.

Why gate 3 proves this. The isolation gate gives each task a private region and
shares one region between two of three tasks. Over random access patterns it
asserts a task can touch a region if and only if it holds a capability for it,
with the access in bounds. A focused case writes a byte through one task and
reads the same byte back through another task capability to the shared region,
confirms the read only holder cannot write, and confirms an outsider that holds
nothing is denied on every slot it names. The determinism property is asserted by
running the same seed twice and requiring byte identical traces, and by requiring
different seeds to diverge.

## User space services

The demo assembles three tasks. A filesystem service receives requests, writes
file bytes into a region it shares with the client, and replies over the reply
capability the client handed it. A console service receives a print request. A
client reads a file over IPC, reads the shared bytes back, prints, and then makes
two illegal moves that the core denies: it names a slot it never held, and it
tries to send on a memory capability. None of these services is privileged. Each
is an ordinary task reached only through an endpoint capability, which is exactly
how a microkernel factors an operating system.

## Determinism

The only sources of nondeterminism a real kernel faces are interrupts, hardware
timing, and true randomness. Seedcore has none of them. Scheduling is a
deterministic policy over a deterministic ready queue, and any randomness in a
scenario comes from a seeded generator. The trace is therefore a pure function of
the seed and the programs, which is what makes the whole system testable by
comparing traces.
