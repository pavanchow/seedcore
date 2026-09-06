# Seedcore

A deterministic microkernel simulator in pure Rust std, with capability based
isolation, synchronous IPC, and user space services.

Live playground: https://pavanchow.github.io/seedcore/

## What this is, honestly

Seedcore is a teaching accurate model of a microkernel, not a bootable one.
There is no assembly, no hardware, no real context switch. Instead it models the
microkernel philosophy directly and precisely: a tiny privileged core provides
only four things, and everything else lives in user space.

The core provides:

1. Threads and a deterministic scheduler.
2. Address spaces, so memory is private unless a capability says otherwise.
3. Synchronous IPC, a blocking send and receive rendezvous over endpoints.
4. Capabilities, unforgeable tokens that gate every access to every object,
   including delegation with reduced rights and transitive revocation.

Everything else, a memory pager, a filesystem, a console driver, runs as an
ordinary unprivileged task that answers IPC. The core does not know what a
filesystem is. That separation, mechanism in the kernel and policy in user
space, is the whole point of a microkernel.

Each task runs a small deterministic program of syscall level operations. The
core interprets them, accounts for their cost, and records every effect in a
trace. Because the only inputs are the seed and the programs, a run reproduces
byte for byte.

## The gap it fills, and why capabilities matter

Most operating system teaching material either drowns in real hardware detail or
hand waves security away. Seedcore isolates the one idea that makes microkernels
interesting to a security engineer: capability based access control. A task
holds no ambient authority. It cannot name a file, a page, or another task
unless it holds a capability for it, and it cannot forge one. Authority moves
between tasks only by explicit transfer inside a message. This is the model
behind seL4 and other capability kernels, reduced to something you can read in
an afternoon and fuzz in a test.

Distinct from Aurora, a broader monolithic style kernel simulator, Seedcore is
deliberately minimal. Its value is the capability spine plus address space
isolation, not breadth of features.

## Quickstart

```
cargo run --bin seedcore -- demo
cargo run --bin seedcore -- run --seed 42 --pairs 4 --burst 3
cargo run --bin seedcore -- delegate
cargo run --bin seedcore -- help
```

The `demo` command stands up a filesystem service and a console service, runs a
client that reads a file over IPC and prints it, transfers a one shot reply
capability inside the request, shares a memory region between the client and the
filesystem, and then shows the core denying two unauthorized accesses.

The `delegate` command shows capability delegation and transitive revocation. An
owner delegates a region to an editor, the editor sub delegates a read only copy
to a viewer, and revoking the editor capability cascades to the derived viewer
copy while the owner keeps its own access.

## API

```rust
use seedcore::prelude::*;

let mut k = Kernel::new(42);
let server = k.create_task("server");
let client = k.create_task("client");
let ep = k.create_endpoint();

let c_send = k.grant(client, ObjectRef::Endpoint(ep), Rights::SEND);
let s_recv = k.grant(server, ObjectRef::Endpoint(ep), Rights::RECV);

k.spawn_thread(server, "srv", 0, vec![Op::Recv { ep: s_recv }, Op::Exit]);
k.spawn_thread(client, "cli", 0, vec![
    Op::Send { ep: c_send, msg: MsgSpec::new(1, b"ping".to_vec()) },
    Op::Exit,
]);

let report = k.run(64);
assert_eq!(report.rendezvous, 1);
```

Core types:

- `Kernel`: creates objects, mints capabilities with `grant`, delegates weaker
  copies with `mint`, revokes a whole derivation subtree with `revoke_tree`,
  spawns threads, and runs the loop.
- `ObjectRef`: an endpoint, a region, a thread, or a task.
- `Rights`: `SEND`, `RECV`, `GRANT`, `READ`, `WRITE`, combined with `|`.
- `Op`: one syscall level step in a thread program (`Compute`, `Send`, `Recv`,
  `Reply`, `Read`, `Write`, `Exit`).
- `Event`: one recorded effect in the trace.
- `RunReport`: the summary of a run.

## The correctness gate

Five properties are asserted over randomized, seeded, bounded scenarios, plus
unit tests per module. Every gate compares the kernel against an independent
shadow model that decides what should happen without ever calling the kernel, so
a pass is never vacuous. Set `SEEDCORE_FUZZ_OPS` to raise the bounds.

1. Capability unforgeability and enforcement (`tests/capability.rs`). A syscall
   succeeds if and only if the caller holds a capability of the right kind with
   the right permission. Fabricated, guessed, and revoked slots are always
   denied, and no capability can be used for an operation whose right it lacks.
2. IPC correctness (`tests/ipc.rs`). Synchronous send and receive deliver every
   message exactly once, blocking semantics are correct in either arrival order,
   and a transferred capability moves from sender to receiver and leaves the
   sender.
3. Address space isolation and determinism (`tests/isolation.rs`). A task can
   touch only the regions it holds a capability for, a shared region genuinely
   carries data between tasks while outsiders are denied, and the same seed
   produces a byte identical trace.
4. The bounded stress harness (`tests/stress.rs`). It drives the kernel from
   many seeds with a mixture of real, fabricated, revoked, minted, and cross task
   slots, and checks every enforcement, isolation, IPC exactly once, and
   determinism claim at once against the shadow. It hunts for any panic,
   overflow, hang, lost or duplicated message, or access granted without the
   capability. The footprint is bounded, so a large op budget costs time, not
   memory.
5. The capability derivation tree (`tests/derivation.rs`). Minting never adds a
   right the parent lacked, and revoking a capability removes exactly its
   subtree, wherever the descendants live and however they travelled, while
   everything outside the subtree is untouched. Descent is computed by the
   shadow, so a wrong subtree in the kernel is a detectable disagreement.

Run them:

```
cargo test
SEEDCORE_FUZZ_OPS=1000000 cargo test
```

At a million ops the auth harness runs two million shadow comparisons per pass,
about a quarter allowed and the rest denied, with zero disagreement.

## Design

See [DESIGN.md](DESIGN.md) for the model in full: the microkernel split,
capabilities and unforgeability, synchronous IPC, address space isolation, user
space services, and why each gate proves its claim.

## License

MIT.
