//! Ready made scenarios.
//!
//! These build a [`Kernel`] populated with tasks, services, endpoints and
//! regions, wired together with capabilities. They are the same building blocks
//! a user of the library would assemble by hand, collected here so the command
//! line tool and the examples have something concrete to run.

use crate::capability::{ObjectRef, Rights};
use crate::ipc::MsgSpec;
use crate::kernel::Kernel;
use crate::thread::Op;

/// The guided demo.
///
/// It stands up two user space services, a filesystem and a console, then runs a
/// client task that reads a file through the filesystem over IPC and prints
/// through the console. The client hands the filesystem a one shot reply
/// capability inside the request, the filesystem writes the file bytes into a
/// region shared with the client and replies, and the client reads them back.
/// Finally the client makes two illegal moves that the core denies: it names a
/// capability slot it never held, and it tries to send on a region capability.
///
/// Everything here is ordinary task code. The only privileged steps are the
/// object creations and the grants, which model a boot time capability
/// distribution.
pub fn demo(seed: u64) -> Kernel {
    let mut k = Kernel::new(seed);

    let fs = k.create_task("filesystem");
    let con = k.create_task("console");
    let app = k.create_task("app");

    let fs_ep = k.create_endpoint();
    let con_ep = k.create_endpoint();
    let reply_ep = k.create_endpoint();

    let shared = k.create_region(fs, 16); // a buffer the app and fs both see
    let fs_private = k.create_region(fs, 16); // the fs private scratch, app cannot reach it
    let _ = fs_private;

    // Filesystem capabilities: receive on its endpoint, and read and write both
    // the shared buffer and its own private scratch.
    let fs_recv = k.grant(fs, ObjectRef::Endpoint(fs_ep), Rights::RECV);
    let fs_shared = k.grant(fs, ObjectRef::Region(shared), Rights::READ | Rights::WRITE);
    let _fs_scratch = k.grant(fs, ObjectRef::Region(fs_private), Rights::READ | Rights::WRITE);

    // Console capability: receive on its endpoint.
    let con_recv = k.grant(con, ObjectRef::Endpoint(con_ep), Rights::RECV);

    // App capabilities, granted in a fixed order so the program can name slots.
    let app_fs = k.grant(app, ObjectRef::Endpoint(fs_ep), Rights::SEND); // slot 0
    let app_reply_recv = k.grant(app, ObjectRef::Endpoint(reply_ep), Rights::RECV); // slot 1
    let app_reply_grant = k.grant(
        app,
        ObjectRef::Endpoint(reply_ep),
        Rights::SEND | Rights::GRANT,
    ); // slot 2, handed to the fs
    let app_shared = k.grant(app, ObjectRef::Region(shared), Rights::READ | Rights::WRITE); // slot 3
    let app_con = k.grant(app, ObjectRef::Endpoint(con_ep), Rights::SEND); // slot 4

    // Filesystem service: take one request, do work, publish the file into the
    // shared buffer, and reply over the received reply capability.
    k.spawn_thread(
        fs,
        "fs-worker",
        0,
        vec![
            Op::Recv { ep: fs_recv },
            Op::Compute(5),
            Op::Write {
                mem: fs_shared,
                offset: 0,
                value: 0x48, // 'H'
            },
            Op::Write {
                mem: fs_shared,
                offset: 1,
                value: 0x49, // 'I'
            },
            Op::Reply {
                msg: MsgSpec::new(2, b"ok".to_vec()),
            },
            Op::Exit,
        ],
    );

    // Console service: take one print request and finish.
    k.spawn_thread(
        con,
        "con-worker",
        0,
        vec![Op::Recv { ep: con_recv }, Op::Compute(1), Op::Exit],
    );

    // The client.
    k.spawn_thread(
        app,
        "app-main",
        0,
        vec![
            Op::Compute(3),
            Op::Send {
                ep: app_fs,
                msg: MsgSpec::with_cap(1, b"read:/hello".to_vec(), app_reply_grant),
            },
            Op::Recv {
                ep: app_reply_recv,
            },
            Op::Read {
                mem: app_shared,
                offset: 0,
            },
            Op::Read {
                mem: app_shared,
                offset: 1,
            },
            Op::Send {
                ep: app_con,
                msg: MsgSpec::new(9, b"HI".to_vec()),
            },
            // Unauthorized: a capability slot the app was never granted.
            Op::Read {
                mem: 99,
                offset: 0,
            },
            // Unauthorized: using a region capability where an endpoint is
            // required. The core refuses the type confusion.
            Op::Send {
                ep: app_shared,
                msg: MsgSpec::new(7, b"nope".to_vec()),
            },
            Op::Exit,
        ],
    );

    k
}

/// A clean producer and consumer pipeline, with no rogue task and no denials.
///
/// Each of `pairs` producers sends a burst of `burst` messages to its own
/// consumer over a private endpoint. Half the pairs spawn the consumer first so
/// it blocks waiting, half spawn the producer first, so both IPC arrival orders
/// are exercised. Nothing here forges or misuses a capability, so a correct run
/// records exactly `pairs * burst` rendezvous and zero denials. The IPC gate uses
/// this to check exactly once delivery against an independently computed count.
pub fn pipeline(seed: u64, pairs: u32, burst: u32) -> Kernel {
    let mut k = Kernel::new(seed);
    let pairs = pairs.max(1);
    let burst = burst.max(1);

    for pair in 0..pairs {
        let producer = k.create_task(format!("producer-{pair}"));
        let consumer = k.create_task(format!("consumer-{pair}"));
        let ep = k.create_endpoint();

        let p_send = k.grant(producer, ObjectRef::Endpoint(ep), Rights::SEND);
        let c_recv = k.grant(consumer, ObjectRef::Endpoint(ep), Rights::RECV);

        let mut prod = Vec::new();
        let mut cons = Vec::new();
        for i in 0..burst {
            prod.push(Op::Send {
                ep: p_send,
                msg: MsgSpec::new(i as u64, vec![i as u8]),
            });
            cons.push(Op::Recv { ep: c_recv });
        }
        prod.push(Op::Exit);
        cons.push(Op::Exit);

        if (pair + seed as u32).is_multiple_of(2) {
            k.spawn_thread(consumer, format!("consumer-{pair}"), 0, cons);
            k.spawn_thread(producer, format!("producer-{pair}"), 0, prod);
        } else {
            k.spawn_thread(producer, format!("producer-{pair}"), 0, prod);
            k.spawn_thread(consumer, format!("consumer-{pair}"), 0, cons);
        }
    }

    k
}

/// A randomized producer and consumer stress scenario for the command line
/// `run` mode and the fuzzing gates.
///
/// It creates `pairs` producer and consumer couples. Each producer sends a burst
/// of messages to its consumer over a private endpoint, with the payload driven
/// by the seed, and each consumer receives them. A shared region per pair lets
/// the producer publish a byte the consumer reads back, exercising shared memory.
/// One extra rogue task repeatedly attempts to use fabricated capability slots
/// so the denial path is always exercised. The whole thing is a pure function of
/// the seed and the parameters.
pub fn stress(seed: u64, pairs: u32, burst: u32) -> Kernel {
    let mut k = Kernel::new(seed);
    let pairs = pairs.max(1);
    let burst = burst.max(1);

    for pair in 0..pairs {
        let producer = k.create_task(format!("producer-{pair}"));
        let consumer = k.create_task(format!("consumer-{pair}"));
        let ep = k.create_endpoint();
        let region = k.create_region(producer, 8);

        let p_send = k.grant(producer, ObjectRef::Endpoint(ep), Rights::SEND);
        let p_mem = k.grant(producer, ObjectRef::Region(region), Rights::READ | Rights::WRITE);
        let c_recv = k.grant(consumer, ObjectRef::Endpoint(ep), Rights::RECV);
        let c_mem = k.grant(consumer, ObjectRef::Region(region), Rights::READ);

        let mut prod_ops = Vec::new();
        let mut cons_ops = Vec::new();
        for i in 0..burst {
            let payload = k.prng().byte();
            let label = k.prng().next_u64();
            prod_ops.push(Op::Write {
                mem: p_mem,
                offset: (i % 8) as usize,
                value: payload,
            });
            prod_ops.push(Op::Compute(1 + (payload as u32 % 3)));
            prod_ops.push(Op::Send {
                ep: p_send,
                msg: MsgSpec::new(label, vec![payload]),
            });
            cons_ops.push(Op::Recv { ep: c_recv });
            cons_ops.push(Op::Read {
                mem: c_mem,
                offset: (i % 8) as usize,
            });
        }
        prod_ops.push(Op::Exit);
        cons_ops.push(Op::Exit);

        let prod_prio = (k.prng().below(4)) as u8;
        let cons_prio = (k.prng().below(4)) as u8;
        k.spawn_thread(producer, format!("producer-{pair}"), prod_prio, prod_ops);
        k.spawn_thread(consumer, format!("consumer-{pair}"), cons_prio, cons_ops);
    }

    // A rogue task that only ever tries to touch things it has no capability
    // for. Every one of its ops must be denied.
    let rogue = k.create_task("rogue");
    let mut rogue_ops = Vec::new();
    for _ in 0..burst {
        let slot = 1000 + k.prng().below(1000);
        rogue_ops.push(Op::Read {
            mem: slot,
            offset: 0,
        });
        rogue_ops.push(Op::Send {
            ep: slot,
            msg: MsgSpec::new(0, vec![0]),
        });
    }
    rogue_ops.push(Op::Exit);
    k.spawn_thread(rogue, "rogue", 0, rogue_ops);

    k
}
