//! Gate 2: synchronous IPC correctness.
//!
//! Synchronous send and receive must deliver every message exactly once. A
//! blocked sender waits for a receiver and vice versa, no message is lost or
//! duplicated, and a capability carried in a message moves from the sender table
//! into the receiver table and leaves the sender.

use seedcore::prelude::*;
use seedcore::Kernel;

fn fuzz_scale() -> u32 {
    std::env::var("SEEDCORE_FUZZ_OPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .map(|n: u64| (n / 100).clamp(1, 64) as u32)
        .unwrap_or(8)
}

#[test]
fn every_message_is_delivered_exactly_once() {
    let scale = fuzz_scale();
    for seed in 0..12u64 {
        let pairs = 1 + (seed as u32 % scale.max(1));
        let burst = 1 + ((seed as u32 * 7) % 9);
        let mut k = Kernel::new(seed);

        for p in 0..pairs {
            let producer = k.create_task(format!("p{p}"));
            let consumer = k.create_task(format!("c{p}"));
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
            // Sometimes the consumer starts first (blocks waiting), sometimes the
            // producer does. Both orders must rendezvous correctly.
            if seed % 2 == 0 {
                k.spawn_thread(consumer, "c", 0, cons);
                k.spawn_thread(producer, "p", 0, prod);
            } else {
                k.spawn_thread(producer, "p", 0, prod);
                k.spawn_thread(consumer, "c", 0, cons);
            }
        }

        let report = k.run(100_000);
        let expected = (pairs * burst) as u64;
        assert_eq!(
            report.rendezvous, expected,
            "seed {seed}: expected {expected} rendezvous, got {}",
            report.rendezvous
        );
        assert_eq!(report.denials, 0, "seed {seed}: clean IPC must not deny");
        assert!(!report.deadlocked, "seed {seed}: pipeline must fully drain");
        assert!(
            k.threads().all(|t| matches!(t.state, ThreadState::Exited)),
            "seed {seed}: every thread must finish"
        );
    }
}

#[test]
fn receiver_first_blocks_then_wakes() {
    // The consumer is dispatched first and must block until the producer sends.
    let mut k = Kernel::new(1);
    let producer = k.create_task("p");
    let consumer = k.create_task("c");
    let ep = k.create_endpoint();
    let ps = k.grant(producer, ObjectRef::Endpoint(ep), Rights::SEND);
    let cr = k.grant(consumer, ObjectRef::Endpoint(ep), Rights::RECV);

    k.spawn_thread(
        consumer,
        "c",
        0,
        vec![Op::Recv { ep: cr }, Op::Exit],
    );
    k.spawn_thread(
        producer,
        "p",
        0,
        vec![
            Op::Compute(2),
            Op::Send {
                ep: ps,
                msg: MsgSpec::new(42, b"hi".to_vec()),
            },
            Op::Exit,
        ],
    );

    let report = k.run(64);
    assert_eq!(report.rendezvous, 1);
    let blocked = k
        .trace()
        .iter()
        .any(|e| matches!(e, Event::BlockRecv { .. }));
    assert!(blocked, "the early consumer must have blocked before delivery");
}

#[test]
fn capability_transfer_moves_the_cap() {
    let mut k = Kernel::new(9);
    let sender = k.create_task("sender");
    let receiver = k.create_task("receiver");
    let main_ep = k.create_endpoint();
    let gift_ep = k.create_endpoint();

    let s_send = k.grant(sender, ObjectRef::Endpoint(main_ep), Rights::SEND);
    // The capability the sender will give away.
    let gift = k.grant(sender, ObjectRef::Endpoint(gift_ep), Rights::SEND | Rights::GRANT);
    let r_recv = k.grant(receiver, ObjectRef::Endpoint(main_ep), Rights::RECV);

    let sender_caps_before = k.task(sender).unwrap().caps.len();
    let receiver_caps_before = k.task(receiver).unwrap().caps.len();

    k.spawn_thread(
        receiver,
        "r",
        0,
        vec![Op::Recv { ep: r_recv }, Op::Exit],
    );
    k.spawn_thread(
        sender,
        "s",
        0,
        vec![
            Op::Send {
                ep: s_send,
                msg: MsgSpec::with_cap(1, b"take this".to_vec(), gift),
            },
            Op::Exit,
        ],
    );

    let report = k.run(64);
    assert_eq!(report.cap_transfers, 1, "exactly one capability transferred");

    // The sender no longer holds the gifted slot.
    assert!(
        !k.task(sender).unwrap().caps.contains(gift),
        "the transferred slot must be gone from the sender"
    );
    assert_eq!(
        k.task(sender).unwrap().caps.len(),
        sender_caps_before - 1,
        "sender lost exactly one capability"
    );
    assert_eq!(
        k.task(receiver).unwrap().caps.len(),
        receiver_caps_before + 1,
        "receiver gained exactly one capability"
    );

    // The received capability points at the gifted endpoint with send rights.
    let got = k
        .task(receiver)
        .unwrap()
        .caps
        .iter()
        .any(|(_, cap)| cap.object == ObjectRef::Endpoint(gift_ep) && cap.rights.contains(Rights::SEND));
    assert!(got, "receiver holds a send capability for the gifted endpoint");
}

#[test]
fn transfer_without_grant_right_is_denied() {
    let mut k = Kernel::new(11);
    let sender = k.create_task("sender");
    let receiver = k.create_task("receiver");
    let main_ep = k.create_endpoint();
    let other_ep = k.create_endpoint();

    let s_send = k.grant(sender, ObjectRef::Endpoint(main_ep), Rights::SEND);
    // No GRANT right: this cap cannot be delegated.
    let no_grant = k.grant(sender, ObjectRef::Endpoint(other_ep), Rights::SEND);
    let r_recv = k.grant(receiver, ObjectRef::Endpoint(main_ep), Rights::RECV);

    k.spawn_thread(receiver, "r", 0, vec![Op::Recv { ep: r_recv }, Op::Exit]);
    k.spawn_thread(
        sender,
        "s",
        0,
        vec![
            Op::Send {
                ep: s_send,
                msg: MsgSpec::with_cap(1, b"x".to_vec(), no_grant),
            },
            Op::Exit,
        ],
    );

    let report = k.run(64);
    assert_eq!(report.cap_transfers, 0, "a cap without grant cannot be delegated");
    assert!(report.denials >= 1, "the illegal transfer must be denied");
    assert!(
        k.task(sender).unwrap().caps.contains(no_grant),
        "the sender keeps the cap it was not allowed to give away"
    );
}
