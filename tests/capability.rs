//! Gate 1: capability unforgeability and enforcement.
//!
//! This is the core security property. Over randomized scenarios we drive the
//! kernel with a mixture of real, fabricated, and revoked capability slots and
//! assert that a syscall succeeds if and only if the calling task actually holds
//! a capability of the right kind with the right permission. A fabricated index,
//! a guessed index, or a revoked slot is always denied, and a capability can
//! never be used for an operation whose right it lacks (no escalation).
//!
//! The number of random operations is bounded for CI and can be raised with the
//! SEEDCORE_FUZZ_OPS environment variable.

use seedcore::prelude::*;
use seedcore::Kernel;

fn fuzz_ops() -> u64 {
    std::env::var("SEEDCORE_FUZZ_OPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3000)
}

const REGION_LEN: usize = 8;

fn authorized_mem(
    shadow: &[(CapSlot, ObjectRef, Rights)],
    slot: CapSlot,
    need: Rights,
    offset: usize,
) -> bool {
    shadow.iter().any(|&(s, obj, rights)| {
        s == slot
            && matches!(obj, ObjectRef::Region(_))
            && rights.contains(need)
            && offset < REGION_LEN
    })
}

#[test]
fn enforcement_and_unforgeability_over_random_ops() {
    let budget = fuzz_ops();
    for seed in 0..24u64 {
        let mut k = Kernel::new(seed);

        let n_tasks = 4usize;
        let mut tasks = Vec::new();
        let mut threads = Vec::new();
        for i in 0..n_tasks {
            tasks.push(k.create_task(format!("t{i}")));
        }
        let mut regions = Vec::new();
        for _ in 0..3 {
            regions.push(k.create_region(tasks[0], REGION_LEN));
        }
        let mut endpoints = Vec::new();
        for _ in 0..2 {
            endpoints.push(k.create_endpoint());
        }
        for &t in &tasks {
            threads.push(k.spawn_thread(t, "d", 0, vec![]));
        }

        // Grant a handful of random capabilities per task and mirror them.
        let mut shadow: Vec<Vec<(CapSlot, ObjectRef, Rights)>> = vec![Vec::new(); n_tasks];
        for ti in 0..n_tasks {
            let grants = 2 + k.prng().below(4);
            for _ in 0..grants {
                let is_region = k.prng().one_in(2);
                let object = if is_region {
                    let r = regions[k.prng().below(regions.len() as u32) as usize];
                    ObjectRef::Region(r)
                } else {
                    let e = endpoints[k.prng().below(endpoints.len() as u32) as usize];
                    ObjectRef::Endpoint(e)
                };
                let rights = Rights::from_bits(k.prng().below(32));
                let slot = k.grant(tasks[ti], object, rights);
                shadow[ti].push((slot, object, rights));
            }
        }

        for _ in 0..budget {
            let ti = k.prng().below(n_tasks as u32) as usize;
            let task = tasks[ti];
            let thread = threads[ti];

            // Choose a slot: real, fabricated, or revoked.
            let choice = k.prng().below(10);
            let slot = if choice < 6 && !shadow[ti].is_empty() {
                // A real, currently granted slot.
                shadow[ti][k.prng().below(shadow[ti].len() as u32) as usize].0
            } else if choice < 8 {
                // A fabricated slot guaranteed never to have been handed out.
                k.task(task).unwrap().caps.high_water() + k.prng().below(500)
            } else if !shadow[ti].is_empty() {
                // Revoke a real slot, then try to use the dead slot.
                let idx = k.prng().below(shadow[ti].len() as u32) as usize;
                let dead = shadow[ti][idx].0;
                k.revoke(task, dead);
                shadow[ti].remove(idx);
                dead
            } else {
                k.prng().below(500) + 10_000
            };

            let offset = k.prng().below((REGION_LEN as u32) + 4) as usize;

            if k.prng().one_in(2) {
                let want = authorized_mem(&shadow[ti], slot, Rights::READ, offset);
                let got = k.sys_read(thread, slot, offset);
                assert_eq!(
                    got.is_ok(),
                    want,
                    "seed {seed}: read task#{task} slot {slot} offset {offset}: kernel said {got:?} but authorization was {want}"
                );
            } else {
                let value = k.prng().byte();
                let want = authorized_mem(&shadow[ti], slot, Rights::WRITE, offset);
                let got = k.sys_write(thread, slot, offset, value);
                assert_eq!(
                    got.is_ok(),
                    want,
                    "seed {seed}: write task#{task} slot {slot} offset {offset}: kernel said {got:?} but authorization was {want}"
                );
            }

            // Endpoint permission checks go through the same resolver.
            if let Some(&(s, obj, rights)) = shadow[ti].first() {
                let send_ok = k.resolve(task, s, "endpoint", Rights::SEND).is_ok();
                let want_send = matches!(obj, ObjectRef::Endpoint(_)) && rights.contains(Rights::SEND);
                assert_eq!(send_ok, want_send, "seed {seed}: endpoint SEND resolution mismatch");
            }
        }
    }
}

#[test]
fn no_escalation_on_a_read_only_capability() {
    let mut k = Kernel::new(7);
    let t = k.create_task("t");
    let th = k.spawn_thread(t, "th", 0, vec![]);
    let r = k.create_region(t, 8);
    let ro = k.grant(t, ObjectRef::Region(r), Rights::READ);

    assert!(k.sys_read(th, ro, 0).is_ok(), "read is granted");
    assert!(
        matches!(k.sys_write(th, ro, 0, 1), Err(KernelError::MissingRight { .. })),
        "a read only capability must never permit a write"
    );
}

#[test]
fn fabricated_and_revoked_slots_are_denied() {
    let mut k = Kernel::new(3);
    let t = k.create_task("t");
    let th = k.spawn_thread(t, "th", 0, vec![]);
    let r = k.create_region(t, 8);
    let cap = k.grant(t, ObjectRef::Region(r), Rights::READ | Rights::WRITE);

    // A slot that was never granted.
    let fake = k.task(t).unwrap().caps.high_water() + 42;
    assert!(matches!(
        k.sys_read(th, fake, 0),
        Err(KernelError::NoSuchCapability { .. })
    ));

    // The real slot works, then is revoked, then is dead forever.
    assert!(k.sys_write(th, cap, 0, 9).is_ok());
    k.revoke(t, cap);
    assert!(matches!(
        k.sys_write(th, cap, 0, 9),
        Err(KernelError::NoSuchCapability { .. })
    ));
}

#[test]
fn wrong_object_kind_is_denied() {
    let mut k = Kernel::new(5);
    let t = k.create_task("t");
    let th = k.spawn_thread(t, "th", 0, vec![]);
    let ep = k.create_endpoint();
    let cap = k.grant(t, ObjectRef::Endpoint(ep), Rights::SEND | Rights::RECV);

    // An endpoint capability cannot be used to read memory.
    assert!(matches!(
        k.sys_read(th, cap, 0),
        Err(KernelError::WrongObject { .. })
    ));
}
