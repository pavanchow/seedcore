//! Gate 3: address space isolation, plus determinism.
//!
//! A task can read or write only the memory it holds a capability for: its own
//! regions and any region explicitly shared with it. It can never reach into
//! another task memory. We check this over random access patterns, confirm that
//! a shared region genuinely carries data between two tasks, and confirm that a
//! task with no capability for a region cannot touch it. We also assert full
//! determinism: the same seed produces a byte identical trace.

use seedcore::prelude::*;
use seedcore::scenario;
use seedcore::Kernel;

fn fuzz_ops() -> u64 {
    std::env::var("SEEDCORE_FUZZ_OPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3000)
}

const LEN: usize = 8;

#[test]
fn a_task_touches_only_regions_it_holds() {
    let budget = fuzz_ops();
    for seed in 0..24u64 {
        let mut k = Kernel::new(seed);

        // Three tasks, three regions. Each task owns one private region, and a
        // fourth region is shared between task 0 and task 1 only.
        let tasks: Vec<_> = (0..3).map(|i| k.create_task(format!("t{i}"))).collect();
        let threads: Vec<_> = tasks
            .iter()
            .map(|&t| k.spawn_thread(t, "d", 0, vec![]))
            .collect();

        let private: Vec<_> = tasks.iter().map(|&t| k.create_region(t, LEN)).collect();
        let shared = k.create_region(tasks[0], LEN);

        // Grant each task read and write on its own private region.
        let mut caps: Vec<Vec<(CapSlot, u32)>> = vec![Vec::new(); tasks.len()];
        for i in 0..tasks.len() {
            let slot = k.grant(tasks[i], ObjectRef::Region(private[i]), Rights::READ | Rights::WRITE);
            caps[i].push((slot, private[i]));
        }
        // Share the shared region with tasks 0 and 1.
        for i in 0..2 {
            let slot = k.grant(tasks[i], ObjectRef::Region(shared), Rights::READ | Rights::WRITE);
            caps[i].push((slot, shared));
        }

        for _ in 0..budget {
            let ti = k.prng().below(tasks.len() as u32) as usize;
            let thread = threads[ti];

            // Half the time use a held slot, half the time a fabricated one that
            // could only be another task memory if forging worked.
            let use_real = k.prng().one_in(2) && !caps[ti].is_empty();
            let (slot, held_region) = if use_real {
                let (s, r) = caps[ti][k.prng().below(caps[ti].len() as u32) as usize];
                (s, Some(r))
            } else {
                (k.task(tasks[ti]).unwrap().caps.high_water() + k.prng().below(50), None)
            };
            let offset = k.prng().below((LEN as u32) + 2) as usize;

            let value = k.prng().byte();
            let write = k.sys_write(thread, slot, offset, value);
            let allowed = held_region.is_some() && offset < LEN;
            assert_eq!(
                write.is_ok(),
                allowed,
                "seed {seed}: task {ti} write slot {slot} offset {offset}"
            );
            let read = k.sys_read(thread, slot, offset);
            assert_eq!(read.is_ok(), allowed, "seed {seed}: task {ti} read mismatch");
        }
    }
}

#[test]
fn shared_region_carries_data_and_outsiders_are_denied() {
    let mut k = Kernel::new(2);
    let a = k.create_task("a");
    let b = k.create_task("b");
    let c = k.create_task("c"); // outsider, no capability for the shared region
    let ta = k.spawn_thread(a, "ta", 0, vec![]);
    let tb = k.spawn_thread(b, "tb", 0, vec![]);
    let tc = k.spawn_thread(c, "tc", 0, vec![]);

    let shared = k.create_region(a, 8);
    let a_cap = k.grant(a, ObjectRef::Region(shared), Rights::READ | Rights::WRITE);
    let b_cap = k.grant(b, ObjectRef::Region(shared), Rights::READ);

    // A writes, B reads the same bytes back through its own capability.
    k.sys_write(ta, a_cap, 3, 0xAB).unwrap();
    assert_eq!(k.sys_read(tb, b_cap, 3).unwrap(), 0xAB);

    // B has read only, so a write is denied.
    assert!(matches!(
        k.sys_write(tb, b_cap, 3, 0x00),
        Err(KernelError::MissingRight { .. })
    ));

    // C holds nothing for this region. Any slot it names is denied.
    for slot in 0..8u32 {
        assert!(
            k.sys_read(tc, slot, 3).is_err(),
            "outsider must not read the shared region via slot {slot}"
        );
    }
}

#[test]
fn same_seed_produces_identical_traces() {
    for seed in [0u64, 1, 7, 42, 1000] {
        let mut a = scenario::stress(seed, 4, 4);
        let mut b = scenario::stress(seed, 4, 4);
        a.run(100_000);
        b.run(100_000);
        assert_eq!(
            a.trace(),
            b.trace(),
            "seed {seed}: two runs from the same seed must produce identical traces"
        );
    }
}

#[test]
fn different_seeds_diverge() {
    let mut a = scenario::stress(1, 4, 4);
    let mut b = scenario::stress(2, 4, 4);
    a.run(100_000);
    b.run(100_000);
    assert_ne!(
        a.trace(),
        b.trace(),
        "different seeds should not produce the same trace"
    );
}

#[test]
fn demo_is_well_formed() {
    let mut k = scenario::demo(1);
    let report = k.run(256);
    assert!(report.rendezvous >= 2, "the demo exercises IPC");
    assert!(report.cap_transfers >= 1, "the demo transfers a reply capability");
    assert!(report.denials >= 2, "the demo shows unauthorized access denied");
    assert!(!report.deadlocked, "the demo runs to completion");
}
