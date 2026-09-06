//! Gate 4: the bounded stress harness.
//!
//! This drives the kernel hard from many seeds and asserts the four core
//! properties against an independent shadow model that is written from scratch
//! and never calls into the kernel to decide what should happen. The shadow is
//! the referee, the kernel is the player, and any disagreement is a defect.
//!
//! The four properties under test:
//!   1. capability enforcement and unforgeability (an op succeeds iff the caller
//!      truly holds a matching capability),
//!   2. address space isolation (no task reads or writes a region it was not
//!      granted, including cross task probes),
//!   3. IPC exactly once delivery (every message rendezvous once, none lost or
//!      duplicated), and
//!   4. determinism (the same seed yields a byte identical trace).
//!
//! The op count scales with SEEDCORE_FUZZ_OPS. The footprint is bounded: nothing
//! here accumulates an unbounded structure, so a large op budget costs time, not
//! memory.

use seedcore::prelude::*;
use seedcore::scenario;
use seedcore::Kernel;

fn fuzz_ops() -> u64 {
    std::env::var("SEEDCORE_FUZZ_OPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000)
}

const REGION_LEN: usize = 8;

/// An independent shadow of one task capability table. It records exactly what
/// was granted, minted, transferred, and revoked, and answers authorization
/// questions without ever consulting the kernel.
#[derive(Clone)]
struct Shadow {
    caps: Vec<(CapSlot, ObjectRef, Rights)>,
}

impl Shadow {
    fn new() -> Shadow {
        Shadow { caps: Vec::new() }
    }

    fn add(&mut self, slot: CapSlot, object: ObjectRef, rights: Rights) {
        self.caps.push((slot, object, rights));
    }

    fn remove(&mut self, slot: CapSlot) {
        self.caps.retain(|&(s, _, _)| s != slot);
    }

    /// Whether a memory op at this slot and offset should be allowed.
    fn mem_ok(&self, slot: CapSlot, need: Rights, offset: usize) -> bool {
        offset < REGION_LEN
            && self.caps.iter().any(|&(s, obj, r)| {
                s == slot && matches!(obj, ObjectRef::Region(_)) && r.contains(need)
            })
    }

    /// Whether an endpoint op at this slot should be allowed.
    fn ep_ok(&self, slot: CapSlot, need: Rights) -> bool {
        self.caps.iter().any(|&(s, obj, r)| {
            s == slot && matches!(obj, ObjectRef::Endpoint(_)) && r.contains(need)
        })
    }
}

#[test]
fn enforcement_isolation_and_no_forgery_over_random_ops() {
    let budget = fuzz_ops();
    let mut checked: u64 = 0;
    let mut allowed: u64 = 0;
    let mut denied: u64 = 0;

    for seed in 0..40u64 {
        let mut k = Kernel::new(seed);
        let n_tasks = 5usize;

        let tasks: Vec<_> = (0..n_tasks)
            .map(|i| k.create_task(format!("t{i}")))
            .collect();
        let threads: Vec<_> = tasks
            .iter()
            .map(|&t| k.spawn_thread(t, "d", 0, vec![]))
            .collect();

        // Regions: some are private to a single task, so a cross task probe of
        // another task private region must always be denied.
        let regions: Vec<_> = (0..4).map(|_| k.create_region(tasks[0], REGION_LEN)).collect();
        let endpoints: Vec<_> = (0..3).map(|_| k.create_endpoint()).collect();

        let mut shadow: Vec<Shadow> = vec![Shadow::new(); n_tasks];

        // Seed each task with a few random grants, mirrored into its shadow.
        for ti in 0..n_tasks {
            let grants = 2 + k.prng().below(4);
            for _ in 0..grants {
                let object = if k.prng().one_in(2) {
                    ObjectRef::Region(regions[k.prng().below(regions.len() as u32) as usize])
                } else {
                    ObjectRef::Endpoint(endpoints[k.prng().below(endpoints.len() as u32) as usize])
                };
                let rights = Rights::from_bits(k.prng().below(32));
                let slot = k.grant(tasks[ti], object, rights);
                shadow[ti].add(slot, object, rights);
            }
        }

        let per_seed = budget / 40;
        for _ in 0..per_seed {
            let ti = k.prng().below(n_tasks as u32) as usize;
            let task = tasks[ti];
            let thread = threads[ti];

            // Periodically grant a fresh, genuinely useful capability so the
            // shadow tables never fully drain under revocation and the allowed
            // path keeps being exercised as the op budget grows.
            if k.prng().one_in(8) {
                let object = if k.prng().one_in(2) {
                    ObjectRef::Region(regions[k.prng().below(regions.len() as u32) as usize])
                } else {
                    ObjectRef::Endpoint(endpoints[k.prng().below(endpoints.len() as u32) as usize])
                };
                let rights = Rights::READ | Rights::WRITE | Rights::SEND | Rights::RECV;
                let slot = k.grant(task, object, rights);
                shadow[ti].add(slot, object, rights);
            }

            // Occasionally mint a reduced-rights child cap from a held cap into
            // another task, exercising delegation. The shadow mirrors it.
            if k.prng().one_in(6) && !shadow[ti].caps.is_empty() {
                let idx = k.prng().below(shadow[ti].caps.len() as u32) as usize;
                let (src_slot, obj, src_rights) = shadow[ti].caps[idx];
                let drop_mask = Rights::from_bits(k.prng().below(32));
                let dst = k.prng().below(n_tasks as u32) as usize;
                if let Ok((slot, rights)) = k.mint(task, src_slot, tasks[dst], drop_mask) {
                    // Independent prediction: minted rights are the source rights
                    // minus the dropped mask, never more.
                    let want = src_rights.minus(drop_mask);
                    assert_eq!(
                        rights.bits(),
                        want.bits(),
                        "seed {seed}: mint must never add rights (src {src_rights}, dropped {drop_mask})"
                    );
                    shadow[dst].add(slot, obj, rights);
                }
            }

            // Choose a slot flavour: real, fabricated, revoked, or a raw guess
            // that could only hit another task object if forgery were possible.
            let choice = k.prng().below(12);
            let slot = if choice < 6 && !shadow[ti].caps.is_empty() {
                shadow[ti].caps[k.prng().below(shadow[ti].caps.len() as u32) as usize].0
            } else if choice < 9 {
                k.task(task).unwrap().caps.high_water() + k.prng().below(1000)
            } else if choice < 11 && !shadow[ti].caps.is_empty() {
                let idx = k.prng().below(shadow[ti].caps.len() as u32) as usize;
                let dead = shadow[ti].caps[idx].0;
                k.revoke(task, dead);
                shadow[ti].remove(dead);
                dead
            } else {
                // A cross task probe: name slot values another task actually holds.
                let victim = (ti + 1) % n_tasks;
                shadow[victim]
                    .caps
                    .first()
                    .map(|c| c.0)
                    .unwrap_or(0)
            };

            let offset = k.prng().below((REGION_LEN as u32) + 4) as usize;

            if k.prng().one_in(2) {
                let want = shadow[ti].mem_ok(slot, Rights::READ, offset);
                let got = k.sys_read(thread, slot, offset).is_ok();
                assert_eq!(
                    got, want,
                    "seed {seed}: read task#{task} slot {slot} offset {offset}"
                );
                checked += 1;
                if want { allowed += 1 } else { denied += 1 }
            } else {
                let value = k.prng().byte();
                let want = shadow[ti].mem_ok(slot, Rights::WRITE, offset);
                let got = k.sys_write(thread, slot, offset, value).is_ok();
                assert_eq!(
                    got, want,
                    "seed {seed}: write task#{task} slot {slot} offset {offset}"
                );
                checked += 1;
                if want { allowed += 1 } else { denied += 1 }
            }

            // Endpoint resolution goes through the same choke point.
            let need = if k.prng().one_in(2) { Rights::SEND } else { Rights::RECV };
            let want = shadow[ti].ep_ok(slot, need);
            let got = k
                .resolve(task, slot, "endpoint", need)
                .is_ok();
            assert_eq!(got, want, "seed {seed}: endpoint resolution mismatch");
            checked += 1;
            if want { allowed += 1 } else { denied += 1 }
        }
    }

    assert!(allowed > 0, "the harness must exercise real allowed ops");
    assert!(denied > 0, "the harness must exercise real denied ops");
    eprintln!("stress auth: checked={checked} allowed={allowed} denied={denied}");
}

#[test]
fn ipc_is_exactly_once_and_runs_do_not_panic_or_hang() {
    let scale = (fuzz_ops() / 1000).clamp(2, 40) as u32;
    let mut total_rendezvous: u64 = 0;
    for seed in 0..scale.max(2) as u64 {
        // Independently compute how many messages must cross: pairs * burst.
        let pairs = 1 + (seed as u32 % 5);
        let burst = 1 + ((seed as u32 * 3) % 7);
        let mut k = scenario::pipeline(seed, pairs, burst);

        // A generous but finite op budget: enough to drain, small enough that a
        // hang shows up as a deadlock report rather than an infinite loop.
        let report = k.run(1_000_000);

        let expected = (pairs * burst) as u64;
        assert_eq!(
            report.rendezvous, expected,
            "seed {seed}: expected {expected} rendezvous, got {}",
            report.rendezvous
        );
        assert!(!report.deadlocked, "seed {seed}: clean pipeline must drain");
        assert!(
            k.threads().all(|t| matches!(t.state, ThreadState::Exited)),
            "seed {seed}: every thread must finish"
        );
        total_rendezvous += report.rendezvous;
    }
    assert!(total_rendezvous > 0);
    eprintln!("stress ipc: total_rendezvous={total_rendezvous}");
}

#[test]
fn determinism_holds_under_stress() {
    for seed in [0u64, 1, 3, 7, 42, 99, 1000, 65535] {
        let mut a = scenario::stress(seed, 5, 5);
        let mut b = scenario::stress(seed, 5, 5);
        a.run(1_000_000);
        b.run(1_000_000);
        assert_eq!(
            a.trace(),
            b.trace(),
            "seed {seed}: identical seed must yield identical trace"
        );
    }
}
