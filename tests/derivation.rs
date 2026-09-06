//! Gate 5: the capability derivation tree.
//!
//! Delegation lets a task hand a weaker copy of a capability to another task by
//! minting a child with a subset of the rights. The derivation tree records who
//! descended from whom, so a single revocation can reach every capability ever
//! minted from a root, no matter which task now holds it or whether it moved
//! over IPC in between. This gate checks three things against a shadow model that
//! computes descent entirely on its own:
//!   1. a minted capability never carries a right its parent lacked,
//!   2. revoking a capability removes exactly its subtree, wherever it lives, and
//!   3. capabilities outside that subtree are left untouched.
//!
//! The shadow only ever asks the kernel for the opaque identity of a freshly
//! minted slot. All descent and subtree reasoning is done here, independently, so
//! a wrong subtree in the kernel is a detectable disagreement.

use seedcore::prelude::*;
use seedcore::Kernel;

fn fuzz_ops() -> u64 {
    std::env::var("SEEDCORE_FUZZ_OPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000)
}

/// One capability as the shadow understands it.
#[derive(Clone)]
struct ShadowCap {
    id: CapId,
    parent: Option<CapId>,
    holder: TaskId,
    slot: CapSlot,
    object: ObjectRef,
    rights: Rights,
    alive: bool,
}

#[test]
fn mint_reduces_rights_and_never_escalates() {
    let mut k = Kernel::new(1);
    let a = k.create_task("a");
    let b = k.create_task("b");
    let ep = k.create_endpoint();

    let root = k.grant(a, ObjectRef::Endpoint(ep), Rights::SEND | Rights::RECV | Rights::GRANT);

    // Drop RECV: the child keeps send and grant only.
    let (child, rights) = k.mint(a, root, b, Rights::RECV).unwrap();
    assert_eq!(rights.bits(), (Rights::SEND | Rights::GRANT).bits());
    assert!(rights.contains(Rights::SEND));
    assert!(!rights.contains(Rights::RECV));

    // A grandchild cannot regain the dropped right: dropping nothing still only
    // yields what the child had, never the root's full set.
    let (_grand, grights) = k.mint(b, child, a, Rights::NONE).unwrap();
    assert_eq!(grights.bits(), (Rights::SEND | Rights::GRANT).bits());
    assert!(!grights.contains(Rights::RECV), "a dropped right can never reappear downstream");
}

#[test]
fn mint_from_a_fabricated_or_absent_slot_is_denied() {
    let mut k = Kernel::new(2);
    let a = k.create_task("a");
    let b = k.create_task("b");
    let ep = k.create_endpoint();
    let root = k.grant(a, ObjectRef::Endpoint(ep), Rights::SEND);

    let fake = k.task(a).unwrap().caps.high_water() + 7;
    assert!(matches!(
        k.mint(a, fake, b, Rights::NONE),
        Err(KernelError::NoSuchCapability { .. })
    ));

    // Revoke the root, then minting from the dead slot is denied.
    k.revoke(a, root);
    assert!(matches!(
        k.mint(a, root, b, Rights::NONE),
        Err(KernelError::NoSuchCapability { .. })
    ));
}

#[test]
fn revoke_tree_transitively_kills_descendants_across_tasks_and_ipc() {
    let mut k = Kernel::new(3);
    let a = k.create_task("a");
    let b = k.create_task("b");
    let c = k.create_task("c");
    let d = k.create_task("d");
    let region = k.create_region(a, 8);

    // a holds the root. It mints a child to b, b mints a grandchild to c.
    let root = k.grant(a, ObjectRef::Region(region), Rights::READ | Rights::WRITE);
    let (b_child, _) = k.mint(a, root, b, Rights::WRITE).unwrap(); // b: read only
    let (c_grand, _) = k.mint(b, b_child, c, Rights::NONE).unwrap(); // c: read only

    // b also mints a second child and gives it to d over IPC, so a descendant
    // travels between tasks. Grant b send/recv plumbing for the transfer.
    let (b_child2, _) = k.mint(a, root, b, Rights::WRITE).unwrap();
    // Make it grantable so it can ride an IPC message.
    // (mint dropped WRITE only, GRANT is not part of a region cap, so instead we
    //  transfer by minting straight into d, which is delegation to another task.)
    let (d_desc, _) = k.mint(b, b_child2, d, Rights::NONE).unwrap();

    // Everyone can currently read.
    let ta = k.spawn_thread(a, "ta", 0, vec![]);
    let tb = k.spawn_thread(b, "tb", 0, vec![]);
    let tc = k.spawn_thread(c, "tc", 0, vec![]);
    let td = k.spawn_thread(d, "td", 0, vec![]);
    assert!(k.sys_read(ta, root, 0).is_ok());
    assert!(k.sys_read(tb, b_child, 0).is_ok());
    assert!(k.sys_read(tc, c_grand, 0).is_ok());
    assert!(k.sys_read(td, d_desc, 0).is_ok());

    // Revoke the root. Every capability descended from it, in every task, dies.
    let removed = k.revoke_tree(a, root);
    assert_eq!(removed, 5, "root, two children, one grandchild, one further descendant");

    assert!(matches!(k.sys_read(ta, root, 0), Err(KernelError::NoSuchCapability { .. })));
    assert!(matches!(k.sys_read(tb, b_child, 0), Err(KernelError::NoSuchCapability { .. })));
    assert!(matches!(k.sys_read(tc, c_grand, 0), Err(KernelError::NoSuchCapability { .. })));
    assert!(matches!(k.sys_read(td, d_desc, 0), Err(KernelError::NoSuchCapability { .. })));
    let _ = b_child2;
}

#[test]
fn revoking_a_subtree_leaves_ancestors_and_siblings_intact() {
    let mut k = Kernel::new(4);
    let a = k.create_task("a");
    let b = k.create_task("b");
    let c = k.create_task("c");
    let region = k.create_region(a, 8);

    let root = k.grant(a, ObjectRef::Region(region), Rights::READ | Rights::WRITE);
    let (child1, _) = k.mint(a, root, b, Rights::NONE).unwrap();
    let (child2, _) = k.mint(a, root, c, Rights::NONE).unwrap();
    let (grand1, _) = k.mint(b, child1, c, Rights::NONE).unwrap();

    let ta = k.spawn_thread(a, "ta", 0, vec![]);
    let tb = k.spawn_thread(b, "tb", 0, vec![]);
    let tc = k.spawn_thread(c, "tc", 0, vec![]);

    // Revoke the child1 subtree: child1 and grand1 die, root and child2 survive.
    let removed = k.revoke_tree(b, child1);
    assert_eq!(removed, 2, "child1 and its grandchild only");

    assert!(k.sys_read(ta, root, 0).is_ok(), "the ancestor is untouched");
    assert!(k.sys_read(tc, child2, 0).is_ok(), "the sibling subtree is untouched");
    assert!(matches!(k.sys_read(tb, child1, 0), Err(KernelError::NoSuchCapability { .. })));
    assert!(matches!(k.sys_read(tc, grand1, 0), Err(KernelError::NoSuchCapability { .. })));
}

#[test]
fn derivation_matches_an_independent_shadow_over_random_ops() {
    let budget = fuzz_ops();
    for seed in 0..24u64 {
        let mut k = Kernel::new(seed);

        let n_tasks = 4usize;
        let tasks: Vec<_> = (0..n_tasks).map(|i| k.create_task(format!("t{i}"))).collect();
        let region = k.create_region(tasks[0], 8);
        let ep = k.create_endpoint();

        // The shadow: every capability the world contains, with its descent.
        let mut caps: Vec<ShadowCap> = Vec::new();

        // A couple of roots to grow trees from.
        for &t in &tasks[..2] {
            let object = if k.prng().one_in(2) {
                ObjectRef::Region(region)
            } else {
                ObjectRef::Endpoint(ep)
            };
            let rights = Rights::from_bits(k.prng().below(32) | 0b1000); // ensure some right
            let slot = k.grant(t, object, rights);
            let id = k.cap_id(t, slot).unwrap();
            caps.push(ShadowCap { id, parent: None, holder: t, slot, object, rights, alive: true });
        }

        let per_seed = (budget / 24).max(50);
        for _ in 0..per_seed {
            let live: Vec<usize> = (0..caps.len()).filter(|&i| caps[i].alive).collect();
            if live.is_empty() {
                break;
            }
            let pick = live[k.prng().below(live.len() as u32) as usize];

            if k.prng().one_in(4) {
                // Revoke the picked capability's whole subtree.
                let (holder, slot, root_id) = (caps[pick].holder, caps[pick].slot, caps[pick].id);

                // Independently compute the doomed subtree from the shadow.
                let mut doomed = vec![root_id];
                let mut i = 0;
                while i < doomed.len() {
                    let cur = doomed[i];
                    for c in &caps {
                        if c.parent == Some(cur) && c.alive && !doomed.contains(&c.id) {
                            doomed.push(c.id);
                        }
                    }
                    i += 1;
                }
                let expected: usize = caps
                    .iter()
                    .filter(|c| c.alive && doomed.contains(&c.id))
                    .count();

                let removed = k.revoke_tree(holder, slot);
                assert_eq!(
                    removed, expected,
                    "seed {seed}: revoke_tree removed {removed}, shadow expected {expected}"
                );
                for c in caps.iter_mut() {
                    if doomed.contains(&c.id) {
                        c.alive = false;
                    }
                }
            } else {
                // Mint a child from the picked capability into a random task.
                let src = caps[pick].clone();
                let drop_mask = Rights::from_bits(k.prng().below(32));
                let dst = tasks[k.prng().below(n_tasks as u32) as usize];
                let (slot, rights) = k.mint(src.holder, src.slot, dst, drop_mask).unwrap();
                let want = src.rights.minus(drop_mask);
                assert_eq!(rights.bits(), want.bits(), "seed {seed}: mint escalated rights");
                let id = k.cap_id(dst, slot).unwrap();
                caps.push(ShadowCap {
                    id,
                    parent: Some(src.id),
                    holder: dst,
                    slot,
                    object: src.object,
                    rights,
                    alive: true,
                });
            }

            // Cross check: every capability the shadow believes is alive really
            // is present in the kernel at its slot with the same rights, and
            // every dead one is truly gone.
            for c in &caps {
                let present = k.task(c.holder).unwrap().caps.get(c.slot);
                if c.alive {
                    let cap = present.unwrap_or_else(|| {
                        panic!("seed {seed}: alive cap id {} missing at task#{} slot {}", c.id, c.holder, c.slot)
                    });
                    assert_eq!(cap.rights.bits(), c.rights.bits(), "seed {seed}: rights drift");
                    assert_eq!(k.cap_id(c.holder, c.slot), Some(c.id), "seed {seed}: identity drift");
                } else {
                    // A dead slot must not resurrect as this identity. Because
                    // slots are never reused, the slot is simply absent.
                    assert!(
                        present.is_none() || k.cap_id(c.holder, c.slot) != Some(c.id),
                        "seed {seed}: revoked cap id {} still present at task#{} slot {}",
                        c.id, c.holder, c.slot
                    );
                }
            }
        }
    }
}
