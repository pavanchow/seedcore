//! Capabilities: the security spine of the microkernel.
//!
//! A capability is an unforgeable token that names a kernel object and carries a
//! set of rights over it. Tasks never hold a capability value directly. They
//! hold an integer slot into their own capability table, and the kernel is the
//! only code that can turn a slot into an object reference. This indirection is
//! what makes a capability unforgeable: a task can name any integer it likes,
//! but only integers that index a real granted entry resolve to anything, and
//! the entry itself was placed there by the kernel.
//!
//! Slots are handed out from a monotonically increasing counter and never
//! reused. That means a revoked slot stays dead forever. A task that guesses or
//! replays an old slot number gets a clean denial rather than someone else's
//! object.

use crate::{EndpointId, RegionId, TaskId, ThreadId};
use std::collections::BTreeMap;
use std::fmt;

/// A slot number into a capability table. This is the only capability handle a
/// task ever sees or names.
pub type CapSlot = u32;

/// A kernel object a capability can point at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectRef {
    /// An IPC endpoint.
    Endpoint(EndpointId),
    /// A memory region.
    Region(RegionId),
    /// Another thread.
    Thread(ThreadId),
    /// A whole task.
    Task(TaskId),
}

impl ObjectRef {
    /// A short human label for the object kind, used in denial messages.
    pub fn kind(&self) -> &'static str {
        match self {
            ObjectRef::Endpoint(_) => "endpoint",
            ObjectRef::Region(_) => "region",
            ObjectRef::Thread(_) => "thread",
            ObjectRef::Task(_) => "task",
        }
    }
}

impl fmt::Display for ObjectRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObjectRef::Endpoint(id) => write!(f, "endpoint#{id}"),
            ObjectRef::Region(id) => write!(f, "region#{id}"),
            ObjectRef::Thread(id) => write!(f, "thread#{id}"),
            ObjectRef::Task(id) => write!(f, "task#{id}"),
        }
    }
}

/// A set of permissions carried by a capability.
///
/// Rights are a small bitset. The kernel checks that a capability carries the
/// exact rights an operation needs before performing it. Holding a capability
/// with only [`Rights::SEND`] never lets a task receive, and no operation can
/// add a right that was not granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rights(u32);

impl Rights {
    /// The empty right set.
    pub const NONE: Rights = Rights(0);
    /// Permission to send a message on an endpoint.
    pub const SEND: Rights = Rights(1 << 0);
    /// Permission to receive a message on an endpoint.
    pub const RECV: Rights = Rights(1 << 1);
    /// Permission to transfer this capability to another task inside a message.
    pub const GRANT: Rights = Rights(1 << 2);
    /// Permission to read a memory region.
    pub const READ: Rights = Rights(1 << 3);
    /// Permission to write a memory region.
    pub const WRITE: Rights = Rights(1 << 4);

    /// Build a right set from a raw bit pattern.
    pub const fn from_bits(bits: u32) -> Rights {
        Rights(bits)
    }

    /// The raw bit pattern.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// The union of two right sets.
    pub const fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }

    /// True when every right in `needed` is present in this set.
    pub const fn contains(self, needed: Rights) -> bool {
        (self.0 & needed.0) == needed.0
    }

    /// This set with the rights in `mask` removed. Used to hand out a weaker
    /// capability than the one held, never a stronger one.
    pub const fn minus(self, mask: Rights) -> Rights {
        Rights(self.0 & !mask.0)
    }
}

impl std::ops::BitOr for Rights {
    type Output = Rights;
    fn bitor(self, rhs: Rights) -> Rights {
        self.union(rhs)
    }
}

impl fmt::Display for Rights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if self.contains(Rights::SEND) {
            parts.push("send");
        }
        if self.contains(Rights::RECV) {
            parts.push("recv");
        }
        if self.contains(Rights::GRANT) {
            parts.push("grant");
        }
        if self.contains(Rights::READ) {
            parts.push("read");
        }
        if self.contains(Rights::WRITE) {
            parts.push("write");
        }
        if parts.is_empty() {
            write!(f, "none")
        } else {
            write!(f, "{}", parts.join("|"))
        }
    }
}

/// An entry in a capability table: an object plus the rights over it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    /// The object this capability grants access to.
    pub object: ObjectRef,
    /// The rights carried.
    pub rights: Rights,
}

impl Capability {
    /// Build a capability.
    pub fn new(object: ObjectRef, rights: Rights) -> Capability {
        Capability { object, rights }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}]", self.object, self.rights)
    }
}

/// A per task table mapping slots to capabilities.
///
/// The table owns the invariant that makes capabilities unforgeable. New slots
/// come from a counter that only ever increases, so a slot is unique for the
/// life of the table and a removed slot is gone for good.
#[derive(Debug, Clone, Default)]
pub struct CapTable {
    slots: BTreeMap<CapSlot, Capability>,
    next: CapSlot,
}

impl CapTable {
    /// An empty table.
    pub fn new() -> CapTable {
        CapTable {
            slots: BTreeMap::new(),
            next: 0,
        }
    }

    /// Install a capability and return the slot it landed in. This is the only
    /// way an entry ever enters a table, and it is kernel only.
    pub fn install(&mut self, cap: Capability) -> CapSlot {
        let slot = self.next;
        self.next += 1;
        self.slots.insert(slot, cap);
        slot
    }

    /// Look up a slot. `None` means the slot was never granted or was revoked,
    /// which the kernel turns into a denial.
    pub fn get(&self, slot: CapSlot) -> Option<Capability> {
        self.slots.get(&slot).copied()
    }

    /// Remove a slot, returning the capability that was there. Used by capability
    /// transfer (move out of the sender) and by explicit revocation.
    pub fn remove(&mut self, slot: CapSlot) -> Option<Capability> {
        self.slots.remove(&slot)
    }

    /// Whether a slot currently holds a capability.
    pub fn contains(&self, slot: CapSlot) -> bool {
        self.slots.contains_key(&slot)
    }

    /// The number of live capabilities.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// The smallest slot number that has never been handed out. Any slot at or
    /// above this value is guaranteed absent, which the fuzz tests use to build
    /// fabricated indices.
    pub fn high_water(&self) -> CapSlot {
        self.next
    }

    /// Iterate the live entries in slot order.
    pub fn iter(&self) -> impl Iterator<Item = (CapSlot, Capability)> + '_ {
        self.slots.iter().map(|(slot, cap)| (*slot, *cap))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_are_never_reused() {
        let mut t = CapTable::new();
        let a = t.install(Capability::new(ObjectRef::Endpoint(0), Rights::SEND));
        t.remove(a);
        let b = t.install(Capability::new(ObjectRef::Endpoint(0), Rights::SEND));
        assert_ne!(a, b, "a revoked slot must never be handed out again");
        assert!(!t.contains(a));
        assert!(t.contains(b));
    }

    #[test]
    fn rights_contains_is_subset() {
        let rw = Rights::READ | Rights::WRITE;
        assert!(rw.contains(Rights::READ));
        assert!(rw.contains(Rights::WRITE));
        assert!(rw.contains(Rights::READ | Rights::WRITE));
        assert!(!rw.contains(Rights::SEND));
        assert!(!Rights::READ.contains(rw));
    }

    #[test]
    fn rights_minus_only_weakens() {
        let full = Rights::READ | Rights::WRITE;
        let ro = full.minus(Rights::WRITE);
        assert!(ro.contains(Rights::READ));
        assert!(!ro.contains(Rights::WRITE));
    }

    #[test]
    fn high_water_marks_absent_slots() {
        let mut t = CapTable::new();
        for _ in 0..5 {
            t.install(Capability::new(ObjectRef::Region(0), Rights::READ));
        }
        let hw = t.high_water();
        assert!(!t.contains(hw));
        assert!(!t.contains(hw + 100));
    }
}
