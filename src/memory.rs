//! Address spaces and memory regions.
//!
//! Each task has its own address space. In this model an address space is simply
//! the set of memory regions the task holds a memory capability for. A region is
//! a kernel object with a fixed length of bytes. There is no flat global memory
//! that a task can walk off the end of into a neighbour, so isolation is total
//! by construction: the only way to touch a region is through a capability, and
//! the only way to get a capability is a grant from the kernel or a transfer
//! over IPC.
//!
//! Two tasks share memory when, and only when, they both hold a capability for
//! the same region. That is how a shared buffer or a pager backed page is
//! modelled. Everything else is private.

use crate::error::KernelError;
use crate::capability::ObjectRef;
use crate::{RegionId, TaskId};

/// A contiguous run of bytes that is a kernel object.
#[derive(Debug, Clone)]
pub struct Region {
    /// The region identifier.
    pub id: RegionId,
    /// The task that created the region. Ownership is informational: access is
    /// always decided by capabilities, not by the owner field.
    pub owner: TaskId,
    /// The backing bytes.
    pub data: Vec<u8>,
}

impl Region {
    /// Create a zeroed region of the given length owned by a task.
    pub fn new(id: RegionId, owner: TaskId, len: usize) -> Region {
        Region {
            id,
            owner,
            data: vec![0u8; len],
        }
    }

    /// The length in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the region has no bytes.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Read one byte, bounds checked.
    pub fn read(&self, offset: usize) -> Result<u8, KernelError> {
        self.data.get(offset).copied().ok_or(KernelError::OutOfBounds {
            object: ObjectRef::Region(self.id),
            offset,
            len: self.data.len(),
        })
    }

    /// Write one byte, bounds checked.
    pub fn write(&mut self, offset: usize, value: u8) -> Result<(), KernelError> {
        let len = self.data.len();
        match self.data.get_mut(offset) {
            Some(slot) => {
                *slot = value;
                Ok(())
            }
            None => Err(KernelError::OutOfBounds {
                object: ObjectRef::Region(self.id),
                offset,
                len,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_roundtrip() {
        let mut r = Region::new(0, 1, 16);
        assert_eq!(r.read(3).unwrap(), 0);
        r.write(3, 0xAB).unwrap();
        assert_eq!(r.read(3).unwrap(), 0xAB);
    }

    #[test]
    fn access_past_end_is_denied() {
        let mut r = Region::new(0, 1, 4);
        assert!(matches!(r.read(4), Err(KernelError::OutOfBounds { .. })));
        assert!(matches!(r.write(99, 1), Err(KernelError::OutOfBounds { .. })));
    }
}
