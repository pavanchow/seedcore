//! The scheduler.
//!
//! The scheduler decides which ready thread runs next. Two policies are offered.
//! Round robin cycles through ready threads in arrival order, which is the
//! simplest fair policy. Priority always picks the highest priority ready thread
//! and breaks ties by arrival order, so it degenerates to round robin when all
//! priorities are equal.
//!
//! Both policies are fully deterministic. Given the same set of ready threads
//! arriving in the same order, the same thread is always chosen. That is what
//! lets a whole run reproduce byte for byte from a seed.

use crate::ThreadId;
use std::collections::VecDeque;

/// Which scheduling policy the kernel uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Cycle through ready threads in arrival order.
    RoundRobin,
    /// Prefer the numerically smallest priority value, ties by arrival order.
    Priority,
}

/// The ready queue plus its policy.
///
/// Each queued entry carries its thread priority so the priority policy can scan
/// without reaching back into the thread table. A smaller priority number means
/// more urgent, matching the common operating system convention.
#[derive(Debug, Clone)]
pub struct Scheduler {
    policy: Policy,
    ready: VecDeque<(ThreadId, u8)>,
    /// Number of dispatches performed, for context switch accounting across the
    /// whole run.
    pub context_switches: u64,
}

impl Scheduler {
    /// A scheduler with the given policy and an empty ready queue.
    pub fn new(policy: Policy) -> Scheduler {
        Scheduler {
            policy,
            ready: VecDeque::new(),
            context_switches: 0,
        }
    }

    /// The active policy.
    pub fn policy(&self) -> Policy {
        self.policy
    }

    /// Add a thread to the back of the ready queue. Arrival order is preserved,
    /// which is what makes tie breaking deterministic.
    pub fn enqueue(&mut self, thread: ThreadId, priority: u8) {
        self.ready.push_back((thread, priority));
    }

    /// How many threads are ready.
    pub fn ready_len(&self) -> usize {
        self.ready.len()
    }

    /// Whether any thread is ready.
    pub fn has_ready(&self) -> bool {
        !self.ready.is_empty()
    }

    /// Remove a specific thread from the ready queue if present. Used when a
    /// thread exits while still queued.
    pub fn remove(&mut self, thread: ThreadId) {
        self.ready.retain(|&(t, _)| t != thread);
    }

    /// Choose and remove the next thread to run. The choice depends on policy.
    /// A dispatch bumps the context switch counter.
    pub fn dispatch(&mut self) -> Option<ThreadId> {
        let chosen = match self.policy {
            Policy::RoundRobin => self.ready.pop_front(),
            Policy::Priority => {
                let mut best_index = None;
                let mut best_priority = u8::MAX;
                for (index, &(_, priority)) in self.ready.iter().enumerate() {
                    if best_index.is_none() || priority < best_priority {
                        best_priority = priority;
                        best_index = Some(index);
                    }
                }
                best_index.and_then(|i| self.ready.remove(i))
            }
        };
        match chosen {
            Some((thread, _)) => {
                self.context_switches += 1;
                Some(thread)
            }
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_robin_is_fifo() {
        let mut s = Scheduler::new(Policy::RoundRobin);
        s.enqueue(10, 0);
        s.enqueue(20, 0);
        s.enqueue(30, 0);
        assert_eq!(s.dispatch(), Some(10));
        assert_eq!(s.dispatch(), Some(20));
        assert_eq!(s.dispatch(), Some(30));
        assert_eq!(s.dispatch(), None);
        assert_eq!(s.context_switches, 3);
    }

    #[test]
    fn priority_prefers_smaller_value() {
        let mut s = Scheduler::new(Policy::Priority);
        s.enqueue(1, 5);
        s.enqueue(2, 1);
        s.enqueue(3, 3);
        assert_eq!(s.dispatch(), Some(2));
        assert_eq!(s.dispatch(), Some(3));
        assert_eq!(s.dispatch(), Some(1));
    }

    #[test]
    fn priority_ties_break_by_arrival() {
        let mut s = Scheduler::new(Policy::Priority);
        s.enqueue(7, 4);
        s.enqueue(8, 4);
        s.enqueue(9, 4);
        assert_eq!(s.dispatch(), Some(7));
        assert_eq!(s.dispatch(), Some(8));
        assert_eq!(s.dispatch(), Some(9));
    }

    #[test]
    fn remove_pulls_thread_out() {
        let mut s = Scheduler::new(Policy::RoundRobin);
        s.enqueue(1, 0);
        s.enqueue(2, 0);
        s.remove(1);
        assert_eq!(s.dispatch(), Some(2));
        assert_eq!(s.dispatch(), None);
    }
}
