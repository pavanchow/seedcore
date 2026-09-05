//! A tiny deterministic pseudo random generator.
//!
//! Seedcore never touches the operating system entropy pool. The whole point of
//! the simulator is that a seed fully determines the run, so scheduling tie
//! breaks and randomized scenarios are reproducible. This is SplitMix64, a well
//! known small generator that is more than good enough for a simulation and is
//! trivial to reason about.

/// A seeded SplitMix64 generator.
#[derive(Debug, Clone)]
pub struct Prng {
    state: u64,
}

impl Prng {
    /// Create a generator from a seed. Every seed yields a distinct stream and
    /// the same seed always yields the same stream.
    pub fn new(seed: u64) -> Self {
        Prng { state: seed }
    }

    /// The raw 64 bit output.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in the half open range `0..bound`. A bound of zero returns zero.
    pub fn below(&mut self, bound: u32) -> u32 {
        if bound == 0 {
            return 0;
        }
        // Lemire style reduction, unbiased enough for a simulator.
        let product = (self.next_u64() as u128) * (bound as u128);
        (product >> 64) as u32
    }

    /// A byte value.
    pub fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xFF) as u8
    }

    /// A coin flip that is true with probability `1 / n` (n of zero is never).
    pub fn one_in(&mut self, n: u32) -> bool {
        n != 0 && self.below(n) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_stream() {
        let mut a = Prng::new(12345);
        let mut b = Prng::new(12345);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seed_diverges() {
        let mut a = Prng::new(1);
        let mut b = Prng::new(2);
        let mut differences = 0;
        for _ in 0..100 {
            if a.next_u64() != b.next_u64() {
                differences += 1;
            }
        }
        assert!(differences > 90, "streams should mostly differ");
    }

    #[test]
    fn below_respects_bound() {
        let mut p = Prng::new(99);
        for _ in 0..10_000 {
            assert!(p.below(7) < 7);
        }
        assert_eq!(p.below(0), 0);
        assert_eq!(p.below(1), 0);
    }
}
