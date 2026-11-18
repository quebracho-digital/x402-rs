//! A small app-level rate limit. The core does not impose one: a public charger does.
//!
//! The key is whatever the app chooses, here the payer address. A token bucket per key: `capacity`
//! requests at once, refilled at `refill_per_second`, with the clock the caller passes.

use std::cell::RefCell;
use std::collections::BTreeMap;

pub trait RateLimit {
    /// Whether `key` may make a request at `now` (Unix seconds).
    fn allow(&self, key: &str, now: u64) -> bool;
}

struct Bucket {
    tokens: u32,
    last: u64,
}

/// A token bucket per key. The map is bounded: a key the map has never seen is refused once the map is
/// full, so a flood of distinct keys cannot grow it without limit.
pub struct TokenBucket {
    capacity: u32,
    refill_per_second: u32,
    max_keys: usize,
    buckets: RefCell<BTreeMap<String, Bucket>>,
}

impl TokenBucket {
    /// `capacity` requests at once, `refill_per_second` after that, at most 10,000 keys.
    pub fn new(capacity: u32, refill_per_second: u32) -> Self {
        Self::with_max_keys(capacity, refill_per_second, 10_000)
    }

    pub fn with_max_keys(capacity: u32, refill_per_second: u32, max_keys: usize) -> Self {
        Self {
            capacity,
            refill_per_second,
            max_keys,
            buckets: RefCell::new(BTreeMap::new()),
        }
    }
}

impl RateLimit for TokenBucket {
    fn allow(&self, key: &str, now: u64) -> bool {
        if self.capacity == 0 {
            return false;
        }
        let mut buckets = self.buckets.borrow_mut();
        if !buckets.contains_key(key) && buckets.len() >= self.max_keys {
            // Fail closed: no room for a new key. Existing keys keep their buckets.
            return false;
        }
        let bucket = buckets.entry(key.into()).or_insert(Bucket {
            tokens: self.capacity,
            last: now,
        });
        if now > bucket.last {
            let elapsed = now - bucket.last;
            let refill = elapsed.saturating_mul(u64::from(self.refill_per_second));
            bucket.tokens =
                (u64::from(bucket.tokens) + refill).min(u64::from(self.capacity)) as u32;
            bucket.last = now;
        } else if now < bucket.last {
            // A clock that went back does not mint tokens.
            bucket.last = now;
        }
        if bucket.tokens == 0 {
            return false;
        }
        bucket.tokens -= 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bucket_allows_its_capacity_then_refills() {
        let limit = TokenBucket::new(2, 1);
        assert!(limit.allow("payer", 0));
        assert!(limit.allow("payer", 0));
        assert!(!limit.allow("payer", 0), "capacity spent");
        assert!(limit.allow("payer", 1), "one token after a second");
        assert!(!limit.allow("payer", 1));
        assert!(limit.allow("payer", 2));
        assert!(!limit.allow("payer", 2));
    }

    #[test]
    fn keys_are_independent() {
        let limit = TokenBucket::new(1, 0);
        assert!(limit.allow("a", 0));
        assert!(!limit.allow("a", 0));
        assert!(limit.allow("b", 0));
    }

    #[test]
    fn a_full_bucket_map_refuses_new_keys() {
        let limit = TokenBucket::with_max_keys(2, 0, 2);
        assert!(limit.allow("a", 0));
        assert!(limit.allow("b", 0));
        assert!(!limit.allow("c", 0), "no room for a third key");
        assert!(limit.allow("a", 0), "an existing key still works");
    }

    #[test]
    fn a_capacity_of_zero_never_allows() {
        let limit = TokenBucket::new(0, 10);
        assert!(!limit.allow("a", 0));
        assert!(!limit.allow("a", 100));
    }

    #[test]
    fn a_clock_that_goes_back_does_not_mint_tokens() {
        let limit = TokenBucket::new(1, 1);
        assert!(limit.allow("a", 10));
        assert!(!limit.allow("a", 5), "backwards: no refill");
        assert!(limit.allow("a", 6), "one second after the new last");
    }
}
