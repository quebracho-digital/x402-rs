//! A ledger in memory, for tests and the demo. It is not durable: a process restart loses it. The
//! product uses `quebracho-x402-qnx`'s `FileLedger`.

use std::cell::RefCell;
use std::collections::BTreeMap;

use quebracho_x402::ports::{Ledger, LedgerUnavailable};
use serde_json::{Value, json};

/// A ledger in a `BTreeMap`. `claim` is atomic because the map is behind one `RefCell`.
#[derive(Default)]
pub struct MemoryLedger {
    states: RefCell<BTreeMap<String, Value>>,
}

impl MemoryLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.states.borrow().is_empty()
    }

    pub fn len(&self) -> usize {
        self.states.borrow().len()
    }
}

impl Ledger for MemoryLedger {
    fn claim(&self, key: &str, _ttl: u64) -> Result<bool, LedgerUnavailable> {
        let mut states = self.states.borrow_mut();
        Ok(!states.contains_key(key)
            && states
                .insert(key.into(), json!({ "status": "claimed" }))
                .is_none())
    }

    fn get(&self, key: &str) -> Result<Option<Value>, LedgerUnavailable> {
        Ok(self.states.borrow().get(key).cloned())
    }

    fn put(&self, key: &str, state: &Value, _ttl: u64) -> Result<(), LedgerUnavailable> {
        self.states.borrow_mut().insert(key.into(), state.clone());
        Ok(())
    }

    fn release(&self, key: &str) -> Result<(), LedgerUnavailable> {
        self.states.borrow_mut().remove(key);
        Ok(())
    }

    fn open(&self, _key: &str, _reference: &Value, _ttl: u64) -> Result<(), LedgerUnavailable> {
        Ok(())
    }

    fn open_keys(&self, _limit: usize) -> Result<Vec<(String, Value)>, LedgerUnavailable> {
        Ok(Vec::new())
    }

    fn close(&self, _key: &str) -> Result<(), LedgerUnavailable> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_claim_is_atomic_and_release_frees_it() {
        let ledger = MemoryLedger::new();
        assert!(ledger.is_empty());
        assert!(ledger.claim("k", 60).unwrap());
        assert!(!ledger.claim("k", 60).unwrap(), "a live claim wins");
        assert_eq!(ledger.len(), 1);
        assert_eq!(
            ledger.get("k").unwrap(),
            Some(json!({ "status": "claimed" }))
        );
        ledger.release("k").unwrap();
        assert!(ledger.is_empty());
        assert!(ledger.claim("k", 60).unwrap(), "released: good again");
    }

    #[test]
    fn put_replaces_the_state() {
        let ledger = MemoryLedger::new();
        assert!(ledger.claim("k", 60).unwrap());
        ledger
            .put("k", &json!({ "status": "settled" }), 60)
            .unwrap();
        assert_eq!(
            ledger.get("k").unwrap(),
            Some(json!({ "status": "settled" }))
        );
    }
}
