//! One paid charge.

/// Where a session is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Starting,
    Charging,
    Stopping,
    Closed,
    Failed,
}

/// One paid charge: who paid, how much, on which connector, with which transaction and from which meter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: u64,
    pub connector: u8,
    pub payer: String,
    /// The amount in atomic units, as the offer said it.
    pub amount: String,
    /// The energy bought, in Wh.
    pub limit_wh: u64,
    pub transaction_id: u64,
    /// The meter when the transaction started, in Wh.
    pub start_energy_wh: u64,
    pub started_at: u64,
    pub state: SessionState,
}

impl Session {
    /// Energy delivered since the transaction started, in Wh.
    pub fn delivered_wh(&self, meter_energy_wh: u64) -> u64 {
        meter_energy_wh.saturating_sub(self.start_energy_wh)
    }

    /// Whether the meter reached the block the buyer paid for.
    pub fn is_complete(&self, meter_energy_wh: u64) -> bool {
        self.delivered_wh(meter_energy_wh) >= self.limit_wh
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Session {
        Session {
            id: 1,
            connector: 1,
            payer: "0xabc".into(),
            amount: "10000".into(),
            limit_wh: 1_000,
            transaction_id: 7,
            start_energy_wh: 500,
            started_at: 1_800_000_000,
            state: SessionState::Charging,
        }
    }

    #[test]
    fn delivered_energy_is_measured_from_the_start() {
        let s = session();
        assert_eq!(s.delivered_wh(500), 0);
        assert_eq!(s.delivered_wh(1_500), 1_000);
        assert_eq!(
            s.delivered_wh(400),
            0,
            "a meter that goes back does not go negative"
        );
    }

    #[test]
    fn complete_at_the_limit() {
        let s = session();
        assert!(!s.is_complete(1_499));
        assert!(s.is_complete(1_500));
        assert!(s.is_complete(1_501));
    }
}
