//! The charge point port and a simulator.
//!
//! The real adapter is OCPP 1.6J over WebSocket: `status` reads `StatusNotification`, `start` sends
//! `RemoteStartTransaction` and waits for `StartTransaction`, `stop` sends `RemoteStopTransaction` and
//! waits for `StopTransaction`, and `meter` reads `MeterValues`. The gateway does not care which.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

/// What a connector is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorStatus {
    Available,
    Preparing,
    Charging,
    Faulted,
    Unavailable,
}

/// A meter reading: cumulative energy, current power and when it was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeterReading {
    pub energy_wh: u64,
    pub power_w: u64,
    pub at: u64,
}

/// The charger accepted a start and gave the transaction an id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartAck {
    pub transaction_id: u64,
}

/// The charger stopped; the meter says how much energy it delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StopAck {
    pub energy_wh: u64,
}

/// Why the gateway stopped a charge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    FullyCharged,
    DriverDisconnected,
    PaymentFailed,
    EmergencyStop,
    ChargerError,
}

/// Why the charge point could not answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChargePointError {
    /// No such connector, or the charger is offline.
    Unavailable,
    /// The connector is faulted or busy.
    Faulted,
    /// The charger refused the command.
    Rejected,
}

/// The port the gateway uses. The OCPP adapter implements it; tests use [`SimulatedChargePoint`].
pub trait ChargePoint {
    fn status(&self, connector: u8) -> Result<ConnectorStatus, ChargePointError>;
    /// Starts a charge with a hard energy limit, in Wh.
    fn start(
        &self,
        connector: u8,
        id_tag: &str,
        limit_wh: u64,
    ) -> Result<StartAck, ChargePointError>;
    fn stop(&self, connector: u8, reason: StopReason) -> Result<StopAck, ChargePointError>;
    /// The cumulative meter, in Wh.
    fn meter(&self, connector: u8) -> Result<MeterReading, ChargePointError>;
}

/// A charge point in memory: enough for the tests and the demo, with knobs to make it fail on purpose.
pub struct SimulatedChargePoint {
    connectors: RefCell<BTreeMap<u8, Connector>>,
    next_transaction: Cell<u64>,
    now: Cell<u64>,
}

struct Connector {
    status: ConnectorStatus,
    transaction: Option<u64>,
    start_energy_wh: u64,
    energy_wh: u64,
    power_w: u64,
    limit_wh: u64,
    reject_start: bool,
}

impl SimulatedChargePoint {
    pub fn new(connectors: u8) -> Self {
        let mut map = BTreeMap::new();
        for connector in 1..=connectors {
            map.insert(
                connector,
                Connector {
                    status: ConnectorStatus::Available,
                    transaction: None,
                    start_energy_wh: 0,
                    energy_wh: 0,
                    power_w: 7_000,
                    limit_wh: 0,
                    reject_start: false,
                },
            );
        }
        Self {
            connectors: RefCell::new(map),
            next_transaction: Cell::new(0),
            now: Cell::new(0),
        }
    }

    /// The cable is plugged: the connector is ready for a remote start.
    pub fn plug(&self, connector: u8) {
        if let Some(c) = self.connectors.borrow_mut().get_mut(&connector)
            && c.status == ConnectorStatus::Available
        {
            c.status = ConnectorStatus::Preparing;
        }
    }

    /// The cable is unplugged. A charge in progress stops.
    pub fn unplug(&self, connector: u8) {
        if let Some(c) = self.connectors.borrow_mut().get_mut(&connector) {
            c.status = ConnectorStatus::Available;
            c.transaction = None;
        }
    }

    pub fn fault(&self, connector: u8) {
        if let Some(c) = self.connectors.borrow_mut().get_mut(&connector) {
            c.status = ConnectorStatus::Faulted;
            c.transaction = None;
        }
    }

    pub fn clear_fault(&self, connector: u8) {
        if let Some(c) = self.connectors.borrow_mut().get_mut(&connector)
            && c.status == ConnectorStatus::Faulted
        {
            c.status = ConnectorStatus::Available;
        }
    }

    /// Makes the next start fail, to exercise the rejection path.
    pub fn reject_start(&self, connector: u8, reject: bool) {
        if let Some(c) = self.connectors.borrow_mut().get_mut(&connector) {
            c.reject_start = reject;
        }
    }

    /// The meter advances by `wh` while the connector is charging.
    pub fn advance(&self, connector: u8, wh: u64) {
        if let Some(c) = self.connectors.borrow_mut().get_mut(&connector)
            && c.status == ConnectorStatus::Charging
        {
            c.energy_wh = c.energy_wh.saturating_add(wh);
        }
    }

    pub fn set_power(&self, connector: u8, watts: u64) {
        if let Some(c) = self.connectors.borrow_mut().get_mut(&connector) {
            c.power_w = watts;
        }
    }

    pub fn set_now(&self, now: u64) {
        self.now.set(now);
    }

    /// Energy delivered in the current (or last) transaction, in Wh.
    pub fn energy_delivered(&self, connector: u8) -> Option<u64> {
        self.connectors
            .borrow()
            .get(&connector)
            .map(|c| c.energy_wh.saturating_sub(c.start_energy_wh))
    }

    pub fn limit_wh(&self, connector: u8) -> Option<u64> {
        self.connectors.borrow().get(&connector).map(|c| c.limit_wh)
    }
}

impl ChargePoint for SimulatedChargePoint {
    fn status(&self, connector: u8) -> Result<ConnectorStatus, ChargePointError> {
        self.connectors
            .borrow()
            .get(&connector)
            .map(|c| c.status)
            .ok_or(ChargePointError::Unavailable)
    }

    fn start(
        &self,
        connector: u8,
        _id_tag: &str,
        limit_wh: u64,
    ) -> Result<StartAck, ChargePointError> {
        let mut connectors = self.connectors.borrow_mut();
        let c = connectors
            .get_mut(&connector)
            .ok_or(ChargePointError::Unavailable)?;
        if c.reject_start {
            return Err(ChargePointError::Rejected);
        }
        match c.status {
            ConnectorStatus::Available | ConnectorStatus::Preparing => {}
            ConnectorStatus::Faulted | ConnectorStatus::Unavailable => {
                return Err(ChargePointError::Faulted);
            }
            ConnectorStatus::Charging => return Err(ChargePointError::Rejected),
        }
        let transaction_id = self.next_transaction.get() + 1;
        self.next_transaction.set(transaction_id);
        c.status = ConnectorStatus::Charging;
        c.transaction = Some(transaction_id);
        c.start_energy_wh = c.energy_wh;
        c.limit_wh = limit_wh;
        Ok(StartAck { transaction_id })
    }

    fn stop(&self, connector: u8, _reason: StopReason) -> Result<StopAck, ChargePointError> {
        let mut connectors = self.connectors.borrow_mut();
        let c = connectors
            .get_mut(&connector)
            .ok_or(ChargePointError::Unavailable)?;
        if c.status == ConnectorStatus::Charging {
            // The cable is still plugged: the connector goes back to Preparing.
            c.status = ConnectorStatus::Preparing;
            c.transaction = None;
            c.limit_wh = 0;
        }
        Ok(StopAck {
            energy_wh: c.energy_wh,
        })
    }

    fn meter(&self, connector: u8) -> Result<MeterReading, ChargePointError> {
        self.connectors
            .borrow()
            .get(&connector)
            .map(|c| MeterReading {
                energy_wh: c.energy_wh,
                power_w: if c.status == ConnectorStatus::Charging {
                    c.power_w
                } else {
                    0
                },
                at: self.now.get(),
            })
            .ok_or(ChargePointError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_charge_starts_meters_and_stops() {
        let cp = SimulatedChargePoint::new(1);
        cp.plug(1);
        assert_eq!(cp.status(1), Ok(ConnectorStatus::Preparing));
        let ack = cp.start(1, "x402-1", 1_000).unwrap();
        assert_eq!(ack.transaction_id, 1);
        assert_eq!(cp.status(1), Ok(ConnectorStatus::Charging));
        assert_eq!(cp.energy_delivered(1), Some(0));
        cp.advance(1, 400);
        assert_eq!(cp.meter(1).unwrap().energy_wh, 400);
        assert_eq!(cp.energy_delivered(1), Some(400));
        let stop = cp.stop(1, StopReason::FullyCharged).unwrap();
        assert_eq!(stop.energy_wh, 400);
        assert_eq!(cp.status(1), Ok(ConnectorStatus::Preparing));
        assert_eq!(cp.meter(1).unwrap().power_w, 0);
    }

    #[test]
    fn a_busy_connector_rejects_a_second_start() {
        let cp = SimulatedChargePoint::new(1);
        cp.plug(1);
        cp.start(1, "a", 1_000).unwrap();
        assert_eq!(cp.start(1, "b", 1_000), Err(ChargePointError::Rejected));
    }

    #[test]
    fn a_rejected_start_leaves_the_connector_alone() {
        let cp = SimulatedChargePoint::new(1);
        cp.plug(1);
        cp.reject_start(1, true);
        assert_eq!(cp.start(1, "a", 1_000), Err(ChargePointError::Rejected));
        assert_eq!(cp.status(1), Ok(ConnectorStatus::Preparing));
        assert_eq!(cp.meter(1).unwrap().energy_wh, 0);
    }

    #[test]
    fn a_faulted_connector_cannot_start() {
        let cp = SimulatedChargePoint::new(1);
        cp.fault(1);
        assert_eq!(cp.start(1, "a", 1_000), Err(ChargePointError::Faulted));
        cp.clear_fault(1);
        assert!(cp.start(1, "a", 1_000).is_ok());
    }

    #[test]
    fn unplugging_stops_the_transaction() {
        let cp = SimulatedChargePoint::new(1);
        cp.plug(1);
        cp.start(1, "a", 1_000).unwrap();
        cp.advance(1, 250);
        cp.unplug(1);
        assert_eq!(cp.status(1), Ok(ConnectorStatus::Available));
        assert_eq!(cp.meter(1).unwrap().energy_wh, 250);
    }

    #[test]
    fn an_unknown_connector_is_unavailable() {
        let cp = SimulatedChargePoint::new(1);
        assert_eq!(cp.status(99), Err(ChargePointError::Unavailable));
        assert_eq!(cp.start(99, "a", 1_000), Err(ChargePointError::Unavailable));
        assert_eq!(
            cp.stop(99, StopReason::ChargerError),
            Err(ChargePointError::Unavailable)
        );
        assert_eq!(cp.meter(99), Err(ChargePointError::Unavailable));
    }
}
