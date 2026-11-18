//! The OCPP gateway: sells a block of energy with x402, then drives the charge point through the
//! [`ChargePoint`] port. The wire adapter (OCPP 1.6J over WebSocket) is not here yet; the simulator is
//! enough for the tests and the demo.
//!
//! The offer is always `extra.paymentFlow = "delivery"`: charging is an effect that can be stopped, and
//! paying upfront with `exact` would charge a buyer if the charger rejects the start, with no refund.

pub mod charge_point;
pub mod gateway;
pub mod memory_ledger;
pub mod rate_limit;
pub mod session;

pub use charge_point::{
    ChargePoint, ChargePointError, ConnectorStatus, MeterReading, SimulatedChargePoint, StartAck,
    StopAck, StopReason,
};
pub use gateway::{ChargeOutcome, ChargeRequest, ConfigError, Gateway, GatewayConfig, MAX_KWH};
pub use memory_ledger::MemoryLedger;
pub use rate_limit::{RateLimit, TokenBucket};
pub use session::{Session, SessionState};
