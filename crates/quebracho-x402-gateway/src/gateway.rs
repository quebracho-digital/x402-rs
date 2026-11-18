//! The paid charge: the core [`Seller`] plus the charge point.
//!
//! The offer is `extra.paymentFlow = "delivery"`: the handler starts the charge, then the seller
//! settles. If the settle fails, the gateway stops the charge. The energy delivered before the stop is
//! bounded by the block and the meter interval.

use core::cell::{Cell, RefCell};

use quebracho_x402::field::{self, Rule};
use quebracho_x402::headers;
use quebracho_x402::ports::Clock;
use quebracho_x402::seller::{HandlerFailed, Request, Response, Seller};
use serde_json::{Value, json};

use crate::charge_point::{
    ChargePoint, ChargePointError, ConnectorStatus, MeterReading, StopAck, StopReason,
};
use crate::rate_limit::RateLimit;
use crate::session::{Session, SessionState};

/// The largest block the gateway sells in one request: 1 MWh. A public charger never needs more, and
/// the cap keeps the amount and the meter limit far from overflow.
pub const MAX_KWH: u64 = 1_000;

/// Why a [`GatewayConfig`] is not usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    Network,
    Asset,
    PayTo,
    TokenName,
    TokenVersion,
    Price,
    MaxTimeout,
    ResourceUrl,
}

/// The offer the gateway makes. `price_per_kwh` is in atomic units; `kwh` is a whole number in the
/// first version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayConfig {
    pub network: String,
    pub asset: String,
    pub pay_to: String,
    pub token_name: String,
    pub token_version: String,
    pub price_per_kwh: u64,
    pub max_timeout_seconds: u64,
    pub resource_url: String,
}

impl GatewayConfig {
    /// Checks the configuration once, at startup. A config that fails here must not serve payments.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !field::is(Rule::EvmNetwork, &self.network) {
            return Err(ConfigError::Network);
        }
        if !field::is(Rule::Address, &self.asset) {
            return Err(ConfigError::Asset);
        }
        if !field::is(Rule::Address, &self.pay_to) {
            return Err(ConfigError::PayTo);
        }
        if self.token_name.is_empty()
            || self.token_name.len() > 64
            || self.token_name.trim() != self.token_name.as_str()
        {
            return Err(ConfigError::TokenName);
        }
        if self.token_version.is_empty()
            || self.token_version.len() > 64
            || self.token_version.trim() != self.token_version.as_str()
        {
            return Err(ConfigError::TokenVersion);
        }
        if self.price_per_kwh == 0 {
            return Err(ConfigError::Price);
        }
        if self.max_timeout_seconds == 0 || self.max_timeout_seconds > 600 {
            return Err(ConfigError::MaxTimeout);
        }
        if !self.resource_url.starts_with("https://") || self.resource_url.len() <= "https://".len()
        {
            return Err(ConfigError::ResourceUrl);
        }
        let host = self.resource_url["https://".len()..]
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default();
        if host.is_empty() || host.chars().any(char::is_whitespace) {
            return Err(ConfigError::ResourceUrl);
        }
        Ok(())
    }
}

/// One request to charge a connector.
#[derive(Debug, Clone, Copy)]
pub struct ChargeRequest<'a> {
    pub connector: u8,
    pub kwh: u64,
    /// The `PAYMENT-SIGNATURE` header, if the driver sent one.
    pub payment: Option<&'a str>,
}

/// What happened to a charge request.
#[derive(Debug)]
pub enum ChargeOutcome {
    /// Nothing was charged: the 402, 400, 409, 429 or 503 answer to send as it is.
    Rejected(Response),
    /// The charge started but the session did not complete: the settle failed or the charger refused.
    Failed {
        session: Option<Session>,
        response: Response,
        reason: &'static str,
    },
    /// Paid, settled and charging.
    Charging {
        session: Session,
        response: Response,
    },
    /// The payment was already settled: the stored response is returned and the handler does not run.
    Replayed { response: Response },
}

/// The gateway: one seller, one charge point, one clock.
pub struct Gateway<'a> {
    seller: Seller<'a>,
    charge_point: &'a dyn ChargePoint,
    clock: &'a dyn Clock,
    config: GatewayConfig,
    rate_limit: Option<&'a dyn RateLimit>,
    next_session: Cell<u64>,
}

impl<'a> Gateway<'a> {
    /// Builds a gateway from a trusted config. Call [`GatewayConfig::validate`] at startup, or use
    /// [`Self::try_new`].
    pub fn new(
        seller: Seller<'a>,
        charge_point: &'a dyn ChargePoint,
        clock: &'a dyn Clock,
        config: GatewayConfig,
    ) -> Self {
        Self {
            seller,
            charge_point,
            clock,
            config,
            rate_limit: None,
            next_session: Cell::new(0),
        }
    }

    /// Builds a gateway only when the config is valid.
    pub fn try_new(
        seller: Seller<'a>,
        charge_point: &'a dyn ChargePoint,
        clock: &'a dyn Clock,
        config: GatewayConfig,
    ) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self::new(seller, charge_point, clock, config))
    }

    /// Applies an app-level rate limit to the payer address.
    pub fn with_rate_limit(mut self, rate_limit: &'a dyn RateLimit) -> Self {
        self.rate_limit = Some(rate_limit);
        self
    }

    pub fn config(&self) -> &GatewayConfig {
        &self.config
    }

    /// Charges one connector for `kwh`. The handler runs at most once; the seller's claim decides.
    pub fn charge(&self, request: ChargeRequest<'_>) -> ChargeOutcome {
        if request.kwh == 0 {
            return ChargeOutcome::Rejected(rejected(400, "kwh_must_be_positive"));
        }
        if request.kwh > MAX_KWH {
            return ChargeOutcome::Rejected(rejected(400, "kwh_too_large"));
        }
        match self.charge_point.status(request.connector) {
            Ok(ConnectorStatus::Available | ConnectorStatus::Preparing) => {}
            Ok(_) => return ChargeOutcome::Rejected(rejected(409, "connector_busy")),
            Err(_) => return ChargeOutcome::Rejected(rejected(503, "charge_point_unavailable")),
        }

        let payer = request.payment.and_then(payer_of);
        if let (Some(limit), Some(payer)) = (self.rate_limit, payer.as_deref())
            && !limit.allow(payer, self.clock.now())
        {
            return ChargeOutcome::Rejected(rejected(429, "rate_limited"));
        }

        let Some(amount) = self.config.price_per_kwh.checked_mul(request.kwh) else {
            return ChargeOutcome::Rejected(rejected(400, "amount_overflow"));
        };
        let Some(limit_wh) = request.kwh.checked_mul(1_000) else {
            return ChargeOutcome::Rejected(rejected(400, "amount_overflow"));
        };
        let offer = json!({
            "scheme": "exact",
            "network": self.config.network.clone(),
            "amount": amount.to_string(),
            "asset": self.config.asset.clone(),
            "payTo": self.config.pay_to.clone(),
            "maxTimeoutSeconds": self.config.max_timeout_seconds,
            "extra": {
                "name": self.config.token_name.clone(),
                "version": self.config.token_version.clone(),
                "paymentFlow": "delivery",
            },
        });
        let accepts = [offer];
        let resource = json!({
            "url": self.config.resource_url.clone(),
            "description": "EV charging",
            "mimeType": "application/json",
        });

        let payer_text = payer.unwrap_or_default();
        let amount_text = amount.to_string();
        let started: RefCell<Option<Session>> = RefCell::new(None);

        let result = self.seller.process(
            &Request {
                accepts: Some(&accepts),
                resource: &resource,
                payment: request.payment,
                keep: true,
            },
            || {
                let session_id = self.next_session.get() + 1;
                self.next_session.set(session_id);
                let id_tag = format!("x402-{session_id}");
                let start_energy_wh = self
                    .charge_point
                    .meter(request.connector)
                    .map(|m| m.energy_wh)
                    .unwrap_or(0);
                let ack = self
                    .charge_point
                    .start(request.connector, &id_tag, limit_wh)
                    .map_err(|_| HandlerFailed)?;
                let session = Session {
                    id: session_id,
                    connector: request.connector,
                    payer: payer_text,
                    amount: amount_text,
                    limit_wh,
                    transaction_id: ack.transaction_id,
                    start_energy_wh,
                    started_at: self.clock.now(),
                    state: SessionState::Charging,
                };
                *started.borrow_mut() = Some(session.clone());
                Ok(Response::json(
                    200,
                    &json!({
                        "session": session.id,
                        "connector": session.connector,
                        "transaction": session.transaction_id,
                        "limitWh": session.limit_wh,
                        "amount": session.amount,
                    }),
                ))
            },
        );

        let session = started.into_inner();
        match result {
            Ok(response) if response.status == 200 && receipt_success(&response) => match session {
                Some(session) => ChargeOutcome::Charging { session, response },
                None => ChargeOutcome::Replayed { response },
            },
            Ok(response) => match session {
                Some(mut session) => {
                    let _ = self.stop(&mut session, StopReason::PaymentFailed);
                    ChargeOutcome::Failed {
                        session: Some(session),
                        response,
                        reason: "settlement_failed",
                    }
                }
                None => ChargeOutcome::Rejected(response),
            },
            Err(HandlerFailed) => {
                let session = match session {
                    Some(mut session) => {
                        let _ = self.stop(&mut session, StopReason::ChargerError);
                        Some(session)
                    }
                    None => None,
                };
                ChargeOutcome::Failed {
                    session,
                    response: rejected(502, "charge_point_rejected"),
                    reason: "charge_point_rejected",
                }
            }
        }
    }

    /// Stops a session and marks it closed.
    pub fn stop(
        &self,
        session: &mut Session,
        reason: StopReason,
    ) -> Result<StopAck, ChargePointError> {
        session.state = SessionState::Stopping;
        match self.charge_point.stop(session.connector, reason) {
            Ok(ack) => {
                session.state = SessionState::Closed;
                Ok(ack)
            }
            Err(e) => {
                session.state = SessionState::Failed;
                Err(e)
            }
        }
    }

    /// Whether the meter reached the block the buyer paid for.
    pub fn should_stop(&self, session: &Session) -> Result<bool, ChargePointError> {
        let meter = self.charge_point.meter(session.connector)?;
        Ok(session.is_complete(meter.energy_wh))
    }

    pub fn meter(&self, session: &Session) -> Result<MeterReading, ChargePointError> {
        self.charge_point.meter(session.connector)
    }

    pub fn status(&self, connector: u8) -> Result<ConnectorStatus, ChargePointError> {
        self.charge_point.status(connector)
    }
}

fn rejected(status: u16, error: &str) -> Response {
    Response::json(status, &json!({ "error": error }))
}

/// The payer in a `PAYMENT-SIGNATURE` header, if the header decodes and `from` is a canonical address.
/// An unverified, arbitrary string never becomes a rate-limit key.
fn payer_of(header: &str) -> Option<String> {
    let payment = headers::decode(header)?;
    let from = payment
        .get("payload")?
        .get("authorization")?
        .get("from")?
        .as_str()?;
    field::is(Rule::Address, from).then(|| from.to_string())
}

/// Whether the `PAYMENT-RESPONSE` header says `success: true`.
fn receipt_success(response: &Response) -> bool {
    response
        .header(headers::RESPONSE)
        .and_then(headers::decode)
        .and_then(|receipt| receipt.get("success").and_then(Value::as_bool))
        == Some(true)
}
