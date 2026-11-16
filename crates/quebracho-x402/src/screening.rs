//! Address screening (port of `OfacSdn`, `AddressCheck` and the list format of `AddressList`).
//!
//! OFAC's SDN list is asked first, always: a seller is built with an [`Ofac`] and the only way to have none
//! is [`Ofac::off`], by name. A snapshot that cannot be read refuses every address (fail closed). Other
//! lists are [`AddressListener`]s, asked only about an address OFAC's list passed; the first rejection wins.

use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};

use serde_json::Value;

use crate::field::{self, Rule};
use crate::ports::{AddressListener, Event, Events, ListFailed};

/// OFAC's reason.
pub const SANCTIONED: &str = "address_sanctioned";
/// A list that threw, or a snapshot that cannot be read.
pub const CHECK_FAILED: &str = "address_check_failed";

pub const PAYER: &str = "payer";
pub const PAY_TO: &str = "payTo";

/// OFAC's SDN digital-currency addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ofac {
    /// A snapshot in use, and when OFAC published it.
    List {
        published: String,
        index: BTreeSet<String>,
    },
    /// Turned off by name: whoever does it answers for paying or being paid by listed addresses.
    Off,
    /// A snapshot that could not be read: every address is refused.
    Unreadable,
}

impl Ofac {
    /// Reads a snapshot (`{"published": "...", "addresses": {"ETH": ["0x…"], ...}}`, the format of the PHP
    /// library's `resources/ofac-sdn.json`). Anything else is [`Ofac::Unreadable`].
    pub fn from_snapshot(json: &str) -> Self {
        let Ok(data) = serde_json::from_str::<Value>(json) else {
            return Self::Unreadable;
        };
        let (Some(published), Some(Value::Object(lists))) = (
            data.get("published").and_then(Value::as_str),
            data.get("addresses"),
        ) else {
            return Self::Unreadable;
        };
        let mut index = BTreeSet::new();
        for list in lists.values() {
            let Value::Array(list) = list else {
                return Self::Unreadable;
            };
            for a in list.iter().filter_map(Value::as_str) {
                index.insert(normalize(a));
            }
        }
        Self::List {
            published: published.to_string(),
            index,
        }
    }

    pub fn off() -> Self {
        Self::Off
    }

    /// The younger of two snapshots (the shipped one and the app's own synced copy): a lagging copy cannot
    /// roll the list back. An unreadable one never wins over a readable one.
    pub fn younger(self, other: Self) -> Self {
        match (&self, &other) {
            (Self::List { published: a, .. }, Self::List { published: b, .. }) => {
                if b >= a {
                    other
                } else {
                    self
                }
            }
            (Self::List { .. }, _) => self,
            _ => other,
        }
    }

    /// When OFAC published the list in use.
    pub fn published(&self) -> Option<&str> {
        match self {
            Self::List { published, .. } => Some(published),
            _ => None,
        }
    }

    /// Why OFAC's list refuses `address`, or `None`.
    pub fn reason(&self, address: &str) -> Option<&'static str> {
        match self {
            Self::List { index, .. } => index.contains(&normalize(address)).then_some(SANCTIONED),
            Self::Off => None,
            Self::Unreadable => Some(CHECK_FAILED),
        }
    }
}

/// A `0x…` EVM address in lower case (EIP-55's case is a checksum); others as they are.
fn normalize(address: &str) -> String {
    if field::is(Rule::Address, address) {
        address.to_ascii_lowercase()
    } else {
        address.to_string()
    }
}

/// Why `address` may not take part in this payment (`role` is [`PAYER`] or [`PAY_TO`]), or `None`.
/// OFAC first, then each listener; an empty address is `invalid_payload`; a listener that fails refuses.
pub fn check(
    ofac: &Ofac,
    listeners: &[&dyn AddressListener],
    events: Option<&dyn Events>,
    role: &str,
    address: Option<&str>,
    req: &Value,
) -> Option<String> {
    let network = req
        .get("network")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let reason: Option<String> = match address {
        None | Some("") => Some("invalid_payload".into()),
        Some(a) => ofac.reason(a).map(String::from).or_else(|| {
            listeners
                .iter()
                .find_map(|l| match l.check(role, network, a, req) {
                    Ok(r) => r,
                    Err(ListFailed) => Some(CHECK_FAILED.into()),
                })
        }),
    };
    if let (Some(r), Some(events)) = (&reason, events) {
        events.report(&Event::AddressRejected {
            role,
            address: address.unwrap_or_default(),
            reason: r,
        });
    }
    reason
}

/// One plain-text list (`resources/address-list.example.txt` of the PHP library): one address per line,
/// `#` comments and blank lines ignored, anything after the address ignored. `0x…` matches in any case.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AddressList {
    entries: alloc::vec::Vec<String>,
    index: BTreeSet<String>,
    reason: String,
    /// The list's date from its `# updated:` line, as `YYYY-MM-DDTHH:MM:SSZ`, if it has one.
    pub updated: Option<String>,
}

impl AddressList {
    pub fn parse(text: &str, reason: &str) -> Self {
        let mut list = Self {
            reason: reason.into(),
            updated: updated(text),
            ..Self::default()
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(address) = line.split_whitespace().next() {
                let address = normalize(address);
                if list.index.insert(address.clone()) {
                    list.entries.push(address);
                }
            }
        }
        list
    }

    /// The addresses, normalized (`0x…` in lower case), in order, without repeats.
    pub fn addresses(&self) -> &[String] {
        &self.entries
    }

    pub fn contains(&self, address: &str) -> bool {
        self.index.contains(&normalize(address))
    }
}

/// The date in a list's `# updated:` comment (any case, any spacing), as `YYYY-MM-DDTHH:MM:SSZ`, or `None`.
pub fn updated(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let rest = line.trim().strip_prefix('#')?.trim_start();
        let rest = rest
            .get(..8)
            .filter(|p| p.eq_ignore_ascii_case("updated:"))
            .map(|_| &rest[8..])?;
        let value = rest.trim();
        (!value.is_empty() && !value.contains(char::is_whitespace))
            .then(|| crate::dates::parse_iso(value).map(crate::dates::iso))?
    })
}

impl AddressListener for AddressList {
    fn check(
        &self,
        _role: &str,
        _network: &str,
        address: &str,
        _req: &Value,
    ) -> Result<Option<String>, ListFailed> {
        Ok(self.contains(address).then(|| self.reason.clone()))
    }
}
