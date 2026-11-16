//! The token's own blacklist, asked on chain (port of `TokenBlacklist.php`): Circle freezes USDC
//! addresses, Tether freezes USDT ones. A frozen payer cannot be settled from, so the payment is refused
//! before anything runs (`address_blacklisted`).
//!
//! One `eth_call` of a `(address) returns (bool)` function per check. A token not in the table is not
//! asked (it passes). A node that cannot answer refuses (`address_check_failed`), unless the list was
//! built to fail open, which reports [`Event::ScreeningSkipped`].

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};

use quebracho_x402::field::{self, Rule};
use quebracho_x402::ports::{AddressListener, Event, Events, Https, ListFailed};
use serde_json::Value;

use crate::rpc;

/// The blacklist functions known, by name: their 4-byte selectors.
pub const FUNCTIONS: [(&str, &str); 4] = [
    ("isBlacklisted", "0xfe575a87"),      // Circle's USDC
    ("isBlackListed", "0xe47d6060"),      // Tether's USDT, legacy
    ("getBlackListStatus", "0x59bf1abe"), // Tether's USDT, legacy (same answer)
    ("isBlocked", "0xfbac3951"),          // Tether's USDT0; no token uses it by default
];

/// The tokens asked by default, `network|asset` (lower case) => function. The PHP library's table, each
/// read from a public RPC on 2026-11-03.
pub const TOKENS: [(&str, &str); 13] = [
    (
        "eip155:84532|0x036cbd53842c5426634e7929541ec2318f3dcf7e",
        "isBlacklisted",
    ),
    (
        "eip155:5042002|0x3600000000000000000000000000000000000000",
        "isBlacklisted",
    ),
    (
        "eip155:43113|0x5425890298aed601595a70ab815c96711a31bc65",
        "isBlacklisted",
    ),
    (
        "eip155:11155111|0x1c7d4b196cb0c7b01d743fbc6116a902379c7238",
        "isBlacklisted",
    ),
    (
        "eip155:80002|0x41e94eb019c0762f9bfcf9fb1e58725bfb0e7582",
        "isBlacklisted",
    ),
    (
        "eip155:1|0xdac17f958d2ee523a2206206994597c13d831ec7",
        "isBlackListed",
    ),
    (
        "eip155:1|0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        "isBlacklisted",
    ),
    (
        "eip155:8453|0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
        "isBlacklisted",
    ),
    (
        "eip155:137|0x3c499c542cef5e3811e1192ce70d8cc03d5c3359",
        "isBlacklisted",
    ),
    (
        "eip155:43114|0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e",
        "isBlacklisted",
    ),
    (
        "eip155:10|0x0b2c639c533813f4aa9d7837caf62653d097ff85",
        "isBlacklisted",
    ),
    (
        "eip155:42161|0xaf88d065e77c8cc2239327c5edb3a432268e5831",
        "isBlacklisted",
    ),
    (
        "eip155:5042|0x3600000000000000000000000000000000000000",
        "isBlacklisted",
    ),
];

/// Public RPC endpoints of the networks the PHP library builds in. Add yours with
/// [`TokenBlacklist::rpc`]; a network without one is not asked.
pub const RPCS: [(&str, &str); 8] = [
    ("eip155:1", "https://ethereum-rpc.publicnode.com"),
    ("eip155:8453", "https://mainnet.base.org"),
    ("eip155:84532", "https://sepolia.base.org"),
    ("eip155:5042", "https://rpc.mainnet.arc.io"),
    ("eip155:5042002", "https://rpc.testnet.arc.network"),
    (
        "eip155:11155111",
        "https://ethereum-sepolia-rpc.publicnode.com",
    ),
    ("eip155:43113", "https://api.avax-test.network/ext/bc/C/rpc"),
    ("eip155:80002", "https://rpc-amoy.polygon.technology"),
];

/// A function name that is not in [`FUNCTIONS`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownFunction(pub String);

pub struct TokenBlacklist<'a> {
    https: &'a dyn Https,
    tokens: BTreeMap<String, &'static str>,
    rpcs: BTreeMap<String, String>,
    fail_open: bool,
    events: Option<&'a dyn Events>,
}

impl<'a> TokenBlacklist<'a> {
    /// The default tokens and RPC endpoints; fails closed.
    pub fn new(https: &'a dyn Https) -> Self {
        Self {
            https,
            tokens: TOKENS
                .iter()
                .map(|(k, f)| ((*k).into(), selector(f).unwrap_or_default()))
                .collect(),
            rpcs: RPCS
                .iter()
                .map(|(n, u)| ((*n).into(), (*u).into()))
                .collect(),
            fail_open: false,
            events: None,
        }
    }

    /// Asks `asset` on `network` with `function` (a name in [`FUNCTIONS`]), or overrides a default.
    pub fn token(
        mut self,
        network: &str,
        asset: &str,
        function: &str,
    ) -> Result<Self, UnknownFunction> {
        let s = selector(function).ok_or_else(|| UnknownFunction(function.into()))?;
        self.tokens
            .insert(alloc::format!("{network}|{asset}").to_ascii_lowercase(), s);
        Ok(self)
    }

    /// The node asked for `network`.
    pub fn rpc(mut self, network: &str, url: &str) -> Self {
        self.rpcs.insert(network.into(), url.into());
        self
    }

    /// Lets an address pass unchecked when the node cannot answer, and reports it.
    pub fn fail_open(mut self, events: Option<&'a dyn Events>) -> Self {
        self.fail_open = true;
        self.events = events;
        self
    }
}

fn selector(function: &str) -> Option<&'static str> {
    FUNCTIONS
        .iter()
        .find(|(n, _)| *n == function)
        .map(|(_, s)| *s)
}

impl AddressListener for TokenBlacklist<'_> {
    fn check(
        &self,
        role: &str,
        network: &str,
        address: &str,
        req: &Value,
    ) -> Result<Option<String>, ListFailed> {
        let asset = req.get("asset").and_then(Value::as_str).unwrap_or_default();
        let Some(sel) = self
            .tokens
            .get(&alloc::format!("{network}|{asset}").to_ascii_lowercase())
        else {
            return Ok(None);
        };
        if !network.starts_with("eip155:") {
            return Ok(None);
        }
        if !field::is(Rule::Address, address) {
            return Ok(Some("invalid_payload".into()));
        }
        let Some(url) = self.rpcs.get(network) else {
            // A token we know on a network without a node: nothing to ask.
            return Ok(None);
        };
        match rpc::ask_bool(self.https, url, asset, sel, address) {
            Ok(true) => Ok(Some("address_blacklisted".into())),
            Ok(false) => Ok(None),
            Err(_) if self.fail_open => {
                if let Some(e) = self.events {
                    e.report(&Event::ScreeningSkipped {
                        role,
                        address,
                        by: "TokenBlacklist",
                    });
                }
                Ok(None)
            }
            Err(_) => Err(ListFailed),
        }
    }
}

/// The default RPC endpoint for a network, if it has one.
pub fn default_rpc(network: &str) -> Option<String> {
    RPCS.iter()
        .find(|(n, _)| *n == network)
        .map(|(_, u)| u.to_string())
}
