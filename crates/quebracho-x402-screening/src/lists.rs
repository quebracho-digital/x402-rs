//! A site's own lists as one listener (port of `Screening.php`): an allowlist, a denylist and, when given,
//! Chainalysis' API.
//!
//! In order, the first refusal decides:
//! 1. OFAC's list, asked by the core before any listener: nothing here lets a sanctioned address through,
//!    the allowlist included;
//! 2. the allowlist: skips 3 and 4 (never OFAC, nor another listener such as [`crate::TokenBlacklist`]);
//! 3. the denylist: `address_denied`;
//! 4. Chainalysis' API, when given.
//!
//! Both lists use the plain-text format of [`AddressList`]. Not ported: PHP's cache of API answers.

use alloc::string::String;

use quebracho_x402::ports::{AddressListener, ListFailed};
use quebracho_x402::screening::AddressList;
use serde_json::Value;

use crate::chainalysis::Api;

pub struct Lists<'a> {
    allow: AddressList,
    deny: AddressList,
    api: Option<Api<'a>>,
    /// A list file that could not be read: everyone is refused (fail closed).
    unreadable: bool,
}

impl<'a> Lists<'a> {
    /// `allow` and `deny` in the list format (an absent file is an empty list).
    pub fn new(allow: &str, deny: &str) -> Self {
        Self {
            allow: AddressList::parse(allow, ""),
            deny: AddressList::parse(deny, "address_denied"),
            api: None,
            unreadable: false,
        }
    }

    /// The lists in `allow` and `deny` files (feature `std`). A file that does not exist is an empty list;
    /// one that cannot be read refuses every address (`address_check_failed`).
    #[cfg(feature = "std")]
    pub fn from_files(allow: &std::path::Path, deny: &std::path::Path) -> Self {
        let read = |p: &std::path::Path| match std::fs::read_to_string(p) {
            Ok(text) => Some(text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(String::new()),
            Err(_) => None,
        };
        match (read(allow), read(deny)) {
            (Some(a), Some(d)) => Self::new(&a, &d),
            _ => Self {
                unreadable: true,
                ..Self::new("", "")
            },
        }
    }

    /// Asks Chainalysis' API about what neither list decided.
    pub fn api(mut self, api: Api<'a>) -> Self {
        self.api = Some(api);
        self
    }
}

impl AddressListener for Lists<'_> {
    fn check(
        &self,
        role: &str,
        _network: &str,
        address: &str,
        _req: &Value,
    ) -> Result<Option<String>, ListFailed> {
        if self.unreadable {
            return Err(ListFailed);
        }
        if self.allow.contains(address) {
            return Ok(None);
        }
        if self.deny.contains(address) {
            return Ok(Some("address_denied".into()));
        }
        match &self.api {
            Some(api) => api.verdict(role, address),
            None => Ok(None),
        }
    }
}
