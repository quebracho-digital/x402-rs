//! The small rules that no PHP vector reaches: unknown names, malformed dates, broken snapshots.

use quebracho_x402::evm_exact::{self, Reason};
use quebracho_x402::field::{self, Rule};
use quebracho_x402::http_facilitator::check_settle;
use quebracho_x402::ports::{AddressListener, Clock, HttpsResponse};
use quebracho_x402::screening::{self, AddressList, Ofac};
use quebracho_x402::{dates, headers, signer};
use serde_json::json;

#[test]
fn unknown_rule_names_are_none() {
    assert_eq!(Rule::from_name("address"), Some(Rule::Address));
    assert_eq!(Rule::from_name("payment_id"), Some(Rule::PaymentId));
    assert_eq!(Rule::from_name("nope"), None);
    assert!(!field::is(Rule::PaymentId, ""));
}

#[test]
fn malformed_dates_are_none() {
    for bad in [
        "2026/11/06",
        "2026-11-06X10:00",
        "2026-11-06T10",
        "2026-11-06T10:00:00:00",
        "2026-11-06T1a:00",
        "2026-11-06T10:00+0x:00",
        "26-11-06",
    ] {
        assert_eq!(dates::parse_iso(bad), None, "{bad}");
    }
    assert_eq!(
        dates::parse_iso("2026-11-06T10:00")
            .map(dates::iso)
            .as_deref(),
        Some("2026-11-06T10:00:00Z")
    );
    assert_eq!(
        dates::parse_iso("2026-11-06 10:00:00+0130")
            .map(dates::iso)
            .as_deref(),
        Some("2026-11-06T08:30:00Z")
    );
    for bad in [
        "Fri, 13 Foo 2026 16:33:06 GMT",
        "Fri, 13 Nov 2026 16:33 GMT",
        "13 Nov 2026",
    ] {
        assert_eq!(dates::parse_http(bad), None, "{bad}");
    }
}

#[test]
fn addresses_parse_only_in_their_spelling() {
    assert!(signer::parse_address("0x000000000000000000000000000000000000dEaD").is_some());
    assert!(signer::parse_address("000000000000000000000000000000000000dEaD").is_none());
    assert!(signer::parse_address("0xdead").is_none());
}

#[test]
fn broken_snapshots_refuse_everyone() {
    for broken in [
        "[]",
        r#"{"published": 5, "addresses": {}}"#,
        r#"{"published": "x", "addresses": []}"#,
        r#"{"published": "x", "addresses": {"ETH": "0xabc"}}"#,
    ] {
        let ofac = Ofac::from_snapshot(broken);
        assert_eq!(ofac, Ofac::Unreadable, "{broken}");
        assert_eq!(
            ofac.reason("0x000000000000000000000000000000000000dEaD"),
            Some(screening::CHECK_FAILED)
        );
        assert_eq!(ofac.published(), None);
    }
    assert_eq!(Ofac::off().reason("anything"), None);
    // An unreadable list never wins; between two non-lists the second is kept.
    assert_eq!(Ofac::Unreadable.younger(Ofac::off()), Ofac::off());
    let list = Ofac::from_snapshot(r#"{"published":"2026-01-01T00:00:00Z","addresses":{}}"#);
    assert_eq!(Ofac::Unreadable.younger(list.clone()), list);
    assert_eq!(list.clone().younger(Ofac::Unreadable), list);
}

#[test]
fn a_list_is_a_listener_and_updated_needs_a_date() {
    let l = AddressList::parse(
        "0xAA00000000000000000000000000000000000001\n",
        "address_denied",
    );
    let ask = |a: &str| l.check("payer", "eip155:1", a, &json!({}));
    assert_eq!(
        ask("0xaa00000000000000000000000000000000000001"),
        Ok(Some("address_denied".into()))
    );
    assert_eq!(ask("0xbb00000000000000000000000000000000000001"), Ok(None));
    assert_eq!(screening::updated("# updated:"), None);
    assert_eq!(screening::updated("# updated: two words"), None);
    assert_eq!(screening::updated("#updated 2026-01-01"), None);
}

#[test]
fn a_settle_on_another_chain_family_only_needs_a_transaction() {
    let req = json!({ "network": "solana:devnet" });
    let ok = check_settle(
        json!({ "success": true, "transaction": "5abc", "network": "solana:devnet" }),
        &json!({}),
        &req,
    );
    assert_eq!(ok["success"], true);
    let empty = check_settle(
        json!({ "success": true, "transaction": "", "network": "solana:devnet" }),
        &json!({}),
        &req,
    );
    assert_eq!(empty["errorReason"], "invalid_settle_response");
}

#[test]
fn response_headers_are_found_in_any_case_and_clocks_trust_by_default() {
    let r = HttpsResponse {
        status: 200,
        headers: vec![("Last-Modified".into(), "x".into())],
        body: vec![],
    };
    assert_eq!(r.header("last-modified"), Some("x"));
    assert_eq!(r.header("etag"), None);
    struct C;
    impl Clock for C {
        fn now(&self) -> u64 {
            7
        }
    }
    assert!(C.reliable());
    assert_eq!(C.now(), 7);
}

/// Audit L2: a date with an absurd year is not a date (it used to overflow).
#[test]
fn absurd_years_are_not_dates() {
    assert_eq!(
        dates::parse_http("Fri, 13 Nov 9999999999999999 16:33:06 GMT"),
        None
    );
    assert_eq!(dates::parse_http("Fri, 13 Nov 99999 16:33:06 GMT"), None);
    assert_eq!(
        dates::parse_http("Fri, 13 Nov 2026 16:33:06 GMT")
            .map(dates::iso)
            .as_deref(),
        Some("2026-11-13T16:33:06Z")
    );
}

/// Calendar edges the property tests are unlikely to hit (found by cargo-mutants).
#[test]
fn calendar_edges() {
    assert!(
        dates::parse_iso("2000-02-29").is_some(),
        "divisible by 400: leap"
    );
    assert_eq!(
        dates::parse_iso("1900-02-29"),
        None,
        "divisible by 100: not leap"
    );
    assert_eq!(dates::parse_iso("2100-02-29"), None);
    assert!(dates::parse_iso("2024-02-29").is_some());
    assert_eq!(dates::parse_iso("2026-04-31"), None, "April has 30 days");
    assert_eq!(dates::parse_iso("2026-06-31"), None);
    assert!(dates::parse_iso("2026-07-31").is_some());
    assert_eq!(
        dates::parse_iso("+026-11-06"),
        None,
        "a sign is not a digit"
    );
    assert_eq!(
        dates::parse_iso("2026x11-06"),
        None,
        "one bad separator is enough"
    );
    assert_eq!(dates::parse_iso("2026-11x06"), None);
    // The last day of a 400-year era.
    assert_eq!(dates::iso(951_782_400), "2000-02-29T00:00:00Z");
    assert_eq!(dates::iso(-1), "1969-12-31T23:59:59Z");
}

#[test]
fn a_list_keeps_its_date() {
    let l = AddressList::parse(
        "# updated: 2026-11-06T19:33:18-03:00\n0xaa00000000000000000000000000000000000001\n",
        "x",
    );
    assert_eq!(l.updated.as_deref(), Some("2026-11-06T22:33:18Z"));
    assert_eq!(
        AddressList::parse("0xaa00000000000000000000000000000000000001\n", "x").updated,
        None
    );
}

/// An offer may ask for a long `maxTimeoutSeconds`, but a ledger claim lives 600 s at most. A payment valid
/// for longer than a claim would be forgotten while its authorization is still good, so it is refused.
#[test]
fn a_payment_never_outlives_the_claim_that_remembers_it() {
    let now = 1_800_000_000_u64;
    let pay_to = "0x000000000000000000000000000000000000dEaD";
    let asset = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
    let offer = |timeout: u64| {
        json!({
            "scheme": "exact", "network": "eip155:84532", "amount": "10000", "asset": asset,
            "payTo": pay_to, "maxTimeoutSeconds": timeout,
            "extra": { "name": "USDC", "version": "2" }
        })
    };
    let payment = |valid_before: u64| {
        json!({
            "x402Version": 2,
            "accepted": { "scheme": "exact", "network": "eip155:84532", "amount": "10000", "asset": asset, "payTo": pay_to },
            "payload": {
                "signature": format!("0x{}", "11".repeat(65)),
                "authorization": {
                    "from": "0x0000000000000000000000000000000000000001", "to": pay_to, "value": "10000",
                    "validAfter": "0", "validBefore": valid_before.to_string(),
                    "nonce": format!("0x{}", "22".repeat(32)),
                }
            }
        })
    };
    let too_long = |timeout: u64, valid_before: u64| {
        evm_exact::verify(&payment(valid_before), &offer(timeout), now) == Err(Reason::ValidBefore)
    };
    // The default offer (300 s + 60 s of skew) is as before: the limit is 360 s.
    assert!(!too_long(300, now + 360));
    assert!(too_long(300, now + 361));
    // A long offer is held to the claim's life (600 s = 540 s + 60 s of skew), not to its own timeout.
    assert!(!too_long(3600, now + 600));
    assert!(too_long(3600, now + 601));
}

/// The decoder takes a header of exactly the limit and nothing longer, whatever it holds.
#[test]
fn a_payment_header_has_a_size_limit() {
    // base64 of n bytes is 4 * ceil(n / 3) characters: 49152 bytes fill the limit exactly.
    let json_of = |bytes: usize| format!("{{\"p\":\"{}\"}}", "x".repeat(bytes - 8));
    let at_limit = headers::base64(json_of(49_152).as_bytes());
    assert_eq!(at_limit.len(), headers::MAX_PAYMENT_HEADER);
    assert!(headers::decode(&at_limit).is_some());
    let over = headers::base64(json_of(49_155).as_bytes());
    assert_eq!(over.len(), headers::MAX_PAYMENT_HEADER + 4);
    assert!(headers::decode(&over).is_none());
}

/// A list an editor saved with a byte order mark, or one that writes `0X…` or the bare digits, still denies:
/// an entry that silently matches nothing is worse than none, because the operator believes it is there.
#[test]
fn a_list_entry_matches_in_any_spelling_of_the_address() {
    let payer = "0xAbCdEf0123456789aBcDeF0123456789AbCdEf01";
    let list = AddressList::parse(
        "\u{feff}# updated: 2026-11-06T10:00:00Z\n0XABCDEF0123456789ABCDEF0123456789ABCDEF01 first\n\
         abcdef0123456789abcdef0123456789abcdef02\n\u{feff}0xabcdef0123456789abcdef0123456789abcdef03\n",
        "denied",
    );
    assert!(list.contains(payer));
    assert!(list.contains("0xabcdef0123456789abcdef0123456789abcdef02"));
    assert!(list.contains("0xAbCdEf0123456789aBcDeF0123456789AbCdEf03"));
    assert!(!list.contains("0xabcdef0123456789abcdef0123456789abcdef04"));
    // All three entries are kept in the one canonical spelling, and the BOM did not hide the date line.
    assert_eq!(list.addresses().len(), 3);
    assert!(list.addresses().iter().all(|a| field::is(Rule::Address, a)));
    assert_eq!(list.updated.as_deref(), Some("2026-11-06T10:00:00Z"));
    // Entries that are not EVM addresses are kept as written.
    let other = AddressList::parse("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\n", "denied");
    assert!(other.contains("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"));
}

/// Only an EVM address (exactly 40 hex digits) gets the canonical spelling. Anything else matches only as
/// written: a short hex string is not an address with its `0x` left out, and 40 characters that are not
/// all hex do not become one by changing their case.
#[test]
fn a_list_entry_that_is_not_an_evm_address_matches_only_as_written() {
    let short = AddressList::parse("abc123\n", "denied");
    assert!(short.contains("abc123"));
    assert!(!short.contains("0xabc123"));
    assert!(!short.contains("ABC123"));

    let not_hex = "zzcdef0123456789abcdef0123456789abcdef01";
    assert_eq!(not_hex.len(), 40);
    let list = AddressList::parse(&format!("{not_hex}\n"), "denied");
    assert!(list.contains(not_hex));
    assert!(!list.contains(&not_hex.to_ascii_uppercase()));
    assert!(!list.contains(&format!("0x{not_hex}")));
}
