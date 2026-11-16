//! The small rules that no PHP vector reaches: unknown names, malformed dates, broken snapshots.

use quebracho_x402::field::{self, Rule};
use quebracho_x402::http_facilitator::check_settle;
use quebracho_x402::ports::{AddressListener, Clock, HttpsResponse};
use quebracho_x402::screening::{self, AddressList, Ofac};
use quebracho_x402::{dates, signer};
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
