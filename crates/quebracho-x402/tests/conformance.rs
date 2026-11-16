//! Conformance against the PHP library: every expected value comes from `conformance/vectors/`,
//! exported by `conformance/export.sh` from quebracho/x402. Nothing here is a hand-typed hash.

use k256::ecdsa::SigningKey;
use quebracho_x402::eip712::{self, Domain, TransferWithAuthorization};
use quebracho_x402::field::{self, Rule};
use quebracho_x402::{evm_exact, keccak256, signer};
use serde_json::Value;

fn cases(json: &str) -> Vec<Value> {
    let doc: Value = serde_json::from_str(json).expect("vector file is JSON");
    doc["cases"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| vec![doc["cases"].clone()])
}

fn hex32(s: &str) -> [u8; 32] {
    let v = hex_bytes(s);
    v.try_into().expect("32 bytes")
}

fn hex_bytes(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn lower_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn keccak_matches_php() {
    for c in cases(include_str!("../../../conformance/vectors/keccak.json")) {
        let got = format!(
            "0x{}",
            lower_hex(&keccak256(c["input"].as_str().unwrap().as_bytes()))
        );
        assert_eq!(got, c["hash"], "keccak({:?})", c["input"]);
    }
}

#[test]
fn type_strings_hash_as_in_php() {
    let by_input = |s: &str| {
        cases(include_str!("../../../conformance/vectors/keccak.json"))
            .into_iter()
            .find(|c| c["input"] == s)
            .unwrap_or_else(|| panic!("no vector for {s}"))["hash"]
            .clone()
    };
    for t in [
        eip712::DOMAIN_TYPE,
        eip712::TRANSFER_WITH_AUTHORIZATION_TYPE,
    ] {
        assert_eq!(
            format!("0x{}", lower_hex(&keccak256(t.as_bytes()))),
            by_input(t)
        );
    }
}

#[test]
fn field_spellings_match_php() {
    let mut n = 0;
    for c in cases(include_str!("../../../conformance/vectors/field.json")) {
        let rule = Rule::from_name(c["rule"].as_str().unwrap()).expect("known rule");
        let value = c["value"].as_str().unwrap();
        assert_eq!(
            field::is(rule, value),
            c["ok"].as_bool().unwrap(),
            "{rule:?} {value:?}"
        );
        n += 1;
    }
    assert!(n > 60);
}

#[test]
fn addresses_and_checksums_match_php() {
    let doc = &cases(include_str!("../../../conformance/vectors/signer.json"))[0];
    for c in doc["keys"].as_array().unwrap() {
        let key = SigningKey::from_slice(&hex_bytes(c["test_signer"].as_str().unwrap())).unwrap();
        assert_eq!(
            signer::checksum(&signer::address_of(key.verifying_key())),
            c["address"]
        );
    }
    for c in doc["checksum"].as_array().unwrap() {
        let addr = signer::parse_address(c["input"].as_str().unwrap()).unwrap();
        assert_eq!(signer::checksum(&addr), c["checksum"]);
    }
}

#[test]
fn eip3009_digests_match_php() {
    for c in cases(include_str!("../../../conformance/vectors/digest.json")) {
        let (req, auth) = (&c["req"], &c["authorization"]);
        let network = req["network"].as_str().unwrap();
        let domain = Domain {
            name: req["extra"]["name"].as_str().unwrap(),
            version: req["extra"]["version"].as_str().unwrap(),
            chain_id: network.strip_prefix("eip155:").unwrap().parse().unwrap(),
            verifying_contract: signer::parse_address(req["asset"].as_str().unwrap()).unwrap(),
        };
        let s = |k: &str| auth[k].as_str().unwrap();
        let message = TransferWithAuthorization {
            from: signer::parse_address(s("from")).unwrap(),
            to: signer::parse_address(s("to")).unwrap(),
            value: eip712::uint256(s("value")).unwrap(),
            valid_after: eip712::uint256(s("validAfter")).unwrap(),
            valid_before: eip712::uint256(s("validBefore")).unwrap(),
            nonce: hex32(s("nonce")),
        };
        let digest = eip712::digest(&domain, &message);
        assert_eq!(
            format!("0x{}", lower_hex(&digest)),
            c["digest"],
            "{}",
            c["name"]
        );
        let who = signer::recover_hex(&digest, c["signature"].as_str().unwrap()).expect("recovers");
        assert_eq!(signer::checksum(&who), c["signer"], "{}", c["name"]);
    }
}

#[test]
fn uint256_rejects_more_than_256_bits() {
    let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    assert_eq!(eip712::uint256(max), Some([0xff; 32]));
    assert_eq!(
        eip712::uint256(
            "115792089237316195423570985008687907853269984665640564039457584007913129639936"
        ),
        None
    );
    assert_eq!(eip712::uint256(""), None);
}

#[test]
fn ecrecover_matches_php() {
    for c in cases(include_str!("../../../conformance/vectors/recover.json")) {
        let got = signer::recover_hex(
            &hex32(c["digest"].as_str().unwrap()),
            c["signature"].as_str().unwrap(),
        );
        let got = got
            .map(|a| Value::String(signer::checksum(&a)))
            .unwrap_or(Value::Null);
        assert_eq!(got, c["address"], "{}", c["name"]);
    }
}

#[test]
fn evm_exact_reasons_match_php() {
    let mut n = 0;
    for c in cases(include_str!("../../../conformance/vectors/evm_exact.json")) {
        let got = evm_exact::verify(&c["payment"], &c["req"], c["now"].as_u64().unwrap());
        let got = got
            .err()
            .map(|r| Value::String(r.as_str().into()))
            .unwrap_or(Value::Null);
        assert_eq!(got, c["reason"], "{}", c["name"]);
        n += 1;
    }
    assert!(n > 40);
}
