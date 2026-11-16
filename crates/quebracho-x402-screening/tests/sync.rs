//! Downloading and keeping the lists: redirects, refusals, dates, and writing the file.

use std::cell::RefCell;

use quebracho_x402::ports::{
    AddressListener, Https, HttpsRequest, HttpsResponse, HttpsUnavailable,
};
use quebracho_x402_screening::chainalysis::{Api, NoKey};
use quebracho_x402_screening::{TokenBlacklist, sync};
use serde_json::{Value, json};

/// Answers in order; records the URLs asked.
struct Script(
    RefCell<Vec<Result<HttpsResponse, HttpsUnavailable>>>,
    RefCell<Vec<String>>,
);
impl Script {
    fn new(answers: Vec<Result<HttpsResponse, HttpsUnavailable>>) -> Self {
        Self(RefCell::new(answers), RefCell::default())
    }
}
impl Https for Script {
    fn send(&self, r: &HttpsRequest) -> Result<HttpsResponse, HttpsUnavailable> {
        self.1.borrow_mut().push(r.url.clone());
        let mut a = self.0.borrow_mut();
        if a.is_empty() {
            Err(HttpsUnavailable)
        } else {
            a.remove(0)
        }
    }
}
fn answer(
    status: u16,
    headers: &[(&str, &str)],
    body: &str,
) -> Result<HttpsResponse, HttpsUnavailable> {
    Ok(HttpsResponse {
        status,
        headers: headers
            .iter()
            .map(|(n, v)| ((*n).into(), (*v).into()))
            .collect(),
        body: body.as_bytes().to_vec(),
    })
}

fn sdn_csv(n: usize) -> String {
    (1..=n).map(|i| format!("{i},\"X\",-0- ,\"CYBER2\",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,\"Digital Currency Address - ETH 0x{i:040x}\"\n")).collect()
}

#[test]
fn ofac_follows_its_redirect_and_dates_the_list_by_last_modified() {
    let https = Script::new(vec![
        answer(
            302,
            &[("Location", "https://download.example/SDN.CSV?sig=1")],
            "",
        ),
        answer(
            200,
            &[("Last-Modified", "Fri, 13 Nov 2026 16:33:06 GMT")],
            &sdn_csv(150),
        ),
    ]);
    let r = sync::ofac(&https, 0, None).unwrap();
    assert_eq!(
        (r.count, r.updated.as_str(), r.replaced()),
        (150, "2026-11-13T16:33:06Z", true)
    );
    assert_eq!(
        *https.1.borrow(),
        vec![
            sync::OFAC_URL.to_string(),
            "https://download.example/SDN.CSV?sig=1".to_string()
        ]
    );
}

#[test]
fn ofac_without_last_modified_is_dated_now() {
    let https = Script::new(vec![answer(200, &[], &sdn_csv(150))]);
    assert_eq!(
        sync::ofac(&https, 1_800_000_000, None).unwrap().updated,
        "2027-01-15T08:00:00Z"
    );
}

#[test]
fn ofac_refuses_errors_too_many_redirects_and_short_lists() {
    assert!(sync::ofac(&Script::new(vec![answer(503, &[], "down")]), 0, None).is_err());
    assert!(
        sync::ofac(&Script::new(vec![]), 0, None).is_err(),
        "unreachable"
    );
    let hop = || answer(302, &[("Location", "https://download.example/next")], "");
    assert!(
        sync::ofac(
            &Script::new(vec![
                hop(),
                hop(),
                hop(),
                hop(),
                answer(200, &[], &sdn_csv(150))
            ]),
            0,
            None
        )
        .is_err(),
        "4 redirects"
    );
    assert!(
        sync::ofac(&Script::new(vec![answer(200, &[], &sdn_csv(3))]), 0, None).is_err(),
        "3 addresses"
    );
}

#[test]
fn a_list_sync_refuses_errors_and_keeps_a_younger_copy() {
    let url = "https://lists.example.org/denied.txt";
    assert!(sync::list(&Script::new(vec![answer(404, &[], "")]), url, 1, 0, None).is_err());
    assert!(
        sync::list(
            &Script::new(vec![answer(200, &[], "# nothing\n")]),
            url,
            1,
            0,
            None
        )
        .is_err(),
        "too few"
    );
    let current = "# updated: 2026-12-01T00:00:00Z\n0xaa00000000000000000000000000000000000001\n0xaa00000000000000000000000000000000000002\n";
    let kept = sync::list(
        &Script::new(vec![answer(
            200,
            &[],
            "# updated: 2026-11-01T00:00:00Z\n0xbb00000000000000000000000000000000000001\n",
        )]),
        url,
        1,
        0,
        Some(current),
    )
    .unwrap();
    assert_eq!(
        (kept.replaced(), kept.count, kept.updated.as_str()),
        (false, 2, "2026-12-01T00:00:00Z")
    );
    // No date in the list: Last-Modified.
    let dated = sync::list(
        &Script::new(vec![answer(
            200,
            &[("Last-Modified", "Sun, 01 Nov 2026 00:00:00 GMT")],
            "0xbb00000000000000000000000000000000000001\n",
        )]),
        url,
        1,
        0,
        None,
    )
    .unwrap();
    assert_eq!(dated.updated, "2026-11-01T00:00:00Z");
}

#[cfg(feature = "std")]
#[test]
fn write_replaces_atomically_and_only_when_replaced() {
    let dir = std::env::temp_dir().join(format!("x402-sync-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("ofac.json");
    let new = sync::SyncResult {
        count: 1,
        updated: "x".into(),
        content: Some("fresh\n".into()),
    };
    sync::write(&file, &new).unwrap();
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "fresh\n");
    sync::write(
        &file,
        &sync::SyncResult {
            count: 1,
            updated: "x".into(),
            content: None,
        },
    )
    .unwrap();
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        "fresh\n",
        "a kept copy is not touched"
    );
    // A file in a directory that does not exist: an error, and no temporary file left behind.
    assert!(sync::write(&dir.join("missing").join("ofac.json"), &new).is_err());
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn token_blacklist_edges() {
    let req = |network: &str, asset: &str| json!({ "network": network, "asset": asset });
    let payer = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23";
    // USDC on Polygon is known, but the network has no default node: not asked (audit L4, as PHP).
    let silent = Script::new(vec![]);
    let l = TokenBlacklist::new(&silent);
    assert_eq!(
        l.check(
            "payer",
            "eip155:137",
            payer,
            &req("eip155:137", "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359")
        ),
        Ok(None)
    );
    assert!(silent.1.borrow().is_empty());
    // With a node given, it is asked.
    let asked = Script::new(vec![answer(
        200,
        &[],
        &json!({ "jsonrpc": "2.0", "id": 1, "result": format!("0x{:064x}", 1) }).to_string(),
    )]);
    let l = TokenBlacklist::new(&asked).rpc("eip155:137", "https://polygon.example/rpc");
    assert_eq!(
        l.check(
            "payer",
            "eip155:137",
            payer,
            &req("eip155:137", "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359")
        ),
        Ok(Some("address_blacklisted".into()))
    );
    assert_eq!(
        *asked.1.borrow(),
        vec!["https://polygon.example/rpc".to_string()]
    );
    // A token added on a non-EVM network is never asked; an unknown function name is refused.
    let l = TokenBlacklist::new(&silent)
        .token("solana:devnet", "Mint", "isBlacklisted")
        .unwrap();
    assert_eq!(
        l.check(
            "payer",
            "solana:devnet",
            "Abc",
            &req("solana:devnet", "Mint")
        ),
        Ok(None)
    );
    assert!(
        TokenBlacklist::new(&silent)
            .token("eip155:1", "0x1", "nope")
            .is_err()
    );
    let _ = Value::Null;
}

#[test]
fn the_api_needs_a_key() {
    let https = Script::new(vec![]);
    assert!(matches!(Api::new(&https, ""), Err(NoKey)));
}

/// Boundaries: exactly the minimum is a list; a copy of the same date is replaced (only a younger one is
/// kept), as in PHP.
#[test]
fn sync_boundaries() {
    assert_eq!(
        sync::ofac_snapshot(
            &sdn_csv(sync::OFAC_MIN_ADDRESSES),
            "2026-11-10T00:00:00Z",
            None
        )
        .unwrap()
        .count,
        100
    );
    assert!(
        sync::ofac_snapshot(
            &sdn_csv(sync::OFAC_MIN_ADDRESSES - 1),
            "2026-11-10T00:00:00Z",
            None
        )
        .is_err()
    );
    let first = sync::ofac_snapshot(&sdn_csv(120), "2026-11-10T00:00:00Z", None)
        .unwrap()
        .content
        .unwrap();
    assert!(
        sync::ofac_snapshot(&sdn_csv(130), "2026-11-10T00:00:00Z", Some(&first))
            .unwrap()
            .replaced(),
        "same date: replaced"
    );
    let url = "https://lists.example.org/denied.txt";
    let current = "# updated: 2026-11-01T00:00:00Z\n0xaa00000000000000000000000000000000000001\n";
    let same = Script::new(vec![answer(
        200,
        &[],
        "# updated: 2026-11-01T00:00:00Z\n0xbb00000000000000000000000000000000000001\n",
    )]);
    assert!(
        sync::list(&same, url, 1, 0, Some(current))
            .unwrap()
            .replaced(),
        "same date: replaced"
    );
}
