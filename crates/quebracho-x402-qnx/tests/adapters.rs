use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use quebracho_x402::ports::{Ledger, Pause};
use quebracho_x402::screening::Ofac;
use quebracho_x402::seller::{Request, Response, Seller};
use quebracho_x402::settlement::MockFacilitator;
use quebracho_x402_qnx::{FileLedger, StopFile, SystemClock};
use serde_json::{Value, json};

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("x402-qnx-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Threat T1: of many concurrent claims of one key (separate ledger handles, as separate processes would
/// have), exactly one wins.
#[test]
fn one_of_many_concurrent_claims_wins() {
    let dir = temp("race");
    let wins = Arc::new(AtomicUsize::new(0));
    let threads: Vec<_> = (0..16)
        .map(|_| {
            let (dir, wins) = (dir.clone(), wins.clone());
            std::thread::spawn(move || {
                if FileLedger::new(dir).claim("same-payment", 600).unwrap() {
                    wins.fetch_add(1, Ordering::SeqCst);
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(wins.load(Ordering::SeqCst), 1);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn states_expire_and_release_frees_them() {
    let dir = temp("states");
    let l = FileLedger::new(&dir);
    assert!(l.claim("k", 600).unwrap());
    assert_eq!(l.get("k").unwrap(), Some(json!({ "status": "claimed" })));
    l.put("k", &json!({ "status": "settled" }), 600).unwrap();
    assert!(
        !l.claim("k", 600).unwrap(),
        "a live state blocks a new claim"
    );
    l.release("k").unwrap();
    assert_eq!(l.get("k").unwrap(), None);
    assert!(l.claim("k", 600).unwrap(), "released: good again");
    // An expired state reads as absent and can be claimed again.
    l.put("old", &json!({ "status": "settled" }), 0).unwrap();
    assert_eq!(l.get("old").unwrap(), None);
    assert!(l.claim("old", 600).unwrap());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn open_entries_keep_their_first_opened_time() {
    let dir = temp("open");
    let l = FileLedger::new(&dir);
    l.open("k", &json!({ "status": "settling", "opened": 1234 }), 600)
        .unwrap();
    l.open("k", &json!({ "status": "pending", "opened": 9999 }), 600)
        .unwrap();
    let open = l.open_keys(10).unwrap();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].0, "k");
    assert_eq!(open[0].1["opened"], 1234);
    assert_eq!(open[0].1["status"], "pending");
    l.close("k").unwrap();
    assert!(l.open_keys(10).unwrap().is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn files_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp("perms");
    let l = FileLedger::new(&dir);
    l.claim("k", 600).unwrap();
    assert_eq!(
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for e in std::fs::read_dir(&dir).unwrap().flatten() {
        assert_eq!(
            e.metadata().unwrap().permissions().mode() & 0o077,
            0,
            "{:?} readable by others",
            e.path()
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn the_stop_switch_engages_and_fails_toward_stopped() {
    let dir = temp("stop");
    let stop = StopFile::new(dir.join("x402.stop")).unwrap();
    assert!(!stop.engaged());
    stop.engage("suspected key leak").unwrap();
    assert!(stop.engaged());
    assert_eq!(stop.note().as_deref(), Some("suspected key leak"));
    stop.release().unwrap();
    assert!(!stop.engaged());
    // A directory at the path counts as engaged.
    std::fs::create_dir_all(dir.join("x402.stop")).unwrap();
    assert!(stop.engaged());
    assert!(StopFile::new("relative/stop").is_err());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_clock_before_its_floor_is_not_trusted() {
    use quebracho_x402::ports::Clock;
    assert!(SystemClock::new(1_700_000_000).reliable());
    assert!(!SystemClock::new(u64::MAX).reliable());
    assert!(!SystemClock::new(0).with_check(|| false).reliable());
}

/// The seller over the file ledger, end to end with a PHP-exported payment: delivered once, replayed after,
/// even by a second seller process sharing the directory.
#[test]
fn the_seller_over_files_delivers_once_and_replays() {
    let doc: Value =
        serde_json::from_str(include_str!("../../../conformance/vectors/sale.json")).unwrap();
    let case = doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "paid: delivered once, the retry is replayed")
        .unwrap();
    let offers = case["offers"].as_array().unwrap().clone();
    let header = case["steps"][0]["step"]["header"].as_str().unwrap();
    let dir = temp("seller");
    struct Pinned;
    impl quebracho_x402::ports::Clock for Pinned {
        fn now(&self) -> u64 {
            1_800_000_000
        }
    }
    let ofac = Ofac::off();
    let runs = AtomicUsize::new(0);
    for _ in 0..2 {
        let ledger = FileLedger::new(&dir); // a fresh handle each time, as another process would have
        let seller = Seller {
            ledger: &ledger,
            facilitator: &MockFacilitator,
            clock: &Pinned,
            ofac: &ofac,
            listeners: &[],
            events: None,
            lookup: None,
            stop: None,
        };
        let r = seller
            .process(
                &Request {
                    accepts: Some(&offers),
                    resource: &case["resource"],
                    payment: Some(header),
                    keep: true,
                },
                || {
                    runs.fetch_add(1, Ordering::SeqCst);
                    Ok(Response::new(200, "21.5"))
                },
            )
            .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"21.5");
        assert!(r.header("PAYMENT-RESPONSE").is_some());
    }
    assert_eq!(
        runs.load(Ordering::SeqCst),
        1,
        "the second request is a replay"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Writes a ledger for the PHP `FileLedger` to read (`X402_INTEROP_DIR`); run by hand, see conformance/README.md.
#[test]
#[ignore]
fn write_a_ledger_for_php() {
    let dir = std::env::var("X402_INTEROP_DIR").expect("X402_INTEROP_DIR");
    let l = FileLedger::new(dir);
    l.put(
        "written-by-rust",
        &json!({ "status": "delivered", "receipt": { "success": true } }),
        600,
    )
    .unwrap();
    l.open("written-by-rust", &json!({ "status": "settling" }), 600)
        .unwrap();
}

/// Audit M2: a state file that cannot be read is not "absent". Admitting the payment again would sell it
/// twice; the ledger answers unavailable instead (nothing is charged, 503).
#[test]
fn an_unreadable_state_is_unavailable_not_absent() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp("unreadable");
    let l = FileLedger::new(&dir);
    assert!(l.claim("k", 600).unwrap());
    let file = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "json"))
        .unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read(&file).is_ok() {
        // Running as root: permissions do not stop reads, so this case cannot be staged.
        let _ = std::fs::remove_dir_all(dir);
        return;
    }
    assert!(l.get("k").is_err(), "get must not say absent");
    assert!(l.claim("k", 600).is_err(), "a second claim must not win");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    // A corrupt file (not what this ledger writes) is held, never absent.
    std::fs::write(&file, b"{not json").unwrap();
    assert!(l.get("k").is_err());
    assert!(l.claim("k", 600).is_err());
    // prune leaves what it cannot read.
    assert_eq!(l.prune().unwrap(), 0);
    assert!(file.exists());
    let _ = std::fs::remove_dir_all(dir);
}
