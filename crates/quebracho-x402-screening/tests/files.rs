//! `Lists::from_files`: an absent file is empty, an unreadable one refuses everyone (feature `std`).
#![cfg(feature = "std")]

use quebracho_x402::ports::AddressListener;
use quebracho_x402_screening::Lists;
use serde_json::json;

#[test]
fn absent_is_empty_unreadable_refuses_everyone() {
    let dir = std::env::temp_dir().join(format!("x402-lists-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let deny = dir.join("deny.txt");
    std::fs::write(&deny, "0x000000000000000000000000000000000000bEEF\n").unwrap();
    let lists = Lists::from_files(&dir.join("absent.txt"), &deny);
    let ask = |l: &Lists, a: &str| l.check("payer", "eip155:84532", a, &json!({}));
    assert_eq!(
        ask(&lists, "0x000000000000000000000000000000000000beef"),
        Ok(Some("address_denied".into()))
    );
    assert_eq!(
        ask(&lists, "0x000000000000000000000000000000000000dEaD"),
        Ok(None)
    );
    // A directory where a file should be cannot be read as a list.
    let broken = Lists::from_files(&dir, &deny);
    assert!(ask(&broken, "0x000000000000000000000000000000000000dEaD").is_err());
    let _ = std::fs::remove_dir_all(dir);
}
