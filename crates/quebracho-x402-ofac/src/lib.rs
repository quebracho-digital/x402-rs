//! OFAC's SDN list, as shipped (port of `resources/ofac-sdn.json` of the PHP library).
//!
//! The copy here is the PHP library's, refreshed with it. **Keeping the list fresh is the device's job**:
//! OFAC updates it a few times a week. A device syncs its own copy and passes both to
//! [`Ofac::younger`], so the younger one is used and a lagging copy can never roll the list back.

#![no_std]

use quebracho_x402::screening::Ofac;

/// The shipped snapshot, as JSON (`{"source", "published", "addresses": {currency: [address]}}`).
pub const SNAPSHOT: &str = include_str!("../ofac-sdn.json");

/// The shipped list. Screening is on by default: a seller or buyer starts from this.
pub fn bundled() -> Ofac {
    Ofac::from_snapshot(SNAPSHOT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_list_reads_and_refuses_a_listed_address() {
        let ofac = bundled();
        assert!(
            matches!(ofac, Ofac::List { .. }),
            "shipped snapshot must parse"
        );
        // Listed in the snapshot as "0x0330070FD38Ec3bB94F58FA55D40368271E9e54A": matched in any case.
        assert!(SNAPSHOT.contains("0x0330070FD38Ec3bB94F58FA55D40368271E9e54A"));
        assert_eq!(
            ofac.reason("0x0330070fd38ec3bb94f58fa55d40368271e9e54a"),
            Some("address_sanctioned")
        );
        assert_eq!(
            ofac.reason("0x000000000000000000000000000000000000dEaD"),
            None
        );
        assert!(ofac.published().is_some_and(|p| p.starts_with("20")));
    }

    #[test]
    fn a_younger_own_copy_wins_and_an_older_one_does_not() {
        let own = |date: &str| Ofac::from_snapshot(alloc_free_json(date));
        assert_eq!(
            bundled().younger(own("2999-01-01T00:00:00Z")).published(),
            Some("2999-01-01T00:00:00Z")
        );
        assert_eq!(
            bundled().younger(own("2000-01-01T00:00:00Z")).published(),
            bundled().published()
        );
        // A broken own copy never replaces a readable list.
        assert_eq!(
            bundled()
                .younger(Ofac::from_snapshot("not json"))
                .published(),
            bundled().published()
        );
    }

    fn alloc_free_json(date: &str) -> &'static str {
        match date {
            "2999-01-01T00:00:00Z" => r#"{"published":"2999-01-01T00:00:00Z","addresses":{}}"#,
            _ => r#"{"published":"2000-01-01T00:00:00Z","addresses":{}}"#,
        }
    }
}
