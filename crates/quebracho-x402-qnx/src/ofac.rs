//! OFAC's list on a device: the shipped copy, or the device's own synced file when it is younger.
//!
//! Syncing (downloading `SDN.CSV` from OFAC) needs HTTPS and is the job of the device's own updater; this
//! only reads what it wrote.

use std::path::Path;

use quebracho_x402::screening::Ofac;

/// The list in use: the younger of the shipped copy and the snapshot at `own` (if any). A missing own file
/// is the shipped list; an unreadable own file never replaces it.
pub fn load(own: Option<&Path>) -> Ofac {
    let shipped = quebracho_x402_screening::ofac::bundled();
    match own.map(std::fs::read_to_string) {
        Some(Ok(text)) => shipped.younger(Ofac::from_snapshot(&text)),
        _ => shipped,
    }
}
