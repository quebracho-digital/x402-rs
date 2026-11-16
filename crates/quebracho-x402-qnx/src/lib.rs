//! Platform adapters for `quebracho-x402`: the ports implemented with the standard library.
//!
//! Plain POSIX through `std` (files, `rename`, `fsync`, file locks), so the same code is developed and
//! tested on Linux and built for QNX 8.0 (`aarch64-unknown-qnx`, `x86_64-pc-qnx`). Whether every call
//! behaves on QNX is part of the viability test (`planning/PLAN.md` §10), not assumed here.
//!
//! - [`FileLedger`]: the payment ledger in files, the same layout as PHP's `FileLedger`.
//! - [`StopFile`]: the stop switch.
//! - [`SystemClock`]: wall time, with an optional floor below which it is not trusted.
//! - [`ofac`]: OFAC's list from the shipped copy or a synced file, whichever is younger.

mod clock;
mod file_ledger;
pub mod ofac;
mod stop;

pub use clock::SystemClock;
pub use file_ledger::FileLedger;
pub use stop::StopFile;
