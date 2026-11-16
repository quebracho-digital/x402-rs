//! Wall time for the core's [`Clock`] port.
//!
//! Fail closed (threat T6 in `docs/THREATS.md`): a clock that reads before `trusted_after` (for example the build date,
//! or the last time recorded on disk) is not trusted, so a device that booted without RTC or NTP and
//! thinks it is 1970 admits no payment. Whether time is synchronized (NTP, PTP) is the platform's to say:
//! pass a check with [`SystemClock::with_check`].

use std::time::{SystemTime, UNIX_EPOCH};

use quebracho_x402::ports::Clock;

pub struct SystemClock {
    trusted_after: u64,
    check: Option<Box<dyn Fn() -> bool + Send + Sync>>,
}

impl SystemClock {
    /// A clock trusted once it reads after `trusted_after` (Unix seconds).
    pub fn new(trusted_after: u64) -> Self {
        Self {
            trusted_after,
            check: None,
        }
    }

    /// Adds a platform check (e.g. "NTP says synchronized"); both must pass.
    pub fn with_check(mut self, check: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        self.check = Some(Box::new(check));
        self
    }
}

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    fn reliable(&self) -> bool {
        self.now() > self.trusted_after && self.check.as_ref().is_none_or(|c| c())
    }
}
