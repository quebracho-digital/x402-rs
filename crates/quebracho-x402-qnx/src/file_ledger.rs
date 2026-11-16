//! The payment ledger in files (port of `FileLedger.php`), one host.
//!
//! Same layout as PHP, so either side reads the other's directory: one `<sha256(key)>.json` file per key
//! holding `{"expires": unix, "state": {...}}`, one `<sha256(key)>.open` per open entry holding
//! `{"expires", "key", "ref"}`, and a `.lock` file. Claims take an exclusive lock on `.lock`, so of N
//! concurrent claims in any number of processes exactly one wins. Every write goes to a temporary file,
//! is `fsync`ed, then renamed over the old one: a reader never sees half a file and a crash leaves the old
//! state or the new one. Directory and files are created `0700`/`0600`.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use quebracho_x402::ports::{Ledger, LedgerUnavailable};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub struct FileLedger {
    dir: PathBuf,
}

static TMP: AtomicU64 = AtomicU64::new(0);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl FileLedger {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Deletes expired states; returns how many.
    pub fn prune(&self) -> Result<usize, LedgerUnavailable> {
        let mut n = 0;
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return Ok(0);
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "json") && read_state(&p).is_none() {
                remove(&p)?;
                n += 1;
            }
        }
        Ok(n)
    }

    fn path(&self, key: &str, extension: &str) -> PathBuf {
        let hash: String = Sha256::digest(key.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        self.dir.join(format!("{hash}.{extension}"))
    }

    fn ensure_dir(&self) -> Result<(), LedgerUnavailable> {
        if self.dir.is_dir() {
            return Ok(());
        }
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .map_err(|_| LedgerUnavailable)
    }

    /// Writes through a synced temporary file and a rename.
    fn write(&self, file: &Path, content: &[u8]) -> Result<(), LedgerUnavailable> {
        self.ensure_dir()?;
        let tmp = self.dir.join(format!(
            ".put-{}-{}",
            std::process::id(),
            TMP.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(content)?;
            f.sync_all()?;
            fs::rename(&tmp, file)?;
            // The rename itself is durable once the directory is synced.
            File::open(&self.dir)?.sync_all()
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
            return Err(LedgerUnavailable);
        }
        Ok(())
    }

    fn lock(&self) -> Result<File, LedgerUnavailable> {
        self.ensure_dir()?;
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(self.dir.join(".lock"))
            .map_err(|_| LedgerUnavailable)?;
        f.lock().map_err(|_| LedgerUnavailable)?;
        Ok(f)
    }

    fn encode(state: &Value, ttl: u64) -> Vec<u8> {
        serde_json::to_vec(&json!({ "expires": now() + ttl, "state": state })).unwrap_or_default()
    }
}

/// Deletes a file; one already gone is not an error.
fn remove(file: &Path) -> Result<(), LedgerUnavailable> {
    match fs::remove_file(file) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(_) => Err(LedgerUnavailable),
    }
}

/// A live state, or `None` (absent, unreadable or expired).
fn read_state(file: &Path) -> Option<Value> {
    let data: Value = serde_json::from_slice(&fs::read(file).ok()?).ok()?;
    let expires = data.get("expires")?.as_u64()?;
    let state = data
        .get("state")
        .filter(|s| s.is_object() || s.is_array())?;
    (expires > now()).then(|| state.clone())
}

/// A live open entry: its key and reference.
fn read_open(file: &Path) -> Option<(String, Value)> {
    let data: Value = serde_json::from_slice(&fs::read(file).ok()?).ok()?;
    let expires = data.get("expires")?.as_u64()?;
    let key = data.get("key")?.as_str()?.to_string();
    let reference = data
        .get("ref")
        .filter(|r| r.is_object() || r.is_array())?
        .clone();
    (expires > now()).then_some((key, reference))
}

impl Ledger for FileLedger {
    fn claim(&self, key: &str, ttl: u64) -> Result<bool, LedgerUnavailable> {
        let lock = self.lock()?;
        let file = self.path(key, "json");
        let out = if read_state(&file).is_some() {
            Ok(false)
        } else {
            // Absent or expired: the lock keeps other claims out, so the rename is the claim.
            self.write(&file, &Self::encode(&json!({ "status": "claimed" }), ttl))
                .map(|()| true)
        };
        drop(lock);
        out
    }

    fn get(&self, key: &str) -> Result<Option<Value>, LedgerUnavailable> {
        Ok(read_state(&self.path(key, "json")))
    }

    fn put(&self, key: &str, state: &Value, ttl: u64) -> Result<(), LedgerUnavailable> {
        self.write(&self.path(key, "json"), &Self::encode(state, ttl))
    }

    fn release(&self, key: &str) -> Result<(), LedgerUnavailable> {
        remove(&self.path(key, "json"))?;
        self.close(key)
    }

    fn open(&self, key: &str, reference: &Value, ttl: u64) -> Result<(), LedgerUnavailable> {
        let file = self.path(key, "open");
        let mut reference = reference.clone();
        let opened = read_open(&file)
            .and_then(|(_, r)| r.get("opened").cloned())
            .or_else(|| reference.get("opened").filter(|o| o.is_u64()).cloned())
            .unwrap_or_else(|| json!(now()));
        if let Value::Object(m) = &mut reference {
            m.insert("opened".into(), opened);
        }
        self.write(
            &file,
            &serde_json::to_vec(&json!({ "expires": now() + ttl, "key": key, "ref": reference }))
                .unwrap_or_default(),
        )
    }

    fn open_keys(&self, limit: usize) -> Result<Vec<(String, Value)>, LedgerUnavailable> {
        let mut out = Vec::new();
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return Ok(out);
        };
        for e in entries.flatten() {
            if out.len() >= limit {
                break;
            }
            let p = e.path();
            if p.extension().is_none_or(|x| x != "open") {
                continue;
            }
            match read_open(&p) {
                Some(entry) => out.push(entry),
                None => remove(&p)?,
            }
        }
        Ok(out)
    }

    fn close(&self, key: &str) -> Result<(), LedgerUnavailable> {
        remove(&self.path(key, "open"))
    }
}
