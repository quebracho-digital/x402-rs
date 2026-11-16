//! Keeping the lists fresh (port of `OfacSdn::sync/write/parse` and `AddressList::sync`): download over the
//! core's [`Https`] port, check the result looks like a real list, and replace the copy only when the new
//! one is not older. On any failure the old copy stays.
//!
//! The decision is pure ([`ofac`], [`list`] return what to write); writing the file atomically is the
//! `std` feature ([`fn@write`]). Run it from the device's own scheduler: the library runs nothing on a timer.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use quebracho_x402::dates;
use quebracho_x402::ports::{Https, HttpsRequest, HttpsResponse};
use quebracho_x402::screening::{self, AddressList};
use serde_json::{Map, Value, json};

/// OFAC's Sanctions List Service export of the SDN list.
pub const OFAC_URL: &str =
    "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.CSV";
/// Fewer addresses than this in a parsed SDN.CSV means the download is not the real list.
pub const OFAC_MIN_ADDRESSES: usize = 100;
const OFAC_MAX_REDIRECTS: usize = 3;

/// Why a sync left the copy as it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncFailed(pub String);

/// What a sync decided: the list's size and date, and the new content when it replaces the copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncResult {
    pub count: usize,
    /// The list's date, `YYYY-MM-DDTHH:MM:SSZ`.
    pub updated: String,
    /// `None` when the copy held a younger list and was kept.
    pub content: Option<String>,
}

impl SyncResult {
    pub fn replaced(&self) -> bool {
        self.content.is_some()
    }
}

/// The digital-currency addresses in an SDN.CSV, by currency, sorted.
pub fn parse_sdn(csv: &str) -> BTreeMap<String, Vec<String>> {
    let mut found: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for row in csv_rows(csv) {
        // The remarks are the 12th column; a remark may span lines inside its quotes.
        let Some(remarks) = row.get(11) else { continue };
        let marker = "Digital Currency Address - ";
        let mut from = 0;
        while let Some(i) = remarks[from..].find(marker) {
            let start = from + i + marker.len();
            from = from + i + 1;
            let rest = &remarks[start..];
            let cur_len = rest
                .bytes()
                .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                .count();
            let after = &rest[cur_len..];
            let gap = after.bytes().take_while(u8::is_ascii_whitespace).count();
            let addr_len = after[gap..]
                .bytes()
                .take_while(|c| !c.is_ascii_whitespace() && *c != b';')
                .count();
            if cur_len == 0 || gap == 0 || addr_len == 0 {
                continue;
            }
            let address = after[gap..gap + addr_len].trim_end_matches('.');
            found
                .entry(rest[..cur_len].into())
                .or_default()
                .insert(address.into());
        }
    }
    found
        .into_iter()
        .map(|(c, set)| (c, set.into_iter().collect()))
        .collect()
}

/// Rows of a CSV: `,` between fields, `"` around a field (`""` inside it), line breaks inside quotes kept.
fn csv_rows(csv: &str) -> Vec<Vec<String>> {
    let (mut rows, mut row, mut field) = (Vec::new(), Vec::new(), String::new());
    let (mut quoted, mut chars) = (false, csv.chars().peekable());
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                chars.next();
                field.push('"');
            }
            (true, '"') => quoted = false,
            (true, c) => field.push(c),
            (false, '"') if field.is_empty() => quoted = true,
            (false, ',') => row.push(core::mem::take(&mut field)),
            (false, '\n') => {
                row.push(core::mem::take(&mut field));
                rows.push(core::mem::take(&mut row));
            }
            (false, '\r') => {}
            (false, c) => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

/// The date a download is from: its `Last-Modified`, else `now`.
fn date_of(response: &HttpsResponse, now: i64) -> String {
    dates::iso(
        response
            .header("Last-Modified")
            .and_then(dates::parse_http)
            .unwrap_or(now),
    )
}

/// GET with the size cap; a redirect is followed only by [`ofac`], by hand.
fn get(https: &dyn Https, url: &str) -> Result<HttpsResponse, SyncFailed> {
    https
        .send(&HttpsRequest {
            method: "GET",
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
        })
        .map_err(|_| SyncFailed(format!("{url}: unreachable")))
}

/// Downloads OFAC's SDN.CSV and decides on a new snapshot. Follows OFAC's redirects (to its signed download
/// URL) itself, at most 3, HTTPS only. `current` is the snapshot the device holds now, if any.
pub fn ofac(https: &dyn Https, now: i64, current: Option<&str>) -> Result<SyncResult, SyncFailed> {
    let mut url = OFAC_URL.to_string();
    let mut hops = 0;
    let response = loop {
        let r = get(https, &url)?;
        if !(300..400).contains(&r.status) {
            break r;
        }
        url = r.header("Location").unwrap_or_default().to_string();
        if hops >= OFAC_MAX_REDIRECTS || !url.starts_with("https://") {
            return Err(SyncFailed(format!("OFAC SDN: redirect to '{url}' refused")));
        }
        hops += 1;
    };
    if response.status != 200 {
        return Err(SyncFailed(format!("OFAC SDN: HTTP {}", response.status)));
    }
    let csv = String::from_utf8_lossy(&response.body);
    ofac_snapshot(&csv, &date_of(&response, now), current)
}

/// The decision of [`ofac`] for an SDN.CSV obtained another way.
pub fn ofac_snapshot(
    csv: &str,
    published: &str,
    current: Option<&str>,
) -> Result<SyncResult, SyncFailed> {
    let addresses = parse_sdn(csv);
    let count: usize = addresses.values().map(Vec::len).sum();
    if count < OFAC_MIN_ADDRESSES {
        return Err(SyncFailed(format!(
            "OFAC SDN: only {count} addresses parsed; the copy was kept"
        )));
    }
    // A younger copy is kept (a broken one is replaced, whatever its date).
    if let Some(cur) = current.and_then(|c| serde_json::from_str::<Value>(c).ok())
        && let (Some(p), Some(Value::Object(lists))) = (
            cur.get("published").and_then(Value::as_str),
            cur.get("addresses"),
        )
        && p > published
    {
        let kept = lists
            .values()
            .filter_map(Value::as_array)
            .map(Vec::len)
            .sum();
        return Ok(SyncResult {
            count: kept,
            updated: p.into(),
            content: None,
        });
    }
    let addresses: Map<String, Value> = addresses
        .into_iter()
        .map(|(c, list)| (c, json!(list)))
        .collect();
    let snapshot = json!({ "source": OFAC_URL, "published": published, "addresses": addresses });
    Ok(SyncResult {
        count,
        updated: published.into(),
        content: Some(serde_json::to_string_pretty(&snapshot).unwrap_or_default() + "\n"),
    })
}

/// Downloads a list another site publishes (HTTPS only, no redirects), checks it has at least `min`
/// addresses, and decides. The list's date is its own `# updated:` line, else the download's
/// `Last-Modified`, else `now`. `current` is the list file the device holds now, if any.
pub fn list(
    https: &dyn Https,
    url: &str,
    min: usize,
    now: i64,
    current: Option<&str>,
) -> Result<SyncResult, SyncFailed> {
    if !url.starts_with("https://") {
        return Err(SyncFailed(format!("{url} is not HTTPS")));
    }
    let response = get(https, url)?;
    if response.status != 200 {
        return Err(SyncFailed(format!("{url}: HTTP {}", response.status)));
    }
    let text = String::from_utf8_lossy(&response.body);
    let parsed = AddressList::parse(&text, "");
    if parsed.addresses().len() < min {
        return Err(SyncFailed(format!(
            "{url}: {} addresses, {min} expected; the copy was kept",
            parsed.addresses().len()
        )));
    }
    let updated = screening::updated(&text).unwrap_or_else(|| date_of(&response, now));
    if let Some(cur) = current
        && let Some(kept) = screening::updated(cur).filter(|k| *k > updated)
    {
        return Ok(SyncResult {
            count: AddressList::parse(cur, "").addresses().len(),
            updated: kept,
            content: None,
        });
    }
    let content = format!(
        "# source: {url}\n# updated: {updated}\n{}\n",
        parsed.addresses().join("\n")
    );
    Ok(SyncResult {
        count: parsed.addresses().len(),
        updated,
        content: Some(content),
    })
}

/// Writes a sync's new content to `file` through a temporary file and a rename (feature `std`). Nothing
/// is written when the copy was kept.
#[cfg(feature = "std")]
pub fn write(file: &std::path::Path, result: &SyncResult) -> std::io::Result<()> {
    use std::io::Write as _;
    let Some(content) = &result.content else {
        return Ok(());
    };
    let tmp = file.with_extension(format!("{}.tmp", std::process::id()));
    let out = (|| {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, file)
    })();
    if out.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    out
}
