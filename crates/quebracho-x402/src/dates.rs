//! The few date forms the lists use: ISO 8601 (`# updated:` lines, snapshots) and HTTP dates
//! (`Last-Modified`), to and from Unix seconds, in UTC. No time zone database: only fixed offsets.
//!
//! PHP reads these with `strtotime`, which accepts much more; anything outside these forms is `None`
//! here, which the callers treat as "no date".

use alloc::format;
use alloc::string::String;

/// Days since 1970-01-01 of a civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn num(s: &str) -> Option<i64> {
    (!s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()))
        .then(|| s.parse().ok())
        .flatten()
}

fn unix(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) -> Option<i64> {
    let valid = (1..=12).contains(&mo)
        && (1..=days_in_month(y, mo)).contains(&d)
        && (0..24).contains(&h)
        && (0..60).contains(&mi)
        && (0..61).contains(&s);
    valid.then(|| days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s)
}

/// `YYYY-MM-DD`, or that with `THH:MM[:SS]` (or a space) and an optional `Z` or `±HH:MM`; UTC when no
/// offset is given.
pub fn parse_iso(text: &str) -> Option<i64> {
    let t = text.trim();
    let (y, mo, d) = (num(t.get(0..4)?)?, num(t.get(5..7)?)?, num(t.get(8..10)?)?);
    if t.get(4..5)? != "-" || t.get(7..8)? != "-" {
        return None;
    }
    let rest = &t[10..];
    if rest.is_empty() {
        return unix(y, mo, d, 0, 0, 0);
    }
    let rest = rest.strip_prefix(['T', 't', ' '])?;
    let (clock, offset) = match rest.find(['Z', 'z', '+', '-']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let mut parts = clock.split(':');
    let h = num(parts.next()?)?;
    let mi = num(parts.next()?)?;
    let s = match parts.next() {
        Some(s) => num(s)?,
        None => 0,
    };
    if parts.next().is_some() {
        return None;
    }
    let shift = match offset {
        "" | "Z" | "z" => 0,
        o => {
            let sign = if o.starts_with('-') { -1 } else { 1 };
            let o = &o[1..];
            let (oh, om) = o.split_once(':').unwrap_or((o.get(0..2)?, o.get(2..)?));
            sign * (num(oh)? * 3600 + num(om)? * 60)
        }
    };
    Some(unix(y, mo, d, h, mi, s)? - shift)
}

/// An HTTP date (`Sun, 06 Nov 1994 08:49:37 GMT`, RFC 9110's preferred form).
pub fn parse_http(text: &str) -> Option<i64> {
    let mut f = text.split_whitespace().skip(1);
    let d = num(f.next()?)?;
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let month = f.next()?;
    let mo = months.iter().position(|m| *m == month)? as i64 + 1;
    let y = num(f.next()?)?;
    let mut clock = f.next()?.split(':');
    let (h, mi, s) = (
        num(clock.next()?)?,
        num(clock.next()?)?,
        num(clock.next()?)?,
    );
    (f.next()? == "GMT").then_some(())?;
    unix(y, mo, d, h, mi, s)
}

/// `YYYY-MM-DDTHH:MM:SSZ`.
pub fn iso(unix: i64) -> String {
    let (y, m, d) = civil_from_days(unix.div_euclid(86_400));
    let s = unix.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        s / 3600,
        s % 3600 / 60,
        s % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(
            parse_iso("2026-11-06T19:33:18Z").map(iso).as_deref(),
            Some("2026-11-06T19:33:18Z")
        );
        assert_eq!(
            parse_iso("2026-11-06T19:33:18-03:00").map(iso).as_deref(),
            Some("2026-11-06T22:33:18Z")
        );
        assert_eq!(
            parse_iso("2024-02-29").map(iso).as_deref(),
            Some("2024-02-29T00:00:00Z")
        );
        assert_eq!(parse_iso("2026-02-29"), None);
        assert_eq!(parse_iso("not-a-date"), None);
        assert_eq!(
            parse_http("Fri, 13 Nov 2026 16:33:06 GMT")
                .map(iso)
                .as_deref(),
            Some("2026-11-13T16:33:06Z")
        );
        assert_eq!(parse_http("Fri, 13 Nov 2026 16:33:06 PST"), None);
    }
}
