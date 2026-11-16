//! Hex helpers. Callers check the spelling with [`crate::field`] first; these only convert.

use alloc::string::String;

fn digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// `0x` + exactly `2 * N` hex digits, in any case, into N bytes.
pub(crate) fn decode<const N: usize>(s: &str) -> Option<[u8; N]> {
    let digits = s.strip_prefix("0x")?.as_bytes();
    if digits.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    for (i, pair) in digits.chunks_exact(2).enumerate() {
        out[i] = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Some(out)
}

/// Lower-case hex, no prefix.
pub(crate) fn encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_only_its_exact_spelling() {
        assert_eq!(decode::<2>("0xAbcD"), Some([0xab, 0xcd]));
        assert_eq!(decode::<2>("0xabc"), None, "wrong length");
        assert_eq!(decode::<2>("abcd"), None, "no 0x");
        assert_eq!(decode::<2>("0xabzz"), None, "not hex");
        assert_eq!(encode(&[0x0f, 0xa0]), "0fa0");
    }
}
