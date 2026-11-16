//! What PHP's loose casts do to JSON values, for the places the port must answer as PHP does.

use serde_json::Value;

pub(crate) static EMPTY: Value = Value::Array(alloc::vec::Vec::new());
pub(crate) static EMPTY_STRING: Value = Value::String(alloc::string::String::new());

/// A PHP array: a JSON object or list.
pub(crate) fn is_array(v: &Value) -> bool {
    matches!(v, Value::Object(_) | Value::Array(_))
}

/// `$v[$key] ?? null`: only objects have string keys.
pub(crate) fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Object(m) => m.get(key).filter(|x| !x.is_null()),
        _ => None,
    }
}

pub(crate) fn at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(v, |v, key| get(v, key))
}

/// PHP `empty()`: missing, null, false, 0, 0.0, "", "0" or an empty array.
pub(crate) fn php_empty(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => true,
        Some(Value::Number(n)) => n.as_f64() == Some(0.0),
        Some(Value::String(s)) => s.is_empty() || s == "0",
        Some(Value::Array(a)) => a.is_empty(),
        Some(Value::Object(o)) => o.is_empty(),
        Some(Value::Bool(true)) => false,
    }
}

/// PHP `(string)`. Always a string, as in PHP: an array is "Array" (PHP also warns), a float is printed
/// with PHP's `precision` of 14 significant digits (`1.5`, `10000`, `1.0E+20`).
pub(crate) fn php_string(v: &Value) -> alloc::string::String {
    use alloc::string::ToString;
    match v {
        Value::String(s) => s.clone(),
        Value::Null | Value::Bool(false) => alloc::string::String::new(),
        Value::Bool(true) => "1".into(),
        Value::Number(n) => match n.as_i64() {
            Some(i) => i.to_string(),
            // A float, or an integer beyond PHP_INT_MAX (json_decode makes it a float too).
            None => php_float_string(n.as_f64().unwrap_or(0.0)),
        },
        Value::Array(_) | Value::Object(_) => "Array".into(),
    }
}

/// PHP 8's float to string: `%.14G`, with ".0" on a whole mantissa in exponent form.
fn php_float_string(f: f64) -> alloc::string::String {
    use alloc::format;
    use alloc::string::String;
    if f == 0.0 {
        return if f.is_sign_negative() {
            "-0".into()
        } else {
            "0".into()
        };
    }
    // 14 significant digits, rounded: "d.ddddddddddddde±x".
    let sci = format!("{:.13e}", f);
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let negative = mantissa.starts_with('-');
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let digits = digits.trim_end_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    let sign = if negative { "-" } else { "" };
    if !(-4..14).contains(&exp) {
        let (head, tail) = digits.split_at(1);
        let tail = if tail.is_empty() { "0" } else { tail };
        let esign = if exp < 0 { '-' } else { '+' };
        return format!("{sign}{head}.{tail}E{esign}{}", exp.unsigned_abs());
    }
    let out = if exp < 0 {
        format!("0.{}{digits}", "0".repeat((-exp - 1) as usize))
    } else {
        let point = exp as usize + 1;
        if digits.len() <= point {
            format!("{digits}{}", "0".repeat(point - digits.len()))
        } else {
            format!("{}.{}", &digits[..point], &digits[point..])
        }
    };
    format!("{sign}{out}")
}

/// PHP 8's float to int: truncated; not finite is 0; out of range wraps modulo 2^64.
fn php_float_int(f: f64) -> i64 {
    if !f.is_finite() {
        return 0;
    }
    if (-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0).contains(&f) {
        return f as i64;
    }
    let two64 = 18_446_744_073_709_551_616.0_f64;
    // f64 % is libm's fmod in std only; f is huge here, so subtracting whole multiples is exact.
    let mut m = f - two64 * libm_floor(f / two64);
    if m >= 9_223_372_036_854_775_808.0 {
        m -= two64;
    }
    m as i64
}

/// `floor` without std: exact for the magnitudes `php_float_int` passes (|x| < 2^53 after the division
/// is not guaranteed, but beyond 2^53 every f64 is already an integer).
fn libm_floor(x: f64) -> f64 {
    if x.abs() >= 4_503_599_627_370_496.0 {
        return x;
    }
    let t = x as i64 as f64;
    if t > x { t - 1.0 } else { t }
}

/// PHP 8's `(int)`: numbers truncated (floats as above), numeric strings read from their numeric prefix
/// (leading whitespace, sign, digits, fraction, exponent), true is 1, an array is 0 when empty and 1
/// otherwise, anything else 0.
pub(crate) fn php_int(v: Option<&Value>) -> i64 {
    match v {
        Some(Value::Number(n)) => n
            .as_i64()
            .unwrap_or_else(|| php_float_int(n.as_f64().unwrap_or(0.0))),
        Some(Value::String(s)) => php_string_int(s),
        Some(Value::Bool(true)) => 1,
        Some(Value::Array(a)) => i64::from(!a.is_empty()),
        Some(Value::Object(o)) => i64::from(!o.is_empty()),
        _ => 0,
    }
}

fn php_string_int(s: &str) -> i64 {
    let t = s.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    let b = t.as_bytes();
    let mut i = usize::from(matches!(b.first(), Some(b'+' | b'-')));
    let int_start = i;
    while b.get(i).is_some_and(u8::is_ascii_digit) {
        i += 1;
    }
    let int_digits = i - int_start;
    let mut float = false;
    if b.get(i) == Some(&b'.') && (int_digits > 0 || b.get(i + 1).is_some_and(u8::is_ascii_digit)) {
        float = true;
        i += 1;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
    }
    let mantissa_end = i;
    // No digit before or after a point: not a number (a lone sign, ".", "-.", "abc").
    if mantissa_end == int_start {
        return 0;
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        let mut j = i + 1;
        if matches!(b.get(j), Some(b'+' | b'-')) {
            j += 1;
        }
        if b.get(j).is_some_and(u8::is_ascii_digit) {
            while b.get(j).is_some_and(u8::is_ascii_digit) {
                j += 1;
            }
            float = true;
            i = j;
        }
    }
    let prefix = &t[..i];
    if float {
        return php_float_int(prefix.parse::<f64>().unwrap_or(0.0));
    }
    // An integer that does not fit saturates, as PHP's strtol does.
    match prefix.parse::<i128>() {
        Ok(n) => n.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64,
        Err(_) => {
            if prefix.starts_with('-') {
                i64::MIN
            } else {
                i64::MAX
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Answers PHP 8.3 gave for these casts (php -r, 2026-11-16).
    #[test]
    fn casts_as_php() {
        for (f, want) in [
            (1.5, "1.5"),
            (1e20, "1.0E+20"),
            (1.0e-5, "1.0E-5"),
            (10000.0, "10000"),
            (0.1, "0.1"),
            (1e15, "1.0E+15"),
            (1e14, "1.0E+14"),
            (123456789012345.0, "1.2345678901234E+14"),
            (1.0e-4, "0.0001"),
            (0.0001234, "0.0001234"),
            (-0.0, "-0"),
            (250.0, "250"),
            (1e16, "1.0E+16"),
        ] {
            assert_eq!(php_string(&json!(f)), want, "{f}");
        }
        for (s, want) in [
            ("300", 300),
            ("300abc", 300),
            (" 300", 300),
            ("1e3", 1000),
            ("-5", -5),
            ("+7", 7),
            ("0x1A", 0),
            ("2.5e2", 250),
            ("99999999999999999999", i64::MAX),
            ("  12.9x", 12),
            ("\t8", 8),
            (".5", 0),
            ("5.", 5),
            ("", 0),
            (" ", 0),
            ("1e400", 0),
        ] {
            assert_eq!(php_int(Some(&json!(s))), want, "{s:?}");
        }
        assert_eq!(php_int(Some(&json!([]))), 0);
        assert_eq!(php_int(Some(&json!([1]))), 1);
        assert_eq!(php_int(Some(&json!(true))), 1);
        assert_eq!(php_int(Some(&json!(null))), 0);
        assert_eq!(php_int(Some(&json!(300.9))), 300);
        assert_eq!(php_int(Some(&json!(-300.9))), -300);
        assert_eq!(php_int(Some(&json!(1e30))), 5_076_964_154_930_102_272);
        assert_eq!(php_string(&json!(["x"])), "Array");
        assert_eq!(php_string(&json!(0.0)), "0");
        assert_eq!(php_string(&json!(false)), "");
        assert_eq!(php_string(&json!(true)), "1");
        assert_eq!(php_string(&json!({"a": 1})), "Array");
        // PHP 8.3, 2026-11-16: out-of-range floats wrap modulo 2^64.
        for (f, want) in [
            (9.3e18, -9_146_744_073_709_551_616_i64),
            (1e19, -8_446_744_073_709_551_616),
            (-1e19, 8_446_744_073_709_551_616),
            (1.8e19, -446_744_073_709_551_616),
            (1.8446744073709552e19, 0),
            (1.85e19, 53_255_926_290_448_384),
            (2e19, 1_553_255_926_290_448_384),
            (3e19, -6_893_488_147_419_103_232),
            (1e20, 7_766_279_631_452_241_920),
            (3.6e19, -893_488_147_419_103_232),
            (-1.85e19, -53_255_926_290_448_384),
            (-3e19, 6_893_488_147_419_103_232),
            (1.844674407370955e19, -2048),
            (1e40, 0),
            (-1e40, 0),
            (1e300, 0),
        ] {
            assert_eq!(php_int(Some(&json!(f))), want, "{f}");
        }
        for (s, want) in [
            ("5.e3", 5000),
            ("-.5e1", -5),
            (".5e1", 5),
            (".e3", 0),
            ("5.5e3", 5500),
            ("-.", 0),
            (".", 0),
            ("+5", 5),
            ("1e+3", 1000),
            ("1E3", 1000),
            ("5e", 5),
            ("5e+", 5),
            ("-1e2x", -100),
            ("  -12", -12),
            ("-9999999999999999999999999999999999999999999", i64::MIN),
            ("99999999999999999999999999999999999999999999", i64::MAX),
        ] {
            assert_eq!(php_int(Some(&json!(s))), want, "{s:?}");
        }
        // A JSON object reaches PHP as an array (json_decode(..., true)): empty is "empty" and 0, else 1.
        assert!(php_empty(Some(&json!({}))));
        assert!(!php_empty(Some(&json!({"a": 1}))));
        assert_eq!(php_int(Some(&json!({}))), 0);
        assert_eq!(php_int(Some(&json!({"a": 1}))), 1);
    }
}
