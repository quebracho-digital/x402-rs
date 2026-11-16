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

/// PHP `(string)`, for the values it is compared with here (digits and addresses). `None` stands for
/// a result that can equal neither (an array's "Array", a float with a fraction or an exponent).
pub(crate) fn php_string(v: &Value) -> Option<alloc::string::String> {
    use alloc::string::ToString;
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Null | Value::Bool(false) => Some(alloc::string::String::new()),
        Value::Bool(true) => Some("1".into()),
        Value::Number(n) if !n.is_f64() => Some(n.to_string()),
        // PHP prints an integral float below 1e15 without ".0".
        // (`f64::fract` is std-only; the round trip through i64 is the same test below 1e15.)
        Value::Number(n) => n
            .as_f64()
            .filter(|&f| f.abs() < 1e15 && (f as i64) as f64 == f)
            .map(|f| (f as i64).to_string()),
        Value::Array(_) | Value::Object(_) => None,
    }
}

/// PHP `(int)` for an offer's number: integers as they are, floats truncated, numeric strings read
/// from the start, anything else 0.
pub(crate) fn php_int(v: Option<&Value>) -> i64 {
    match v {
        Some(Value::Number(n)) => n
            .as_i64()
            .or_else(|| n.as_f64().map(|f| f as i64))
            .unwrap_or(0),
        Some(Value::String(s)) => {
            let t = s.trim_start();
            let end = t
                .char_indices()
                .find(|&(i, c)| !(c.is_ascii_digit() || (i == 0 && (c == '-' || c == '+'))))
                .map_or(t.len(), |(i, _)| i);
            t[..end].parse().unwrap_or(0)
        }
        Some(Value::Bool(true)) => 1,
        _ => 0,
    }
}
