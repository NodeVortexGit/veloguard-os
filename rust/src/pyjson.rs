//! JSON exactly as Python's `json.dumps(v, sort_keys=True)` writes it.
//!
//! The guard's audit log is hash-chained over that text (guardd/audit.py:
//! sha256(prev + "\n" + json.dumps(entry, sort_keys=True, default=str))), and
//! `veloguard audit verify` re-computes it in Python. An entry written from
//! Rust must hash to the same bytes, so this mirrors Python's encoder: keys
//! sorted, ", " and ": " separators, ensure_ascii (\uXXXX, surrogate pairs,
//! lower-case hex), Python's float repr for the timestamps.

use serde_json::Value;

pub fn dumps(v: &Value) -> String {
    let mut out = String::new();
    write(v, &mut out);
    out
}

fn write(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else if let Some(f) = n.as_f64() {
                out.push_str(&py_float(f));
            }
        }
        Value::String(s) => write_str(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write(x, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            // serde_json's Map is a BTreeMap (no preserve_order): byte order of
            // UTF-8 keys = code point order = Python's sort_keys.
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_str(k, out);
                out.push_str(": ");
                write(x, out);
            }
            out.push('}');
        }
    }
}

/// Python's repr(float) for the values the guard writes (timestamps,
/// percentages): shortest round-trip digits; integral values keep ".0".
pub fn py_float(f: f64) -> String {
    if f.is_nan() {
        return "NaN".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    let a = f.abs();
    if a != 0.0 && !(1e-4..1e16).contains(&a) {
        // Python switches to exponent form outside [1e-4, 1e16): 1e+16, 1e-05
        let s = format!("{:e}", f); // "1e16", "1.5e-5"
        let (m, e) = s.split_once('e').unwrap_or((&s, "0"));
        let e: i32 = e.parse().unwrap_or(0);
        return format!("{m}e{}{:02}", if e < 0 { '-' } else { '+' }, e.abs());
    }
    if f.fract() == 0.0 {
        return format!("{f:.1}");
    }
    format!("{f}")
}

fn write_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            _ => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{:04x}", u));
                }
            }
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_python_json_dumps_sort_keys() {
        // python3 -c 'import json; print(json.dumps({...}, sort_keys=True))'
        let v = json!({"b": [1, 2.5, null, true], "a": "x\"y\\z\n\t", "é": "Бг😀", "c": {}, "d": [],
                       "ts": 1795246082.1234567, "n": -3, "z": 2.0, "ctl": "\u{1}\u{7f}"});
        // Exactly what Python printed for the same value (kept in a file so no
        // editor can turn the \u escapes into characters).
        let expected = include_str!("pyjson_expected.txt").trim_end();
        assert_eq!(dumps(&v), expected);
    }

    #[test]
    fn floats_like_python_repr() {
        assert_eq!(py_float(1e16), "1e+16");
        assert_eq!(py_float(1.5e-5), "1.5e-05");
        assert_eq!(py_float(0.0001), "0.0001");
        assert_eq!(py_float(0.0), "0.0");
        assert_eq!(py_float(123.25), "123.25");
    }
}
