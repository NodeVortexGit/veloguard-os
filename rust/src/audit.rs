//! The guard's audit trail — the same hash-chained file guardd/audit.py
//! writes, so `veloguard audit verify` checks Rust and Python entries alike.
//!
//! Location (first that applies), as in Python:
//!   $VELOGUARD_AUDIT_LOG
//!   /var/log/veloguard/audit.log        when running as root
//!   <guard home>/audit.log              a writable dev checkout
//!   ~/.config/veloguard/audit.log       everyone else ($VELOGUARD_STATE overrides the dir)
//! Never panics: an unwritable log must not turn a decision into a crash.

use crate::{pyjson, sys};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

static WARNED: AtomicBool = AtomicBool::new(false);

pub fn state_dir() -> PathBuf {
    if let Ok(d) = std::env::var("VELOGUARD_STATE") {
        if !d.is_empty() {
            let p = PathBuf::from(d);
            let _ = std::fs::create_dir_all(&p);
            return p;
        }
    }
    let base = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(sys::home()).join(".config"))
        .join("veloguard");
    let _ = std::fs::create_dir_all(&base);
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700));
    base
}

pub fn log_path() -> PathBuf {
    if let Ok(p) = std::env::var("VELOGUARD_AUDIT_LOG") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    if sys::euid() == 0 {
        return PathBuf::from("/var/log/veloguard/audit.log");
    }
    let home = crate::guard_home();
    let dev = home.join("audit.log");
    let writable = |p: &std::path::Path| {
        let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap_or_default();
        unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
    };
    if writable(&home) && (!dev.exists() || writable(&dev)) {
        return dev;
    }
    state_dir().join("audit.log")
}

fn chain_hash(prev: &str, entry: &Map<String, Value>) -> String {
    let mut body = entry.clone();
    body.remove("hash");
    let text = pyjson::dumps(&Value::Object(body));
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(b"\n");
    h.update(text.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn last_hash(f: &mut std::fs::File) -> String {
    let size = f.seek(SeekFrom::End(0)).unwrap_or(0);
    let _ = f.seek(SeekFrom::Start(size.saturating_sub(65536)));
    let mut buf = Vec::new();
    let _ = f.read_to_end(&mut buf);
    for line in String::from_utf8_lossy(&buf).lines().rev() {
        if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(line) {
            return m.get("hash").and_then(|h| h.as_str()).unwrap_or("").to_string();
        }
    }
    String::new()
}

/// Append one decision to the chain.
pub fn record(entry: Value) {
    record_to(entry, &log_path())
}

pub fn record_to(entry: Value, path: &std::path::Path) {
    let mut e = Map::new();
    let t = sys::now();
    e.insert("ts".into(), Value::from(t));
    e.insert("iso".into(), Value::from(sys::strftime("%Y-%m-%dT%H:%M:%S", t)));
    e.insert("pid".into(), Value::from(std::process::id()));
    e.insert("uid".into(), Value::from(sys::uid()));
    if let Value::Object(m) = entry {
        for (k, v) in m {
            e.insert(k, v);
        }
    }
    let res = (|| -> std::io::Result<()> {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        let mut f = OpenOptions::new().read(true).append(true).create(true).mode(0o600).open(path)?;
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let prev = last_hash(&mut f);
        e.insert("prev".into(), Value::from(prev.clone()));
        let h = chain_hash(&prev, &e);
        e.insert("hash".into(), Value::from(h));
        let line = pyjson::dumps(&Value::Object(e.clone())) + "\n";
        f.write_all(line.as_bytes())?;
        Ok(())
    })();
    if let Err(err) = res {
        if !WARNED.swap(true, Ordering::SeqCst) {
            eprintln!("veloguard: audit log {} not writable ({err})", path.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn entries_chain_and_python_verifies_them() {
        let dir = std::env::temp_dir().join(format!("vg-rs-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let log = dir.join("audit.log");
        record_to(json!({"control": "test", "what": "Бг 😀 \"q\""}), &log);
        record_to(json!({"control": "test", "n": 2, "pct": 12.5}), &log);
        let text = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1]["prev"], lines[0]["hash"]);
        // The real check: the Python guard's own verifier accepts the chain.
        let guardd = concat!(env!("CARGO_MANIFEST_DIR"), "/../veloguard");
        if std::path::Path::new(guardd).join("guardd/audit.py").exists() && sys::which("python3").is_some() {
            let out = std::process::Command::new("python3")
                .args(["-I", "-c", "import sys; sys.path.insert(0, sys.argv[1]); from pathlib import Path; \
                        from guardd import audit; ok, msg = audit.verify(Path(sys.argv[2])); print(msg); sys.exit(0 if ok else 1)",
                       guardd, log.to_str().unwrap()])
                .output()
                .unwrap();
            assert!(out.status.success(), "python verify: {}", String::from_utf8_lossy(&out.stdout));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
