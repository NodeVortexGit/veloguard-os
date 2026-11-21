//! Integrity — the guard checks itself (zero trust: assume breach).
//!
//! A root-only baseline (/var/lib/veloguard/integrity.json, the same format
//! guardd/integrity.py wrote: {"ts", "files": {path: sha256 | "link:<target>"}})
//! holds every file that IS the guard. `check` (at boot and every 6 h)
//! compares; anything changed, added or gone outside a deploy is recorded in
//! the audit log, saved as an incident and announced. A deploy ends with
//! `update`, which re-baselines.
//!
//! Differences from the Python version, on purpose:
//!   * hidden files are covered: Python's glob skipped them, so the Claude
//!     plugin's .mcp.json (which names the MCP server command) and the plugin
//!     manifests under .claude-plugin/ and .agents/ were never checked;
//!   * a finding is never lost: it's audited first, and a failure to save the
//!     incident is reported (exit 1), not a crash before anyone hears of it.

use crate::{audit, incident, sys};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const BASELINE: &str = "/var/lib/veloguard/integrity.json";
pub const COVERED: &[&str] = &[
    "/opt/veloguard/guardd/*.py", "/opt/veloguard/bin/*", "/opt/veloguard/provision/*",
    "/opt/veloguard/*.json", "/usr/local/bin/veloguard*", "/usr/share/veloguard/agents/**",
    "/etc/veloguard/**", "/etc/polkit-1/rules.d/49-veloguard*", "/etc/codex/requirements.toml",
    "/etc/systemd/system/veloguard*", "/etc/tmpfiles.d/veloguard.conf",
    "/etc/sysctl.d/90-veloguard*", "/etc/systemd/resolved.conf.d/90-veloguard*",
    "/etc/NetworkManager/conf.d/90-veloguard*", "/etc/NetworkManager/dispatcher.d/90-veloguard",
];
const SKIP: &[&str] = &["/__pycache__/", ".orig-", ".pyc"];

/// fnmatch with * and ? (no leading-dot match, like a shell glob).
fn name_match(pat: &str, name: &str) -> bool {
    if name.starts_with('.') && !pat.starts_with('.') {
        return false;
    }
    fn m(p: &[u8], n: &[u8]) -> bool {
        match (p.first(), n.first()) {
            (None, None) => true,
            (Some(b'*'), _) => m(&p[1..], n) || (!n.is_empty() && m(p, &n[1..])),
            (Some(b'?'), Some(_)) => m(&p[1..], &n[1..]),
            (Some(a), Some(b)) if a == b => m(&p[1..], &n[1..]),
            _ => false,
        }
    }
    m(pat.as_bytes(), name.as_bytes())
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>, depth: usize) {
    if depth > 32 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        match e.file_type() {
            Ok(t) if t.is_dir() => walk(&p, out, depth + 1), // a real dir (not a symlink): descend
            Ok(_) => out.push(p),
        Err(_) => {}
        }
    }
}

/// Every covered file: symlinks as themselves, other files by their real path.
pub fn files(patterns: &[&str]) -> Vec<String> {
    let mut found = Vec::new();
    for pat in patterns {
        let (dir, name) = pat.rsplit_once('/').unwrap_or(("", pat));
        let dir = if dir.is_empty() { "/" } else { dir };
        if name == "**" {
            walk(Path::new(dir), &mut found, 0);
        } else if name.contains(['*', '?']) {
            if let Ok(rd) = std::fs::read_dir(dir) {
                for e in rd.flatten() {
                    if name_match(name, &e.file_name().to_string_lossy()) {
                        found.push(e.path());
                    }
                }
            }
        } else {
            found.push(PathBuf::from(pat));
        }
    }
    let mut out = BTreeSet::new();
    for p in found {
        let s = p.to_string_lossy().into_owned();
        if SKIP.iter().any(|k| s.contains(k)) || !p.is_file() {
            continue; // is_file follows links: a link to a file counts
        }
        let is_link = std::fs::symlink_metadata(&p).map(|m| m.file_type().is_symlink()).unwrap_or(false);
        out.insert(if is_link { s } else { std::fs::canonicalize(&p).map(|c| c.to_string_lossy().into_owned()).unwrap_or(s) });
    }
    out.into_iter().collect()
}

pub fn digest(path: &str) -> Option<String> {
    let md = std::fs::symlink_metadata(path).ok()?;
    if md.file_type().is_symlink() {
        return Some(format!("link:{}", sys::readlink(path)?));
    }
    let mut f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(path).ok()?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

pub fn snapshot(patterns: &[&str]) -> BTreeMap<String, String> {
    files(patterns).into_iter().filter_map(|f| digest(&f).map(|d| (f, d))).collect()
}

pub fn write_baseline(path: &Path, snap: &BTreeMap<String, String>) -> std::io::Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension("tmp");
    let body = json!({"ts": sys::now(), "files": snap});
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    use std::io::Write;
    f.write_all(serde_json::to_string_pretty(&body).unwrap_or_default().as_bytes())?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

pub struct Diff {
    pub changed: Vec<String>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

impl Diff {
    pub fn is_clean(&self) -> bool {
        self.changed.is_empty() && self.added.is_empty() && self.removed.is_empty()
    }

    pub fn to_json(&self) -> Value {
        json!({"changed": self.changed, "added": self.added, "removed": self.removed})
    }
}

/// None = no (readable) baseline yet.
pub fn compare(base_path: &Path, now: &BTreeMap<String, String>) -> Option<Diff> {
    let text = std::fs::read_to_string(base_path).ok()?;
    let base: Map<String, Value> = serde_json::from_str::<Value>(&text).ok()?.get("files")?.as_object()?.clone();
    Some(Diff {
        changed: now.iter().filter(|(f, d)| base.get(*f).and_then(Value::as_str).is_some_and(|b| b != d.as_str()))
            .map(|(f, _)| f.clone()).collect(),
        added: now.keys().filter(|f| !base.contains_key(*f)).cloned().collect(),
        removed: base.keys().filter(|f| !now.contains_key(*f)).cloned().collect(),
    })
}

/// `veloguard-integrity update | check` — exit 0 ok, 1 mismatch, 2 usage / not root.
pub fn main(args: &[String]) -> i32 {
    let sub = args.first().map(String::as_str).unwrap_or("check");
    if !["check", "update"].contains(&sub) {
        eprintln!("usage: veloguard-integrity check | update");
        return 2;
    }
    if sys::euid() != 0 {
        eprintln!("integrity needs root (the baseline is root-only)");
        return 2;
    }
    let base = PathBuf::from(std::env::var("VELOGUARD_BASELINE").unwrap_or_else(|_| BASELINE.into()));
    let snap = snapshot(COVERED);
    if sub == "update" {
        return match write_baseline(&base, &snap) {
            Ok(()) => {
                audit::record(json!({"control": "integrity", "action": "update", "files": snap.len(), "result": "ok",
                                     "engine": "rust"}));
                println!("baseline: {} guard files", snap.len());
                0
            }
            Err(e) => {
                eprintln!("can't write the baseline {}: {e}", base.display());
                1
            }
        };
    }
    let Some(diff) = compare(&base, &snap) else {
        return match write_baseline(&base, &snap) {
            Ok(()) => { println!("no baseline yet — took one ({} files)", snap.len()); 0 }
            Err(e) => { eprintln!("no baseline, and can't write one ({e})"); 1 }
        };
    };
    if diff.is_clean() {
        println!("✓ the guard's files are as deployed ({} files)", snap.len());
        return 0;
    }
    let n = diff.changed.len() + diff.added.len() + diff.removed.len();
    // Audited first: whatever happens next, the finding is on record.
    let mut entry = json!({"control": "integrity", "action": "check", "result": "mismatch", "engine": "rust"});
    for (k, v) in diff.to_json().as_object().cloned().unwrap_or_default() {
        entry[k] = v;
    }
    audit::record(entry);
    for (k, list) in [("changed", &diff.changed), ("added", &diff.added), ("removed", &diff.removed)] {
        for f in list {
            println!("  {k:8} {f}");
        }
    }
    match incident::save("integrity", &format!("VeloGuard's own files changed outside a deploy ({n})"), diff.to_json(), true) {
        Ok(inc) => println!("incident {}", inc["id"].as_str().unwrap_or("")),
        Err(e) => eprintln!("the incident couldn't be saved ({e}) — the finding is in the audit log"),
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs_like_a_shell_and_star_star_sees_hidden_files() {
        assert!(name_match("veloguard*", "veloguard-mcp") && name_match("*.py", "a.py"));
        assert!(!name_match("*", ".hidden") && !name_match("*.py", "a.pyc"));
        let d = std::env::temp_dir().join(format!("vg-rs-int-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("plug/.claude-plugin")).unwrap();
        std::fs::write(d.join("plug/.mcp.json"), "{}").unwrap();
        std::fs::write(d.join("plug/.claude-plugin/plugin.json"), "{}").unwrap();
        std::fs::write(d.join("a.py"), "x").unwrap();
        std::fs::write(d.join("a.py.orig-1"), "x").unwrap();
        std::os::unix::fs::symlink(d.join("a.py"), d.join("link.py")).unwrap();
        let star = format!("{}/plug/**", d.display());
        let py = format!("{}/*.py", d.display());
        let fs = files(&[&star, &py]);
        assert!(fs.iter().any(|f| f.ends_with("/.mcp.json")), "{fs:?}");
        assert!(fs.iter().any(|f| f.ends_with("/.claude-plugin/plugin.json")));
        assert!(!fs.iter().any(|f| f.contains(".orig-")));
        let link = fs.iter().find(|f| f.ends_with("link.py")).unwrap();
        assert!(digest(link).unwrap().starts_with("link:"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn finds_changed_added_and_removed() {
        let d = std::env::temp_dir().join(format!("vg-rs-int2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        for f in ["a", "b", "c"] {
            std::fs::write(d.join(f), f).unwrap();
        }
        let pat = format!("{}/*", d.display());
        let base = std::env::temp_dir().join(format!("vg-rs-int2-{}.json", std::process::id()));
        write_baseline(&base, &snapshot(&[&pat])).unwrap();
        assert!(compare(&base, &snapshot(&[&pat])).unwrap().is_clean());
        std::fs::write(d.join("a"), "tampered").unwrap();
        std::fs::remove_file(d.join("b")).unwrap();
        std::fs::write(d.join("new"), "x").unwrap();
        let diff = compare(&base, &snapshot(&[&pat])).unwrap();
        let tail = |v: &Vec<String>| v.iter().map(|f| f.rsplit('/').next().unwrap().to_string()).collect::<Vec<_>>();
        assert_eq!((tail(&diff.changed), tail(&diff.removed), tail(&diff.added)),
                   (vec!["a".to_string()], vec!["b".to_string()], vec!["new".to_string()]));
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_file(&base);
    }

    #[test]
    fn reads_the_python_baseline_format() {
        let base = std::env::temp_dir().join(format!("vg-rs-int3-{}.json", std::process::id()));
        std::fs::write(&base, r#"{"ts": 1.5, "files": {"/x": "abc", "/l": "link:/y"}}"#).unwrap();
        let mut now = BTreeMap::new();
        now.insert("/x".to_string(), "abc".to_string());
        now.insert("/l".to_string(), "link:/y".to_string());
        assert!(compare(&base, &now).unwrap().is_clean());
        let _ = std::fs::remove_file(&base);
    }
}
