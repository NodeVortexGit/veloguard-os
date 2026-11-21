//! Incidents — what the guard caught, saved so a person (and the agent they
//! pick) can look into it, and announced on the desktop. Same files as
//! guardd/incident.py: one JSON per incident, {id, ts, iso, kind, title, details}.
//!
//! Where: as root, ALWAYS the system store /var/lib/veloguard/incidents (dir
//! 0750 root:wheel, files 0640) — the one the desktop and the agents read. The
//! Python version used root's own ~/.config, which a hardened unit mounts
//! read-only: the integrity check crashed there for 5 days and its alarm never
//! reached anyone. As a user: $VELOGUARD_STATE or ~/.config/veloguard.

use crate::{audit, sys};
use serde_json::{Value, json};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::time::Duration;

const NOTIFY: &str = "/usr/local/bin/veloguard-notify";
pub const SYSTEM_STORE: &str = "/var/lib/veloguard/incidents";

fn wheel_gid() -> Option<u32> {
    let g = std::ffi::CString::new("wheel").ok()?;
    let gr = unsafe { libc::getgrnam(g.as_ptr()) };
    (!gr.is_null()).then(|| unsafe { (*gr).gr_gid })
}

pub fn store() -> PathBuf {
    if sys::euid() == 0 {
        PathBuf::from(std::env::var("VELOGUARD_INCIDENTS").unwrap_or_else(|_| SYSTEM_STORE.into()))
    } else {
        audit::state_dir().join("incidents")
    }
}

fn chown_wheel(p: &std::path::Path) {
    if sys::euid() == 0 {
        if let (Some(gid), Ok(c)) = (wheel_gid(), std::ffi::CString::new(p.as_os_str().as_encoded_bytes())) {
            unsafe { libc::chown(c.as_ptr(), 0, gid) };
        }
    }
}

/// Save one incident; Err says why (the caller still reports the finding).
pub fn save(kind: &str, title: &str, details: Value, notify: bool) -> Result<Value, String> {
    let ts = sys::now();
    let id = format!("{}-{kind}", sys::strftime("%Y%m%d-%H%M%S", ts));
    let inc = json!({"id": id, "ts": ts, "iso": sys::strftime("%Y-%m-%dT%H:%M:%S", ts), "kind": kind,
                     "title": title, "details": details});
    let d = store();
    std::fs::create_dir_all(&d).map_err(|e| format!("can't create {}: {e}", d.display()))?;
    chown_wheel(&d);
    let mode = if sys::euid() == 0 && wheel_gid().is_some() { 0o750 } else { 0o700 };
    let _ = std::fs::set_permissions(&d, std::fs::Permissions::from_mode(mode));
    let f = d.join(format!("{id}.json"));
    let mut fh = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o640).open(&f)
        .map_err(|e| format!("can't write {}: {e}", f.display()))?;
    fh.write_all(serde_json::to_string_pretty(&inc).unwrap_or_default().as_bytes())
        .map_err(|e| format!("can't write {}: {e}", f.display()))?;
    chown_wheel(&f);
    if notify {
        announce(&inc);
    }
    Ok(inc)
}

/// The user of the active local graphical session (for root callers).
pub fn session_user() -> Option<String> {
    let (_, out) = sys::run(&["loginctl", "list-sessions", "--no-legend"], Duration::from_secs(5));
    for line in out.lines() {
        let Some(sid) = line.split_whitespace().next() else { continue };
        let (_, props) = sys::run(&["loginctl", "show-session", sid, "-p", "Active", "-p", "Class", "-p", "Type",
                                    "-p", "Name", "-p", "Remote"], Duration::from_secs(5));
        let v: std::collections::HashMap<&str, &str> = props.lines().filter_map(|l| l.split_once('=')).collect();
        if v.get("Active") == Some(&"yes") && v.get("Class") == Some(&"user") && v.get("Remote") != Some(&"yes")
            && matches!(v.get("Type"), Some(&"wayland") | Some(&"x11")) {
            return v.get("Name").filter(|n| !n.is_empty()).map(|n| n.to_string());
        }
    }
    None
}

fn uid_of(user: &str) -> Option<u32> {
    let c = std::ffi::CString::new(user).ok()?;
    let pw = unsafe { libc::getpwnam(c.as_ptr()) };
    (!pw.is_null()).then(|| unsafe { (*pw).pw_uid })
}

/// `veloguard watch` runs in that person's session: it has the agent write a
/// report and announces the incident itself.
fn responder_alive(uid: u32) -> bool {
    std::fs::metadata(format!("/run/user/{uid}/veloguard/responder.alive")).and_then(|m| m.modified())
        .ok().and_then(|t| t.elapsed().ok()).is_some_and(|age| age < Duration::from_secs(60))
}

/// A desktop notification with "Investigate with <agent>". Never fails the save.
pub fn announce(inc: &Value) {
    if !std::path::Path::new(NOTIFY).exists() {
        return;
    }
    let id = inc["id"].as_str().unwrap_or("");
    let title = inc["title"].as_str().unwrap_or("");
    let mut cmd;
    if sys::euid() == 0 {
        let Some(user) = session_user() else { return };
        let Some(uid) = uid_of(&user) else { return };
        if responder_alive(uid) {
            return;
        }
        cmd = std::process::Command::new("runuser");
        cmd.args(["-u", &user, "--", "env", &format!("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus"),
                  &format!("XDG_RUNTIME_DIR=/run/user/{uid}"), "WAYLAND_DISPLAY=wayland-1",
                  "PATH=/usr/local/bin:/usr/bin", NOTIFY, "--incident", id, "VeloGuard caught something", title]);
    } else {
        if responder_alive(sys::uid()) {
            return;
        }
        cmd = std::process::Command::new(NOTIFY);
        cmd.args(["--incident", id, "VeloGuard caught something", title]);
    }
    use std::os::unix::process::CommandExt;
    let _ = cmd.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null()).process_group(0).spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saves_the_same_shape_as_python() {
        if sys::euid() == 0 {
            return; // would write the real system store
        }
        let dir = std::env::temp_dir().join(format!("vg-rs-inc-{}", std::process::id()));
        unsafe { std::env::set_var("VELOGUARD_STATE", &dir) };
        let inc = save("test", "a title", json!({"x": 1}), false).unwrap();
        let f = dir.join("incidents").join(format!("{}.json", inc["id"].as_str().unwrap()));
        let back: Value = serde_json::from_str(&std::fs::read_to_string(&f).unwrap()).unwrap();
        for k in ["id", "ts", "iso", "kind", "title", "details"] {
            assert!(back.get(k).is_some(), "{k}");
        }
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o640);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
