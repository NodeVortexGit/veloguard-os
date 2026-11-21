//! Approve / Deny — the person decides what the guard would restrict.
//!
//! The non-root half (drawn as the person): a desktop pop-up with what the
//! agent wants, who it is (read from the process tree) and why it was stopped.
//! Deny is the default; no answer within the timeout is a Deny. Root commands
//! keep their own dialog, drawn by root (veloguard-elevate-root).
//! Shares guardd/approve.py's lock ($XDG_RUNTIME_DIR/veloguard/ask.lock): one
//! question at a time, whichever language asks.

use crate::agentid::Who;
use crate::sys::{self, escape as e};
use std::os::unix::io::AsRawFd;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const TIMEOUT: u64 = 90;

fn session_env() -> Vec<(String, String)> {
    let uid = sys::uid();
    let rt = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| format!("/run/user/{uid}"));
    let mut env = vec![("XDG_RUNTIME_DIR".to_string(), rt.clone())];
    let wl = std::env::var("WAYLAND_DISPLAY").ok().filter(|s| !s.is_empty());
    let x = std::env::var("DISPLAY").ok().filter(|s| !s.is_empty());
    if wl.is_none() && x.is_none() {
        let mut socks: Vec<String> = std::fs::read_dir(&rt).map(|r| r.flatten()
            .map(|d| d.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("wayland-") && n.len() == 9 && n.as_bytes()[8].is_ascii_digit()).collect())
            .unwrap_or_default();
        socks.sort();
        if let Some(s) = socks.first() {
            env.push(("WAYLAND_DISPLAY".into(), s.clone()));
        }
    }
    if std::env::var("DBUS_SESSION_BUS_ADDRESS").is_err() {
        env.push(("DBUS_SESSION_BUS_ADDRESS".into(), format!("unix:path={rt}/bus")));
    }
    env
}

/// VeloGuard's own dialog (rust/ask: Esc = Deny, Ctrl+Enter = Approve), else zenity.
pub fn dialog_program() -> String {
    let ask = crate::guard_home().join("bin/veloguard-ask");
    let c = std::ffi::CString::new(ask.as_os_str().as_encoded_bytes()).unwrap_or_default();
    if unsafe { libc::access(c.as_ptr(), libc::X_OK) } == 0 { ask.to_string_lossy().into_owned() } else { "zenity".into() }
}

pub fn can_ask() -> bool {
    if std::env::var_os("VELOGUARD_NO_ASK").is_some() {
        return false; // tests, headless runs: nobody to ask → Deny
    }
    let env = session_env();
    let has = |k: &str| std::env::var(k).ok().filter(|s| !s.is_empty()).is_some() || env.iter().any(|(n, _)| n == k);
    (dialog_program() != "zenity" || sys::which("zenity").is_some()) && (has("WAYLAND_DISPLAY") || has("DISPLAY"))
}

fn class_line(cls: &str) -> Option<(&'static str, &'static str)> {
    match cls {
        "disable" => Some(("#e01b24", "This switches off part of VeloGuard itself (its services, firewall, audit trail or this agent's guard plugin).")),
        "tamper" => Some(("#e01b24", "This changes VeloGuard's own files.")),
        "malware" => Some(("#f5a623", "This is something malware (or a steered agent) does.")),
        "secret" => Some(("#f5a623", "This reads credentials — keys, tokens, cookies or passwords.")),
        "self" => Some(("#e01b24", "This stops the agent itself — its session ends.")),
        _ => None,
    }
}

pub fn text_for(agent: &str, what: &str, reason: &str, cls: &str, cwd: Option<&str>, who: Option<&Who>) -> String {
    let mut t = format!("<b>{}</b> wants to do something VeloGuard normally doesn't let an agent do:\n\n<tt>{}</tt>\n",
                        e(if agent.is_empty() { "An AI agent" } else { agent }), e(&sys::clip(what, 700)));
    if let Some(c) = cwd.filter(|c| !c.is_empty()) {
        t += &format!("\nin <tt>{}</tt>\n", e(c));
    }
    t += &format!("\nWhy it was stopped: it {}.\n", e(if reason.is_empty() { "is restricted" } else { reason }));
    if let Some((color, line)) = class_line(cls) {
        t += &format!("<span foreground='{color}'><b>{}</b></span>\n", e(line));
    }
    if let Some(w) = who {
        t += &format!("\n{}\n", w.pango());
    }
    t + "\nApprove only if you asked for exactly this. No answer = Deny."
}

pub fn question_text(agent: &str, question: &str, details: &str, who: Option<&Who>) -> String {
    let mut t = format!("<b>{}</b> asks for your permission:\n\n<i>{}</i>\n",
                        e(if agent.is_empty() { "An AI agent" } else { agent }), e(&sys::clip(question, 500)));
    if !details.is_empty() {
        t += &format!("\n<tt>{}</tt>\n", e(&sys::clip(details, 1200)));
    }
    if let Some(w) = who {
        t += &format!("\n{}\n", w.pango());
    }
    t + "\n<small>These are the agent's own words. Approving answers its question; it gives it no new access — \
         root still asks separately.</small>\n\nNo answer = Deny."
}

/// (approved?, how it was decided). Never panics; anything odd is a Deny.
pub fn ask(agent: &str, what: &str, reason: &str, cls: &str, cwd: Option<&str>, who: Option<&Who>) -> (bool, String) {
    dialog(&format!("VeloGuard — {} asks", if agent.is_empty() { "an AI agent" } else { agent }),
           &text_for(agent, what, reason, cls, cwd, who), TIMEOUT, "dialog-warning")
}

pub fn ask_question(agent: &str, question: &str, details: &str, who: Option<&Who>) -> (bool, String) {
    dialog(&format!("VeloGuard — {} asks your permission", if agent.is_empty() { "an AI agent" } else { agent }),
           &question_text(agent, question, details, who), TIMEOUT, "dialog-question")
}

fn dialog(title: &str, text: &str, timeout: u64, icon: &str) -> (bool, String) {
    if !can_ask() {
        return (false, "no desktop to ask on".into());
    }
    let env = session_env();
    let rt = env.iter().find(|(k, _)| k == "XDG_RUNTIME_DIR").map(|x| x.1.clone()).unwrap_or_default();
    let dir = format!("{rt}/veloguard");
    use std::os::unix::fs::DirBuilderExt;
    let _ = std::fs::DirBuilder::new().mode(0o700).recursive(true).create(&dir);
    let Ok(lock) = std::fs::OpenOptions::new().write(true).create(true).truncate(false).open(format!("{dir}/ask.lock")) else {
        return (false, "couldn't open the approval lock".into());
    };
    let deadline = Instant::now() + Duration::from_secs(timeout);
    // One dialog at a time: a burst of requests queues, it doesn't stack.
    while unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        if Instant::now() > deadline {
            return (false, "timed out waiting for an earlier question".into());
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    let left = deadline.saturating_duration_since(Instant::now()).as_secs().max(10);
    let title: String = title.chars().take(120).collect();
    let mut cmd = Command::new(dialog_program());
    cmd.args(["--question", "--title", &title, "--text", text, "--width", "580", "--ok-label", "Approve",
              "--cancel-label", "Deny", "--default-cancel", "--icon", icon, &format!("--timeout={left}")])
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    for (k, v) in &env {
        cmd.env(k, v);
    }
    let code = match cmd.spawn() {
        Ok(mut child) => {
            let end = Instant::now() + Duration::from_secs(left + 15);
            loop {
                match child.try_wait() {
                    Ok(Some(st)) => break st.code().unwrap_or(-1),
                    Ok(None) if Instant::now() < end => std::thread::sleep(Duration::from_millis(50)),
                    _ => {
                        let _ = child.kill();
                        let _ = child.wait();
                        break -1;
                    }
                }
            }
        }
        Err(_) => -1,
    };
    drop(lock);
    match code {
        0 => (true, "approved by the person".into()),
        5 => (false, "no answer (timed out)".into()),
        -1 => (false, "the dialog didn't answer".into()),
        _ => (false, "denied by the person".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn everything_shown_is_escaped() {
        let t = text_for("<b>", "rm <x>", "y", "disable", Some("/tmp"), None);
        assert!(t.contains("&lt;b&gt;") && t.contains("rm &lt;x&gt;") && !t.contains("<b><"));
        let q = question_text("Codex", "Delete <b>build</b>?", "rm -rf build", None);
        assert!(q.contains("Delete &lt;b&gt;build&lt;/b&gt;?"));
    }

    #[test]
    fn nobody_to_ask_is_a_deny() {
        // SAFETY of the test: only this test touches the variable.
        unsafe { std::env::set_var("VELOGUARD_NO_ASK", "1") };
        assert!(!can_ask());
        assert_eq!(ask("T", "x", "y", "", None, None).0, false);
    }
}
