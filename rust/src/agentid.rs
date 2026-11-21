//! Who is asking — the AI agent behind a request, read from the process tree.
//!
//! What an agent says about itself (VELOGUARD_AGENT, `--agent`, MCP
//! clientInfo) is a claim. This answers from /proc instead: walk up from the
//! requesting process to the nearest ancestor that IS a known agent's program
//! and describe it — product, version, process, start time, working folder and
//! how the request reached the guard. So a pop-up names "Codex 0.169.0 —
//! app-server, process 202479, started 01:13", never "a program".
//!
//! Limits: this is the user's own process tree; a program running as the user
//! can copy an agent's binary into an agent's install path. The program path
//! is part of the description so the person can spot an odd one. Package
//! metadata is read non-blocking, regular files only, at most 1 MiB (the root
//! helper will run this too).

use crate::sys;
use serde_json::{Value, json};
use std::os::unix::fs::OpenOptionsExt;

const MAX_DEPTH: usize = 64;
const META_MAX: u64 = 1 << 20;
const SHELLS: &[&str] = &["bash", "sh", "zsh", "dash", "fish", "env", "timeout", "nice", "nohup",
                          "pkexec", "sudo", "setsid", "script", "stdbuf", "xargs"];

#[derive(Clone, Debug)]
pub struct Proc {
    pub pid: i32,
    pub ppid: i32,
    pub start: String,
    pub uid: u32,
    pub exe: String,
    pub argv: Vec<String>,
}

pub fn proc_info(pid: i32) -> Option<Proc> {
    let raw = std::fs::read(format!("/proc/{pid}/stat")).ok()?;
    let raw = String::from_utf8_lossy(&raw);
    let after = &raw[raw.rfind(')')? + 2..];
    let f: Vec<&str> = after.split_whitespace().collect();
    let status = sys::read_text(&format!("/proc/{pid}/status"), 65536);
    let uid = status.lines().find(|l| l.starts_with("Uid:"))?.split_whitespace().nth(1)?.parse().ok()?;
    let argv = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let argv = argv.split(|b| *b == 0).filter(|a| !a.is_empty())
        .map(|a| String::from_utf8_lossy(a).into_owned()).collect();
    let exe = sys::readlink(&format!("/proc/{pid}/exe")).unwrap_or_default();
    Some(Proc {
        pid,
        ppid: f.get(1)?.parse().ok()?,
        start: f.get(19)?.to_string(),
        uid,
        exe: exe.trim_end_matches(" (deleted)").to_string(),
        argv,
    })
}

/// pid itself, then its parent, … up to (not including) init.
pub fn ancestors(mut pid: i32) -> Vec<Proc> {
    let mut out = Vec::new();
    while pid > 1 && out.len() < MAX_DEPTH {
        match proc_info(pid) {
            Some(p) => {
                pid = p.ppid;
                out.push(p);
            }
            None => break,
        }
    }
    out
}

/// A /proc start time (clock ticks since boot) as a Unix time.
pub fn started_at(start: &str) -> Option<f64> {
    let btime: f64 = sys::read_text("/proc/stat", 1 << 16).lines()
        .find(|l| l.starts_with("btime "))?.split_whitespace().nth(1)?.parse().ok()?;
    Some(btime + start.parse::<f64>().ok()? / sys::clk_tck())
}

fn is_version(v: &str) -> bool {
    // \d+(\.\d+){1,3}([.+-][0-9A-Za-z.]{1,30})?
    let (core, _) = v.split_once(['+', '-']).unwrap_or((v, ""));
    let parts: Vec<&str> = core.split('.').collect();
    (2..=6).contains(&parts.len()) && parts.iter().take(4).all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        && v.len() <= 48 && v.chars().all(|c| c.is_ascii_alphanumeric() || ".+-".contains(c))
}

fn small_json(path: &str) -> Option<serde_json::Map<String, Value>> {
    let f = std::fs::OpenOptions::new().read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY).open(path).ok()?;
    let md = f.metadata().ok()?;
    if !md.file_type().is_file() || md.len() > META_MAX {
        return None;
    }
    let mut buf = Vec::new();
    use std::io::Read;
    (&f).take(META_MAX).read_to_end(&mut buf).ok()?;
    match serde_json::from_slice(&buf).ok()? {
        Value::Object(m) => Some(m),
        _ => None,
    }
}

/// The "version" of the nearest package file above `path` (with a matching
/// "name" for package.json).
fn version_near(path: &str, names: &[&str], files: &[&str], levels: usize) -> Option<String> {
    let mut d = std::path::Path::new(path).parent()?.to_path_buf();
    for _ in 0..levels {
        for f in files {
            if let Some(m) = small_json(&d.join(f).to_string_lossy()) {
                let named = *f != "package.json" || names.is_empty()
                    || m.get("name").and_then(|n| n.as_str()).is_some_and(|n| names.contains(&n));
                let v = m.get("version").and_then(|v| v.as_str()).unwrap_or("");
                if named && is_version(v) {
                    return Some(v.split('+').next().unwrap_or(v).to_string());
                }
            }
        }
        if !d.pop() {
            break;
        }
    }
    None
}

fn script(argv: &[String]) -> String {
    argv.iter().skip(1).find(|a| !a.starts_with('-')).cloned().unwrap_or_default()
}

pub struct Recognised {
    pub label: &'static str,
    pub version: Option<String>,
    pub role: String,
}

/// This process is a known AI agent's program?
pub fn recognise(p: &Proc) -> Option<Recognised> {
    let name = p.exe.rsplit('/').next().unwrap_or("");
    let cmd = p.argv.join(" ");
    let args = if p.argv.is_empty() { &[][..] } else { &p.argv[1..] };
    let first = args.first().map(String::as_str).unwrap_or("");

    let claude_ver = p.exe.split_once("/.local/share/claude/versions/").map(|(_, v)| v.to_string());
    if claude_ver.as_deref().is_some_and(|v| !v.contains('/')) || name == "claude"
        || (cmd.contains("@anthropic-ai/claude-code") && (name.starts_with("node") || name.starts_with("bun"))) {
        let mut version = claude_ver.filter(|v| is_version(v));
        if version.is_none() && cmd.contains("@anthropic-ai/claude-code") {
            version = version_near(&script(&p.argv), &["@anthropic-ai/claude-code"], &["package.json"], 6);
        }
        let role = if first == "daemon" { "its background daemon" }
                   else if args.iter().any(|a| a.starts_with("--bg-")) { "a background session" } else { "" };
        return Some(Recognised { label: "Claude Code", version, role: role.into() });
    }
    if name == "codex" || name == "codex-cli" || name.starts_with("codex-") || cmd.contains("@openai/codex") {
        let mut version = version_near(&p.exe, &[], &["codex-package.json"], 3);
        if version.is_none() && cmd.contains("@openai/codex") {
            let s = script(&p.argv);
            version = version_near(if s.is_empty() { &p.exe } else { &s }, &["@openai/codex"], &["package.json"], 6);
        }
        let role = if first == "app-server" || p.exe.contains("/app-server-daemon/") {
            "its app-server — it serves every open Codex window"
        } else if name.starts_with("codex-code-mode") { "its code-mode runner" } else { "" };
        return Some(Recognised { label: "Codex", version, role: role.into() });
    }
    if name.starts_with("node") || name.starts_with("bun") || name.starts_with("deno") || name == "kimi" {
        let s = script(&p.argv);
        if cmd.contains("kimi-code") || p.exe.contains("/.kimi-code/") || name == "kimi" {
            return Some(Recognised { label: "Kimi Code", role: String::new(),
                version: version_near(&s, &["@moonshot-ai/kimi-code"], &["package.json"], 6) });
        }
        if cmd.contains("openclaw") {
            return Some(Recognised { label: "OpenClaw",
                role: if args.iter().any(|a| a == "gateway") { "its gateway".into() } else { String::new() },
                version: version_near(&s, &["openclaw"], &["package.json"], 6) });
        }
        if cmd.contains("@openai/codex") {
            return Some(Recognised { label: "Codex", role: String::new(),
                version: version_near(&s, &["@openai/codex"], &["package.json"], 6) });
        }
    }
    if name.starts_with("python") && (cmd.contains("hermes") || p.exe.contains("/.hermes/")) {
        return Some(Recognised { label: "Hermes Agent", version: None, role: String::new() });
    }
    None
}

fn when(epoch: Option<f64>) -> String {
    match epoch {
        None => String::new(),
        Some(t) if sys::same_day(t, sys::now()) => sys::strftime("%H:%M", t),
        Some(t) => sys::strftime("%b %d %H:%M", t),
    }
}

fn home_rel(path: &str, uid: u32) -> String {
    let home = sys::home_of(uid).unwrap_or_else(sys::home);
    if !path.is_empty() && home != "/" && (path == home || path.starts_with(&(home.clone() + "/"))) {
        format!("~{}", &path[home.len()..])
    } else {
        path.to_string()
    }
}

fn alnum_lower(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_lowercase()).collect()
}

fn generic(name: &str) -> bool {
    let a: String = name.chars().filter(|c| c.is_ascii_alphabetic()).map(|c| c.to_ascii_lowercase()).collect();
    ["", "aprogram", "anaiagent", "aiagent", "agent", "unknown", "program"].contains(&a.as_str())
}

fn is_mcp_server(p: &Proc) -> bool {
    p.argv.iter().take(4).any(|a| a.contains("guardd.mcp_server"))
        || p.exe.ends_with("/veloguard-mcp") || p.exe.ends_with("/veloguard-mcp-rs")
}

/// Who is behind process `pid` (an agent run by `uid`, when given).
#[derive(Clone, Debug, Default)]
pub struct Who {
    pub verified: bool,
    pub label: String,
    pub version: Option<String>,
    pub role: String,
    pub pid: i32,
    pub start: String,
    pub uid: Option<u32>,
    pub exe: String,
    pub started: String,
    pub cwd: String,
    pub via_mcp: bool,
    pub name: String,
    pub claimed: Option<String>,
    pub chain: String,
}

pub fn describe(pid: i32, claimed: Option<&str>, uid: Option<u32>) -> Who {
    let chain = ancestors(pid);
    let mut via_mcp = false;
    for p in &chain {
        if is_mcp_server(p) {
            via_mcp = true;
        }
        if let Some(r) = recognise(p) {
            if uid.is_some_and(|u| u != p.uid) {
                continue;
            }
            let name = match &r.version { Some(v) => format!("{} {v}", r.label), None => r.label.to_string() };
            let mut w = Who {
                verified: true, label: r.label.into(), version: r.version, role: r.role, pid: p.pid,
                start: p.start.clone(), uid: Some(p.uid), exe: p.exe.clone(),
                started: when(started_at(&p.start)),
                cwd: home_rel(&sys::readlink(&format!("/proc/{}/cwd", p.pid)).unwrap_or_default(), p.uid),
                via_mcp, name, ..Default::default()
            };
            if let Some(c) = claimed.filter(|c| !generic(c)) {
                if !alnum_lower(c).contains(&alnum_lower(&w.label)) {
                    w.claimed = Some(c.chars().take(60).collect());
                }
            }
            return w;
        }
    }
    // No agent above it: name the exact program that asked.
    let req = chain.iter()
        .find(|p| !SHELLS.contains(&p.exe.rsplit('/').next().unwrap_or("")) && !is_mcp_server(p))
        .or(chain.first());
    let exe = req.map(|p| p.exe.clone()).unwrap_or_default();
    let base = exe.rsplit('/').next().filter(|b| !b.is_empty()).unwrap_or("unknown program").to_string();
    Who {
        verified: false,
        label: "a program that isn't a known AI agent".into(),
        pid: req.map(|p| p.pid).unwrap_or(pid),
        start: req.map(|p| p.start.clone()).unwrap_or_default(),
        uid: req.map(|p| p.uid),
        started: req.map(|p| when(started_at(&p.start))).unwrap_or_default(),
        cwd: req.map(|p| home_rel(&sys::readlink(&format!("/proc/{}/cwd", p.pid)).unwrap_or_default(), p.uid))
            .unwrap_or_default(),
        exe,
        via_mcp,
        name: format!("{base} (not a known AI agent)"),
        claimed: claimed.filter(|c| !generic(c)).map(|c| c.chars().take(60).collect()),
        chain: chain.iter().take(5).map(|p| p.exe.rsplit('/').next().unwrap_or("?").to_string())
            .collect::<Vec<_>>().join(" ← "),
        ..Default::default()
    }
}

/// Who the current process works for (the MCP server).
pub fn me(claimed: Option<&str>) -> Who {
    describe(std::process::id() as i32, claimed, Some(sys::uid()))
}

impl Who {
    /// 'Codex 0.169.0 — process 202479 (its app-server …), started 01:13,
    /// working in ~, through the VeloGuard MCP server'
    pub fn one_line(&self) -> String {
        let mut bits = vec![format!("process {}{}", self.pid,
                                    if self.role.is_empty() { String::new() } else { format!(" ({})", self.role) })];
        if !self.started.is_empty() {
            bits.push(format!("started {}", self.started));
        }
        if !self.cwd.is_empty() {
            bits.push(format!("working in {}", self.cwd));
        }
        bits.push(if self.via_mcp { "through the VeloGuard MCP server" } else { "through a command in its shell" }.into());
        let mut s = format!("{} — {}", self.name, bits.join(", "));
        if let Some(c) = &self.claimed {
            s += &format!("; it calls itself “{c}”");
        }
        if !self.verified && !self.chain.is_empty() {
            s += &format!("; process chain: {}", self.chain);
        }
        s
    }

    /// The 'who is asking' block for a zenity dialog (Pango, escaped).
    pub fn pango(&self) -> String {
        let e = sys::escape;
        let mut l = vec![
            "<b>Who is asking</b> (read from the process tree, not taken on its word):".to_string(),
            format!("• {}{}", e(&self.name), if self.role.is_empty() { String::new() } else { format!(" — {}", e(&self.role)) }),
            format!("• process {}{}{}", self.pid,
                    if self.started.is_empty() { String::new() } else { format!(", started {}", e(&self.started)) },
                    if self.cwd.is_empty() { String::new() } else { format!(", working in <tt>{}</tt>", e(&self.cwd)) }),
            format!("• program <tt>{}</tt>", e(if self.exe.is_empty() { "?" } else { &self.exe })),
            format!("• asked {}", if self.via_mcp { "through the VeloGuard MCP server" } else { "through a command in its shell (sudo)" }),
        ];
        if let Some(c) = &self.claimed {
            l.push(format!("• <span foreground='#f5a623'>it calls itself “{}” — that doesn't match the program above</span>", e(c)));
        }
        if !self.verified {
            l.push(format!("• <span foreground='#e01b24'>not a known AI agent</span>{}",
                           if self.chain.is_empty() { String::new() } else { format!(" (chain: {})", e(&self.chain)) }));
        }
        format!("<small>{}</small>", l.join("\n"))
    }

    pub fn to_json(&self) -> Value {
        json!({"verified": self.verified, "label": self.label, "version": self.version, "role": self.role,
               "pid": self.pid, "started": self.started, "cwd": self.cwd, "exe": self.exe,
               "via": if self.via_mcp { "mcp" } else { "shell" }, "name": self.name,
               "claimed": self.claimed, "as_the_guard_sees_you": self.one_line()})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(exe: &str, argv: &[&str]) -> Proc {
        Proc { pid: 2, ppid: 1, start: "0".into(), uid: 1000, exe: exe.into(),
               argv: argv.iter().map(|s| s.to_string()).collect() }
    }

    #[test]
    fn recognises_the_agents_by_their_programs() {
        let r = recognise(&p("/home/u/.local/share/claude/versions/2.1.330", &["claude", "--resume", "x"])).unwrap();
        assert_eq!((r.label, r.version.as_deref()), ("Claude Code", Some("2.1.330")));
        let r = recognise(&p("/home/u/.codex/packages/app-server-daemon/releases/x/bin/codex", &["codex", "app-server"])).unwrap();
        assert_eq!(r.label, "Codex");
        assert!(r.role.contains("app-server"));
        let r = recognise(&p("/usr/bin/node", &["node", "--x=1", "/h/.local/lib/node_modules/openclaw/dist/index.js", "gateway"])).unwrap();
        assert_eq!((r.label, r.role.as_str()), ("OpenClaw", "its gateway"));
        assert!(recognise(&p("/usr/bin/bash", &["bash"])).is_none());
        assert!(recognise(&p("/usr/bin/python3", &["python3", "-m", "http.server"])).is_none());
    }

    #[test]
    fn versions_are_strict() {
        assert!(is_version("2.1.330"));
        assert!(is_version("0.169.0+arch.1"));
        assert!(is_version("2026.11.3"));
        assert!(!is_version("latest"));
        assert!(!is_version("1"));
        assert!(!is_version("1.2.3<script>"));
    }

    #[test]
    fn claims_are_kept_only_when_they_dont_match() {
        assert!(generic("an AI agent") && generic("a program") && !generic("Codex"));
        assert!(alnum_lower("codex-mcp-client 0.169").contains(&alnum_lower("Codex")));
        assert!(alnum_lower("claude-code").contains(&alnum_lower("Claude Code")));
    }

    #[test]
    fn describes_this_test_process() {
        let w = me(Some("Totally Codex"));
        assert!(w.pid > 1);
        assert!(!w.one_line().is_empty());
        assert!(w.pango().starts_with("<small>"));
    }
}
