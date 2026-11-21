//! Root for AI agents, over MCP — sudo_run, sudo_grant, sudo_status,
//! sudo_revoke, sudo_result, and ask_permission.
//!
//! The agent never gets root itself. Every request goes the one road root
//! goes on VeloGuardOS: veloguard-elevate → pkexec → veloguard-elevate-root,
//! which reads WHO is asking from the process tree, shows the exact command,
//! the folder and the agent's own reason on the person's real screen, and runs
//! nothing until they click Approve. sudo_grant: the agent picks how long (at
//! most 4 h), the person approves once, and that one agent's later root
//! commands run without a dialog — never the ones that switch the guard off.
//!
//! Never freezing the agent: the dialog waits up to 2 minutes; MCP clients
//! give up on a call much sooner (Codex: 60 s). A call waits at most
//! `wait_seconds` (default 40), then answers {"status": "pending",
//! "request_id"}; the request carries on and sudo_result collects it.
//! Output is capped: first 16 KiB + last 48 KiB of each stream.

use crate::agentid::{self, Who};
use crate::{approve, audit, osstate, sys};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const DEFAULT_WAIT: u64 = 40;
pub const MAX_WAIT: u64 = 55;
const DEFAULT_TIMEOUT: u64 = 600;
const MAX_TIMEOUT: u64 = 6 * 3600;
const HEAD: usize = 16 * 1024;
const TAIL: usize = 48 * 1024;
const INPUT_MAX: usize = 1 << 20;
const KEEP: usize = 32;
const MARK: &str = "VELOGUARD-ELEVATE ";

/// Who is calling, and from where — set once by the MCP server.
#[derive(Clone, Default)]
pub struct Ctx {
    pub who: Option<Who>,
    pub client: Map<String, Value>,
    pub cwd: Option<String>,
}

impl Ctx {
    /// What this agent calls itself, in the shape --agent accepts.
    pub fn claimed(&self) -> String {
        let c = &self.client;
        let mut name = c.get("title").or(c.get("name")).and_then(Value::as_str).map(str::to_string)
            .or_else(|| std::env::var("VELOGUARD_AGENT").ok()).unwrap_or_else(|| "an AI agent".into());
        if let Some(v) = c.get("version").and_then(Value::as_str) {
            name = format!("{name} {v}");
        }
        let n: String = name.chars().filter(|c| c.is_ascii_alphanumeric() || " ._+-".contains(*c)).take(40).collect();
        let n = n.trim().to_string();
        if n.is_empty() { "an AI agent".into() } else { n }
    }

    pub fn who(&self) -> Who {
        self.who.clone().unwrap_or_else(|| agentid::me(Some(&self.claimed())))
    }
}

pub fn elevate_bin() -> String {
    std::env::var("VELOGUARD_ELEVATE").ok().filter(|s| !s.is_empty())
        .or_else(|| sys::which("veloguard-elevate"))
        .unwrap_or_else(|| "/usr/local/bin/veloguard-elevate".into())
}

// --- capped output --------------------------------------------------------------

#[derive(Default)]
struct Capped {
    head: Vec<u8>,
    tail: Vec<u8>,
    total: usize,
}

impl Capped {
    fn add(&mut self, mut b: &[u8]) {
        self.total += b.len();
        let room = HEAD.saturating_sub(self.head.len());
        if room > 0 {
            let n = room.min(b.len());
            self.head.extend_from_slice(&b[..n]);
            b = &b[n..];
        }
        if !b.is_empty() {
            self.tail.extend_from_slice(b);
            if self.tail.len() > TAIL {
                let cut = self.tail.len() - TAIL;
                self.tail.drain(..cut);
            }
        }
    }

    fn text(&self) -> (String, bool) {
        let kept = self.head.len() + self.tail.len();
        let cut = self.total > kept;
        let mid = if cut { format!("\n…[{} bytes cut]…\n", self.total - kept) } else { String::new() };
        (format!("{}{mid}{}", String::from_utf8_lossy(&self.head), String::from_utf8_lossy(&self.tail)), cut)
    }
}

// --- requests -------------------------------------------------------------------

struct Req {
    id: String,
    kind: &'static str,
    what: String,
    started: Instant,
    state: Mutex<(Option<Value>, Option<Map<String, Value>>)>, // (result, the helper's decision line)
    cv: Condvar,
}

impl Req {
    fn finish(&self, v: Value) {
        let mut s = self.state.lock().unwrap();
        s.0 = Some(v);
        self.cv.notify_all();
    }

    fn decision(&self) -> Option<String> {
        self.state.lock().unwrap().1.as_ref().and_then(|d| d.get("decision")?.as_str().map(str::to_string))
    }

    fn is_done(&self) -> bool {
        self.state.lock().unwrap().0.is_some()
    }
}

fn registry() -> &'static Mutex<HashMap<String, Arc<Req>>> {
    static R: OnceLock<Mutex<HashMap<String, Arc<Req>>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(HashMap::new()))
}

static IDS: AtomicU64 = AtomicU64::new(1);

fn new_req(kind: &'static str, what: String) -> Arc<Req> {
    let id = format!("r{}-{}", IDS.fetch_add(1, Ordering::SeqCst), (sys::now() as u64) % 100000);
    let r = Arc::new(Req { id: id.clone(), kind, what, started: Instant::now(),
                           state: Mutex::new((None, None)), cv: Condvar::new() });
    let mut reg = registry().lock().unwrap();
    reg.insert(id, r.clone());
    if reg.len() > KEEP {
        let mut done: Vec<(Instant, String)> = reg.values().filter(|r| r.is_done()).map(|r| (r.started, r.id.clone())).collect();
        done.sort();
        for (_, id) in done.into_iter().take(reg.len() - KEEP) {
            reg.remove(&id);
        }
    }
    r
}

fn await_req(req: &Arc<Req>, wait: u64) -> Value {
    let deadline = Duration::from_secs(wait.min(MAX_WAIT));
    let guard = req.state.lock().unwrap();
    let (guard, _) = req.cv.wait_timeout_while(guard, deadline, |s| s.0.is_none()).unwrap();
    if let Some(v) = guard.0.clone() {
        drop(guard);
        registry().lock().unwrap().remove(&req.id);
        let mut v = v;
        v["request_id"] = Value::from(req.id.clone());
        return v;
    }
    let dec = guard.1.as_ref().and_then(|d| d.get("decision")?.as_str().map(str::to_string));
    drop(guard);
    let waiting = match (req.kind, dec.as_deref()) {
        ("command", Some("approved")) => "the command to finish (it was approved)",
        (_, None) => "the person's answer on screen (Approve / Deny, up to 2 minutes)",
        _ => "it to finish",
    };
    json!({"ok": false, "status": "pending", "request_id": req.id, "kind": req.kind, "waiting_for": waiting,
           "seconds_so_far": req.started.elapsed().as_secs(),
           "next": format!("call sudo_result with request_id \"{}\" (it can wait up to {MAX_WAIT} s)", req.id)})
}

type Parse = Box<dyn FnOnce(&Req, i32, String, String, bool) -> Value + Send>;

fn spawn(req: Arc<Req>, argv: Vec<String>, cwd: String, stdin: Option<Vec<u8>>, parse: Parse) {
    std::thread::spawn(move || {
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..]).current_dir(&cwd).env("PWD", &cwd)
            .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped()).stderr(Stdio::piped());
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                req.finish(json!({"ok": false, "status": "failed", "error": format!("couldn't start {}: {e}", argv[0])}));
                return;
            }
        };
        let out = Arc::new(Mutex::new(Capped::default()));
        let err = Arc::new(Mutex::new(Capped::default()));
        let mut so = child.stdout.take().unwrap();
        let se = child.stderr.take().unwrap();
        let o2 = out.clone();
        let t1 = std::thread::spawn(move || {
            let mut buf = [0u8; 65536];
            while let Ok(n) = so.read(&mut buf) {
                if n == 0 { break; }
                o2.lock().unwrap().add(&buf[..n]);
            }
        });
        let (e2, r2) = (err.clone(), req.clone());
        let t2 = std::thread::spawn(move || {
            let mut rd = BufReader::new(se);
            let mut line = Vec::new();
            while let Ok(n) = rd.read_until(b'\n', &mut line) {
                if n == 0 { break; }
                let is_mark = line.starts_with(MARK.as_bytes());
                if is_mark {
                    if let Ok(Value::Object(m)) = serde_json::from_slice::<Value>(line[MARK.len()..].trim_ascii()) {
                        r2.state.lock().unwrap().1 = Some(m);
                    }
                } else {
                    e2.lock().unwrap().add(&line);
                }
                line.clear();
            }
        });
        if let (Some(data), Some(mut si)) = (stdin, child.stdin.take()) {
            let _ = si.write_all(&data);
        }
        let rc = child.wait().map(|s| s.code().unwrap_or(1)).unwrap_or(1);
        let _ = t1.join();
        let _ = t2.join();
        let (o, oc) = out.lock().unwrap().text();
        let (e, ec) = err.lock().unwrap().text();
        let v = parse(&req, rc, o, e, oc || ec);
        req.finish(v);
    });
}

fn decision_or_polkit(req: &Req, rc: i32, err: &str) -> Map<String, Value> {
    if let Some(d) = req.state.lock().unwrap().1.clone() {
        return d;
    }
    let (dec, how) = if err.contains("Not authorized") || err.contains("Error executing command as another user") || rc == 126 {
        ("refused", "polkit refused to start the approval helper (not an active local admin session?)")
    } else if rc == 127 {
        ("failed", "the approval helper (veloguard-elevate / pkexec) is missing")
    } else {
        ("unknown", "the approval helper gave no decision")
    };
    let mut m = Map::new();
    m.insert("decision".into(), Value::from(dec));
    m.insert("how".into(), Value::from(how));
    m
}

// --- argument helpers -------------------------------------------------------------

pub fn num(a: &Value, key: &str, default: u64, lo: u64, hi: u64) -> Result<u64, String> {
    let v = match a.get(key) {
        None | Some(Value::Null) => return Ok(default.clamp(lo, hi)),
        Some(Value::Number(n)) => n.as_f64().ok_or(format!("{key} must be a number"))?,
        Some(Value::String(s)) => s.trim().parse::<f64>().map_err(|_| format!("{key} must be a number"))?,
        _ => return Err(format!("{key} must be a number")),
    };
    Ok((v.max(0.0) as u64).clamp(lo, hi))
}

pub fn text(a: &Value, key: &str, limit: usize, required: bool) -> Result<String, String> {
    let s = match a.get(key) {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.trim().to_string(),
        _ => return Err(format!("{key} must be a string")),
    };
    if required && s.is_empty() {
        return Err(format!("{key} is required"));
    }
    if s.chars().count() > limit {
        return Err(format!("{key} is too long (at most {limit} characters)"));
    }
    Ok(s)
}

/// A shell-like split for agents that send a command line instead of argv.
fn split_words(s: &str) -> Result<Vec<String>, String> {
    let (mut out, mut cur, mut q, mut any) = (vec![], String::new(), None::<char>, false);
    let mut it = s.chars();
    while let Some(c) = it.next() {
        match (q, c) {
            (None, ' ' | '\t' | '\n') => { if any { out.push(std::mem::take(&mut cur)); any = false; } }
            (None, '\'' | '"') => { q = Some(c); any = true; }
            (Some(x), _) if c == x => q = None,
            (None | Some('"'), '\\') => { if let Some(n) = it.next() { cur.push(n); any = true; } }
            _ => { cur.push(c); any = true; }
        }
    }
    if q.is_some() {
        return Err("unbalanced quote in command".into());
    }
    if any {
        out.push(cur);
    }
    Ok(out)
}

fn command(a: &Value) -> Result<Vec<String>, String> {
    let err = || "command must be a non-empty list of strings, e.g. [\"pacman\", \"-S\", \"git\"]".to_string();
    let v: Vec<String> = match a.get("command") {
        Some(Value::String(s)) => split_words(s)?,
        Some(Value::Array(xs)) => xs.iter().map(|x| x.as_str().map(str::to_string).ok_or_else(err)).collect::<Result<_, _>>()?,
        _ => return Err(err()),
    };
    if v.is_empty() || v.iter().any(|x| x.is_empty()) {
        return Err(err());
    }
    if v.iter().any(|x| x.contains('\0')) {
        return Err("command contains a NUL byte".into());
    }
    Ok(v)
}

fn cwd(a: &Value, ctx: &Ctx) -> Result<String, String> {
    let c = a.get("cwd").and_then(Value::as_str).map(str::to_string)
        .or_else(|| ctx.cwd.clone()).unwrap_or_else(sys::home);
    std::fs::canonicalize(&c).ok().filter(|p| p.is_dir()).map(|p| p.to_string_lossy().into_owned())
        .ok_or(format!("cwd {c:?} is not a folder"))
}

fn shown(cmd: &[String]) -> String {
    cmd.iter().map(|w| {
        if !w.is_empty() && w.chars().all(|c| c.is_ascii_alphanumeric() || "@%+=:,./-_".contains(c)) { w.clone() }
        else { format!("'{}'", w.replace('\'', "'\"'\"'")) }
    }).collect::<Vec<_>>().join(" ")
}

fn audit_op(ctx: &Ctx, mut entry: Value) {
    let w = ctx.who();
    entry["control"] = "mcp-root".into();
    entry["source"] = "mcp".into();
    entry["agent"] = w.name.clone().into();
    entry["who"] = w.one_line().into();
    audit::record(entry);
}

// --- the tools ------------------------------------------------------------------------

pub fn sudo_run(a: &Value, ctx: &Ctx) -> Result<Value, String> {
    let cmd = command(a)?;
    let cwd = cwd(a, ctx)?;
    let reason = text(a, "reason", 300, false)?;
    let timeout = num(a, "timeout_seconds", DEFAULT_TIMEOUT, 1, MAX_TIMEOUT)?;
    let wait = num(a, "wait_seconds", DEFAULT_WAIT, 0, MAX_WAIT)?;
    let input = match a.get("input") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.len() > INPUT_MAX => return Err("input is larger than 1 MiB — write it to a file and pass the path".into()),
        Some(Value::String(s)) if s.is_empty() => None,
        Some(Value::String(s)) => Some(s.as_bytes().to_vec()),
        _ => return Err("input must be a string".into()),
    };
    let mut argv = vec![elevate_bin(), "--agent".into(), ctx.claimed(), "--report".into(), "--timeout".into(), timeout.to_string()];
    if !reason.is_empty() {
        argv.extend(["--reason".into(), reason.clone()]);
    }
    argv.push("--".into());
    argv.extend(cmd.iter().cloned());
    audit_op(ctx, json!({"tool": "sudo_run", "argv": cmd, "cwd": cwd, "reason": reason, "result": "asked"}));
    let req = new_req("command", shown(&cmd));
    spawn(req.clone(), argv, cwd, input, Box::new(|req, rc, out, err, cut| {
        let d = decision_or_polkit(req, rc, &err);
        let dec = d.get("decision").and_then(Value::as_str).unwrap_or("failed").to_string();
        if dec == "approved" {
            let mut v = json!({"ok": rc == 0, "status": "done", "approved": d.get("how"), "exit_code": rc,
                               "stdout": out, "stderr": err});
            if cut { v["truncated"] = true.into(); }
            if rc == 124 && v["stderr"].as_str().unwrap_or("").contains("time limit") {
                v["status"] = "stopped_at_time_limit".into();
            }
            return v;
        }
        let hint = match dec.as_str() {
            "denied" => "The person said no. Take that as the answer — don't retry it, rephrase it or look for another way to root.",
            "timeout" => "Nobody answered within 2 minutes (that counts as a Deny). Ask the person in the chat before trying again.",
            "no_desktop" => "No desktop session to show the question on — the person has to run it themselves in a terminal.",
            _ => "",
        };
        let mut v = json!({"ok": false, "status": dec, "how": d.get("how"), "exit_code": rc});
        if !hint.is_empty() { v["hint"] = hint.into(); }
        if !["denied", "timeout"].contains(&dec.as_str()) && !err.is_empty() {
            v["stderr"] = err.chars().rev().take(2000).collect::<String>().chars().rev().collect::<String>().into();
        }
        v
    }));
    Ok(await_req(&req, wait))
}

/// "45m", "2h", "1h30m" (or a bare number = minutes) → the helper's form.
pub fn duration(v: Option<&Value>) -> Result<String, String> {
    let err = || "duration like \"45m\", \"2h\" or \"1h30m\" (at most 4h)".to_string();
    let s = match v {
        Some(Value::Number(n)) => format!("{}m", n.as_f64().ok_or_else(err)? as u64),
        Some(Value::String(s)) => s.to_lowercase().replace([' ', '\t'], "").replace("min", "m"),
        _ => return Err(err()),
    };
    let (h, rest) = match s.split_once('h') { Some((h, r)) => (Some(h), r), None => (None, s.as_str()) };
    let m = if rest.is_empty() { None } else { Some(rest.strip_suffix('m').ok_or_else(err)?) };
    let ok = |x: Option<&str>| x.is_none_or(|x| !x.is_empty() && x.chars().all(|c| c.is_ascii_digit()));
    if (h.is_none() && m.is_none()) || !ok(h) || !ok(m) {
        return Err(err());
    }
    let mins = h.map_or(0, |h| h.parse::<u64>().unwrap_or(0) * 60) + m.map_or(0, |m| m.parse::<u64>().unwrap_or(0));
    if mins == 0 {
        return Err("the grant needs at least 1 minute".into());
    }
    Ok(s)
}

pub fn sudo_grant(a: &Value, ctx: &Ctx) -> Result<Value, String> {
    let dur = duration(a.get("duration"))?;
    let reason = text(a, "reason", 300, true)?;
    let wait = num(a, "wait_seconds", DEFAULT_WAIT, 0, MAX_WAIT)?;
    let argv = vec![elevate_bin(), "--agent".into(), ctx.claimed(), "--report".into(), "--reason".into(), reason.clone(),
                    "--grant".into(), dur.clone()];
    audit_op(ctx, json!({"tool": "sudo_grant", "duration": dur, "reason": reason, "result": "asked"}));
    let req = new_req("grant", format!("grant {dur}"));
    spawn(req.clone(), argv, sys::home(), None, Box::new(|req, rc, _out, err, _cut| {
        let d = decision_or_polkit(req, rc, &err);
        let dec = d.get("decision").and_then(Value::as_str).unwrap_or("failed");
        if dec == "granted" {
            let secs = d.get("seconds").and_then(Value::as_u64).unwrap_or(0);
            let asked = d.get("asked_seconds").and_then(Value::as_u64).unwrap_or(secs);
            let mut v = json!({"ok": true, "status": "granted", "minutes": secs / 60,
                "expires": sys::strftime("%H:%M", d.get("expires").and_then(Value::as_f64).unwrap_or(0.0)),
                "covers": format!("process {} and everything it starts — sudo_run (and `sudo` in your shell) now run \
                                   without a dialog, except anything that would switch the guard off",
                                  d.get("pid").cloned().unwrap_or(Value::Null))});
            if asked > secs {
                v["note"] = format!("you asked for {} min; the most VeloGuard gives is 4 h", asked / 60).into();
            }
            return v;
        }
        let mut v = json!({"ok": false, "status": dec, "how": d.get("how")});
        if dec == "denied" {
            v["hint"] = "The person said no — work without root, or ask in the chat.".into();
        } else if dec != "timeout" {
            v["stderr"] = err.chars().take(1500).collect::<String>().into();
        }
        v
    }));
    Ok(await_req(&req, wait))
}

pub fn sudo_status(_a: &Value, ctx: &Ctx) -> Result<Value, String> {
    let w = ctx.who();
    let grant = osstate::grant_info().map(|g| {
        let mine = agentid::ancestors(std::process::id() as i32).iter().any(|a| {
            Some(a.pid as i64) == g.get("pid").and_then(Value::as_i64) && Some(a.start.as_str()) == g.get("start").and_then(Value::as_str)
        });
        json!({"holder": g.get("who").or(g.get("agent")),
               "minutes_left": ((g["expires"].as_f64().unwrap_or(0.0) - sys::now()) / 60.0) as i64, "covers_you": mine})
    });
    let reqs: Vec<Value> = registry().lock().unwrap().values().map(|r| json!({
        "request_id": r.id, "kind": r.kind, "what": r.what.chars().take(200).collect::<String>(),
        "seconds": r.started.elapsed().as_secs(),
        "state": if r.is_done() { "finished — collect with sudo_result" }
                 else if r.decision().as_deref() == Some("approved") { "approved, running" } else { "waiting for the person" }
    })).collect();
    Ok(json!({"ok": true, "you": {"as_the_guard_sees_you": w.one_line(), "verified": w.verified, "pid": w.pid,
                                  "calls_itself": ctx.claimed()},
              "root_grant": grant, "requests": reqs,
              "how_root_works": "sudo_run shows the person your exact command (and who you are) with Approve/Deny; \
                                 sudo_grant asks once for a time window."}))
}

pub fn sudo_revoke(_a: &Value, ctx: &Ctx) -> Result<Value, String> {
    let bin = elevate_bin();
    let claimed = ctx.claimed();
    let out = Command::new(&bin).args(["--agent", &claimed, "--report", "--revoke"])
        .stdin(Stdio::null()).output().map_err(|e| format!("couldn't run {bin}: {e}"))?;
    let ok = out.status.success();
    audit_op(ctx, json!({"tool": "sudo_revoke", "result": if ok { "done" } else { "failed" }}));
    let msg = String::from_utf8_lossy(if out.stdout.is_empty() { &out.stderr } else { &out.stdout }).lines()
        .filter(|l| !l.starts_with(MARK)).collect::<Vec<_>>().join("\n");
    Ok(json!({"ok": ok, "status": if ok { "revoked" } else { "failed" }, "message": msg.trim()}))
}

pub fn sudo_result(a: &Value, _ctx: &Ctx) -> Result<Value, String> {
    let id = text(a, "request_id", 40, true)?;
    let wait = num(a, "wait_seconds", DEFAULT_WAIT, 0, MAX_WAIT)?;
    let req = registry().lock().unwrap().get(&id).cloned();
    Ok(match req {
        Some(r) => await_req(&r, wait),
        None => json!({"ok": false, "status": "unknown_request",
                       "error": format!("no request {id} (already collected, or the MCP server restarted)")}),
    })
}

pub fn ask_permission(a: &Value, ctx: &Ctx) -> Result<Value, String> {
    let question = text(a, "question", 500, true)?;
    let details = text(a, "details", 1200, false)?;
    let wait = num(a, "wait_seconds", DEFAULT_WAIT, 0, MAX_WAIT)?;
    let w = ctx.who();
    let req = new_req("question", question.clone());
    let r2 = req.clone();
    std::thread::spawn(move || {
        let (ok, how) = approve::ask_question(&w.name, &question, &details, Some(&w));
        audit::record(json!({"control": "agent-approval", "source": "mcp", "agent": w.name, "who": w.one_line(),
                             "class": "question", "what": question, "details": details,
                             "result": if ok { "approved" } else { "denied" }, "how": how}));
        let mut v = json!({"ok": ok, "status": if ok { "approved" } else { "denied" }, "how": how});
        if !ok {
            v["hint"] = "Take a Deny as the answer; don't ask again for the same thing.".into();
        }
        r2.finish(v);
    });
    Ok(await_req(&req, wait))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_the_agent_may_pick() {
        assert_eq!(duration(Some(&json!("45m"))).unwrap(), "45m");
        assert_eq!(duration(Some(&json!("1h 30min"))).unwrap(), "1h30m");
        assert_eq!(duration(Some(&json!("2h"))).unwrap(), "2h");
        assert_eq!(duration(Some(&json!(90))).unwrap(), "90m");
        for bad in [json!("3"), json!("0m"), json!("forever"), json!("1h30"), json!(true), json!("h")] {
            assert!(duration(Some(&bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn commands_are_argv() {
        assert_eq!(command(&json!({"command": ["pacman", "-S", "git"]})).unwrap(), ["pacman", "-S", "git"]);
        assert_eq!(command(&json!({"command": "tee '/etc/a b' \"x y\""})).unwrap(), ["tee", "/etc/a b", "x y"]);
        assert!(command(&json!({"command": []})).is_err());
        assert!(command(&json!({"command": ["a", 1]})).is_err());
        assert!(command(&json!({"command": "echo 'unterminated"})).is_err());
        assert_eq!(shown(&["echo".into(), "a b".into(), "it's".into()]), "echo 'a b' 'it'\"'\"'s'");
    }

    #[test]
    fn output_is_capped_head_and_tail() {
        let mut c = Capped::default();
        c.add(&vec![b'a'; HEAD + TAIL + 1000]);
        let (t, cut) = c.text();
        assert!(cut && t.contains("[1000 bytes cut]"));
    }

    #[test]
    fn claimed_names_are_cleaned() {
        let mut ctx = Ctx::default();
        ctx.client.insert("title".into(), "Codex <x>".into());
        ctx.client.insert("version".into(), "0.169.0".into());
        assert_eq!(ctx.claimed(), "Codex x 0.169.0");
    }

    #[test]
    fn a_stub_helper_round_trip_and_pending() {
        // A stand-in for veloguard-elevate: report a decision, then act.
        let dir = std::env::temp_dir().join(format!("vg-rs-elev-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let stub = dir.join("veloguard-elevate");
        std::fs::write(&stub, "#!/bin/bash\nfor a; do [ \"$a\" = -- ] && break; shift; done; shift\n\
            [ \"$1\" = slow ] && sleep 3\necho 'VELOGUARD-ELEVATE {\"decision\": \"approved\", \"how\": \"by you\"}' >&2\n\
            echo out-$*; echo err-line >&2; exit 3\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        unsafe { std::env::set_var("VELOGUARD_ELEVATE", &stub) };
        unsafe { std::env::set_var("VELOGUARD_AUDIT_LOG", dir.join("audit.log")) };
        let ctx = Ctx::default();
        let v = sudo_run(&json!({"command": ["fast", "x"], "reason": "test", "cwd": "/"}), &ctx).unwrap();
        assert_eq!(v["status"], "done", "{v}");
        assert_eq!(v["exit_code"], 3);
        assert_eq!(v["stdout"], "out-fast x\n");
        assert_eq!(v["stderr"], "err-line\n");
        let p = sudo_run(&json!({"command": ["slow"], "reason": "test", "cwd": "/", "wait_seconds": 0}), &ctx).unwrap();
        assert_eq!(p["status"], "pending");
        let id = p["request_id"].as_str().unwrap().to_string();
        let r = sudo_result(&json!({"request_id": id, "wait_seconds": 10}), &ctx).unwrap();
        assert_eq!(r["status"], "done", "{r}");
        assert_eq!(sudo_result(&json!({"request_id": id}), &ctx).unwrap()["status"], "unknown_request");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
