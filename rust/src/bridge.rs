//! The bridge to the Python guard, for the tools not ported yet.
//!
//! Firewall, VPN, quarantine, sandbox, incidents, memory and the signed
//! updater still live in guardd (policy → consent → HMAC-sealed executor →
//! audit). Rather than re-implement half of that, the Rust MCP server hands
//! those calls to guardd's own dispatch.execute_tool — the same road the
//! Python MCP server used. Each one moves into Rust (and off this bridge) when
//! its module is ported and passes the ported tests.

use crate::sys;
use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(300);
const CODE: &str = "import json, sys\n\
sys.path.insert(0, sys.argv[1])\n\
from guardd import dispatch\n\
args = json.loads(sys.stdin.read() or '{}')\n\
r = dispatch.execute_tool(sys.argv[2], args if isinstance(args, dict) else {}, apply=sys.argv[3] == '1',\n\
                          autonomy=sys.argv[4], source='mcp')\n\
sys.stdout.write(json.dumps(r))\n";

fn python() -> String {
    let home = crate::guard_home();
    let venv = std::env::var("VELOGUARD_VENV").map(std::path::PathBuf::from).unwrap_or_else(|_| home.join(".venv"));
    let vpy = venv.join("bin/python");
    if vpy.is_file() { vpy.to_string_lossy().into_owned() } else { "python3".into() }
}

pub fn call(name: &str, args: &Value, apply: bool, autonomy: &str) -> Value {
    let home = crate::guard_home();
    if !home.join("guardd/dispatch.py").is_file() {
        return json!({"ok": false, "status": "failed", "error": format!("the Python guard isn't at {}", home.display())});
    }
    let mut child = match Command::new(python())
        .args(["-I", "-c", CODE, &home.to_string_lossy(), name, if apply { "1" } else { "0" }, autonomy])
        .current_dir(&home).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
        Ok(c) => c,
        Err(e) => return json!({"ok": false, "status": "failed", "error": format!("couldn't start the Python guard: {e}")}),
    };
    if let Some(mut si) = child.stdin.take() {
        let _ = si.write_all(args.to_string().as_bytes());
    }
    // Read while it runs (a big answer must not fill the pipe and stall it).
    let pid = child.id() as libc::pid_t;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || { let _ = tx.send(child.wait_with_output()); });
    let out = match rx.recv_timeout(TIMEOUT) {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return json!({"ok": false, "status": "failed", "error": e.to_string()}),
        Err(_) => {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            return json!({"ok": false, "status": "failed", "error": "the Python guard didn't answer in 5 minutes"});
        }
    };
    match serde_json::from_slice::<Value>(&out.stdout) {
        Ok(v @ Value::Object(_)) => v,
        _ => json!({"ok": false, "status": "failed",
                    "error": format!("the Python guard failed: {}",
                                     sys::clip(String::from_utf8_lossy(&out.stderr).trim(), 800))}),
    }
}
