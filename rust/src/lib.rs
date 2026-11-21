//! VeloGuardOS's guard, in Rust.
//!
//! The port from Python (veloguard/guardd) goes module by module; a Rust
//! module replaces its Python one only once it passes the same tests (see
//! rust/PORTING.md). Until a guard action is ported, the MCP server hands it to
//! the Python guard unchanged (bridge.rs) — one road to the kernel either way.

use std::path::PathBuf;

pub mod agentid;
pub mod approve;
pub mod audit;
pub mod bridge;
pub mod elevation;
pub mod mcp;
pub mod osstate;
pub mod procs;
pub mod pyjson;
pub mod sys;
pub mod tools;

/// The guard's install dir (holds guardd/ and policy.json): $VELOGUARD_HOME,
/// else the dir above this binary (/opt/veloguard/bin/x → /opt/veloguard),
/// else /opt/veloguard.
pub fn guard_home() -> PathBuf {
    if let Ok(h) = std::env::var("VELOGUARD_HOME") {
        if !h.is_empty() {
            return PathBuf::from(h);
        }
    }
    if let Some(home) = std::env::current_exe().ok().and_then(|e| e.canonicalize().ok())
        .and_then(|e| e.parent().and_then(|b| b.parent()).map(|p| p.to_path_buf())) {
        if home.join("guardd").is_dir() {
            return home;
        }
    }
    PathBuf::from("/opt/veloguard")
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
