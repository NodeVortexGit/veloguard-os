# VeloGuard: Python → Rust

The decision (2026-11-21): all of the guard moves to Rust, module by module.
A Rust module replaces its Python one only once it passes the same tests
(ported to Rust, or run against the Rust binary from `veloguard/tests`), and
the Python one is deleted in the same change. Until then both stay, and the
MCP server hands not-yet-ported guard actions to Python (`src/bridge.rs`).

Build and test:

    cd rust && cargo build --release && cargo test --release
    cd ../veloguard && python3 -m unittest discover -s tests   # includes RustMCPServer

Deploy: `target/release/veloguard-integrity` → `/opt/veloguard/bin/veloguard-integrity`
(`veloguard integrity …` hands off to it when root-owned),
`target/release/veloguard-mcp` → `/opt/veloguard/bin/veloguard-mcp-rs`
(the `veloguard-mcp` launcher prefers it; `VELOGUARD_MCP_PYTHON=1` falls back),
`target/release/veloguard-ask` → `/opt/veloguard/bin/veloguard-ask` (the root
helper only uses it root-owned, not group/world-writable).

## Status

| Python (veloguard/…)                    | Rust (rust/…)            | State |
|-----------------------------------------|--------------------------|-------|
| guardd/mcp_server.py                    | src/mcp.rs               | **ported** — threaded calls, instructions, client identity |
| guardd/tools.py (registry)              | src/tools.rs             | **ported** |
| guardd/agentid.py                       | src/agentid.rs           | **ported** (Python kept: the root helper still uses it) |
| guardd/procs.py, osstate.py, elevation.py | src/procs.rs, osstate.rs, elevation.rs | **ported** (Python kept as the fallback server's) |
| guardd/approve.py                       | src/approve.rs           | **ported** (Python kept: the agent hooks use it) |
| guardd/audit.py (write side)            | src/audit.rs + pyjson.rs | **ported** — same hash chain, verified by the Python verifier in tests |
| zenity (dialogs)                        | ask/ (veloguard-ask)     | **new** — Esc = Deny, Ctrl+Enter = Approve |
| bin/veloguard-elevate-root              | —                        | next: needs cmdguard first |
| guardd/cmdguard.py                      | —                        | next (the rules the root helper and every hook use) |
| agent hooks (guard_hook.py, register.ts)| —                        | after cmdguard: one `veloguard-hook` binary |
| dispatch, actions, policy, authchan, executor | —                  | then: the guard actions (off the bridge) |
| guardd/integrity.py                     | src/integrity.rs (bin veloguard-integrity) | **ported** — also covers hidden plugin files (.mcp.json); a finding is audited first, never lost; Python kept as fallback until the ISO builds Rust |
| guardd/incident.py (save, announce)     | src/incident.rs          | **ported** — as root always the system store /var/lib/veloguard/incidents |
| incident (read side), memory, netclass, updater, state | —        | then |
| watch, honeypot, microvm, vlayer        | —                        | then |
| ai_adapter, analyst, agent, snn, voice, agent_plugins | —          | last (the AI plane) |
| __main__.py (the `veloguard` CLI)       | —                        | last, as subcommands of one binary |

Open item: the ISO build (`.github/workflows/build-iso.yml`) doesn't run cargo
yet — installs from a new ISO get the Python server until it does.
