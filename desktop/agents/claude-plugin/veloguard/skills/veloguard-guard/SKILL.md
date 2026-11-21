---
name: veloguard-guard
description: Drive VeloGuardOS through its guard — block IPs, raise the VPN, quarantine or sandbox processes, check signed updates — safely, via the guard's MCP tools or the built-in agent loop.
---

# Driving VeloGuardOS through the guard

VeloGuardOS exposes every kernel-level capability as a **typed, guarded tool**.
You (an AI agent) never touch the kernel directly: each tool call becomes an
Action that passes `validate → policy → consent → execute → audit`. A policy
`DENY` always blocks (you cannot block loopback or the local LAN, even at full
autonomy), the updater stays fail-closed, and every call is written to the audit
log. Work *with* that guard — never try to bypass it.

## Two ways to drive it

1. **MCP (recommended for coding agents like Claude Code / Codex / opencode).**
   Attach the guard's MCP server; add to your agent's MCP config (`./.mcp.json`):
   ```json
   { "mcpServers": { "veloguard": { "command": "veloguard-mcp",
       "env": { "VELOGUARD_AGENT_AUTONOMY": "guarded" } } } }
   ```
   or run `veloguard-agent mcp` to print it.

2. **The built-in agent loop** (local, no coding-agent needed):
   ```bash
   veloguard-agent set ollama          # or: claude   (local vs API brain)
   veloguard-agent "lock down: block 203.0.113.10 and raise the VPN"
   ```

## Tools

Guard actions (policy + consent): `block_ip`, `unblock_ip`, `vpn_up`,
`vpn_down`, `quarantine`, `release_quarantine`, `kill_quarantine`, `sandbox_run`.
Read-only (always safe): `status`, `classify_network`, `check_update`, `recall`,
`list_blocked`, `incidents`.

**Root, with the person's Approve** — `sudo_run` (one command: exact argv +
your reason), `sudo_grant` (ask once for a time window you choose, at most 4 h),
`sudo_status` (who the guard sees you as, grant, pending requests),
`sudo_result` (collect a pending request), `sudo_revoke`, `ask_permission`
(a yes/no question on the person's screen; grants nothing).
The dialog names you as the guard reads you from the process tree — product,
version, process, folder — not by what you call yourself.

**Processes** — `process_list`, `process_info` (read); `process_signal`,
`process_priority` (your own processes; the guard, you yourself, other agents
and the desktop session's essentials go to the person).

**OS state** — `system_state` (CPU, memory, pressure stalls, disks, temps,
battery, failed units, the guard), `network_state`, `services`, `journal`
(read); `service_control` for your own `--user` units.

## Autonomy

- `read` — mutating tools disabled.
- `guarded` (default) — protective actions run; destructive ones need a yes.
- `full` — destructive actions auto-approved (the session is standing consent);
  policy DENY still blocks and everything is still audited.

## Rules for a well-behaved agent

- Only act on an IP or target the **user actually named** — never invent one
  (the guard discards invented IPs, but don't rely on it).
- Prefer the least-destructive action; if a tool is denied or needs approval,
  adapt or explain — do not attempt a workaround.
- When the goal is met, stop and summarize what you did.

## Root commands: ask with `sudo_run` (or `sudo`)

Prefer the MCP tool `sudo_run` — it works in every agent (Codex's shell
sandbox can't start a root helper), never hangs your session, and returns the
exit code and output. A call waits at most `wait_seconds` (default 40); if the
person hasn't answered by then you get `"status": "pending"` and a
`request_id` — call `sudo_result` with it. For a long job while they're away,
ask once with `sudo_grant` ("45m", "2h" — the shortest the work needs) and say
what you'll do with it.

The dialog: **Esc = Deny, Ctrl+Enter = Approve** (armed after 1 s), Enter =
Deny, no answer in 2 minutes = Deny.

### `sudo` in your shell asks the user too

Opened through `veloguard-agent`, your `sudo` is VeloGuard's: each command is
shown to the user — your name, the exact command, the folder — with
**Approve / Deny** (Deny is the default; no answer in 2 minutes is a Deny), and
every request is audited. There is no password to supply and nothing to cache.

- Run one root command per `sudo`, exactly the command you need; say *why*
  before you run it, so the user knows what they're approving.
- `sudo -i` / `sudo -s` (root shells) are refused — use `sudo <command>`.
  Long pipelines: put them in a script and `sudo bash script.sh`.
- If it's denied, that's the user's answer: don't retry it, rephrase it, or
  look for another way to root. Ask, or carry on without it.
- Prefer the guard's MCP tools over `sudo` for anything they cover (firewall,
  VPN, quarantine) — those are typed, policy-checked and need no root shell.
