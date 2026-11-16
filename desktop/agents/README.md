# VeloGuardOS agent plugin (Omarchy-style)

VeloGuard's **agentic workflows merged into Omarchy's agent model**: a default
"brain" you pick once and launch in a terminal — except the brain here drives
*the machine, through the guard*, not a code editor.

Installed to `/usr/share/veloguard/agents/`.

## Brains

| Brain | What it is | Setup |
|---|---|---|
| **claude** | Anthropic API — in the guard | `guardd key claude <KEY>` (or `$ANTHROPIC_API_KEY`) |
| **ollama** | a **local** model, private & free | `ollama serve` + `ollama pull <model>` |
| **claude-code** | Claude Code (agent plugin) | installed by the installer; sign in once: `claude` |
| **codex** | OpenAI Codex CLI (agent plugin) | `codex login` |
| **kimi** | Kimi Code CLI (agent plugin) | `kimi`, then `/login` |
| **hermes** | Nous Research Hermes Agent (agent plugin) | `hermes setup` |
| **openclaw** | OpenClaw (agent plugin) | `openclaw onboard` |

Any of them stands in for the others: `veloguard-agent set codex` (or the guard
menu ▸ *Switch AI agent…*) makes Codex the brain the guard reasons with —
intents, attack analysis, voice — and what Super+Shift+A opens.

### Agent plugins (`plugins/*.json`)

One JSON file per coding agent: where its binary lives, which of its home
folders it needs, how to ask it one question (`brain`) and how to open it
(`launch`). As the **brain**, an agent only answers — the guard still validates,
policy-checks, asks consent for and audits every action it proposes — and since
what it's asked contains attacker-chosen text (SSIDs, honeypot payloads), it
always runs with tools off where its CLI allows, inside a throwaway bubblewrap
sandbox: an empty home except its own config folders as discardable overlays,
read-only system, private /tmp, clean environment. No bubblewrap, no brain
(it never falls back to running unsandboxed). Check one: `veloguard-agent test codex`.

**Opened** (`veloguard-agent` with an agent as the default), it's the agent's own
app with the guard's MCP tools attached, and its `sudo` is VeloGuard's: every
root command is shown to you — agent, command, folder — with Approve/Deny
(`veloguard-elevate`; the dialog is drawn by a root helper on your verified
compositor, so the agent can't answer it). Delete
`/etc/polkit-1/rules.d/49-veloguard-elevate.rules` to require your password
on top of the click.

Installed by the installer (`provision/install-agents.sh`; anything it couldn't
finish is retried on the first online boot) or later: `veloguard-agent install kimi`.

Both are real in-guard brains (`guardd/ai_adapter.py`): the guard itself reasons
with them, and every action is still typed, policy-gated, consent-gated and
audited. Pick and launch Omarchy-style:

```bash
veloguard-agent set ollama            # persist the default brain (or: codex, kimi, …)
veloguard-agent                       # interactive agent console (Super+Shift+A)
veloguard-agent "raise the VPN and block 203.0.113.10"
```

## VeloGuard's plugin inside each agent

Every agent gets VeloGuard's own plugin (`veloguard-agent connect`, also run by
the installer), so the guard rides along however you open it:

| Agent | What goes in | The check before shell / file edits |
|---|---|---|
| **Claude Code** | `/plugin` ▸ *veloguard* (marketplace `claude-plugin/`, read in place): MCP tools, the skill, the rules in every session's system prompt, `/veloguard:diagnose`, `:investigate`, `:defend`, `:status` | `tool.check` hooks: refused, or put to you in Claude Code's own dialog |
| **Codex** | the portable Agent Plugin (`agent-plugin/`): MCP tools + skill | `~/.codex/hooks.json` PreToolUse (trust it once: `/hooks`) |
| **Hermes** | the portable plugin + a native one (`hermes-plugin/`) | `pre_tool_call` (fails closed on timeout) |
| **Kimi Code** | its config (`~/.kimi-code`: `mcp.json`, the skill, `[[hooks]]`) — Kimi installs plugins from its UI only | PreToolUse hook |
| **OpenClaw** | the portable plugin: MCP tools + skill | none (OpenClaw runs no bundle hooks) — its root commands still need your Approve |

**Defended by design** (`guardd/cmdguard.py`, one rule set for every agent and
for `veloguard-elevate`): an agent never switches off or rewrites the guard —
its services, nftables table, files, audit log, its own VeloGuard plugin;
those calls are refused with the reason. What malware typically does (a
script piped from the internet, persistence, disk wipes, a reverse shell) is
held for you. A guard that can't answer means no command.

### Hand it an error — or an incident

- **Super+Shift+E** (or guard menu ▸ *Ask an AI agent about an error…*): the
  text you copied, recent system errors, or the latest incident, to the agent
  you pick — through its plugin (`/veloguard:diagnose` in Claude Code).
  From a terminal: `some-command 2>&1 | veloguard-agent ask`.
- VeloGuard's own error notifications have **Ask an AI agent**.
- **If the guard catches something** (a honeypot attack, a quarantined
  process), it's saved as an incident (`veloguard incidents`) and diagnosed by
  your chosen brain — agents included, sandboxed — and the notification has
  **Investigate with an AI agent**: contain first with the guard's tools, then
  scope and report (`/veloguard:investigate`). The incident text is the
  attacker's: every hand-over frames it as data.

## Driving from an external coding agent (Claude Code, Codex, opencode)

Attach the guard over MCP so your existing coding agent drives the machine
through the guard:

```bash
veloguard-agent mcp                   # prints the MCP config below
```
```json
{ "mcpServers": { "veloguard": { "command": "veloguard-mcp",
    "env": { "VELOGUARD_AGENT_AUTONOMY": "guarded" } } } }
```

## Files

- `veloguard-mcp.json` — the MCP server config template.
- `plugins/<agent>.json` — the agent plugins (see above).
- `bin/sudo` — an agent's `sudo` → `veloguard-elevate` (Approve/Deny).
- `skills/veloguard-guard/SKILL.md` — an Omarchy-format skill teaching an agent
  how to drive the guard safely.

Launcher: `/usr/local/bin/veloguard-agent`. Keybind: `Super+Shift+A`.
