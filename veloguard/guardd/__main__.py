"""VeloGuard daemon CLI — run security intents, and hot-swap the AI core.

Two kinds of command:

  RUN an intent (goes through AI -> guard -> kernel):
    python3 -m guardd "block 203.0.113.10"
    python3 -m guardd --apply --yes "block 203.0.113.10"     # for real, no prompt

  CONTROL the core (hot-swap — takes effect on the very next intent):
    python3 -m guardd use ollama                   # a LOCAL model via Ollama (private, free)
    python3 -m guardd use claude                   # Anthropic API (needs a key)
    python3 -m guardd use snn                       # the built-in local SNN brain
    python3 -m guardd use mock                      # offline keyword fallback
    python3 -m guardd key claude sk-ant-...         # store the Claude API key (chmod 600)
    python3 -m guardd host ollama http://127.0.0.1:11434
    python3 -m guardd model ollama llama3.1         # pick the model (or SNN weights path)
    python3 -m guardd status                        # what's active

  PROTECT:
    python3 -m guardd net --ssid Cafe --security open   # classify wifi, auto-VPN
    python3 -m guardd honeypot --analyze --block        # decoy + AI diagnosis
    python3 -m guardd analyze <captures.jsonl>          # diagnose a saved capture
    python3 -m guardd run-safe ./sketchy.AppImage       # run isolated (AI picks tier)
    python3 -m guardd update check --json               # signed update check (agent)
    python3 -m guardd update apply --domain veloguard --apply

  AGENTIC (full control via API, through the guard):
    python3 -m guardd agent --autonomy full "lock down: block 203.0.113.10, vpn up"
    python3 -m guardd mcp                                # MCP server for Claude Code/Codex
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
from pathlib import Path

from . import (__version__, agent, analyst, honeypot, memory, netclass, state,
               updater, vlayer, voice)
from .actions import Action, ActionType
from .ai_adapter import get_adapter
from .audit import record
from .executor import VPN_HELPER, NftExecutor
from .policy import Decision, PolicyEngine, Verdict

VELOGUARD_DIR = Path(__file__).resolve().parent.parent
DEFAULT_POLICY_PATH = VELOGUARD_DIR / "policy.json"
CONFIG_PATH = VELOGUARD_DIR / "config.json"

CONTROL_VERBS = {"setup", "use", "model", "key", "host", "status",
                 "providers", "net", "honeypot", "analyze", "run-safe",
                 "update", "agent", "agents", "check-command", "incidents", "integrity",
                 "audit", "mcp", "voice", "approve", "watch", "detonate",
                 "help"}


def _configured_adapter() -> str:
    """Factory-default adapter from config.json (runtime state overrides it)."""
    try:
        return json.loads(CONFIG_PATH.read_text()).get("adapter", "mock")
    except (OSError, json.JSONDecodeError):
        return "mock"


# ===========================================================================
# SETUP SCREEN — first-boot wizard (a friendly front-end over use/key/model)
# ===========================================================================

def _boxed(*lines: str) -> str:
    """A box drawn around `lines`, its width computed from them — the old
    hand-drawn banner had text rows one column wider than its borders, so the
    right edge stuck out. (Every character here is single-width.)"""
    inner = max(len(line) for line in lines) + 4
    rows = [f"│  {line.ljust(inner - 2)}│" for line in lines]
    return "\n".join([f"┌{'─' * inner}┐", *rows, f"└{'─' * inner}┘"])


_BANNER = ("\n\033[1;36m"
           + _boxed("VeloGuardOS  ·  setup", "AI-first. Local-only brain. Nothing leaves.")
           + "\033[0m")


def _ask(prompt: str, default: str | None = None) -> str:
    suffix = f" \033[2m[{default}]\033[0m" if default else ""
    try:
        val = input(f"{prompt}{suffix}: ").strip()
    except EOFError:
        val = ""
    return val or (default or "")


def _choose(prompt: str, options: list[tuple[str, str]], default: int = 1) -> str:
    """Numbered menu. Returns the chosen option key. Accepts the number or key."""
    print(prompt)
    for i, (_, label) in enumerate(options, 1):
        print(f"   \033[1m{i}\033[0m) {label}")
    keys = {k for k, _ in options}
    while True:
        raw = _ask("  >", str(default))
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1][0]
        if raw.lower() in keys:
            return raw.lower()
        print("  please pick a number from the list.")


def _test_connection(provider: str) -> bool:
    from .ai_adapter import get_adapter
    print(f"  testing {provider} …")
    try:
        adapter = get_adapter(provider, **state.adapter_config(provider))
        action = adapter.parse("block 203.0.113.10")
        print(f"  \033[1;32m✓\033[0m ok — test intent parsed as: {action.type.value}")
        return True
    except Exception as e:
        print(f"  \033[1;31m✗\033[0m failed: {e}")
        return False


def _setup_snn() -> None:
    path = _ask("\n  SNN model path (blank = default, set later with "
                "'guardd model snn <path>')")
    if path:
        state.set_model("snn", path)
    state.set_active("snn")
    record({"control": "setup", "plane": "snn",
            "model": path or None, "result": "ok"})
    print("\n  → SNN plane selected — in-process, nothing leaves this machine.")
    print("    (model code pending: intents will say so until it lands in guardd/snn.py)")


def _setup_claude() -> None:
    print("\n  Claude (Anthropic API) — most capable brain. Only the intent/"
          "prompt leaves the box; the key is stored chmod 600 and never logged.")
    key = _ask("  API key (blank keeps existing / uses $ANTHROPIC_API_KEY)")
    if key:
        state.set_key("claude", key)
    model = _ask("  model", state.model_for("claude"))
    if model:
        state.set_model("claude", model)
    state.set_active("claude")
    record({"control": "setup", "plane": "claude",
            "model": state.model_for("claude"), "result": "ok"})
    print("  → Claude plane selected.")


def _setup_ollama() -> None:
    print("\n  Ollama (LOCAL model) — private, free, offline. Needs `ollama serve` "
          "running and the model pulled (`ollama pull <model>`).")
    host = _ask("  host", state.host_for("ollama"))
    if host:
        state.set_host("ollama", host)
    model = _ask("  model", state.model_for("ollama"))
    if model:
        state.set_model("ollama", model)
    state.set_active("ollama")
    record({"control": "setup", "plane": "ollama",
            "model": state.model_for("ollama"), "result": "ok"})
    print("  → Ollama plane selected — nothing leaves this machine.")


def _setup_agent(name: str) -> None:
    """An AI agent as the brain: install it if needed, sign in once, connect
    VeloGuard's plugin into it (tools, rules, the check), make it active."""
    import shutil
    import subprocess
    from . import agent_plugins
    pl = agent_plugins.get(name)
    print(f"\n  {pl.label} ({pl.vendor}) — as the brain it answers in a throwaway sandbox with "
          "its tools off; opened (Super+Shift+A) it's its own app with VeloGuard's plugin.")
    if not agent_plugins.status(pl)["installed"]:
        if _ask(f"  {pl.label} isn't installed. Install it now? [Y/n]", "Y").lower() in ("y", "yes"):
            subprocess.run(["veloguard-agent", "install", name], check=False)
        if not agent_plugins.status(agent_plugins.get(name))["installed"]:
            print(f"  ✗ not installed — later: veloguard-agent install {name}")
            return
    if shutil.which("veloguard-agent-connect"):
        subprocess.run(["veloguard-agent-connect", name], check=False)
    if pl.signin and _ask(f"  Sign in to {pl.label} now ({pl.signin})? [Y/n]", "Y").lower() in ("y", "yes"):
        exe = pl.find_bin(os.path.expanduser("~"))
        cmd = pl.signin.split("(")[0].split()
        if exe and cmd:
            subprocess.run([exe, *cmd[1:]], check=False)
    state.set_active(name)
    record({"control": "setup", "plane": name, "result": "ok"})
    print(f"\n  → {pl.label} is the brain. Change it any time: veloguard-agent pick (or guard menu ▸ Switch AI agent…)")


def _setup_wizard() -> int:
    print(_BANNER)
    if not sys.stdin.isatty():
        print("\033[2m(non-interactive input — reading answers from stdin)\033[0m")

    from . import agent_plugins
    agents = []
    for pl in agent_plugins.load_all().values():
        st = agent_plugins.status(pl)
        tag = "installed" if st["installed"] else "not installed yet — installs now"
        agents.append((pl.name, f"{pl.label:<12} — AI agent ({pl.vendor}), via its plugin · {tag}"))
    plane = _choose("\nChoose your AI plane (the brain the guard thinks with):", [
        ("ollama", "Ollama       — a LOCAL model, private & free (needs `ollama serve`)"),
        ("claude", "Claude API   — Anthropic API, most capable (needs an API key)"),
        *agents,
        ("snn",    "SNN          — VeloGuard's built-in local neural brain (lands soon)"),
        ("mock",   "Mock         — offline keyword mode; deterministic, works today"),
    ], default=len(agents) + 4)

    if state.is_agent(plane):
        _setup_agent(plane)
    elif plane == "mock":
        state.set_active("mock")
        record({"control": "setup", "plane": "mock", "result": "ok"})
        print("\n  → offline mock mode. Run 'guardd setup' again any time.")
    elif plane == "claude":
        _setup_claude()
    elif plane == "ollama":
        _setup_ollama()
    else:
        _setup_snn()

    active = state.active_provider(config_default=_configured_adapter())
    if (active in ("mock", "claude", "ollama") or state.is_agent(active)) \
            and _ask("\nTest the brain now? [Y/n]", "Y").lower() in ("y", "yes"):
        _test_connection(active)

    # Voice assistant wake word (optional; engines via provision/install-voice.sh)
    ww = _ask("\nVoice assistant wake word (blank to skip)", "hey guard")
    if ww:
        memory.set_pref("wake_word", ww)
        print(f"  wake word: '{ww}'  (install voice engines: sudo provision/install-voice.sh)")

    if _ask("\nInitialize the VeloGuard firewall table now? [y/N]", "N").lower() in ("y", "yes"):
        as_root = os.geteuid() == 0
        if not as_root:
            print("  (not root — showing what it WOULD do; re-run with sudo to apply)")
        for line in NftExecutor(apply=as_root).setup():
            print("  " + line)

    print("\n\033[1;32m── setup complete ──\033[0m")
    _control(["status"])
    return 0


# ===========================================================================
# NETWORK AUTO-PROTECT — classify the Wi-Fi, bring the VPN up if untrusted
# ===========================================================================

def _vpn_up_through_guard(ex: NftExecutor, profile: str, note: str) -> str:
    """Run VPN_UP through the policy engine (auto-allowed) + audit it.

    The executor self-protects: it refuses to raise a tunnel with no real
    endpoint and rolls back one that comes up dead. Surface that as a clean,
    audited message instead of a traceback — this path runs unattended from the
    NetworkManager dispatcher, where failing safe must not mean killing the net."""
    action = Action(ActionType.VPN_UP, {"target": profile} if profile else {})
    try:
        action.validate()          # the profile comes from a stored pref
    except ValueError as exc:
        record({"control": "net", "action": "vpn_up", "target": profile,
                "result": "invalid", "error": str(exc), "note": note})
        return f"VPN not applied — {exc}"
    decision = PolicyEngine.shared(DEFAULT_POLICY_PATH).evaluate(action)
    if decision.verdict == Verdict.DENY:
        return f"VPN blocked by policy: {decision.reason}"
    # Was a tunnel already carrying the traffic? Then it isn't ours to drop
    # later; only a VPN raised HERE is marked auto-started (trusting the
    # network takes that one down again — see veloguard-vpn drop-auto).
    was_up = ex.apply and _vpn_helper("active")
    try:
        out, result = ex.vpn_up(action.params.get("target")), "executed"
    except (RuntimeError, ValueError) as exc:
        out, result = f"VPN not applied — {exc}", "failed"
    if ex.apply and result == "executed" and not was_up:
        _vpn_helper("mark-auto", note)
    record({"control": "net", "action": "vpn_up", "target": profile,
            "result": result, "output": out, "note": note})
    return out


def _vpn_helper(*args: str) -> bool:
    """Run bin/veloguard-vpn quietly; True on exit 0. Never raises."""
    import subprocess
    try:
        return subprocess.run([VPN_HELPER, *args], capture_output=True,
                              timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _net(rest: list[str]) -> int:
    p = argparse.ArgumentParser(prog="guardd net",
                                description="classify a network and auto-protect")
    p.add_argument("--ssid")
    p.add_argument("--bssid")
    p.add_argument("--security", help="e.g. wpa2, wpa3, open")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--yes", action="store_true", help="non-interactive: safe default")
    args = p.parse_args(rest)

    verdict, reason = netclass.classify(args.ssid, args.bssid, args.security)
    label = args.ssid or args.bssid or "(unknown)"
    print(f"network '{label}': {verdict} — {reason}")
    memory.log_decision("network", label, verdict, reason)
    ex = NftExecutor(apply=args.apply)
    profile = memory.get_pref("vpn_profile", "veloguard")

    if verdict == "trusted":
        print("  trusted — no VPN needed.")
        return 0
    if verdict == "untrusted":
        print("  untrusted → auto-protecting (no questions).")
        print("  " + _vpn_up_through_guard(ex, profile, f"auto on {label}"))
        return 0

    # unknown: ask the human if we can; otherwise fail safe (protect).
    if sys.stdin.isatty() and not args.yes:
        ans = input(f"  trust '{label}'? [y/N] ").strip().lower()
        if ans in ("y", "yes"):
            memory.set_network_trust(args.ssid, args.bssid, args.security, "trusted")
            print("  remembered as trusted — no VPN.")
            return 0
        memory.set_network_trust(args.ssid, args.bssid, args.security, "untrusted")
    else:
        print("  non-interactive → failing safe.")
    print("  " + _vpn_up_through_guard(ex, profile, f"unknown net {label}"))
    return 0


# ===========================================================================
# HONEYPOT — decoy listeners + AI attack diagnosis
# ===========================================================================

def _active_adapter():
    """Build the currently-active AI plane; (None, provider, model) on failure."""
    provider = state.active_provider(config_default=_configured_adapter())
    cfg = state.adapter_config(provider)
    try:
        return get_adapter(provider, **cfg), provider, cfg.get("model")
    except (ValueError, RuntimeError) as e:
        print(f"  (AI analysis disabled: {e})", file=sys.stderr)
        return None, provider, cfg.get("model")


def _lan_neighbours_to_keep() -> set[str]:
    """Never block these, whatever they did: the gateway(s), the DNS servers,
    this machine's own addresses."""
    import subprocess as sp
    keep: set[str] = set()
    for fam in ("-4", "-6"):
        try:
            for r in json.loads(sp.run(["ip", "-j", fam, "route", "show", "default"], capture_output=True,
                                       text=True, timeout=5).stdout or "[]"):
                if r.get("gateway"):
                    keep.add(r["gateway"])
            for a in json.loads(sp.run(["ip", "-j", fam, "addr"], capture_output=True,
                                       text=True, timeout=5).stdout or "[]"):
                for i in a.get("addr_info", []):
                    keep.add(i.get("local", ""))
        except (OSError, ValueError, sp.SubprocessError):
            pass
    try:
        for line in Path("/etc/resolv.conf").read_text().splitlines():
            if line.startswith("nameserver"):
                keep.add(line.split()[1])
        out = sp.run(["resolvectl", "dns"], capture_output=True, text=True, timeout=5).stdout
        keep.update(re.findall(r"(\d+\.\d+\.\d+\.\d+|[0-9a-f:]{3,})", out))
    except (OSError, sp.SubprocessError):
        pass
    return keep


def _lan_blockable(ip: str) -> bool:
    """A honeypot visitor on the local network (where nearly all of a laptop's
    probes come from: public Wi-Fi, a compromised device at home) may be
    blocked even though private ranges are protected for everything else —
    except the gateway, DNS and our own addresses, which never are."""
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if not a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified:
        return False
    return ip not in _lan_neighbours_to_keep()


def _auto_block(ex: NftExecutor, ip: str) -> str:
    """Protective auto-block of a confirmed attacker (the --block flag is consent)."""
    action = Action(ActionType.BLOCK_IP, {"ip": ip})
    try:
        action.validate()
    except ValueError as e:
        return f"not blocked: {e}"
    engine = PolicyEngine.shared(DEFAULT_POLICY_PATH)
    decision = engine.evaluate(action)          # protected ranges + rate limit
    if decision.verdict == Verdict.DENY and not _lan_blockable(ip):
        return f"not blocked: {decision.reason}"
    try:
        out = ex.block_ip(action.params["ip"])
    except RuntimeError as e:
        record({"control": "honeypot", "action": "block_ip", "params": action.params,
                "result": "failed", "error": str(e)})
        return f"not blocked: {e}"
    engine.record(action)                        # count it toward the rate limit
    record({"control": "honeypot", "action": "block_ip", "params": action.params,
            "result": "executed", "output": out})
    return out


def _honeypot(rest: list[str]) -> int:
    p = argparse.ArgumentParser(prog="guardd honeypot")
    p.add_argument("--ports", default="2222,8080,2323",
                   help="comma-separated decoy ports (default high ports, no root)")
    p.add_argument("--analyze", action="store_true",
                   help="have the active AI diagnose each captured attack")
    p.add_argument("--block", action="store_true",
                   help="auto-block the attacker's IP (protective)")
    p.add_argument("--apply", action="store_true",
                   help="actually touch nftables for --block (needs root)")
    args = p.parse_args(rest)
    sys.stdout.reconfigure(line_buffering=True)  # live output for a long-runner
    ports = [int(x) for x in args.ports.split(",") if x.strip()]

    adapter = provider = model = None
    if args.analyze:
        adapter, provider, model = _active_adapter()
        if adapter:
            tier = analyst.analysis_tier(provider, model)
            print(f"  AI analysis: {provider}/{model or '-'} → '{tier}' tier"
                  + ("  ★ local high-end bonus" if tier == "deep" else ""))
    ex = NftExecutor(apply=args.apply)

    def on_capture(cap: dict) -> None:
        print(f"\n[capture] {cap['service']} from {cap['src_ip']}:{cap['src_port']}"
              f"  {cap['bytes']}B")
        memory.log_decision("honeypot", cap["src_ip"], "captured",
                            f"{cap['service']} {cap['bytes']}B")
        rep = None
        if adapter:
            rep = analyst.analyze_capture(cap, adapter, provider, model)
            print(f"  ── AI diagnosis ({rep['tier']}) ──\n  "
                  + rep["report"].replace("\n", "\n  "))
        blocked = _auto_block(ex, cap["src_ip"]) if args.block else None
        if blocked:
            print("  " + blocked)
        # An incident the person (and the agent they pick) can look into.
        from . import incident
        incident.save("honeypot",
                      f"{cap['service']} attack from {cap['src_ip']} ({cap['bytes']} B)",
                      {"capture": cap, "diagnosis": rep, "auto_block": blocked})

    print(f"VeloGuard honeypot starting on ports {ports}")
    honeypot.run(ports, on_capture)
    return 0


def _analyze(rest: list[str]) -> int:
    p = argparse.ArgumentParser(prog="guardd analyze")
    p.add_argument("capture", help="a capture .json or .jsonl file from the honeypot")
    args = p.parse_args(rest)
    text = Path(args.capture).read_text().strip()
    last = [ln for ln in text.splitlines() if ln.strip()][-1] if text else "{}"
    try:
        cap = json.loads(last)
    except json.JSONDecodeError as e:
        print(f"bad capture file: {e}", file=sys.stderr)
        return 2
    adapter, provider, model = _active_adapter()
    if not adapter:
        return 2
    rep = analyst.analyze_capture(cap, adapter, provider, model)
    print(f"── AI diagnosis ({rep['tier']} · {provider}/{model or '-'}) ──")
    print(rep["report"])
    return 0


# ===========================================================================
# AGENT — autonomous loop: give the active AI a goal, it drives the tools
# ===========================================================================

def _agent(rest: list[str]) -> int:
    autonomy, apply, max_steps = "guarded", False, 8
    if "--apply" in rest:
        apply = True; rest = [a for a in rest if a != "--apply"]
    if "--autonomy" in rest:
        i = rest.index("--autonomy")
        autonomy = rest[i + 1] if i + 1 < len(rest) else "guarded"
        del rest[i:i + 2]
    if "--max-steps" in rest:
        i = rest.index("--max-steps")
        raw = rest[i + 1] if i + 1 < len(rest) else "8"
        if not raw.isdigit() or not 1 <= int(raw) <= 50:
            print("--max-steps must be an integer 1-50", file=sys.stderr)
            return 2
        max_steps = int(raw)
        del rest[i:i + 2]
    if autonomy not in ("read", "guarded", "full"):
        autonomy = "guarded"
    goal = " ".join(rest).strip()
    if not goal:
        print('usage: guardd agent [--autonomy read|guarded|full] [--apply] '
              '[--max-steps N] "<goal>"', file=sys.stderr)
        return 2

    provider = state.active_provider(config_default=_configured_adapter())
    if provider == "mock":
        print("agent needs a reasoning brain — run: guardd use claude|ollama|snn",
              file=sys.stderr)
        return 2
    cfg = state.adapter_config(provider)
    label = cfg.get("model") or cfg.get("model_path") or "-"
    print(f"agent: {provider}/{label} · autonomy={autonomy} · "
          f"{'APPLY' if apply else 'dry-run'}")
    try:
        result = agent.run(goal, provider, autonomy=autonomy, apply=apply,
                           max_steps=max_steps)
    except (RuntimeError, KeyError, ValueError) as e:
        print(f"agent error: {e}", file=sys.stderr)
        return 1
    for s in result["steps"]:
        print(f"  → {s['tool']}({s['args']}) :: {s['result'].get('status', '?')}")
    print("\n" + (result["final"] or "(no summary)"))
    record({"control": "agent", "goal": goal, "autonomy": autonomy,
            "steps": len(result["steps"]), "result": "done"})
    return 0


# ===========================================================================
# UPDATER — signed VeloGuard releases + kernel re-merge (agent-drivable)
# ===========================================================================

def _update(rest: list[str]) -> int:
    sub = rest[0] if rest and not rest[0].startswith("-") else "check"
    flags = [a for a in rest if a.startswith("-")]
    as_json = "--json" in flags
    do_apply = "--apply" in flags
    yes = "--yes" in flags
    build = "--build" in flags
    domain = "all"
    if "--domain" in rest:
        i = rest.index("--domain")
        domain = rest[i + 1] if i + 1 < len(rest) else "all"

    try:
        if sub in ("check", "apply") and not updater.PUBKEY.exists():
            print("updater: not configured yet — add your release key to "
                  "veloguard/keys/veloguard-release.pem and set VELOGUARD_UPDATE_URL "
                  "(see keys/SIGNING.md). Nothing to do.")
            record({"control": "update", "sub": sub, "result": "not_configured"})
            return 0
        if sub == "check":
            res = updater.check()
            if as_json:
                print(json.dumps(res))
            else:
                print(f"signature: verified ✓   (root of trust: keys/veloguard-release.pem)")
                for dom, d in res["domains"].items():
                    flag = "UPDATE" if d["update_available"] else "up to date"
                    print(f"  {dom:<9} {d['current']} → {d['latest']}   [{flag}]")
            record({"control": "update", "sub": "check", "result": "ok"})
            return 0

        if sub == "rollback":
            print(updater.rollback_veloguard())
            record({"control": "update", "sub": "rollback", "result": "ok"})
            return 0

        if sub == "apply":
            # Verification happens inside the updater regardless of consent.
            # The kernel domain means the shippable path — stage the signed
            # prebuilt package for apply-on-reboot. Compiling from source
            # (--build) is the developer/kernel-tree path only.
            def _kernel(dry: bool) -> str:
                if build:
                    return updater.apply_kernel(build=True, dry_run=dry)
                return updater.stage_kernel(dry_run=dry)
            if not do_apply:
                if domain in ("all", "veloguard"):
                    print(updater.apply_veloguard(dry_run=True))
                if domain in ("all", "kernel"):
                    print(_kernel(True))
                print("\n(preview only — add --apply to execute)")
                return 0
            if not yes:
                sys.stderr.write(f"\n  Apply VeloGuard updates ({domain})? Signature is "
                                 "verified. This is privileged. [y/N] ")
                if input().strip().lower() not in ("y", "yes"):
                    print("aborted by user", file=sys.stderr)
                    return 1
            out = []
            if domain in ("all", "veloguard"):
                out.append(updater.apply_veloguard(dry_run=False))
            if domain in ("all", "kernel"):
                out.append(_kernel(False))
            for line in out:
                print(line)
            record({"control": "update", "sub": "apply", "domain": domain,
                    "build": build, "result": "executed"})
            return 0

        if sub == "kernel":
            # Offline, prebuilt kernel path (Fedora-style apply-on-reboot).
            if "--pending" in flags:                       # read-only, no key needed
                p = updater.kernel_update_pending()
                print(p["version"] if p else "none")
                return 0
            if "--arm" in flags:                           # opt-in confirmed (root)
                print(updater.arm_reboot_update())
                record({"control": "update", "sub": "kernel-arm", "result": "ok"})
                return 0
            if "--disarm" in flags:
                print(updater.disarm_reboot_update())
                record({"control": "update", "sub": "kernel-disarm", "result": "ok"})
                return 0
            # default: stage — download + verify the SIGNED prebuilt package
            if not updater.PUBKEY.exists():
                print("updater: not configured (no release key) — see keys/SIGNING.md")
                record({"control": "update", "sub": "kernel-stage", "result": "not_configured"})
                return 0
            print(updater.stage_kernel(dry_run=not do_apply))
            if not do_apply:
                print("\n(preview only — add --apply to download + stage for reboot)")
            record({"control": "update", "sub": "kernel-stage",
                    "apply": do_apply, "result": "executed" if do_apply else "preview"})
            return 0

        print(f"unknown update subcommand {sub!r} (check | apply | kernel | rollback)",
              file=sys.stderr)
        return 2
    except updater.UpdateError as e:
        print(f"update refused (fail-closed): {e}", file=sys.stderr)
        record({"control": "update", "sub": sub, "result": "refused", "error": str(e)})
        return 1


# ===========================================================================
# VIRTUALIZATION LAYER — run an uncertain app in an isolated 'digital layer'
# ===========================================================================

def _run_safe(rest: list[str]) -> int:
    apply = "--apply" in rest; rest = [a for a in rest if a != "--apply"]
    allow_net = "--net" in rest; rest = [a for a in rest if a != "--net"]
    tier = None
    if "--tier" in rest:
        i = rest.index("--tier")
        tier = rest[i + 1] if i + 1 < len(rest) else None
        del rest[i:i + 2]
    if not rest:
        print("usage: guardd run-safe [--tier light|strong|vm] [--net] [--apply] "
              "<command...>", file=sys.stderr)
        return 2

    cmd, app = rest, rest[0]
    if not tier:                       # let the AI judge how hard to sandbox
        adapter, provider, model = _active_adapter()
        risk, why = vlayer.assess_risk(app, adapter, provider, model)
        tier = vlayer.TIER_FOR_RISK[risk]
        print(f"  risk: {risk} — {why}")
    chosen, degraded = vlayer.resolve_tier(tier)
    print(f"  isolation tier: {chosen}"
          + (f"  (degraded from '{tier}' — not installed)" if degraded else ""))

    action = Action(ActionType.SANDBOX_RUN,
                    {"target": " ".join(shlex.quote(c) for c in cmd),
                     "tier": tier, "net": allow_net})
    try:
        action.validate()
    except ValueError as e:
        print(e, file=sys.stderr)
        return 2
    decision = PolicyEngine.shared(DEFAULT_POLICY_PATH).evaluate(action)
    if decision.verdict == Verdict.DENY:
        print(f"DENIED: {decision.reason}", file=sys.stderr)
        return 1
    ex = NftExecutor(apply=apply)
    out = ex.sandbox_run(action.params["target"], tier, allow_net)
    print(out)
    record({"control": "run-safe", "target": action.params["target"],
            "tier": chosen, "net": allow_net, "apply": apply, "result": "executed"})
    return 0


# ===========================================================================
# CONTROL PLANE — the hot-swap commands
# ===========================================================================

def _integrity(rest: list[str]) -> int:
    """guardd integrity update | check — the guard checks its own files.
    The Rust check (rust/src/integrity.rs: covers hidden plugin files too, and
    never loses a finding) runs when installed root-owned; this is the fallback."""
    rs = Path(__file__).resolve().parent.parent / "bin" / "veloguard-integrity"
    try:
        st = rs.stat()
        if st.st_uid == 0 and not st.st_mode & 0o022 and os.access(rs, os.X_OK):
            os.execv(str(rs), [str(rs), *(rest or ["check"])])
    except OSError:
        pass
    from . import incident, integrity
    sub = rest[0] if rest else "check"
    if os.geteuid() != 0:
        print("integrity needs root (the baseline is root-only)", file=sys.stderr)
        return 2
    if sub == "update":
        n = integrity.update()
        record({"control": "integrity", "action": "update", "files": n, "result": "ok"})
        print(f"baseline: {n} guard files")
        return 0
    r = integrity.check()
    if r.get("no_baseline"):
        n = integrity.update()
        print(f"no baseline yet — took one ({n} files)")
        return 0
    bad = r["changed"] + r["added"] + r["removed"]
    if not bad:
        print("✓ the guard's files are as deployed")
        return 0
    record({"control": "integrity", "action": "check", "result": "mismatch", **r})
    incident.save("integrity", f"VeloGuard's own files changed outside a deploy ({len(bad)})", r)
    for k in ("changed", "added", "removed"):
        for f in r[k]:
            print(f"  {k:8} {f}")
    return 1


def _incidents(rest: list[str]) -> int:
    """guardd incidents [--latest | --show ID] [--json] — what the guard caught."""
    from . import incident
    as_json = "--json" in rest
    if "--latest" in rest or "--show" in rest:
        iid = rest[rest.index("--show") + 1] if "--show" in rest and rest.index("--show") + 1 < len(rest) else "latest"
        inc = incident.get(iid)
        if not inc:
            print("no such incident" if iid != "latest" else "no incidents", file=sys.stderr)
            return 1
        print(json.dumps(inc, indent=2, default=str) if as_json else incident.as_text(inc))
        return 0
    rows = incident.latest(20)
    if as_json:
        print(json.dumps(rows, default=str))
    elif not rows:
        print("no incidents — nothing caught")
    else:
        for r in rows:
            print(f"  {r['id']:<34} {r['title']}")
    return 0


def _check_command(rest: list[str]) -> int:
    """guardd check-command [--write PATH] [--json] [-- CMD…]: is this OK for an
    AI agent to run (or write)? The command (or the file's new text, with
    --write) comes from the arguments after --, else stdin. Exit 0 allow,
    1 warn, 3 deny; --json prints {"verdict", "reason"} either way."""
    from . import cmdguard
    as_json = "--json" in rest
    write = None
    if "--write" in rest:
        i = rest.index("--write")
        write = rest[i + 1] if i + 1 < len(rest) else ""
    tail = rest[rest.index("--") + 1:] if "--" in rest else []
    text = " ".join(tail) if tail else sys.stdin.read()
    opts = rest[:rest.index("--")] if "--" in rest else rest

    def opt(name: str) -> str | None:
        return opts[opts.index(name) + 1] if name in opts and opts.index(name) + 1 < len(opts) else None

    cls, what = "", text
    if "--read" in rest:
        i = rest.index("--read")
        target = rest[i + 1] if i + 1 < len(rest) else ""
        verdict, reason = cmdguard.check_read(target)
        cls, what = "secret", f"read {target}"
    elif write is not None:
        verdict, reason = cmdguard.check_write(write, text)
        cls = "tamper" if verdict == "deny" else "malware"
        what = f"write {write}"
    else:
        verdict, reason, cls = cmdguard.check_detail(text)
    # --ask deny|all: put what the guard would stop to the person (Approve/Deny
    # pop-up) instead of deciding alone. deny = only refusals (the host asks
    # about warnings itself); all = refusals and warnings.
    ask = opt("--ask")
    asked = approved = None
    if ask in ("deny", "all") and (verdict == "deny" or (verdict == "warn" and ask == "all")):
        from . import approve
        agent_name = opt("--agent") or os.environ.get("VELOGUARD_AGENT") or "An AI agent"
        approved, how = approve.ask(agent_name, what, reason, cls, opt("--cwd"))
        asked = True
        record({"control": "agent-approval", "agent": agent_name, "verdict": verdict,
                "class": cls, "reason": reason, "what": what[:2000],
                "result": "approved" if approved else "denied", "how": how})
        if approved:
            verdict, reason = "allow", f"approved by the person (it {reason})"
        else:
            verdict, reason = "deny", f"the person didn't approve it ({how}) — it {reason}"
    if as_json:
        out = {"verdict": verdict, "reason": reason, "class": cls if verdict != "allow" else ""}
        if asked:
            out.update({"asked": True, "approved": bool(approved)})
        print(json.dumps(out))
    elif verdict != "allow":
        print(f"{verdict}: {reason}")
    return {"allow": 0, "warn": 1}.get(verdict, 3)


def _approve(rest: list[str]) -> int:
    """guardd approve --agent NAME [--class C] [--reason R] [--cwd DIR] -- WHAT:
    put something the guard restricts to the person (Approve/Deny pop-up).
    Prints {"approved": bool, "how": ...}; exit 0 approved, 1 not."""
    from . import approve
    opts = rest[:rest.index("--")] if "--" in rest else rest
    what = " ".join(rest[rest.index("--") + 1:]) if "--" in rest else sys.stdin.read()

    def opt(name: str) -> str:
        return opts[opts.index(name) + 1] if name in opts and opts.index(name) + 1 < len(opts) else ""

    agent_name = opt("--agent") or os.environ.get("VELOGUARD_AGENT") or "An AI agent"
    ok, how = approve.ask(agent_name, what, opt("--reason"), opt("--class"), opt("--cwd") or None)
    record({"control": "agent-approval", "agent": agent_name, "class": opt("--class"),
            "reason": opt("--reason"), "what": what[:2000],
            "result": "approved" if ok else "denied", "how": how})
    print(json.dumps({"approved": ok, "how": how}))
    return 0 if ok else 1


def _agents(rest: list[str]) -> int:
    """guardd agents [list] | test <name> | json — the agent plugins."""
    from . import agent_plugins
    plugins = agent_plugins.load_all()
    sub = rest[0] if rest else "list"
    if sub in ("list", "json"):
        rows = [agent_plugins.status(p) for p in plugins.values()]
        if sub == "json":
            print(json.dumps(rows))
            return 0
        active = state.active_provider(config_default=_configured_adapter())
        for r in rows:
            mark = "➤" if r["name"] == active else " "
            st = "installed" if r["installed"] else "not installed"
            if r["installed"] and not r["config"]:
                st += " — sign in: " + r["signin"]
            print(f"  {mark} {r['name']:<12} {r['label']:<14} {st}")
        return 0
    if sub == "test" and len(rest) == 2:
        name = rest[1]
        if name not in plugins:
            print(f"no agent plugin {name!r} (have: {', '.join(plugins)})", file=sys.stderr)
            return 2
        cfg = state.adapter_config(name) if state.is_agent(name) else {}
        try:
            text = agent_plugins.run_brain(
                name, "You are a connectivity check. Follow the instruction exactly.",
                "Reply with exactly the word VELOGUARD-OK and nothing else.",
                cfg.get("model"), timeout=120)
        except RuntimeError as exc:
            print(f"✗ {plugins[name].label}: {exc}")
            return 1
        ok = "VELOGUARD-OK" in text
        print(("✓ " if ok else "✗ ") + f"{plugins[name].label} answered: {text[:200]!r}")
        return 0 if ok else 1
    if sub == "handoff" and len(rest) == 3:
        try:
            print(json.dumps(agent_plugins.handoff(rest[1], rest[2], sys.stdin.read())))
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0
    print("usage: guardd agents [list|json] | test <name> | handoff <name> error|incident  (text on stdin)",
          file=sys.stderr)
    return 2


def _control(argv: list[str]) -> int:
    verb, rest = argv[0], argv[1:]

    if verb == "help" or not argv:
        print(__doc__)
        return 0

    if verb == "setup":
        return _setup_wizard()

    if verb == "net":
        return _net(rest)

    if verb == "honeypot":
        return _honeypot(rest)

    if verb == "analyze":
        return _analyze(rest)

    if verb == "run-safe":
        return _run_safe(rest)

    if verb == "update":
        return _update(rest)

    if verb == "agent":
        return _agent(rest)

    if verb == "mcp":
        from .mcp_server import serve
        serve()
        return 0

    if verb == "voice":
        return voice.run()

    if verb == "providers":
        tags = {
            "mock":   " (offline keyword fallback)",
            "snn":    " (local SNN brain — model pending)",
            "claude": " (Anthropic API — needs a key)",
            "ollama": " (local model via Ollama — private, free)",
        }
        from . import agent_plugins
        plugins = agent_plugins.load_all()
        for p in state.providers():
            tag = tags.get(p) or (f" ({plugins[p].label} — agent plugin)" if p in plugins else "")
            print(f"  {p}{tag}")
        return 0

    if verb == "agents":
        return _agents(rest)

    if verb == "check-command":
        return _check_command(rest)

    if verb == "approve":
        return _approve(rest)

    if verb == "watch":
        from . import watch
        return watch.status() if rest[:1] == ["status"] else watch.Watch().run()

    if verb == "detonate":
        from . import microvm
        p = argparse.ArgumentParser(prog="guardd detonate")
        p.add_argument("file")
        p.add_argument("--seconds", type=int, default=30)
        a = p.parse_args(rest)
        print(f"detonating {a.file} in a Firecracker micro-VM (no network, {a.seconds} s)…", flush=True)
        res = microvm.detonate(a.file, a.seconds)
        print(microvm.as_text(res))
        record({"control": "detonate", "file": a.file, "result": "ok" if res.get("ok") else "failed",
                "exit": res.get("exit"), "error": res.get("error")})
        return 0 if res.get("ok") else 1

    if verb == "incidents":
        return _incidents(rest)

    if verb == "integrity":
        return _integrity(rest)

    if verb == "audit":
        from . import audit as audit_mod
        if rest[:1] == ["verify"]:
            ok, msg = audit_mod.verify()
            print(("✓ " if ok else "✗ ") + msg)
            return 0 if ok else 1
        print("usage: guardd audit verify", file=sys.stderr)
        return 2

    if verb == "key":
        if len(rest) < 2 or rest[0] != "claude":
            print("usage: guardd key claude <API_KEY>", file=sys.stderr)
            return 2
        state.set_key("claude", rest[1])
        print("claude API key stored (chmod 600, never logged)")
        record({"control": "key", "provider": "claude", "result": "ok"})
        return 0

    if verb == "host":
        if len(rest) < 2 or rest[0] != "ollama":
            print("usage: guardd host ollama <URL>", file=sys.stderr)
            return 2
        state.set_host("ollama", rest[1])
        print(f"ollama host → {rest[1]}")
        record({"control": "host", "provider": "ollama", "host": rest[1],
                "result": "ok"})
        return 0

    if verb == "use":
        if not rest:
            print("usage: guardd use <provider> [model]", file=sys.stderr)
            return 2
        provider = rest[0]
        if provider not in state.providers():
            print(f"unknown provider {provider!r} "
                  f"(choices: {', '.join(state.providers())})", file=sys.stderr)
            return 2
        state.set_active(provider)
        msg = f"active AI plane → {provider}"
        if len(rest) > 1:
            state.set_model(provider, rest[1])
            msg += f"  (model: {rest[1]})"
        print(msg)
        if provider == "snn":
            print("  ⚠ SNN model code pending — intents will say so until it "
                  "lands in guardd/snn.py")
        elif provider == "claude" and not state.get_key("claude"):
            print("  ⚠ no Claude API key yet — set one: guardd key claude <KEY>")
        elif provider == "ollama":
            print(f"  ℹ using local Ollama at {state.host_for('ollama')} — "
                  "make sure `ollama serve` is running and the model is pulled")
        elif state.is_agent(provider):
            from . import agent_plugins
            pl = agent_plugins.get(provider)
            st = agent_plugins.status(pl)
            if not st["installed"]:
                print(f"  ⚠ {pl.label} is not installed — veloguard-agent install {provider}")
            elif not st["config"]:
                print(f"  ⚠ {pl.label} looks signed out — sign in once: {pl.signin}")
            print(f"  ℹ {pl.label} answers as the brain in a throwaway sandbox; "
                  "check it with: guardd agents test " + provider)
        record({"control": "use", "provider": provider,
                "model": state.model_for(provider) if provider != "mock" else None,
                "result": "ok"})
        return 0

    if verb == "model":
        if len(rest) < 2:
            print("usage: guardd model <provider> <model>", file=sys.stderr)
            return 2
        provider, model = rest[0], rest[1]
        if provider not in state.providers() or provider == "mock":
            print(f"cannot set a model for {provider!r}", file=sys.stderr)
            return 2
        state.set_model(provider, model)
        print(f"{provider} model → {model}")
        record({"control": "model", "provider": provider,
                "model": model, "result": "ok"})
        return 0

    if verb == "status":
        active = state.active_provider(config_default=_configured_adapter())
        print(f"active AI plane : {active}")
        print("providers:")
        from . import agent_plugins
        plugins = agent_plugins.load_all()
        for p in state.providers():
            line = f"  {'➤' if p == active else ' '} {p:<11}"
            if p == "snn":
                line += f" model={state.model_for('snn') or '(default path)'}  [model code pending]"
            elif p == "claude":
                have = "key set" if state.get_key("claude") else "no key"
                line += f" model={state.model_for('claude')}  ({have})"
            elif p == "ollama":
                line += f" model={state.model_for('ollama')}  host={state.host_for('ollama')}"
            elif p in plugins:
                st = agent_plugins.status(plugins[p])
                line += (f" {plugins[p].label}: "
                         + ("installed" if st["installed"] else "not installed")
                         + ("" if st["config"] or not st["installed"] else ", signed out?"))
            print(line)
        return 0

    print(f"unknown command {verb!r}. Try: guardd help", file=sys.stderr)
    return 2


# ===========================================================================
# RUN PLANE — execute one security intent
# ===========================================================================

def _confirm(action: Action, decision: Decision) -> bool:
    sys.stderr.write(
        f"\n  VeloGuard wants to: {action.describe()}\n"
        f"  reason: {action.rationale or '(none)'}\n"
        f"  policy: {decision.reason}\n"
        f"  approve? [y/N] ")
    sys.stderr.flush()
    try:
        return input().strip().lower() in ("y", "yes")
    except EOFError:           # no stdin (piped/service) — never assume consent
        return False


def _execute(action: Action, ex: NftExecutor) -> str:
    t = action.type
    if t == ActionType.BLOCK_IP:
        return ex.block_ip(action.params["ip"])
    if t == ActionType.UNBLOCK_IP:
        return ex.unblock_ip(action.params["ip"])
    if t == ActionType.LIST_BLOCKED:
        return ex.list_blocked()
    if t == ActionType.VPN_UP:
        return ex.vpn_up(action.params.get("target"))
    if t == ActionType.VPN_DOWN:
        return ex.vpn_down(action.params.get("target"))
    if t == ActionType.QUARANTINE:
        return ex.quarantine(action.params["target"])
    if t == ActionType.RELEASE_QUARANTINE:
        return ex.release_quarantine(action.params["target"])
    if t == ActionType.KILL_QUARANTINE:
        return ex.kill_quarantine(action.params["target"])
    if t == ActionType.SANDBOX_RUN:
        return ex.sandbox_run(action.params["target"],
                              action.params.get("tier", "light"),
                              action.params.get("net", False))
    return "noop"


def _run(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="guardd", description="VeloGuard — run a security intent")
    p.add_argument("intent", nargs="?", help="natural-language security intent")
    p.add_argument("--adapter", default=None,
                   help="override the active AI plane for this one command")
    p.add_argument("--apply", action="store_true",
                   help="actually touch nftables (needs root); default is dry-run")
    p.add_argument("--yes", action="store_true",
                   help="auto-approve actions that need consent (USE CAREFULLY)")
    p.add_argument("--setup", action="store_true",
                   help="create the veloguard nft table/set/rule, then exit")
    p.add_argument("--policy", type=Path, default=DEFAULT_POLICY_PATH)
    p.add_argument("--version", action="version", version=f"VeloGuard {__version__}")
    args = p.parse_args(argv)

    ex = NftExecutor(apply=args.apply)

    if args.setup:
        for line in ex.setup():
            print(line)
        return 0

    if not args.intent:
        p.error("provide an intent, or a control command (try: guardd help)")

    # 1. AI plane: resolve the *currently active* brain (hot-swappable state),
    #    unless this one command overrides it with --adapter.
    provider = state.active_provider(cli=args.adapter,
                                     config_default=_configured_adapter())
    cfg = state.adapter_config(provider)
    try:
        adapter = get_adapter(provider, **cfg)
        action = adapter.parse(args.intent)
    except (ValueError, RuntimeError) as e:
        print(f"AI plane error: {e}", file=sys.stderr)
        return 2

    try:
        action.validate()
    except ValueError as e:
        print(f"rejected (malformed): {e}", file=sys.stderr)
        record({"intent": args.intent, "provider": provider,
                "action": action.type.value, "result": "malformed", "error": str(e)})
        return 2

    # 2. Control plane: judge it
    engine = PolicyEngine.shared(args.policy)
    decision = engine.evaluate(action)
    base = {"intent": args.intent, "provider": provider,
            "model": cfg.get("model"), "action": action.type.value,
            "params": action.params, "rationale": action.rationale,
            "verdict": decision.verdict.value, "reason": decision.reason,
            "apply": args.apply}

    if decision.verdict == Verdict.DENY:
        print(f"DENIED: {action.describe()} — {decision.reason}", file=sys.stderr)
        record({**base, "result": "denied"})
        return 1

    # 3. Consent gate ("when the user demands it")
    if decision.verdict == Verdict.NEEDS_APPROVAL and not args.yes:
        if not _confirm(action, decision):
            print("aborted by user", file=sys.stderr)
            record({**base, "result": "aborted_by_user"})
            return 1

    # 4. Kernel plane: do it. The executor self-protects (refuses a tunnel
    #    with no endpoint, rolls back a dead one, refuses to run unsandboxed)
    #    — audit those refusals like every other decision, no traceback.
    try:
        out = _execute(action, ex)
    except (RuntimeError, ValueError) as e:
        print(f"FAILED: {action.describe()} — {e}", file=sys.stderr)
        record({**base, "result": "failed", "error": str(e)})
        return 1
    engine.record(action)
    print(out)
    record({**base, "result": "executed", "output": out})
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print(__doc__)
        return 0
    if argv[0] in CONTROL_VERBS:
        return _control(argv)
    return _run(argv)


if __name__ == "__main__":
    raise SystemExit(main())
