"""One guarded road to the kernel — used by the MCP server and the agent loop.

Every mutating tool call becomes an Action that passes the SAME guard the CLI
uses: validate → policy → consent (by autonomy) → execute → audit. There is no
back door. Read tools never mutate and are always allowed.

Autonomy levels:
  read    — mutating tools disabled entirely.
  guarded — protective actions run; destructive ones need an interactive yes.
  full    — destructive actions auto-approved (the session is standing consent);
            policy DENY still blocks, everything is still audited.

"op" tools (root, processes, services) have their own guard: root always goes
to the person's Approve in the root dialog (autonomy never stands in for it —
only a grant the person approved does), and signalling a protected process or
stopping a guard unit is put to the person as an Approve/Deny pop-up.
`ctx` carries who is calling (guardd/agentid.py) and from where.
"""

from __future__ import annotations

from pathlib import Path

from . import authchan, memory, netclass, state, tools as toolmod, updater
from .actions import Action, ActionType
from .audit import record
from .executor import NftExecutor
from .policy import PolicyEngine, Verdict

DEFAULT_POLICY_PATH = Path(__file__).resolve().parent.parent / "policy.json"
AUTONOMY = ("read", "guarded", "full")


def _run_on_executor(action: Action, ex: NftExecutor) -> str:
    t = action.type
    if t == ActionType.BLOCK_IP:           return ex.block_ip(action.params["ip"])
    if t == ActionType.UNBLOCK_IP:         return ex.unblock_ip(action.params["ip"])
    if t == ActionType.LIST_BLOCKED:       return ex.list_blocked()
    if t == ActionType.VPN_UP:             return ex.vpn_up(action.params.get("target"))
    if t == ActionType.VPN_DOWN:           return ex.vpn_down(action.params.get("target"))
    if t == ActionType.QUARANTINE:         return ex.quarantine(action.params["target"])
    if t == ActionType.RELEASE_QUARANTINE: return ex.release_quarantine(action.params["target"])
    if t == ActionType.KILL_QUARANTINE:    return ex.kill_quarantine(action.params["target"])
    if t == ActionType.SANDBOX_RUN:
        return ex.sandbox_run(action.params["target"],
                              action.params.get("tier", "light"),
                              action.params.get("net", False))
    return "noop"


def _read_tool(name: str, args: dict) -> dict:
    if name == "status":
        active = state.active_provider()
        return {"ok": True, "data": {
            "active": active,
            "model": state.model_for(active) if active != "mock" else None}}
    if name == "classify_network":
        v, reason = netclass.classify(args.get("ssid"), args.get("bssid"),
                                      args.get("security"))
        return {"ok": True, "data": {"verdict": v, "reason": reason}}
    if name == "check_update":
        if not updater.PUBKEY.exists():
            return {"ok": True, "data": {"configured": False}}
        try:
            return {"ok": True, "data": updater.check()}
        except updater.UpdateError as e:
            return {"ok": False, "status": "refused", "error": str(e)}
    if name == "incidents":
        from . import incident
        return {"ok": True, "data": {"incidents": incident.latest(int(args.get("limit", 5)))}}
    if name == "recall":
        return {"ok": True, "data": {
            "matches": memory.SemanticMemory().recall(args.get("query", ""))}}
    if name in _STATE_READS:
        from . import osstate, procs
        try:
            return _STATE_READS[name](args, procs, osstate)
        except (ValueError, TypeError) as e:
            return {"ok": False, "status": "invalid", "error": str(e)}
    return {"ok": False, "error": f"no read handler for {name}"}


def _int(args: dict, key: str, default=None, lo=None, hi=None):
    v = args.get(key, default)
    if v is None:
        raise ValueError(f"{key} is required")
    if isinstance(v, bool) or not isinstance(v, (int, str)) or (isinstance(v, str) and not v.strip().lstrip("-").isdigit()):
        raise ValueError(f"{key} must be a whole number")
    v = int(v)
    if lo is not None:
        v = max(lo, v)
    if hi is not None:
        v = min(hi, v)
    return v


def _opt(args: dict, key: str, allowed: tuple | None = None, default=None):
    v = args.get(key, default)
    if v is None:
        return default
    if not isinstance(v, str):
        raise ValueError(f"{key} must be a string")
    if allowed and v not in allowed:
        raise ValueError(f"{key} is one of {', '.join(allowed)}")
    return v


def _wrap(d: dict) -> dict:
    return d if "ok" in d else {"ok": True, "data": d}


_STATE_READS = {
    "process_list": lambda a, P, O: {"ok": True, "data": P.list_processes(
        _opt(a, "name"), _opt(a, "user"), _opt(a, "sort", ("cpu", "mem", "pid", "start", "name"), "cpu"),
        _int(a, "limit", 40, 1, 500))},
    "process_info": lambda a, P, O: _wrap(P.process_info(_int(a, "pid"))),
    "system_state": lambda a, P, O: {"ok": True, "data": O.system_state()},
    "network_state": lambda a, P, O: {"ok": True, "data": O.network_state()},
    "services": lambda a, P, O: _wrap(O.services(
        _opt(a, "scope", ("system", "user"), "system"), _opt(a, "unit"),
        _opt(a, "state", ("failed", "running", "all"), "failed"), _int(a, "limit", 100, 1, 1000))),
    "journal": lambda a, P, O: _wrap(O.journal(
        _opt(a, "unit"), _opt(a, "scope", ("system", "user"), "system"),
        _opt(a, "priority", O.PRIORITIES, "warning"), _int(a, "lines", 50, 1, 500),
        _opt(a, "since"), bool(a.get("this_boot", True)))),
}


# --- "op" tools -------------------------------------------------------------------

def _ask_person(ctx: dict, what: str, why: str, cls: str, reason: str = "") -> tuple[bool, str]:
    from . import agentid, approve
    who = ctx.get("who") or agentid.me()
    shown = what + (f"\n\nIts reason, in its own words: {reason}" if reason else "")
    ok, how = approve.ask(who.get("name", "An AI agent"), shown, why, cls,
                          ctx.get("cwd"), who=who)
    record({"control": "agent-approval", "source": "mcp", "agent": who.get("name"),
            "who": agentid.one_line(who), "class": cls, "reason": why, "what": what[:2000],
            "result": "approved" if ok else "denied", "how": how})
    return ok, how


def _process_signal(args: dict, ctx: dict) -> dict:
    from . import procs
    pid = _int(args, "pid")
    sig = (_opt(args, "signal", None, "TERM") or "TERM").upper().removeprefix("SIG")
    reason = (_opt(args, "reason") or "")[:300]
    c = procs.check_signal(pid, sig)
    base = {"source": "mcp", "tool": "process_signal", "pid": pid, "signal": sig}
    if c["decision"] in ("refuse", "needs_root"):
        record({**base, "result": c["decision"], "why": c["why"]})
        return {"ok": False, "status": c["decision"], "error": c["why"],
                **({"hint": c["hint"]} if c.get("hint") else {})}
    p = c["process"]
    how = "allowed (your own process)"
    if c["decision"] == "ask":
        ok, how = _ask_person(ctx, f"kill -{sig} {pid}   # {p['name']}: {p['cmd'][:300]}",
                              c["why"], c["class"], reason)
        if not ok:
            record({**base, "result": "denied", "how": how})
            return {"ok": False, "status": "denied", "how": how, "why": c["why"],
                    "hint": "The person said no — leave that process alone." if "denied" in how
                    else f"Nobody could be asked ({how}) — leave that process alone."}
    try:
        procs.send_signal(p, sig)
    except (ProcessLookupError, PermissionError, OSError) as e:
        record({**base, "result": "failed", "error": str(e)})
        return {"ok": False, "status": "failed", "error": str(e)}
    record({**base, "result": "executed", "name": p["name"], "how": how})
    return {"ok": True, "status": "sent", "pid": pid, "name": p["name"], "signal": sig, "how": how}


def _process_priority(args: dict, ctx: dict) -> dict:
    from . import procs
    r = procs.set_priority(_int(args, "pid"), _int(args, "nice"))
    record({"source": "mcp", "tool": "process_priority", "args": args,
            "result": "executed" if r.get("ok") else r.get("status", "failed")})
    return r


def _service_control(args: dict, ctx: dict) -> dict:
    from . import osstate
    unit = _opt(args, "unit") or ""
    action = _opt(args, "action", osstate.SERVICE_ACTIONS) or ""
    scope = _opt(args, "scope", ("user", "system"), "user")
    c = osstate.check_service(unit, action, scope)
    base = {"source": "mcp", "tool": "service_control", "unit": unit, "action": action, "scope": scope}
    if c["decision"] in ("refuse", "needs_root"):
        record({**base, "result": c["decision"]})
        return {"ok": False, "status": c["decision"], "error": c["why"],
                **({"hint": c["hint"]} if c.get("hint") else {})}
    if c["decision"] == "ask":
        ok, how = _ask_person(ctx, f"systemctl --user {action} {unit}", c["why"], c["class"],
                              (_opt(args, "reason") or "")[:300])
        if not ok:
            record({**base, "result": "denied", "how": how})
            return {"ok": False, "status": "denied", "how": how}
    r = osstate.control_service(unit, action)
    record({**base, "result": "executed" if r["ok"] else "failed", "exit_code": r["exit_code"]})
    return r


def _ops() -> dict:
    from . import elevation as el
    return {"sudo_run": el.sudo_run, "sudo_grant": el.sudo_grant, "sudo_status": el.sudo_status,
            "sudo_result": el.sudo_result, "sudo_revoke": el.sudo_revoke,
            "ask_permission": el.ask_permission, "process_signal": _process_signal,
            "process_priority": _process_priority, "service_control": _service_control}


def _run_op(name: str, spec: dict, args: dict, autonomy: str, ctx: dict | None) -> dict:
    if spec.get("mutating") and autonomy == "read":
        return {"ok": False, "status": "read_only",
                "reason": "autonomy=read: mutating tools are disabled"}
    fn = _ops().get(name)
    if fn is None:
        return {"ok": False, "error": f"no handler for {name}"}
    try:
        return fn(args, ctx or {})
    except (ValueError, TypeError) as e:
        return {"ok": False, "status": "invalid", "error": str(e)}


def execute_tool(name: str, args: dict, *, apply: bool = False,
                 autonomy: str = "guarded", interactive: bool = False,
                 confirm=None, source: str = "agent", ctx: dict | None = None) -> dict:
    spec = toolmod.get(name)
    if not spec:
        return {"ok": False, "error": f"unknown tool: {name}"}
    if spec["kind"] == "read":
        return _read_tool(name, args)
    if spec["kind"] == "op":
        return _run_op(name, spec, args, autonomy, ctx)

    if autonomy == "read":
        return {"ok": False, "status": "read_only",
                "reason": "autonomy=read: mutating tools are disabled"}

    try:
        action = Action(toolmod.action_type(name), dict(args))
        action.validate()
    except ValueError as e:
        return {"ok": False, "status": "invalid", "error": str(e)}

    engine = PolicyEngine.shared(DEFAULT_POLICY_PATH)
    decision = engine.evaluate(action)
    base = {"source": source, "tool": name, "params": action.params,
            "verdict": decision.verdict.value, "reason": decision.reason,
            "autonomy": autonomy, "apply": apply}

    if decision.verdict == Verdict.DENY:
        record({**base, "result": "denied"})
        return {"ok": False, "status": "denied", "reason": decision.reason}

    if decision.verdict == Verdict.NEEDS_APPROVAL:
        approved = (autonomy == "full") or bool(
            interactive and confirm and confirm(action, decision))
        if not approved:
            record({**base, "result": "needs_approval"})
            return {"ok": False, "status": "needs_approval",
                    "reason": "destructive — needs autonomy=full or an interactive yes"}

    try:
        # Seal the policy-approved action: the executor will refuse it if the
        # HMAC doesn't match, so an injected/forged action can't reach the kernel.
        ex = NftExecutor(apply=apply, seal=authchan.seal(action), action=action)
        out = _run_on_executor(action, ex)
    except RuntimeError as e:
        # Executor failed or self-protected (e.g. vpn_up refused/rolled back a
        # black-holing tunnel). Audit the failure too — the guard logs every
        # decision — and hand callers (MCP/agent/CLI) a clean error, not a crash.
        record({**base, "result": "failed", "error": str(e)})
        return {"ok": False, "status": "failed", "error": str(e)}
    engine.record(action)
    record({**base, "result": "executed", "output": out})
    if apply and action.type in (ActionType.QUARANTINE, ActionType.KILL_QUARANTINE):
        # A suspicious process: an incident to look into, with the agent of
        # the person's choice ("Investigate with …" on the desktop).
        from . import incident
        incident.save("quarantine", f"Process {'quarantined' if action.type == ActionType.QUARANTINE else 'killed'}: "
                      f"{action.params.get('target')}",
                      {"tool": name, "params": action.params, "source": source, "output": out,
                       "reason": decision.reason})
    return {"ok": True, "status": "executed", "output": out}
