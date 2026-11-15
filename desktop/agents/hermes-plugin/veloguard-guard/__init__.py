"""VeloGuard's guard for Hermes Agent (native plugin: pre_tool_call).

Hermes runs portable Agent Plugins without their hooks, so the portable
"veloguard" plugin brings the guard's MCP tools and skill, and this one brings
the check: before `terminal`, `execute_code`, `write_file` and `patch` run,
guardd/cmdguard.py judges them. Anything it restricts (deny or warn) is put to
the person as a desktop Approve/Deny pop-up (guardd/approve.py): approved → it
runs; denied or unanswered → blocked, and the model is told that's the answer.
If the guard can't be loaded, those tools are blocked: no check, no command.
"""
from __future__ import annotations

import sys
from typing import Any, Optional

GUARD_HOME = "/opt/veloguard"
SHELL = {"terminal": "command", "execute_code": "code"}
WRITE = {"write_file": ("path", ("content",)), "patch": ("path", ("new_string", "patch"))}


def _guard():
    if GUARD_HOME not in sys.path:
        sys.path.insert(0, GUARD_HOME)
    from guardd import cmdguard  # noqa: PLC0415
    return cmdguard


def _on_pre_tool_call(tool_name: str = "", args: Any = None, **_: Any) -> Optional[dict]:
    if tool_name not in SHELL and tool_name not in WRITE:
        return None
    args = args if isinstance(args, dict) else {}
    try:
        g = _guard()
        if tool_name in SHELL:
            what = str(args.get(SHELL[tool_name]) or "")
            verdict, why, cls = g.check_detail(what)
        else:
            key, texts = WRITE[tool_name]
            what = f"write {args.get(key) or ''}"
            verdict, why = g.check_write(str(args.get(key) or ""),
                                         " ".join(str(args.get(t) or "") for t in texts))
            cls = "tamper" if verdict == "deny" else "malware"
    except Exception as e:  # noqa: BLE001 — a broken guard must not open the door
        return {"action": "block", "message": f"VeloGuard couldn't check this call ({e}), so it doesn't run."}
    if verdict in ("deny", "warn"):
        try:
            from guardd import approve  # noqa: PLC0415
            from guardd.audit import record  # noqa: PLC0415
            ok, how = approve.ask("Hermes", what, why, cls)
            record({"control": "agent-approval", "agent": "Hermes", "class": cls, "reason": why,
                    "what": what[:2000], "result": "approved" if ok else "denied", "how": how})
        except Exception as e:  # noqa: BLE001 — no pop-up, no permission
            ok, how = False, f"couldn't ask ({e})"
        if ok:
            return None
        return {"action": "block", "message":
                f"VeloGuard asked the person and they didn't approve it ({how}): it {why}. "
                "Take that as the answer — don't retry it or look for another way."}
    return None


def register(ctx) -> None:
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
