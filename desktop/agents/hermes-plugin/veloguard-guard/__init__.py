"""VeloGuard's guard for Hermes Agent (native plugin: pre_tool_call).

Hermes runs portable Agent Plugins without their hooks, so the portable
"veloguard" plugin brings the guard's MCP tools and skill, and this one brings
the check: before `terminal`, `execute_code`, `write_file` and `patch` run,
guardd/cmdguard.py judges them. deny → blocked with the reason; warn → also
blocked (a hook here can't ask the person), telling the model to ask them.
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
            verdict, why = g.check(str(args.get(SHELL[tool_name]) or ""))
        else:
            key, texts = WRITE[tool_name]
            verdict, why = g.check_write(str(args.get(key) or ""),
                                         " ".join(str(args.get(t) or "") for t in texts))
    except Exception as e:  # noqa: BLE001 — a broken guard must not open the door
        return {"action": "block", "message": f"VeloGuard couldn't check this call ({e}), so it doesn't run."}
    if verdict == "deny":
        return {"action": "block", "message":
                f"VeloGuard refused this: it {why}. An AI agent never switches off the machine's "
                "own protection — tell the person what you wanted to do; they can do it themselves."}
    if verdict == "warn":
        return {"action": "block", "message":
                f"VeloGuard held this back: it {why}. Ask the person first, in plain words; if they "
                "want it, they can run it themselves."}
    return None


def register(ctx) -> None:
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
