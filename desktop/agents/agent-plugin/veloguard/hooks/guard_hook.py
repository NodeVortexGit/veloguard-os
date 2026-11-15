#!/usr/bin/env python3
"""PreToolUse guard for Agent Plugins hosts (Claude-style hook protocol).

stdin: {"tool_name": ..., "tool_input": {...}} — judged by the same rules as
the Claude Code plugin and veloguard-elevate (guardd/cmdguard.py). Anything the
guard restricts — switching off or rewriting the guard, what malware typically
does, reading credentials — is put to the PERSON as an Approve/Deny pop-up on
their desktop (hosts differ on whether a hook may ask in their own UI, so this
one asks on the desktop itself). Approve → the call runs; Deny or no answer →
it doesn't. If the guard can't be asked, the call is refused: no check, no
command.

Hosts: Codex CLI (~/.codex/hooks.json), Kimi Code (config.toml [[hooks]]), and
any Agent Plugins host that runs plugin hooks.
"""
import json
import re
import sys

SHELL = {"bash", "shell", "exec_command", "local_shell", "run_shell_command", "terminal",
         "exec", "shell_command", "run_terminal_cmd"}
WRITE = {"edit", "write", "multiedit", "write_file", "edit_file", "str_replace_editor",
         "create_file", "replace", "patch"}
PATCH = {"apply_patch"}             # Codex: the patch text is tool_input.command
PATCH_FILE = re.compile(r"^\*\*\* (?:Add|Update|Delete) File: (.+)$|^\*\*\* Move to: (.+)$", re.M)


def answer(decision: str, reason: str) -> None:
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                             "permissionDecision": decision,
                                             "permissionDecisionReason": reason},
                      **({"decision": "block", "reason": reason} if decision == "deny" else {})}))
    sys.exit(0)


GUARD_HOME = "/opt/veloguard"


def main() -> None:
    try:
        ev = json.load(sys.stdin)
    except ValueError:
        answer("deny", "VeloGuard couldn't read this tool call, so it doesn't run.")
    tool = str(ev.get("tool_name", "")).lower()
    ti = ev.get("tool_input") or {}
    if tool not in SHELL and tool not in WRITE and tool not in PATCH:
        sys.exit(0)                                   # not ours to judge
    try:
        sys.path.insert(0, GUARD_HOME)
        from guardd import cmdguard
    except Exception as e:  # noqa: BLE001 — a broken guard must not open the door
        answer("deny", f"VeloGuard couldn't check this call ({e}), so it doesn't run.")
    cls = ""
    if tool in PATCH:
        patch = str(ti.get("command") or ti.get("patch") or ti.get("input") or "")
        paths = [a or b for a, b in PATCH_FILE.findall(patch)] or [""]
        verdict, why = "allow", ""
        for path in paths:
            v, w = cmdguard.check_write(path.strip(), patch)
            if v == "deny" or (v == "warn" and verdict == "allow"):
                verdict, why = v, w
        what = "change " + ", ".join(p.strip() for p in paths if p.strip())
        cls = "tamper" if verdict == "deny" else "malware"
    elif tool in SHELL:
        cmd = ti.get("command") or ti.get("cmd") or ""
        if isinstance(cmd, list):
            cmd = " ".join(map(str, cmd))
        verdict, why, cls = cmdguard.check_detail(str(cmd))
        what = str(cmd)
    elif tool in WRITE:
        path = ti.get("file_path") or ti.get("path") or ti.get("filename") or ""
        text = ti.get("content") or ti.get("new_string") or ti.get("new_str") or ""
        verdict, why = cmdguard.check_write(str(path), str(text))
        what = f"write {path}"
        cls = "tamper" if verdict == "deny" else "malware"
    if verdict in ("deny", "warn"):
        ok, how = ask_person(what, why, cls)
        if ok:
            sys.exit(0)                               # the person approved it
        answer("deny", f"VeloGuard asked the person and they didn't approve it ({how}): it {why}. "
                       "Take that as the answer — don't retry it or look for another way.")
    sys.exit(0)


def ask_person(what: str, why: str, cls: str) -> tuple[bool, str]:
    """The desktop Approve/Deny pop-up (guardd/approve.py), audited."""
    import os
    try:
        from guardd import approve
        from guardd.audit import record
        agent = os.environ.get("VELOGUARD_AGENT") or HOST
        ok, how = approve.ask(agent, what, why, cls, os.getcwd(), timeout=85)
        record({"control": "agent-approval", "agent": agent, "class": cls, "reason": why,
                "what": what[:2000], "result": "approved" if ok else "denied", "how": how})
        return ok, how
    except Exception as e:  # noqa: BLE001 — no pop-up, no permission
        return False, f"couldn't ask ({e})"


HOST = "An AI agent"


if __name__ == "__main__":
    if len(sys.argv) > 1:
        HOST = sys.argv[1]          # the host names itself: guard_hook.py "Kimi Code"
    main()
