#!/usr/bin/env python3
"""PreToolUse guard for Agent Plugins hosts (Claude-style hook protocol).

stdin: {"tool_name": ..., "tool_input": {...}} — answers with a deny, from the
same rules as the Claude Code plugin and veloguard-elevate (guardd/cmdguard.py):
switching off or rewriting the guard is refused; what malware typically does is
held back with "ask the person first" (hosts differ on whether a hook may ask,
so this one never assumes it can). If the guard can't be asked, the call is
refused: no check, no command.

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
    if tool in PATCH:
        patch = str(ti.get("command") or ti.get("patch") or ti.get("input") or "")
        paths = [a or b for a, b in PATCH_FILE.findall(patch)] or [""]
        verdict, why = "allow", ""
        for path in paths:
            v, w = cmdguard.check_write(path.strip(), patch)
            if v == "deny" or (v == "warn" and verdict == "allow"):
                verdict, why = v, w
    elif tool in SHELL:
        cmd = ti.get("command") or ti.get("cmd") or ""
        if isinstance(cmd, list):
            cmd = " ".join(map(str, cmd))
        verdict, why = cmdguard.check(str(cmd))
    elif tool in WRITE:
        path = ti.get("file_path") or ti.get("path") or ti.get("filename") or ""
        text = ti.get("content") or ti.get("new_string") or ti.get("new_str") or ""
        verdict, why = cmdguard.check_write(str(path), str(text))
    if verdict == "deny":
        answer("deny", f"VeloGuard refused this: it {why}. An AI agent never switches off "
                       "the machine's own protection — tell the person; they can do it themselves.")
    if verdict == "warn":
        answer("deny", f"VeloGuard held this back: it {why}. Ask the person first, in plain "
                       "words; if they want it, they can run it themselves.")
    sys.exit(0)


if __name__ == "__main__":
    main()
