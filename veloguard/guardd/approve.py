"""Approve / Deny — the person decides everything the guard would restrict.

Zero trust means an agent gets nothing it wasn't given. It does NOT mean the
person can't give it: whatever the guard holds back from an AI agent — a
command that switches the guard off or rewrites its files, a classic malware
move, reading credentials — is put to the person as a desktop pop-up with the
exact command, the folder and why it was stopped. Deny is the default, and no
answer within the timeout is a Deny.

This is the non-root half (drawn as the person, for a tool call the agent's
own process asked about). Root commands keep their own dialog, drawn by root
(veloguard-elevate-root), which an agent can't script.

  veloguard check-command --json --ask all --agent "Kimi Code" -- "systemctl …"
"""
from __future__ import annotations

import fcntl
import glob
import html
import os
import shutil
import subprocess
import time
from pathlib import Path

TIMEOUT = 90                      # seconds; then it's a Deny

_CLASS_LINE = {
    "disable": ("#e01b24", "This switches off part of VeloGuard itself "
                "(its services, firewall, audit trail or this agent's guard plugin)."),
    "tamper":  ("#e01b24", "This changes VeloGuard's own files."),
    "malware": ("#f5a623", "This is something malware (or a steered agent) does."),
    "secret":  ("#f5a623", "This reads credentials — keys, tokens, cookies or passwords."),
}


def _session_env() -> dict:
    """Enough of the desktop session to draw a dialog from a hook or a service."""
    env = dict(os.environ)
    uid = os.getuid()
    env.setdefault("XDG_RUNTIME_DIR", f"/run/user/{uid}")
    if not env.get("WAYLAND_DISPLAY") and not env.get("DISPLAY"):
        socks = sorted(glob.glob(f"{env['XDG_RUNTIME_DIR']}/wayland-[0-9]"))
        if socks:
            env["WAYLAND_DISPLAY"] = os.path.basename(socks[0])
    env.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path={env['XDG_RUNTIME_DIR']}/bus")
    return env


def can_ask() -> bool:
    if os.environ.get("VELOGUARD_NO_ASK"):        # tests, headless runs: nobody to ask → Deny
        return False
    env = _session_env()
    return bool(shutil.which("zenity")) and bool(env.get("WAYLAND_DISPLAY") or env.get("DISPLAY"))


def text_for(agent: str, what: str, reason: str, cls: str, cwd: str | None) -> str:
    e = html.escape
    shown = what if len(what) <= 700 else what[:700] + " …"
    t = (f"<b>{e(agent or 'An AI agent')}</b> wants to do something VeloGuard normally doesn't "
         f"let an agent do:\n\n<tt>{e(shown)}</tt>\n")
    if cwd:
        t += f"\nin <tt>{e(cwd)}</tt>\n"
    t += f"\nWhy it was stopped: it {e(reason or 'is restricted')}.\n"
    color, line = _CLASS_LINE.get(cls, ("#f5a623", ""))
    if line:
        t += f"<span foreground='{color}'><b>{e(line)}</b></span>\n"
    t += "\nApprove only if you asked for exactly this. No answer = Deny."
    return t


def ask(agent: str, what: str, reason: str, cls: str = "", cwd: str | None = None,
        timeout: int = TIMEOUT) -> tuple[bool, str]:
    """(approved?, how it was decided). Never raises; anything odd is a Deny."""
    if not can_ask():
        return False, "no desktop to ask on"
    env = _session_env()
    lockdir = Path(env["XDG_RUNTIME_DIR"]) / "veloguard"
    try:
        lockdir.mkdir(mode=0o700, exist_ok=True)
        lock = open(lockdir / "ask.lock", "w")
    except OSError:
        return False, "couldn't open the approval lock"
    deadline = time.monotonic() + timeout
    with lock:
        # one dialog at a time: a burst of requests queues, it doesn't stack
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    return False, "timed out waiting for an earlier question"
                time.sleep(0.3)
        left = max(10, int(deadline - time.monotonic()))
        argv = ["zenity", "--question", "--title", f"VeloGuard — {agent or 'an AI agent'} asks",
                "--text", text_for(agent, what, reason, cls, cwd), "--width", "560",
                "--ok-label", "Approve", "--cancel-label", "Deny", "--default-cancel",
                "--icon", "dialog-warning", f"--timeout={left}"]
        try:
            r = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=left + 15)
        except (OSError, subprocess.TimeoutExpired):
            return False, "the dialog didn't answer"
    if r.returncode == 0:
        return True, "approved by the person"
    return False, "no answer (timed out)" if r.returncode == 5 else "denied by the person"
