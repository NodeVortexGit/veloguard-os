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
import re
import shutil
import subprocess
import time
import unicodedata
from pathlib import Path

TIMEOUT = 90                      # seconds; then it's a Deny

# A dialog shows the person what an agent will do — and the agent chooses that
# text. So nothing in it may render as something other than itself: 30 newlines
# pushed "; curl … | sh" and the red warning below the dialog's 560-px fold,
# U+202E drew the rest of the line backwards, U+200B hid inside a path. Those
# are written out (\n, \u{202e}); a long run of spaces is counted.
_SPACE_RUN = re.compile(r" {4,}")
_NAMED = {"\n": "\\n", "\t": "\\t", "\r": "\\r"}
_BLANK = set("\u115f\u1160\u3164\uffa0\u2800")    # "letters" that draw nothing


def visible(s) -> str:
    """The text with every character that doesn't show as itself written out:
    controls, format characters (bidi, zero-width), separators other than the
    plain space, private-use, combining marks, undecodable bytes."""
    o = []
    for c in str(s):
        cat = unicodedata.category(c)
        if c in _NAMED:
            o.append(_NAMED[c])
        elif (cat[0] == "C" or cat in ("Zl", "Zp", "Mn", "Me") or (cat == "Zs" and c != " ")
              or c in _BLANK):
            cp = ord(c)
            if 0xDC80 <= cp <= 0xDCFF:            # a byte that wasn't UTF-8 (surrogateescape)
                o.append(f"\\x{cp - 0xDC00:02x}")
            elif cp < 0x100:
                o.append(f"\\x{cp:02x}")
            else:
                o.append(f"\\u{{{cp:04x}}}")
        else:
            o.append(c)
    return _SPACE_RUN.sub(lambda m: f" ⟨{len(m.group())} spaces⟩ ", "".join(o))


def esc(s) -> str:
    """Escaped for Pango markup, with nothing hidden (see visible)."""
    return html.escape(visible(s))


HIDDEN_LINE = ("It contains characters that don't show on screen — "
               "they're written out above (\\n, \\u{…}).")

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


def _dialog_program() -> str:
    """VeloGuard's own dialog (rust/ask: Esc = Deny, Ctrl+Enter = Approve), else zenity."""
    ask = Path(__file__).resolve().parent.parent / "bin" / "veloguard-ask"
    return str(ask) if os.access(ask, os.X_OK) else "zenity"


def can_ask() -> bool:
    if os.environ.get("VELOGUARD_NO_ASK"):        # tests, headless runs: nobody to ask → Deny
        return False
    env = _session_env()
    have = _dialog_program() != "zenity" or bool(shutil.which("zenity"))
    return have and bool(env.get("WAYLAND_DISPLAY") or env.get("DISPLAY"))


def text_for(agent: str, what: str, reason: str, cls: str, cwd: str | None,
             who: dict | None = None) -> str:
    e = esc
    shown = what if len(what) <= 700 else what[:700] + " …"
    t = (f"<b>{e(agent or 'An AI agent')}</b> wants to do something VeloGuard normally doesn't "
         f"let an agent do:\n\n<tt>{e(shown)}</tt>\n")
    if cwd:
        t += f"\nin <tt>{e(cwd)}</tt>\n"
    if visible(shown) != shown or (cwd and visible(cwd) != cwd):
        t += f"<span foreground='#e01b24'><b>{e(HIDDEN_LINE)}</b></span>\n"
    t += f"\nWhy it was stopped: it {e(reason or 'is restricted')}.\n"
    color, line = _CLASS_LINE.get(cls, ("#f5a623", ""))
    if line:
        t += f"<span foreground='{color}'><b>{e(line)}</b></span>\n"
    if who:
        t += "\n" + _who_block(who) + "\n"
    t += "\nApprove only if you asked for exactly this. No answer = Deny."
    return t


def _who_block(who: dict) -> str:
    try:
        from . import agentid
        return agentid.pango(who)
    except Exception:  # noqa: BLE001 — the question still gets asked
        return ""


def question_text(agent: str, question: str, details: str = "", who: dict | None = None) -> str:
    """An agent asking the person something (MCP ask_permission) — its words, marked as such."""
    e = esc
    q = question if len(question) <= 500 else question[:500] + " …"
    t = f"<b>{e(agent or 'An AI agent')}</b> asks for your permission:\n\n<i>{e(q)}</i>\n"
    if details:
        d = details if len(details) <= 1200 else details[:1200] + " …"
        t += f"\n<tt>{e(d)}</tt>\n"
    if who:
        t += "\n" + _who_block(who) + "\n"
    t += ("\n<small>These are the agent's own words. Approving answers its question; "
          "it gives it no new access — root still asks separately.</small>"
          "\n\nNo answer = Deny.")
    return t


def ask(agent: str, what: str, reason: str, cls: str = "", cwd: str | None = None,
        timeout: int = TIMEOUT, who: dict | None = None) -> tuple[bool, str]:
    """(approved?, how it was decided). Never raises; anything odd is a Deny."""
    return _dialog(f"VeloGuard — {agent or 'an AI agent'} asks",
                   text_for(agent, what, reason, cls, cwd, who), timeout)


def ask_question(agent: str, question: str, details: str = "", who: dict | None = None,
                 timeout: int = TIMEOUT) -> tuple[bool, str]:
    return _dialog(f"VeloGuard — {agent or 'an AI agent'} asks your permission",
                   question_text(agent, question, details, who), timeout, icon="dialog-question")


def _dialog(title: str, text: str, timeout: int, icon: str = "dialog-warning") -> tuple[bool, str]:
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
        argv = [_dialog_program(), "--question", "--title", title[:120],
                "--text", text, "--width", "580",
                "--ok-label", "Approve", "--cancel-label", "Deny", "--default-cancel",
                "--icon", icon, f"--timeout={left}"]
        try:
            r = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=left + 15)
        except (OSError, subprocess.TimeoutExpired):
            return False, "the dialog didn't answer"
    if r.returncode == 0:
        return True, "approved by the person"
    return False, "no answer (timed out)" if r.returncode == 5 else "denied by the person"
