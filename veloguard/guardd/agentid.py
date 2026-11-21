"""Who is asking — the AI agent behind a request, read from the process tree.

What an agent says about itself (VELOGUARD_AGENT, `--agent NAME`, the MCP
clientInfo) is a claim. This module answers from /proc instead: it walks up
from the requesting process to the nearest ancestor that IS a known agent's
program and describes it — which product, which version, which process, when
it started, where it works and how the request reached the guard (a `sudo` in
the agent's shell, or the VeloGuard MCP server). The root dialog
(veloguard-elevate-root, running as root) and the MCP server both use it, so a
pop-up names "Codex 0.169.0 — app-server, process 202479, started 01:13", not
"a program".

Limits, stated plainly: this is the user's own process tree. A program running
as the user can copy an agent's binary into an agent's install path; the
program's path is part of the description so the person can spot an odd one.
Reading is careful because the root helper runs it: /proc only, plus small
regular files (package metadata, at most 1 MiB) opened non-blocking — a FIFO or a huge file
planted by the user can't stall or flood it.
"""
from __future__ import annotations

import json
import os
import re
import stat
import time

MAX_DEPTH = 64
_VERSION = re.compile(r"^\d+(\.\d+){1,3}([.+-][0-9A-Za-z.]{1,30})?$")
_SHELLS = {"bash", "sh", "zsh", "dash", "fish", "env", "timeout", "nice", "nohup",
           "pkexec", "sudo", "setsid", "script", "stdbuf", "xargs"}


# --- /proc ----------------------------------------------------------------------

def _read(path: str, limit: int = 65536) -> bytes:
    with open(path, "rb") as f:
        return f.read(limit)


def proc(pid: int) -> dict | None:
    """The bits of one process the description needs, or None if it's gone."""
    try:
        raw = _read(f"/proc/{pid}/stat").decode(errors="replace")
        fields = raw[raw.rindex(")") + 2:].split()
        status = _read(f"/proc/{pid}/status").decode(errors="replace")
        uid = int(next(l.split()[1] for l in status.splitlines() if l.startswith("Uid:")))
        argv = [a.decode(errors="replace") for a in _read(f"/proc/{pid}/cmdline").split(b"\0") if a]
    except (OSError, ValueError, StopIteration, IndexError):
        return None
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        exe = ""
    return {"pid": pid, "ppid": int(fields[1]), "start": fields[19], "uid": uid,
            "exe": exe.removesuffix(" (deleted)"), "argv": argv, "tty": int(fields[4])}


def ancestors(pid: int):
    """pid itself, then its parent, … up to (not including) init."""
    seen = 0
    while pid > 1 and seen < MAX_DEPTH:
        p = proc(pid)
        if p is None:
            return
        yield p
        pid, seen = p["ppid"], seen + 1


def started_at(start_ticks: str) -> float | None:
    """A /proc start time (clock ticks since boot) as a Unix time."""
    try:
        btime = next(int(l.split()[1]) for l in _read("/proc/stat").decode().splitlines()
                     if l.startswith("btime "))
        return btime + int(start_ticks) / os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError, StopIteration):
        return None


def _cwd(pid: int) -> str:
    try:
        return os.readlink(f"/proc/{pid}/cwd")
    except OSError:
        return ""


# --- package metadata (for versions) ----------------------------------------------

_META_MAX = 1 << 20          # OpenClaw's package.json alone is ~150 KiB


def _small_json(path: str) -> dict | None:
    """A regular file of at most 1 MiB, parsed — never a FIFO, device or link loop."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > _META_MAX:
            return None
        data = os.read(fd, _META_MAX)
    except OSError:
        return None
    finally:
        os.close(fd)
    try:
        v = json.loads(data)
    except ValueError:
        return None
    return v if isinstance(v, dict) else None


def _version_near(path: str, names: tuple[str, ...] = (), files=("package.json",),
                  levels: int = 6) -> str | None:
    """The "version" of the nearest package file above `path` (whose "name"
    is one of `names`, when given)."""
    d = os.path.dirname(path)
    for _ in range(levels):
        for fn in files:
            meta = _small_json(os.path.join(d, fn))
            if meta and (not names or meta.get("name") in names or fn != "package.json"):
                v = str(meta.get("version", ""))
                if _VERSION.match(v):
                    return v.split("+")[0]
        nd = os.path.dirname(d)
        if nd == d:
            break
        d = nd
    return None


def _script(argv: list[str]) -> str:
    """The script a node/python/bun interpreter runs (its first non-option arg)."""
    for a in argv[1:]:
        if not a.startswith("-"):
            return a
    return ""


# --- recognising an agent --------------------------------------------------------

def recognise(p: dict) -> dict | None:
    """{label, version, role} when this process is a known AI agent's program."""
    exe, argv = p["exe"], p["argv"]
    name = os.path.basename(exe)
    cmd = " ".join(argv)
    args = argv[1:]

    m = re.search(r"/\.local/share/claude/versions/([^/]+)$", exe)
    if m or name == "claude" or ("@anthropic-ai/claude-code" in cmd and name.startswith(("node", "bun"))):
        ver = m.group(1) if m and _VERSION.match(m.group(1)) else None
        if ver is None and "@anthropic-ai/claude-code" in cmd:
            ver = _version_near(_script(argv), ("@anthropic-ai/claude-code",))
        role = ("its background daemon" if args[:1] == ["daemon"] else
                "a background session" if any(a.startswith("--bg-") for a in args) else "")
        return {"label": "Claude Code", "version": ver, "role": role}

    if name in ("codex", "codex-cli") or name.startswith("codex-") or "@openai/codex" in cmd:
        ver = _version_near(exe, files=("codex-package.json",), levels=3)
        if ver is None and "@openai/codex" in cmd:
            ver = _version_near(_script(argv) or exe, ("@openai/codex",))
        role = ("its app-server — it serves every open Codex window"
                if "app-server" in args[:1] or "/app-server-daemon/" in exe else
                "its code-mode runner" if name.startswith("codex-code-mode") else "")
        return {"label": "Codex", "version": ver, "role": role}

    if name.startswith(("node", "bun", "deno")) or name == "kimi":
        script = _script(argv)
        if "kimi-code" in cmd or "/.kimi-code/" in exe or name == "kimi":
            return {"label": "Kimi Code", "role": "",
                    "version": _version_near(script, ("@moonshot-ai/kimi-code",))}
        if "openclaw" in cmd:
            return {"label": "OpenClaw", "role": "its gateway" if "gateway" in args else "",
                    "version": _version_near(script, ("openclaw",))}
        if "@openai/codex" in cmd:
            return {"label": "Codex", "role": "", "version": _version_near(script, ("@openai/codex",))}

    if name.startswith("python") and ("hermes" in cmd or "/.hermes/" in exe):
        return {"label": "Hermes Agent", "version": None, "role": ""}
    return None


def _when(epoch: float | None) -> str:
    if epoch is None:
        return ""
    lt, now = time.localtime(epoch), time.localtime()
    return time.strftime("%H:%M" if lt[:3] == now[:3] else "%b %d %H:%M", lt)


def _home_rel(path: str, uid: int | None = None) -> str:
    """~/… for a path in that user's home. No stat of the path itself: as root,
    stat on a user's FUSE mount could hang the approval."""
    home = os.environ.get("HOME", "")
    if uid is not None:
        try:
            import pwd
            home = pwd.getpwuid(uid).pw_dir
        except (KeyError, ImportError):
            pass
    if home and home != "/" and (path == home or path.startswith(home + "/")):
        return "~" + path[len(home):]
    return path


def _generic(name: str) -> bool:
    return re.sub(r"[^a-z]", "", (name or "").lower()) in (
        "", "aprogram", "anaiagent", "aiagent", "agent", "unknown", "program")


def describe(pid: int, claimed: str | None = None, uid: int | None = None) -> dict:
    """Who is behind process `pid`: the nearest agent ancestor (run by `uid`,
    when given), described from /proc. `claimed` is what the requester called
    itself; it's kept only when it doesn't match what was verified."""
    chain = list(ancestors(pid))
    via = "shell"
    for p in chain:
        if any("guardd.mcp_server" in a for a in p["argv"][:4]):
            via = "mcp"
        r = recognise(p)
        if r and (uid is None or p["uid"] == uid):
            d = {"verified": True, **r, "pid": p["pid"], "start": p["start"], "uid": p["uid"],
                 "exe": p["exe"], "started": _when(started_at(p["start"])),
                 "cwd": _home_rel(_cwd(p["pid"]), p["uid"]), "via": via}
            name = d["label"] + (f" {d['version']}" if d.get("version") else "")
            d["name"] = name
            if claimed and not _generic(claimed):
                c = re.sub(r"[^a-z0-9]", "", claimed.lower())
                if re.sub(r"[^a-z0-9]", "", d["label"].lower()) not in c:
                    d["claimed"] = claimed[:60]
            return d
    # No agent among the ancestors: name the exact program that asked.
    req = next((p for p in chain if os.path.basename(p["exe"]) not in _SHELLS
                and not any("guardd.mcp_server" in a for a in p["argv"][:4])),
               chain[0] if chain else None)
    exe = req["exe"] if req else ""
    d = {"verified": False, "label": "a program that isn't a known AI agent", "version": None,
         "role": "", "pid": req["pid"] if req else pid, "start": req["start"] if req else "",
         "uid": req["uid"] if req else None, "exe": exe,
         "started": _when(started_at(req["start"])) if req else "",
         "cwd": _home_rel(_cwd(req["pid"]), req["uid"]) if req else "", "via": via,
         "name": f"{os.path.basename(exe) or 'unknown program'} (not a known AI agent)",
         "chain": " ← ".join(os.path.basename(p["exe"]) or "?" for p in chain[:5])}
    if claimed and not _generic(claimed):
        d["claimed"] = claimed[:60]
    return d


def one_line(d: dict) -> str:
    """Plain text: 'Codex 0.169.0 — process 202479 (its app-server…), started
    01:13, working in ~, through the VeloGuard MCP server'."""
    bits = [f"process {d['pid']}" + (f" ({d['role']})" if d.get("role") else "")]
    if d.get("started"):
        bits.append(f"started {d['started']}")
    if d.get("cwd"):
        bits.append(f"working in {d['cwd']}")
    bits.append("through the VeloGuard MCP server" if d.get("via") == "mcp"
                else "through a command in its shell")
    s = f"{d['name']} — " + ", ".join(bits)
    if d.get("claimed"):
        s += f"; it calls itself “{d['claimed']}”"
    if not d.get("verified") and d.get("chain"):
        s += f"; process chain: {d['chain']}"
    return s


def pango(d: dict) -> str:
    """The 'who is asking' block for a zenity dialog (Pango markup, escaped)."""
    from html import escape as e
    lines = [f"<b>Who is asking</b> (read from the process tree, not taken on its word):",
             f"• {e(d['name'])}" + (f" — {e(d['role'])}" if d.get("role") else ""),
             f"• process {d['pid']}" + (f", started {e(d['started'])}" if d.get("started") else "")
             + (f", working in <tt>{e(d['cwd'])}</tt>" if d.get("cwd") else ""),
             f"• program <tt>{e(d['exe'] or '?')}</tt>",
             "• asked " + ("through the VeloGuard MCP server" if d.get("via") == "mcp"
                           else "through a command in its shell (sudo)")]
    if d.get("claimed"):
        lines.append(f"• <span foreground='#f5a623'>it calls itself “{e(d['claimed'])}” — "
                     "that doesn't match the program above</span>")
    if not d.get("verified"):
        lines.append(f"• <span foreground='#e01b24'>not a known AI agent</span>"
                     + (f" (chain: {e(d.get('chain', ''))})" if d.get("chain") else ""))
    return "<small>" + "\n".join(lines) + "</small>"


def me(claimed: str | None = None) -> dict:
    """Who the current process works for (the MCP server, a hook)."""
    return describe(os.getpid(), claimed, os.getuid())
