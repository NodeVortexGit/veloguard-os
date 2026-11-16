"""Incidents — what the guard caught, kept so a person (and the AI agent they
pick) can look into it: a honeypot capture with the brain's diagnosis, a
process the guard quarantined.

Stored one JSON file per incident in <state>/incidents (the system store,
/var/lib/veloguard/incidents, is 0750 root:wheel: admins read it, nobody else).
Each new one is announced on the desktop with "Investigate with <agent>"
(veloguard-notify), which opens the agent of the person's choice on it —
through its VeloGuard plugin (/veloguard:investigate in Claude Code).

Everything in an incident came from an attacker's traffic or a suspicious
program: it is DATA for the agent, framed as such wherever it is handed over.
"""
from __future__ import annotations

import grp
import json
import os
import subprocess
import time
from pathlib import Path

from . import state

NOTIFY = "/usr/local/bin/veloguard-notify"


def incident_dir() -> Path:
    d = state.state_dir() / "incidents"
    d.mkdir(exist_ok=True)
    if os.geteuid() == 0:
        try:
            os.chown(d, 0, grp.getgrnam("wheel").gr_gid)
            d.chmod(0o750)
        except (KeyError, OSError):
            d.chmod(0o700)
    return d


def _readable_dirs() -> list[Path]:
    """The system store first (when this user may read it), then their own."""
    out = []
    sysd = Path("/var/lib/veloguard/incidents")
    if os.access(sysd, os.R_OK | os.X_OK):
        out.append(sysd)
    own = state.state_dir() / "incidents"
    if own.is_dir() and own not in out:
        out.append(own)
    return out


def save(kind: str, title: str, details: dict, notify: bool = True) -> dict:
    ts = time.time()
    iid = time.strftime("%Y%m%d-%H%M%S", time.localtime(ts)) + f"-{kind}"
    inc = {"id": iid, "ts": ts, "iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts)),
           "kind": kind, "title": title, "details": details}
    d = incident_dir()
    f = d / f"{iid}.json"
    fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
    with os.fdopen(fd, "w") as fh:
        json.dump(inc, fh, indent=2, default=str)
    if os.geteuid() == 0:
        try:
            os.chown(f, 0, grp.getgrnam("wheel").gr_gid)
        except (KeyError, OSError):
            pass
    if notify:
        announce(inc)
    return inc


def latest(n: int = 10) -> list[dict]:
    rows = []
    for d in _readable_dirs():
        for f in d.glob("*.json"):
            try:
                rows.append(json.loads(f.read_text()))
            except (OSError, ValueError):
                continue
    rows.sort(key=lambda r: r.get("ts", 0), reverse=True)
    return rows[:n]


def get(iid: str) -> dict | None:
    if iid in ("latest", ""):
        r = latest(1)
        return r[0] if r else None
    return next((r for r in latest(500) if r.get("id") == iid), None)


def as_text(inc: dict, limit: int = 6000) -> str:
    body = json.dumps(inc.get("details", {}), indent=2, default=str)
    if len(body) > limit:
        body = body[:limit] + "\n…(truncated)"
    return f"[{inc.get('iso')}] {inc.get('kind')}: {inc.get('title')}\n{body}"


def responder_alive(uid: int) -> bool:
    """`veloguard watch` is running in that person's session: it has the
    current agent write a report and announces the incident itself."""
    try:
        p = Path(f"/run/user/{uid}/veloguard/responder.alive")
        return time.time() - p.stat().st_mtime < 60
    except OSError:
        return False


def announce(inc: dict) -> None:
    """A desktop notification with "Investigate with <agent>". Never raises:
    the incident is saved whether or not anyone is there to see it."""
    if not os.path.exists(NOTIFY):
        return
    try:
        if os.geteuid() == 0:
            from .agent_plugins import session_user
            import pwd
            u = session_user()
            uid = pwd.getpwnam(u).pw_uid if u else -1
        else:
            uid = os.getuid()
        if uid >= 0 and responder_alive(uid):
            return                      # the watch reports it, with the agent's verdict
    except (KeyError, OSError):
        pass
    argv = [NOTIFY, "--incident", inc["id"], "VeloGuard caught something", inc["title"]]
    try:
        if os.geteuid() == 0:
            from .agent_plugins import session_user
            import pwd
            u = session_user()
            if not u:
                return
            uid = pwd.getpwnam(u).pw_uid
            argv = ["runuser", "-u", u, "--", "env",
                    f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
                    f"XDG_RUNTIME_DIR=/run/user/{uid}", "WAYLAND_DISPLAY=wayland-1",
                    "PATH=/usr/local/bin:/usr/bin", *argv]
        subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    except (OSError, KeyError):
        pass
