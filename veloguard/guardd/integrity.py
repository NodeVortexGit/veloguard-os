"""Integrity — the guard checks itself (zero trust: assume breach).

A root-only baseline (/var/lib/veloguard/integrity.json) holds the sha256 of
every file that IS the guard: its code, its helpers on PATH, the agents'
plugins, its polkit rules, firewall, Codex policy and units. `check` (at boot
and every 6 h, veloguard-integrity.timer) compares; anything changed, added or
gone outside a deploy becomes an incident ("Investigate with an AI agent").
A deploy ends with `update`, which re-baselines.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import time
from pathlib import Path

BASELINE = Path("/var/lib/veloguard/integrity.json")
COVERED = [
    "/opt/veloguard/guardd/*.py", "/opt/veloguard/bin/*", "/opt/veloguard/provision/*",
    "/opt/veloguard/*.json", "/usr/local/bin/veloguard*", "/usr/share/veloguard/agents/**",
    "/etc/veloguard/**", "/etc/polkit-1/rules.d/49-veloguard*", "/etc/codex/requirements.toml",
    "/etc/systemd/system/veloguard*", "/etc/tmpfiles.d/veloguard.conf",
    "/etc/sysctl.d/90-veloguard*", "/etc/systemd/resolved.conf.d/90-veloguard*",
    "/etc/NetworkManager/conf.d/90-veloguard*", "/etc/NetworkManager/dispatcher.d/90-veloguard",
]
SKIP = ("/__pycache__/", ".orig-", ".pyc")


def files() -> list[str]:
    out = set()
    for pat in COVERED:
        for f in glob.glob(pat, recursive=True):
            if os.path.isfile(f) and not any(s in f for s in SKIP):
                out.add(os.path.realpath(f) if not os.path.islink(f) else f)
    return sorted(out)


def digest(path: str) -> str:
    if os.path.islink(path):
        return "link:" + os.readlink(path)
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot() -> dict[str, str]:
    snap = {}
    for f in files():
        try:
            snap[f] = digest(f)
        except OSError:
            continue
    return snap


def update() -> int:
    snap = snapshot()
    BASELINE.parent.mkdir(parents=True, exist_ok=True)
    tmp = BASELINE.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"ts": time.time(), "files": snap}, f, indent=1)
    os.replace(tmp, BASELINE)
    return len(snap)


def check() -> dict:
    """{"changed", "added", "removed"} against the baseline (or "no_baseline")."""
    try:
        base = json.loads(BASELINE.read_text())["files"]
    except (OSError, ValueError, KeyError):
        return {"no_baseline": True}
    now = snapshot()
    return {"changed": sorted(f for f in now if f in base and now[f] != base[f]),
            "added": sorted(f for f in now if f not in base),
            "removed": sorted(f for f in base if f not in now)}
