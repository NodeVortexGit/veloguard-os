"""Tamper-evident-ish audit trail. Every intent that reaches the guard — allowed,
denied, or approved — lands here as one JSON line. If an AI ever does something
to this box, the answer to 'what and when' lives in this file.

Location (first that applies):
  $VELOGUARD_AUDIT_LOG
  /var/log/veloguard/audit.log           when running as root (services, pkexec)
  <checkout>/audit.log                   a writable dev checkout (demo.sh reads it)
  ~/.config/veloguard/audit.log          everyone else (desktop agent, user MCP)
The install dir (/opt/veloguard) is root-owned, so writing there from the
desktop user's agent used to raise PermissionError on the first decision.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

DEFAULT_LOG = Path(__file__).resolve().parent.parent / "audit.log"
SYSTEM_LOG = Path("/var/log/veloguard/audit.log")
_warned = False


def log_path() -> Path:
    env = os.environ.get("VELOGUARD_AUDIT_LOG")
    if env:
        return Path(env)
    if os.geteuid() == 0:
        return SYSTEM_LOG
    if os.access(DEFAULT_LOG.parent, os.W_OK) and (
            not DEFAULT_LOG.exists() or os.access(DEFAULT_LOG, os.W_OK)):
        return DEFAULT_LOG
    from . import state
    return state.state_dir() / "audit.log"


def record(entry: dict, log_path_: Path | None = None) -> None:
    """Append one decision. Never raises: an unwritable log must not turn a
    refused/approved action into a crash (the decision itself already happened);
    it warns once on stderr instead."""
    global _warned
    entry = {"ts": time.time(), "iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
             "pid": os.getpid(), "uid": os.getuid(), **entry}
    path = log_path_ or log_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except OSError as e:
        if not _warned:
            print(f"veloguard: audit log {path} not writable ({e})", file=sys.stderr)
            _warned = True
