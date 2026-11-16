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

import fcntl
import hashlib
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


def _chain_hash(prev: str, entry: dict) -> str:
    body = json.dumps({k: v for k, v in entry.items() if k != "hash"}, sort_keys=True, default=str)
    return hashlib.sha256((prev + "\n" + body).encode()).hexdigest()


def _last_hash(f) -> str:
    """The hash of the log's last entry ("" for a new or pre-chain log)."""
    f.seek(0, os.SEEK_END)
    size = f.tell()
    f.seek(max(0, size - 65536))
    lines = f.read().splitlines()
    for line in reversed(lines):
        try:
            return json.loads(line).get("hash", "") or ""
        except ValueError:
            continue
    return ""


def record(entry: dict, log_path_: Path | None = None) -> None:
    """Append one decision. Never raises: an unwritable log must not turn a
    refused/approved action into a crash (the decision itself already happened);
    it warns once on stderr instead.

    Hash-chained (zero trust, assume breach): each entry carries the hash of the
    one before it, so editing or deleting a past entry breaks the chain —
    `veloguard audit verify` says where."""
    global _warned
    entry = {"ts": time.time(), "iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
             "pid": os.getpid(), "uid": os.getuid(), **entry}
    path = log_path_ or log_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            entry["prev"] = _last_hash(f)
            entry["hash"] = _chain_hash(entry["prev"], entry)
            f.write(json.dumps(entry, default=str) + "\n")
    except OSError as e:
        if not _warned:
            print(f"veloguard: audit log {path} not writable ({e})", file=sys.stderr)
            _warned = True


def verify(path: Path | None = None) -> tuple[bool, str]:
    """Walk the chain. (ok, message) — the first broken line, if any. Entries
    written before chaining began (no "hash") are skipped until the first one."""
    path = path or log_path()
    try:
        lines = path.read_text().splitlines()
    except OSError as e:
        return False, f"can't read {path} ({e})"
    prev, checked, started = "", 0, False
    for n, line in enumerate(lines, 1):
        try:
            e = json.loads(line)
        except ValueError:
            return False, f"line {n}: not valid JSON — the log was edited"
        if "hash" not in e:
            if started:
                return False, f"line {n}: an entry without a hash inside the chain — inserted?"
            continue
        if started and e.get("prev") != prev:
            return False, f"line {n}: chain broken — an entry before it was changed or removed"
        if _chain_hash(e.get("prev", ""), e) != e["hash"]:
            return False, f"line {n}: entry changed after it was written"
        prev, started, checked = e["hash"], True, checked + 1
    return True, f"ok — {checked} chained entries intact ({path})"
