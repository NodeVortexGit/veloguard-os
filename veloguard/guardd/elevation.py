"""Root for AI agents, over MCP — sudo_run, sudo_grant, sudo_status, sudo_revoke,
sudo_result, and ask_permission.

The agent never gets root itself. Every request goes the one road root goes on
VeloGuardOS: veloguard-elevate → pkexec → veloguard-elevate-root, which reads
WHO is asking from the process tree (guardd/agentid.py — "Codex 0.169.0,
app-server process 202479, through the VeloGuard MCP server"), shows the exact
command, the folder and the agent's own reason on the person's real screen,
and runs nothing until they click Approve. A time-limited grant (sudo_grant:
the agent picks how long, at most 4 h, the person approves it once) lets that
one agent's later root commands run without a dialog — never the ones that
would switch the guard off.

Never freezing the agent: the dialog waits up to 2 minutes for the person, and
an MCP client gives up on a tool call long before that (Codex: 60 s). So a
call waits at most `wait_seconds` (default 40) and otherwise answers
{"status": "pending", "request_id": …}; the request carries on in the
background and `sudo_result` collects it. Calls run on their own threads in
the MCP server, so one waiting dialog never blocks another tool.

Output is capped (first 16 KiB + last 48 KiB of each stream). Root commands
can't be signalled from here (they run as root): --timeout makes ROOT stop them.
"""
from __future__ import annotations

import itertools
import json
import os
import re
import shlex
import shutil
import subprocess
import threading
import time

from . import agentid
from .audit import record

DEFAULT_WAIT, MAX_WAIT = 40, 55
DEFAULT_TIMEOUT, MAX_TIMEOUT = 600, 6 * 3600
HEAD, TAIL = 16 * 1024, 48 * 1024
INPUT_MAX = 1 << 20
KEEP = 32                                   # finished results kept for sudo_result
GRANT_INFO = os.environ.get("VELOGUARD_GRANT_INFO", "/run/veloguard-grant.json")
AGENT_RE = re.compile(r"[^A-Za-z0-9 ._+-]")
MARK = "VELOGUARD-ELEVATE "

_lock = threading.Lock()
_reqs: dict[str, "_Req"] = {}
_ids = itertools.count(1)


def elevate_bin() -> str:
    return (os.environ.get("VELOGUARD_ELEVATE") or shutil.which("veloguard-elevate")
            or "/usr/local/bin/veloguard-elevate")


def claimed_name(ctx: dict) -> str:
    """What this agent calls itself, in the shape --agent accepts."""
    c = ctx.get("client") or {}
    name = c.get("title") or c.get("name") or os.environ.get("VELOGUARD_AGENT") or "an AI agent"
    if c.get("version"):
        name = f"{name} {c['version']}"
    return AGENT_RE.sub("", name)[:40].strip() or "an AI agent"


# --- capped output ----------------------------------------------------------------

class _Capped:
    def __init__(self):
        self.head, self.tail, self.total = bytearray(), bytearray(), 0

    def add(self, b: bytes) -> None:
        self.total += len(b)
        room = HEAD - len(self.head)
        if room > 0:
            self.head += b[:room]
            b = b[room:]
        if b:
            self.tail += b
            if len(self.tail) > TAIL:
                del self.tail[:len(self.tail) - TAIL]

    def text(self) -> tuple[str, bool]:
        cut = self.total > len(self.head) + len(self.tail)
        mid = f"\n…[{self.total - len(self.head) - len(self.tail)} bytes cut]…\n" if cut else ""
        return (self.head.decode(errors="replace") + mid + self.tail.decode(errors="replace")), cut


def _pump(stream, sink: _Capped, on_line=None) -> None:
    buf = b""
    for chunk in iter(lambda: stream.read1(65536) if hasattr(stream, "read1") else stream.read(65536), b""):
        if on_line:
            buf += chunk
            *lines, buf = buf.split(b"\n")
            for ln in lines:
                if not on_line(ln):
                    sink.add(ln + b"\n")
        else:
            sink.add(chunk)
    if buf and (not on_line or not on_line(buf)):
        sink.add(buf)


# --- requests ----------------------------------------------------------------------

class _Req:
    def __init__(self, kind: str, what: str):
        self.id = f"r{next(_ids)}-{int(time.time()) % 100000}"
        self.kind, self.what, self.started = kind, what, time.time()
        self.done = threading.Event()
        self.result: dict | None = None
        self.decision: dict | None = None             # the root helper's VELOGUARD-ELEVATE line

    def finish(self, result: dict) -> None:
        self.result = result
        self.done.set()


def _register(req: _Req) -> None:
    with _lock:
        _reqs[req.id] = req
        finished = [r for r in _reqs.values() if r.done.is_set()]
        for r in sorted(finished, key=lambda r: r.started)[:max(0, len(_reqs) - KEEP)]:
            _reqs.pop(r.id, None)


def _await(req: _Req, wait: float) -> dict:
    if req.done.wait(max(0.0, min(wait, MAX_WAIT))):
        with _lock:
            _reqs.pop(req.id, None)
        return {**(req.result or {}), "request_id": req.id}
    d = (req.decision or {}).get("decision")
    if req.kind == "command" and d == "approved":
        waiting = "the command to finish (it was approved)"
    elif not d:
        waiting = "the person's answer on screen (Approve / Deny, up to 2 minutes)"
    else:
        waiting = "it to finish"
    return {"ok": False, "status": "pending", "request_id": req.id, "kind": req.kind,
            "waiting_for": waiting, "seconds_so_far": int(time.time() - req.started),
            "next": f"call sudo_result with request_id \"{req.id}\" (it can wait up to {MAX_WAIT} s)"}


def _spawn(req: _Req, argv: list[str], cwd: str, stdin: bytes | None, parse) -> None:
    """Run argv in the background; parse(req, rc, out, err, cut) → the result."""
    def on_err_line(line: bytes) -> bool:
        if line.startswith(MARK.encode()):
            try:
                req.decision = json.loads(line[len(MARK):])
            except ValueError:
                pass
            return True                                # not part of the command's stderr
        return False

    def run() -> None:
        try:
            p = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.PIPE if stdin else subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env={**os.environ, "PWD": cwd}, start_new_session=True)
        except OSError as e:
            req.finish({"ok": False, "status": "failed", "error": f"couldn't start {argv[0]}: {e}"})
            return
        out, err = _Capped(), _Capped()
        ts = [threading.Thread(target=_pump, args=(p.stdout, out), daemon=True),
              threading.Thread(target=_pump, args=(p.stderr, err, on_err_line), daemon=True)]
        for t in ts:
            t.start()
        if stdin:
            try:
                p.stdin.write(stdin)
            except (BrokenPipeError, OSError):
                pass
        if p.stdin:
            try:
                p.stdin.close()
            except OSError:
                pass
        rc = p.wait()
        for t in ts:
            t.join(5)
        o, oc = out.text()
        e, ec = err.text()
        try:
            req.finish(parse(req, rc, o, e, oc or ec))
        except Exception as ex:  # noqa: BLE001 — a result must always arrive
            req.finish({"ok": False, "status": "failed", "error": str(ex), "exit_code": rc})

    _register(req)
    threading.Thread(target=run, daemon=True, name=f"vg-{req.id}").start()


def _decision_or_polkit(req: _Req, rc: int, err: str) -> dict:
    if req.decision:
        return req.decision
    if "Not authorized" in err or "Error executing command as another user" in err or rc in (126,):
        return {"decision": "refused", "how": "polkit refused to start the approval helper "
                "(not an active local admin session?)"}
    if rc == 127 and "pkexec" in err:
        return {"decision": "failed", "how": "pkexec is missing"}
    return {"decision": "unknown", "how": "the approval helper gave no decision"}


# --- helpers for args --------------------------------------------------------------

def _num(args: dict, key: str, default: int, lo: int, hi: int) -> int:
    v = args.get(key, default)
    try:
        v = int(v)
    except (TypeError, ValueError):
        raise ValueError(f"{key} must be a number")
    return max(lo, min(hi, v))


def _text(args: dict, key: str, limit: int, required: bool = False) -> str:
    v = args.get(key, "")
    if v is None:
        v = ""
    if not isinstance(v, str):
        raise ValueError(f"{key} must be a string")
    v = v.strip()
    if required and not v:
        raise ValueError(f"{key} is required")
    if len(v) > limit:
        raise ValueError(f"{key} is too long (at most {limit} characters)")
    return v


def _command(args: dict) -> list[str]:
    cmd = args.get("command")
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    if not isinstance(cmd, list) or not cmd or not all(isinstance(c, str) and c for c in cmd):
        raise ValueError("command must be a non-empty list of strings, e.g. [\"pacman\", \"-S\", \"git\"]")
    if any("\0" in c for c in cmd):
        raise ValueError("command contains a NUL byte")
    return cmd


def _cwd(args: dict, ctx: dict) -> str:
    cwd = args.get("cwd") or ctx.get("cwd") or os.path.expanduser("~")
    if not isinstance(cwd, str) or not os.path.isdir(cwd):
        raise ValueError(f"cwd {cwd!r} is not a folder")
    return os.path.realpath(cwd)


def _who(ctx: dict) -> dict:
    return ctx.get("who") or agentid.me(claimed_name(ctx))


def _audit(ctx: dict, entry: dict) -> None:
    w = _who(ctx)
    record({"control": "mcp-root", "source": "mcp", "agent": w.get("name"),
            "who": agentid.one_line(w), **entry})


# --- the tools ------------------------------------------------------------------------

def sudo_run(args: dict, ctx: dict) -> dict:
    cmd = _command(args)
    cwd = _cwd(args, ctx)
    reason = _text(args, "reason", 300)
    timeout = _num(args, "timeout_seconds", DEFAULT_TIMEOUT, 1, MAX_TIMEOUT)
    wait = _num(args, "wait_seconds", DEFAULT_WAIT, 0, MAX_WAIT)
    data = args.get("input")
    if data is not None and not isinstance(data, str):
        raise ValueError("input must be a string")
    stdin = data.encode() if data else None
    if stdin and len(stdin) > INPUT_MAX:
        raise ValueError("input is larger than 1 MiB — write it to a file and pass the path")
    argv = [elevate_bin(), "--agent", claimed_name(ctx), "--report", "--timeout", str(timeout)]
    if reason:
        argv += ["--reason", reason]
    argv += ["--", *cmd]
    shown = shlex.join(cmd)
    _audit(ctx, {"tool": "sudo_run", "argv": cmd, "cwd": cwd, "reason": reason, "result": "asked"})

    def parse(req, rc, out, err, cut):
        d = _decision_or_polkit(req, rc, err)
        dec = d.get("decision")
        if dec == "approved":
            res = {"ok": rc == 0, "status": "done", "approved": d.get("how"), "exit_code": rc,
                   "stdout": out, "stderr": err, **({"truncated": True} if cut else {})}
            if rc == 124 and "time limit" in err:
                res["status"] = "stopped_at_time_limit"
            return res
        hint = {"denied": "The person said no. Take that as the answer — don't retry it, "
                          "rephrase it or look for another way to root.",
                "timeout": "Nobody answered within 2 minutes (that counts as a Deny). "
                           "Ask the person in the chat before trying again.",
                "no_desktop": "No desktop session to show the question on — the person has "
                              "to run it themselves in a terminal."}.get(dec, "")
        return {"ok": False, "status": dec or "failed", "how": d.get("how"), "exit_code": rc,
                **({"hint": hint} if hint else {}), **({"stderr": err[-2000:]} if dec not in
                                                        ("denied", "timeout") and err else {})}

    req = _Req("command", shown)
    _spawn(req, argv, cwd, stdin, parse)
    return _await(req, wait)


def sudo_grant(args: dict, ctx: dict) -> dict:
    dur = args.get("duration")
    if isinstance(dur, (int, float)) and not isinstance(dur, bool):
        dur = f"{int(dur)}m"                                  # a bare number = minutes
    if not isinstance(dur, str) or not re.fullmatch(r"\s*(\d+\s*h)?\s*(\d+\s*m(in)?)?\s*", dur or "") \
            or not re.search(r"\d", dur or ""):
        raise ValueError("duration like \"45m\", \"2h\" or \"1h30m\" (at most 4h)")
    dur = dur.replace(" ", "").replace("min", "m")
    reason = _text(args, "reason", 300, required=True)
    wait = _num(args, "wait_seconds", DEFAULT_WAIT, 0, MAX_WAIT)
    argv = [elevate_bin(), "--agent", claimed_name(ctx), "--report", "--reason", reason,
            "--grant", dur]
    _audit(ctx, {"tool": "sudo_grant", "duration": dur, "reason": reason, "result": "asked"})

    def parse(req, rc, out, err, cut):
        d = _decision_or_polkit(req, rc, err)
        if d.get("decision") == "granted":
            secs = int(d.get("seconds", 0))
            return {"ok": True, "status": "granted", "minutes": secs // 60,
                    "expires": time.strftime("%H:%M", time.localtime(d.get("expires", 0))),
                    **({"note": f"you asked for {int(d['asked_seconds']) // 60} min; "
                                "the most VeloGuard gives is 4 h"}
                       if d.get("asked_seconds", 0) > secs else {}),
                    "covers": f"process {d.get('pid')} and everything it starts — sudo_run (and "
                              "`sudo` in your shell) now run without a dialog, except anything "
                              "that would switch the guard off"}
        return {"ok": False, "status": d.get("decision") or "failed", "how": d.get("how"),
                **({"hint": "The person said no — work without root, or ask in the chat."}
                   if d.get("decision") == "denied" else {}),
                **({"stderr": err[-1500:]} if d.get("decision") not in ("denied", "timeout") else {})}

    req = _Req("grant", f"grant {dur}")
    _spawn(req, argv, os.path.expanduser("~"), None, parse)
    return _await(req, wait)


def grant_info() -> dict | None:
    try:
        with open(GRANT_INFO) as f:
            g = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(g, dict) or g.get("expires", 0) <= time.time():
        return None
    return g


def sudo_status(args: dict, ctx: dict) -> dict:
    w = _who(ctx)
    g = grant_info()
    grant = None
    if g:
        mine = any(a["pid"] == g.get("pid") and a["start"] == g.get("start")
                   for a in agentid.ancestors(os.getpid()))
        grant = {"holder": g.get("who") or g.get("agent"), "minutes_left": int(g["expires"] - time.time()) // 60,
                 "covers_you": mine}
    with _lock:
        pending = [{"request_id": r.id, "kind": r.kind, "what": r.what[:200],
                    "seconds": int(time.time() - r.started),
                    "state": "finished — collect with sudo_result" if r.done.is_set() else
                             ("approved, running" if (r.decision or {}).get("decision") == "approved"
                              else "waiting for the person")}
                   for r in _reqs.values()]
    return {"ok": True, "you": {"as_the_guard_sees_you": agentid.one_line(w),
                                "verified": w.get("verified"), "pid": w.get("pid"),
                                "calls_itself": claimed_name(ctx)},
            "root_grant": grant, "requests": pending,
            "how_root_works": "sudo_run shows the person your exact command (and who you are) with "
                              "Approve/Deny; sudo_grant asks once for a time window."}


def sudo_revoke(args: dict, ctx: dict) -> dict:
    try:
        r = subprocess.run([elevate_bin(), "--agent", claimed_name(ctx), "--report", "--revoke"],
                           capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"ok": False, "status": "failed", "error": str(e)}
    _audit(ctx, {"tool": "sudo_revoke", "result": "done" if r.returncode == 0 else "failed"})
    return {"ok": r.returncode == 0, "status": "revoked" if r.returncode == 0 else "failed",
            "message": (r.stdout or r.stderr).strip()[-500:]}


def sudo_result(args: dict, ctx: dict) -> dict:
    rid = _text(args, "request_id", 40, required=True)
    wait = _num(args, "wait_seconds", DEFAULT_WAIT, 0, MAX_WAIT)
    with _lock:
        req = _reqs.get(rid)
    if req is None:
        return {"ok": False, "status": "unknown_request",
                "error": f"no request {rid} (already collected, or the MCP server restarted)"}
    return _await(req, wait)


def ask_permission(args: dict, ctx: dict) -> dict:
    from . import approve
    question = _text(args, "question", 500, required=True)
    details = _text(args, "details", 1200)
    wait = _num(args, "wait_seconds", DEFAULT_WAIT, 0, MAX_WAIT)
    w = _who(ctx)
    req = _Req("question", question)

    def run():
        ok, how = approve.ask_question(w.get("name") or claimed_name(ctx), question, details, w)
        record({"control": "agent-approval", "source": "mcp", "agent": w.get("name"),
                "who": agentid.one_line(w), "class": "question", "what": question[:2000],
                "details": details[:2000], "result": "approved" if ok else "denied", "how": how})
        req.finish({"ok": ok, "status": "approved" if ok else "denied", "how": how,
                    **({} if ok else {"hint": "Take a Deny as the answer; don't ask again for the same thing."})})

    _register(req)
    threading.Thread(target=run, daemon=True, name=f"vg-{req.id}").start()
    return _await(req, wait)
