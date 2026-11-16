"""Command guard — what an AI agent may not do to the machine's own defenses.

One rule set, asked from two places, so every agent hits the same wall:
  * the Claude Code plugin (desktop/agents/claude-plugin) before every Bash,
    Edit and Write call — `guardd check-command`;
  * veloguard-elevate-root before showing a root command for approval.

Verdicts:
  deny  — switches off, blinds or rewrites the guard itself (its services,
          firewall table, files, audit trail, the agent's own VeloGuard
          plugin). An agent never does this; the person can, in a terminal.
  warn  — legitimate sometimes, classic for malware or a prompt-injected agent
          (remote script piped into a shell, persistence, wiping disks,
          switching off other protection, READING SECRETS — keys, tokens,
          browser cookies: the first thing an injected agent exfiltrates).
          Shown to the person to decide.
  allow — everything else.

This is a guardrail for an agent that was steered wrong, not a sandbox: it
reads the command as text, and a determined human can always phrase around a
pattern. The hard boundaries stay where they are — root needs the person's
Approve, the guard runs as root, the brain runs sandboxed.
"""

from __future__ import annotations

import os
import re
import shlex

GUARD_PATHS = (
    "/opt/veloguard", "/var/lib/veloguard", "/var/log/veloguard", "/etc/veloguard",
    "/usr/share/veloguard", "/usr/local/bin/veloguard", "/usr/local/lib/veloguard",
    "/etc/polkit-1/rules.d/49-veloguard", "/etc/networkmanager/dispatcher.d/90-veloguard",
    "/etc/tmpfiles.d/veloguard", "/etc/systemd/system/veloguard",
    "/etc/claude-code/managed-settings",
)
USER_GUARD_PATHS = ("~/.config/veloguard",)
AUDIT_PATHS = ("/var/log/veloguard", "audit.log")

# Commands that change what they're given anywhere on their line, and ones
# that only change their LAST argument (the destination: cp src DEST).
_CHANGES_ARGS = re.compile(r"^(rm|mv|truncate|shred|unlink|chmod|chown|chgrp|chattr|setfacl|tee|sed\s+(-\S*\s+)*-i|perl\s+-\S*i)\b")
_CHANGES_DEST = re.compile(r"^(cp|install|ln|rsync|scp|dd)\b")
_PREFIX = re.compile(r"^((sudo|doas|pkexec|veloguard-elevate|env|nice|ionice|nohup|time|command|exec|xargs)(\s+-\S+)*\s+|\w+=\S*\s+)+")


def _norm(cmd: str) -> str:
    """Lower-cased, quotes/escapes dropped, whitespace collapsed — enough to
    see `sys''temctl` or `"/opt/veloguard"` as what they are."""
    t = cmd.replace("\\\n", " ")
    t = re.sub(r"""["'`\\]""", "", t)
    return re.sub(r"\s+", " ", t).strip().lower()


def _expand_home(paths: tuple[str, ...]) -> tuple[str, ...]:
    home = os.path.expanduser("~").lower()
    out = []
    for p in paths:
        out.append(p)
        if p.startswith("~/"):
            out += [home + p[1:], "$home" + p[1:]]
    return tuple(out)


_RULES: list[tuple[str, str, str]] = [
    # --- deny: the guard itself ------------------------------------------
    ("deny", r"\bsystemctl\b.*\b(stop|disable|mask|kill|reset-failed|edit|revert)\b.*\b(veloguard\S*|guardd|nftables|networkmanager-dispatcher)",
     "stops or disables a VeloGuard service or the firewall"),
    ("deny", r"\bnft\b.*\b(flush\s+ruleset|(delete|flush|destroy)\s+table\s+(inet\s+)?veloguard)",
     "flushes the firewall or deletes the guard's nftables table"),
    ("deny", r"\b(pkill|killall|kill)\b.*\b(veloguard|guardd|nordvpnd)\b",
     "kills the guard (or the VPN daemon)"),
    ("deny", r"\b(journalctl\b.*--vacuum|auditctl\s+-[de])",
     "erases or stops the system's audit trail"),
    ("deny", r"\bclaude\b.*\bplugins?\b.*\b(disable|uninstall|remove|rm)\b.*\bveloguard",
     "switches off the agent's own VeloGuard plugin"),
    ("deny", r"\bveloguard-agent\b.*\bset\b.*\bmock\b|\bguardd?\b.*\buse\b.*\bmock\b",
     "turns the guard's brain off"),
    # --- warn: what malware and steered agents do ---------------------------
    ("warn", r"\b(curl|wget|fetch)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b",
     "runs a script straight from the internet"),
    ("warn", r"\bbase64\s+(-d|--decode)\b.*\|\s*(sudo\s+)?(ba|z)?sh\b",
     "runs a hidden (base64-decoded) script"),
    ("warn", r"(\.ssh/authorized_keys|/etc/sudoers|/etc/cron|crontab\s+-|\.config/autostart|\.config/systemd/user|/etc/systemd/system/|\.bashrc|\.zshrc|\.profile|/etc/profile|ld\.so\.preload)",
     "changes how the system starts or who can log in (a persistence spot)"),
    ("warn", r"\b(ufw\s+disable|iptables\s+-f|iptables\s+--flush|setenforce\s+0|systemctl\b.*\b(stop|disable)\b.*\b(firewalld|ufw|apparmor|fail2ban|sshguard))",
     "switches off other system protection"),
    ("warn", r"\b(mkfs(\.\w+)?|wipefs|dd\b.*\bof=/dev/(sd|nvme|vd|mmcblk))|\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(/|/\*|~|/home|/etc|/usr)(\s|$)",
     "erases a disk or a whole system folder"),
    ("warn", r"\bchmod\b.*\b(777|u\+s|\+s)\b.*(/usr|/bin|/etc|/)",
     "loosens permissions on system files (or sets setuid)"),
    ("warn", r"\b(nc|ncat|socat)\b.*\s-(e|c)\b|/dev/tcp/",
     "opens a remote shell"),
]
# Zero trust for data: where credentials live. Reading them is put to the
# person (an agent rarely needs to; an injected one always wants to).
SECRET_PATHS = (
    r"\.ssh/(id_|.*_key\b|.*\.pem)", r"\.ssh/?(\s|$|\*)", r"\.gnupg(/|\s|$)", r"\.local/share/keyrings/", r"\.password-store/",
    r"/etc/(shadow|gshadow|sudoers)", r"\.netrc\b", r"\.git-credentials", r"\.docker/config\.json",
    r"\.aws/credentials", r"\.config/gcloud/", r"\.kube/config",
    r"\.claude/\.credentials\.json", r"\.codex/auth\.json", r"\.kimi-code/(credentials|auth|oauth)",
    r"\.hermes/\.env", r"\.openclaw/(credentials|auth|secrets)", r"\.config/veloguard/credentials\.json",
    r"/var/lib/veloguard/.*(key|secret|credential)", r"/etc/wireguard/", r"/var/lib/private/",
    r"(cookies|login data|local state|web data)(\.sqlite)?\b", r"\.mozilla/firefox/.*\.(sqlite|json)",
    r"\.var/app/[^/]+/(config|data)/.*(cookies|login data|keyring)",
)
_SECRET_RX = re.compile("|".join(f"(?:{p})" for p in SECRET_PATHS))
_READS = re.compile(r"\b(cat|less|more|head|tail|cp|scp|rsync|tar|zip|base64|xxd|od|strings|grep|rg|sed|awk|curl|wget|nc|python3?|node|perl|sqlite3|gpg|openssl|bat|vim?|nano|code)\b")

_COMPILED = [(v, re.compile(p), why) for v, p, why in _RULES]


def reads_secret(text: str) -> bool:
    return bool(_SECRET_RX.search(text.lower()))


def _touches(path_list: tuple[str, ...], t: str) -> str | None:
    for p in _expand_home(path_list):
        if p.lower() in t:
            return p
    return None


def check(command: str) -> tuple[str, str]:
    """Classify one shell command line → (verdict, reason)."""
    v, why, _ = check_detail(command)
    return v, why


def check_detail(command: str) -> tuple[str, str, str]:
    """(verdict, reason, class). class: "disable" (switches the guard off —
    never allowed for an agent), "tamper" (changes the guard's files — only
    under a maintenance grant the person approved), "malware" (warn), ""."""
    t = _norm(command)
    if not t:
        return "allow", "", ""
    for verdict, rx, why in _COMPILED:
        if verdict == "deny" and rx.search(t):
            return "deny", why, "disable"
    hit = _writes_guard(t)
    if hit:
        return "deny", f"changes the guard's own files ({hit})", "tamper"
    for verdict, rx, why in _COMPILED:
        if verdict == "warn" and rx.search(t):
            return "warn", why, "malware"
    if reads_secret(t) and _READS.search(t):
        return "warn", "reads credentials (keys, tokens, cookies or passwords)", "secret"
    return "allow", "", ""


def check_read(path: str) -> tuple[str, str]:
    """An agent's file-reading tool (Claude Code's Read / Grep / Glob)."""
    p = os.path.abspath(os.path.expanduser(path or "")).lower()
    if reads_secret(p):
        return "warn", "reads credentials (keys, tokens, cookies or passwords)"
    return "allow", ""


def _writes_guard(t: str) -> str | None:
    """The guard path a command line writes to, if any: per simple command
    (split on ; | && ||), what its command word changes, plus redirections."""
    guard = _expand_home(GUARD_PATHS + USER_GUARD_PATHS)
    def is_guard(tok: str) -> str | None:
        tok = tok.split("=", 1)[1] if tok.startswith("of=") else tok
        return next((g for g in guard if tok.startswith(g.lower())), None)
    for m in re.finditer(r">>?\s*(\S+)", t):                    # > /var/log/veloguard/…
        g = is_guard(m.group(1))
        if g:
            return g
    for seg in re.split(r"\|\||&&|[;|&]", t):
        seg = _PREFIX.sub("", seg.strip())
        toks = seg.split()
        if not toks:
            continue
        if _CHANGES_ARGS.match(seg):
            g = next((is_guard(x) for x in toks[1:] if is_guard(x)), None)
            if g:
                return g
        elif _CHANGES_DEST.match(seg):
            dests = [x for x in toks[1:] if not x.startswith("-")]
            if toks[0] == "dd":
                dests = [x for x in toks[1:] if x.startswith("of=")]
            if dests and is_guard(dests[-1]):
                return is_guard(dests[-1])
    return None


def check_argv(argv: list[str]) -> tuple[str, str]:
    return check(shlex.join(argv))


_SETTINGS = re.compile(r"/\.claude/settings(\.local)?\.json$|/\.claude\.json$")


def check_write(path: str, text: str = "") -> tuple[str, str]:
    """An editor tool writing `text` into `path` (Claude Code's Edit/Write)."""
    p = os.path.abspath(os.path.expanduser(path)).lower()
    for g in _expand_home(GUARD_PATHS + USER_GUARD_PATHS):
        g = os.path.expanduser(g).lower()
        if g.startswith("$home"):
            continue
        if p.startswith(g):
            return "deny", f"is one of the guard's own files ({path})"
    home = os.path.expanduser("~").lower()
    if p.startswith(f"{home}/.claude/plugins/"):
        return "deny", "is the agent's plugin store (where the VeloGuard plugin is kept)"
    if _SETTINGS.search(p) and "veloguard" in text.lower():
        return "deny", "would change the agent's VeloGuard plugin settings"
    t = _norm(p)
    for verdict, rx, why in _COMPILED:
        if verdict == "warn" and rx.search(t):
            return "warn", why
    return "allow", ""
