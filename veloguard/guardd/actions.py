"""Structured actions — the contract between the AI plane and the kernel plane.

The AI never speaks to the kernel directly. It can only emit one of these
typed, validated actions. Adding a capability to VeloGuard means adding an
Action here, teaching the adapter to produce it, the policy engine to judge
it, and the executor to carry it out. Nothing else can reach the kernel.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shlex
from dataclasses import dataclass, field
from enum import Enum

# Targets reach root-run argv and filesystem paths (pkill, rm -rf under
# /run/veloguard/quarantine, wg-quick's /etc/wireguard/<name>.conf), and they
# are AI-proposed — i.e. attacker-influenced via prompt injection. Shape them
# here, once, for every brain and every entry point (CLI, agent, MCP).
#   process name: what the kernel keeps in /proc/<pid>/comm (≤15 bytes); no
#     leading '-' (option injection) or '.' (path traversal), no '/'.
#   VPN profile: wg-quick's own interface-name rule, minus leading '.'/'-'.
_PROC_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.+-]{0,14}$")
_VPN_NAME_RE = re.compile(r"^[A-Za-z0-9_=+][A-Za-z0-9_=+.-]{0,14}$")
_PID_MAX = 4194304                     # kernel PID_MAX_LIMIT on 64-bit
SANDBOX_TIERS = ("light", "strong", "vm")


def _validate_process_target(target) -> str:
    """A quarantine target is a real PID or an exact process name — never a
    pattern, a path, or something that freezes the whole machine."""
    if not isinstance(target, str):
        target = str(target)
    target = target.strip()
    if target.isdigit():
        pid = int(target)
        if pid <= 1 or pid > _PID_MAX:
            raise ValueError(f"refusing pid {pid}: not a userspace process")
        if pid in (os.getpid(), os.getppid()):
            raise ValueError("refusing to quarantine the guard itself")
        return str(pid)
    if not _PROC_NAME_RE.fullmatch(target):
        raise ValueError(f"invalid process target {target!r}: use a pid or an "
                         "exact process name (letters, digits, _.+-; ≤15 chars)")
    return target


def validate_vpn_target(target) -> str | None:
    """None (default profile), 'tor', or a wg-quick interface name."""
    if target in (None, ""):
        return None
    if not isinstance(target, str) or not _VPN_NAME_RE.fullmatch(target):
        raise ValueError(f"invalid VPN profile {target!r}: a WireGuard profile "
                         "name (letters, digits, _=+.-; ≤15 chars) or 'tor'")
    return target


class ActionType(str, Enum):
    BLOCK_IP = "block_ip"
    UNBLOCK_IP = "unblock_ip"
    LIST_BLOCKED = "list_blocked"
    # VPN — bring the encrypted tunnel up/down (WireGuard profile, or "tor").
    VPN_UP = "vpn_up"
    VPN_DOWN = "vpn_down"
    # Quarantine — isolate an unknown process in a RAM (tmpfs) sandbox, then
    # either release it (user trusts it) or kill+wipe it (user rejects it).
    QUARANTINE = "quarantine"
    RELEASE_QUARANTINE = "release_quarantine"
    KILL_QUARANTINE = "kill_quarantine"
    # Run an uncertain app in an isolated 'digital layer' (RAM, no net).
    SANDBOX_RUN = "sandbox_run"
    NOOP = "noop"  # adapter could not map the intent to anything


@dataclass
class Action:
    type: ActionType
    # Free-form parameters; validated per-type in `validate()`.
    params: dict = field(default_factory=dict)
    # Why the AI thinks this is the right action — surfaced to the user/audit.
    rationale: str = ""

    def validate(self) -> None:
        """Raise ValueError if params are malformed for this action type.

        This is *shape* validation only (is the IP a real IP?). Whether the
        action is *allowed* is the policy engine's job, not ours.
        """
        if not isinstance(self.params, dict):
            raise ValueError("action params must be an object")
        if self.type in (ActionType.BLOCK_IP, ActionType.UNBLOCK_IP):
            ip = self.params.get("ip")
            if not ip:
                raise ValueError(f"{self.type.value} requires an 'ip' param")
            # Raises ValueError on garbage; normalises e.g. trailing zeros.
            self.params["ip"] = str(ipaddress.ip_address(str(ip)))
        if self.type in (ActionType.QUARANTINE, ActionType.RELEASE_QUARANTINE,
                         ActionType.KILL_QUARANTINE):
            if not self.params.get("target"):
                raise ValueError(f"{self.type.value} requires a 'target' "
                                 "(pid or process name)")
            self.params["target"] = _validate_process_target(self.params["target"])
        if self.type in (ActionType.VPN_UP, ActionType.VPN_DOWN):
            tgt = validate_vpn_target(self.params.get("target"))
            if tgt is None:
                self.params.pop("target", None)
            else:
                self.params["target"] = tgt
        if self.type == ActionType.SANDBOX_RUN:
            target = self.params.get("target")
            if not target or not isinstance(target, str):
                raise ValueError("sandbox_run requires a 'target' (command to run)")
            try:
                if not shlex.split(target):
                    raise ValueError("sandbox_run target is empty")
            except ValueError as e:
                raise ValueError(f"sandbox_run target is not a valid command: {e}") from None
            tier = self.params.get("tier", "light")
            if tier not in SANDBOX_TIERS:
                raise ValueError(f"sandbox tier must be one of {', '.join(SANDBOX_TIERS)}")
            self.params["tier"] = tier
            net = self.params.get("net", False)
            if not isinstance(net, bool):
                raise ValueError("sandbox 'net' must be true or false")
            self.params["net"] = net

    def describe(self) -> str:
        if self.type == ActionType.BLOCK_IP:
            return f"block traffic from {self.params.get('ip')}"
        if self.type == ActionType.UNBLOCK_IP:
            return f"unblock {self.params.get('ip')}"
        if self.type == ActionType.LIST_BLOCKED:
            return "list blocked addresses"
        if self.type == ActionType.VPN_UP:
            return f"bring up the VPN ({self.params.get('target') or 'default'})"
        if self.type == ActionType.VPN_DOWN:
            return f"take down the VPN ({self.params.get('target') or 'default'})"
        if self.type == ActionType.QUARANTINE:
            return f"quarantine {self.params.get('target')} in a RAM sandbox"
        if self.type == ActionType.RELEASE_QUARANTINE:
            return f"release {self.params.get('target')} from quarantine"
        if self.type == ActionType.KILL_QUARANTINE:
            return f"kill and wipe quarantined {self.params.get('target')}"
        if self.type == ActionType.SANDBOX_RUN:
            return f"run '{self.params.get('target')}' in an isolated layer"
        return "do nothing"
