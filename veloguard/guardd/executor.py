"""The kernel plane interface — the only code allowed to touch nftables.

For this first vertical slice we drive the in-kernel nftables/netfilter engine
(already part of the kernel we cloned) via the `nft` userspace tool. Later this
becomes a direct netlink talker, and eventually our own VeloGuard LSM. The
interface here stays the same; the backend gets closer to the metal.

Default mode is DRY-RUN: it prints exactly what it *would* run. Touching the
real firewall requires apply=True and (usually) root. Safe by default.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
from pathlib import Path

from .actions import _validate_process_target, validate_vpn_target

TABLE = "inet veloguard"
SET = "blocklist"          # ipv4_addr
SET6 = "blocklist6"        # ipv6_addr — an inet table still needs one set per family
QUARANTINE_DIR = "/run/veloguard/quarantine"  # /run is tmpfs == RAM
WG_DIR = "/etc/wireguard"                      # where wg-quick reads <profile>.conf
# Provider apps (signed in once by the user) serve a VPN target when no
# WireGuard profile of that name exists; bin/veloguard-vpn drives them as the
# desktop user and verifies the connection. Fixed path next to this package —
# deliberately not overridable from the environment of a root process.
APP_PROVIDERS = frozenset({"proton", "nord", "surfshark"})
DEFAULT_APP_FILE = "/etc/veloguard/vpn-default-app"
VPN_HELPER = str(Path(__file__).resolve().parents[1] / "bin" / "veloguard-vpn")


class NftExecutor:
    def __init__(self, apply: bool = False, *, seal: str | None = None,
                 action=None):
        self.apply = apply
        self._planned: list[list[str]] = []
        # AI/agent/MCP actions arrive SEALED (dispatch sets seal+action). The
        # local-root CLI calls construct us plainly (seal is None) and run as
        # before — that path is the operator, not the AI.
        self._seal = seal
        self._action = action

    def _check_seal(self) -> None:
        """On a sealed channel, refuse any real kernel op whose action doesn't
        carry the guard's per-boot HMAC — i.e. that didn't pass the policy gate.
        Defeats a prompt-injected/compromised AI forging a kernel command."""
        if self._seal is None:
            return
        from . import authchan
        if not authchan.verify(self._action, self._seal):
            raise RuntimeError("guard seal invalid — refusing kernel op "
                               "(only policy-approved actions may touch the kernel)")

    def _run(self, args: list[str]) -> str:
        cmd = ["nft", *args]
        if not self.apply:
            self._planned.append(cmd)
            return f"[dry-run] {' '.join(cmd)}"
        self._check_seal()
        if shutil.which("nft") is None:
            raise RuntimeError("nft not found — install nftables")
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"nft failed: {proc.stderr.strip()}")
        return proc.stdout.strip() or f"ok: {' '.join(cmd)}"

    def setup(self) -> list[str]:
        """Create the veloguard table, both blocklist sets and their drop rules.

        Idempotent: the table is flushed and rebuilt from one transaction, so
        re-running setup never stacks duplicate drop rules (`nft add rule`
        appends every time)."""
        script = (
            f"table {TABLE} {{}}\n"
            f"flush table {TABLE}\n"
            f"table {TABLE} {{\n"
            f"  set {SET} {{ type ipv4_addr; flags interval; }}\n"
            f"  set {SET6} {{ type ipv6_addr; flags interval; }}\n"
            f"  chain input {{\n"
            f"    type filter hook input priority -100; policy accept;\n"
            f"    ip saddr @{SET} drop\n"
            f"    ip6 saddr @{SET6} drop\n"
            f"  }}\n"
            f"}}\n"
        )
        return [self._run_script(script)]

    def _run_script(self, script: str) -> str:
        """Apply an nft ruleset atomically (nft -f -), same dry-run rules."""
        if not self.apply:
            self._planned.append(["nft", "-f", "-"])
            return "[dry-run] nft -f - <<EOF\n" + script + "EOF"
        self._check_seal()
        if shutil.which("nft") is None:
            raise RuntimeError("nft not found — install nftables")
        proc = subprocess.run(["nft", "-f", "-"], input=script,
                              capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"nft failed: {proc.stderr.strip()}")
        return "ok: veloguard table ready (IPv4 + IPv6 blocklists)"

    @staticmethod
    def _set_for(ip: str) -> tuple[str, str]:
        addr = ipaddress.ip_address(ip)          # re-validate at the point of use
        return (SET6 if addr.version == 6 else SET), str(addr)

    def block_ip(self, ip: str) -> str:
        s, ip = self._set_for(ip)
        return self._run(["add", "element", *TABLE.split(), s, "{", ip, "}"])

    def unblock_ip(self, ip: str) -> str:
        s, ip = self._set_for(ip)
        return self._run(["delete", "element", *TABLE.split(), s, "{", ip, "}"])

    def list_blocked(self) -> str:
        return "\n".join([self._run(["list", "set", *TABLE.split(), SET]),
                          self._run(["list", "set", *TABLE.split(), SET6])])

    # --- generic command runner (non-nft): same dry-run discipline ----------
    def _sh(self, argv: list[str]) -> str:
        if not self.apply:
            self._planned.append(argv)
            return f"[dry-run] {' '.join(argv)}"
        self._check_seal()
        if shutil.which(argv[0]) is None:
            raise RuntimeError(f"{argv[0]} not found")
        proc = subprocess.run(argv, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"{argv[0]} failed: {proc.stderr.strip()}")
        return proc.stdout.strip() or f"ok: {' '.join(argv)}"

    # --- VPN: WireGuard profiles, or Tor as the fallback transport ----------
    def vpn_up(self, target: str | None) -> str:
        # Validated here too: the netwatch/CLI paths reach us without an Action,
        # and wg-quick runs the profile's PostUp hooks as root — a crafted
        # "../../tmp/x" target would load an attacker-written config.
        target = validate_vpn_target(target) or "veloguard"
        if target == "tor":
            return self._sh(["systemctl", "start", "tor"])
        if self._app_for(target) is not None:
            # The provider's own app (signed in by the user) connects; the
            # helper refuses with a clear reason when it can't (not signed in,
            # no desktop session, app open in the foreground…). Same rule as a
            # WireGuard tunnel: one that carries no traffic is rolled back.
            out = self._sh([VPN_HELPER, "connect", target])
            if self.apply and not self._tunnel_has_connectivity():
                self._sh([VPN_HELPER, "disconnect"])
                raise RuntimeError(
                    f"the {target} app reported a connection but nothing gets "
                    f"through — disconnected it again")
            return out
        # A WireGuard profile with AllowedIPs=0.0.0.0/0 *replaces the default
        # route*. If the profile is missing or its endpoint is dead, every
        # interface (Wi-Fi AND wired) silently black-holes — the connection
        # looks up but no traffic flows. So never raise a tunnel we can't
        # verify, and roll back one that comes up with no connectivity: better
        # no VPN than no network. (Real-run only; dry-run just previews.)
        cfg = f"{WG_DIR}/{target}.conf"
        if self.apply and self._tunnel_is_up(target):
            # Idempotent: the NM dispatcher fires on every Wi-Fi "up"; a second
            # `wg-quick up` on a live tunnel errors out ("already exists").
            return f"ok: tunnel '{target}' already up"
        if self.apply and not self._config_has_endpoint(cfg):
            raise RuntimeError(
                f"{cfg} is missing or has no Endpoint — bringing this tunnel up "
                f"would black-hole all routing. Import one first: "
                f"veloguard-vpn import <wg.conf>")
        out = self._sh(["wg-quick", "up", target])
        if self.apply and not self._tunnel_has_connectivity():
            # Internal rollback of our own failed action — not a user-initiated
            # vpn_down, so it needs no consent (leaving the black hole would).
            self._sh(["wg-quick", "down", target])
            raise RuntimeError(
                f"tunnel '{target}' came up but has no connectivity "
                f"(dead/unreachable endpoint) — rolled back to direct routing")
        return out

    def vpn_down(self, target: str | None) -> str:
        target = validate_vpn_target(target) or "veloguard"
        if target == "tor":
            return self._sh(["systemctl", "stop", "tor"])
        if self._app_for(target) is not None:
            return self._sh([VPN_HELPER, "disconnect"])
        return self._sh(["wg-quick", "down", target])

    @staticmethod
    def _app_for(target: str) -> str | None:
        """The provider app serving `target` — only when NO WireGuard profile
        of that name exists (a profile always wins, exactly as before)."""
        if os.path.exists(f"{WG_DIR}/{target}.conf"):
            return None
        if target in APP_PROVIDERS:
            return target
        if target == "veloguard":
            try:
                with open(DEFAULT_APP_FILE) as fh:
                    app = fh.read().strip()
            except OSError:
                return None
            return app if app in APP_PROVIDERS else None
        return None

    # --- VPN safety: a tunnel that can't carry traffic is worse than none ----
    @staticmethod
    def _tunnel_is_up(name: str) -> bool:
        if shutil.which("wg") is None:
            return False
        r = subprocess.run(["wg", "show", "interfaces"], capture_output=True, text=True)
        return r.returncode == 0 and name in r.stdout.split()

    def _config_has_endpoint(self, path: str) -> bool:
        """A usable WireGuard profile must exist and name a non-empty Endpoint."""
        try:
            with open(path) as fh:
                for line in fh:
                    s = line.strip()
                    if (s.lower().startswith("endpoint") and "=" in s
                            and s.split("=", 1)[1].strip()):
                        return True
        except OSError:
            return False
        return False

    def _tunnel_has_connectivity(self, settle: float = 1.5,
                                 timeout: float = 2.0, rounds: int = 2) -> bool:
        """Can we actually reach the internet through the freshly-raised tunnel?
        Raw TCP to anycast resolvers on :443 — deliberately NO DNS, because a
        dead tunnel usually breaks resolution too and we'd just hang on it."""
        import socket
        import time
        time.sleep(settle)  # WireGuard's first handshake is async — let it settle.
        for attempt in range(rounds):
            for host in ("1.1.1.1", "9.9.9.9"):
                try:
                    socket.create_connection((host, 443), timeout=timeout).close()
                    return True
                except OSError:
                    continue
            if attempt + 1 < rounds:
                time.sleep(1.0)
        return False

    # --- Quarantine: freeze an unknown process, stash its exe in RAM (tmpfs) -
    # The target is a validated pid or EXACT process name: `pkill -x` matches
    # the whole name (a bare `pkill .` would freeze every process on the box),
    # `--` ends option parsing, and the stash path can't traverse out of
    # QUARANTINE_DIR (`rm -rf …/quarantine/../../etc` was reachable before).
    @staticmethod
    def _signal_argv(sig: str, target: str) -> list[str]:
        if target.isdigit():
            return ["kill", f"-{sig}", "--", target]
        return ["pkill", f"-{sig}", "-x", "--", target]

    def quarantine(self, target: str) -> str:
        target = _validate_process_target(target)
        out = [self._sh(self._signal_argv("STOP", target))]
        # /run is tmpfs (RAM) on systemd systems — the "RAM partition".
        qdir = f"{QUARANTINE_DIR}/{target}"
        out.append(self._sh(["mkdir", "-p", "-m", "700", qdir]))
        if target.isdigit():
            # /proc/<pid>/exe is a magic link — follow it (-L) to stash the
            # actual executable, not a dangling symlink.
            out.append(self._sh(["cp", "-L", "--", f"/proc/{target}/exe",
                                 f"{qdir}/exe"]))
        return "\n".join(out)

    def release_quarantine(self, target: str) -> str:
        target = _validate_process_target(target)
        return "\n".join([self._sh(self._signal_argv("CONT", target)),
                          self._sh(["rm", "-rf", "--", f"{QUARANTINE_DIR}/{target}"])])

    def kill_quarantine(self, target: str) -> str:
        target = _validate_process_target(target)
        # SIGKILL the frozen process, then wipe its RAM stash.
        return "\n".join([self._sh(self._signal_argv("KILL", target)),
                          self._sh(["rm", "-rf", "--", f"{QUARANTINE_DIR}/{target}"])])

    # --- Virtualization layer: run an uncertain app isolated (RAM, no net) ---
    def sandbox_run(self, target: str, tier: str = "light",
                    allow_net: bool = False) -> str:
        import shlex
        from . import vlayer
        chosen, degraded = vlayer.resolve_tier(tier)
        if chosen == "none":
            # Fail CLOSED: "run it sandboxed" must never degrade to "run it
            # with the guard's own (root) privileges" because bwrap is missing.
            raise RuntimeError("no isolation layer installed (bubblewrap/gVisor/"
                               "Firecracker) — refusing to run unsandboxed")
        argv = vlayer.build_argv(shlex.split(target), chosen, allow_net=allow_net)
        out = self._sh(argv)
        note = f"  (tier: {chosen}{' — degraded from ' + tier if degraded else ''}"
        note += ", network OFF)" if not allow_net else ", network ON)"
        return out + "\n" + note
