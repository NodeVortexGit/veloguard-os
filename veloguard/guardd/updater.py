"""Built-in updater — merge kernel updates and signed VeloGuard releases, safely.

Two streams:
  veloguard — our userspace (guard, scripts, kernel fragments). SIGNED releases.
  kernel    — upstream Linux: fetch a new tag, re-merge our fragments, rebuild.

NON-NEGOTIABLE: every 'veloguard' update is verified against a PINNED public key
before anything touches disk. Unsigned or tampered → refused. The updater fails
CLOSED (missing key / missing openssl / bad signature all mean "do not apply").
An updater that skips this is a malware-delivery service, not a guard.

Agent-friendly: `check()` is read-only and JSON-able, so an external "keep it
updated" agent can poll, decide, and call apply (which re-verifies + audits).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path

VELOGUARD_DIR = Path(__file__).resolve().parent.parent
KERNEL_TREE = VELOGUARD_DIR.parent
VERSION_FILE = VELOGUARD_DIR / "VERSION"
PUBKEY = VELOGUARD_DIR / "keys" / "veloguard-release.pem"
DEFAULT_MANIFEST = "https://raw.githubusercontent.com/NodeVortexGit/veloguard-os/main/manifest.json"

# Prebuilt-kernel offline updates (Fedora-style: download in the background,
# apply on reboot). The staged package lives here; systemd enters
# system-update.target on the next boot iff SYSTEM_UPDATE_FLAG exists.
KERNEL_STAGE = Path("/var/lib/veloguard/staged-kernel")
SYSTEM_UPDATE_FLAG = Path("/system-update")


class UpdateError(Exception):
    pass


# --- versions --------------------------------------------------------------

def local_veloguard_version() -> str:
    try:
        return VERSION_FILE.read_text().strip()
    except OSError:
        return "0.0.0"


KERNEL_PKG = "linux-veloguard"
KERNEL_SUFFIX = "-veloguard"          # CONFIG_LOCALVERSION in the fragments
_PKG_FILE_RE = re.compile(r"^[A-Za-z0-9@._+-]+\.pkg\.tar\.zst$")


def _norm_kver(v: str) -> str:
    """'7.2.0' → '7.2' (mainline tag v7.2 is pkgver 7.2); '7.2.11' stays."""
    parts = v.split(".")
    if len(parts) == 3 and parts[2] == "0":
        parts = parts[:2]
    return ".".join(parts)


def local_kernel_version() -> str:
    """Version of the VeloGuardOS kernel on THIS machine, comparable to the
    manifest's kernel.version (the pkgver, e.g. '7.2.11'):
      1. the installed linux-veloguard package (what the next boot runs),
      2. else the running kernel if it is ours (uname -r = 7.2.11-veloguard),
      3. else a kernel source tree we live in (developer layout),
      4. else 'none' — stock Arch kernel only, nothing of ours installed.
    (This used to read <install dir>/../Makefile, which never exists on an
    installed system — so every timer run re-downloaded the same kernel.)"""
    if shutil.which("pacman"):
        r = subprocess.run(["pacman", "-Q", KERNEL_PKG], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.split():
            return r.stdout.split()[-1].rsplit("-", 1)[0]       # strip pkgrel
    rel = os.uname().release
    if rel.endswith(KERNEL_SUFFIX):
        return _norm_kver(rel[: -len(KERNEL_SUFFIX)])
    try:
        mk = (KERNEL_TREE / "Makefile").read_text()[:600]
        v = [re.search(rf"^{k} = (\d+)", mk, re.M) for k in
             ("VERSION", "PATCHLEVEL", "SUBLEVEL")]
        if all(v):
            return _norm_kver(".".join(m.group(1) for m in v))
    except OSError:
        pass
    return "none"


def _vercmp(a: str, b: str) -> int:
    """<0 if a<b, 0 if equal, >0 if a>b. pacman's vercmp when present."""
    if shutil.which("vercmp"):
        r = subprocess.run(["vercmp", a, b], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip().lstrip("-").isdigit():
            return int(r.stdout.strip())
    def key(v: str) -> list[int]:
        return [int(x) if x.isdigit() else 0 for x in re.split(r"[.+-]", v)]
    ka, kb = key(a), key(b)
    return (ka > kb) - (ka < kb)


# --- fetch + verify (the trust boundary) -----------------------------------

def _fetch(src: str) -> bytes:
    if src.startswith(("http://", "https://")):
        with urllib.request.urlopen(src, timeout=30) as r:
            return r.read()
    return Path(src).read_bytes()


def verify(data: bytes, sig: bytes) -> bool:
    """True only if `sig` is a valid signature of `data` under the pinned key.
    Any uncertainty (no key, no openssl, bad sig) returns False — fail closed."""
    if not PUBKEY.exists() or shutil.which("openssl") is None:
        return False
    with tempfile.TemporaryDirectory() as d:
        dp, sp = Path(d) / "data", Path(d) / "sig"
        dp.write_bytes(data)
        sp.write_bytes(sig)
        rc = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(PUBKEY),
             "-signature", str(sp), str(dp)],
            capture_output=True).returncode
        return rc == 0


def load_manifest(source: str | None = None) -> dict:
    """Fetch the manifest and its detached signature; refuse if unverified."""
    source = source or os.environ.get("VELOGUARD_UPDATE_URL", DEFAULT_MANIFEST)
    data = _fetch(source)
    try:
        sig = _fetch(source + ".sig")
    except Exception as e:
        raise UpdateError(f"no signature alongside manifest: {e}") from e
    if not verify(data, sig):
        raise UpdateError("manifest signature INVALID — refusing (fail closed)")
    return json.loads(data)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# --- check (read-only; safe for the agent to poll) -------------------------

def check(source: str | None = None) -> dict:
    m = load_manifest(source)
    out = {"verified": True, "domains": {}}
    cur_v, lat_v = local_veloguard_version(), m.get("veloguard", {}).get("version")
    out["domains"]["veloguard"] = {
        "current": cur_v, "latest": lat_v,
        "update_available": bool(lat_v) and lat_v != cur_v}
    cur_k, lat_k = local_kernel_version(), m.get("kernel", {}).get("version")
    out["domains"]["kernel"] = {
        "current": cur_k, "latest": lat_k,
        "update_available": bool(lat_k) and (
            cur_k == "none" or _vercmp(str(lat_k), cur_k) > 0)}
    return out


# --- apply (re-verifies; atomic with rollback for veloguard) ---------------

def apply_veloguard(source: str | None = None, dry_run: bool = True) -> str:
    m = load_manifest(source)                      # verifies the manifest
    info = m.get("veloguard", {})
    art, want = info.get("artifact"), info.get("sha256")
    if not art or not want:
        raise UpdateError("manifest has no veloguard artifact")
    if dry_run:
        return (f"[dry-run] would fetch {art}, verify sha256, back up "
                f"{VELOGUARD_DIR} → .bak, then swap in v{info.get('version')}")
    with tempfile.TemporaryDirectory() as d:
        tarball = Path(d) / "rel.tar.gz"
        tarball.write_bytes(_fetch(art))
        got = sha256(tarball)
        if got != want:                            # manifest is signed → chain of trust
            raise UpdateError(f"artifact sha256 mismatch (got {got[:12]}…)")
        backup = VELOGUARD_DIR.with_suffix(".bak")
        if backup.exists():
            shutil.rmtree(backup)
        shutil.copytree(VELOGUARD_DIR, backup)
        try:
            try:
                # 'data' filter: no absolute paths, no ../ escapes, no device
                # nodes or setuid bits — even a signed tarball shouldn't be
                # able to write outside the install dir. (Python ≥ 3.12)
                shutil.unpack_archive(str(tarball), str(VELOGUARD_DIR.parent),
                                      filter="data")
            except TypeError:
                shutil.unpack_archive(str(tarball), str(VELOGUARD_DIR.parent))
        except Exception as e:
            shutil.rmtree(VELOGUARD_DIR, ignore_errors=True)
            shutil.move(str(backup), str(VELOGUARD_DIR))
            raise UpdateError(f"apply failed, rolled back: {e}") from e
    return f"updated veloguard → v{info.get('version')} (backup at {VELOGUARD_DIR}.bak)"


def rollback_veloguard() -> str:
    backup = VELOGUARD_DIR.with_suffix(".bak")
    if not backup.exists():
        raise UpdateError("no backup to roll back to")
    shutil.rmtree(VELOGUARD_DIR, ignore_errors=True)
    shutil.move(str(backup), str(VELOGUARD_DIR))
    return "rolled back veloguard to the previous version"


def apply_kernel(source: str | None = None, build: bool = False,
                 dry_run: bool = True) -> str:
    """Fetch the target upstream tag, re-merge our fragments, olddefconfig, build.
    Upstream integrity comes from git (and optionally `git verify-tag`)."""
    m = load_manifest(source)
    k = m.get("kernel", {})
    tag = k.get("tag") or k.get("base_tag")      # build-recipe emits base_tag
    if not tag:
        raise UpdateError("manifest has no kernel tag")
    if not (KERNEL_TREE / "Makefile").exists() or not (KERNEL_TREE / "Kconfig").exists():
        raise UpdateError(f"{KERNEL_TREE} is not a kernel source tree — the "
                          "source-build path is for the developer layout; installed "
                          "systems use the prebuilt package: veloguard-update kernel --apply")
    frags = [f"veloguard/kernel/veloguardos-{x}.config"
             for x in ("base", "desktop", "hardware")]
    steps = [
        ["git", "-C", str(KERNEL_TREE), "fetch", "--depth", "1", "origin", "tag", tag],
        ["git", "-C", str(KERNEL_TREE), "checkout", tag],
        ["scripts/kconfig/merge_config.sh", "-m",
         "arch/x86/configs/x86_64_defconfig", *frags],
        ["make", "olddefconfig"],
    ]
    if build:
        steps.append(["make", "-j", str(os.cpu_count() or 4)])
    if dry_run:
        return "[dry-run] kernel update steps:\n  " + "\n  ".join(
            " ".join(s) for s in steps)
    out = []
    for s in steps:
        cwd = str(KERNEL_TREE) if s[0] in ("scripts/kconfig/merge_config.sh", "make") else None
        r = subprocess.run(s, cwd=cwd, capture_output=True, text=True)
        if r.returncode != 0:
            raise UpdateError(f"kernel step failed: {' '.join(s)}\n{r.stderr[-400:]}")
        out.append(" ".join(s))
    return "kernel updated to " + tag + ":\n  " + "\n  ".join(out)


# --- kernel: prebuilt, offline, apply-on-reboot (the shippable path) --------
# Users don't compile. CI builds linux-veloguard once; the updater downloads the
# SIGNED, hash-pinned package in the background and stages it. Applying happens
# on the next reboot — and only if the user ticked the box on the restart dialog.

def kernel_update_pending() -> dict | None:
    """If a verified kernel package is staged, return {'version','package'};
    else None. Read-only — safe for the restart UI / agent to poll."""
    try:
        return json.loads((KERNEL_STAGE / "pending.json").read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _kernel_artifacts(k: dict) -> list[dict]:
    """[{package, artifact, sha256}] for the kernel and (if published) its
    headers. Package names come from the signed manifest but still become
    filenames under KERNEL_STAGE — basename-only, pacman package names."""
    items = [{"package": k.get("package"), "artifact": k.get("artifact"),
              "sha256": k.get("sha256")}]
    h = k.get("headers")
    if isinstance(h, dict) and h.get("package"):
        items.append({"package": h.get("package"), "artifact": h.get("artifact"),
                      "sha256": h.get("sha256")})
    for it in items:
        if not (it["package"] and it["artifact"] and it["sha256"]):
            raise UpdateError("manifest kernel block has no prebuilt artifact/sha256/"
                              "package — the prebuilt channel isn't published yet")
        if not _PKG_FILE_RE.fullmatch(it["package"]):
            raise UpdateError(f"refusing odd package name {it['package']!r}")
        if not re.fullmatch(r"[0-9a-f]{64}", str(it["sha256"])):
            raise UpdateError(f"manifest sha256 for {it['package']} is malformed")
    return items


def stage_kernel(source: str | None = None, dry_run: bool = True) -> str:
    """Download + verify the prebuilt kernel (and its headers, so DKMS drivers
    like nvidia rebuild for it) named in the SIGNED manifest, and stage them.
    Does NOT arm the reboot — that's the user's opt-in at restart (the
    checkbox → arm_reboot_update())."""
    m = load_manifest(source)                       # verifies the signature first
    k = m.get("kernel", {})
    ver = str(k.get("version") or "")
    items = _kernel_artifacts(k)
    cur = local_kernel_version()
    if ver and cur != "none":
        c = _vercmp(ver, cur)
        if c == 0:
            return f"kernel already at {ver} — nothing to stage"
        if c < 0:
            # A validly-signed but OLD manifest (replayed, or a stale mirror)
            # must not walk users back onto a kernel with fixed CVEs.
            raise UpdateError(f"manifest offers {ver} but {cur} is installed — "
                              "downgrade refused")
    pending = kernel_update_pending()
    if pending and pending.get("version") == ver and all(
            (KERNEL_STAGE / it["package"]).is_file() for it in items):
        return f"kernel v{ver} already staged — confirm at restart to install"
    if dry_run:
        return (f"[dry-run] would fetch {', '.join(it['package'] for it in items)}, "
                f"verify sha256, stage to {KERNEL_STAGE}, mark pending v{ver}")

    KERNEL_STAGE.mkdir(parents=True, exist_ok=True)
    KERNEL_STAGE.chmod(0o755)
    (KERNEL_STAGE / "pending.json").unlink(missing_ok=True)   # not pending mid-download
    keep = {it["package"] for it in items}
    for old in KERNEL_STAGE.glob("*.pkg.tar.zst"):               # drop stale stages
        if old.name not in keep:
            old.unlink(missing_ok=True)
    for it in items:
        dest = KERNEL_STAGE / it["package"]
        part = dest.with_name(dest.name + ".part")
        part.write_bytes(_fetch(it["artifact"]))
        got = sha256(part)
        if got != it["sha256"]:                      # manifest signed → trust chain
            part.unlink(missing_ok=True)
            raise UpdateError(f"{it['package']} sha256 mismatch (got {got[:12]}…) — refused")
        part.replace(dest)                           # atomic: never a half file
    (KERNEL_STAGE / "pending.json").write_text(json.dumps({
        "version": ver,
        "package": items[0]["package"],              # back-compat key
        "packages": [{"file": it["package"], "sha256": it["sha256"]} for it in items],
    }))
    return (f"staged kernel v{ver} ({', '.join(sorted(keep))}) — "
            "confirm at restart to install")


def arm_reboot_update() -> str:
    """Opt-in confirmed: flip systemd into offline-update mode for the next boot
    (it installs the staged package, then reboots normally)."""
    if kernel_update_pending() is None:
        raise UpdateError("nothing staged to apply")
    if SYSTEM_UPDATE_FLAG.is_symlink() or SYSTEM_UPDATE_FLAG.exists():
        SYSTEM_UPDATE_FLAG.unlink()
    SYSTEM_UPDATE_FLAG.symlink_to(KERNEL_STAGE)      # systemd.offline-updates(7)
    return "armed — VeloGuardOS will install the kernel on the next reboot"


def disarm_reboot_update() -> str:
    """Opt-out: keep the package staged but don't apply it on reboot."""
    if SYSTEM_UPDATE_FLAG.is_symlink() or SYSTEM_UPDATE_FLAG.exists():
        SYSTEM_UPDATE_FLAG.unlink()
    return "disarmed — staged kernel will not be applied on reboot"
