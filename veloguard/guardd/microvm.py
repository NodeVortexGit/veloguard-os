"""The 'vm' tier — detonate a suspicious file in a Firecracker micro-VM and watch.

A separate kernel (KVM), no network device at all, a read-only root filesystem,
and RAM-only scratch space: the sample runs for a few seconds and the guest
reports what it printed, which files it created and what was still running.
That record goes to the agent writing the incident report — "what did it try
to do?" — without the sample ever touching this machine's kernel, files or
network.

Images (install-sandbox.sh --firecracker): a guest kernel (vmlinux) and a root
filesystem (rootfs.ext4) with VeloGuard's /vg-init baked in, under
/var/lib/veloguard/microvm (or ~/.local/share/veloguard/microvm). Runs as the
person (needs /dev/kvm), never as root.

  veloguard detonate ./suspicious.bin [--seconds 30]
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

IMAGE_DIRS = [Path("/var/lib/veloguard/microvm"),
              Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share")))
              / "veloguard" / "microvm"]
MAX_SAMPLE = 256 << 20          # 256 MiB — bigger files aren't detonated
MAX_OUTPUT = 64 << 10           # what the guest may print back (it also caps itself)


def images() -> tuple[Path, Path] | None:
    for d in IMAGE_DIRS:
        k, r = d / "vmlinux", d / "rootfs.ext4"
        if k.is_file() and r.is_file():
            return k, r
    return None


def ready() -> tuple[bool, str]:
    if not shutil.which("firecracker"):
        return False, "Firecracker isn't installed (install-sandbox.sh --firecracker)"
    if not os.access("/dev/kvm", os.R_OK | os.W_OK):
        return False, "no access to /dev/kvm"
    if not images():
        return False, "the micro-VM images aren't there (install-sandbox.sh --firecracker)"
    if not shutil.which("mkfs.ext4"):
        return False, "mkfs.ext4 (e2fsprogs) is missing"
    return True, "ready"


def _runner(name: str, head: bytes) -> str:
    """How the guest should start the sample, by what it is."""
    low = name.lower()
    if head.startswith(b"\x7fELF"):
        return "./sample"
    if head.startswith(b"#!"):
        return "./sample"
    if low.endswith(".py"):
        return "python3 ./sample"
    if low.endswith((".sh", ".bash", ".run")):
        return "sh ./sample"
    if low.endswith(".pl"):
        return "perl ./sample"
    return "./sample"


def vm_config(kernel: Path, rootfs: Path, sample_img: Path, seconds: int,
              mem_mib: int = 512) -> dict:
    return {
        "boot-source": {
            "kernel_image_path": str(kernel),
            "boot_args": ("console=ttyS0 reboot=k panic=1 pci=off ro quiet "
                          f"init=/vg-init vg.seconds={int(seconds)}"),
        },
        "drives": [
            {"drive_id": "rootfs", "path_on_host": str(rootfs),
             "is_root_device": True, "is_read_only": True},
            {"drive_id": "sample", "path_on_host": str(sample_img),
             "is_root_device": False, "is_read_only": True},
        ],
        "machine-config": {"vcpu_count": 1, "mem_size_mib": int(mem_mib)},
        "network-interfaces": [],          # no NIC: the sample can't reach anything
    }


def parse_console(text: str) -> dict:
    """The guest prints VG-BEGIN … VG-END exit=N, VG-NEWFILES …, VG-PROCS …, VG-DONE."""
    out = {"output": "", "exit": None, "new_files": [], "processes": [], "completed": False}
    sec = None
    lines: dict[str, list[str]] = {"out": [], "files": [], "procs": []}
    for line in text.splitlines():
        s = line.rstrip("\r")
        if s == "VG-BEGIN":
            sec = "out"; continue
        if s.startswith("VG-END"):
            sec = None
            try:
                out["exit"] = int(s.split("exit=", 1)[1])
            except (IndexError, ValueError):
                pass
            continue
        if s == "VG-NEWFILES":
            sec = "files"; continue
        if s == "VG-PROCS":
            sec = "procs"; continue
        if s == "VG-DONE":
            out["completed"] = True; sec = None; continue
        if sec:
            lines[sec].append(s)
    out["output"] = "\n".join(lines["out"])[-16000:]
    out["new_files"] = [x for x in lines["files"] if x.strip()][:100]
    out["processes"] = [x for x in lines["procs"] if x.strip()][:60]
    return out


def detonate(path: str, seconds: int = 30, mem_mib: int = 512) -> dict:
    """Run `path` inside a throwaway micro-VM; never raises."""
    ok, why = ready()
    if not ok:
        return {"ok": False, "error": why}
    src = Path(path)
    try:
        size = src.stat().st_size
    except OSError as e:
        return {"ok": False, "error": f"can't read the sample ({e.strerror})"}
    if size > MAX_SAMPLE:
        return {"ok": False, "error": "the sample is too big to detonate (>256 MiB)"}
    kernel, rootfs = images()
    seconds = max(5, min(int(seconds), 120))
    work = Path(tempfile.mkdtemp(prefix="vg-microvm-"))
    try:
        box = work / "s"
        box.mkdir()
        with open(src, "rb") as f:
            head = f.read(64)
        shutil.copyfile(src, box / "sample")       # readable copy, even of a mode-000 file we own
        os.chmod(box / "sample", 0o755)
        (box / "run.sh").write_text(f"#!/bin/sh\ncd /tmp/vg\nexec {_runner(src.name, head)}\n")
        (box / "name").write_text(src.name[:200] + "\n")
        img = work / "sample.ext4"
        with open(img, "wb") as f:
            f.truncate(max(16 << 20, size * 2 + (8 << 20)))
        r = subprocess.run(["mkfs.ext4", "-q", "-F", "-d", str(box), str(img)],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return {"ok": False, "error": f"couldn't build the sample disk: {r.stderr.strip()[:200]}"}
        cfg = work / "vm.json"
        cfg.write_text(json.dumps(vm_config(kernel, rootfs, img, seconds, mem_mib)))
        t0 = time.monotonic()
        proc = subprocess.Popen(["firecracker", "--no-api", "--config-file", str(cfg),
                                 "--level", "Error", "--log-path", str(work / "fc.log")],
                                cwd=work, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, start_new_session=True)
        try:
            raw, _ = proc.communicate(timeout=seconds + 40)
        except subprocess.TimeoutExpired:
            proc.kill()
            raw, _ = proc.communicate()
        dur = round(time.monotonic() - t0, 1)
        text = raw[:MAX_OUTPUT * 4].decode("utf-8", "backslashreplace")
        res = parse_console(text)
        res.update({"ok": True, "seconds": seconds, "duration": dur,
                    "network": "none (no network device in the VM)"})
        if not res["completed"]:
            res["note"] = "the VM didn't finish cleanly (crashed, hung, or the sample stopped it)"
        return res
    except (OSError, subprocess.SubprocessError) as e:
        return {"ok": False, "error": f"micro-VM failed: {e}"}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def as_text(res: dict) -> str:
    if not res.get("ok"):
        return f"(not detonated: {res.get('error')})"
    parts = [f"Ran {res['seconds']} s in a Firecracker micro-VM, no network "
             f"({res['duration']} s wall); exit code: {res.get('exit')}"]
    if res.get("note"):
        parts.append(res["note"])
    parts.append("Output:\n" + (res["output"].strip() or "(nothing)"))
    parts.append("Files it created:\n" + ("\n".join(res["new_files"]) or "(none)"))
    parts.append("Processes still running at the end:\n" + ("\n".join(res["processes"]) or "(none)"))
    return "\n\n".join(parts)
