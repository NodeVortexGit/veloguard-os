#!/usr/bin/env bash
#
# VeloGuardOS — virtualization layer tiers.
#
# The default 'light' tier (bubblewrap + RAM overlay) needs only bubblewrap and
# is already pulled by install-app-formats.sh. This adds the optional stronger
# tiers the AI can escalate to for riskier apps.
#
#   ./install-sandbox.sh              # ensure bubblewrap (light tier)
#   ./install-sandbox.sh --gvisor     # + gVisor runsc (strong tier)
#   ./install-sandbox.sh --all        # + notes for Firecracker (vm tier)
#
set -euo pipefail
say()  { printf '\033[1;36m[veloguard]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[veloguard]\033[0m %s\n' "$*" >&2; }
priv() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi; }

# light tier — bubblewrap
if ! command -v bwrap >/dev/null; then
  if   command -v dnf     >/dev/null; then priv dnf install -y bubblewrap
  elif command -v apt-get >/dev/null; then priv apt-get update && priv apt-get install -y bubblewrap
  elif command -v pacman  >/dev/null; then priv pacman -S --noconfirm --needed bubblewrap
  else warn "install 'bubblewrap' manually"; fi
fi
command -v bwrap >/dev/null && say "light tier ready (bubblewrap)"

# strong tier — gVisor (runsc)
if [ "${1:-}" = "--gvisor" ] || [ "${1:-}" = "--all" ]; then
  say "installing gVisor (runsc) for the 'strong' tier…"
  arch="$(uname -m)"
  gcs="https://storage.googleapis.com/gvisor/releases/release"
  # Private temp dir: a fixed /tmp path could be swapped by another local
  # user between the checksum and the root-owned install below.
  dl="$(mktemp -d)"; trap 'rm -rf "$dl"' EXIT
  got=""
  # Releases ship as gvisor.tar.bz2 (+ .sha512) holding runsc; older ones as a
  # bare runsc. Either way the sha512 is checked before anything is installed.
  for base in "$gcs/latest/$arch" \
      $(curl -fsSL -m 30 "https://storage.googleapis.com/gvisor?prefix=releases/release/&delimiter=/" \
          | grep -oE 'releases/release/[0-9]{8}/' | sort -uVr | head -4 \
          | sed "s#^releases/release/#$gcs/#; s#/\$#/$arch#"); do
    if ( cd "$dl" && curl -fsSL -m 600 "$base/gvisor.tar.bz2" -o gvisor.tar.bz2 \
          && curl -fsSL -m 60 "$base/gvisor.tar.bz2.sha512" -o gvisor.tar.bz2.sha512 \
          && sha512sum -c gvisor.tar.bz2.sha512 >/dev/null \
          && mkdir -p x && tar -xjf gvisor.tar.bz2 -C x && [ -f x/runsc ] ); then got="$dl/x"; break; fi
    if ( cd "$dl" && curl -fsSL -m 600 "$base/runsc" -o runsc.bin \
          && curl -fsSL -m 60 "$base/runsc.sha512" -o runsc.sha512 \
          && sed -i 's/runsc$/runsc.bin/' runsc.sha512 && sha512sum -c runsc.sha512 >/dev/null \
          && mkdir -p x && mv runsc.bin x/runsc ); then
      got="$dl/x"; break
    fi
  done
  # runsc looks for its helpers (gvisor_sentry, gofers…) in gvisor-bin/ next to itself
  if [ -n "$got" ] && priv install -m755 -o root -g root "$got/runsc" /usr/local/bin/runsc \
     && { [ ! -d "$got/gvisor-bin" ] || { priv install -d -m755 /usr/local/bin/gvisor-bin \
          && priv install -m755 -o root -g root "$got"/gvisor-bin/* /usr/local/bin/gvisor-bin/; }; }; then
    say "gVisor installed (strong tier): $(/usr/local/bin/runsc --version 2>/dev/null | head -1)"
  else
    warn "gVisor install failed — strong tier will keep degrading to light"
  fi
fi

# vm tier — Firecracker micro-VM: a separate kernel, no network device, a
# read-only root. guardd/microvm.py "detonates" a suspicious file in it and
# reports what it did. Guest images: Firecracker's own published CI kernel +
# Ubuntu rootfs (its getting-started images), with VeloGuard's /vg-init added.
if [ "${1:-}" = "--firecracker" ] || [ "${1:-}" = "--all" ]; then
  say "installing Firecracker + the detonation VM for the 'vm' tier…"
  if command -v pacman >/dev/null; then
    priv pacman -S --noconfirm --needed firecracker squashfs-tools e2fsprogs || true
  fi
  if ! command -v firecracker >/dev/null; then
    warn "firecracker isn't installed — the vm tier stays off"
  else
    dest=/var/lib/veloguard/microvm
    init_src="$(dirname "$(readlink -f "$0")")/microvm-init"
    arch="$(uname -m)"; s3="https://s3.amazonaws.com/spec.ccfc.min"   # path-style: the bucket has dots
    fcv="$(firecracker --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1 || true)"
    major="${fcv%%.*}"; minor="${fcv##*.}"; key_k=""; key_r=""
    # the newest published image set at or below this Firecracker version
    for m in $(seq "${minor:-0}" -1 0); do
      list="$(curl -fsSL -m 30 "$s3/?prefix=firecracker-ci/v$major.$m/$arch/&list-type=2" || true)"
      # (|| true: a version with no published images is the normal case, not an error)
      key_k="$(grep -oP '(?<=<Key>)firecracker-ci/v[0-9.]+/'"$arch"'/vmlinux-6\.1\.[0-9]+(?=</Key>)' <<<"$list" | sort -V | tail -1 || true)"
      key_r="$(grep -oP '(?<=<Key>)firecracker-ci/v[0-9.]+/'"$arch"'/ubuntu-[0-9.]+\.squashfs(?=</Key>)' <<<"$list" | sort -V | tail -1 || true)"
      [ -n "$key_k" ] && [ -n "$key_r" ] && break
    done
    if [ -z "$key_k" ] || [ -z "$key_r" ] || [ ! -r "$init_src" ]; then
      warn "couldn't find Firecracker's guest images — the vm tier stays off"
    else
      vm="$(mktemp -d)"; trap 'rm -rf "$vm"; rm -rf "${dl:-}"' EXIT
      if curl -fsSL -m 900 -o "$vm/vmlinux" "https://s3.amazonaws.com/spec.ccfc.min/$key_k" \
         && curl -fsSL -m 1800 -o "$vm/rootfs.squashfs" "https://s3.amazonaws.com/spec.ccfc.min/$key_r" \
         && priv unsquashfs -q -d "$vm/root" "$vm/rootfs.squashfs" >/dev/null \
         && priv install -m 755 -o root -g root "$init_src" "$vm/root/vg-init" \
         && size=$(( $(priv du -sm "$vm/root" | cut -f1) + 256 )) \
         && truncate -s "${size}M" "$vm/rootfs.ext4" \
         && priv mkfs.ext4 -q -F -L vg-detonate -d "$vm/root" "$vm/rootfs.ext4"; then
        priv install -d -m 755 "$dest"
        priv install -m 644 -o root -g root "$vm/vmlinux" "$dest/vmlinux"
        priv install -m 644 -o root -g root "$vm/rootfs.ext4" "$dest/rootfs.ext4"
        printf '%s\n%s\n' "$key_k" "$key_r" | priv tee "$dest/SOURCE" >/dev/null
        priv rm -rf "$vm/root"
        say "vm tier ready ($(basename "$key_k"), $(basename "$key_r"))"
      else
        warn "building the detonation VM failed — the vm tier stays off"
      fi
    fi
  fi
fi

say "tiers available now:"
python3 - <<'PY' 2>/dev/null || true
import shutil
print("  light :", "yes" if shutil.which("bwrap") else "no")
print("  strong:", "yes" if shutil.which("runsc") else "no  (re-run with --gvisor)")
import os
print("  vm    :", "yes" if (shutil.which("firecracker") and os.path.isfile("/var/lib/veloguard/microvm/rootfs.ext4")) else "no  (re-run with --firecracker)")
PY
