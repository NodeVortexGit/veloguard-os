#!/usr/bin/env bash
# VeloGuardOS hardware layer — shared helpers.
# Derived from Omarchy's install/hardware helpers + bin/omarchy-pkg-add and the
# omarchy-hw-nvidia-* detectors (MIT). See desktop/omarchy/PROVENANCE.md.
#
# These replace Omarchy's omarchy-* commands with self-contained bash functions
# so the hardware scripts run without Omarchy's helper-script web. Exported with
# `export -f` by all.sh so the per-device scripts can call them.

# Install packages if missing: official repos first, then an AUR helper (for the
# handful of AUR-only driver packages, e.g. nvidia-580xx). Best-effort: a missing
# package logs a warning but never aborts the whole hardware pass.
# Each package is resolved on its own: ONE name the sync repos don't carry
# (lib32-* without [multilib], an AUR-only driver) used to abort the whole
# `pacman -S` transaction — so on a stock install NVIDIA users got no driver
# at all because lib32-nvidia-utils was in the same list.
vg_pkg_add() {
  local p missing=() repo=() aur=() rc=0
  for p in "$@"; do pacman -Q "$p" &>/dev/null || missing+=("$p"); done
  ((${#missing[@]})) || return 0
  for p in "${missing[@]}"; do
    if pacman -Si "$p" &>/dev/null; then repo+=("$p"); else aur+=("$p"); fi
  done
  if ((${#repo[@]})); then
    pacman -S --noconfirm --needed "${repo[@]}" || rc=1
  fi
  if ((${#aur[@]})); then
    local helper done_aur=""
    for helper in yay paru; do
      if command -v "$helper" >/dev/null 2>&1; then
        # AUR helpers refuse root; build as the desktop user.
        sudo -u "${VELOGUARD_HW_USER:-veloguard}" "$helper" -S --noconfirm --needed "${aur[@]}" \
          && done_aur=1
        break
      fi
    done
    if [ -z "$done_aur" ]; then
      echo "vg-hardware: not in the enabled repos (no AUR helper): ${aur[*]}" >&2
      rc=1
    fi
  fi
  return $rc
}

# Kernel headers for EVERY installed kernel, so DKMS builds out-of-tree
# drivers (nvidia, broadcom-wl) for whichever one boots. linux-veloguard's
# headers aren't in any repo: they arrive with the kernel through the signed
# offline updater (same pacman transaction), so they're skipped here.
vg_kernel_headers() {
  local k
  for k in linux linux-lts linux-zen linux-hardened; do
    pacman -Q "$k" &>/dev/null && printf '%s-headers\n' "$k"
  done
}

# pacman's [multilib] (32-bit libs) — Arch ships it disabled.
vg_multilib_enabled() { grep -q '^\[multilib\]' /etc/pacman.conf 2>/dev/null; }

# NVIDIA GSP firmware present (Turing / RTX 20-series or newer): device id >= 0x1e00.
# Reads cached sysfs IDs (not lspci, which resumes runtime-suspended GPUs).
vg_hw_nvidia_gsp() {
  local dev pci="${VELOGUARD_PCI_DEVICES_PATH:-/sys/bus/pci/devices}"
  shopt -s nullglob
  for dev in "$pci"/*; do
    [[ $(< "$dev/vendor") == "0x10de" ]] || continue
    [[ $(< "$dev/class")  == 0x03*    ]] || continue
    (( $(< "$dev/device") >= 0x1e00 )) && return 0
  done
  return 1
}

# NVIDIA without GSP (Maxwell/Pascal/Volta): 0x1340 <= device id < 0x1e00.
vg_hw_nvidia_without_gsp() {
  local dev id pci="${VELOGUARD_PCI_DEVICES_PATH:-/sys/bus/pci/devices}"
  shopt -s nullglob
  for dev in "$pci"/*; do
    [[ $(< "$dev/vendor") == "0x10de" ]] || continue
    [[ $(< "$dev/class")  == 0x03*    ]] || continue
    id=$(< "$dev/device")
    (( id >= 0x1340 && id < 0x1e00 )) && return 0
  done
  return 1
}
