#!/usr/bin/env bash
#
# VeloGuardOS hardware layer — orchestrator. Runs each device/driver script
# guarded, so one failing (or irrelevant) probe never aborts the rest. Modeled
# on Omarchy's install/hardware/all.sh (MIT); see desktop/omarchy/PROVENANCE.md.
#
# Run as root:  veloguard-hardware        (or the veloguard-hardware.service unit)
set -uo pipefail

HW_DIR="${VELOGUARD_HW_DIR:-/usr/share/veloguard/hardware}"
[ -d "$HW_DIR" ] || HW_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG="${VELOGUARD_HW_LOG:-/var/log/veloguard-hardware.log}"

# Load + export the shared helpers so child scripts can call them.
# shellcheck source=/dev/null
. "$HW_DIR/lib.sh"
export -f vg_pkg_add vg_kernel_headers vg_multilib_enabled \
          vg_hw_nvidia_gsp vg_hw_nvidia_without_gsp
# The desktop user: sudo's caller, else the first human account (the installed
# system's user is named in the installer — "veloguard" is only the live user).
_first_user="$(getent passwd | awk -F: '$3 >= 1000 && $3 < 60000 {print $1; exit}')"
export VELOGUARD_HW_USER="${VELOGUARD_HW_USER:-${SUDO_USER:-${_first_user:-veloguard}}}"

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$LOG" ; }

run_logged() {                                    # $1 = script path
  local script="$1" name
  name="$(basename "$script")"
  [ -f "$script" ] || return 0
  log "── $name"
  if bash "$script" >>"$LOG" 2>&1; then
    log "   ok: $name"
  else
    log "   WARN: $name exited non-zero (continuing)"
  fi
}

main() {
  [ "$(id -u)" -eq 0 ] || { echo "run as root: sudo veloguard-hardware" >&2; exit 1; }
  mkdir -p "$(dirname "$LOG")"
  log "VeloGuardOS hardware setup starting"

  # Drivers come from the network. Offline (first boot with no Wi-Fi yet,
  # or the Wi-Fi driver is exactly what's missing) → exit non-zero so the
  # unit does NOT mark itself done and retries next boot. It used to run,
  # fail every install, and stamp .hardware-done anyway — forever.
  # A FULL -Syu, never a bare -Sy: -Sy + -S <pkg> is a partial upgrade (new
  # packages against old libraries), and DKMS needs headers matching the
  # kernel that's actually installed — the ISO-era versions are long gone
  # from the mirrors.
  if ! pacman -Syu --noconfirm >>"$LOG" 2>&1; then
    log "system sync/upgrade failed (offline?) — will retry on next boot"
    exit 75
  fi

  # Broadly-applicable driver/hardware scripts (order matters: network first).
  run_logged "$HW_DIR/network.sh"
  run_logged "$HW_DIR/input-group.sh"
  run_logged "$HW_DIR/set-wireless-regdom.sh"
  run_logged "$HW_DIR/fix-fkeys.sh"
  run_logged "$HW_DIR/fix-synaptic-touchpad.sh"
  run_logged "$HW_DIR/bluetooth.sh"
  run_logged "$HW_DIR/nvidia.sh"
  run_logged "$HW_DIR/vulkan.sh"
  run_logged "$HW_DIR/fix-bcm43xx.sh"

  # Rebuild the initramfs if any script changed modules/modprobe (nvidia early KMS).
  if command -v mkinitcpio >/dev/null 2>&1; then
    log "── regenerating initramfs (mkinitcpio -P)"
    mkinitcpio -P >>"$LOG" 2>&1 || log "   WARN: mkinitcpio failed"
  fi

  log "VeloGuardOS hardware setup complete → $LOG"
}

main "$@"
