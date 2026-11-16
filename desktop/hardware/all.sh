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

# One hardware probe for every stage: exported as VG_HW_<key> so the
# per-device scripts decide from the same facts (and log what was seen).
PROBE="$(command -v veloguard-hwprobe || echo /opt/veloguard/provision/veloguard-hwprobe)"
if [ -x "$PROBE" ]; then
  while IFS='=' read -r k v; do
    [ -n "$k" ] && export "VG_HW_$k=$(eval "printf '%s' $v")"
  done < <("$PROBE")
fi

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
  [ -x "$PROBE" ] && "$PROBE" --human | while IFS= read -r l; do log "   $l"; done

  # Drivers come from the network. Offline (first boot with no Wi-Fi yet,
  # or the Wi-Fi driver is exactly what's missing) → exit non-zero so the
  # unit does NOT mark itself done and retries next boot. It used to run,
  # fail every install, and stamp .hardware-done anyway — forever.
  # A FULL -Syu, never a bare -Sy: -Sy + -S <pkg> is a partial upgrade (new
  # packages against old libraries), and DKMS needs headers matching the
  # kernel that's actually installed — the ISO-era versions are long gone
  # from the mirrors.
  # A lock with no pacman running is left from a killed run (power loss, a
  # timeout mid-transaction) and would block every package operation forever.
  if [ -e /var/lib/pacman/db.lck ] && ! pgrep -x pacman >/dev/null 2>&1; then
    rm -f /var/lib/pacman/db.lck; log "removed a stale pacman lock"
  fi
  # Keyring first (the one sanctioned partial update): the disc's
  # archlinux-keyring predates every packager who joined since, and their
  # packages would fail signature checks in the -Syu below.
  pacman -Sy --noconfirm --needed archlinux-keyring >>"$LOG" 2>&1 || true
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
  run_logged "$HW_DIR/video-accel.sh"
  run_logged "$HW_DIR/fix-bcm43xx.sh"
  run_logged "$HW_DIR/laptop.sh"

  # Rebuild the initramfs if any script changed modules/modprobe (nvidia early
  # KMS). The installer sets VELOGUARD_HW_SKIP_INITRAMFS: its initcpio step
  # runs right after this one anyway.
  if [ "${VELOGUARD_HW_SKIP_INITRAMFS:-0}" != 1 ] && command -v mkinitcpio >/dev/null 2>&1; then
    log "── regenerating initramfs (mkinitcpio -P)"
    mkinitcpio -P >>"$LOG" 2>&1 || log "   WARN: mkinitcpio failed"
  fi

  # A desktop picked in the installer that couldn't be downloaded then
  # (offline install, mirror or GitHub outage) is finished here, on the first
  # boot that has a network. The user had the disc's Hyprland meanwhile; the
  # unit keeps running at boot until this file is gone.
  local pending=/var/lib/veloguard/desktop-pending de u
  if [ -f "$pending" ] && read -r de u < "$pending"; then
    log "── finishing the installer's desktop choice: $de (user ${u:-?})"
    "${VELOGUARD_PROVISION_DIR:-/opt/veloguard/provision}/calamares-desktop.sh" "$de" "$u" >>"$LOG" 2>&1
    if [ -f "$pending" ]; then log "   desktop still pending — retried next boot"
    else log "   ok: $de installed (it opens at the next login)"; fi
  fi

  log "VeloGuardOS hardware setup complete → $LOG"
}

main "$@"
