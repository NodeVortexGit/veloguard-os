#!/usr/bin/env bash
# Broadcom BCM4360/BCM4331 Wi-Fi (some MacBooks + other systems). Derived from
# Omarchy install/hardware/fix-bcm43xx.sh (MIT). Uses vg_pkg_add.
# The probe knows the whole wl-only family (BCM4331/4352/4360/43602 …), not
# just the two IDs this used to grep for.
pci_info=$(lspci -nn 2>/dev/null)
if [ "${VG_HW_wifi_broadcom_wl:-0}" = 1 ] || echo "$pci_info" | grep -qE "14e4:(43a0|4331)"; then
  # The DKMS flavour + headers for every installed kernel: the prebuilt
  # broadcom-wl is compiled for the stock `linux` only, so linux-veloguard
  # (or -lts/-zen) would boot with no Wi-Fi.
  echo "Broadcom chip that needs the proprietary wl driver — installing broadcom-wl-dkms"
  mapfile -t HEADERS < <(vg_kernel_headers)
  vg_pkg_add dkms "${HEADERS[@]}" || exit 1
  # broadcom-wl conflicts with -dkms. Swap in ONE transaction (--ask 4 =
  # accept the conflict removal) so a failed install can never leave the
  # machine with neither driver.
  pacman -S --noconfirm --needed --ask 4 broadcom-wl-dkms
fi
