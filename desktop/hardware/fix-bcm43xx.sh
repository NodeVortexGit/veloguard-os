#!/usr/bin/env bash
# Broadcom BCM4360/BCM4331 Wi-Fi (some MacBooks + other systems). Derived from
# Omarchy install/hardware/fix-bcm43xx.sh (MIT). Uses vg_pkg_add.
pci_info=$(lspci -nn)
if echo "$pci_info" | grep -q "14e4:43a0" || echo "$pci_info" | grep -q "14e4:4331"; then
  # The DKMS flavour + headers for every installed kernel: the prebuilt
  # broadcom-wl is compiled for the stock `linux` only, so linux-veloguard
  # (or -lts/-zen) would boot with no Wi-Fi.
  echo "BCM4360 / BCM4331 detected — installing broadcom-wl-dkms"
  mapfile -t HEADERS < <(vg_kernel_headers)
  vg_pkg_add dkms "${HEADERS[@]}" || exit 1
  # broadcom-wl conflicts with -dkms. Swap in ONE transaction (--ask 4 =
  # accept the conflict removal) so a failed install can never leave the
  # machine with neither driver.
  pacman -S --noconfirm --needed --ask 4 broadcom-wl-dkms
fi
