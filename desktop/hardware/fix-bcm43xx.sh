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
  if pacman -Q broadcom-wl &>/dev/null; then
    pacman -Rdd --noconfirm broadcom-wl   # conflicts with -dkms; replaced below
  fi
  vg_pkg_add dkms "${HEADERS[@]}" broadcom-wl-dkms
fi
