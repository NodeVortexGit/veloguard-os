#!/usr/bin/env bash
#
# calamares-hardware — detect every component and install its drivers DURING
# installation (in the target chroot, with the network calamares-target-net.sh
# provided): GPU (NVIDIA open/legacy + DKMS headers, Vulkan, VA-API), Broadcom
# wl, Bluetooth, laptop power/thermals/sensors/fingerprint, regulatory domain…
# Same layer as the first-boot veloguard-hardware.service (desktop/hardware/).
#
#   calamares-hardware.sh <user>
#
# Never fails the installation. Success stamps .hardware-done so first boot
# skips it; offline (all.sh exits 75) leaves the service armed to retry.
set -u
U="${1:-}"
HW=/usr/share/veloguard/hardware/all.sh
[ -f "$HW" ] || { echo "no hardware layer at $HW — first boot will handle drivers"; exit 0; }
echo "machine: $(/opt/veloguard/provision/veloguard-hwprobe --human | tr '\n' ';')"
if VELOGUARD_HW_USER="$U" VELOGUARD_HW_SKIP_INITRAMFS=1 bash "$HW"; then
  mkdir -p /var/lib/veloguard && touch /var/lib/veloguard/.hardware-done
  echo "drivers installed"
else
  echo "hardware step incomplete (rc=$?) — veloguard-hardware.service retries on first boot"
fi
exit 0
