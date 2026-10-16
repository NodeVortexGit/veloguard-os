#!/usr/bin/env bash
# Laptop power, thermals and sensors — only on machines veloguard-hwprobe
# classifies as laptops (DMI chassis type / system battery). Desktops and VMs
# are left alone. Uses the probe results all.sh exports (VG_HW_*).
[ "${VG_HW_chassis:-}" = laptop ] || { echo "not a laptop (${VG_HW_chassis:-unknown}) — skipping"; exit 0; }

pkgs=(power-profiles-daemon)                       # the Waybar/GNOME/COSMIC power-profile switch
[ "${VG_HW_cpu:-}" = intel ]       && pkgs+=(thermald)
[ "${VG_HW_sensors:-0}" = 1 ]      && pkgs+=(iio-sensor-proxy)   # 2-in-1 rotation, ambient light
[ "${VG_HW_fingerprint:-0}" = 1 ]  && pkgs+=(fprintd)            # enroll: fprintd-enroll
[ "${VG_HW_thunderbolt:-0}" = 1 ]  && pkgs+=(bolt)               # Thunderbolt device authorization
[ "${VG_HW_hybrid_gpu:-0}" = 1 ]   && pkgs+=(nvidia-prime)       # prime-run <app> → dGPU on demand

vg_pkg_add "${pkgs[@]}" || exit 1

systemctl enable power-profiles-daemon.service 2>/dev/null || true
[ "${VG_HW_cpu:-}" = intel ] && { systemctl enable thermald.service 2>/dev/null || true; }

# Hybrid NVIDIA laptops: let the dGPU drop to D3 when idle — otherwise it
# burns several watts of battery doing nothing (Turing+ supports fine-grained
# runtime PM through the open driver).
if [ "${VG_HW_hybrid_gpu:-0}" = 1 ]; then
  install -d /etc/modprobe.d
  printf 'options nvidia "NVreg_DynamicPowerManagement=0x02"\n' > /etc/modprobe.d/nvidia-pm.conf
fi
