#!/usr/bin/env bash
# NVIDIA drivers, matched to the GPU generation. Derived from Omarchy
# install/hardware/nvidia.sh (MIT). Uses the VeloGuard vg_* helpers.
if lspci | grep -qi 'nvidia'; then
  # Kernel headers for the DKMS build — for EVERY installed kernel (the old
  # `head -1` picked just one, so the other kernel booted without a driver).
  # linux-veloguard-headers ship with that kernel via the offline updater.
  mapfile -t HEADERS < <(vg_kernel_headers)
  ((${#HEADERS[@]})) && vg_pkg_add dkms "${HEADERS[@]}"

  if vg_hw_nvidia_gsp; then
    PACKAGES=(nvidia-open-dkms nvidia-utils libva-nvidia-driver)
    LIB32=(lib32-nvidia-utils)
  elif vg_hw_nvidia_without_gsp; then
    # Legacy 580xx branch (Maxwell/Pascal/Volta) — AUR; vg_pkg_add falls back to
    # an AUR helper if one is installed.
    PACKAGES=(nvidia-580xx-dkms nvidia-580xx-utils)
    LIB32=(lib32-nvidia-580xx-utils)
  fi
  # 32-bit GL only matters for Steam/Wine and lives in [multilib], which is
  # off by default (install-gaming.sh enables it) — never let it block the
  # driver itself.
  vg_multilib_enabled && PACKAGES+=("${LIB32[@]}")

  if [[ -z ${PACKAGES+x} ]]; then
    echo "No matching VeloGuard NVIDIA driver package for this GPU."
    echo "See: https://wiki.archlinux.org/title/NVIDIA"
    exit 0
  fi

  if ! vg_pkg_add "${PACKAGES[@]}"; then
    # Don't write the nvidia initramfs/KMS config for a driver that isn't
    # there: MODULES+=(nvidia …) would make every mkinitcpio run fail.
    echo "NVIDIA driver install failed — leaving nouveau/simpledrm in place" >&2
    exit 1
  fi

  # Early KMS + modeset
  mkdir -p /etc/modprobe.d
  printf 'options nvidia_drm modeset=1\n' > /etc/modprobe.d/nvidia.conf

  mkdir -p /etc/mkinitcpio.conf.d
  printf 'MODULES+=(nvidia nvidia_modeset nvidia_uvm nvidia_drm)\n' \
    > /etc/mkinitcpio.conf.d/nvidia.conf

  # Hyprland NVIDIA session env (cursor + GBM) so Wayland comes up clean.
  install -d /usr/share/veloguard/desktop/hypr
  cat > /usr/share/veloguard/desktop/hypr/nvidia.conf <<'EOF'
# Loaded on NVIDIA hardware (sourced by hyprland.conf when present)
env = LIBVA_DRIVER_NAME,nvidia
env = __GLX_VENDOR_LIBRARY_NAME,nvidia
env = NVD_BACKEND,direct
cursor {
  no_hardware_cursors = true
}
EOF
fi
