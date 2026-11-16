#!/usr/bin/env bash
# Vulkan drivers matched to the detected GPU (NVIDIA Vulkan comes from nvidia.sh
# via nvidia-utils). Derived from Omarchy install/hardware/vulkan.sh (MIT).
declare -A VULKAN_DRIVERS=(
  [Intel]=vulkan-intel
  [AMD]=vulkan-radeon
  [Apple]=vulkan-asahi
)

PACKAGES=()
for vendor in "${!VULKAN_DRIVERS[@]}"; do
  if lspci | grep -iE "(VGA|Display).*$vendor" >/dev/null; then
    PACKAGES+=("${VULKAN_DRIVERS[$vendor]}")
  fi
done

# `if`, not `((n)) && …`: as the last command that returned 1 with nothing to
# add (a VM, an NVIDIA-only box) and logged a false "vulkan.sh exited non-zero".
if ((${#PACKAGES[@]})); then
  vg_pkg_add "${PACKAGES[@]}"
fi
