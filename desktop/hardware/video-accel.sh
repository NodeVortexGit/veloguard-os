#!/usr/bin/env bash
# Hardware video decode/encode (VA-API) for the detected GPU(s). AMD needs
# nothing extra — Mesa itself carries the radeonsi VA-API driver now (the old
# libva-mesa-driver/mesa-vdpau packages were folded into mesa). NVIDIA's
# VA-API bridge comes with nvidia.sh.
pkgs=(libva-utils)                                  # vainfo, to check it works
# iHD covers Broadwell and newer; i965 the older Intel iGPUs.
[ "${VG_HW_gpu_intel:-0}" = 1 ] && pkgs+=(intel-media-driver libva-intel-driver)
vg_pkg_add "${pkgs[@]}"
