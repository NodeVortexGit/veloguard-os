# VeloGuardOS ISO — live USB (archiso)

Builds a **live, bootable, mutable** VeloGuardOS ISO — boot it or `dd` it to a
USB stick and it runs live, with an "Install to Disk" option. Built by
[`build.sh`](build.sh), which layers our overlay on top of archiso's official
`releng` profile (so the BIOS+UEFI boot configs are always correct).

## What's in it

- Arch base + an **Omarchy-derived Hyprland desktop on Wayland + PipeWire**
  (Waybar, mako, wofi, SDDM autologin → Hyprland via uwsm), NetworkManager.
  The desktop is vendored hermetically from `desktop/` (official Arch repos
  only, no AUR); see [`desktop/README.md`](../desktop/README.md).
- The **VeloGuard guard** at `/opt/veloguard` with `veloguard`, `veloguard-vpn`,
  `veloguard-update`, `veloguard-install`, `veloguard-bulgarian-mode` on `PATH`.
- Security stack: `nftables`, `wireguard-tools`, `bubblewrap`, `tor`.
- `flatpak`, `mpv`/`ffmpeg`, broad filesystem tools.
- **Updater baked in**: `veloguard-update.timer` is enabled (signed, fail-closed;
  stays quiet until you add your release key — see `veloguard/keys/SIGNING.md`).
- Bulgarian Mode assets at `/opt/Bulgarian_Mode` + its launcher. 🇧🇬
- **Install VeloGuardOS** launcher → **Calamares**, the one installer
  (archinstall is gone). Beyond the stock pages it adds a **Desktop** page —
  Clean Config (NodeVortex's Hyprland rice, installed exactly as published,
  pre-selected on laptops), VeloGuard Hyprland, GNOME, Xfce, niri, i3, COSMIC,
  or **Headless** (no desktop: text login, desktop stack removed; the guard,
  VPN, drivers and Ollama stay). The installer wears the default VeloGuard
  theme (navy + cyan). During installation it probes every
  component (`veloguard-hwprobe`) and installs its drivers: NVIDIA (open/
  legacy, DKMS for every kernel), Vulkan, VA-API, Broadcom `wl`, Bluetooth,
  and on laptops power-profiles/thermald/sensors/fingerprint/Thunderbolt and
  NVIDIA PRIME power management. Offline installs still work: VeloGuard
  Hyprland is on the disc, and the drivers + chosen desktop finish on the
  first online boot (`veloguard-hardware.service`).

## Build it

In CI: push a `v*` tag → `.github/workflows/build-iso.yml` builds it and attaches
the `.iso` to a Release. Locally, on Arch or in an Arch container (as root):

```bash
pacman -Sy --needed archiso
OUT=./out WORK=./work bash iso/build.sh        # → ./out/veloguardos-*.iso

# from any distro with podman/docker:
podman run --rm --privileged -v "$PWD":/repo -w /repo archlinux:latest \
  bash -c 'pacman -Sy --noconfirm archiso && OUT=/repo/out WORK=/repo/work bash iso/build.sh'
```

Write it to a USB stick (this erases the stick):

```bash
sudo dd if=out/veloguardos-*.iso of=/dev/sdX bs=4M status=progress oflag=sync
```

## The custom kernel (upgrade path)

The ISO uses Arch's `linux` for a guaranteed-bootable base. To run the
**VeloGuardOS kernel** (Linus's tree + `veloguard/kernel/*.config`), build it and
install it on top — a `linux-veloguard` package + CI job is the clean next step.
