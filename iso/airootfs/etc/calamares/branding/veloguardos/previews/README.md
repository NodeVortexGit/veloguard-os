# Desktop previews (installer → "Choose your desktop")

Real screenshots of each choice as a **fresh VeloGuardOS account sees it at
first login**: the packages `calamares-desktop.sh` installs for that choice,
the VeloGuard `/etc/skel` (Waybar, Alacritty and mako configs, theme link),
stock everything else. 1280×800 (16:10, the preview pane's shape), JPEG with
4:4:4 chroma so terminal text stays sharp.

`veloguarddesktop.qml` shows `previews/<key>.jpg` for the selected choice and
falls back to the drawn schematic in `DesktopPreview.qml` when a file is
missing, so a desktop without a screenshot never shows a broken image (still
drawn for now: Clean Config, i3, COSMIC).

| file | how it was captured |
|------|---------------------|
| `hyprland.jpg` | installed VeloGuardOS VM (QEMU, KMS), Hyprland 0.57.2: a headless install with VeloGuard Hyprland added later (`calamares-desktop.sh hyprland`), SDDM login, two terminals |
| `gnome.jpg` | Arch build chroot, `gnome-shell --headless` (software rendering), first-login overview |
| `xfce.jpg` | Arch build chroot, Xvfb + `startxfce4`, a Thunar window opened |
| `niri.jpg` | Arch build chroot, niri nested on Xvfb, two terminals (Super+T) |
| `headless.jpg` | the installed headless VM's tty1 with the SSH link connected; top-left region zoomed so the text is legible at preview size |

Test-rig adjustments (so the picture matches a real install, not the rig):
GNOME's "unsafe mode" panel icon hidden (the flag only enabled the screenshot
call); niri run with `mod-key-nested "Super"` (nested niri switches to Alt;
on hardware it is Super) and its first-start hotkey overlay already dismissed;
hostname `veloguard`, account `user`.

## Credits

The desktops shown are free software under their own licences (GNOME Shell
GPL-3.0+, Xfce GPL-2.0+/LGPL-2.1, niri GPL-3.0+, i3 BSD, COSMIC GPL-3.0,
Hyprland BSD-3-Clause, Alacritty Apache-2.0/MIT). Wallpapers visible:

- GNOME default background — GNOME Project, `gnome-backgrounds`, CC BY-SA 3.0.
- Xfce default backdrop — Xfce Project, `xfdesktop`, GPL-2.0-or-later.
- COSMIC default background "Orion Nebula" (heic0601a) — NASA, ESA,
  M. Robberto (STScI/ESA) and the Hubble Space Telescope Orion Treasury
  Project Team, CC BY 4.0, via `cosmic-wallpapers`.
- VeloGuardOS default wallpaper — this repository
  (`iso/airootfs/usr/share/backgrounds/veloguard/default.png`).

Retake a screenshot when that desktop's look changes (new upstream release
or a change to what `calamares-desktop.sh` installs).
