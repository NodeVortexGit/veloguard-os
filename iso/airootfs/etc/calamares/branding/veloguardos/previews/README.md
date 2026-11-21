# Desktop previews (installer → "Choose your desktop")

Real screenshots of each choice as a **fresh VeloGuardOS account sees it at
first login**: the packages `calamares-desktop.sh` installs for that choice,
the VeloGuard `/etc/skel` (Waybar, Alacritty and wofi configs, the Frost theme
link) and that desktop's VeloGuard rice (`veloguard-desktop-setup`: the same
buttons as VeloGuard Hyprland, see `desktop/README.md`). 1280×800 (16:10, the
preview pane's shape), JPEG with 4:4:4 chroma so terminal text stays sharp.

`veloguarddesktop.qml` shows `previews/<key>.jpg` for the selected choice and
falls back to the drawn schematic in `DesktopPreview.qml` when a file is
missing, so a desktop without a screenshot never shows a broken image (still
drawn for now: Clean Config — it can't be built in the capture VM; a
screenshot of the real rice belongs here).

| file | how it was captured |
|------|---------------------|
| `hyprland.jpg` | installed VeloGuardOS VM (QEMU, KMS), Hyprland 0.57.2: a headless install with VeloGuard Hyprland added later (`calamares-desktop.sh hyprland`), SDDM login, two terminals |
| `i3.jpg` | same VM, `calamares-desktop.sh i3`, SDDM login (real Xorg); i3's first-run config wizard answered with its defaults (Enter, Enter); three terminals opened through i3 |
| `gnome.jpg` | Arch build chroot, GNOME Shell 51 `--headless` (software rendering) with the VeloGuard Shell extension and dconf defaults, first-login overview |
| `xfce.jpg` | Arch build chroot, Xvfb + `startxfce4` with the VeloGuard panel, a Thunar window opened |
| `niri.jpg` | Arch build chroot, niri nested on Xvfb with VeloGuard's Waybar, two terminals |
| `cosmic.jpg` | Arch build chroot, `cosmic-session` nested on Xvfb (COSMIC 1.11): VeloGuard's Waybar in place of COSMIC's top panel, the dock |
| `headless.jpg` | the installed headless VM's tty1 with the SSH link connected; top-left region zoomed so the text is legible at preview size |

Test-rig adjustments (so the picture matches a real install, not the rig):
account `user`, hostname `veloguard` (its own UTS namespace); the first-login
`veloguard setup` terminal closed; GNOME: logind mocked (python-dbusmock, the
chroot has no systemd) and its one-time "Screen Lock disabled" notice marked
seen — a real GNOME install runs GDM, which has the lock screen; COSMIC: the
VeloGuard autostart started by hand (on a real login systemd's XDG autostart
does it).

## Credits

The desktops shown are free software under their own licences (GNOME Shell
GPL-3.0+, Xfce GPL-2.0+/LGPL-2.1, niri GPL-3.0+, i3 BSD, COSMIC GPL-3.0,
Hyprland BSD-3-Clause, Waybar MIT, polybar MIT, Alacritty Apache-2.0/MIT).
Wallpaper visible: the VeloGuardOS default wallpaper — this repository
(`iso/airootfs/usr/share/backgrounds/veloguard/default.png`).

Retake a screenshot when that desktop's look changes (new upstream release,
a change to what `calamares-desktop.sh` installs, or to its VeloGuard rice).
