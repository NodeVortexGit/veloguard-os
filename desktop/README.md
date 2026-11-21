# VeloGuardOS desktop layer (Omarchy-style Hyprland)

This directory is the VeloGuardOS **desktop**: an Omarchy-derived Hyprland
(Wayland tiling) environment, re-branded and made **self-contained** so the ISO
builds hermetically from official Arch repos. It replaces the old GNOME/GDM
desktop while the VeloGuard **guard** (kernel, `guardd`, VPN, honeypot, updater,
installer) is unchanged and is wired into the desktop.

Derived from Omarchy (MIT, © David Heinemeier Hansson / 37signals). See
[`omarchy/OMARCHY-LICENSE`](omarchy/OMARCHY-LICENSE) and
[`omarchy/PROVENANCE.md`](omarchy/PROVENANCE.md).

## Layout

| Path | Installed to | What it is |
|---|---|---|
| `defaults/hypr/` | `/usr/share/veloguard/desktop/hypr/` | Shipped Hyprland defaults (envs, autostart, look'n'feel, window rules, keybindings). Read-only. |
| `skel/.config/` | `/etc/skel/.config/` → every user's `~/.config` | Per-user configs: Hyprland entry + overrides, Waybar, mako, wofi, alacritty, hyprlock, hypridle. |
| `themes/<name>/` | `/usr/share/veloguard/themes/<name>/` | Themes (colors for Hyprland/Waybar/mako/alacritty/hyprlock). Default: `veloguard`. |
| `hardware/` | `/usr/share/veloguard/hardware/` | Omarchy-derived driver/hardware setup, run once at first boot (see below). |
| `agents/` | `/usr/share/veloguard/agents/` | Agent plugin: MCP config + skill for driving the guard (see below). |
| `bin/` | `/usr/local/bin/` | Guard↔desktop helpers (see below). |
| `packages.desktop` | — | The desktop package set (official repos only). |

## Keybindings — stock Hyprland defaults

By request, VeloGuardOS uses the **default Hyprland keybindings** (not Omarchy's):
`defaults/hypr/bindings/hyprland-default.lua` (SUPER+Q terminal, SUPER+C close,
SUPER+E files, SUPER+R launcher, SUPER+V float, SUPER 1-0 workspaces, …). Only
the app variables point at VeloGuard's shipped apps. Omarchy's **look & feel**
(gaps/blur/animations, Waybar, mako, theming) is kept. VeloGuard's own additions
live in `veloguard.lua`, all under SUPER+SHIFT / SUPER+CTRL so they never
clobber a default.

## Hyprland config is Lua

Hyprland 0.57 removed `hyprland.conf`: it reads only `~/.config/hypr/hyprland.lua`
(Lua configs work since 0.55). VeloGuard's Hyprland config is Lua:

- `defaults/hypr/init.lua` loads the shipped defaults (`envs`, `autostart`,
  `looknfeel`, `windows`, `bindings/*`, the NVIDIA env when present, the active
  theme's `hyprland.lua`); `skel/.config/hypr/hyprland.lua` loads that, then the
  user's own `monitors/input/bindings/looknfeel/autostart.lua`, which win.
- The `*.conf` twins stay for accounts that still `source` them;
  `defaults/hypr/legacy-skel/` keeps the old per-user `.conf` files so
  `veloguard-hypr-migrate` can tell a user's own changes from VeloGuard's.
- `veloguard-hypr-migrate` moves `.conf` accounts to Lua, converting the usual
  personal settings (monitors, input/keyboard layout, `bind`/`unbind` with
  `exec`, `exec-once`, simple looks) and listing what it couldn't in
  `~/.config/hypr/MIGRATED-FROM-CONF.txt`. A pacman hook runs it whenever
  Hyprland is installed or upgraded.
- `hyprctl dispatch` takes Lua since 0.57 (`hl.dsp.exit()`), so scripts go
  through `veloguard-hypr dpms on|off|toggle` / `veloguard-hypr exit`.

## Hardware / drivers (Omarchy-derived)

`hardware/all.sh` runs once on **first boot** (`veloguard-hardware.service`) and
installs the drivers this machine actually needs — NVIDIA (matched to GPU gen),
Vulkan (Intel/AMD), Broadcom Wi-Fi, Bluetooth, wireless reg-domain, F-keys,
Synaptics touchpad — then regenerates the initramfs. Re-run any time with
`sudo veloguard-hardware`. Derived from Omarchy's `install/hardware/` with its
`omarchy-*` helpers reimplemented self-contained (`hardware/lib.sh`).

## AI agent plugin

`veloguard-agent` launches VeloGuard's guarded autonomous agent Omarchy-style
(`Super+Shift+A`, or the guard menu → "AI agent…"). Two brains, both restored in
the guard (`veloguard/guardd/ai_adapter.py`): **claude** (API) and **ollama**
(local). Everything the agent does still goes through the guard. External coding
agents (Claude Code, Codex) can drive the guard over MCP — see `agents/`.

## Guard ↔ desktop integration

The old GNOME Shell extension's behavior is ported to Hyprland/Waybar:

| Helper | Role |
|---|---|
| `veloguard-waybar-guard` | Waybar `custom/guard` module — read-only VPN / Wi-Fi-trust / staged-update / guard status, color-coded. |
| `veloguard-guard-menu` | `wofi` menu → VPN connect/import/Tor, Wi-Fi trust toggle, Bulgarian Mode. Wraps the existing `veloguard-vpn`, `veloguard-wifi-trust`, `veloguard-bulgarian-mode` helpers (polkit rules unchanged). |
| `veloguard-powermenu` | Power menu incl. **Reboot & Update** → `veloguard-arm-offline-update`. |
| `veloguard-theme` | Theme switcher (relinks `~/.config/veloguard/current`, live-reloads the session). |
| `veloguard-agent` | Launch the guarded autonomous agent (claude/ollama), Omarchy-style. |
| `veloguard-hardware` | Run the Omarchy-derived driver/hardware setup. |
| `veloguard-firstboot-desktop` | Runs `veloguard setup` once on first graphical login. |

VeloGuard keybindings (added on top of the Hyprland defaults): `Super+Shift+G`
guard menu · `Super+Shift+V` VPN · `Super+Shift+A` agent · `Super+Escape` power
menu · `Super+Shift+T` theme. Full set in `defaults/hypr/bindings/`.

## Every desktop gets the same buttons

The installer's Desktop page offers more than VeloGuard Hyprland. Whichever is
picked, it gets VeloGuard's buttons — the same set as the Hyprland bar: the
guard menu (󰒃), AI plan usage, the guard's state (VPN / network trust /
staged update / root grant), keyboard layout, Wi-Fi, Bluetooth, volume,
brightness, power profile, battery + power menu, tray, notifications, and the
quick panel (󰒓) — plus VeloGuard's keys and the active theme's colours.

| Desktop | Bar | Quick panel | Menus | Notifications | Config (per account) |
|---|---|---|---|---|---|
| VeloGuard Hyprland | Waybar | Quickshell | wofi | swaync | `~/.config/hypr`, `~/.config/waybar` |
| niri | Waybar (`defaults/waybar/niri.jsonc`) | Quickshell | wofi | swaync | `~/.config/niri/config.kdl` |
| COSMIC | Waybar (`defaults/waybar/cosmic.jsonc`) in place of COSMIC's top panel; the dock stays | Quickshell | wofi | COSMIC's (bell on the dock) | `~/.config/cosmic/…` |
| i3 | polybar (`defaults/polybar`) | Quickshell (X11) | rofi | dunst | `~/.config/i3/config`, `~/.config/polybar` |
| Xfce | the Xfce panel, VeloGuard buttons as Generic Monitor plugins | Quickshell (X11) | rofi | xfce4-notifyd | xfconf (`defaults/xfce`) |
| GNOME | GNOME's top bar + the VeloGuard Shell extension | GNOME's quick settings (+ VPN, Trusted, Bulgarian Mode) | zenity / the extension's menus | GNOME's | system dconf (`defaults/gnome`) |
| Clean Config | kept exactly as published | its own island panel, with VeloGuard's buttons fitted in (VPN, Trusted, Guard, AI agent, AI usage — `veloguard-clean-config-buttons`) | wofi | its own | the Clean Config repo |

What makes that possible:

| Helper | Role |
|---|---|
| `veloguard-dmenu` | One menu for every desktop: wofi (Wayland), rofi (X11), zenity (GNOME). Every VeloGuard menu goes through it. |
| `veloguard-session` | The session actions each desktop does its own way: log out, lock, screens off, next keyboard layout, screenshot, night light, do not disturb, notifications, clipboard history, show/hide the bar, wallpaper. |
| `veloguard-bar` | The bar's status buttons for polybar and Xfce's Generic Monitor (and Clean Config's panel): the guard, AI usage, Bluetooth, network, power profile, brightness, the bell. Escapes what it shows (the guard's tooltip carries the Wi-Fi's name). |
| `veloguard-desktop-autostart` | Starts the VeloGuard session on niri, COSMIC, i3, Xfce and GNOME. |
| `veloguard-desktop-setup` | Puts a desktop's VeloGuard configs into an account (the installer runs it; files already there are kept). |
| `veloguard-polybar` | polybar on i3, with this machine's battery / Wi-Fi filled in. |

Changing your mind later: `sudo calamares-desktop.sh <desktop> <you>` installs
another desktop with its VeloGuard rice; pick it at the login screen.

## Theming

A theme is a directory of color files under `/usr/share/veloguard/themes/`. The
active theme is the symlink `~/.config/veloguard/current`; every desktop config
sources its colors *through* that symlink, so switching is a relink + reload.
Configs that can't read Waybar's CSS (rofi, polybar, dunst, i3, niri) include
colour files that `veloguard-theme` writes into `~/.config/veloguard/generated`
from the theme's `waybar.css` palette:

```bash
veloguard-theme list          # frost, veloguard, tokyo-night, catppuccin
veloguard-theme set tokyo-night
veloguard-theme menu          # pick with wofi (Super+Shift+Ctrl+Space)
```

## Not vendored

Omarchy's installer, its `omarchy-*` helper scripts, `omarchy-menu`/walker,
web-app launchers, and branding assets are **not** included — VeloGuardOS ships
its own guard-integrated equivalents from official-repo tools only.
