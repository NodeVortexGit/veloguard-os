# VeloGuardOS on COSMIC

Copied into `~/.config/cosmic/` the first time an account uses COSMIC
(`veloguard-desktop-setup`), never over a file that is already there:

| File | What it does |
|---|---|
| `com.system76.CosmicPanel/v1/entries` | Only the dock: VeloGuard's top bar (Waybar, `/usr/share/veloguard/desktop/waybar/cosmic.jsonc`) takes the top panel's place |
| `com.system76.CosmicPanel.Dock/v1/plugins_wings` | COSMIC's notification bell on the dock's right |
| `com.system76.CosmicSettings.Shortcuts/v1/custom` | VeloGuard's keys (Settings → Keyboard → Shortcuts → Custom lists them) |
| `com.system76.CosmicBackground/v1/all` | The VeloGuard wallpaper |

To get COSMIC's own top panel back: Settings → Desktop → Panel, or
`rm ~/.config/cosmic/com.system76.CosmicPanel/v1/entries` and log in again
(then remove `veloguard-desktop.desktop` from Settings → Applications →
Startup Applications if you don't want VeloGuard's bar as well).
