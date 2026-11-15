-- VeloGuardOS window rules — Lua port of windows.conf (derived from Omarchy
-- default/hypr/windows.conf, MIT). Order matters: the opacity rule matches the
-- tag the second rule sets, so it stays last.
hl.window_rule({
  name = "suppress-maximize-events",
  match = { class = ".*" },
  suppress_event = "maximize",
})

-- Tag all windows for default opacity (apps can override via the -default-opacity tag)
hl.window_rule({
  name = "tag-default-opacity",
  match = { class = ".*" },
  tag = "+default-opacity",
})

-- Fix some dragging issues with XWayland
hl.window_rule({
  name = "fix-xwayland-drags",
  match = { class = "^$", title = "^$", xwayland = true, float = true, fullscreen = false, pin = false },
  no_focus = true,
})

-- Float VeloGuard helper dialogs (VPN import, power menu, guard menu use wofi/zenity)
hl.window_rule({
  name = "float-gtk-portal",
  match = { class = "^(org.freedesktop.impl.portal.desktop.gtk)$" },
  float = true,
})
hl.window_rule({
  name = "float-zenity",
  match = { class = "^(zenity)$" },
  float = true,
  center = true,
})

-- The installer (live ISO): a fixed-size 980x660 window. Tiled next to another
-- window it got half the screen and its pages were clipped.
hl.window_rule({
  name = "float-installer",
  match = { class = "^(io.calamares.calamares)$" },
  float = true,
  center = true,
})

-- Media and games are never frosted: video under glass is unwatchable.
hl.window_rule({
  name = "opaque-media",
  match = { class = "^(mpv|vlc|org.videolan.VLC|imv|swayimg|org.gnome.Loupe|steam_app_.*|gamescope|com.obsproject.Studio|zoom|org.kde.gwenview)$" },
  opacity = "1.0 override 1.0 override",
  tag = "-default-opacity",
})

-- Default opacity after apps have had a chance to opt out. Neutral here: the
-- glass level is the theme's (decoration.active/inactive_opacity).
hl.window_rule({
  name = "default-opacity",
  match = { tag = "default-opacity" },
  opacity = "1.0 1.0",
})

-- Frosted layers: the bar, the quick panel and notifications (swaync), the
-- launcher (Albert), wofi menus and the lock screen blur what's behind them.
for _, ns in ipairs({ "waybar", "swaync-control-center", "swaync-notification-window",
                      "albert", "wofi", "notifications", "logout_dialog" }) do
  hl.layer_rule({ name = "frost-" .. ns, match = { namespace = ns }, blur = true, ignore_alpha = 0.15 })
end

-- Screen capture, allowed for the tools that are meant to (enforce_permissions
-- is on in looknfeel.lua: anything else asks).
for _, bin in ipairs({ "/usr/bin/grim", "/usr/bin/hyprpicker", "/usr/bin/wf-recorder",
                       "/usr/lib/xdg-desktop-portal-hyprland", "/usr/bin/hyprlock", "/usr/bin/obs" }) do
  hl.permission({ binary = bin, type = "screencopy", mode = "allow" })
end
