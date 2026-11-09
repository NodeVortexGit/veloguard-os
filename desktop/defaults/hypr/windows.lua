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

-- Apply default opacity after apps have had a chance to opt out
hl.window_rule({
  name = "default-opacity",
  match = { tag = "default-opacity" },
  opacity = "0.985 0.96",
})
