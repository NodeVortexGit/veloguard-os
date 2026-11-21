-- VeloGuardOS autostart — Lua port of autostart.conf (derived from Omarchy
-- default/hypr/autostart.conf, MIT). `exec-once` is now a handler for the
-- "hyprland.start" event: it runs once per session, not on config reloads.
hl.on("hyprland.start", function()
  -- Make sure a theme is selected (creates ~/.config/veloguard/current if missing).
  hl.exec_cmd("veloguard-theme ensure")
  -- Core session services (plain launches — VeloGuardOS does not use uwsm)
  hl.exec_cmd("hypridle")
  -- The bar and notifications through veloguard-session-start: their output
  -- goes to the journal, and a crash during login is retried.
  -- Notifications AND the quick panel: swaync (its control centre is the
  -- bar's quick panel). mako stays installed as a fallback, not started.
  hl.exec_cmd("veloguard-session-start swaync")
  hl.exec_cmd("veloguard-session-start waybar")
  -- Albert: the search bar (Super+Alt / Super+R); fcitx5: Japanese input (jp layout)
  hl.exec_cmd("veloguard-session-start albert")
  -- The quick panel (Quickshell) and the volume / brightness pop-up (swayosd)
  hl.exec_cmd("veloguard-session-start qs -c veloguard -n")
  hl.exec_cmd("veloguard-session-start swayosd-server")
  hl.exec_cmd("fcitx5 -d --replace")
  -- Clipboard history (Super+Ctrl+V): nothing recorded it before, so the
  -- history was always empty. Text and images, as they're copied.
  hl.exec_cmd("wl-paste --type text --watch cliphist store")
  hl.exec_cmd("wl-paste --type image --watch cliphist store")
  hl.exec_cmd('swaybg -i "$(veloguard-theme background)" -m fill')
  -- Polkit authentication agent (VPN/import/update flows raise polkit prompts)
  hl.exec_cmd("/usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1")
  -- First-boot: run the guard AI-plane setup wizard once (no-op afterward)
  hl.exec_cmd("veloguard-firstboot-desktop")
  -- Wi-Fi auto-protect through a VPN app (needs the session; no-op otherwise)
  hl.exec_cmd("veloguard-vpn-autoprotect")
  -- Slow-app-launch fix: export the session environment to systemd + D-Bus
  hl.exec_cmd("systemctl --user import-environment $(env | cut -d'=' -f 1)")
  hl.exec_cmd("dbus-update-activation-environment --systemd --all")
end)
