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
  hl.exec_cmd("veloguard-session-start mako")
  hl.exec_cmd("veloguard-session-start waybar")
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
