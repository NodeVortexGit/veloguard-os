-- VeloGuardOS — Hyprland entry config. Lua: Hyprland 0.55 and later (0.57
-- dropped hyprland.conf and reads only this file). Derived from Omarchy
-- config/hypr/hyprland.conf (MIT).
-- Learn how to configure Hyprland: https://wiki.hypr.land/configuring/

-- ── VeloGuardOS defaults (shipped, read-only — do not edit those files) ────
-- Environment, autostart, look'n'feel, window rules, the default + VeloGuard
-- keybindings, the NVIDIA env on NVIDIA machines and the active theme's colours.
dofile("/usr/share/veloguard/desktop/hypr/init.lua")

-- ── Your personal settings (edit these; they load last, so they win) ───────
local here = (os.getenv("XDG_CONFIG_HOME") or ((os.getenv("HOME") or "") .. "/.config")) .. "/hypr/"
for _, name in ipairs({ "monitors", "input", "bindings", "looknfeel", "autostart" }) do
  local path = here .. name .. ".lua"
  local f = io.open(path, "r")
  if f then f:close(); dofile(path) end
end

-- Add any other personal Hyprland configuration below, e.g.:
-- hl.window_rule({ name = "qemu-on-5", match = { class = "qemu" }, workspace = "5" })
