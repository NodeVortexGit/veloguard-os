-- VeloGuardOS — Hyprland defaults, Lua edition (Hyprland 0.55 and later;
-- 0.57 dropped hyprland.conf and reads ONLY Lua). Derived from Omarchy
-- default/hypr (MIT) — see desktop/omarchy/PROVENANCE.md.
--
-- Loaded first by ~/.config/hypr/hyprland.lua. Shipped and read-only: change
-- things in your own ~/.config/hypr/*.lua, which load after this and win.
-- The *.conf files next to this one are the hyprlang equivalent, kept as-is
-- so accounts that still `source` them keep working until they're migrated
-- (veloguard-hypr-migrate).
local dir = "/usr/share/veloguard/desktop/hypr/"
local home = os.getenv("HOME") or ""

-- Optional files may be absent: the NVIDIA env exists only on NVIDIA machines
-- (written by the hardware layer), the theme only once veloguard-theme has
-- picked one. A missing required file is a real error and shows as one.
local function load(path, optional)
  local f = io.open(path, "r")
  if not f then
    if optional then return end
    error("VeloGuardOS: missing " .. path)
  end
  f:close()
  dofile(path)
end

load(dir .. "envs.lua")
load(dir .. "keyboard.lua")   -- the installer's / localectl's keyboard layout
load(dir .. "autostart.lua")
load(dir .. "looknfeel.lua")
load(dir .. "windows.lua")
load(dir .. "bindings/hyprland-default.lua")
load(dir .. "bindings/veloguard.lua")
load(dir .. "nvidia.lua", true)                                  -- NVIDIA session env
load(home .. "/.config/veloguard/current/hyprland.lua", true)     -- active theme colours
