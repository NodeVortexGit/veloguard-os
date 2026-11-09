-- VeloGuardOS environment — Lua port of envs.conf (derived from Omarchy
-- default/hypr/envs.conf, MIT; see desktop/omarchy/PROVENANCE.md).
local home = os.getenv("HOME") or ""

-- Theme-provided gum styling env. The theme keeps one file for both config
-- formats (`env = NAME,VALUE` lines), read here; a missing file is fine.
local gum = io.open(home .. "/.config/veloguard/current/gum.env.conf", "r")
if gum then
  for line in gum:lines() do
    local name, value = line:match("^%s*env%s*=%s*([%w_]+)%s*,%s*(.-)%s*$")
    if name then hl.env(name, value) end
  end
  gum:close()
end

-- Cursor size
hl.env("XCURSOR_SIZE", "24")
hl.env("HYPRCURSOR_SIZE", "24")

-- Force all apps to use Wayland where possible
hl.env("GDK_BACKEND", "wayland,x11,*")
hl.env("QT_QPA_PLATFORM", "wayland;xcb")
hl.env("QT_STYLE_OVERRIDE", "kvantum")
hl.env("MOZ_ENABLE_WAYLAND", "1")
hl.env("ELECTRON_OZONE_PLATFORM_HINT", "wayland")
hl.env("OZONE_PLATFORM", "wayland")
hl.env("XDG_SESSION_TYPE", "wayland")

-- Screen-sharing support (portals)
hl.env("XDG_CURRENT_DESKTOP", "Hyprland")
hl.env("XDG_SESSION_DESKTOP", "Hyprland")

hl.env("XCOMPOSEFILE", home .. "/.XCompose")

hl.config({
  xwayland = { force_zero_scaling = true },
  ecosystem = { no_update_news = true },
})
