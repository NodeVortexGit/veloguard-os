-- catppuccin theme — Hyprland border colours (Lua twin of hyprland.conf here;
-- loaded by /usr/share/veloguard/desktop/hypr/init.lua through the
-- ~/.config/veloguard/current symlink that veloguard-theme switches).
local active = { colors = { "rgba(89b4faee)", "rgba(cba6f7ee)" }, angle = 45 }
local inactive = "rgba(45475aaa)"
hl.config({
  general = { col = { active_border = active, inactive_border = inactive } },
  group = {
    col = {
      border_active = active,
      border_inactive = inactive,
      border_locked_active = active,
      border_locked_inactive = inactive,
    },
  },
})
