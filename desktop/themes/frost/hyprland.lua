-- Frost theme — Hyprland: a thin dark-blue edge, frosted glass everywhere.
local active = { colors = { "rgba(3b5bd9ee)", "rgba(2e49aeee)" }, angle = 45 }
local inactive = "rgba(12121aaa)"
hl.config({
  general = { gaps_in = 0, gaps_out = 0, border_size = 1,
              col = { active_border = active, inactive_border = inactive } },
  decoration = {
    rounding = 0,                 -- no gaps → square corners (rounded ones leave slivers)
    active_opacity = 0.88,
    inactive_opacity = 0.80,
    fullscreen_opacity = 1.0,
    dim_inactive = false,
    shadow = { enabled = false },
    blur = {
      enabled = true, size = 8, passes = 3, vibrancy = 0.22, vibrancy_darkness = 0.4,
      noise = 0.012, contrast = 1.0, brightness = 0.85, new_optimizations = true,
      ignore_opacity = true, xray = false, popups = true, special = true,
    },
  },
  group = { col = { border_active = active, border_inactive = inactive,
                    border_locked_active = active, border_locked_inactive = inactive } },
})
