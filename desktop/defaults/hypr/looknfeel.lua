-- VeloGuardOS look & feel — Lua port of looknfeel.conf (derived from Omarchy
-- default/hypr/looknfeel.conf, MIT). Border colours here are fallbacks: the
-- active theme (~/.config/veloguard/current/hyprland.lua) loads later and
-- overrides them, so the WM is themed even before a theme is picked.
local active = { colors = { "rgba(33ccffee)", "rgba(00ff99ee)" }, angle = 45 }
local inactive = "rgba(595959aa)"

hl.config({
  general = {
    -- No gaps (the person's call: they hate gaps). Themes may tint the
    -- border; none bring gaps back.
    gaps_in = 0,
    gaps_out = 0,
    border_size = 1,
    col = { active_border = active, inactive_border = inactive },
    resize_on_border = false,
    allow_tearing = false,
    layout = "dwindle",
  },

  decoration = {
    rounding = 0,
    -- Frosted glass by default: every window translucent over real blur
    -- (the Frost theme goes further). Media and games opt out (windows.lua).
    active_opacity = 0.92,
    inactive_opacity = 0.86,
    fullscreen_opacity = 1.0,
    shadow = { enabled = false },
    blur = {
      enabled = true,
      size = 7,
      passes = 3,
      vibrancy = 0.2,
      noise = 0.012,
      new_optimizations = true,
      ignore_opacity = true,
      xray = false,
      popups = true,
      special = true,
      brightness = 0.85,
      contrast = 1.0,
    },
  },

  -- Zero trust for the screen: a program that wants to capture it (screenshots,
  -- screen sharing, colour pickers) needs permission — the tools below have it,
  -- anything else (an agent included) makes Hyprland itself ask you.
  ecosystem = { enforce_permissions = true, no_update_news = true, no_donation_nag = true },

  group = {
    col = {
      border_active = active,
      border_inactive = inactive,
      border_locked_active = active,
      border_locked_inactive = inactive,
    },
    groupbar = {
      font_size = 12,
      font_family = "monospace",
      font_weight_active = "ultraheavy",
      font_weight_inactive = "normal",
      indicator_height = 0,
      indicator_gap = 5,
      height = 22,
      gaps_in = 5,
      gaps_out = 0,
      text_color = "rgb(ffffff)",
      text_color_inactive = "rgba(ffffff90)",
      col = { active = "rgba(00000040)", inactive = "rgba(00000020)" },
      gradients = true,
      gradient_rounding = 0,
      gradient_round_only_edges = false,
    },
  },

  animations = { enabled = true },

  dwindle = {
    preserve_split = true,   -- you probably want this
    force_split = 2,         -- always split to the right/bottom
  },

  master = { new_status = "master" },

  misc = {
    allow_session_lock_restore = true,
    disable_hyprland_logo = true,
    disable_splash_rendering = true,
    disable_scale_notification = true,
    focus_on_activate = true,
    anr_missed_pings = 3,
    on_focus_under_fullscreen = 1,
  },

  cursor = {
    hide_on_key_press = true,
    warp_on_change_workspace = 1,
  },

  binds = { hide_special_on_workspace_change = true },
})

-- Curves and animations (https://wiki.hypr.land/configuring/core/animations/)
hl.curve("easeOutQuint",   { type = "bezier", points = { { 0.23, 1 },    { 0.32, 1 } } })
hl.curve("easeInOutCubic", { type = "bezier", points = { { 0.65, 0.05 }, { 0.36, 1 } } })
hl.curve("linear",         { type = "bezier", points = { { 0, 0 },       { 1, 1 } } })
hl.curve("almostLinear",   { type = "bezier", points = { { 0.5, 0.5 },   { 0.75, 1.0 } } })
hl.curve("quick",          { type = "bezier", points = { { 0.15, 0 },    { 0.1, 1 } } })

hl.animation({ leaf = "global",           enabled = true,  speed = 10,   bezier = "default" })
hl.animation({ leaf = "border",           enabled = true,  speed = 5.39, bezier = "easeOutQuint" })
hl.animation({ leaf = "windows",          enabled = true,  speed = 3.79, bezier = "easeOutQuint" })
hl.animation({ leaf = "windowsIn",        enabled = true,  speed = 4.1,  bezier = "easeOutQuint", style = "popin 87%" })
hl.animation({ leaf = "windowsOut",       enabled = true,  speed = 1.49, bezier = "linear",       style = "popin 87%" })
hl.animation({ leaf = "fadeIn",           enabled = true,  speed = 1.73, bezier = "almostLinear" })
hl.animation({ leaf = "fadeOut",          enabled = true,  speed = 1.46, bezier = "almostLinear" })
hl.animation({ leaf = "fade",             enabled = true,  speed = 3.03, bezier = "quick" })
hl.animation({ leaf = "layers",           enabled = true,  speed = 3.81, bezier = "easeOutQuint" })
hl.animation({ leaf = "layersIn",         enabled = true,  speed = 4,    bezier = "easeOutQuint", style = "fade" })
hl.animation({ leaf = "layersOut",        enabled = true,  speed = 1.5,  bezier = "linear",       style = "fade" })
hl.animation({ leaf = "fadeLayersIn",     enabled = true,  speed = 1.79, bezier = "almostLinear" })
hl.animation({ leaf = "fadeLayersOut",    enabled = true,  speed = 1.39, bezier = "almostLinear" })
hl.animation({ leaf = "workspaces",       enabled = false, speed = 1,    bezier = "default" })
hl.animation({ leaf = "specialWorkspace", enabled = true,  speed = 3,    bezier = "easeOutQuint", style = "slidevert" })
