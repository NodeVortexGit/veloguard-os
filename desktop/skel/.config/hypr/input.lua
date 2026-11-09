-- VeloGuardOS — input devices. See https://wiki.hypr.land/configuring/core/config-options/#input
-- Derived from Omarchy config/hypr/input.conf (MIT).
hl.config({
  input = {
    -- Multiple layouts switchable with Left Alt + Right Alt:
    -- kb_layout = "us,bg",
    -- kb_options = "grp:alts_toggle,compose:caps",
    kb_options = "compose:caps",
    repeat_rate = 40,
    repeat_delay = 250,
    numlock_by_default = true,
    touchpad = {
      clickfinger_behavior = true,
      scroll_factor = 0.4,
    },
  },
})

-- Scroll nicely in the terminal
hl.window_rule({
  name = "terminal-touchpad-scroll",
  match = { class = "(Alacritty|kitty|foot)" },
  scroll_touchpad = 1.5,
})
