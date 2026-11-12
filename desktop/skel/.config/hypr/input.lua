-- VeloGuardOS — input devices. See https://wiki.hypr.land/configuring/core/config-options/#input
-- Derived from Omarchy config/hypr/input.conf (MIT).
hl.config({
  input = {
    -- The keyboard layout comes from the system setting (the installer's
    -- Keyboard page; change it with `sudo localectl set-x11-keymap us,bg`).
    -- To override it here, e.g. two layouts switched with both Alt keys:
    -- kb_layout = "us,bg",
    -- kb_options = "grp:alts_toggle,compose:caps",
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
