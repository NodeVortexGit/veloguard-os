-- VeloGuardOS — Hyprland's stock default keybindings, Lua port of
-- hyprland-default.conf. Change them in ~/.config/hypr/bindings.lua:
--   hl.unbind("SUPER + Q")
--   hl.bind("SUPER + Q", hl.dsp.exec_cmd("kitty"))
local mainMod = "SUPER"
local terminal = "alacritty"
local fileManager = "thunar"
local menu = "wofi --show drun"

local function key(k) return mainMod .. " + " .. k end

hl.bind(key("Q"), hl.dsp.exec_cmd(terminal), { description = "Terminal" })
hl.bind(key("C"), hl.dsp.window.close(), { description = "Close window" })
hl.bind(key("M"), hl.dsp.exit(), { description = "Exit Hyprland" })
hl.bind(key("E"), hl.dsp.exec_cmd(fileManager), { description = "File manager" })
hl.bind(key("V"), hl.dsp.window.float({ action = "toggle" }), { description = "Toggle floating" })
hl.bind(key("R"), hl.dsp.exec_cmd(menu), { description = "App launcher" })
hl.bind(key("P"), hl.dsp.window.pseudo())                     -- dwindle
hl.bind(key("J"), hl.dsp.layout("togglesplit"))               -- dwindle

-- Move focus with mainMod + arrow keys
hl.bind(key("left"),  hl.dsp.focus({ direction = "left" }))
hl.bind(key("right"), hl.dsp.focus({ direction = "right" }))
hl.bind(key("up"),    hl.dsp.focus({ direction = "up" }))
hl.bind(key("down"),  hl.dsp.focus({ direction = "down" }))

-- Switch workspaces with mainMod + [0-9]; move the window with mainMod + SHIFT + [0-9]
for i = 1, 10 do
  local k = tostring(i % 10)   -- workspace 10 is the 0 key
  hl.bind(key(k), hl.dsp.focus({ workspace = i }))
  hl.bind(key("SHIFT + " .. k), hl.dsp.window.move({ workspace = i }))
end

-- Special workspace (scratchpad)
hl.bind(key("S"), hl.dsp.workspace.toggle_special("magic"))
hl.bind(key("SHIFT + S"), hl.dsp.window.move({ workspace = "special:magic" }))

-- Scroll through existing workspaces with mainMod + scroll
hl.bind(key("mouse_down"), hl.dsp.focus({ workspace = "e+1" }))
hl.bind(key("mouse_up"),   hl.dsp.focus({ workspace = "e-1" }))

-- Move/resize windows with mainMod + LMB/RMB and dragging
hl.bind(key("mouse:272"), hl.dsp.window.drag(),   { mouse = true })
hl.bind(key("mouse:273"), hl.dsp.window.resize(), { mouse = true })

-- Multimedia keys for volume and LCD brightness (work on the lock screen, repeat)
local media = { locked = true, repeating = true }
hl.bind("XF86AudioRaiseVolume",  hl.dsp.exec_cmd("wpctl set-volume -l 1 @DEFAULT_AUDIO_SINK@ 5%+"), media)
hl.bind("XF86AudioLowerVolume",  hl.dsp.exec_cmd("wpctl set-volume @DEFAULT_AUDIO_SINK@ 5%-"), media)
hl.bind("XF86AudioMute",         hl.dsp.exec_cmd("wpctl set-mute @DEFAULT_AUDIO_SINK@ toggle"), media)
hl.bind("XF86AudioMicMute",      hl.dsp.exec_cmd("wpctl set-mute @DEFAULT_AUDIO_SOURCE@ toggle"), media)
hl.bind("XF86MonBrightnessUp",   hl.dsp.exec_cmd("brightnessctl s 10%+"), media)
hl.bind("XF86MonBrightnessDown", hl.dsp.exec_cmd("brightnessctl s 10%-"), media)

-- Requires playerctl
hl.bind("XF86AudioNext",  hl.dsp.exec_cmd("playerctl next"),       { locked = true })
hl.bind("XF86AudioPause", hl.dsp.exec_cmd("playerctl play-pause"), { locked = true })
hl.bind("XF86AudioPlay",  hl.dsp.exec_cmd("playerctl play-pause"), { locked = true })
hl.bind("XF86AudioPrev",  hl.dsp.exec_cmd("playerctl previous"),   { locked = true })
