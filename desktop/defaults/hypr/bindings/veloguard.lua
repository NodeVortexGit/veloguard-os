-- VeloGuardOS additions to the default bindings — Lua port of veloguard.conf.
hl.bind("SUPER + SHIFT + G", hl.dsp.exec_cmd("veloguard-guard-menu"),     { description = "Guard menu" })
-- The same menu (the bar's top-left 󰒃 button) on a tap of Super+Ctrl, either order;
-- tap again to close. On release, so Super+Ctrl+L / +V / +Backspace keep working.
for _, key in ipairs({ "SUPER + CTRL + Control_L", "SUPER + CTRL + Super_L" }) do
    hl.bind(key, hl.dsp.exec_cmd("pkill -x wofi || veloguard-guard-menu"),
            { release = true, description = "VeloGuard search menu" })
end
hl.bind("SUPER + SHIFT + V", hl.dsp.exec_cmd("veloguard-guard-menu vpn"), { description = "VPN" })
hl.bind("SUPER + SHIFT + A", hl.dsp.exec_cmd("veloguard-agent"),          { description = "AI agent" })
hl.bind("SUPER + SHIFT + E", hl.dsp.exec_cmd("veloguard-agent ask"),      { description = "Ask an AI agent about an error" })
hl.bind("SUPER + ESCAPE",    hl.dsp.exec_cmd("veloguard-powermenu"),      { description = "Power menu" })
hl.bind("XF86PowerOff",      hl.dsp.exec_cmd("veloguard-powermenu"),      { locked = true })

-- Volume, microphone and brightness keys with on-screen feedback: a frosted bar
-- near the bottom (swayosd, via veloguard-osd — plain wpctl/brightnessctl if
-- the pop-up isn't running). Work on the lock screen; repeat when held.
local function rebind(k, dsp, opts) pcall(hl.unbind, k); hl.bind(k, dsp, opts) end
local osd = { locked = true, repeating = true }
rebind("XF86AudioRaiseVolume",  hl.dsp.exec_cmd("veloguard-osd volume up"), osd)
rebind("XF86AudioLowerVolume",  hl.dsp.exec_cmd("veloguard-osd volume down"), osd)
rebind("XF86AudioMute",         hl.dsp.exec_cmd("veloguard-osd volume mute"), { locked = true })
rebind("XF86AudioMicMute",      hl.dsp.exec_cmd("veloguard-osd mic mute"), { locked = true })
rebind("XF86MonBrightnessUp",   hl.dsp.exec_cmd("veloguard-osd brightness up"), osd)
rebind("XF86MonBrightnessDown", hl.dsp.exec_cmd("veloguard-osd brightness down"), osd)
hl.bind("SUPER + SHIFT + T", hl.dsp.exec_cmd("veloguard-theme menu"),     { description = "Theme" })
hl.bind("SUPER + SHIFT + SPACE", hl.dsp.exec_cmd("pkill -SIGUSR1 waybar"), { description = "Toggle top bar" })
hl.bind("SUPER + CTRL + L",  hl.dsp.exec_cmd("loginctl lock-session"),    { description = "Lock" })
hl.bind("SUPER + CTRL + V",  hl.dsp.exec_cmd("veloguard-session clipboard"),
        { description = "Clipboard history" })
hl.bind("PRINT",         hl.dsp.exec_cmd('grim -g "$(slurp)" - | wl-copy && notify-send -u low "Screenshot copied"'))
hl.bind("SHIFT + PRINT", hl.dsp.exec_cmd('grim - | wl-copy && notify-send -u low "Screenshot copied"'))
hl.bind("SUPER + PRINT", hl.dsp.exec_cmd("pkill hyprpicker || hyprpicker -a"), { description = "Colour picker" })
hl.bind("SUPER + SHIFT + BACKSPACE", hl.dsp.exec_cmd("makoctl dismiss --all"))
hl.bind("SUPER + CTRL + BACKSPACE",  hl.dsp.exec_cmd("makoctl mode -t do-not-disturb"))
