-- The person's own key combinations (Clean Config —
-- github.com/NodeVortexGit/Clean_Config_Hyperland), on VeloGuardOS. Loaded
-- after the stock defaults and VeloGuard's additions, so where a key differs
-- these win. Caelestia-shell bindings map to their VeloGuard equivalents:
-- the island/quick panel → the bar's quick panel (swaync), the launcher →
-- Albert, nexus → the AI agent, session → the power menu.
local M = "SUPER"
local function key(k) return M .. " + " .. k end
local function rebind(k, dsp, opts) pcall(hl.unbind, k); hl.bind(k, dsp, opts) end

-- Super alone (on release) toggles the quick panel, Super+Alt the launcher
rebind("SUPER + SUPER_L", hl.dsp.exec_cmd("veloguard-quickpanel"), { release = true, description = "Quick panel" })
rebind(key("ALT_L"),      hl.dsp.exec_cmd("albert toggle"), { description = "Search (Albert)" })
rebind(key("R"),          hl.dsp.exec_cmd("albert toggle"), { description = "Search (Albert)" })
rebind(key("SPACE"),      hl.dsp.exec_cmd("veloguard-switch-layout"), { description = "Keyboard layout (us · bg · jp)" })

rebind(key("SHIFT + Q"),  hl.dsp.window.kill(), { description = "Kill window" })
rebind(key("Q"),          hl.dsp.exec_cmd("veloguard-close-workspace"), { description = "Close every window on this workspace" })
rebind(key("RETURN"),     hl.dsp.exec_cmd("alacritty"), { description = "Terminal" })
rebind(key("E"),          hl.dsp.exec_cmd("flatpak run org.kde.dolphin"), { description = "Files" })
rebind(key("V"),          hl.dsp.window.float({ action = "toggle" }), { description = "Toggle floating" })
rebind(key("P"),          hl.dsp.window.pseudo())
rebind(key("J"),          hl.dsp.layout("togglesplit"))

-- Caelestia shortcuts → VeloGuard
rebind(key("A"),          hl.dsp.exec_cmd("veloguard-agent"), { description = "AI agent" })
rebind(key("TAB"),        hl.dsp.window.cycle_next(), { description = "Next window" })
rebind(key("N"),          hl.dsp.exec_cmd("swaync-client -t -sw"), { description = "Notifications" })
rebind(key("U"),          hl.dsp.exec_cmd("veloguard-quickpanel"), { description = "Quick panel" })
rebind(key("X"),          hl.dsp.exec_cmd("veloguard-powermenu"), { description = "Power menu" })
rebind(key("L"),          hl.dsp.exec_cmd("loginctl lock-session"), { description = "Lock" })
rebind(key("SHIFT + N"),  hl.dsp.exec_cmd("swaync-client -C -sw"), { description = "Clear notifications" })

-- Screenshots
rebind("PRINT",               hl.dsp.exec_cmd('grim -g "$(slurp)" - | wl-copy && notify-send -u low "Screenshot copied"'))
rebind(key("PRINT"),          hl.dsp.exec_cmd('grim - | wl-copy && notify-send -u low "Screenshot copied"'))
rebind("SHIFT + PRINT",       hl.dsp.exec_cmd('f=~/Pictures/Screenshot-$(date +%F-%H%M%S).png; grim -g "$(slurp)" "$f" && notify-send -u low "Saved $f"'))
rebind(key("SHIFT + PRINT"),  hl.dsp.exec_cmd('f=~/Pictures/Screenshot-$(date +%F-%H%M%S).png; grim "$f" && notify-send -u low "Saved $f"'))
