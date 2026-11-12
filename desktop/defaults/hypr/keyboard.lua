-- VeloGuardOS — keyboard layout from the system setting (what the installer's
-- Keyboard page chose, or `localectl set-x11-keymap us,bg` later). Hyprland
-- has its own input.kb_layout and defaults to "us": without this, picking
-- Bulgarian (or us+bg) in the installer changed the console and X11 but not
-- the Hyprland session. Your ~/.config/hypr/input.lua loads later and wins.
local function system_keyboard()
  local kb = {}
  local f = io.open("/etc/X11/xorg.conf.d/00-keyboard.conf", "r")
  if not f then return kb end
  for line in f:lines() do
    local key, value = line:match('^%s*Option%s+"Xkb(%a+)"%s+"([^"]*)"')
    if key then kb[key:lower()] = value end
  end
  f:close()
  return kb
end

local kb = system_keyboard()
-- Only plain XKB names: this file is root-owned, but it is still input.
local function ok(v) return v ~= nil and v ~= "" and v:match("^[%w_,:+%-%(%)]+$") ~= nil end

local input = { kb_options = "compose:caps" }       -- Caps Lock = Compose, as before
if ok(kb.layout) then input.kb_layout = kb.layout end
if ok(kb.variant) then input.kb_variant = kb.variant end
if ok(kb.model) then input.kb_model = kb.model end
if ok(kb.options) then input.kb_options = kb.options .. ",compose:caps" end   -- keeps the layout switch (grp:…)
hl.config({ input = input })
