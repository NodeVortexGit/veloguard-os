#!/usr/bin/env bash
# Synaptics InterTouch (RMI4 over SMBus): smoother tracking and real
# multi-finger gestures instead of the PS/2 fallback. Derived from Omarchy
# install/hardware/fix-synaptic-touchpad.sh (MIT).
#
# The old version ran `modprobe psmouse synaptics_intertouch=1` only when
# psmouse was NOT loaded — it always is by the time this runs, so it never
# fired, and when it did it lasted until the next reboot. Now: enabled only
# for touchpads the kernel itself flagged as InterTouch-capable but not on
# its allow-list ("…might want to try setting psmouse.synaptics_intertouch
# to 1"), and persisted in modprobe.d so it applies from the next boot on.
conf=/etc/modprobe.d/veloguard-psmouse.conf
[ -f "$conf" ] && exit 0
grep -qi synaptics /proc/bus/input/devices 2>/dev/null || exit 0
if dmesg 2>/dev/null | grep -q 'psmouse.synaptics_intertouch to 1'; then
  printf '# Written by VeloGuardOS: the kernel reported this touchpad supports InterTouch.\noptions psmouse synaptics_intertouch=1\n' > "$conf"
  echo "Synaptics InterTouch enabled (from next boot)"
fi
