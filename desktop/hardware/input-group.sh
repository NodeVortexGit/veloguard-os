#!/usr/bin/env bash
# Raw input access (the `input` group) — OPT-IN on VeloGuardOS.
# Derived from Omarchy install/hardware/input-group.sh (MIT), which added the
# primary user unconditionally "for dictation and game controllers".
#
# Not here: the group grants read AND write on every /dev/input/event* to every
# process the user runs. Reading is a keylogger for the whole session
# (passwords included) without root; writing injects keystrokes into the real
# keyboard — an agent could press Ctrl+Enter on its own root Approve dialog.
# Neither is needed: the compositor gets the devices from logind, and game
# controllers get a per-seat uaccess ACL from systemd. Only tools that read
# evdev themselves (some push-to-talk dictation, key remappers) need it — set
# VELOGUARD_INPUT_GROUP=1 to give it knowingly.
[ "${VELOGUARD_INPUT_GROUP:-0}" = 1 ] || exit 0
user="${VELOGUARD_HW_USER:-}"
if [ -z "$user" ] || ! getent passwd "$user" >/dev/null 2>&1; then
  user="$(getent passwd | awk -F: '$3 >= 1000 && $3 < 60000 {print $1; exit}')"
fi
if getent passwd "$user" >/dev/null 2>&1; then
  usermod -aG input "$user" 2>/dev/null || true
fi
