#!/usr/bin/env bash
# Give the primary user privileged input access (dictation, game controllers).
# Derived from Omarchy install/hardware/input-group.sh (MIT).
# On an installed system the account is whatever the user named it in the
# installer — "veloguard" is only the live user. Fall back to the first human
# account (UID 1000-59999) when no explicit user was handed in.
user="${VELOGUARD_HW_USER:-}"
if [ -z "$user" ] || ! getent passwd "$user" >/dev/null 2>&1; then
  user="$(getent passwd | awk -F: '$3 >= 1000 && $3 < 60000 {print $1; exit}')"
fi
if getent passwd "$user" >/dev/null 2>&1; then
  usermod -aG input "$user" 2>/dev/null || true
fi
