#!/usr/bin/env bash
#
# calamares-target-finish — the last step before Calamares unmounts the target
# (runs on the LIVE system, dontChroot). A step that ran out of time can leave
# processes behind inside the target (pacman, DKMS, a build): they keep the
# filesystem busy, and the unmount — the very last step — then fails the whole
# installation. Stop them, and clear the pacman lock they could no longer
# release (nothing can hold it once no process is left in the target).
#
#   calamares-target-finish.sh <target root>      (${ROOT})
set -u
ROOT="${1:?target root path required}"
root="$(readlink -f "$ROOT")"
[ -n "$root" ] && [ "$root" != / ] || { echo "refusing: target root resolves to '/'" >&2; exit 0; }

in_target() {  # PIDs whose root directory is the target (chrooted into it)
  local p
  for p in /proc/[0-9]*; do
    [ "$(readlink -f "$p/root" 2>/dev/null)" = "$root" ] && echo "${p#/proc/}"
  done
}

left="$(in_target)"
if [ -n "$left" ]; then
  for pid in $left; do
    echo "stopping leftover process in the target: $pid $(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | cut -c1-100)"
    kill -INT "$pid" 2>/dev/null
  done
  for _ in 1 2 3 4 5 6 7 8 9 10; do [ -z "$(in_target)" ] && break; sleep 1; done
  for pid in $(in_target); do kill -KILL "$pid" 2>/dev/null; done
fi
if [ -e "$root/var/lib/pacman/db.lck" ]; then
  rm -f "$root/var/lib/pacman/db.lck"
  echo "removed a stale pacman lock (a step was stopped mid-transaction)"
fi
echo "target is idle"
exit 0
