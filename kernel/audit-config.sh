#!/usr/bin/env bash
#
# audit-config.sh — prove every CONFIG_ symbol our fragments request survived
# `make olddefconfig`. Kconfig silently drops a symbol whose `depends on` isn't
# met (or that upstream renamed/removed), so a fragment can say =y while the
# built kernel says "is not set" — that is exactly how a kernel ends up
# compiling fine and then not loading firmware, not seeing the disk, etc.
#
#   audit-config.sh <resolved .config> <fragment>...
#
# Fragments are read in merge order; the LAST one to mention a symbol wins
# (same as merge_config.sh). A request of =m that resolves to =y is accepted
# (something built-in selected it — strictly more capable). Anything else is a
# drop. Prints one line per drop to stderr and exits 1 if there were any;
# prints the dropped symbol names on stdout so callers can embed them.
set -uo pipefail

[ $# -ge 2 ] || { echo "usage: $0 <.config> <fragment>..." >&2; exit 2; }
cfg="$1"; shift
[ -f "$cfg" ] || { echo "audit-config: no such config: $cfg" >&2; exit 2; }

declare -A want=()
declare -a order=()
for frag in "$@"; do
  [ -f "$frag" ] || { echo "audit-config: no such fragment: $frag" >&2; exit 2; }
  while IFS= read -r line || [ -n "$line" ]; do
    if [[ $line =~ ^(CONFIG_[A-Za-z0-9_]+)=(.*)$ ]]; then
      sym="${BASH_REMATCH[1]}"; val="${BASH_REMATCH[2]}"
    elif [[ $line =~ ^#\ (CONFIG_[A-Za-z0-9_]+)\ is\ not\ set$ ]]; then
      sym="${BASH_REMATCH[1]}"; val="n"
    else
      continue
    fi
    [ -n "${want[$sym]+x}" ] || order+=("$sym")
    want[$sym]="$val"
  done < "$frag"
done

dropped=()
for sym in "${order[@]}"; do
  req="${want[$sym]}"
  got="$(sed -n "s/^${sym}=//p" "$cfg" | head -n1)"
  [ -n "$got" ] || got="n"
  [ "$got" = "$req" ] && continue
  [ "$req" = m ] && [ "$got" = y ] && continue
  echo "  DROPPED ${sym}: requested ${req}, resolved ${got}" >&2
  dropped+=("$sym")
done

if [ ${#dropped[@]} -gt 0 ]; then
  echo "audit-config: ${#dropped[@]} requested symbol(s) did not survive olddefconfig" >&2
  printf '%s\n' "${dropped[@]}"
  exit 1
fi
echo "audit-config: all ${#order[@]} requested symbols survived olddefconfig" >&2
exit 0
