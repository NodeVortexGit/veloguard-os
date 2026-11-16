#!/usr/bin/env bash
#
# calamares-target-net — runs on the LIVE system (Calamares dontChroot) before
# anything in the target needs the network (drivers, desktops, default apps).
#
# Calamares' mount module puts a FRESH tmpfs on <target>/run, and Arch's
# /etc/resolv.conf is a symlink to /run/systemd/resolve/stub-resolv.conf — so
# inside the install chroot there is no resolver at all: every pacman/flatpak/
# git call during installation failed DNS (the old "Flatpak-in-chroot is
# finicky"). The chroot shares the live system's network namespace, so the
# live stub resolver (127.0.0.53) answers there too; we just need the file.
# /run is that tmpfs, so nothing here persists into the installed system.
#
# $1 = target root (Calamares substitutes ${ROOT}).
set -u
ROOT="${1:?target root path required}"
[ -d "$ROOT" ] || { echo "ERROR: target root '$ROOT' is not a directory" >&2; exit 1; }

install -d "$ROOT/run/systemd/resolve"
if ! cp -L /etc/resolv.conf "$ROOT/run/systemd/resolve/stub-resolv.conf" 2>/dev/null \
   || ! grep -q '^nameserver' "$ROOT/run/systemd/resolve/stub-resolv.conf"; then
  printf 'nameserver 1.1.1.1\nnameserver 9.9.9.9\n' > "$ROOT/run/systemd/resolve/stub-resolv.conf"
fi
cp "$ROOT/run/systemd/resolve/stub-resolv.conf" "$ROOT/run/systemd/resolve/resolv.conf"

# A mirrorlist the live session already ranked (reflector / mirror= boot
# parameter) beats the disc's unranked one.
if grep -q '^Server' /etc/pacman.d/mirrorlist 2>/dev/null; then
  cp /etc/pacman.d/mirrorlist "$ROOT/etc/pacman.d/mirrorlist"
elif ! grep -q '^Server' "$ROOT/etc/pacman.d/mirrorlist" 2>/dev/null; then
  # shellcheck disable=SC2016  # $repo/$arch are pacman's variables, not ours
  printf 'Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch\n' > "$ROOT/etc/pacman.d/mirrorlist"
fi
echo "target network ready ($(grep -c '^nameserver' "$ROOT/run/systemd/resolve/stub-resolv.conf") resolver(s))"
exit 0
