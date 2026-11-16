#!/usr/bin/env bash
#
# install-vpn-apps.sh — the three provider VPN apps the guard menu and
# auto-protect connect through (veloguard-vpn connect proton|nord|surfshark).
# Run by the installer (Calamares, in the target chroot) for the new account:
#
#   sudo install-vpn-apps.sh [--user NAME] [--headless | --desktop NAME] [proton nord surfshark]
#
#   proton     Arch [extra]: proton-vpn-gtk-app + proton-vpn-cli (CLI only headless)
#   nord       AUR nordvpn-bin — a repack of Nord's official .deb, built from a
#              PINNED, reviewed commit (PKGBUILD + install hook checked by
#              sha256 before anything runs); built as the user, installed by
#              pacman. A newer AUR commit is NOT picked up silently: bump the pin
#              after reviewing it (or install by hand: veloguard-vpn app nord install).
#   surfshark  Flathub com.surfshark.Surfshark (desktop only; no Linux CLI).
#              Queued with the default Flatpaks if the network isn't up.
#
# Best-effort per app: one failing never stops the others. Signing in to each
# app is yours, once — VPN… ▸ Connect: <provider> walks you through it.
set -uo pipefail
say()  { printf '\033[1;36m[veloguard]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[veloguard]\033[0m %s\n' "$*" >&2; }
[ "$(id -u)" -eq 0 ] || { warn "run as root"; exit 1; }

# The reviewed nordvpn-bin (6.0.2-2): downloads Nord's .deb from
# repo.nordvpn.com and checks it against the sha256 in this PKGBUILD.
NORD_AUR=https://aur.archlinux.org/nordvpn-bin.git
NORD_COMMIT=8694f9430bb2e1c93a9394725107c56eb79f78ac
NORD_PKGBUILD_SHA=bfc9f809bf1e62da2ebba2fce7c6ad7a5b71be9802643679460cc77fb1959bbe
NORD_INSTALL_SHA=e5e804228d7d3a436330bffee96adf05f6b5c85710ba82e4417c078805f760f5
SURFSHARK_ID=com.surfshark.Surfshark
STEP_TIMEOUT=900

U=""; headless=0; want=()
while [ $# -gt 0 ]; do
  case "$1" in
    --user)     U="${2:-}"; shift 2 ;;
    --headless) headless=1; shift ;;
    --desktop)  [ "${2:-}" = headless ] && headless=1; shift 2 ;;   # the installer's Desktop page
    -h|--help)  sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*)         warn "unknown option $1"; exit 2 ;;
    *)          want+=("$1"); shift ;;
  esac
done
[ -n "$U" ] || U="${SUDO_USER:-}"
[ -n "$U" ] || U="$(getent passwd | awk -F: '$3 >= 1000 && $3 < 60000 {print $1; exit}')"
getent passwd "$U" >/dev/null 2>&1 && [ "$U" != root ] || { warn "pass --user NAME (the desktop account)"; exit 1; }
[ ${#want[@]} -gt 0 ] || want=(proton nord surfshark)

pkgs() { timeout -s INT -k 30 "$STEP_TIMEOUT" pacman -S --noconfirm --needed "$@"; }

install_proton() {
  if [ "$headless" -eq 1 ]; then pkgs proton-vpn-cli; else pkgs proton-vpn-gtk-app proton-vpn-cli; fi
}

install_nord() {
  command -v nordvpn >/dev/null 2>&1 && { say "nord: already installed"; return 0; }
  pkgs base-devel git || return 1
  local t; t="$(mktemp -d)"
  chown "$U:" "$t"
  # shellcheck disable=SC2064  # expand now: $t is local
  trap "rm -rf -- '$t'" RETURN
  local d="$t/nordvpn-bin"
  as() { runuser -u "$U" -- env -i HOME="$t" PATH=/usr/bin LANG=C.UTF-8 \
           timeout -s INT -k 30 "$STEP_TIMEOUT" "$@" </dev/null; }
  as git clone -q "$NORD_AUR" "$d" && as git -C "$d" checkout -q "$NORD_COMMIT" || return 1
  if [ "$(sha256sum "$d/PKGBUILD" | cut -d' ' -f1)" != "$NORD_PKGBUILD_SHA" ] ||
     [ "$(sha256sum "$d/nordvpn-bin.install" | cut -d' ' -f1)" != "$NORD_INSTALL_SHA" ]; then
    warn "nord: the pinned PKGBUILD doesn't match its reviewed checksum — not building it"
    return 1
  fi
  ( cd "$d" && as makepkg --noconfirm --nodeps ) || return 1
  # [0-9]: the package itself, not the -debug split makepkg also writes
  pacman -U --noconfirm "$d"/nordvpn-bin-[0-9]*.pkg.tar.zst || return 1
  systemctl enable nordvpnd.socket 2>/dev/null || systemctl enable nordvpnd.service 2>/dev/null || true
  gpasswd -a "$U" nordvpn >/dev/null 2>&1 || usermod -aG nordvpn "$U"
}

install_surfshark() {
  [ "$headless" -eq 0 ] || { say "surfshark: desktop app — skipped on a headless install"; return 0; }
  command -v flatpak >/dev/null 2>&1 || pkgs flatpak || return 1
  flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo || return 1
  flatpak info --system "$SURFSHARK_ID" >/dev/null 2>&1 && return 0
  if ! timeout -s INT -k 30 "$STEP_TIMEOUT" flatpak install -y --noninteractive --system flathub "$SURFSHARK_ID"; then
    # The default-apps queue installs it on the first online boot.
    if [ -x /usr/local/lib/veloguard/flatpak-pending ]; then
      grep -qxF "$SURFSHARK_ID" /var/lib/veloguard/flatpak-pending 2>/dev/null \
        || echo "$SURFSHARK_ID" >> /var/lib/veloguard/flatpak-pending
      mkdir -p /etc/systemd/system/multi-user.target.wants
      ln -sf ../veloguard-flatpak-pending.service \
        /etc/systemd/system/multi-user.target.wants/veloguard-flatpak-pending.service
      warn "surfshark: queued for the first online boot"
    fi
    return 1
  fi
}

failed=()
for a in "${want[@]}"; do
  case "$a" in proton|nord|surfshark) ;; *) warn "unknown VPN app '$a'"; failed+=("$a"); continue ;; esac
  say "installing the $a VPN app…"
  if "install_$a"; then say "$a: ready"; else warn "$a: not installed"; failed+=("$a"); fi
done
if [ ${#failed[@]} -eq 0 ]; then say "VPN apps ready: ${want[*]} — sign in once from VPN… ▸ Connect"; exit 0; fi
warn "not installed: ${failed[*]} — later: veloguard-vpn app <provider> install"
exit 1
