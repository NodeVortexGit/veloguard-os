#!/usr/bin/env bash
#
# calamares-desktop — install the desktop picked on the installer's Desktop page
# (Global Storage `veloguard_desktop`) into the target. Runs IN the target
# chroot, after calamares-target-net.sh gave it DNS.
#
#   calamares-desktop.sh <desktop> <user>
#   desktop: cleanconfig | hyprland | gnome | xfce | niri | i3 | cosmic
#
# Never fails the installation: VeloGuard Hyprland is already on the disc, so
# if a download fails (offline) the user gets that, and the choice is kept in
# /var/lib/veloguard/desktop-pending for the first online boot to finish
# (veloguard-hardware.service picks it up). All packages: official Arch repos.
set -uo pipefail
DE="${1:-hyprland}"; U="${2:-}"
LOG=/var/log/veloguard-install-desktop.log
PENDING=/var/lib/veloguard/desktop-pending
HERE="$(dirname "$(readlink -f "$0")")"
mkdir -p /var/lib/veloguard "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1
echo "=== desktop '$DE' for user '${U:-?}' — $(date -u)"

case "$DE" in
  hyprland|cleanconfig)
    PKGS=(); SESSION=/usr/share/wayland-sessions/hyprland.desktop ;;
  gnome)
    PKGS=(gnome-shell gnome-session gnome-settings-daemon gnome-control-center gnome-keyring
          nautilus gnome-console gnome-text-editor gnome-system-monitor gnome-calculator
          gnome-disk-utility gnome-tweaks loupe papers gvfs xdg-desktop-portal-gnome)
    SESSION=/usr/share/wayland-sessions/gnome.desktop ;;
  xfce)
    PKGS=(xfce4 xfce4-whiskermenu-plugin xfce4-pulseaudio-plugin xfce4-screenshooter
          xfce4-notifyd xfce4-power-manager mousepad ristretto network-manager-applet
          pavucontrol xorg-server)
    SESSION=/usr/share/xsessions/xfce.desktop ;;
  niri)
    PKGS=(niri xwayland-satellite fuzzel waybar mako swaybg swaylock swayidle alacritty
          xdg-desktop-portal-gnome xdg-desktop-portal-gtk)
    SESSION=/usr/share/wayland-sessions/niri.desktop ;;
  i3)
    PKGS=(i3-wm i3status i3lock dmenu rofi picom xss-lock dex feh alacritty
          network-manager-applet xorg-server xorg-xinit)
    SESSION=/usr/share/xsessions/i3.desktop ;;
  cosmic)
    PKGS=(cosmic-session cosmic-comp cosmic-panel cosmic-launcher cosmic-files
          cosmic-terminal cosmic-settings cosmic-store xdg-desktop-portal-cosmic)
    SESSION=/usr/share/wayland-sessions/cosmic.desktop ;;
  *)
    echo "unknown desktop '$DE' — keeping VeloGuard Hyprland"
    DE=hyprland; PKGS=(); SESSION=/usr/share/wayland-sessions/hyprland.desktop ;;
esac

ok=1
if [ ${#PKGS[@]} -gt 0 ]; then
  # Full -Syu, never -Sy: the disc's package DB is from ISO build day, and a
  # bare -Sy + -S is a partial upgrade (new packages against old libraries).
  if ! pacman -Syu --noconfirm --needed "${PKGS[@]}"; then
    ok=0; echo "package install failed (offline?) — VeloGuard Hyprland stays the session for now"
  fi
fi
if [ "$DE" = cleanconfig ] && [ -n "$U" ]; then
  "$HERE/install-clean-config.sh" "$U" || { ok=0; echo "Clean Config build failed — VeloGuard Hyprland stays until it succeeds"; }
fi

if [ "$ok" = 1 ]; then
  rm -f "$PENDING"
else
  printf '%s %s\n' "$DE" "$U" > "$PENDING"; SESSION=/usr/share/wayland-sessions/hyprland.desktop
fi

# Default session for this user in SDDM (the one display manager for every
# choice: it launches Wayland and X11 sessions alike).
if [ -n "$U" ] && [ -f "$SESSION" ]; then
  install -d /var/lib/sddm
  printf '[Last]\nSession=%s\nUser=%s\n' "$SESSION" "$U" > /var/lib/sddm/state.conf
  chown -R sddm:sddm /var/lib/sddm 2>/dev/null || true
fi
echo "desktop step done: $DE (session $(basename "$SESSION"), complete=$ok)"
exit 0
