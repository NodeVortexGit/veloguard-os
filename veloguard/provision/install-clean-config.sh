#!/usr/bin/env bash
#
# install-clean-config — the "Clean Config" laptop desktop: NodeVortex's
# Clean_Config_Hyperland (a caelestia-dots/shell fork: Dynamic Island, black +
# dark-blue rice) on Hyprland.
#
#   sudo install-clean-config.sh <user>       # build/install + deploy for <user>
#   sudo install-clean-config.sh --system     # build/install only (no dotfiles)
#
# Everything comes from OFFICIAL Arch repos or from the UPSTREAM project
# sources — pinned release tarballs verified against their published
# checksums. No AUR helper and no AUR PKGBUILD is ever executed: the AUR had a
# real supply-chain compromise in June 2026 (the repo's own finish-install.sh
# warns about it), and an installer must not run unreviewed build scripts.
#
#   quickshell        official repo (0.3.2 — newer than the AUR -git snapshot)
#   libcava 1.0.0     LukashonakV/cava release, sha256-pinned   → /usr/local
#   app2unit 1.4.4    Vladimir-csp/app2unit release, sha256     → /usr/local
#   caelestia-cli     caelestia-dots/cli v1.1.3 release, sha256 → its own venv
#   albert 35.1.0     albertlauncher/albert release, sha512     → /usr/local
#   Material Symbols  google/material-design-icons (font data)  → /usr/local
#   the shell itself  NodeVortexGit/Clean_Config_Hyperland      → /usr/lib, /etc/xdg
#
# Safe by construction: the desktop only switches to Clean Config once every
# REQUIRED piece has built; until then the user keeps the stock VeloGuard
# Hyprland desktop. Albert is optional — if it can't be built, a tiny `albert`
# shim opens fuzzel instead, so the config's keybinds still work unchanged.
#
# The config is deployed AS-IS: hyprland.conf lands byte-for-byte — every
# keybind, monitor line, look and autostart exactly as in the repo. Nothing
# VeloGuard is merged into it. Idempotent; re-run any time.
# Log: /var/log/veloguard-clean-config.log
set -euo pipefail

REPO_URL="${CLEAN_CONFIG_REPO:-https://github.com/NodeVortexGit/Clean_Config_Hyperland}"
REPO_REF="${CLEAN_CONFIG_REF:-main}"
SRC=/usr/local/src/veloguard-clean-config
STAMP=/var/lib/veloguard/clean-config.built
LOG="${CLEAN_CONFIG_LOG:-/var/log/veloguard-clean-config.log}"
JOBS="$(nproc 2>/dev/null || echo 2)"

LIBCAVA_VER=1.0.0
LIBCAVA_SHA256=437df0a29e52e555357a06238f4c5cbe6d51b5dd4225700cb7adbb19d8bb9474
APP2UNIT_VER=1.4.4
APP2UNIT_SHA256=03c1206097a1596c0e49dc48b82d0b602cc9f38cc498542fe27ef613a050d6fc
CLI_VER=1.1.3
CLI_SHA256=f31447efdd94a18556e338bcf8a38236f34660a56b241657817e6cbe80b067e3
ALBERT_VER=35.1.0
ALBERT_SHA512=a0eaadef90b0524f9e0eb6a2bd6f41e49e11846b6a0ca73ed178122aadbfd1402204a688060be18d6ede59fd07af8729604a72c218feda1f1fb600b188c12a23

OFFICIAL=(
  # session + apps the config launches
  hyprland kitty dolphin fuzzel wl-clipboard cliphist grim slurp swappy playerctl brightnessctl
  # the shell runtime
  quickshell qt6-base qt6-declarative qt6-svg qt6-wayland qt6-5compat qt6-shadertools
  ddcutil lm_sensors networkmanager pipewire wireplumber libpipewire libnotify fish
  aubio fftw iniparser libqalculate cava ttf-cascadia-code-nerd fontconfig file
  # caelestia-cli runtime
  python python-pillow dart-sass gpu-screen-recorder dconf
  # albert runtime
  qcoro qt6-scxml qtkeychain-qt6 hicolor-icon-theme
  # build tools (kept: re-runs and updates rebuild in place)
  base-devel git cmake ninja meson pkgconf scdoc python-build python-installer
  python-hatch python-hatch-vcs pybind11 qt6-tools ncurses alsa-lib sdl2 portaudio
  libpulse autoconf-archive
)

say()  { printf '[clean-config] %s\n' "$*"; }
die()  { printf '[clean-config] FAILED: %s\n' "$*" >&2; exit 1; }

# fetch <url> <dest> <algo> <hash> — download + verify. RETURNS non-zero (never
# exits): required steps add `|| die`, optional ones (albert) fall back.
fetch() {
  local url="$1" dest="$2" algo="$3" want="$4" got
  curl -fsSL --retry 3 -o "$dest.part" "$url" || { echo "download failed: $url" >&2; return 1; }
  got="$("${algo}sum" "$dest.part" | cut -d' ' -f1)"
  [ "$got" = "$want" ] || { rm -f "$dest.part"; echo "$algo mismatch for $url (got $got)" >&2; return 1; }
  mv -f "$dest.part" "$dest"
}

[ "$(id -u)" -eq 0 ] || die "run as root"
TARGET_USER=""
case "${1:-}" in
  --system) ;;
  "") die "usage: install-clean-config.sh <user> | --system" ;;
  *) TARGET_USER="$1"; getent passwd "$TARGET_USER" >/dev/null || die "no such user: $TARGET_USER" ;;
esac

mkdir -p "$(dirname "$LOG")" "$SRC" /var/lib/veloguard
exec > >(tee -a "$LOG") 2>&1
say "=== $(date -u) — target user: ${TARGET_USER:-<none>}"

build_system() {
  say "official packages…"
  # -Syu, never -S: if the install's driver step couldn't finish its full
  # upgrade, a bare -S would put new packages on top of old libraries.
  pacman -Syu --noconfirm --needed "${OFFICIAL[@]}"

  local W; W="$(mktemp -d "$SRC/build.XXXXXX")"; trap 'rm -rf "$W"' RETURN

  # Everything built here installs under /usr/local, which isn't in Arch's
  # default linker path — without this libcava ("libcava.so.1: cannot open
  # shared object file" → the shell's "Failed to load configuration") and
  # albert (libalbert.so) can't be loaded. Registered first, for every step.
  echo /usr/local/lib > /etc/ld.so.conf.d/veloguard-usrlocal.conf

  say "libcava $LIBCAVA_VER (upstream release, sha256-pinned)…"
  if ! pkg-config --exists --with-path=/usr/local/lib/pkgconfig cava 2>/dev/null; then
    fetch "https://github.com/LukashonakV/cava/archive/$LIBCAVA_VER.tar.gz" "$W/cava.tgz" sha256 "$LIBCAVA_SHA256" \
      || die "libcava source unavailable"
    tar -xzf "$W/cava.tgz" -C "$W"
    ( cd "$W/cava-$LIBCAVA_VER" && meson setup -Dcava_font=false --prefix=/usr/local build \
        && meson compile -C build -j "$JOBS" && meson install -C build )
  fi
  ldconfig

  say "app2unit $APP2UNIT_VER…"
  if ! command -v app2unit >/dev/null; then
    fetch "https://github.com/Vladimir-csp/app2unit/archive/v$APP2UNIT_VER.tar.gz" "$W/a2u.tgz" sha256 "$APP2UNIT_SHA256" \
      || die "app2unit source unavailable"
    tar -xzf "$W/a2u.tgz" -C "$W"
    ( cd "$W/app2unit-$APP2UNIT_VER" && prefix=/usr/local make install )
  fi

  say "Material Symbols Rounded (icon font)…"
  local fd=/usr/local/share/fonts/material-symbols
  # Validated before it's kept: a cut-off download used to stay in place, and
  # every re-run then skipped both the download and the check.
  if ! file "$fd/MaterialSymbolsRounded.ttf" 2>/dev/null | grep -qiE 'TrueType|OpenType'; then
    install -d "$fd"
    curl -fsSL --retry 3 -o "$fd/MaterialSymbolsRounded.ttf.part" \
      "https://raw.githubusercontent.com/google/material-design-icons/master/variablefont/MaterialSymbolsRounded%5BFILL%2CGRAD%2Copsz%2Cwght%5D.ttf" \
      || { rm -f "$fd/MaterialSymbolsRounded.ttf.part"; die "icon font download failed"; }
    file "$fd/MaterialSymbolsRounded.ttf.part" | grep -qiE 'TrueType|OpenType' \
      || { rm -f "$fd/MaterialSymbolsRounded.ttf.part"; die "icon font download is not a font"; }
    mv -f "$fd/MaterialSymbolsRounded.ttf.part" "$fd/MaterialSymbolsRounded.ttf"
  fi
  fc-cache -f >/dev/null

  say "caelestia-cli $CLI_VER (own venv — never pip into the system python)…"
  local venv=/opt/veloguard/caelestia-cli
  if [ ! -x "$venv/bin/caelestia" ]; then
    fetch "https://github.com/caelestia-dots/cli/releases/download/v$CLI_VER/caelestia-$CLI_VER.tar.gz" "$W/cli.tgz" sha256 "$CLI_SHA256" \
      || die "caelestia-cli source unavailable"
    tar -xzf "$W/cli.tgz" -C "$W"
    ( cd "$W/caelestia-$CLI_VER" && python -m build --wheel --no-isolation )
    rm -rf "$venv"
    python -m venv --system-site-packages "$venv"     # pillow etc. from pacman
    "$venv/bin/pip" install --no-cache-dir --quiet materialyoucolor
    "$venv/bin/pip" install --no-cache-dir --quiet --no-deps "$W"/caelestia-"$CLI_VER"/dist/*.whl
  fi
  ln -sfn "$venv/bin/caelestia" /usr/local/bin/caelestia

  say "the shell (Clean_Config_Hyperland @ $REPO_REF)…"
  if [ -d "$SRC/shell/.git" ]; then
    git -C "$SRC/shell" fetch --depth 1 origin "$REPO_REF" && git -C "$SRC/shell" reset --hard FETCH_HEAD
  else
    rm -rf "$SRC/shell"; git clone --depth 1 --branch "$REPO_REF" "$REPO_URL" "$SRC/shell"
  fi
  local rev; rev="$(git -C "$SRC/shell" rev-parse HEAD)"; BUILT_REV="$rev"
  (
    cd "$SRC/shell"
    export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig:${PKG_CONFIG_PATH:-}"
    # The fork carries no git tags, so CMake's `git describe` version lookup
    # fails — pass VERSION (and the exact revision) explicitly.
    cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/ \
      -DVERSION=1.0.0 -DGIT_REVISION="$rev" -DDISTRIBUTOR=VeloGuardOS
    cmake --build build -j "$JOBS"
    cmake --install build
  )
  say "shell installed (revision ${rev:0:12})"

  # Optional: Albert (the config's launcher). A failure here is not fatal: the
  # shim below takes its name, so `albert toggle` (Super+Alt, $menu) and the
  # `exec-once = albert` line keep working without editing the config.
  if ! albert_real; then
    say "albert $ALBERT_VER (optional)…"
    if fetch "https://github.com/albertlauncher/albert/releases/download/v$ALBERT_VER/v$ALBERT_VER.tar.gz" \
         "$W/albert.tgz" sha512 "$ALBERT_SHA512" 2>/dev/null \
       && tar -xzf "$W/albert.tgz" -C "$W" \
       && cmake -S "$W/albert" -B "$W/albert-build" -G Ninja -DCMAKE_BUILD_TYPE=MinSizeRel \
            -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib \
            -DCMAKE_FIND_PACKAGE_RESOLVE_SYMLINKS=ON -DQHOTKEY_INSTALL=OFF -DBUILD_PLUGIN_DEBUG=OFF \
       && cmake --build "$W/albert-build" -j "$JOBS" && cmake --install "$W/albert-build"; then
      ldconfig; say "albert installed"
    else
      install_albert_shim
      say "albert did not build — 'albert toggle' opens fuzzel until it does (re-run to retry)"
    fi
  fi
  # Stamped LAST: if anything above is interrupted (the installer's deadline,
  # a reboot mid-build), the next run builds again instead of deploying a
  # config whose launcher — `albert` — doesn't exist yet.
  echo "$BUILT_REV" > "$STAMP"
}

# Real Albert on PATH — the shim doesn't count, so a re-run retries the build.
albert_real() {
  local a; a="$(command -v albert 2>/dev/null)" || return 1
  ! grep -q 'veloguard-albert-shim' "$a" 2>/dev/null
}

install_albert_shim() {
  cat > /usr/local/bin/albert <<'SHIM'
#!/bin/sh
# veloguard-albert-shim — stands in for Albert while it can't be built, so the
# Clean Config keybinds stay exactly as written: `albert toggle` opens fuzzel
# (a second press closes it); a bare `albert` — the config's exec-once daemon
# start — does nothing. A successful Albert build replaces this file.
case "${1:-}" in
  toggle|show) pkill -x fuzzel 2>/dev/null || exec fuzzel ;;
  hide)        pkill -x fuzzel 2>/dev/null ;;
esac
exit 0
SHIM
  chmod 755 /usr/local/bin/albert
}

deploy() {
  local u="$1" home; home="$(getent passwd "$u" | cut -d: -f6)"
  local dot="$SRC/shell/dotfiles"
  [ -d "$dot" ] || die "dotfiles missing in $SRC/shell"
  say "deploying dotfiles for $u → $home"
  # Keep the stock VeloGuard Hyprland config one rename away.
  if [ -f "$home/.config/hypr/hyprland.conf" ] && [ ! -f "$home/.config/hypr/hyprland.conf.veloguard-default" ] \
     && ! grep -q 'caelestia:islandToggle' "$home/.config/hypr/hyprland.conf"; then
    runuser -u "$u" -- cp -a "$home/.config/hypr/hyprland.conf" "$home/.config/hypr/hyprland.conf.veloguard-default"
  fi
  runuser -u "$u" -- mkdir -p "$home/.config" "$home/.local" "$home/Pictures" "$home/.local/state/caelestia/wallpaper"
  runuser -u "$u" -- cp -r "$dot/.config/." "$home/.config/"
  runuser -u "$u" -- cp -r "$dot/.local/." "$home/.local/"
  runuser -u "$u" -- cp "$dot/wallpaper.png" "$home/Pictures/wallhaven-p838q3.png"
  # Point the shell at the wallpaper WITHOUT `caelestia wallpaper`, which would
  # regenerate scheme.json from the image and clobber the dark-blue palette.
  runuser -u "$u" -- sh -c 'printf "%s" "$1" > "$2"' _ "$home/Pictures/wallhaven-p838q3.png" \
    "$home/.local/state/caelestia/wallpaper/path.txt"
  # Super+Q runs this script — the one file the config needs to be executable.
  chmod +x "$home/.config/hypr/scripts/close-workspace.sh" 2>/dev/null || true
  # hyprland.conf is NOT edited: keybinds, monitor, look and autostart stay
  # exactly as in the repo. (The VeloGuard guard menu is still one command
  # away — veloguard-guard-menu — it just has no key here.)

  # SDDM: open the Hyprland session for this user by default.
  install -d -o sddm -g sddm /var/lib/sddm 2>/dev/null || install -d /var/lib/sddm
  printf '[Last]\nSession=/usr/share/wayland-sessions/hyprland.desktop\nUser=%s\n' "$u" > /var/lib/sddm/state.conf
  chown sddm:sddm /var/lib/sddm/state.conf 2>/dev/null || true
  touch "/var/lib/veloguard/clean-config.deployed.$u"
  say "Clean Config ready for $u — log into Hyprland."
}

if [ ! -f "$STAMP" ] || [ "${CLEAN_CONFIG_REBUILD:-0}" = 1 ]; then
  build_system
fi
[ -n "$TARGET_USER" ] && deploy "$TARGET_USER"
say "done"
