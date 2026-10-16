#!/usr/bin/env bash
#
# build-recipe.sh — turn {BASE tag + our config fragments + patches} into a
# prebuilt VeloGuardOS kernel package. Runs in an Arch container (CI), where
# makepkg + the toolchain exist. Emits:
#   out/linux-veloguard-<ver>-1-x86_64.pkg.tar.zst          the kernel
#   out/linux-veloguard-headers-<ver>-1-x86_64.pkg.tar.zst  headers (DKMS)
#   out/kernel-manifest.json                                 the 'kernel' block to sign
#
# It does NOT sign anything — signing the manifest uses the offline release key
# (see ../veloguard/keys/SIGNING.md), done after this publishes the artifacts.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
OUT="${OUT:-$REPO/out}"
FRAG="$REPO/veloguard/kernel"
RELEASE_BASE="${RELEASE_BASE:-https://github.com/NodeVortexGit/veloguard-os/releases/latest/download}"

BASE="$(tr -d ' \t\n\r' < "$HERE/BASE")"     # e.g. v7.2.11
[[ $BASE =~ ^v[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || {
  echo "kernel/BASE must be a release tag like v7.2 or v7.2.11 (got '$BASE')" >&2; exit 1; }
KVER="${BASE#v}"                              # 7.2.11
# Point releases (vX.Y.Z — where every security backport lands) exist only in
# the stable tree; torvalds/linux carries just mainline vX.Y. Mirrors on
# GitHub so CI never depends on kernel.org git hosting.
if [[ $KVER == *.*.* ]]; then
  GIT="${KERNEL_GIT:-https://github.com/gregkh/linux}"
else
  GIT="${KERNEL_GIT:-https://github.com/torvalds/linux}"
fi
echo "==> VeloGuardOS kernel: base=$BASE  pkgver=$KVER  source=$GIT"

for f in base desktop hardware; do
  [ -f "$FRAG/veloguardos-$f.config" ] || { echo "missing fragment veloguardos-$f.config" >&2; exit 1; }
done

mkdir -p "$OUT"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# --- stage the build context next to a version-injected PKGBUILD -----------
sed "s/__PKGVER__/${KVER}/g" "$HERE/PKGBUILD" > "$WORK/PKGBUILD"
cp "$FRAG/veloguardos-base.config"     "$WORK/"
cp "$FRAG/veloguardos-desktop.config"  "$WORK/"
cp "$FRAG/veloguardos-hardware.config" "$WORK/"
cp "$HERE/audit-config.sh"             "$WORK/"
# our patch series (sorted) — none yet is fine
shopt -s nullglob
for p in "$HERE"/patches/*.patch; do cp "$p" "$WORK/"; done
shopt -u nullglob

# --- source tarball: shallow git archive of the BASE tag --------------------
# --depth 1 keeps it to a single snapshot, not 6.4 GB of history.
echo "==> fetching upstream $BASE (shallow)…"
git clone --quiet --depth 1 --branch "$BASE" "$GIT" "$WORK/linux-src"
( cd "$WORK/linux-src" && git archive --format=tar --prefix="linux-${KVER}/" HEAD ) > "$WORK/linux-${KVER}.tar"
rm -rf "$WORK/linux-src"

# --- build (this compiles the kernel — long) -------------------------------
cd "$WORK"
echo "==> makepkg…"
makepkg -f --noconfirm --skipinteg --nocheck "$@"

# Name both packages exactly: a glob like linux-veloguard-* also matches the
# headers package, and picking the wrong one would pin the wrong sha256.
emit_pkg() {   # $1 = pkgname → copies it to $OUT, prints its basename
  local f="$WORK/$1-${KVER}-1-x86_64.pkg.tar.zst"
  [ -f "$f" ] || { echo "makepkg produced no $1 package ($f)" >&2; exit 1; }
  cp -f "$f" "$OUT/"
  basename "$f"
}
KPKG="$(emit_pkg linux-veloguard)"
HPKG="$(emit_pkg linux-veloguard-headers)"
KSHA="$(sha256sum "$OUT/$KPKG" | cut -d' ' -f1)"
HSHA="$(sha256sum "$OUT/$HPKG" | cut -d' ' -f1)"

echo "==> built  : $OUT/$KPKG  ($KSHA)"
echo "==> built  : $OUT/$HPKG  ($HSHA)"

# --- emit the signed-updater 'kernel' manifest block -----------------------
cat > "$OUT/kernel-manifest.json" <<EOF
{
  "version": "${KVER}",
  "base_tag": "${BASE}",
  "package": "${KPKG}",
  "artifact": "${RELEASE_BASE}/${KPKG}",
  "sha256": "${KSHA}",
  "headers": {
    "package": "${HPKG}",
    "artifact": "${RELEASE_BASE}/${HPKG}",
    "sha256": "${HSHA}"
  }
}
EOF
echo "==> wrote  : $OUT/kernel-manifest.json"
echo "==> next   : publish both packages to a Release, fold kernel-manifest.json into manifest.json, sign (offline key)"
