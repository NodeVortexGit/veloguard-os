# albert — the desktop's launcher (Super+Alt, Albert is the default search bar)

AUR `albert` 35.2.0-1 at commit b0cf6e1a186c634488f618f73c5114c99d566d44,
PKGBUILD sha256 f3fe41fa77f3534c1efe78d45063a94d71074c2260dc5fc7b90e4872993fea10
(reviewed: builds Albert's official v35.2.0 release tarball, sha512-pinned).
Not in the Arch repos, so — like hyprland-multicursor — the built package
ships in iso/pkgs (the ISO's local [veloguard] repo) and the ISO stays
AUR-free. Rebuild: `makepkg --nodeps` here (deps from [extra]: qcoro,
qt6-5compat qt6-declarative qt6-scxml qt6-shadertools qt6-svg qtkeychain-qt6;
make: cmake libqalculate pybind11 qt6-tools), copy the .pkg.tar.zst to iso/pkgs.
