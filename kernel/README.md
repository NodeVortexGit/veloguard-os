# VeloGuardOS kernel update-tree

This directory is **our kernel expressed as a delta on Linus's tree** — never the
full 6.4 GB source (GitHub can't host that, and nobody should pull it per update).
The full source is fetched from kernel.org at build time; here we keep only:

| File | What it is |
|------|------------|
| `BASE` | the upstream release tag we're pinned to (e.g. `v7.2.11`). The agent bumps this. A point release `vX.Y.Z` is fetched from the stable tree (where every security backport lands); a bare `vX.Y` from torvalds/linux. |
| `PKGBUILD` | Arch recipe: upstream source + our config + our patches → `linux-veloguard` + `linux-veloguard-headers` (DKMS: nvidia, broadcom-wl) |
| `build-recipe.sh` | CI entry point: stages context, runs `makepkg`, emits both packages + sha256s + the manifest block |
| `audit-config.sh` | fails the build if any requested `CONFIG_` symbol didn't survive `olddefconfig` (Kconfig drops unmet dependencies silently) |
| `patches/*.patch` | our source patches on top of upstream (none yet — config-only so far) |

The config fragments themselves live in `../veloguard/kernel/veloguardos-*.config`
(single source of truth, also used by the ISO + `veloguard-kernel-sync`); the
recipe copies them into the build context.

## The pipeline

```
Linus stable tag ─┐
                  ├─[agent] bump BASE + rebase patches + validate → commit & push
our patches+config┘                         │
                              [CI build-kernel.yml] makepkg in an Arch container
                                            │
        linux-veloguard{,-headers}-X.Y.Z-1-x86_64.pkg.tar.zst → GitHub Release
                                            │
                              sign manifest.json (kernel version + sha256)   ← offline key
                                            │
                    [user's updater] background download → stage → apply on reboot (opt-in)
```

- **Compare our kernel to Linus's** = compare `BASE` + `patches/` against Linus's
  latest stable. The agent does the merge and updates this tree (see the
  `kernel-sync` agent contract).
- **Deliver to users** = the built-in updater (`guardd update`) downloads the
  signed, prebuilt package in the background and stages it for an
  apply-on-reboot, Fedora-style (opt-in checkbox on the restart dialog).

## Bump the kernel by hand (what the agent automates)

```bash
echo v7.2.12 > kernel/BASE       # pin a newer upstream stable tag
# (add/refresh kernel/patches/*.patch if our deltas need rebasing)
git commit -am "kernel: bump to v7.2.12"   # CI builds; publish both packages, then sign the manifest
```

## Why the config looks the way it does

`x86_64_defconfig` is a *build-test* config, not a distro config. On Arch
userspace a kernel built from it (plus feature fragments) compiles and boots to
a shell, then fails in ways that look like "the kernel is broken":

- **no firmware loads** — Arch ships every blob `.zst`-compressed; without
  `FW_LOADER_COMPRESS_ZSTD` there is no Wi-Fi, Bluetooth, amdgpu, GuC/HuC, SOF;
- **no root disk** on Intel RST/VMD laptops (`VMD`);
- **no touchpad** — I2C-HID needs the DesignWare I2C controller, LPSS and the
  GPIO/pinctrl subsystem, none of which defconfig enables;
- **`wg-quick` full-tunnel aborts** — needs `NFT_FIB_*`, `NF_CONNTRACK_MARK`,
  `IPV6_MULTIPLE_TABLES`;
- **black screen until a GPU module loads** — `SIMPLEDRM` needs `SYSFB_SIMPLEFB`.

The fragments now cover these, and `audit-config.sh` runs inside `prepare()`
so a fragment line that Kconfig quietly drops fails CI instead of shipping.
The kernel identifies itself as `X.Y.Z-veloguard` (`uname -r`), and its
modules live in their own `/usr/lib/modules/X.Y.Z-veloguard`.
