# Kernel-sync agent contract

The job: **keep VeloGuardOS's kernel current with Linus's latest stable, prove it
still builds with our delta, and ship it** — the "compare our kernel to Linus's"
agent. It works on the *delta* in this repo; it never commits kernel source.

## Inputs it reads
- `kernel/BASE` — the upstream release tag we're pinned to (e.g. `v7.2.11`).
- `kernel/patches/*.patch` — our source deltas (none yet).
- `../veloguard/kernel/veloguardos-*.config` — our config fragments.
- Linus's tree at `/home/nodevortex/VeloGuardOS` (`origin = torvalds/linux`)
  plus a `stable` remote (`git remote add stable https://github.com/gregkh/linux`):
  mainline only tags `vX.Y`; the point releases that carry security fixes
  (`vX.Y.Z`) exist only in the stable tree.

## The loop

1. **Compare.** Fetch both trees and find the newest release tag:
   ```bash
   cd /home/nodevortex/VeloGuardOS && git fetch --tags --prune origin && git fetch --tags stable
   latest=$(git tag --list 'v*' --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+(\.[0-9]+)?$' | head -1)
   ```
   A non-LTS series goes end-of-life a few weeks after the next one ships —
   staying on an EOL `BASE` means no more security fixes (v7.0 sat EOL).
   If `latest` == `kernel/BASE`, nothing to do.

2. **Validate the delta against the new tag** (catches dropped config symbols and
   patch/build breaks *before* shipping). This is what `veloguard-kernel-sync`
   does — full compile, out-of-tree, non-destructive flags available:
   ```bash
   veloguard/bin/veloguard-kernel-sync --tag "$latest"        # checkout + config + full build
   # parse the trailing  VGKSYNC_JSON: {...}
   ```
   - `config:"dropped"` → our `CONFIG_` symbols didn't survive `olddefconfig`
     (unmet `depends`/`select` upstream). Inspect each in the new tree, explain,
     fix the fragment. **Don't ship a silently-degraded config.**
   - `build:"failed"` → read the first compile error; usually a renamed/removed
     upstream symbol or an API change a patch touches. Fix the fragment/patch.
   - `build:"ok"` → proceed.

3. **Bump + push** (this triggers `build-kernel.yml`):
   ```bash
   echo "$latest" > kernel/BASE          # in the veloguard-os repo
   # refresh kernel/patches/* if a rebase was needed
   git commit -am "kernel: track $latest"
   git push                               # CI builds the package, publishes a Release
   ```

4. **Hand off to the human for the trust step.** CI emits both packages and
   `out/kernel-manifest.json` (real sha256s, including the `headers` sub-block).
   Publish **both** packages to the Release, fold the block into `manifest.json`,
   then **sign with the offline release key** (`keys/SIGNING.md`) and push. The
   agent must **not** hold the signing key.

After that, users' `veloguard-update.timer` stages the new signed kernel in the
background and offers it on the next restart (opt-in checkbox → apply on reboot).

## Guardrails
- Never bypass `veloguard-kernel-sync`'s dirty-tree refusal or compile by hand.
- Never `git push` a `BASE` bump whose validation `build` wasn't `ok`.
- Never sign or fabricate `manifest.json.sig`.
