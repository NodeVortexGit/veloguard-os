#!/usr/bin/env bash
#
# calamares-target-cleanup — runs INSIDE the freshly-installed system (chroot)
# during install, before the initramfs is regenerated. The install copies the
# live squashfs 1:1, so everything that makes the live ISO "live" must be
# stripped here or the installed system boots like (or fails like) the ISO.
set -u

# 1. archiso initramfs machinery → stock Arch initramfs
rm -f /etc/mkinitcpio.conf.d/archiso.conf
cat > /etc/mkinitcpio.d/linux.preset <<'EOF'
# mkinitcpio preset file for the 'linux' package (restored by VeloGuardOS installer)
ALL_kver="/boot/vmlinuz-linux"

PRESETS=('default' 'fallback')

default_image="/boot/initramfs-linux.img"

fallback_image="/boot/initramfs-linux-fallback.img"
fallback_options="-S autodetect"
EOF

# 2. live-session autologin (tty + SDDM + GDM) must not reach the installed
#    system. The SDDM drop-in names the live account "veloguard", which does
#    not exist here — the installed system tried to autologin a ghost user.
rm -rf /etc/systemd/system/getty@tty1.service.d
rm -f  /etc/sddm.conf.d/10-veloguard-autologin.conf /etc/gdm/custom.conf

# 3. live-only units + their activation links (releng's live helpers, its
#    cloud-init wiring, and our live-boot hardware probe for the installer)
for u in pacman-init.service choose-mirror.service veloguard-live-user.service \
         reflector.service reflector.timer etc-pacman.d-gnupg.mount \
         livecd-talk.service livecd-alsa-unmuter.service veloguard-hwprobe.service \
         cloud-config.service cloud-final.service cloud-init-local.service \
         cloud-init-main.service cloud-init-network.service; do
    rm -f "/etc/systemd/system/$u" \
          "/etc/systemd/system/"*.wants/"$u" 2>/dev/null
done
systemctl disable --no-reload reflector.service reflector.timer >/dev/null 2>&1 || true

# 4. live NOPASSWD sudo: the users module writes proper %wheel sudoers
rm -f /etc/sudoers.d/10-wheel-nopasswd

# 5. the installer itself makes no sense on an installed system
rm -f /usr/share/applications/install-to-disk.desktop \
      /usr/share/applications/install-to-disk-advanced.desktop \
      /etc/polkit-1/rules.d/49-veloguard-live-calamares.rules
for p in calamares ckbcomp archinstall; do
  pacman -Q "$p" >/dev/null 2>&1 && pacman -Rns --noconfirm "$p" >/dev/null 2>&1
done
rm -rf /etc/calamares /usr/lib/calamares /usr/share/calamares

# 6. archiso login cosmetics
rm -f /root/.automated_script.sh /root/.zlogin /etc/motd 2>/dev/null

# 7. releng's live-session system policy, which the squashfs copy carried
#    straight into every install:
#    - logind ignored the lid switch and suspend keys (a laptop never slept
#      with the lid shut),
#    - journald kept logs in RAM only (every boot's logs gone at shutdown),
#    - resolved announced the hostname over mDNS on every network,
#    - sshd was enabled with PermitRootLogin + password auth.
rm -f /etc/systemd/logind.conf.d/do-not-suspend.conf \
      /etc/systemd/journald.conf.d/volatile-storage.conf \
      /etc/systemd/resolved.conf.d/archiso.conf \
      /etc/ssh/sshd_config.d/10-archiso.conf \
      /etc/systemd/system/multi-user.target.wants/sshd.service

# 8. root: the live image's /etc/shadow has an EMPTY root password and the
#    users module doesn't set one (setRootPassword: false) — so `su` gave any
#    local process root with no password. Administration is sudo via %wheel;
#    lock an empty root password (`sudo passwd root` sets one deliberately;
#    a password the users module was configured to set is left alone).
[ -z "$(getent shadow root | cut -d: -f2)" ] && passwd -l root >/dev/null

# 9. pacman keyring. On the live system /etc/pacman.d/gnupg is a tmpfs that
#    pacman-init.service fills at boot, so the squashfs (= this target) holds
#    an EMPTY keyring: every signed package — the drivers and desktop picked in
#    the installer, first-boot hardware setup, updates — failed verification.
#    Build this machine's own keyring (its own master key, not the live one).
rm -rf /etc/pacman.d/gnupg
if pacman-key --init >/dev/null 2>&1 && pacman-key --populate archlinux >/dev/null 2>&1; then
  echo "pacman keyring initialised"
else
  echo "WARNING: pacman keyring setup failed — run: sudo pacman-key --init && sudo pacman-key --populate" >&2
fi
# pacman-key leaves a gpg-agent running inside the target; it would keep the
# target busy and make the final unmount fail.
gpgconf --homedir /etc/pacman.d/gnupg --kill all >/dev/null 2>&1 || true

exit 0
