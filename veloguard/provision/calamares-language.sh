#!/usr/bin/env bash
# calamares-language.sh [LOCALE] — the installed system's language, all of it
# (LANG only, no LC_* mix). LOCALE: en_US.UTF-8 (default) | bg_BG.UTF-8 |
# ja_JP.UTF-8. Runs in the target chroot (shellprocess@veloguardlanguage).
set -euo pipefail
lang="${1:-}"
case "$lang" in
  en_US.UTF-8|bg_BG.UTF-8|ja_JP.UTF-8) ;;
  *) lang=en_US.UTF-8 ;;          # nothing picked (or not substituted): English
esac
for l in en_US bg_BG ja_JP; do
  sed -i -E "s/^#\s*(${l}\.UTF-8 UTF-8)/\1/" /etc/locale.gen
  grep -q "^${l}.UTF-8 UTF-8" /etc/locale.gen || echo "${l}.UTF-8 UTF-8" >> /etc/locale.gen
done
locale-gen >/dev/null
printf 'LANG=%s\n' "$lang" > /etc/locale.conf
echo "system language: $lang"
