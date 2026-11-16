#!/usr/bin/env bash
#
# install-agents.sh — the AI coding agents VeloGuard can use as its brain
# (agent plugins, /usr/share/veloguard/agents/plugins): Claude Code, Codex,
# Kimi Code, Hermes Agent, OpenClaw. Run by the installer (Calamares, in the
# target chroot) for the new account; also the way to add one later:
#
#   sudo install-agents.sh [--user NAME] [AGENT...]      # default: claude-code codex kimi
#   sudo install-agents.sh --user NAME all | none          # all five / nothing
#   veloguard-agent install codex                         # same, with an Approve click
#   install-agents.sh --pending                           # first boot: finish the rest
#
# Where each one comes from — the vendor's own channel, nothing repackaged:
#   claude-code  Anthropic's native installer    → ~/.local/bin/claude (self-updating)
#   codex        Arch [extra] openai-codex       → /usr/bin/codex
#   kimi         npm @moonshot-ai/kimi-code      → ~/.local/bin/kimi (Kimi Code; the
#                old PyPI kimi-cli is unmaintained, and the vendor's own download
#                host isn't reachable from everywhere — npm is their listed fallback)
#   hermes       Nous Research's install.sh      → ~/.hermes, ~/.local/bin/hermes
#   openclaw     npm openclaw (user prefix)      → ~/.local/bin/openclaw
# Third-party installers and npm/uv run as THE USER, never as root; only the
# distro packages (pacman) are installed as root. Then VeloGuard's plugin goes
# into each agent (veloguard-agent-connect, as the user): the guard's MCP
# tools, its rules, and a check before shell and file-edit tools.
#
# Best-effort and resumable: every agent is queued in $PENDING first and struck
# off once installed, so one failing (or the installer's time limit, or no
# network) never costs the others — veloguard-agents-pending.service installs
# whatever is left on the first online boot. Signing in is yours, per agent,
# the first time you open it (veloguard-agent set <agent>).
set -uo pipefail
say()  { printf '\033[1;36m[veloguard]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[veloguard]\033[0m %s\n' "$*" >&2; }
[ "$(id -u)" -eq 0 ] || { warn "run as root (sudo, or: veloguard-agent install <agent>)"; exit 1; }

ALL=(claude-code codex kimi hermes openclaw)
DEFAULT=(claude-code codex kimi)       # what the installer's AI agents page ticks
PENDING=/var/lib/veloguard/agents-pending
UNIT=/etc/systemd/system/veloguard-agents-pending.service
STEP_TIMEOUT=900

U=""; pending=0; want=()
while [ $# -gt 0 ]; do
  case "$1" in
    --user)    U="${2:-}"; shift 2 ;;
    --pending) pending=1; shift ;;
    -h|--help) sed -n '3,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*)        warn "unknown option $1"; exit 2 ;;
    '${'*)     shift ;;                 # a Calamares value that wasn't filled in
    *)         want+=("$1"); shift ;;
  esac
done
case " ${want[*]:-} " in
  *" none "*) echo "no AI agents picked — nothing to install"; exit 0 ;;
  *" all "*)  want=("${ALL[@]}") ;;
esac
if [ "$pending" -eq 1 ]; then
  [ -s "$PENDING" ] || { rm -f "$PENDING"; exit 0; }
  U="$(sed -n 's/^user=//p' "$PENDING" | head -1)"
  mapfile -t want < <(grep -vE '^(user=|$)' "$PENDING")
fi
[ -n "$U" ] || U="${SUDO_USER:-}"
[ -n "$U" ] || U="$(getent passwd | awk -F: '$3 >= 1000 && $3 < 60000 {print $1; exit}')"
getent passwd "$U" >/dev/null 2>&1 || { warn "no such user '$U' — pass --user NAME"; exit 1; }
[ "$U" != root ] || { warn "agents are per-user — pass --user NAME (not root)"; exit 1; }
[ ${#want[@]} -gt 0 ] || want=("${DEFAULT[@]}")
for a in "${want[@]}"; do
  case " ${ALL[*]} " in *" $a "*) ;; *) warn "unknown agent '$a' (have: ${ALL[*]})"; exit 2 ;; esac
done
H="$(getent passwd "$U" | cut -d: -f6)"
G="$(id -gn "$U")"

# As the user, with a clean, predictable environment (the chroot has no session).
as_user() {
  runuser -u "$U" -- env -i HOME="$H" USER="$U" LOGNAME="$U" SHELL=/bin/bash \
    PATH="$H/.local/bin:/usr/local/bin:/usr/bin" LANG="${LANG:-C.UTF-8}" TERM=dumb \
    timeout -s INT -k 30 "$STEP_TIMEOUT" "$@" </dev/null
}
pkgs() { timeout -s INT -k 30 "$STEP_TIMEOUT" pacman -S --noconfirm --needed "$@"; }

installed() {
  case "$1" in
    claude-code) [ -x "$H/.local/bin/claude" ] ;;
    codex)       command -v codex >/dev/null 2>&1 ;;
    kimi)        [ -x "$H/.local/bin/kimi" ] ;;
    hermes)      [ -x "$H/.local/bin/hermes" ] || [ -x "$H/.hermes/hermes-agent/venv/bin/hermes" ] ;;
    openclaw)    [ -x "$H/.local/bin/openclaw" ] || command -v openclaw >/dev/null 2>&1 ;;
  esac
}

install_one() {
  install -d -o "$U" -g "$G" "$H/.local" "$H/.local/bin"
  case "$1" in
    claude-code)
      as_user bash -c 'curl -fsSL https://claude.ai/install.sh | bash' ;;
    codex)
      pkgs openai-codex ;;
    kimi)
      pkgs nodejs npm && as_user npm install -g --prefix "$H/.local" --no-fund --no-audit @moonshot-ai/kimi-code ;;
    hermes)
      pkgs git && as_user bash -c 'curl -fsSL https://hermes-agent.nousresearch.com/install.sh \
        | bash -s -- --non-interactive --skip-browser --skip-computer-use' ;;
    openclaw)
      # User prefix: npm's install scripts run as the user, and updates
      # (openclaw update / npm i -g) need no root.
      pkgs nodejs npm && as_user npm install -g --prefix "$H/.local" --no-fund --no-audit openclaw@latest ;;
  esac
}

# --- queue everything first, strike off as each lands ----------------------
install -d /var/lib/veloguard
{ echo "user=$U"; printf '%s\n' "${want[@]}"; } > "$PENDING"
queue_unit() {
  install -Dm644 /dev/stdin "$UNIT" <<'UNIT'
[Unit]
Description=VeloGuardOS: install the AI agents the installer had to postpone
ConditionPathExists=/var/lib/veloguard/agents-pending
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/veloguard/provision/install-agents.sh --pending
Restart=on-failure
RestartSec=5min

[Install]
WantedBy=multi-user.target
UNIT
  mkdir -p /etc/systemd/system/multi-user.target.wants
  ln -sf ../veloguard-agents-pending.service \
    /etc/systemd/system/multi-user.target.wants/veloguard-agents-pending.service
}
queue_unit

failed=()
for a in "${want[@]}"; do
  if installed "$a"; then
    say "$a: already installed"
  else
    say "installing $a for $U…"
    if ! install_one "$a" || ! installed "$a"; then
      warn "$a: not installed yet"
      failed+=("$a"); continue
    fi
    say "$a: installed"
  fi
  sed -i "/^${a}\$/d" "$PENDING"
done

# VeloGuard's plugin into every agent that's there (best-effort; re-run any
# time: veloguard-agent connect).
if [ -x /usr/local/bin/veloguard-agent-connect ]; then
  as_user /usr/local/bin/veloguard-agent-connect || warn "some agents didn't take the VeloGuard plugin — later: veloguard-agent connect"
fi

if [ ${#failed[@]} -eq 0 ]; then
  rm -f "$PENDING" "$UNIT" /etc/systemd/system/multi-user.target.wants/veloguard-agents-pending.service
  say "AI agents ready: ${want[*]} — pick one as the brain: veloguard-agent set <agent>"
  exit 0
fi
warn "still to install: ${failed[*]} — retried on the next online boot (or: veloguard-agent install ${failed[*]})"
exit 1
