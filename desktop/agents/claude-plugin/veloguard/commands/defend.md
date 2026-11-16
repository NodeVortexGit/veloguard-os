---
description: Check this machine's defenses and tighten what's weak, with the guard
---
Review this VeloGuardOS machine's security posture and help the person tighten it. Read-only first; change nothing without their yes.

Check:
- The guard: `veloguard status`, the `status` and `list_blocked` MCP tools, `nft list table inet veloguard`.
- Network: listening services (`ss -tulpn`), sshd settings if it runs, the current Wi-Fi's trust and whether the VPN is up on an untrusted one (`classify_network`).
- Updates: the guard's `check_update` tool and pending system updates (`checkupdates` if present).
- Accounts and persistence: users with a login shell, sudoers/wheel members, cron jobs, enabled systemd units and user autostart entries that look out of place.

Then give a short list, most important first: what's fine, what's weak and why it matters, and the one-step fix for each. Apply fixes only when the person picks them — root commands go through `sudo` (Approve/Deny), guard actions through the MCP tools.
