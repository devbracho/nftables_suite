---
description: "Use when editing policy.conf, firewall scripts, documentation, or any file in this nftables project. Enforces privacy rules, user tier model, single source-of-truth policy file, and safe apply workflow."
applyTo: "**"
---

# nftables Firewall Project Instructions

This project is a complete nftables-based firewall solution for multi-user Linux workstations. It enforces per-user egress control, inbound service allowlisting, and git/IDE access restrictions.

## Privacy: Never Use Real Usernames

All personal usernames in policy files, scripts, and documentation must use anonymous placeholders.

- Substitute real usernames with `user1`, `user2`, ... `userN`
- **Keep** system/service accounts as-is: `root`, `_apt`, `promtail`, `git`, `gitlab-runner`, `gitlab-www`
- Replace organisation/project names with generic equivalents (`myorg`, `nftables`)
- Replace personal email addresses — the one exception is the alert destination: `devbracho@gmail.com`
- Use `/path/to/nftables_suite` for installation path references in documentation

## policy.conf: Single Source of Truth

- There is one policy file: `policy.conf`. Do not create machine-specific variants in the project root.
- Machine-specific configs belong in `policy-configs/` and must not duplicate the root file.
- Keep 5 representative example users covering all 4 tiers (see below). Do not inflate membership lists.

## User Tier Model

Always assign users to one of these four groups. Do not invent new group names.

| Group | Purpose | Default egress |
|---|---|---|
| `group:open` | Sysadmins, service accounts, unrestricted devs | `allow_all` |
| `group:restricted` | Regular employees — internal network only | `block_all` + internal CIDRs |
| `group:ai_tools_full` | Developers with full AI tools (ChatGPT, Claude, Copilot) | `block_all` + AI domain list |
| `group:ai_tools_basic` | Copilot authentication only, no external git clone | `block_all` + Copilot domains |

Example distribution for 5 representative users:
```ini
[group:open]
members=root,user1,_apt,promtail,git,gitlab-runner
egress_policy=allow_all

[group:restricted]
members=user2,user3
egress_policy=block_all

[group:ai_tools_full]
members=user4
egress_policy=block_all

[group:ai_tools_basic]
members=user5
egress_policy=block_all
```

## Safe Apply Workflow

Never suggest applying firewall changes without this sequence:

1. `sudo nftablets.suite.sh --dry-run` — validate and render without touching live rules
2. Review rendered output; confirm no unintended ports are open
3. `sudo nftablets.suite.sh --safe-apply 120` — apply with auto-rollback window
4. Test connectivity from an affected user or source
5. Confirm keep: `sudo touch /root/.nft_ok && sudo systemctl stop nft-rollback-<ID>`

Never use bare `nftablets.suite.sh` (without `--dry-run` or `--safe-apply`) for untested changes.

## Alert Email

The default alert recipient is `devbracho@gmail.com`. Do not replace this with a placeholder.
The sender (`EMAIL_FROM`) should use a project-appropriate address — `noreply@example.com` is acceptable if no real domain is configured.

## Script Permissions

All `.sh` scripts must be installed with `chmod 755`.

## Documentation Style

- Use `/path/to/nftables_suite` for all installation path examples
- Use `github.com/devbracho/nftables_suite` as the canonical repository URL
- Inline `users=` lists in service stanzas should reference only the minimal set of users that need that specific service
