## nftablets.suite.sh

### Overview
 - Generates and applies an nftables ruleset from a plain-text policy (`/etc/nftables.d/policy.conf` by default).
 - Performs syntax validation, takes backups, and configures logging before activating changes.
 - Supports dry runs and status reporting so you can inspect rule output without touching the live firewall.

### Prerequisites
 - Run as root (`sudo scripts/iptables/nftablets.suite.sh ...`).
 - `nft` binary available (package `nftables`).
 - `rsyslog` optional but recommended for capturing log prefixes (`NFT-CONN`, `NFT-ATTEMPT`).
 - Policy file readable by root; directory writable when using `--init-config`.

### CLI Options
 - `--dry-run` Validates the policy and renders the batch ruleset without applying it.
 - `--status` Shows the current nftables ruleset, listening sockets, interface summary, and log tail.
 - `--init-config` Creates the default policy template if it is missing.
 - `--help` Prints the usage synopsis.

### Policy Format
 - Services are declared in INI-like stanzas (`[service-name]`).
 - Keys accept comma-separated values (whitespace ignored).
 - Recognized keys:
	 - `tcp_ports`, `udp_ports`: single ports (`22`) or ascending ranges (`5900-5920`).
	 - `sources`: IPv4 CIDRs (`192.168.1.0/24`).
	 - `users`: usernames or numeric user IDs to restrict socket owner.
	 - `log_prefix`: optional prefix for accept-logs (default `NFT-CONN <service> allow`).
 - Example: `scripts/iptables/nftablets.policy.conf`.

### Workflow
 1. Copy the automation helpers into your path for system-wide use, e.g.
		- `sudo install -m 0755 scripts/iptables/nftablets.suite.sh /usr/sbin/nftablets.suite.sh`
		- `sudo install -m 0755 scripts/iptables/nftablets_discover.py /usr/sbin/nftablets-discover`
 2. `sudo nftablets.suite.sh --dry-run` confirms the policy parses and `nft -c` accepts the render.
 3. Review the generated rules (dry-run output) or run `sudo nft list ruleset` after applying.
 4. Apply live: `sudo nftablets.suite.sh`.
 5. Persist ruleset (handled automatically by writing `/etc/nftables.conf` and touching `nftables.service`).

### Logging & Backups
 - Drop and accept events log under `/var/log/nftables/` once `rsyslog` reloads.
 - Existing ruleset is backed up to `/root/nftables.backup.<timestamp>.rules` before changes.

### Discovering Current Listeners
 - Generate policy suggestions from active sockets: `sudo scripts/iptables/nftablets_discover.py` (or the installed path such as `sudo nftablets-discover`).
 - Redirect output to append/update the policy file, e.g. `sudo nftablets-discover >> /etc/nftables.d/policy.conf` (review before appending).
 - After adding new entries, run `sudo nftablets.suite.sh --dry-run` to validate before applying live.
 - Review the proposed stanzas, adjust `sources`/`log_prefix`, then append to `/etc/nftables.d/policy.conf`.
 - Rerun `sudo nftablets.suite.sh --dry-run` to validate before applying live.

### Troubleshooting
 - Port validation failures are reported with the offending service and field.
 - Ensure ranges are ascending and inside `1-65535`.

## nftablets.suite.sh

### Overview
 - Generates and applies an nftables ruleset from a plain‑text policy (`/etc/nftables.d/policy.conf` by default).
 - Validates syntax, takes backups, configures logging, and applies atomically.
 - Supports dry runs, safe‑apply with auto‑rollback, and a status report (rules, sockets, interfaces, logs).
 - Defaults: inbound DROP (allow via services), outbound DROP (allow via per‑user egress).

### Prerequisites
 - Run as root (e.g., `sudo ./scripts/nft-firewall/nftablets.suite.sh ...`).
 - Packages:
	 - `nftables` (provides `nft`)
	 - `dnsutils` (or equivalent, provides `dig`) for domain resolution
	 - `rsyslog` optional (routes `NFT-CONN`, `NFT-ATTEMPT`, `NFT-EGR` into `/var/log/nftables/*`)
 - Policy file readable by root; directory writable when using `--init-config`.

### Install
 ```bash
 sudo install -m 0755 scripts/nft-firewall/nftablets.suite.sh /usr/sbin/nftablets.suite.sh
sudo install -m 0755 scripts/nft-firewall/nftablets_discover.py /usr/sbin/nftablets-discover
 sudo mkdir -p /etc/nftables.d
 sudo install -m 0644 scripts/nft-firewall/nftablets.policy.conf /etc/nftables.d/policy.conf
 ```
 Debian/Ubuntu dependencies:
 ```bash
 sudo apt-get update
 sudo apt-get install -y nftables dnsutils rsyslog
 ```

Install auto-refresh timer (optional but recommended for domain snapshots):
```bash
sudo install -m 0644 scripts/nft-firewall/systemd/nftablets-refresh.service /etc/systemd/system/nftablets-refresh.service
sudo install -m 0644 scripts/nft-firewall/systemd/nftablets-refresh.timer /etc/systemd/system/nftablets-refresh.timer
sudo systemctl daemon-reload
sudo systemctl enable --now nftablets-refresh.timer
sudo systemctl list-timers | grep nftablets-refresh || true
```

### CLI Options
 - `--dry-run` Validate configuration and render rules without applying.
 - `--status` Show current ruleset, listening sockets, interfaces, and recent logs.
 - `--init-config` Create the default policy template if missing.
 - `--safe-apply S` Apply with an automatic rollback after `S` seconds unless confirmed.
 - `--help` Print usage.

### Safe Apply (Auto‑Rollback)
 - Prevents lockouts while testing firewall changes.
 ```bash
 sudo env NFTABLES_POLICY_FILE="/etc/nftables.d/policy.conf" \
	 /usr/sbin/nftablets.suite.sh --safe-apply 120
 # If everything is fine, confirm and cancel rollback:
 sudo touch /root/.nft_ok
 sudo systemctl stop nft-rollback-<ID>
 ```
 - If you do nothing, rules auto‑revert after the timer using the pre‑apply backup.

### Policy Format
 - INI‑like stanzas; keys accept comma‑separated values (whitespace ignored).
 - Service stanzas (inbound allow‑list):
	 - `tcp_ports`, `udp_ports`: single ports (`22`) or ascending ranges (`5900-5920`).
	 - `sources`: IPv4 CIDRs (`192.168.1.0/24`, `0.0.0.0/0`).
	 - `users`: restrict inbound to sockets owned by given usernames/UIDs (optional).
	 - `log_prefix`: accept log prefix (default `NFT-CONN <service> allow`).
 - Per‑user egress stanzas (outbound allow‑list): header `[user:USERNAME]` with keys:
	 - `egress_policy`: `allow_all` | `block_all` (default `block_all`)
	 - `egress_allow_domains`: comma‑separated domains (resolved to IPv4 A records at apply time)
	 - `egress_allow_tcp_ports`, `egress_allow_udp_ports`: ports allowed to those domains
	 - If only domains are given, TCP 80,443 are assumed.
 - Global blocklist (best‑effort snapshot): any stanza can add `block_domains=domain1,domain2` to block egress to their resolved IPv4s.

### Examples
 ```ini
 [ssh]
 tcp_ports=22
 sources=0.0.0.0/0
 log_prefix=NFT-CONN SSH allow

 [web]
 tcp_ports=80,443
 sources=0.0.0.0/0

 # Per-user egress (default outbound policy is DROP)
 [user:ppl]
 egress_policy=allow_all

 [user:user3]
 egress_allow_domains=example.com,github.com
 egress_allow_tcp_ports=80,443

 [user:p1rogit]
 egress_policy=block_all

 # Optional global blocklist (snapshot at apply time)
 [block_sites]
 block_domains=pastebin.com,dropbox.com
 ```

### Typical Workflow
 ```bash
 # 1) Initialize template if needed
 sudo /usr/sbin/nftablets.suite.sh --init-config

 # 2) Edit policy
 sudoedit /etc/nftables.d/policy.conf

 # 3) Validate without applying
 sudo /usr/sbin/nftablets.suite.sh --dry-run

 # 4) Apply safely with rollback window
 sudo /usr/sbin/nftablets.suite.sh --safe-apply 300

 # 5) Confirm keep (or let it auto-revert)
 sudo touch /root/.nft_ok
 sudo systemctl stop nft-rollback-<ID>

 # 6) Inspect current state
 sudo /usr/sbin/nftablets.suite.sh --status
 ```

### What the Script Enforces
 - Table/chains: `table inet firewall` with `input`, `output`, `forward` (DROP by default).
 - Base allows: loopback, established/related; ICMP echo on input.
 - Inbound allows: generated from service stanzas.
 - Outbound: default DROP; per‑user allows via `meta skuid`:
	 - Domains resolved at apply time to IPv4 sets; traffic allowed only to those IPs and ports.
	 - Users with domain rules get DNS to system resolvers automatically (UDP/TCP 53).
	 - System resolver user (systemd‑resolve[d]) also gets DNS to `/etc/resolv.conf` nameservers.
 - Persistence: writes `/etc/nftables.conf` and enables/restarts `nftables.service` if present.

### Testing
 ```bash
 # As current user (e.g., ppl)
 curl -I https://github.com
 curl -I https://example.com

 # As specific users
 sudo -u user3 curl -I https://github.com
 sudo -u user3 curl -I https://google.com   # expect block
 sudo -u p1rogit  curl -I https://example.com  # expect block

 # Inspect output chain counters
 sudo nft list ruleset | sed -n '/chain output/,/chain/p'
 ```

### Logging & Backups
 - Backups: `/root/nftables.backup.<timestamp>.rules` before apply; `/root/nftables.rollback.rules` for safe‑apply.
 - Logs (when `rsyslog` installed):
	 - Drops -> `/var/log/nftables/attempts.log` (prefix `NFT-ATTEMPT`)
	 - Allows -> `/var/log/nftables/connections.log` (prefixes `NFT-CONN`, `NFT-EGR`)

### Disable / Re‑enable nftables
 ```bash
 # Flush now
 sudo nft flush ruleset

 # Disable at boot
 sudo systemctl stop nftables
 sudo systemctl disable nftables
 sudo systemctl mask nftables

 # Re‑enable
 sudo systemctl unmask nftables
 sudo systemctl enable --now nftables
 ```

### Notes & Caveats
 - IPv4 only: current implementation uses A records and `ipv4_addr` sets. IPv6 can be added if needed.
 - Domain resolution: allow‑lists/block‑lists are snapshots at apply time; CDNs and fast‑changing IPs may need periodic re‑apply or broader IP ranges.
 - Containers/daemons: egress matching uses process UID (`meta skuid`). Ensure the UID reflects the process initiating network connections.
 - Other managers: disable or coordinate with `ufw`, `firewalld`, or `netfilter-persistent` to avoid conflicts.
## nftablets.suite.sh

### Overview
- Generates and applies an nftables ruleset from a plain-text policy (`/etc/nftables.d/policy.conf` by default).
- Performs syntax validation, takes backups, and configures logging before activating changes.
- Supports dry runs and status reporting so you can inspect rule output without touching the live firewall.

### Prerequisites
- Run as root (`sudo scripts/iptables/nftablets.suite.sh ...`).
- `nft` binary available (package `nftables`).
- `rsyslog` optional but recommended for capturing log prefixes (`NFT-CONN`, `NFT-ATTEMPT`).
- Policy file readable by root; directory writable when using `--init-config`.

### CLI Options
- `--dry-run` Validates the policy and renders the batch ruleset without applying it.
- `--status` Shows the current nftables ruleset, listening sockets, interface summary, and log tail.
- `--init-config` Creates the default policy template if it is missing.
- `--help` Prints the usage synopsis.

### Policy Format
- Services are declared in INI-like stanzas (`[service-name]`).
- Keys accept comma-separated values (whitespace ignored).
- Recognized keys:
	- `tcp_ports`, `udp_ports`: single ports (`22`) or ascending ranges (`5900-5920`).
	- `sources`: IPv4 CIDRs (`192.168.1.0/24`).
	- `users`: usernames or numeric user IDs to restrict socket owner.
	- `log_prefix`: optional prefix for accept-logs (default `NFT-CONN <service> allow`).
- Example: `scripts/iptables/nftablets.policy.conf`.

### Workflow
1. Copy the automation helpers into your path for system-wide use, e.g.
	- `sudo install -m 0755 scripts/iptables/nftablets.suite.sh /usr/sbin/nftablets.suite.sh`
	- `sudo install -m 0755 scripts/iptables/nftablets_discover.py /usr/sbin/nftablets-discover`
2. `sudo nftablets.suite.sh --dry-run` confirms the policy parses and `nft -c` accepts the render.
3. Review the generated rules (dry-run output) or run `sudo nft list ruleset` after applying.
4. Apply live: `sudo nftablets.suite.sh`.
5. Persist ruleset (handled automatically by writing `/etc/nftables.conf` and touching `nftables.service`).

### Logging & Backups
- Drop and accept events log under `/var/log/nftables/` once `rsyslog` reloads.
- Existing ruleset is backed up to `/root/nftables.backup.<timestamp>.rules` before changes.

### Discovering Current Listeners
- Generate policy suggestions from active sockets: `sudo scripts/iptables/nftablets_discover.py` (or the installed path such as `sudo nftablets-discover`).
- Redirect output to append/update the policy file, e.g. `sudo nftablets-discover >> /etc/nftables.d/policy.conf` (review before appending).
- After adding new entries, run `sudo nftablets.suite.sh --dry-run` to validate before applying live.
- Review the proposed stanzas, adjust `sources`/`log_prefix`, then append to `/etc/nftables.d/policy.conf`.
- Rerun `sudo nftablets.suite.sh --dry-run` to validate before applying live.

### Troubleshooting
- Port validation failures are reported with the offending service and field.
- Ensure ranges are ascending and inside `1-65535`.

---

## Git Access Control Wrapper

### Overview
Application-level git access control that complements firewall rules to:
- Allow GitHub Copilot authentication while blocking repository cloning via HTTPS
- Permit SSH-based GitHub access for specific users
- Enforce internal GitLab-only access for restricted users

### Components
- `/usr/local/bin/git-access-control` - Main wrapper script
- `/etc/profile.d/git-access-control.sh` - Shell integration for controlled users
- `/usr/local/bin/install-git-wrapper.sh` - Installer
- `/usr/local/bin/uninstall-git-wrapper.sh` - Uninstaller

### User Groups

**[group:open]** - Fully unrestricted
- Members: `root, user1, user2, _apt, promtail, git`
- No firewall or git restrictions

**[group:ssh_github]** - GitHub SSH + Copilot
- Members: `user3, user14, user15`
- Firewall: Allows SSH (port 22), HTTPS (443) to GitHub IP ranges
- Git wrapper: Blocks HTTPS git clone/push, allows SSH git operations
- Access: GitHub Copilot, SSH clone, internal GitLab

**[group:ai_tools]** - AI Tools Only
- Members: `user17`
- Firewall: Allows HTTPS (443, 8080) but NO SSH (port 22)
- Git wrapper: Blocks all GitHub repository operations
- Access: ChatGPT, Claude Sonnet, GitHub Copilot authentication only

**[group:restricted]** - Internal Only
- Members: `user4, user5, user6, user7, user8, user9, user10, user11, user12, user13`
- Firewall: Allows internal networks only (192.168.1.0/24, 10.66.66.0/24)
- Git wrapper: Blocks external GitHub
- Access: Internal GitLab, PyPI, Python.org (via CDN ranges)

### Installation

```bash
# Copy wrapper and configuration
sudo cp /path/to/nftables/scripts/nft-firewall/git-access-control /usr/local/bin/
sudo cp /path/to/nftables/scripts/nft-firewall/git-access-control.sh /etc/profile.d/
sudo chmod +x /usr/local/bin/git-access-control

# Users need to logout/login for alias to take effect
# Or source manually:
source /etc/profile.d/git-access-control.sh
```

### Policy Configuration

The policy file uses CIDR ranges to avoid DNS resolution conflicts:
- `140.82.112.0/20` = github.com
- `185.199.108.0/22` = GitHub Pages/CDN (githubassets, githubusercontent, pyenv.run)
- `151.101.0.0/16` = Fastly CDN (GitHub, PyPI, Python.org)

Example policy stanza:
```ini
[group:ssh_github]
members=user3,user14,user15
egress_policy=block_all
egress_allow_domains=192.168.1.0/24,10.66.66.0/24,140.82.112.0/20,185.199.108.0/22,151.101.0.0/16,bitbucket.org,artefact.skao.int,google.com
egress_allow_tcp_ports=22,80,443,8080
```

### Testing

**For ssh_github users (user3, user14, user15):**
```bash
# Should BLOCK
git clone https://github.com/user/repo.git

# Should ALLOW
git clone git@github.com:user/repo.git
git clone git@192.168.1.11:group/project.git
curl -I https://github.com/login  # Copilot auth
```

**For ai_tools users (user17):**
```bash
# Should BLOCK
git clone https://github.com/user/repo.git
git clone git@github.com:user/repo.git  # SSH blocked by firewall

# Should ALLOW
curl -I https://github.com/login  # Copilot auth
curl -I https://chat.openai.com   # ChatGPT
curl -I https://claude.ai         # Claude Sonnet
```

**For restricted users:**
```bash
# Should BLOCK
curl -I https://github.com
git clone https://github.com/user/repo.git

# Should ALLOW
git clone git@192.168.1.11:group/project.git
curl -I https://pypi.org
```

### Common Issues

**GitHub domain resolution conflicts:**
- GitHub uses multiple IPs that rotate
- Solution: Use CIDR ranges instead of domain names in policy
- The script resolves domains once at apply time

**Git wrapper not active:**
- Users must logout/login after installation
- Or run: `source /etc/profile.d/git-access-control.sh`
- Test with: `type git` (should show alias to wrapper)

**Browser can't access github.com:**
- Firewall requires GitHub CDN ranges (185.199.108.0/22, 151.101.0.0/16)
- Check logs: `tail -f /var/log/nftables/attempts.log`
- Verify IPs: `sudo nft list set inet firewall u_user_USERNAME_egress_ips`

### VS Code Integration

**Problem**: VS Code may bypass the git wrapper by using system git directly

**Solution**: Configure VS Code to use the wrapper explicitly

```bash
# For single user (e.g., user16)
sudo -u user16 bash -c 'mkdir -p ~/.config/Code/User && cat > ~/.config/Code/User/settings.json << "EOF"
{
    "git.path": "/usr/local/bin/git-access-control"
}
EOF'

# Apply to all controlled users
for user in user14 user15 user16 user17 user4 user5 user6 user7 user8 user9 user10 user11 user12 user13; do
    sudo -u "$user" bash -c 'mkdir -p ~/.config/Code/User && echo "{\"git.path\": \"/usr/local/bin/git-access-control\"}" > ~/.config/Code/User/settings.json' 2>/dev/null || echo "Skipped $user"
done
```

**User must restart VS Code** after configuration change.

**Verification:**
```bash
# Check if VS Code is using wrapper
grep "git.path" ~/.config/Code/User/settings.json

# Test in VS Code:
# 1. Try cloning GitHub repo (should show ERROR from wrapper)
# 2. Internal GitLab should still work
```

### Automated Security Checks

**Purpose**: Detect and remediate users attempting to bypass git wrapper

**Installation**:
```bash
# Install security check script
sudo install -m 0755 scripts/nft-firewall/vscode-security-check.sh /usr/local/bin/

# Install systemd timer (runs hourly)
sudo install -m 0644 scripts/nft-firewall/systemd/vscode-security-check.service /etc/systemd/system/
sudo install -m 0644 scripts/nft-firewall/systemd/vscode-security-check.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vscode-security-check.timer

# Check timer status
systemctl list-timers vscode-security-check.timer
```

**What it does**:
- Checks all users in `ai_tools_full`, `ai_tools_basic`, `restricted` groups
- Detects tampering (git.path changed to different binary)
- Auto-corrects violations by restoring secure wrapper
- Sends email alerts via GitLab SMTP for violations
- Logs to `/var/log/vscode-security-check.log` and `/var/log/vscode-security-violations.log`
- Runs every hour (OnCalendar=hourly)

**Manual test**:
```bash
# Create violation
sudo -u someuser bash -c 'echo "{\"git.path\": \"/usr/bin/git\"}" > ~/.config/Code/User/settings.json'

# Run check
sudo /usr/local/bin/vscode-security-check.sh

# Should detect violation, fix it, and send email
```

### Multi-Machine Email Relay

**For machines without GitLab** (pcw02lin, hp-probook):

1. **Install email relay helper on pcw01lin**:
```bash
sudo install -m 0755 scripts/nft-firewall/send-alert-email.sh /usr/local/bin/
```

2. **Set up SSH keys from other machines to pcw01lin**:
```bash
# On pcw02lin or hp-probook (as root)
ssh-keygen -t ed25519 -f /root/.ssh/id_email_relay -N ""
ssh-copy-id -i /root/.ssh/id_email_relay root@pcw01lin

# Test
ssh pcw01lin "/usr/local/bin/send-alert-email.sh 'Test Alert' 'Testing from $(hostname)'"
```

3. **Deploy security check script** - it auto-detects:
   - If on pcw01lin: uses local gitlab-rails
   - If on other machine: SSH to pcw01lin and uses relay

4. **Deploy timer on all machines**:
```bash
# On each machine (pcw02lin, hp-probook)
sudo install -m 0755 scripts/nft-firewall/vscode-security-check.sh /usr/local/bin/
sudo install -m 0644 scripts/nft-firewall/systemd/vscode-security-check.service /etc/systemd/system/
sudo install -m 0644 scripts/nft-firewall/systemd/vscode-security-check.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vscode-security-check.timer
```

**Email configuration** (in script):
- FROM: `devbracho@gmail.com`
- TO: `devbracho@gmail.com`
- Change via environment: `EMAIL_FROM=... EMAIL_TO=... /usr/local/bin/vscode-security-check.sh`

### Maintenance

**Adding users to groups:**
1. Edit `/etc/nftables.d/policy.conf`
2. Add username to appropriate `members=` line
3. Apply firewall: `sudo /usr/sbin/nftablets.suite.sh`
4. Configure VS Code (if applicable): `sudo -u USERNAME bash -c 'mkdir -p ~/.config/Code/User && echo "{\"git.path\": \"/usr/local/bin/git-access-control\"}" > ~/.config/Code/User/settings.json'`
5. User logout/login (for shell alias) or restart VS Code

**Removing git wrapper:**
```bash
sudo /usr/local/bin/uninstall-git-wrapper.sh
```
# nftables_suite
