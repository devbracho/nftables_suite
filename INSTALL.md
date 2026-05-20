# nftablets Installation Guide

## Overview

The `install.sh` script automates the installation of the nftablets firewall suite, validates system dependencies, and checks policy configuration for user/group consistency.

## What Gets Installed

```
/usr/sbin/nftablets.suite.sh          - Main firewall rules generator and applier
/usr/sbin/nftablets-discover          - Policy discovery tool (from listening ports)
/etc/nftables.d/policy.conf           - Default firewall policy configuration
/var/log/nftables/                    - Log directory for firewall events
/etc/systemd/system/nftablets-refresh.service
/etc/systemd/system/nftablets-refresh.timer
```

## Installation Steps

### 1. Run Dry-Run First

Always preview what will be changed before committing:

```bash
cd scripts/nft-firewall/
sudo ./install.sh --dry-run
```

This will:
- Validate all source files exist
- Check system dependencies (nftables, dnsutils, rsyslog)
- Validate policy file syntax
- **Check that all users/groups referenced in policy actually exist on the system**
- Show exactly what would be installed

### 2. Address Any Missing Users

If the dry-run reports missing users, you have three options:

#### Option A: Create the missing users
```bash
# Create individual users
sudo useradd -s /sbin/nologin -M -r user2
sudo useradd -s /sbin/nologin -M -r user4
# ... etc

# Or create system groups
sudo groupadd -f -r developers
```

#### Option B: Remove/update entries in policy
Edit `/etc/nftables.d/policy.conf` and:
- Remove user/group sections that don't apply: `[user:username]`
- Update service user restrictions in the `users=` key
- Keep only users that exist on your system

#### Option C: Use numeric UIDs instead
Instead of referencing usernames, use their numeric UIDs directly:
```ini
[ssh]
tcp_ports=22
users=0,1000    # root (UID 0) and ppl (UID 1000)
```

### 3. Perform Installation

Once all issues are resolved:

```bash
sudo ./install.sh
```

Or install with timer enabled:

```bash
sudo ./install.sh --with-timer
```

### 4. Verify Installation

```bash
# Check firewall status
sudo nftablets.suite.sh --status

# View current rules
sudo nft list ruleset

# Test specific rules
sudo nft list chain inet firewall input
```

## Usage After Installation

### View Current Firewall Status
```bash
sudo nftablets.suite.sh --status
```

### Validate Policy Before Applying
```bash
sudo nftablets.suite.sh --dry-run
```

### Apply Firewall Rules
```bash
sudo nftablets.suite.sh
```

### Apply with Auto-Rollback Window
```bash
sudo nftablets.suite.sh --safe-apply 300
# Confirm within 300 seconds, or rules revert automatically:
sudo touch /root/.nft_ok
```

### Discover Listening Ports and Generate Policy
```bash
sudo nftablets-discover > /tmp/suggested_policy.conf
# Review before adding to actual policy
cat /tmp/suggested_policy.conf
sudo cat /tmp/suggested_policy.conf >> /etc/nftables.d/policy.conf
```

## Policy File Format

The policy file at `/etc/nftables.d/policy.conf` uses INI-style sections:

### Service Definitions (Inbound Rules)
```ini
[ssh]
tcp_ports=22
sources=0.0.0.0/0
users=root,user3
log_prefix=NFT-CONN SSH allow

[web]
tcp_ports=80,443
sources=0.0.0.0/0
```

### Per-User Egress (Outbound) Rules
```ini
[user:ppl]
egress_policy=allow_all

[user:user3]
egress_allow_domains=github.com,gitlab.com
egress_allow_tcp_ports=22,80,443

[user:jenkins]
egress_policy=block_all
```

### Group-Based Rules (Optional)
```ini
[group:developers]
egress_allow_domains=github.com,npm.js.org
egress_allow_tcp_ports=80,443
```

## System Users on This Machine

The following users are available for policy configuration:

```
Interactive/Shell Users:
  - ppl (UID 1000) - primary user
  - user3 (UID 1003) - admin account
  - p1rogit (UID 1001) - developer account

System Services (commonly used in policy):
  - root (UID 0) - system root
  - http (UID 33) - web server
  - postgres (UID 957) - database server
  - mongodb (UID 956) - database server
  - mysql (UID 952) - database server
  - redis (UID 955) - cache server
  - jenkins (UID 948) - CI/CD server
  - git (UID 964) - git service
  - transmission (UID 169) - torrent daemon
  - openvpn (UID 961) - VPN daemon
```

**Full user list available in `/etc/passwd`:**
```bash
getent passwd | awk -F: '{print $1, "(" $3 ")"}'
```

## Troubleshooting

### Script Reports Missing Users
```
✗ User/group 'user2' DOES NOT EXIST
```

**Solution:** Either create the user, remove from policy, or use numeric UID.

### Dependencies Missing
```
✗ nftables is NOT installed (required)
```

**Solution:** Install missing packages:
```bash
sudo apt-get update
sudo apt-get install -y nftables dnsutils rsyslog
```

### Permission Denied During Install
Ensure you're running as root:
```bash
sudo ./install.sh
```

### Firewall Rules Not Taking Effect
```bash
# Verify nftables is running
sudo systemctl status nftables

# Check policy syntax
sudo nftablets.suite.sh --dry-run

# View actual rules loaded
sudo nft list ruleset
```

### Can't SSH After Applying Firewall
Emergency recover:
```bash
# Flush all rules (allows everything temporarily)
sudo nft flush ruleset

# Fix policy and reapply
sudo nftablets.suite.sh --dry-run
sudo nftablets.suite.sh
```

## Monitoring Firewall Activity

### View Real-Time Logs
```bash
# Watch dropped packets
sudo tail -f /var/log/nftables/attempts.log

# Watch allowed connections
sudo tail -f /var/log/nftables/connections.log

# Both logs simultaneously
sudo tail -f /var/log/nftables/*.log
```

### Check Rule Counters
```bash
# Show packet/byte counts for each rule
sudo nft list ruleset

# Watch counters update
watch -n1 'sudo nft list ruleset | grep -A5 "chain input"'
```

## Optional: Enable Hourly Refresh Timer

For automatic DNS snapshot updates (useful if you have domain-based egress rules):

```bash
sudo systemctl enable nftablets-refresh.timer
sudo systemctl start nftablets-refresh.timer

# Check next scheduled run
sudo systemctl list-timers nftablets-refresh.timer

# View timer logs
sudo journalctl -u nftablets-refresh.service -f
```

## Policy Best Practices

1. **Start Permissive**: Begin with `allow_all` rules, then restrict gradually
2. **Test Changes**: Always use `--dry-run` before applying with `--safe-apply`
3. **Document Rules**: Use `log_prefix=` to clearly mark what each rule allows
4. **User Groups**: Create policy groups for related users to avoid duplication
5. **DNS for Egress**: If you specify domains, TCP/UDP 53 are auto-granted for DNS
6. **IP Ranges**: Use CIDR notation for subnets (e.g., `192.168.1.0/24`)

## Support and More Info

- **Main Script Help**: `sudo nftablets.suite.sh --help`
- **Discover Tool Help**: `sudo nftablets-discover --help`
- **nftables Manual**: `man nft`
- **Policy File Location**: `/etc/nftables.d/policy.conf`

## Installation Completed!

After running `install.sh`, the firewall suite is ready to use. Review the policy file, test with `--dry-run`, and apply when ready.

```bash
# Review policy
sudo nano /etc/nftables.d/policy.conf

# Validate
sudo nftablets.suite.sh --dry-run

# Apply
sudo nftablets.suite.sh

# Check status
sudo nftablets.suite.sh --status
```
