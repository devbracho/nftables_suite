# Complete Deployment Guide
## nftables Firewall + Alerting

This guide covers deploying the nftables firewall suite on Linux.

---

## 🎯 What Gets Deployed

1. **nftables Firewall** - Group-based egress control (ai_tools_full, ai_tools_basic, restricted)
2. **Email Alerts** - Violations sent to mailexample@gmail.com via Alertmanager / SMTP

---

## 📦 Prerequisites

### On Target Machine
```bash
# Install required packages
sudo apt-get update
sudo apt-get install -y nftables dnsutils rsyslog git

# Clone repository
git clone https://github.com/devbracho/nftables_suite.git
# OR if already cloned:
cd nftables_suite && git pull origin main
```

### On Alert Server (email relay host)
```bash
# Already installed - verify email relay works
sudo /usr/local/bin/send-alert-email.sh "Test from $(hostname)" "Testing email relay"
```

---

## 🚀 Quick Deployment (Full Stack)

### Step 1: Deploy Firewall

```bash
cd nftables_suite

# Install nftablets.suite.sh
sudo install -m 0755 nftablets.suite.sh /usr/sbin/nftablets.suite.sh

# Copy policy configuration (IMPORTANT: Review and customize for this machine!)
sudo mkdir -p /etc/nftables.d
sudo cp policy.conf /etc/nftables.d/policy.conf

# CUSTOMIZE POLICY: Edit for this machine's users
sudo vim /etc/nftables.d/policy.conf
# - Update [group:ai_tools_full] members list
# - Update [group:ai_tools_basic] members list  
# - Update [group:restricted] members list
# - Verify egress_allow_domains include necessary CDN ranges

# Test firewall (dry-run first!)
sudo /usr/sbin/nftablets.suite.sh --dry-run

# Apply firewall (use safe-apply for rollback protection)
sudo /usr/sbin/nftablets.suite.sh --safe-apply 120
# Confirm within 120 seconds:
sudo touch /root/.nft_ok

# Verify rules
sudo nft list ruleset | head -50
```


## ✅ Verification Tests

### Test 1: Firewall (Egress Control)

```bash
# Test as ai_tools_full user (should ALLOW Copilot, BLOCK GitHub clone)
sudo -u user4 curl -I https://github.com/login  # ✓ Should succeed (ai_tools_full)
sudo -u user4 curl -I https://chat.openai.com   # ✓ Should succeed (ai_tools_full)

# Test as restricted user (should BLOCK external)
sudo -u user2 curl -I https://github.com  # ✗ Should timeout or block
```

### Test 2: Email Alerts

```bash
# On the alert server:
sudo /usr/local/bin/send-alert-email.sh "Test from $(hostname)" "Direct test"
```

---

## 🔧 Configuration Files Reference

### `/etc/nftables.d/policy.conf`
- **[group:open]**: Unrestricted users (root, user1, _apt, promtail, git, gitlab-runner)
- **[group:restricted]**: Internal network only (user2, user3)
- **[group:ai_tools_full]**: Full AI tools — ChatGPT, Claude, Copilot (user4)
- **[group:ai_tools_basic]**: Copilot authentication only (user5)

**Critical IP ranges** (for Copilot Chat):
- GitHub: `140.82.112.0/20, 185.199.108.0/22, 151.101.0.0/16`
- Microsoft Azure: `13.107.0.0/16, 20.0.0.0/8, 40.0.0.0/8, 52.0.0.0/8, 104.0.0.0/8`
- Akamai CDN: `23.0.0.0/8, 95.100.0.0/16, 150.171.0.0/16, 173.222.0.0/15`

### Scripts Locations

**Firewall:**
- `/usr/sbin/nftablets.suite.sh` - Main firewall orchestration
- `/etc/nftables.d/policy.conf` - Single source of truth for all rules

**Alerts:**
- `/usr/local/bin/send-alert-email.sh` - Email relay helper

**Logs:**
- `/var/log/nftables/attempts.log` - Firewall drops
- `/var/log/nftables/connections.log` - Firewall allows

---

## 👥 Adding New Users

```bash
# 1. Edit policy file
sudo vim /etc/nftables.d/policy.conf
# Add username to appropriate [group:*] members= line

# 2. Apply firewall
sudo nft flush ruleset
sudo /usr/sbin/nftablets.suite.sh

# Done!
```

---

## 🗑️ Uninstall / Rollback

```bash
# Remove firewall
sudo nft flush ruleset
sudo systemctl stop nftables
sudo systemctl disable nftables

# Restore VS Code default git
for user in $(awk -F: '$3>=1000 && $3<60000 {print $1}' /etc/passwd); do
    sudo -u "$user" bash -c 'rm -f ~/.config/Code/User/settings.json' 2>/dev/null
done
```

---

## 📊 Monitoring & Maintenance

### View Firewall Status
```bash
sudo /usr/sbin/nftablets.suite.sh --status
sudo nft list ruleset | grep -A5 "chain output"
tail -f /var/log/nftables/attempts.log  # Watch blocks in real-time
```

---

## 🚨 Troubleshooting

### "Copilot Chat stuck on 'Getting chat ready...'"
**Cause**: Firewall blocking Microsoft Azure or Akamai CDN IPs

**Debug**:
```bash
# Check which IPs are being blocked for user
sudo dmesg -c > /dev/null && sleep 10 && sudo dmesg | grep "UID=$(id -u USERNAME)" | grep DROP

# Identify blocked IP owner
whois BLOCKED_IP | grep -E "netname|NetName|CIDR"

# Add CIDR range to policy.conf egress_allow_domains
# Re-apply firewall
```

### "Email alerts not arriving"
**Cause**: Alertmanager unreachable or SMTP credentials not configured

**Debug on alert server**:
```bash
# Test Alertmanager endpoint
curl -s http://localhost:9093/api/v2/status | python3 -m json.tool

# Test direct SMTP fallback
SMTP_HOST=smtp.example.com SMTP_USER=user SMTP_PASS=pass \
  sudo /usr/local/bin/send-alert-email.sh 'Test' 'SMTP fallback test'
```

**Debug on remote machine**:
```bash
# Test SSH relay to alert server
sudo ssh alert-server "/usr/local/bin/send-alert-email.sh 'Test' 'SSH relay test'"

# Check SSH key
sudo ssh alert-server "echo SSH working"
```

---

## 📖 Additional Documentation

- [README.md](https://github.com/devbracho/nftables_suite/blob/main/README.md) - Full technical documentation
- [policy.conf](/etc/nftables.d/policy.conf) - Current firewall configuration
- [INSTALL.md](https://github.com/devbracho/nftables_suite/blob/main/INSTALL.md) - Installation guide

---

**Last Updated**: 2026-01-15  
**Tested On**: Ubuntu 20.04  
**Repository**: https://github.com/devbracho/nftables_suite (main branch)
