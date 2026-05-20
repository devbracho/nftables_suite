# NFTables Policy Configuration Files

This directory contains additional policy configuration files for the nftables firewall managed by `nftablets.suite.sh`.

## File Structure

- **policy.conf.base** - Minimal base policy (no machine-specific rules)

Copy the appropriate file to `/etc/nftables.d/policy.conf` and customise for the target machine.

```bash
sudo /usr/sbin/nftablets.suite.sh
# or
sudo systemctl restart nftables.service
```