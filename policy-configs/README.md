# NFTables Policy Configuration Files

This directory contains machine-specific policy configuration files for the nftables firewall managed by `nftablets.suite.sh`.

## File Structure

- **policy.conf** - Base configuration for all machines without machine-specific forward rules

## Deployment

On each machine, symlink the appropriate policy file:

```bash
# On a machine with a custom config
sudo ln -sf /etc/nftables.d/policy.conf.<hostname> /etc/nftables.d/policy.conf

# On machines using the base config
sudo ln -sf /etc/nftables.d/policy.conf.base /etc/nftables.d/policy.conf
```

## Creating New Machine Configurations

1. Copy base or existing machine config:
   ```bash
   sudo cp policy.conf /etc/nftables.d/policy.conf
   ```

## Applying Changes

After modifying policy configuration:

```bash
sudo /usr/sbin/nftablets.suite.sh
# or
sudo systemctl restart nftables.service
```