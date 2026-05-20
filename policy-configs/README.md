# NFTables Policy Configuration Files

This directory contains machine-specific policy configuration files for the nftables firewall managed by `nftablets.suite.sh`.

## File Structure

- **policy.conf.base** - Base configuration for all machines without machine-specific forward rules
- **policy.conf.`<hostname>`** - Optional machine-specific config (e.g. with Grafana NAT forwarding)

## Deployment

On each machine, symlink the appropriate policy file:

```bash
# On a machine with a custom config
sudo ln -sf /etc/nftables.d/policy.conf.<hostname> /etc/nftables.d/policy.conf

# On machines using the base config
sudo ln -sf /etc/nftables.d/policy.conf.base /etc/nftables.d/policy.conf
```

## Machine-Specific Configurations

### Machine with Grafana NAT forwarding (example)
- **WireGuard VPN**: wg0 interface
- **Grafana forwarding**: Routes VPN traffic to Synology NAS (192.168.1.12:3000)
- **Interfaces**: wg0 (VPN), eno1 (LAN)
- **Additional services**: nftables-nat-grafana.service for DNAT/MASQUERADE

### Other Machines
Use `policy.conf.base` which excludes the `[forward:grafana]` section.

## Creating New Machine Configurations

1. Copy base or existing machine config:
   ```bash
   sudo cp /etc/nftables.d/policy.conf.base /etc/nftables.d/policy.conf.<hostname>
   ```

2. Add machine-specific sections (services, forward rules, etc.)

3. Create symlink:
   ```bash
   sudo ln -sf /etc/nftables.d/policy.conf.<hostname> /etc/nftables.d/policy.conf
   ```

4. Copy to repository for version control:
   ```bash
   sudo cp /etc/nftables.d/policy.conf.<hostname> /path/to/nftables/scripts/nft-firewall/policy-configs/
   sudo chown user3:user3 /path/to/nftables/scripts/nft-firewall/policy-configs/policy.conf.<hostname>
   ```

5. Commit to repository

## Applying Changes

After modifying policy configuration:

```bash
sudo /usr/sbin/nftablets.suite.sh
# or
sudo systemctl restart nftables.service
```

## Version Control

All policy files are tracked in the git repository. When making changes:

1. Edit the machine-specific file in `/etc/nftables.d/`
2. Test the configuration
3. Copy to repository: `sudo cp /etc/nftables.d/policy.conf.<hostname> /path/to/nftables/scripts/nft-firewall/policy-configs/`
4. Fix ownership: `sudo chown user3:user3 /path/to/nftables/scripts/nft-firewall/policy-configs/*`
5. Commit and push changes
