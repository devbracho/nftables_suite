#!/usr/bin/env python3
################################################################################
# nftablets_discover.py - Network service discovery for nftables policy
################################################################################
# DESCRIPTION:
#   Automatically discovers listening network services and generates nftables
#   policy configuration stanzas. Analyzes active sockets via 'ss' command and
#   produces INI-format sections ready for use with nftablets.suite.sh.
#
# FEATURES:
#   - Discovers TCP/UDP listeners with port information
#   - Identifies process owners and UIDs for socket-based filtering
#   - Detects bind addresses (0.0.0.0 vs specific IPs)
#   - Maps common ports to service names (SSH, HTTP, etc.)
#   - Supports appending to existing policy files
#   - Skips duplicate sections to avoid conflicts
#   - Provides human-readable service labels
#
# USAGE:
#   sudo ./nftablets_discover.py                    # Print to stdout
#   sudo ./nftablets_discover.py --append           # Append to policy file
#   sudo ./nftablets_discover.py --policy /path     # Custom policy location
#   sudo ./nftablets_discover.py --append --ensure  # Create file if missing
#
# OUTPUT FORMAT:
#   [service_name]
#   tcp_ports=22,80,443
#   udp_ports=53
#   sources=0.0.0.0/0
#   users=root,www-data
#   log_prefix=NFT-CONN service_name discover
#
# REQUIREMENTS:
#   - Python 3.7+
#   - iproute2 package (ss command)
#   - Root privileges (recommended for full process visibility)
#
# AUTHOR: IT Operations Team
# LICENSE: Internal Use Only
################################################################################

from __future__ import annotations

# Standard library imports - organized by category
import argparse
import os
import pwd
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, Optional, Set, Tuple


################################################################################
# CONSTANTS AND CONFIGURATION
################################################################################

# Well-known port mappings to friendly service names
# Format: (protocol, port) -> service_name
# These override the system's /etc/services for common infrastructure ports
PORT_OVERRIDES: Dict[Tuple[str, int], str] = {
    # Common TCP services
    ("tcp", 22): "ssh",
    ("tcp", 80): "http",
    ("tcp", 443): "https",
    ("tcp", 3306): "mysql",
    ("tcp", 5432): "postgresql",
    ("tcp", 5900): "vnc",
    ("tcp", 7070): "anydesk",
    ("tcp", 8080): "http-alt",
    
    # Common UDP services
    ("udp", 53): "dns",
    ("udp", 67): "dhcp-server",
    ("udp", 68): "dhcp-client",
    ("udp", 123): "ntp",
    ("udp", 161): "snmp",
    ("udp", 51820): "wireguard",
    ("udp", 61142): "wireguard",
}


################################################################################
# UTILITY FUNCTIONS
################################################################################


def sanitize(name: str) -> str:
    """Convert arbitrary service names to safe nftables policy identifiers.
    
    Transforms input to lowercase, replaces non-alphanumeric characters with
    underscores, and strips leading/trailing underscores.
    
    Args:
        name: Raw service name (e.g., "HTTP/HTTPS", "My Service 2.0")
    
    Returns:
        Sanitized identifier suitable for INI section names (e.g., "http_https", "my_service_2_0")
        Returns "svc" if input results in empty string.
    
    Examples:
        >>> sanitize("SSH Daemon")
        'ssh_daemon'
        >>> sanitize("HTTP/HTTPS")
        'http_https'
        >>> sanitize("___test___")
        'test'
    """
    cleaned = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    return cleaned or "svc"


def friendly_service_name(port: int, proto: str, fallback: str) -> str:
    """Resolve port/protocol to a human-readable service name.
    
    Priority order:
        1. PORT_OVERRIDES dictionary (custom mappings)
        2. System /etc/services via socket.getservbyport()
        3. Fallback value (usually process name or "proto_port")
    
    Args:
        port: Port number (1-65535)
        proto: Protocol name ("tcp" or "udp")
        fallback: Default value if port is unknown
    
    Returns:
        Service name string (e.g., "ssh", "http", "my_app")
    
    Examples:
        >>> friendly_service_name(22, "tcp", "unknown")
        'ssh'
        >>> friendly_service_name(12345, "tcp", "myapp")
        'myapp'
    """
    # Check custom overrides first (takes precedence over /etc/services)
    override = PORT_OVERRIDES.get((proto, port))
    if override:
        return override
    
    # Try system service database
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        # Port not in /etc/services, use fallback
        return fallback


################################################################################
# SERVICE DISCOVERY FUNCTIONS
################################################################################


def record(
    services: Dict[str, Dict[str, object]],
    service_key: str,
    label: str,
    proto: str,
    port: int,
    source: str,
    process_name: Optional[str] = None,
    owners: Optional[Set[str]] = None,
) -> None:
    """Accumulate service metadata into the discovery dictionary.
    
    This function aggregates multiple socket instances into unified service
    definitions. If a service listens on multiple ports or addresses, all
    are collected into a single policy section.
    
    Args:
        services: Mutable dictionary of discovered services (updated in-place)
        service_key: Sanitized service identifier (e.g., "ssh", "http")
        label: Human-readable service name for comments
        proto: Protocol type ("tcp" or "udp")
        port: Port number being recorded
        source: Source IP/CIDR that can reach this socket (e.g., "0.0.0.0/0")
        process_name: Optional process binary name (e.g., "nginx", "sshd")
        owners: Optional set of usernames/UIDs that own the socket
    
    Returns:
        None (modifies services dictionary in-place)
    
    Side Effects:
        Creates or updates entry in services[service_key] with accumulated data
    """
    # Get or create service entry with default structure
    service = services.setdefault(
        service_key,
        {
            "label": label,           # Human-readable name
            "tcp": set(),             # TCP ports
            "udp": set(),             # UDP ports
            "sources": set(),         # Allowed source IPs/CIDRs
            "processes": set(),       # Process binary names
            "owners": set(),          # Usernames/UIDs owning sockets
        },
    )
    
    # Update service metadata (sets automatically deduplicate)
    service["label"] = label
    service[proto].add(str(port))
    service["sources"].add(source)
    
    if process_name:
        service["processes"].add(process_name)
    
    if owners:
        service["owners"].update(owners)


def parse_listeners(lines: Iterable[str]) -> Tuple[Dict[str, Dict[str, object]], bool]:
    """Parse 'ss' command output to discover listening network services.
    
    Processes each line from 'ss -tulpnH' output, extracting:
        - Protocol (TCP/UDP)
        - Port number
        - Bind address (0.0.0.0 for all interfaces, or specific IP)
        - Process name and PID
        - Socket owner UID/username
    
    Args:
        lines: Iterator of output lines from 'ss -tulpnH' command
    
    Returns:
        Tuple of:
            - Dictionary of discovered services, keyed by sanitized service name
            - Boolean flag indicating if IPv6 listeners were encountered and skipped
    
    Example ss output format:
        tcp   LISTEN  0  128  0.0.0.0:22  0.0.0.0:*  users:(("sshd",pid=1234,fd=3))
        udp   UNCONN  0  0    0.0.0.0:53  0.0.0.0:*  users:(("dnsmasq",pid=5678,fd=5))
    """
    services: Dict[str, Dict[str, object]] = {}
    ipv6_skipped = False

    for raw_line in lines:
        line = raw_line.strip()
        
        # Skip empty lines
        if not line:
            continue

        # Parse ss output columns: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
        parts = line.split()
        if len(parts) < 5:
            continue

        proto_raw = parts[0]  # 'tcp' or 'udp'
        state = parts[1]      # 'LISTEN', 'UNCONN', etc.
        local = parts[4]      # 'address:port' (e.g., "0.0.0.0:22", "[::]:80")

        # Determine protocol and validate state
        if proto_raw.startswith("tcp"):
            # TCP sockets: only process LISTEN state
            if state.upper() != "LISTEN":
                continue
            proto = "tcp"
        elif proto_raw.startswith("udp"):
            # UDP is connectionless, no specific state required
            proto = "udp"
        else:
            # Skip unknown protocols
            continue

        # Skip wildcard bindings (not useful for policy)
        if local == "*:*":
            continue

        # Parse address:port, handling both IPv4 and IPv6 formats
        # IPv6: [::1]:80 or [fe80::1]:443
        # IPv4: 0.0.0.0:22 or 192.168.1.1:80
        if local.startswith("["):
            # IPv6 format: strip brackets
            host_port = local.rsplit(":", 1)
            address = host_port[0].strip("[]")
            is_ipv6 = True
        else:
            # IPv4 or hostname format
            host_port = local.rsplit(":", 1)
            address = host_port[0]
            # Detect IPv6 by presence of colons in address part
            is_ipv6 = ":" in address

        # Validate we got both host and port
        if len(host_port) != 2:
            continue

        port_token = host_port[1]
        # Skip dynamic/wildcard ports
        if port_token == "*":
            continue

        # Convert port to integer
        try:
            port = int(port_token)
        except ValueError:
            # Port is not numeric, skip
            continue

        # Currently only handling IPv4 (nftables script supports IPv4 only)
        if is_ipv6:
            ipv6_skipped = True
            continue

        # Skip loopback listeners (not externally accessible)
        if address.startswith("127."):
            continue

        # Determine source CIDR for policy file
        # 0.0.0.0 or * means listening on all interfaces
        if address == "0.0.0.0" or address == "*":
            source = "0.0.0.0/0"  # Allow from anywhere
        else:
            # Specific IP binding - restrict to that single IP
            source = f"{address}/32"

        # Extract process name from ss output
        # Format: users:(("sshd",pid=1234,fd=3),…)
        programs = re.findall(r'"([^"/]+)"', raw_line)
        program_name: Optional[str] = programs[0] if programs else None

        # Extract socket owner UIDs from process PIDs
        # This enables per-user/per-service filtering in nftables
        owners: Set[str] = set()
        for pid_str in re.findall(r"pid=(\d+)", raw_line):
            try:
                pid = int(pid_str)
                # Read process ownership from /proc filesystem
                stat = os.stat(Path("/proc") / str(pid))
                uid = stat.st_uid
                
                # Resolve UID to username if possible
                try:
                    user = pwd.getpwuid(uid).pw_name
                except KeyError:
                    # User not in passwd database, use numeric UID
                    user = str(uid)
                
                owners.add(user)
            except (OSError, ValueError, PermissionError):
                # Process may have terminated, or insufficient permissions
                # Skip this PID and continue
                continue
        
        # Build service label: prefer process name, fallback to "proto_port"
        fallback_label = program_name or f"{proto}_{port}"
        friendly_label = friendly_service_name(port, proto, fallback_label)

        # Create sanitized key for policy section
        service_key = sanitize(friendly_label)
        
        # Record this socket in the services dictionary
        record(services, service_key, friendly_label, proto, port, source, program_name, owners)

    return services, ipv6_skipped


################################################################################
# SYSTEM INTERACTION FUNCTIONS
################################################################################


def run_ss() -> Tuple[int, str, str]:
    """Execute 'ss' command to list listening network sockets.
    
    Runs: ss -tulpnH
        -t: TCP sockets
        -u: UDP sockets
        -l: Listening sockets only
        -p: Show process using socket
        -n: Numeric addresses (no DNS resolution)
        -H: No header line
    
    Returns:
        Tuple of (exit_code, stdout, stderr)
            exit_code: 0 on success, non-zero on failure
            stdout: Command output containing socket information
            stderr: Error messages (if any)
    
    Raises:
        No exceptions raised; errors returned as tuple values
    """
    # Locate ss binary in system PATH
    ss_path = shutil.which("ss")
    if not ss_path:
        return 1, "", "ss command not found. Install iproute2 (iproute package) and retry."

    try:
        # Execute ss with appropriate flags
        result = subprocess.run(
            [ss_path, "-tulpnH"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,  # Prevent hanging indefinitely
        )
    except FileNotFoundError:
        return 1, "", f"Unable to execute {ss_path}."
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() if exc.stderr else str(exc)
        return exc.returncode or 1, exc.stdout, f"Failed to execute {ss_path}: {stderr}"
    except subprocess.TimeoutExpired:
        return 1, "", "ss command timed out after 30 seconds."

    return 0, result.stdout, result.stderr


################################################################################
# POLICY FILE OPERATIONS
################################################################################


def load_existing_sections(policy_path: Path) -> Set[str]:
    """Load existing section names from policy file to avoid duplicates.
    
    Parses the policy file and extracts all [section_name] headers.
    Used when --append is specified to skip sections that already exist.
    
    Args:
        policy_path: Path to the nftables policy configuration file
    
    Returns:
        Set of section names found in the file (e.g., {"ssh", "http", "nginx"})
        Returns empty set if file doesn't exist or can't be read
    
    Examples:
        If policy file contains:
            [ssh]
            tcp_ports=22
            
            [http]
            tcp_ports=80
        
        Returns: {"ssh", "http"}
    """
    sections: Set[str] = set()
    
    # File doesn't exist yet - no sections to load
    if not policy_path.exists():
        return sections
    
    try:
        # Read file and extract section headers
        with policy_path.open("r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = raw.strip()
                # Match INI-style section headers: [section_name]
                m = re.match(r"^\[(.+)\]$", line)
                if m:
                    sections.add(m.group(1).strip())
    except (OSError, PermissionError) as e:
        # File read failed - return empty set rather than crashing
        print(f"Warning: Could not read {policy_path}: {e}", file=sys.stderr)
    
    return sections


def write_stanzas(
    policy_path: Path,
    services: Dict[str, Dict[str, object]],
    append: bool,
    ensure: bool,
    skip_existing: bool,
) -> int:
    """Write discovered services to policy file or stdout.
    
    Generates INI-format policy stanzas for each discovered service.
    Can either print to stdout (default) or append to existing policy file.
    
    Args:
        policy_path: Target policy file path
        services: Dictionary of discovered services from parse_listeners()
        append: If True, append to policy file; if False, print to stdout
        ensure: If True, create policy directory/file if missing (requires append=True)
        skip_existing: If True, skip services already in policy file (requires append=True)
    
    Returns:
        Exit code: 0 on success, non-zero on failure
    
    Output Format:
        # service: nginx (processes: nginx)
        [nginx]
        tcp_ports=80,443
        sources=0.0.0.0/0
        users=www-data,root
        log_prefix=NFT-CONN nginx discover
    """
    if append:
        # APPEND MODE: Write to policy file
        if ensure:
            # Create directory structure if missing
            policy_path.parent.mkdir(parents=True, exist_ok=True)
            if not policy_path.exists():
                policy_path.touch(mode=0o644)
        
        # Load existing sections to avoid duplicates
        existing = load_existing_sections(policy_path)
        appended = 0
        
        with policy_path.open("a", encoding="utf-8") as out:
            # Iterate services in alphabetical order for consistent output
            for key in sorted(services):
                # Skip services already in policy file if requested
                if skip_existing and key in existing:
                    print(f"# Skipping existing section [{key}] in {policy_path}", file=sys.stderr)
                    continue
                
                # Extract service metadata
                entry = services[key]
                display = entry["label"]                          # Human-readable name
                tcp_ports = sorted(entry["tcp"], key=int)         # TCP ports (numerically sorted)
                udp_ports = sorted(entry["udp"], key=int)         # UDP ports (numerically sorted)
                sources = entry["sources"]                        # Source IP CIDRs
                processes = sorted(entry["processes"])            # Process names
                owners = sorted(entry["owners"])                  # Usernames/UIDs

                # Write INI-style stanza
                out.write("\n")
                
                # Comment header with process information
                if processes:
                    out.write(f"# service: {display} (processes: {', '.join(processes)})\n")
                else:
                    out.write(f"# service: {display}\n")
                
                # Section header: [service_name]
                out.write(f"[{key}]\n")
                
                # TCP ports (if any)
                if tcp_ports:
                    out.write(f"tcp_ports={','.join(tcp_ports)}\n")
                
                # UDP ports (if any)
                if udp_ports:
                    out.write(f"udp_ports={','.join(udp_ports)}\n")
                
                # Source IPs: simplify if listening on all interfaces
                if "0.0.0.0/0" in sources:
                    out.write("sources=0.0.0.0/0\n")
                else:
                    sorted_sources = sorted(sources)
                    out.write(f"sources={','.join(sorted_sources)}\n")
                
                # Socket owners for UID-based filtering
                if owners:
                    out.write(f"users={','.join(owners)}\n")
                
                # Log prefix for rsyslog routing
                out.write(f"log_prefix=NFT-CONN {display} discover\n")
                
                appended += 1
        print(f"Appended {appended} new section(s) to {policy_path}")
        return 0

    # STDOUT MODE: Print to console for review
    print("# Suggested additions for /etc/nftables.d/policy.conf")
    print("# Review and adjust sources, users, and log_prefix values before applying.")
    
    # Output services in alphabetical order
    for key in sorted(services):
        entry = services[key]
        display = entry["label"]
        tcp_ports = sorted(entry["tcp"], key=int)
        udp_ports = sorted(entry["udp"], key=int)
        sources = entry["sources"]
        processes = sorted(entry["processes"])
        owners = sorted(entry["owners"])  # usernames or numeric UIDs

        print()
        if processes:
            print(f"# service: {display} (processes: {', '.join(processes)})")
        else:
            print(f"# service: {display}")
        print(f"[{key}]")
        if tcp_ports:
            print(f"tcp_ports={','.join(tcp_ports)}")
        if udp_ports:
            print(f"udp_ports={','.join(udp_ports)}")
        if "0.0.0.0/0" in sources:
            print("sources=0.0.0.0/0")
        else:
            sorted_sources = sorted(sources)
            print(f"sources={','.join(sorted_sources)}")
        if owners:
            print(f"users={','.join(owners)}")
        print(f"log_prefix=NFT-CONN {display} discover")
    return 0


################################################################################
# MAIN ENTRY POINT
################################################################################


def main() -> int:
    """Main entry point for nftablets_discover.
    
    Orchestrates the discovery process:
        1. Parse command-line arguments
        2. Execute 'ss' to get listening sockets
        3. Parse output to discover services
        4. Write policy stanzas to file or stdout
    
    Returns:
        Exit code: 0 on success, non-zero on failure
    """
    # Configure command-line argument parser
    parser = argparse.ArgumentParser(
        description="Discover network services and generate nftables policy stanzas",
        epilog="Run as root for full process and socket visibility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        "--append",
        action="store_true",
        help="Append results to policy file (avoids duplicate sections)",
    )
    
    parser.add_argument(
        "--policy",
        default=os.environ.get("NFTABLES_POLICY_FILE", "/etc/nftables.d/policy.conf"),
        help="Path to policy file (default: $NFTABLES_POLICY_FILE or /etc/nftables.d/policy.conf)",
    )
    
    parser.add_argument(
        "--ensure",
        action="store_true",
        help="Create policy directory/file if missing (requires --append)",
    )
    
    parser.add_argument(
        "--no-skip-existing",
        action="store_true",
        help="Include existing sections when appending (may create duplicates)",
    )
    
    args = parser.parse_args()

    # Step 1: Execute 'ss' command to get listening sockets
    rc, stdout, stderr = run_ss()
    if rc != 0:
        if stderr:
            print(stderr, file=sys.stderr)
        return rc

    # Step 2: Parse ss output to discover services
    services, ipv6_skipped = parse_listeners(stdout.splitlines())

    # Step 3: Handle empty results
    if not services:
        print("# No externally listening sockets detected (or insufficient privileges).")
        print("# Run as root to see all processes and sockets.", file=sys.stderr)
        return 0

    # Step 4: Write discovered services to file or stdout
    policy_path = Path(args.policy)
    skip_existing = not args.no_skip_existing
    result = write_stanzas(policy_path, services, args.append, args.ensure, skip_existing)
    
    # Step 5: Warn about IPv6 if encountered
    if ipv6_skipped:
        print(
            "\n# Note: IPv6 listeners were detected and skipped.",
            file=sys.stderr,
        )
        print(
            "# The nftablets.suite.sh script currently supports IPv4 only.",
            file=sys.stderr,
        )

    return result


################################################################################
# SCRIPT ENTRY POINT
################################################################################

if __name__ == "__main__":
    # Check if running with sufficient privileges
    # Root access provides full visibility into all sockets and processes
    if hasattr(os, "geteuid"):
        try:
            if os.geteuid() != 0:
                print(
                    "⚠  Warning: Not running as root - some listeners may not be visible.",
                    file=sys.stderr,
                )
                print(
                    "   Run with 'sudo' for complete socket and process discovery.",
                    file=sys.stderr,
                )
        except AttributeError:
            # geteuid() not available on this platform (e.g., Windows)
            pass

    # Execute main function and exit with its return code
    sys.exit(main())
