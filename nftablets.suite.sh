#!/bin/bash
################################################################################
# nftablets.suite.sh - Policy-driven nftables firewall orchestration
################################################################################
# DESCRIPTION:
#   Generates and applies nftables rulesets from a declarative policy file.
#   Supports per-service inbound rules and per-user/group outbound (egress) control.
#
# FEATURES:
#   - Atomic ruleset application with validation before deployment
#   - Safe-apply mode with automatic rollback protection
#   - Per-user egress policies with domain/IP/CIDR allow-lists
#   - Group-based policy inheritance for easier management
#   - Comprehensive logging with dedicated log files
#   - DNS resolution with CIDR notation support for local networks
#
# USAGE:
#   sudo nftablets.suite.sh [--dry-run|--status|--init-config|--safe-apply SECONDS]
#
# POLICY FILE:
#   Default: /etc/nftables.d/policy.conf (INI-like format)
#   Override: export NFTABLES_POLICY_FILE=/custom/path
#
# SECURITY MODEL:
#   - Default DROP policy on input, output, and forward chains
#   - Explicit allow rules generated from policy configuration
#   - Per-user egress enforcement using meta skuid matching
#   - System DNS resolver exceptions for name resolution
#
# LICENSE: MIT
################################################################################

# Exit immediately on error, treat unset variables as errors, fail on pipe errors
set -Eeuo pipefail

################################################################################
# PREREQUISITES AND GLOBAL CONFIGURATION
################################################################################

# Verify script is running with root privileges
if [ "${EUID}" -ne 0 ]; then
  echo "This script must be run as root." >&2
  exit 1
fi

# Verify nftables is installed
if ! command -v nft >/dev/null 2>&1; then
  echo "nft command not found. Install nftables and retry." >&2
  exit 1
fi

################################################################################
# GLOBAL VARIABLES
################################################################################

# Operational flags
DRY_RUN=0                    # When set, validate without applying changes
SAFE_ROLLBACK_DELAY=0        # Seconds before auto-rollback (0=disabled)
ROLLBACK_UNIT_NAME=""        # systemd unit name for rollback timer
BACKUP_PATH=""               # Path to current ruleset backup

# Command paths
NFT=$(command -v nft)        # nftables command binary

# Configuration paths
POLICY_FILE=${NFTABLES_POLICY_FILE:-/etc/nftables.d/policy.conf}
POLICY_DIR=$(dirname "$POLICY_FILE")

# Logging configuration
LOG_DIR="/var/log/nftables"
ATTEMPT_LOG="${LOG_DIR}/attempts.log"      # Dropped packets log
CONNECTION_LOG="${LOG_DIR}/connections.log" # Allowed connections log
RSYSLOG_DROPIN="/etc/rsyslog.d/30-nftables.conf"

################################################################################
# POLICY DATA STRUCTURES
################################################################################
# These associative arrays store parsed policy configuration
# Array keys are service/user/group names; values are policy attributes

# Inbound service configuration (from [service_name] sections)
declare -a POLICY_SERVICES=()              # Array of all service names
declare -A SERVICE_TCP_PORTS=()            # service -> TCP port list
declare -A SERVICE_UDP_PORTS=()            # service -> UDP port list
declare -A SERVICE_SOURCES=()              # service -> allowed source CIDRs
declare -A SERVICE_USERS=()                # service -> allowed socket owner UIDs
declare -A SERVICE_LOG_PREFIX=()           # service -> custom log prefix
declare -A SERVICE_BLOCK_DOMAINS=()        # service -> blocked domains (optional)

# Per-user egress (outbound) policies (from [user:username] sections)
declare -A USER_POLICY=()                  # username -> allow_all|block_all
declare -A USER_ALLOW_TCP_PORTS=()         # username -> allowed TCP ports
declare -A USER_ALLOW_UDP_PORTS=()         # username -> allowed UDP ports
declare -A USER_ALLOW_DOMAINS=()           # username -> allowed domains/IPs/CIDRs

# Group-based egress policies (from [group:groupname] sections)
declare -A GROUP_MEMBERS=()                # groupname -> comma-separated usernames
declare -A GROUP_POLICY=()                 # groupname -> allow_all|block_all
declare -A GROUP_ALLOW_TCP_PORTS=()        # groupname -> allowed TCP ports
declare -A GROUP_ALLOW_UDP_PORTS=()        # groupname -> allowed UDP ports
declare -A GROUP_ALLOW_DOMAINS=()          # groupname -> allowed domains/IPs/CIDRs

################################################################################
# UTILITY FUNCTIONS
################################################################################
# Helper functions for string manipulation, array operations, and validation

join_by() {
  # Join array elements with a separator for nftables syntax.
  # Args:
  #   $1: separator string (e.g., ", " for nftables sets)
  #   $@: elements to join
  # Returns: joined string on stdout
  local sep=$1
  shift
  local IFS=$sep
  echo "$*"
}

trim_whitespace() {
  # Remove leading and trailing whitespace from a string.
  # Interior whitespace is preserved.
  # Args: $1: string to trim
  # Returns: trimmed string on stdout
  local value=$1
  value=${value#"${value%%[![:space:]]*}"}
  value=${value%"${value##*[![:space:]]}"}
  printf '%s' "$value"
}

array_contains() {
  # Check if an array contains a specific value.
  # Uses nameref for efficient array passing.
  # Args:
  #   $1: array variable name (passed by reference)
  #   $2: value to search for
  # Returns: 0 if found, 1 if not found
  local -n arr_ref=$1
  local needle=$2
  local item
  for item in "${arr_ref[@]}"; do
    if [ "$item" = "$needle" ]; then
      return 0
    fi
  done
  return 1
}

csv_to_array() {
  # Convert comma-separated values to an array with whitespace trimming.
  # Empty elements are skipped.
  # Args:
  #   $1: output array variable name (passed by reference)
  #   $2: comma-separated string
  # Returns: populates the named array
  local -n out=$1
  local raw=$2
  out=()
  if [ -z "$raw" ]; then
    return 0
  fi
  IFS=',' read -ra parts <<<"$raw"
  local part trimmed
  for part in "${parts[@]}"; do
    trimmed=$(trim_whitespace "$part")
    if [ -n "$trimmed" ]; then
      out+=("$trimmed")
    fi
  done
}

validate_port_list() {
  # Validate TCP/UDP port numbers and ranges.
  # Ensures all ports are within 1-65535 and ranges are ascending.
  # Args:
  #   $1: service name (for error messages)
  #   $2: field name (for error messages)
  #   $@: port numbers or ranges (e.g., "80" or "8000-8080")
  # Returns: 0 if valid, 1 if invalid (with error message)
  local service=$1
  local field=$2
  shift 2
  if [ "$#" -eq 0 ]; then
    return 0
  fi

  local token start end
  for token in "$@"; do
    if [[ $token =~ ^([0-9]+)-([0-9]+)$ ]]; then
      start=${BASH_REMATCH[1]}
      end=${BASH_REMATCH[2]}
      if (( start < 1 || start > 65535 || end < 1 || end > 65535 )); then
        echo "Error: ${field} entry '$token' in service [$service] is outside 1-65535." >&2
        return 1
      fi
      if (( start > end )); then
        echo "Error: ${field} range '$token' in service [$service] has start greater than end." >&2
        return 1
      fi
      continue
    fi

    if [[ $token =~ ^[0-9]+$ ]]; then
      start=$token
      if (( start < 1 || start > 65535 )); then
        echo "Error: ${field} port '$token' in service [$service] is outside 1-65535." >&2
        return 1
      fi
      continue
    fi

    echo "Error: ${field} token '$token' in service [$service] is not a valid port or range." >&2
    return 1
  done

  return 0
}

sanitize_identifier() {
  # Convert arbitrary strings to safe nftables set names.
  # Converts to lowercase, replaces non-alphanumeric with underscores.
  # Args: $1: input string
  # Returns: sanitized identifier on stdout
  local input=$1
  input=$(echo "$input" | tr '[:upper:]' '[:lower:]')
  input=$(echo "$input" | tr -cs '[:alnum:]' '_')
  input=${input#_}
  input=${input%_}
  if [ -z "$input" ]; then
    input="svc"
  fi
  printf '%s' "$input"
}

resolve_users_to_uids() {
  # Convert usernames to numeric UIDs for nftables meta skuid matching.
  # Accepts usernames or numeric UIDs; numeric values pass through unchanged.
  # Args:
  #   $1: output array variable name (passed by reference)
  #   $@: usernames or UIDs to resolve
  # Returns: 0 if any UIDs resolved, 1 if all failed
  local -n dest=$1
  shift
  dest=()
  local token uid
  for token in "$@"; do
    if [ -z "$token" ]; then
      continue
    fi
    if [[ $token =~ ^[0-9]+$ ]]; then
      dest+=("$token")
      continue
    fi
    if uid=$(id -u "$token" 2>/dev/null); then
      dest+=("$uid")
    else
      echo "Warning: unable to resolve user '$token'; skipping." >&2
    fi
  done
  [ ${#dest[@]} -gt 0 ]
}

resolve_domains_to_ips() {
  # Resolve domains to IPv4 addresses for nftables IP sets.
  # Supports:
  #   - Domain names (resolved via DNS)
  #   - Direct IPv4 addresses (pass-through)
  #   - CIDR notation for networks (e.g., 192.168.1.0/24)
  # Args:
  #   $1: output array variable name (passed by reference)
  #   $@: domains, IPs, or CIDR ranges to process
  # Returns: populates the named array with IPv4 addresses/CIDRs
  local -n out_ips=$1
  shift
  out_ips=()
  local domain ip domain_ips
  for domain in "$@"; do
    if [ -z "$domain" ]; then
      continue
    fi
    
    # Check if it's already an IP address or CIDR notation
    # Pattern: xxx.xxx.xxx.xxx or xxx.xxx.xxx.xxx/xx
    if [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
      out_ips+=("$domain")
      continue
    fi
    
    # Resolve domain name via DNS
    # Prefer systemd-resolved local stub (127.0.0.53) to avoid egress policy conflicts
    if timeout 1 bash -lc "exec 3<>/dev/tcp/127.0.0.53/53" 2>/dev/null; then
      domain_ips=$(dig @127.0.0.53 +short A "$domain" 2>/dev/null || echo "")
    else
      domain_ips=$(dig +short A "$domain" 2>/dev/null || echo "")
    fi
    for ip in $domain_ips; do
      if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        out_ips+=("$ip")
      fi
    done
  done
}

ip_in_cidr() {
  # Check if an IP address is within a CIDR range (bash native implementation)
  # Args: $1: IP address, $2: CIDR range
  # Returns: 0 if IP is in CIDR, 1 otherwise
  local ip=$1 cidr=$2
  local cidr_ip cidr_mask ip_dec cidr_dec mask_dec
  
  # Parse CIDR notation
  cidr_ip="${cidr%/*}"
  cidr_mask="${cidr#*/}"
  
  # Convert IP to decimal
  IFS=. read -r i1 i2 i3 i4 <<< "$ip"
  ip_dec=$((i1 * 256**3 + i2 * 256**2 + i3 * 256 + i4))
  
  # Convert CIDR IP to decimal
  IFS=. read -r c1 c2 c3 c4 <<< "$cidr_ip"
  cidr_dec=$((c1 * 256**3 + c2 * 256**2 + c3 * 256 + c4))
  
  # Calculate network mask
  mask_dec=$(( (0xFFFFFFFF << (32 - cidr_mask)) & 0xFFFFFFFF ))
  
  # Check if IP is in the same network
  [ $(( ip_dec & mask_dec )) -eq $(( cidr_dec & mask_dec )) ] && return 0
  return 1
}

collect_resolvers_ipv4() {
  # Discover IPv4 DNS resolver addresses from system configuration.
  # Sources (in priority order):
  #   1. /run/systemd/resolve/resolv.conf (systemd-resolved upstreams)
  #   2. /etc/systemd/resolved.conf (fallback)
  #   3. /etc/resolv.conf (traditional)
  #   4. resolvectl status output (if available)
  # Skips loopback addresses (127.x.x.x) to get actual upstream resolvers.
  # Args: $1: output array variable name (passed by reference)
  # Returns: 0 always (safe for set -e), populates array
  local -n out=$1
  out=()
  local ip iprx='^([0-9]+\.){3}[0-9]+$'

  # Helper to parse nameserver lines from a file
  local f
  for f in /run/systemd/resolve/resolv.conf /etc/systemd/resolved.conf /etc/resolv.conf; do
    [ -f "$f" ] || continue
    while read -r ip; do
      ip=$(echo "$ip" | awk '/^nameserver[[:space:]]+[0-9.]+/ {print $2}')
      if [[ $ip =~ $iprx ]] && [[ ! $ip =~ ^127\. ]]; then
        out+=("$ip")
      fi
    done <"$f"
    [ ${#out[@]} -gt 0 ] && break
  done

  # Try resolvectl (systemd-resolved) if available
  if command -v resolvectl >/dev/null 2>&1; then
    # Extract IPv4 DNS servers from all links
    while read -r ip; do
      if [[ $ip =~ $iprx ]] && [[ ! $ip =~ ^127\. ]]; then
        # dedupe
        local seen=0 x
        for x in "${out[@]}"; do [ "$x" = "$ip" ] && seen=1 && break; done
        [ $seen -eq 0 ] && out+=("$ip")
      fi
    done < <(resolvectl status 2>/dev/null | awk '/DNS Servers:/{for(i=3;i<=NF;i++) print $i}') || true
  fi
  
  return 0
}

################################################################################
# POLICY FILE OPERATIONS
################################################################################
# Functions for policy file initialization and parsing

initialize_policy_file() {
  # Create a default policy configuration file with example services.
  # Only creates if file doesn't exist; safe to call multiple times.
  # Returns: 0 if file exists or was created successfully
  mkdir -p "$POLICY_DIR"
  if [ -f "$POLICY_FILE" ]; then
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "Dry run: would create $POLICY_FILE template." >&2
    return 0
  fi
  cat >"$POLICY_FILE" <<'POLICY'
# nftables policy configuration
# Each section defines a service and the inbound ports permitted.
# Recognized keys:
#   tcp_ports   Comma-separated TCP port list
#   udp_ports   Comma-separated UDP port list
#   sources     Comma-separated IPv4 CIDRs allowed to reach the service
#   users       Comma-separated usernames or numeric UIDs owning the socket
#   log_prefix  Optional log prefix override
#
# To control outbound (egress) per user, add sections like [user:USERNAME]
# with keys:
#   egress_policy            allow_all | block_all (default block_all)
#   egress_allow_domains     Comma-separated domains to allow (resolved to IPv4)
#   egress_allow_tcp_ports   Comma-separated TCP ports to allow to those domains
#   egress_allow_udp_ports   Comma-separated UDP ports to allow to those domains

[ssh]
tcp_ports=22
sources=0.0.0.0/0
users=root
log_prefix=NFT-CONN SSH allow

[web]
tcp_ports=80,443
sources=0.0.0.0/0

# Example per-user egress policies
[user:alice]
egress_policy=allow_all

[user:bob]
egress_allow_domains=example.com
egress_allow_tcp_ports=80,443

[user:charlie]
egress_policy=block_all

# Add your custom services below this line.
POLICY
  echo "Initialized policy template at $POLICY_FILE"
}

parse_policy_file() {
  # Parse INI-style policy file into global associative arrays.
  # Handles three section types:
  #   [service_name]         - Inbound service definitions
  #   [user:username]        - Per-user egress policies
  #   [group:groupname]      - Group-based egress policies
  # Populates: POLICY_SERVICES, SERVICE_*, USER_*, GROUP_* arrays
  # Returns: 0 on success, 1 on failure
  if [ ! -f "$POLICY_FILE" ]; then
    initialize_policy_file
  fi
  if [ ! -f "$POLICY_FILE" ]; then
    echo "Policy file $POLICY_FILE not found." >&2
    return 1
  fi

  POLICY_SERVICES=()
  SERVICE_TCP_PORTS=()
  SERVICE_UDP_PORTS=()
  SERVICE_SOURCES=()
  SERVICE_USERS=()
  SERVICE_LOG_PREFIX=()

  local current=""
  local -a user_section_users=()
  local current_group=""
  local raw line key value lower_key
  while IFS= read -r raw || [ -n "$raw" ]; do
    line=$(trim_whitespace "$raw")
    if [ -z "$line" ] || [[ $line == \#* ]]; then
      continue
    fi
    if [[ $line =~ ^\[(.+)\]$ ]]; then
      current=${BASH_REMATCH[1]}
      current=$(trim_whitespace "$current")
      if [ -z "$current" ]; then
        echo "Warning: encountered empty service name; skipping." >&2
        current=""
        continue
      fi
      user_section_users=()
      current_group=""
      if [[ $current =~ ^user:(.+)$ ]]; then
        csv_to_array user_section_users "${BASH_REMATCH[1]}"
      elif [[ $current =~ ^users:(.+)$ ]]; then
        # Alias: [users:a,b] same as [user:a,b]
        csv_to_array user_section_users "${BASH_REMATCH[1]}"
      elif [[ $current =~ ^group:(.+)$ ]]; then
        current_group=$(trim_whitespace "${BASH_REMATCH[1]}")
      fi
      if ! array_contains POLICY_SERVICES "$current"; then
        POLICY_SERVICES+=("$current")
      fi
      continue
    fi
    if [ -z "$current" ]; then
      echo "Warning: found key outside of a service stanza: $line" >&2
      continue
    fi
    if [[ $line != *=* ]]; then
      echo "Warning: ignoring malformed line '$line' in service [$current]." >&2
      continue
    fi
    key=${line%%=*}
    value=${line#*=}
    key=$(trim_whitespace "$key")
    value=$(trim_whitespace "$value")
    lower_key=$(echo "$key" | tr '[:upper:]' '[:lower:]')
    if [ ${#user_section_users[@]} -gt 0 ]; then
      case "$lower_key" in
        egress_policy)
          for _u in "${user_section_users[@]}"; do USER_POLICY["$_u"]="$value"; done
          ;;
        egress_allow_domains)
          for _u in "${user_section_users[@]}"; do USER_ALLOW_DOMAINS["$_u"]="$value"; done
          ;;
        egress_allow_tcp_ports)
          for _u in "${user_section_users[@]}"; do USER_ALLOW_TCP_PORTS["$_u"]="$value"; done
          ;;
        egress_allow_udp_ports)
          for _u in "${user_section_users[@]}"; do USER_ALLOW_UDP_PORTS["$_u"]="$value"; done
          ;;
        *)
          echo "Warning: unknown key '$key' in user policy [user:${user_section_users[*]}]; skipping." >&2
          ;;
      esac
    elif [ -n "$current_group" ]; then
      case "$lower_key" in
        members)
          GROUP_MEMBERS["$current_group"]="$value"
          ;;
        egress_policy)
          GROUP_POLICY["$current_group"]="$value"
          ;;
        egress_allow_domains)
          GROUP_ALLOW_DOMAINS["$current_group"]="$value"
          ;;
        egress_allow_tcp_ports)
          GROUP_ALLOW_TCP_PORTS["$current_group"]="$value"
          ;;
        egress_allow_udp_ports)
          GROUP_ALLOW_UDP_PORTS["$current_group"]="$value"
          ;;
        *)
          echo "Warning: unknown key '$key' in group policy [group:$current_group]; skipping." >&2
          ;;
      esac
    else
      case "$lower_key" in
        tcp_ports)
          SERVICE_TCP_PORTS["$current"]="$value"
          ;;
        udp_ports)
          SERVICE_UDP_PORTS["$current"]="$value"
          ;;
        sources)
          # Normalize wildcard source formats
          local _srcs
          if [[ "$value" == *"*"* ]]; then
            _srcs="0.0.0.0/0"
          else
            _srcs="$value"
          fi
          SERVICE_SOURCES["$current"]="$_srcs"
          ;;
        users)
          SERVICE_USERS["$current"]="$value"
          ;;
        log_prefix)
          SERVICE_LOG_PREFIX["$current"]="$value"
          ;;
        block_domains)
          SERVICE_BLOCK_DOMAINS["$current"]="$value"
          ;;
        *)
          echo "Warning: unknown key '$key' in service [$current]; skipping." >&2
          ;;
      esac
    fi
  done <"$POLICY_FILE"

  return 0
}

################################################################################
# LOGGING CONFIGURATION
################################################################################
# Functions for log file setup and rsyslog integration

setup_log_targets() {
  # Configure dedicated log files for nftables events.
  # Creates:
  #   - /var/log/nftables/attempts.log (dropped packets)
  #   - /var/log/nftables/connections.log (allowed connections)
  # Configures rsyslog to route log prefixes to appropriate files.
  # Returns: 0 on success
  mkdir -p "$LOG_DIR"
  touch "$ATTEMPT_LOG" "$CONNECTION_LOG"
  chmod 0640 "$ATTEMPT_LOG" "$CONNECTION_LOG"
  chown root:adm "$LOG_DIR" "$ATTEMPT_LOG" "$CONNECTION_LOG" 2>/dev/null || true

  if command -v rsyslogd >/dev/null 2>&1; then
    if [ -f "$RSYSLOG_DROPIN" ] && ! grep -q "NFT-ATTEMPT" "$RSYSLOG_DROPIN"; then
      mv "$RSYSLOG_DROPIN" "${RSYSLOG_DROPIN}.bak.$(date +%F_%H%M%S)"
    fi
    cat >"$RSYSLOG_DROPIN" <<'RSYSLOG'
:msg, contains, "NFT-ATTEMPT" -/var/log/nftables/attempts.log
& stop
:msg, contains, "NFT-CONN" -/var/log/nftables/connections.log
& stop
  :msg, contains, "NFT-EGR" -/var/log/nftables/connections.log
  & stop
RSYSLOG
    systemctl restart rsyslog >/dev/null 2>&1 || {
      echo "rsyslog restart failed; please restart it manually to activate nftables logging." >&2
    }
  else
    echo "rsyslog is not installed. Configure your syslog daemon to route messages" >&2
    echo "with prefixes NFT-ATTEMPT and NFT-CONN into $LOG_DIR." >&2
  fi
}

################################################################################
# BACKUP AND STATUS OPERATIONS
################################################################################
# Functions for ruleset backup and firewall status reporting

backup_existing_rules() {
  # Save current nftables ruleset before applying changes.
  # Backup file: /root/nftables.backup.YYYY-MM-DD_HHMMSS.rules
  # Sets global BACKUP_PATH variable for rollback operations.
  # Returns: 0 always (non-fatal if backup fails)
  local backup_path="/root/nftables.backup.$(date +%F_%H%M%S).rules"
  if $NFT list ruleset >/dev/null 2>&1; then
    $NFT list ruleset >"$backup_path"
    echo "Backed up current nftables ruleset to $backup_path"
    BACKUP_PATH="$backup_path"
  fi
}

show_firewall_status() {
  # Display comprehensive firewall status report.
  # Includes:
  #   - Current nftables ruleset
  #   - Listening sockets (via ss)
  #   - Network interface addresses
  #   - Recent log entries (drops and allowed)
  #   - nftables.service systemd status
  # Used by --status CLI flag.
  # Returns: 0 always
  local timestamp
  timestamp=$(date -u '+%Y-%m-%d %H:%M:%SZ')
  echo "nftables status @ ${timestamp} (UTC)"
  echo
  echo "Policy file: $POLICY_FILE"
  echo
  echo "=== nft list ruleset ==="
  if ! $NFT list ruleset; then
    echo "Unable to list nftables ruleset." >&2
  fi
  echo
  echo "=== Listening sockets (ss -tulpn) ==="
  if ! ss -tulpn 2>/dev/null; then
    echo "Failed to list listening sockets (requires ss command and sufficient privileges)." >&2
  fi
  echo
  echo "=== Interface addresses ==="
  if ! ip -o addr show | awk '
    {
      gsub(/\\/, "");
      iface=$2;
      family=$3;
      addr=$4;
      scope="";
      for (i = 5; i <= NF; i++) {
        if ($i == "scope" && (i + 1) <= NF) {
          scope = $(i + 1);
        }
      }
      printf("  %-12s %-5s %-22s scope=%s\n", iface, family, addr, scope);
    }
  ';
  then
    echo "Failed to list interface addresses." >&2
  fi
  if [ -f "$ATTEMPT_LOG" ] || [ -f "$CONNECTION_LOG" ]; then
    echo
    echo "=== Recent nftables log entries ==="
    [ -f "$ATTEMPT_LOG" ] && { echo "-- Drops:"; tail -n 20 "$ATTEMPT_LOG"; }
    [ -f "$CONNECTION_LOG" ] && { echo "-- Allowed:"; tail -n 20 "$CONNECTION_LOG"; }
  fi
  if systemctl list-unit-files | grep -q "^nftables.service"; then
    echo
    echo "=== nftables.service state ==="
    systemctl status nftables --no-pager || true
  fi
}

################################################################################
# MAIN RULESET GENERATION AND APPLICATION
################################################################################

apply_ruleset() {
  # Generate and apply complete nftables ruleset from policy configuration.
  # 
  # PROCESS:
  #   1. Parse policy file into memory structures
  #   2. Build nftables command batch with:
  #      - Base chains with DROP policy
  #      - Loopback and established connection rules
  #      - System DNS resolver exceptions
  #      - Per-service inbound rules
  #      - Per-user/group egress rules
  #      - Default drop logging
  #   3. Validate syntax with 'nft -c'
  #   4. Apply atomically with 'nft -f'
  #   5. Persist to /etc/nftables.conf
  #   6. Enable nftables.service (if available)
  #   7. Schedule rollback timer (if --safe-apply used)
  #
  # Returns: 0 on success, exits on failure
  #
  if ! parse_policy_file; then
    echo "ERROR: parse_policy_file failed" >&2
    exit 1
  fi

  # Initialize nftables command batch array
  local -a nft_cmds=()
  
  # Flush existing ruleset and create base table
  nft_cmds+=("flush ruleset")
  nft_cmds+=("add table inet firewall")
  
  # Create base chains with default DROP policy
  nft_cmds+=("add chain inet firewall input { type filter hook input priority 0; policy drop; }")
  nft_cmds+=("add chain inet firewall output { type filter hook output priority 0; policy drop; }")
  nft_cmds+=("add chain inet firewall forward { type filter hook forward priority 0; policy drop; }")

  # Base input rules: loopback, established connections, ICMP
  nft_cmds+=("add rule inet firewall input iif \"lo\" counter accept")
  nft_cmds+=("add rule inet firewall input ct state established,related counter accept")
  nft_cmds+=("add rule inet firewall input ct state invalid log prefix \"NFT-ATTEMPT DROP invalid \" flags all counter drop")
  nft_cmds+=("add rule inet firewall input icmp type { echo-request, echo-reply } counter accept")

  # Base output rules: loopback and established connections
  nft_cmds+=("add rule inet firewall output oif \"lo\" counter accept")
  nft_cmds+=("add rule inet firewall output ct state established,related counter accept")

  # WireGuard VPN support: auto-detect and allow WireGuard interfaces
  # This prevents nftables from blocking VPN connections on server restart
  local -a wg_interfaces=()
  while IFS= read -r wg_iface; do
    wg_interfaces+=("$wg_iface")
  done < <(ip -o link show | awk -F': ' '{print $2}' | grep '^wg' || true)
  
  if [ ${#wg_interfaces[@]} -gt 0 ]; then
    for wg_iface in "${wg_interfaces[@]}"; do
      # Allow all traffic on WireGuard virtual interfaces (decrypted tunnel traffic)
      nft_cmds+=("add rule inet firewall input iifname \"${wg_iface}\" log prefix \"NFT-CONN wg ${wg_iface} in \" counter accept")
      nft_cmds+=("add rule inet firewall output oifname \"${wg_iface}\" log prefix \"NFT-CONN wg ${wg_iface} out \" counter accept")
      
      # Allow WireGuard protocol (UDP) traffic on physical interface (encrypted tunnel)
      # Extract listening port from wg show
      local wg_port
      wg_port=$(wg show "$wg_iface" listen-port 2>/dev/null || echo "")
      if [ -n "$wg_port" ]; then
        nft_cmds+=("add rule inet firewall input udp dport ${wg_port} log prefix \"NFT-CONN wg ${wg_iface} udp-in \" counter accept")
        nft_cmds+=("add rule inet firewall output udp sport ${wg_port} log prefix \"NFT-CONN wg ${wg_iface} udp-out \" counter accept")
        echo "WireGuard ${wg_iface}: allowing UDP port ${wg_port}"
      fi
    done
    echo "Detected WireGuard interfaces: ${wg_interfaces[*]}"
  fi

  # Base forward rules: Docker bridge and container traffic
  # Allow Docker containers to access external networks (NAT handled by Docker's iptables)
  nft_cmds+=("add rule inet firewall forward iifname \"docker0\" oifname \"enp3s0\" ct state new,established,related log prefix \"NFT-FWD docker-out \" counter accept")
  nft_cmds+=("add rule inet firewall forward iifname \"enp3s0\" oifname \"docker0\" ct state established,related log prefix \"NFT-FWD docker-in \" counter accept")
  # Allow other Docker bridge networks (e.g., br-*)
  nft_cmds+=("add rule inet firewall forward iifname \"br-*\" oifname \"enp3s0\" ct state new,established,related log prefix \"NFT-FWD docker-br-out \" counter accept")
  nft_cmds+=("add rule inet firewall forward iifname \"enp3s0\" oifname \"br-*\" ct state established,related log prefix \"NFT-FWD docker-br-in \" counter accept")

  # System DNS resolver exception: allow systemd-resolved to reach upstream DNS
  # This prevents breaking DNS resolution when egress policy is DROP
  local -a resolvers_all=()
  collect_resolvers_ipv4 resolvers_all || {
    echo "ERROR: Failed to collect DNS resolvers" >&2
    exit 1
  }

  # Determine systemd-resolved UID (varies by distribution)
  local resolver_uid=""
  if id -u systemd-resolve >/dev/null 2>&1; then
    resolver_uid="$(id -u systemd-resolve 2>/dev/null || true)"
  elif id -u systemd-resolved >/dev/null 2>&1; then
    resolver_uid="$(id -u systemd-resolved 2>/dev/null || true)"
  fi
  
  # Create DNS resolver exception if resolver UID found
  if [ -n "$resolver_uid" ] && [ ${#resolvers_all[@]} -gt 0 ]; then
    nft_cmds+=("add set inet firewall sys_dns_resolvers { type ipv4_addr; flags interval; }")
    for ns in "${resolvers_all[@]}"; do
      nft_cmds+=("add element inet firewall sys_dns_resolvers { ${ns} }")
    done
    # Allow DNS queries (UDP/TCP port 53) and DNS-over-TLS (TCP port 853)
    nft_cmds+=("add rule inet firewall output meta skuid ${resolver_uid} ip daddr @sys_dns_resolvers udp dport 53 log prefix \"NFT-EGR dns-svc \" flags all counter accept")
    nft_cmds+=("add rule inet firewall output meta skuid ${resolver_uid} ip daddr @sys_dns_resolvers tcp dport 53 log prefix \"NFT-EGR dns-svc \" flags all counter accept")
    nft_cmds+=("add rule inet firewall output meta skuid ${resolver_uid} ip daddr @sys_dns_resolvers tcp dport 853 log prefix \"NFT-EGR dns-svc-dot \" flags all counter accept")
  fi

  # ============================================================================
  # INBOUND SERVICE RULES GENERATION
  # ============================================================================
  # Process [service_name] sections to generate input chain rules
  
  local service slug log_prefix
  local -a tcp_ports udp_ports sources users uids
  local source_set uid_set ports_expr

  for service in "${POLICY_SERVICES[@]}"; do
    # Skip user/group egress sections (processed later)
    if [[ $service =~ ^user: ]]; then
      continue
    fi
    csv_to_array tcp_ports "${SERVICE_TCP_PORTS[$service]-}"
    csv_to_array udp_ports "${SERVICE_UDP_PORTS[$service]-}"
    csv_to_array sources "${SERVICE_SOURCES[$service]-}"
    csv_to_array users "${SERVICE_USERS[$service]-}"

    if ! validate_port_list "$service" "tcp_ports" "${tcp_ports[@]}"; then
      exit 1
    fi
    if ! validate_port_list "$service" "udp_ports" "${udp_ports[@]}"; then
      exit 1
    fi

    log_prefix=${SERVICE_LOG_PREFIX[$service]-}
    if [ -n "$log_prefix" ]; then
      log_prefix="${log_prefix}"
    else
      log_prefix="NFT-CONN ${service} allow"
    fi

    if [ ${#tcp_ports[@]} -eq 0 ] && [ ${#udp_ports[@]} -eq 0 ]; then
      continue
    fi

    slug=$(sanitize_identifier "$service")
    source_set=""
    uid_set=""

    if [ ${#sources[@]} -gt 0 ]; then
      source_set="svc_${slug}_sources"
      nft_cmds+=("add set inet firewall ${source_set} { type ipv4_addr; flags interval; }")
      local entry
      for entry in "${sources[@]}"; do
        nft_cmds+=("add element inet firewall ${source_set} { ${entry} }")
      done
    fi

    if [ ${#users[@]} -gt 0 ] && resolve_users_to_uids uids "${users[@]}"; then
      uid_set="svc_${slug}_uids"
      nft_cmds+=("add set inet firewall ${uid_set} { type uid; }")
      local uid
      for uid in "${uids[@]}"; do
        nft_cmds+=("add element inet firewall ${uid_set} { ${uid} }")
      done
    fi

    if [ ${#tcp_ports[@]} -gt 0 ]; then
      if [ ${#tcp_ports[@]} -eq 1 ]; then
        ports_expr=${tcp_ports[0]}
      else
        ports_expr="{ $(join_by ', ' "${tcp_ports[@]}") }"
      fi
      local rule="add rule inet firewall input tcp dport ${ports_expr}"
      if [ -n "$source_set" ]; then
        rule+=" ip saddr @${source_set}"
      fi
      if [ -n "$uid_set" ]; then
        rule+=" meta skuid @${uid_set}"
      fi
      rule+=" ct state new log prefix \"${log_prefix} \" flags all counter accept"
      nft_cmds+=("$rule")
    fi

    if [ ${#udp_ports[@]} -gt 0 ]; then
      if [ ${#udp_ports[@]} -eq 1 ]; then
        ports_expr=${udp_ports[0]}
      else
        ports_expr="{ $(join_by ', ' "${udp_ports[@]}") }"
      fi
      local rule="add rule inet firewall input udp dport ${ports_expr}"
      if [ -n "$source_set" ]; then
        rule+=" ip saddr @${source_set}"
      fi
      rule+=" ct state new log prefix \"${log_prefix} \" flags all counter accept"
      nft_cmds+=("$rule")
    fi
  done

  # ============================================================================
  # OUTBOUND DOMAIN BLOCKING (OPTIONAL)
  # ============================================================================
  # Process block_domains directives for service-level egress blocking
  
  for service in "${POLICY_SERVICES[@]}"; do
    csv_to_array block_domains "${SERVICE_BLOCK_DOMAINS[$service]-}"
    if [ ${#block_domains[@]} -eq 0 ]; then
      continue
    fi

    slug=$(sanitize_identifier "$service")
    local -a ips=()
    local domain ip

    for domain in "${block_domains[@]}"; do
      # Resolve domain to IPv4 addresses using dig
      local domain_ips
      domain_ips=$(dig +short A "$domain" 2>/dev/null || echo "")
      for ip in $domain_ips; do
        if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
          ips+=("$ip")
        fi
      done
    done

    if [ ${#ips[@]} -gt 0 ]; then
      local block_set="svc_${slug}_block"
      nft_cmds+=("add set inet firewall ${block_set} { type ipv4_addr; flags interval; }")
      for ip in "${ips[@]}"; do
        nft_cmds+=("add element inet firewall ${block_set} { ${ip} }")
      done
      nft_cmds+=("add rule inet firewall output ip daddr @${block_set} counter drop")
    fi
  done

  # ============================================================================
  # PER-USER EGRESS (OUTBOUND) ENFORCEMENT
  # ============================================================================
  # Process [user:username] and [group:groupname] sections
  # User-specific settings override group defaults
  # Uses meta skuid matching for per-user packet filtering
  
  local username uid policy slug_u
  local -a allow_tcp allow_udp allow_domains resolved_ips
  
  # Build comprehensive user list from all sources
  declare -A _SEEN_USERS=()  # Deduplication map
  local -a _ALL_USERS=()      # Final user list
  
  # Collect users from explicit [user:username] sections
  for username in "${!USER_POLICY[@]}" "${!USER_ALLOW_DOMAINS[@]}" "${!USER_ALLOW_TCP_PORTS[@]}" "${!USER_ALLOW_UDP_PORTS[@]}"; do
    [ -n "$username" ] || continue
    if [ -z "${_SEEN_USERS[$username]-}" ]; then
      _SEEN_USERS[$username]=1
      _ALL_USERS+=("$username")
    fi
  done
  
  # Add users from [group:groupname] member lists
  local g members_arr
  for g in "${!GROUP_MEMBERS[@]}"; do
    csv_to_array members_arr "${GROUP_MEMBERS[$g]}"
    for username in "${members_arr[@]}"; do
      [ -n "$username" ] || continue
      if [ -z "${_SEEN_USERS[$username]-}" ]; then
        _SEEN_USERS[$username]=1
        _ALL_USERS+=("$username")
      fi
    done
  done

  for username in "${_ALL_USERS[@]}"; do
      if ! uid=$(id -u "$username" 2>/dev/null); then
        echo "Warning: user '$username' not found on system; skipping egress rules." >&2
        continue
      fi
      # Determine effective policy: user-specific overrides group defaults
      policy="${USER_POLICY[$username]-}"
      if [ -z "$policy" ]; then
        # Search for group membership and inherit group policy
        for g in "${!GROUP_MEMBERS[@]}"; do
          csv_to_array members_arr "${GROUP_MEMBERS[$g]}"
          if array_contains members_arr "$username"; then
            policy="${GROUP_POLICY[$g]-}"
            [ -n "$policy" ] && break
          fi
        done
      fi
      slug_u=$(sanitize_identifier "user_${username}")

      # Handle policy types
      case "$policy" in
        allow_all|ALLOW_ALL)
          # Unrestricted internet access
          nft_cmds+=("add rule inet firewall output meta skuid ${uid} log prefix \"NFT-EGR ${username} allow_all \" flags all counter accept")
          continue
          ;;
        block_all|BLOCK_ALL|"" )
          # Default DROP policy applies; process allow-list below
          ;;
        *)
          # Unknown policy value; treat as block_all for safety
          ;;
      esac

      # Collect allow-lists: user-specific or inherited from group
      csv_to_array allow_tcp "${USER_ALLOW_TCP_PORTS[$username]-}"
      csv_to_array allow_udp "${USER_ALLOW_UDP_PORTS[$username]-}"
      csv_to_array allow_domains "${USER_ALLOW_DOMAINS[$username]-}"
      
      # Inherit from group if user-specific settings are empty
      if [ ${#allow_domains[@]} -eq 0 ]; then
        for g in "${!GROUP_MEMBERS[@]}"; do
          csv_to_array members_arr "${GROUP_MEMBERS[$g]}"
          if array_contains members_arr "$username"; then
            local -a _tmp=()
            csv_to_array _tmp "${GROUP_ALLOW_DOMAINS[$g]-}"
            if [ ${#_tmp[@]} -gt 0 ]; then allow_domains=("${_tmp[@]}"); break; fi
          fi
        done
      fi
      if [ ${#allow_tcp[@]} -eq 0 ]; then
        for g in "${!GROUP_MEMBERS[@]}"; do
          csv_to_array members_arr "${GROUP_MEMBERS[$g]}"
          if array_contains members_arr "$username"; then
            local -a _tmp=()
            csv_to_array _tmp "${GROUP_ALLOW_TCP_PORTS[$g]-}"
            if [ ${#_tmp[@]} -gt 0 ]; then allow_tcp=("${_tmp[@]}"); break; fi
          fi
        done
      fi
      if [ ${#allow_udp[@]} -eq 0 ]; then
        for g in "${!GROUP_MEMBERS[@]}"; do
          csv_to_array members_arr "${GROUP_MEMBERS[$g]}"
          if array_contains members_arr "$username"; then
            local -a _tmp=()
            csv_to_array _tmp "${GROUP_ALLOW_UDP_PORTS[$g]-}"
            if [ ${#_tmp[@]} -gt 0 ]; then allow_udp=("${_tmp[@]}"); break; fi
          fi
        done
      fi

      # Sensible default ports if domains are provided but ports omitted
      if [ ${#allow_tcp[@]} -eq 0 ] && [ ${#allow_udp[@]} -eq 0 ] && [ ${#allow_domains[@]} -gt 0 ]; then
        allow_tcp=(80 443)
      fi

      if ! validate_port_list "user:$username" "egress_allow_tcp_ports" "${allow_tcp[@]}"; then
        exit 1
      fi
      if ! validate_port_list "user:$username" "egress_allow_udp_ports" "${allow_udp[@]}"; then
        exit 1
      fi

      resolved_ips=()
      if [ ${#allow_domains[@]} -gt 0 ]; then
        resolve_domains_to_ips resolved_ips "${allow_domains[@]}"
      fi

      if [ ${#resolved_ips[@]} -gt 0 ]; then
        local allow_set="u_${slug_u}_egress_ips"
        nft_cmds+=("add set inet firewall ${allow_set} { type ipv4_addr; flags interval; }")
        # Deduplicate IPs and filter out those within CIDR ranges to avoid conflicts
        local -a unique_ips=() cidrs=() single_ips=()
        local ip cidr in_cidr
        local -A seen_ips=()
        
        # Separate CIDRs from single IPs
        for ip in "${resolved_ips[@]}"; do
          if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
            if [ -z "${seen_ips[$ip]+x}" ]; then
              seen_ips[$ip]=1
              cidrs+=("$ip")
            fi
          else
            single_ips+=("$ip")
          fi
        done
        
        # Add CIDRs first
        unique_ips=("${cidrs[@]}")
        
        # Add single IPs only if not in any CIDR
        for ip in "${single_ips[@]}"; do
          if [ -z "${seen_ips[$ip]+x}" ]; then
            seen_ips[$ip]=1
            in_cidr=0
            for cidr in "${cidrs[@]}"; do
              if ip_in_cidr "$ip" "$cidr" 2>/dev/null; then
                in_cidr=1
                break
              fi
            done
            [ $in_cidr -eq 0 ] && unique_ips+=("$ip")
          fi
        done
        
        # Add all unique IPs in one command to avoid duplicates
        if [ ${#unique_ips[@]} -gt 0 ]; then
          nft_cmds+=("add element inet firewall ${allow_set} { $(join_by ', ' "${unique_ips[@]}") }")
        fi

        if [ ${#allow_tcp[@]} -gt 0 ]; then
          if [ ${#allow_tcp[@]} -eq 1 ]; then
            ports_expr=${allow_tcp[0]}
          else
            ports_expr="{ $(join_by ', ' "${allow_tcp[@]}") }"
          fi
          nft_cmds+=("add rule inet firewall output meta skuid ${uid} ip daddr @${allow_set} tcp dport ${ports_expr} log prefix \"NFT-EGR ${username} allow \" flags all counter accept")
        fi
        if [ ${#allow_udp[@]} -gt 0 ]; then
          if [ ${#allow_udp[@]} -eq 1 ]; then
            ports_expr=${allow_udp[0]}
          else
            ports_expr="{ $(join_by ', ' "${allow_udp[@]}") }"
          fi
          nft_cmds+=("add rule inet firewall output meta skuid ${uid} ip daddr @${allow_set} udp dport ${ports_expr} log prefix \"NFT-EGR ${username} allow \" flags all counter accept")
        fi
        
        # Allow ICMP (ping) to allowed destinations
        nft_cmds+=("add rule inet firewall output meta skuid ${uid} ip daddr @${allow_set} icmp type { echo-request, echo-reply } log prefix \"NFT-EGR ${username} icmp \" flags all counter accept")
      fi

      # Grant DNS access when domains are specified (required for resolution)
      if [ ${#allow_domains[@]} -gt 0 ]; then
        local -a resolvers=()
        local ns iprx='^([0-9]+\.){3}[0-9]+$'
        while read -r ns; do
          ns=$(echo "$ns" | awk '/^nameserver[[:space:]]+[0-9.]+/ {print $2}')
          if [[ $ns =~ $iprx ]]; then
            resolvers+=("$ns")
          fi
        done < /etc/resolv.conf || true
        if [ ${#resolvers[@]} -gt 0 ]; then
          local dns_set="u_${slug_u}_dns"
          nft_cmds+=("add set inet firewall ${dns_set} { type ipv4_addr; flags interval; }")
          # Deduplicate DNS resolver IPs
          local -a unique_dns=()
          local -A seen_dns=()
          for ip in "${resolvers[@]}"; do
            if [ -z "${seen_dns[$ip]+x}" ]; then
              seen_dns[$ip]=1
              unique_dns+=("$ip")
            fi
          done
          if [ ${#unique_dns[@]} -gt 0 ]; then
            nft_cmds+=("add element inet firewall ${dns_set} { $(join_by ', ' "${unique_dns[@]}") }")
          fi
          nft_cmds+=("add rule inet firewall output meta skuid ${uid} ip daddr @${dns_set} udp dport 53 log prefix \"NFT-EGR ${username} dns \" flags all counter accept")
          nft_cmds+=("add rule inet firewall output meta skuid ${uid} ip daddr @${dns_set} tcp dport 53 log prefix \"NFT-EGR ${username} dns \" flags all counter accept")
        fi
      fi
      # Note: Users without explicit allow-lists remain blocked by default DROP
  done

  # ============================================================================
  # DEFAULT DROP LOGGING
  # ============================================================================
  # Log and drop all packets not matched by explicit allow rules
  nft_cmds+=("add rule inet firewall input log prefix \"NFT-ATTEMPT DROP input-default \" flags all counter drop")
  nft_cmds+=("add rule inet firewall output log prefix \"NFT-ATTEMPT DROP output-default \" flags all counter drop")
  nft_cmds+=("add rule inet firewall forward log prefix \"NFT-ATTEMPT DROP forward-default \" flags all counter drop")

  # ============================================================================
  # RULESET VALIDATION AND APPLICATION
  # ============================================================================
  
  # Write command batch to temporary file
  local nft_script
  nft_script=$(mktemp)
  printf '%s\n' "${nft_cmds[@]}" >"$nft_script"

  # Validate syntax before applying
  if ! $NFT -c -f "$nft_script"; then
    echo "nftables syntax check failed; ruleset not applied." >&2
    echo "ERROR: Validation failed, script kept at $nft_script for inspection" >&2
    exit 1
  fi

  # Dry-run mode: validate only, do not apply
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "Dry run successful. No changes were applied."
    rm -f "$nft_script"
    return 0
  fi

  # Prepare logging and backup before applying changes
  setup_log_targets
  backup_existing_rules

  # Apply ruleset atomically
  $NFT -f "$nft_script"
  rm -f "$nft_script"

  # Persist ruleset for boot-time restoration
  if [ -d /etc ]; then
    $NFT list ruleset >/etc/nftables.conf
    # Enable nftables service if systemd is available
    if systemctl list-unit-files | grep -q "^nftables.service"; then
      systemctl enable nftables >/dev/null 2>&1 || true
      systemctl restart nftables >/dev/null 2>&1 || true
    fi
  fi

  echo "nftables ruleset applied. Review $POLICY_FILE for future changes."

  # ============================================================================
  # SAFE-APPLY ROLLBACK TIMER (OPTIONAL)
  # ============================================================================
  # Schedule automatic rollback unless user confirms with: touch /root/.nft_ok
  if [ "$SAFE_ROLLBACK_DELAY" -gt 0 ]; then
    if [ -n "$BACKUP_PATH" ]; then
      cp -f "$BACKUP_PATH" /root/nftables.rollback.rules || true
    else
      $NFT list ruleset >/root/nftables.rollback.rules || true
    fi
    if command -v systemd-run >/dev/null 2>&1; then
      ROLLBACK_UNIT_NAME="nft-rollback-$(date +%s)"
      systemd-run --unit "$ROLLBACK_UNIT_NAME" --on-active="${SAFE_ROLLBACK_DELAY}" \
        /bin/bash -lc "[[ -f /root/.nft_ok ]] || $NFT -f /root/nftables.rollback.rules"
      echo "Scheduled rollback in ${SAFE_ROLLBACK_DELAY}s as unit '$ROLLBACK_UNIT_NAME'."
      echo "Confirm keep: sudo touch /root/.nft_ok && sudo systemctl stop $ROLLBACK_UNIT_NAME"
    else
      nohup /bin/bash -lc "sleep ${SAFE_ROLLBACK_DELAY}; [[ -f /root/.nft_ok ]] || $NFT -f /root/nftables.rollback.rules" \
        >/dev/null 2>&1 &
      echo "Scheduled background rollback in ${SAFE_ROLLBACK_DELAY}s (nohup)."
      echo "Confirm keep: sudo touch /root/.nft_ok"
    fi
  fi
}

################################################################################
# COMMAND-LINE INTERFACE
################################################################################

usage() {
  # Display help message with available options and usage examples.
  # Called by --help flag or on invalid arguments.
  cat <<'EOF'
Usage: sudo nftablets.suite.sh [options]

Options:
  --dry-run       Validate configuration and ruleset without applying changes.
  --status        Display current nftables rules, sockets, and logs.
  --init-config   Create the policy configuration template if missing.
  --safe-apply S  Apply rules and schedule auto-rollback after S seconds unless confirmed.
  --help          Show this help message.

Notes:
  - Outbound (egress) policy is DROP by default.
  - Configure per-user egress in the policy file with [user:USERNAME] sections.
  - DNS is preserved via allowing the system resolver (systemd-resolve[d]) to reach resolvers in /etc/resolv.conf on port 53.
EOF
}

################################################################################
# ARGUMENT PARSING AND MAIN EXECUTION
################################################################################

# Process command-line arguments
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --status)
      show_firewall_status
      exit 0
      ;;
    --init-config)
      initialize_policy_file
      exit 0
      ;;
    --safe-apply)
      if [ -n "${2-}" ] && [[ ${2} =~ ^[0-9]+$ ]] && [ "$2" -gt 0 ]; then
        SAFE_ROLLBACK_DELAY="$2"
        shift 2
      else
        echo "--safe-apply requires a positive integer seconds argument." >&2
        exit 1
      fi
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

# Execute main ruleset generation and application
apply_ruleset
