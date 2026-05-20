#!/bin/bash
################################################################################
# install.sh - nftablets suite installation and validation
################################################################################
# DESCRIPTION:
#   Installs nftablets firewall suite components, validates prerequisites,
#   checks policy file for user/group existence, and reports issues.
#
# FEATURES:
#   - Installs main script, discover utility, and systemd units
#   - Checks system dependencies (nftables, dnsutils, rsyslog)
#   - Validates policy file syntax and user/group existence
#   - Creates log directory with proper permissions
#   - Enables and starts systemd timer (optional)
#
# USAGE:
#   sudo ./install.sh [--with-timer] [--dry-run] [--policy-file PATH]
#
# OPTIONS:
#   --with-timer       Enable and start systemd refresh timer
#   --dry-run          Show what would be installed without making changes
#   --policy-file PATH Use custom policy file path (default: /etc/nftables.d/policy.conf)
#   --help             Show this help message
#
# LICENSE: MIT
################################################################################

set -Eeuo pipefail

################################################################################
# GLOBAL CONFIGURATION
################################################################################

# Script directory and related paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"

# Installation flags
ENABLE_TIMER=0
DRY_RUN=0
POLICY_FILE=""

# Installation paths
INSTALL_BIN_DIR="/usr/sbin"
INSTALL_ETC_DIR="/etc/nftables.d"
INSTALL_LOG_DIR="/var/log/nftables"
INSTALL_SYSTEMD_DIR="/etc/systemd/system"

# Source files to install
SUITE_SCRIPT="${SCRIPT_DIR}/nftablets.suite.sh"
DISCOVER_SCRIPT="${SCRIPT_DIR}/nftablets_discover.py"
REFRESH_SERVICE="${SCRIPT_DIR}/systemd/nftablets-refresh.service"
REFRESH_TIMER="${SCRIPT_DIR}/systemd/nftablets-refresh.timer"
DEFAULT_POLICY="${SCRIPT_DIR}/nftablets.policy.conf"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

################################################################################
# UTILITY FUNCTIONS
################################################################################

print_header() {
    echo -e "${BLUE}===> $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}" >&2
}

log_dry_run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "${BLUE}[DRY-RUN]${NC} $1"
    fi
}

check_root() {
    if [ "${EUID}" -ne 0 ]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

check_command_exists() {
    # Check if a command is available in PATH
    # Args: $1 = command name, $2 = package name (for suggestions)
    # Returns: 0 if exists, 1 if not
    if command -v "$1" &>/dev/null; then
        return 0
    else
        return 1
    fi
}

check_file_exists() {
    # Check if a file exists
    # Args: $1 = file path
    # Returns: 0 if exists, 1 if not
    if [ -f "$1" ]; then
        return 0
    else
        return 1
    fi
}

install_file() {
    # Install a file with proper permissions
    # Args: $1 = source, $2 = destination, $3 = mode (default 0644)
    local src=$1
    local dst=$2
    local mode=${3:-0644}
    
    if [ ! -f "$src" ]; then
        print_error "Source file not found: $src"
        return 1
    fi
    
    if [ "$DRY_RUN" -eq 1 ]; then
        log_dry_run "Would install $src -> $dst (mode: $mode)"
        return 0
    fi
    
    mkdir -p "$(dirname "$dst")"
    cp -v "$src" "$dst"
    chmod "$mode" "$dst"
}

create_directory() {
    # Create directory with proper permissions
    # Args: $1 = path, $2 = permissions (default 0755), $3 = owner:group (optional)
    local path=$1
    local perms=${2:-0755}
    local owner=${3:-}
    
    if [ "$DRY_RUN" -eq 1 ]; then
        log_dry_run "Would create directory: $path (perms: $perms)"
        return 0
    fi
    
    mkdir -p "$path"
    chmod "$perms" "$path"
    if [ -n "$owner" ]; then
        chown "$owner" "$path"
    fi
}

################################################################################
# DEPENDENCY CHECKING
################################################################################

check_dependencies() {
    # Verify required and optional system packages
    # Returns: 0 if all required deps present, 1 otherwise
    print_header "Checking system dependencies"
    
    local required_missing=0
    local optional_missing=""
    
    # Required dependencies
    if check_command_exists "nft"; then
        print_success "nftables (nft) is installed"
    else
        print_error "nftables is NOT installed (required)"
        print_error "  Install: sudo apt-get install -y nftables"
        required_missing=1
    fi
    
    # Check for dig (dnsutils)
    if check_command_exists "dig"; then
        print_success "dnsutils (dig) is installed"
    else
        print_warning "dnsutils is NOT installed (recommended for domain resolution)"
        optional_missing="${optional_missing}dnsutils "
    fi
    
    # Check for rsyslog
    if check_command_exists "rsyslogd" || systemctl list-unit-files | grep -q "rsyslog.service"; then
        print_success "rsyslog is installed"
    else
        print_warning "rsyslog is NOT installed (optional, but recommended for logging)"
        optional_missing="${optional_missing}rsyslog "
    fi
    
    if [ "$required_missing" -eq 1 ]; then
        print_error "Missing required dependencies. Please install them and retry."
        return 1
    fi
    
    if [ -n "$optional_missing" ]; then
        print_warning "Missing optional packages: $optional_missing"
        print_warning "Install with: sudo apt-get install -y $optional_missing"
    fi
    
    return 0
}

################################################################################
# POLICY VALIDATION
################################################################################

validate_policy_users() {
    # Check that all users/groups referenced in policy exist on system
    # Args: $1 = policy file path
    # Returns: 0 if valid, 1 if issues found
    
    local policy_file=$1
    local has_errors=0
    local -a policy_users=()
    local -a missing_users=()
    local -a found_users=()
    
    print_header "Validating policy file: $policy_file"
    
    if [ ! -f "$policy_file" ]; then
        print_warning "Policy file not found: $policy_file"
        print_warning "Will be initialized on first run with default template"
        return 0
    fi
    
    # Extract all [user:username] sections
    local line section_type section_name
    while IFS= read -r line || [ -n "$line" ]; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$(echo "$line" | tr -d '[:space:]')" ]] && continue
        
        # Match [user:username] sections
        if [[ "$line" =~ ^\[user:([[:alnum:]_\.-]+)\] ]]; then
            section_name="${BASH_REMATCH[1]}"
            policy_users+=("$section_name")
        fi
        
        # Match [group:groupname] sections
        if [[ "$line" =~ ^\[group:([[:alnum:]_\.-]+)\] ]]; then
            section_name="${BASH_REMATCH[1]}"
            policy_users+=("$section_name")
        fi
        
        # Extract users from 'users=' key in service sections
        if [[ "$line" =~ ^[[:space:]]*users[[:space:]]*=[[:space:]]*(.+)$ ]]; then
            local users_str="${BASH_REMATCH[1]}"
            IFS=',' read -ra user_list <<<"$users_str"
            for user in "${user_list[@]}"; do
                user=$(echo "$user" | tr -d '[:space:]')
                # Skip numeric UIDs
                if ! [[ "$user" =~ ^[0-9]+$ ]]; then
                    policy_users+=("$user")
                fi
            done
        fi
    done <"$policy_file"
    
    # Check each user exists
    if [ ${#policy_users[@]} -gt 0 ]; then
        echo
        print_header "Checking referenced users/groups"
        
        # Deduplicate user list
        local -a unique_users
        declare -A seen
        for user in "${policy_users[@]}"; do
            if [ -z "${seen[$user]:-}" ]; then
                unique_users+=("$user")
                seen[$user]=1
            fi
        done
        
        for user in "${unique_users[@]}"; do
            if id "$user" &>/dev/null 2>&1; then
                local uid=$(id -u "$user")
                print_success "User/group '$user' exists (UID: $uid)"
                found_users+=("$user")
            else
                print_error "User/group '$user' DOES NOT EXIST"
                missing_users+=("$user")
                has_errors=1
            fi
        done
    fi
    
    echo
    print_header "Policy validation summary"
    echo "  Total referenced users/groups: ${#policy_users[@]}"
    echo "  Found on system: ${#found_users[@]}"
    echo "  Missing: ${#missing_users[@]}"
    
    if [ ${#missing_users[@]} -gt 0 ]; then
        print_error "The following users/groups from policy do NOT exist on this system:"
        printf '  - %s\n' "${missing_users[@]}"
        echo
        print_warning "Options to fix:"
        echo "  1. Create the missing users: sudo useradd <username>"
        echo "  2. Remove or correct the entries in the policy file"
        echo "  3. Use numeric UIDs instead of usernames if users exist with different names"
        return 1
    fi
    
    return 0
}

################################################################################
# SOURCE FILE VALIDATION
################################################################################

validate_source_files() {
    # Check that all required source files exist in the script directory
    # Returns: 0 if all present, 1 if any missing
    print_header "Validating source files"
    
    local all_present=0
    
    if check_file_exists "$SUITE_SCRIPT"; then
        print_success "Found nftablets.suite.sh"
    else
        print_error "Missing nftablets.suite.sh in $SCRIPT_DIR"
        all_present=1
    fi
    
    if check_file_exists "$DISCOVER_SCRIPT"; then
        print_success "Found nftablets_discover.py"
    else
        print_warning "Missing nftablets_discover.py (discovery tool is optional)"
    fi
    
    if check_file_exists "$REFRESH_SERVICE"; then
        print_success "Found nftablets-refresh.service"
    else
        print_warning "Missing nftablets-refresh.service (systemd integration)"
    fi
    
    if check_file_exists "$REFRESH_TIMER"; then
        print_success "Found nftablets-refresh.timer"
    else
        print_warning "Missing nftablets-refresh.timer (systemd integration)"
    fi
    
    if check_file_exists "$DEFAULT_POLICY"; then
        print_success "Found nftablets.policy.conf"
    else
        print_warning "Default policy not found in $SCRIPT_DIR"
    fi
    
    if [ "$all_present" -eq 1 ]; then
        print_error "Cannot proceed without nftablets.suite.sh"
        return 1
    fi
    
    return 0
}

################################################################################
# INSTALLATION STEPS
################################################################################

install_binaries() {
    # Install main script and discovery tool to /usr/sbin/
    print_header "Installing binary scripts"
    
    if install_file "$SUITE_SCRIPT" "$INSTALL_BIN_DIR/nftablets.suite.sh" 0755; then
        print_success "Installed nftablets.suite.sh"
    else
        return 1
    fi
    
    if check_file_exists "$DISCOVER_SCRIPT"; then
        if install_file "$DISCOVER_SCRIPT" "$INSTALL_BIN_DIR/nftablets-discover" 0755; then
            print_success "Installed nftablets-discover"
        fi
    fi
    
    return 0
}

install_config() {
    # Install default policy configuration
    print_header "Installing configuration"
    
    if [ "$DRY_RUN" -eq 1 ]; then
        log_dry_run "Would install policy to $INSTALL_ETC_DIR/policy.conf"
        return 0
    fi
    
    create_directory "$INSTALL_ETC_DIR" 0755
    
    # Only install default policy if none exists
    if [ -f "$INSTALL_ETC_DIR/policy.conf" ]; then
        print_warning "Policy file already exists at $INSTALL_ETC_DIR/policy.conf"
        print_warning "Keeping existing configuration; backup saved if needed"
        
        # But validate the existing one
        if validate_policy_users "$INSTALL_ETC_DIR/policy.conf"; then
            :  # Validation passed, do nothing
        else
            print_warning "Validation of existing policy found issues (non-fatal)"
        fi
    else
        if check_file_exists "$DEFAULT_POLICY"; then
            install_file "$DEFAULT_POLICY" "$INSTALL_ETC_DIR/policy.conf" 0644
            print_success "Installed default policy to $INSTALL_ETC_DIR/policy.conf"
            validate_policy_users "$INSTALL_ETC_DIR/policy.conf"
        else
            print_warning "Default policy template not found; skipping"
            print_warning "Run: sudo nftablets.suite.sh --init-config"
        fi
    fi
    
    return 0
}

install_logging() {
    # Create log directory with proper permissions
    print_header "Setting up logging"
    
    create_directory "$INSTALL_LOG_DIR" 0750 "root:adm"
    
    if [ "$DRY_RUN" -eq 0 ]; then
        touch "$INSTALL_LOG_DIR/attempts.log" "$INSTALL_LOG_DIR/connections.log"
        chmod 0640 "$INSTALL_LOG_DIR"/*.log
        chown root:adm "$INSTALL_LOG_DIR"/*.log 2>/dev/null || true
        print_success "Created log directory and files at $INSTALL_LOG_DIR"
    else
        print_success "Would create log directory at $INSTALL_LOG_DIR"
    fi
    
    return 0
}

install_systemd_units() {
    # Install systemd service and timer units
    print_header "Installing systemd units"
    
    if ! check_file_exists "$REFRESH_SERVICE" || ! check_file_exists "$REFRESH_TIMER"; then
        print_warning "Systemd unit files not found; skipping"
        return 0
    fi
    
    if install_file "$REFRESH_SERVICE" "$INSTALL_SYSTEMD_DIR/nftablets-refresh.service" 0644; then
        print_success "Installed nftablets-refresh.service"
    fi
    
    if install_file "$REFRESH_TIMER" "$INSTALL_SYSTEMD_DIR/nftablets-refresh.timer" 0644; then
        print_success "Installed nftablets-refresh.timer"
    fi
    
    if [ "$DRY_RUN" -eq 0 ]; then
        systemctl daemon-reload
        print_success "Reloaded systemd configuration"
    else
        log_dry_run "Would reload systemd daemon"
    fi
    
    return 0
}

enable_systemd_timer() {
    # Enable and start the refresh timer
    if [ "$ENABLE_TIMER" -eq 0 ]; then
        return 0
    fi
    
    print_header "Enabling systemd refresh timer"
    
    if [ "$DRY_RUN" -eq 0 ]; then
        systemctl enable nftablets-refresh.timer
        systemctl start nftablets-refresh.timer
        print_success "Enabled and started nftablets-refresh.timer"
        
        echo
        systemctl list-timers nftablets-refresh.timer || true
    else
        log_dry_run "Would enable and start nftablets-refresh.timer"
    fi
    
    return 0
}

show_post_install_info() {
    # Display post-installation information and next steps
    print_header "Installation complete!"
    echo
    echo "Next steps:"
    echo "  1. Review the policy configuration:"
    echo "     sudo nano $INSTALL_ETC_DIR/policy.conf"
    echo
    echo "  2. Validate the policy before applying:"
    echo "     sudo nftablets.suite.sh --dry-run"
    echo
    echo "  3. Apply the firewall rules:"
    echo "     sudo nftablets.suite.sh"
    echo
    echo "  4. Check firewall status:"
    echo "     sudo nftablets.suite.sh --status"
    echo
    echo "  5. (Optional) Discover current listening ports and generate policy:"
    echo "     sudo nftablets-discover >> $INSTALL_ETC_DIR/policy.conf"
    echo
    echo "Useful commands:"
    echo "  - Reload rules from policy: sudo nftablets.suite.sh"
    echo "  - View current ruleset: sudo nft list ruleset"
    echo "  - View firewall logs: sudo tail -f /var/log/nftables/*.log"
    echo "  - Disable firewall (emergency): sudo nft flush ruleset"
    echo
    if [ "$ENABLE_TIMER" -eq 1 ]; then
        echo "Systemd timer enabled:"
        echo "  - Refresh rate: hourly"
        echo "  - View next run: systemctl list-timers nftablets-refresh.timer"
        echo "  - Check logs: journalctl -u nftablets-refresh.service -f"
        echo
    fi
}

################################################################################
# COMMAND-LINE INTERFACE
################################################################################

usage() {
    cat <<'EOF'
Usage: sudo ./install.sh [OPTIONS]

OPTIONS:
  --with-timer       Enable and start systemd refresh timer (hourly)
  --dry-run          Show what would be installed without making changes
  --policy-file PATH Use custom policy file path for validation
  --help             Show this help message

DESCRIPTION:
  Installs nftablets firewall suite components, validates prerequisites,
  and checks policy file for user/group existence.

EXAMPLES:
  # Standard installation
  sudo ./install.sh

  # Installation with timer enabled
  sudo ./install.sh --with-timer

  # Preview what would be installed
  sudo ./install.sh --dry-run

  # Validate custom policy file
  sudo ./install.sh --policy-file /custom/path/policy.conf

EOF
}

################################################################################
# MAIN EXECUTION
################################################################################

main() {
    # Parse command-line arguments
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --with-timer)
                ENABLE_TIMER=1
                shift
                ;;
            --dry-run)
                DRY_RUN=1
                shift
                ;;
            --policy-file)
                POLICY_FILE="$2"
                shift 2
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Verify root
    check_root
    
    # Display mode
    echo
    if [ "$DRY_RUN" -eq 1 ]; then
        print_header "DRY-RUN MODE (no changes will be made)"
    fi
    echo
    
    # Execute installation steps
    validate_source_files || exit 1
    check_dependencies || exit 1
    
    # Validate policy (use custom path if provided, otherwise use default location)
    if [ -n "$POLICY_FILE" ]; then
        validate_policy_users "$POLICY_FILE" || print_warning "Policy validation found issues"
    elif [ -f "$DEFAULT_POLICY" ]; then
        validate_policy_users "$DEFAULT_POLICY" || print_warning "Default policy validation found issues"
    fi
    
    echo
    
    install_binaries || exit 1
    install_config || exit 1
    install_logging || exit 1
    install_systemd_units || exit 1
    enable_systemd_timer || exit 1
    
    echo
    show_post_install_info
    echo
    
    if [ "$DRY_RUN" -eq 1 ]; then
        print_header "DRY-RUN COMPLETE"
        echo "Run without --dry-run to perform actual installation:"
        echo "  sudo $SCRIPT_NAME"
    fi
}

main "$@"
