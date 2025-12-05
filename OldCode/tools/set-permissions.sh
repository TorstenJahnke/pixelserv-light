#!/bin/bash
# ============================================================================
# TLSGate NX - Permission Setup Script
# ============================================================================
#
# Sets up secure permissions for TLSGate NX instances
#
# Usage:
#   sudo ./set-permissions.sh /opt/tlsgateNG/aviontexv4
#   sudo ./set-permissions.sh /opt/tlsgateNG/aviontexv6
#
# Directory structure created:
#   BASE_DIR/
#   ├── cache/           (tlsgateNG:tlsgateNG, 755) - Generated certificates
#   └── rootCA/          (root:root, 755) - CA certificates
#       ├── ca.key       (root:root, 600) - CA private key [PROTECTED]
#       ├── ca.crt       (root:root, 644) - SubCA certificate
#       └── rootca.crt   (root:root, 644) - RootCA certificate (optional)
#
# Security Model:
#   1. TLSGate starts as root
#   2. Binds privileged ports (80/443)
#   3. Loads CA key (readable only by root)
#   4. Drops privileges to tlsgateNG user
#   5. Workers generate certs in cache/ (as tlsgateNG)
#
# ============================================================================

set -e  # Exit on error

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
USER="tlsgateNG"
GROUP="tlsgateNG"

# ============================================================================
# Helper Functions
# ============================================================================

print_header() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║  TLSGate NX - Permission Setup                        ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ ERROR: $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  WARNING: $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        echo "Usage: sudo $0 <base_directory>"
        exit 1
    fi
}

# Create user and group if they don't exist
create_user_group() {
    # Check if group exists
    if ! getent group "$GROUP" > /dev/null 2>&1; then
        print_info "Creating group: $GROUP"
        groupadd --system "$GROUP"
        print_success "Group created: $GROUP"
    else
        print_info "Group already exists: $GROUP"
    fi

    # Check if user exists
    if ! id "$USER" > /dev/null 2>&1; then
        print_info "Creating user: $USER"
        useradd --system --gid "$GROUP" --home-dir /nonexistent \
                --shell /usr/sbin/nologin --comment "TLSGate NX Service User" "$USER"
        print_success "User created: $USER"
    else
        print_info "User already exists: $USER"
    fi
}

# Create directory structure
create_directories() {
    local base_dir="$1"

    print_info "Creating directory structure..."

    # Create base directory
    if [[ ! -d "$base_dir" ]]; then
        mkdir -p "$base_dir"
        print_success "Created: $base_dir"
    fi

    # Create cache directory
    if [[ ! -d "$base_dir/cache" ]]; then
        mkdir -p "$base_dir/cache"
        print_success "Created: $base_dir/cache"
    fi

    # Create rootCA directory
    if [[ ! -d "$base_dir/rootCA" ]]; then
        mkdir -p "$base_dir/rootCA"
        print_success "Created: $base_dir/rootCA"
    fi
}

# Set permissions
set_permissions() {
    local base_dir="$1"

    print_info "Setting permissions..."

    # Base directory: tlsgateNG can read/write
    chown "$USER:$GROUP" "$base_dir"
    chmod 755 "$base_dir"
    print_success "Base directory: $base_dir (755, $USER:$GROUP)"

    # Cache directory: tlsgateNG can write generated certs here
    chown -R "$USER:$GROUP" "$base_dir/cache"
    chmod 755 "$base_dir/cache"
    print_success "Cache directory: $base_dir/cache (755, $USER:$GROUP)"

    # rootCA directory: root owns, tlsgateNG can read
    chown -R root:root "$base_dir/rootCA"
    chmod 755 "$base_dir/rootCA"
    print_success "rootCA directory: $base_dir/rootCA (755, root:root)"

    # CA private key: ONLY root can read (600)
    if [[ -f "$base_dir/rootCA/ca.key" ]]; then
        chown root:root "$base_dir/rootCA/ca.key"
        chmod 600 "$base_dir/rootCA/ca.key"
        print_success "CA private key: ca.key (600, root:root) [PROTECTED]"
    else
        print_warning "CA key not found: $base_dir/rootCA/ca.key"
        print_info "Place your CA key here and run this script again"
    fi

    # CA certificates: root owns, world readable (644)
    for cert_file in "$base_dir/rootCA"/*.{crt,pem}; do
        if [[ -f "$cert_file" ]]; then
            chown root:root "$cert_file"
            chmod 644 "$cert_file"
            print_success "CA certificate: $(basename "$cert_file") (644, root:root)"
        fi
    done

    # Generated certificates in cache: tlsgateNG owns
    if [[ -d "$base_dir/cache" ]] && [[ -n "$(ls -A "$base_dir/cache" 2>/dev/null)" ]]; then
        chown -R "$USER:$GROUP" "$base_dir/cache"/*
        chmod 644 "$base_dir/cache"/*.pem 2>/dev/null || true
        print_success "Generated certificates in cache/ (644, $USER:$GROUP)"
    fi
}

# Validate setup
validate_setup() {
    local base_dir="$1"
    local errors=0

    echo ""
    print_info "Validating setup..."

    # Check if user exists
    if ! id "$USER" > /dev/null 2>&1; then
        print_error "User $USER does not exist"
        ((errors++))
    fi

    # Check if directories exist
    if [[ ! -d "$base_dir" ]]; then
        print_error "Base directory does not exist: $base_dir"
        ((errors++))
    fi

    if [[ ! -d "$base_dir/cache" ]]; then
        print_error "Cache directory does not exist: $base_dir/cache"
        ((errors++))
    fi

    if [[ ! -d "$base_dir/rootCA" ]]; then
        print_error "rootCA directory does not exist: $base_dir/rootCA"
        ((errors++))
    fi

    # Check CA key permissions (if exists)
    if [[ -f "$base_dir/rootCA/ca.key" ]]; then
        local key_perms=$(stat -c "%a" "$base_dir/rootCA/ca.key" 2>/dev/null || stat -f "%Lp" "$base_dir/rootCA/ca.key" 2>/dev/null)
        if [[ "$key_perms" != "600" ]]; then
            print_error "CA key has wrong permissions: $key_perms (should be 600)"
            ((errors++))
        fi

        local key_owner=$(stat -c "%U:%G" "$base_dir/rootCA/ca.key" 2>/dev/null || stat -f "%Su:%Sg" "$base_dir/rootCA/ca.key" 2>/dev/null)
        if [[ "$key_owner" != "root:root" ]]; then
            print_error "CA key has wrong owner: $key_owner (should be root:root)"
            ((errors++))
        fi
    fi

    if [[ $errors -eq 0 ]]; then
        print_success "Validation passed!"
        return 0
    else
        print_error "Validation failed with $errors error(s)"
        return 1
    fi
}

# Print summary
print_summary() {
    local base_dir="$1"

    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Setup Complete!${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Base directory: $base_dir"
    echo "User/Group: $USER:$GROUP"
    echo ""
    echo "Directory structure:"
    echo "  $base_dir/                    (755, $USER:$GROUP)"
    echo "  ├── cache/                      (755, $USER:$GROUP) - Generated certs"
    echo "  └── rootCA/                     (755, root:root) - CA certificates"
    if [[ -f "$base_dir/rootCA/ca.key" ]]; then
        echo "      ├── ca.key                  (600, root:root) [PROTECTED]"
    else
        echo "      ├── ca.key                  (NOT FOUND - place your CA key here)"
    fi
    echo "      └── *.crt, *.pem            (644, root:root)"
    echo ""
    echo "Next steps:"
    if [[ ! -f "$base_dir/rootCA/ca.key" ]]; then
        echo "  1. Place your CA certificates in $base_dir/rootCA/"
        echo "     - ca.key (private key)"
        echo "     - ca.crt or SubCA (SubCA certificate)"
        echo "     - rootca.crt or RootCA (RootCA certificate, optional)"
        echo "  2. Run this script again: sudo $0 $base_dir"
        echo "  3. Start TLSGate NX:"
    else
        echo "  1. Start TLSGate NX:"
    fi
    echo "     sudo ./tlsgateNG -l <IP> -p 80 -s 443 -D $base_dir -u $USER"
    echo ""
    echo "Security model:"
    echo "  • TLSGate starts as root (to bind ports 80/443)"
    echo "  • Loads CA key from rootCA/ (readable only by root)"
    echo "  • Drops privileges to $USER user"
    echo "  • Workers generate certificates in cache/ (as $USER)"
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
}

# ============================================================================
# Main Script
# ============================================================================

main() {
    local base_dir="$1"

    print_header

    # Validate arguments
    if [[ -z "$base_dir" ]]; then
        print_error "Missing argument: base directory"
        echo ""
        echo "Usage: $0 <base_directory>"
        echo ""
        echo "Examples:"
        echo "  $0 /opt/tlsgateNG/aviontexv4"
        echo "  $0 /opt/tlsgateNG/aviontexv6"
        exit 1
    fi

    # Check if running as root
    check_root

    # Create user and group
    create_user_group

    # Create directories
    create_directories "$base_dir"

    # Set permissions
    set_permissions "$base_dir"

    # Validate
    validate_setup "$base_dir"

    # Print summary
    print_summary "$base_dir"
}

# Run main function
main "$@"
