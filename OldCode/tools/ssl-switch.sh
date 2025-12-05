#!/bin/bash
# =============================================================================
# ssl-switch.sh - Switch between OpenSSL and Tongsuo installations
# =============================================================================
#
# This script allows you to easily switch between different SSL library
# installations (OpenSSL versions and Tongsuo) in your current shell session.
#
# Usage:
#   source ssl-switch.sh [command] [version]
#
# Commands:
#   list              - List all available installations
#   openssl [version] - Activate OpenSSL (optionally specific version)
#   tongsuo [version] - Activate Tongsuo (optionally specific version)
#   system            - Revert to system OpenSSL
#   status            - Show current active SSL library
#   help              - Show this help
#
# Examples:
#   source ssl-switch.sh list
#   source ssl-switch.sh openssl 3.6.0
#   source ssl-switch.sh tongsuo
#   source ssl-switch.sh system
# =============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Detect available installations
find_openssl_versions() {
    ls -d /opt/openssl-* 2>/dev/null | while read dir; do
        version=$(basename "$dir" | sed 's/openssl-//')
        if [ -x "$dir/bin/openssl" ]; then
            echo "$version"
        fi
    done
}

find_tongsuo_versions() {
    ls -d /opt/tongsuo-* 2>/dev/null | while read dir; do
        version=$(basename "$dir" | sed 's/tongsuo-//')
        if [ -x "$dir/bin/openssl" ]; then
            echo "$version"
        fi
    done
}

# Clear SSL environment
clear_ssl_env() {
    # Remove custom SSL paths from PATH
    if [ -n "$PATH" ]; then
        export PATH=$(echo "$PATH" | tr ':' '\n' | grep -v -E "/opt/(openssl|tongsuo)" | tr '\n' ':' | sed 's/:$//')
    fi

    # Remove custom SSL paths from LD_LIBRARY_PATH
    if [ -n "$LD_LIBRARY_PATH" ]; then
        export LD_LIBRARY_PATH=$(echo "$LD_LIBRARY_PATH" | tr ':' '\n' | grep -v -E "/opt/(openssl|tongsuo)" | tr '\n' ':' | sed 's/:$//')
    fi

    # Remove custom SSL paths from PKG_CONFIG_PATH
    if [ -n "$PKG_CONFIG_PATH" ]; then
        export PKG_CONFIG_PATH=$(echo "$PKG_CONFIG_PATH" | tr ':' '\n' | grep -v -E "/opt/(openssl|tongsuo)" | tr '\n' ':' | sed 's/:$//')
    fi

    # Clear SSL-related variables
    unset OPENSSL_CONF
    unset OPENSSL_ROOT_DIR
    unset TONGSUO_ROOT_ACTIVE
    unset SSL_SWITCH_ACTIVE

    # Reset shell hash
    hash -r
}

# Activate OpenSSL
activate_openssl() {
    local version="$1"
    local openssl_root

    if [ -z "$version" ]; then
        # Find latest version
        openssl_root=$(ls -d /opt/openssl-* 2>/dev/null | sort -V | tail -1)
        if [ -z "$openssl_root" ]; then
            echo -e "${RED}Error: No OpenSSL installation found in /opt/openssl-*${NC}"
            return 1
        fi
    else
        openssl_root="/opt/openssl-$version"
        if [ ! -d "$openssl_root" ]; then
            echo -e "${RED}Error: OpenSSL $version not found${NC}"
            echo "Available versions:"
            find_openssl_versions | sed 's/^/  /'
            return 1
        fi
    fi

    # Clear existing environment
    clear_ssl_env

    # Set new environment
    export PATH="$openssl_root/bin:$PATH"
    export LD_LIBRARY_PATH="$openssl_root/lib:$LD_LIBRARY_PATH"
    export PKG_CONFIG_PATH="$openssl_root/lib/pkgconfig:$PKG_CONFIG_PATH"
    export OPENSSL_CONF="$openssl_root/ssl/openssl.cnf"
    export OPENSSL_ROOT_DIR="$openssl_root"
    export SSL_SWITCH_ACTIVE="openssl"

    hash -r

    local ver=$($openssl_root/bin/openssl version 2>/dev/null)
    echo -e "${GREEN}OpenSSL activated:${NC} $ver"
    echo -e "${BLUE}Path:${NC} $openssl_root"
}

# Activate Tongsuo
activate_tongsuo() {
    local version="$1"
    local tongsuo_root

    if [ -z "$version" ]; then
        # Find latest version
        tongsuo_root=$(ls -d /opt/tongsuo-* 2>/dev/null | sort -V | tail -1)
        if [ -z "$tongsuo_root" ]; then
            echo -e "${RED}Error: No Tongsuo installation found in /opt/tongsuo-*${NC}"
            return 1
        fi
    else
        tongsuo_root="/opt/tongsuo-$version"
        if [ ! -d "$tongsuo_root" ]; then
            echo -e "${RED}Error: Tongsuo $version not found${NC}"
            echo "Available versions:"
            find_tongsuo_versions | sed 's/^/  /'
            return 1
        fi
    fi

    # Clear existing environment
    clear_ssl_env

    # Set new environment
    export PATH="$tongsuo_root/bin:$PATH"
    export LD_LIBRARY_PATH="$tongsuo_root/lib:$LD_LIBRARY_PATH"
    export PKG_CONFIG_PATH="$tongsuo_root/lib/pkgconfig:$PKG_CONFIG_PATH"
    export OPENSSL_CONF="$tongsuo_root/ssl/openssl.cnf"
    export TONGSUO_ROOT_ACTIVE="$tongsuo_root"
    export SSL_SWITCH_ACTIVE="tongsuo"

    hash -r

    local ver=$($tongsuo_root/bin/openssl version 2>/dev/null)
    echo -e "${CYAN}Tongsuo activated:${NC} $ver"
    echo -e "${BLUE}Path:${NC} $tongsuo_root"
}

# Activate system OpenSSL
activate_system() {
    clear_ssl_env
    echo -e "${YELLOW}System OpenSSL activated${NC}"
    openssl version
}

# Show status
show_status() {
    echo -e "${BLUE}============================================${NC}"
    echo -e "${BLUE} SSL Library Status${NC}"
    echo -e "${BLUE}============================================${NC}"
    echo ""

    if [ -n "$SSL_SWITCH_ACTIVE" ]; then
        if [ "$SSL_SWITCH_ACTIVE" = "openssl" ]; then
            echo -e "Active: ${GREEN}OpenSSL (custom)${NC}"
            echo -e "Root:   $OPENSSL_ROOT_DIR"
        elif [ "$SSL_SWITCH_ACTIVE" = "tongsuo" ]; then
            echo -e "Active: ${CYAN}Tongsuo${NC}"
            echo -e "Root:   $TONGSUO_ROOT_ACTIVE"
        fi
    else
        echo -e "Active: ${YELLOW}System OpenSSL${NC}"
    fi

    echo ""
    echo "Current openssl:"
    which openssl
    openssl version

    if [ -n "$OPENSSL_CONF" ]; then
        echo ""
        echo "Config: $OPENSSL_CONF"
    fi
}

# List all installations
list_installations() {
    echo -e "${BLUE}============================================${NC}"
    echo -e "${BLUE} Available SSL Installations${NC}"
    echo -e "${BLUE}============================================${NC}"
    echo ""

    echo -e "${GREEN}OpenSSL versions:${NC}"
    local openssl_versions=$(find_openssl_versions)
    if [ -n "$openssl_versions" ]; then
        echo "$openssl_versions" | while read v; do
            local root="/opt/openssl-$v"
            local ver=$($root/bin/openssl version 2>/dev/null | head -1)
            if [ "$OPENSSL_ROOT_DIR" = "$root" ]; then
                echo -e "  ${GREEN}* $v${NC} - $ver (active)"
            else
                echo "    $v - $ver"
            fi
        done
    else
        echo "    (none installed)"
    fi

    echo ""
    echo -e "${CYAN}Tongsuo versions:${NC}"
    local tongsuo_versions=$(find_tongsuo_versions)
    if [ -n "$tongsuo_versions" ]; then
        echo "$tongsuo_versions" | while read v; do
            local root="/opt/tongsuo-$v"
            local ver=$($root/bin/openssl version 2>/dev/null | head -1)
            if [ "$TONGSUO_ROOT_ACTIVE" = "$root" ]; then
                echo -e "  ${CYAN}* $v${NC} - $ver (active)"
            else
                echo "    $v - $ver"
            fi
        done
    else
        echo "    (none installed)"
    fi

    echo ""
    echo -e "${YELLOW}System OpenSSL:${NC}"
    local sys_ssl=$(which openssl 2>/dev/null | grep -v "/opt/")
    if [ -n "$sys_ssl" ]; then
        local sys_ver=$($sys_ssl version 2>/dev/null)
        if [ -z "$SSL_SWITCH_ACTIVE" ]; then
            echo -e "  ${YELLOW}* system${NC} - $sys_ver (active)"
        else
            echo "    system - $sys_ver"
        fi
    else
        echo "    (not found)"
    fi
}

# Show help
show_help() {
    cat << 'EOF'
SSL Library Switcher
====================

Usage: source ssl-switch.sh [command] [version]

Commands:
  list              List all available installations
  openssl [version] Activate OpenSSL (latest or specific version)
  tongsuo [version] Activate Tongsuo (latest or specific version)
  system            Revert to system OpenSSL
  status            Show current active SSL library
  help              Show this help

Examples:
  source ssl-switch.sh list
  source ssl-switch.sh openssl 3.6.0
  source ssl-switch.sh openssl           # latest OpenSSL
  source ssl-switch.sh tongsuo 8.4.0
  source ssl-switch.sh tongsuo           # latest Tongsuo
  source ssl-switch.sh system

Note: This script must be sourced (not executed) to modify
      the current shell environment.

EOF
}

# Main
case "${1:-status}" in
    list|ls)
        list_installations
        ;;
    openssl|ssl)
        activate_openssl "$2"
        ;;
    tongsuo|ts|babassl)
        activate_tongsuo "$2"
        ;;
    system|sys|default)
        activate_system
        ;;
    status|info)
        show_status
        ;;
    help|-h|--help)
        show_help
        ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        echo "Use 'source ssl-switch.sh help' for usage"
        ;;
esac
