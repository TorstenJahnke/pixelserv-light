#!/bin/bash
# activate_force.sh - Force-activate custom OpenSSL installation
# Auto-detects installed version or uses specified path

# Find OpenSSL installation
if [ -n "$1" ]; then
    OPENSSL_ROOT="$1"
elif [ -d "/opt/openssl-3.6.0" ]; then
    OPENSSL_ROOT="/opt/openssl-3.6.0"
else
    OPENSSL_ROOT=$(ls -d /opt/openssl-* 2>/dev/null | sort -V | tail -1)
fi

if [ -z "$OPENSSL_ROOT" ] || [ ! -d "$OPENSSL_ROOT" ]; then
    echo "Error: No OpenSSL installation found in /opt/openssl-*"
    return 1 2>/dev/null || exit 1
fi

# Remove all other OpenSSL paths temporarily
export PATH="$OPENSSL_ROOT/bin:$(echo "$PATH" | tr ':' '\n' | grep -v -E "(/usr/bin|/usr/local/bin|/opt/openssl)" | tr '\n' ':' | sed 's/:$//')"

# Set configuration
export OPENSSL_CONF="$OPENSSL_ROOT/ssl/openssl.cnf"
export OPENSSL_ROOT_DIR="$OPENSSL_ROOT"
export LD_LIBRARY_PATH="$OPENSSL_ROOT/lib:$LD_LIBRARY_PATH"

# Reset shell hash
hash -r

echo "OpenSSL FORCE-activated"
echo "Path: $OPENSSL_ROOT"
$OPENSSL_ROOT/bin/openssl version
