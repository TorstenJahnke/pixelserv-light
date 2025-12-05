#!/bin/bash
# Setup script for OpenSSL installation directory
# Usage: ./setup-start.sh [version]
# Example: ./setup-start.sh 3.6.0

VERSION="${1:-3.6.0}"
OPENSSL_ROOT="/opt/openssl-${VERSION}"

echo "Setting up OpenSSL $VERSION directory structure..."

# Create directories
mkdir -p "$OPENSSL_ROOT/scripts"

# Copy all scripts
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")/scripts"
if [ -d "$SCRIPT_DIR" ]; then
    for script in activate.sh activate_force.sh clean_old_install.sh install_benchmark_tools.sh \
                  install_openssl_universal.sh live_monitor.sh openssl_benchmark_epyc.sh \
                  test_legacy_compatibility.sh; do
        if [ -f "$SCRIPT_DIR/$script" ]; then
            cp "$SCRIPT_DIR/$script" "$OPENSSL_ROOT/scripts/"
            chmod +x "$OPENSSL_ROOT/scripts/$script"
        fi
    done
fi

# Symlink for easy access
ln -sf "$OPENSSL_ROOT/scripts/activate.sh" "$OPENSSL_ROOT/activate"

echo "OpenSSL $VERSION setup complete at $OPENSSL_ROOT"
echo "To activate: source $OPENSSL_ROOT/activate"
