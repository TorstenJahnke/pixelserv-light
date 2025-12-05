#!/bin/bash
# =============================================================================
# Tongsuo Activation Script
# Aktiviert Tongsuo für die aktuelle Shell-Session
# =============================================================================

# Auto-detect installed version
TONGSUO_VERSIONS=$(ls -d /opt/tongsuo-* 2>/dev/null | sort -V)

if [ -z "$TONGSUO_VERSIONS" ]; then
    echo "Fehler: Keine Tongsuo-Installation gefunden in /opt/tongsuo-*"
    echo "Bitte zuerst installieren: ./install_tongsuo.sh"
    return 1 2>/dev/null || exit 1
fi

# Use specified version or latest
if [ -n "$1" ]; then
    TONGSUO_ROOT="/opt/tongsuo-$1"
    if [ ! -d "$TONGSUO_ROOT" ]; then
        echo "Fehler: Tongsuo $1 nicht gefunden"
        echo "Verfügbare Versionen:"
        for v in $TONGSUO_VERSIONS; do
            echo "  - $(basename "$v" | sed 's/tongsuo-//')"
        done
        return 1 2>/dev/null || exit 1
    fi
else
    # Use latest version
    TONGSUO_ROOT=$(echo "$TONGSUO_VERSIONS" | tail -1)
fi

# Deactivate any existing SSL environment
if [ -n "$OPENSSL_ROOT_DIR" ] || [ -n "$TONGSUO_ROOT_ACTIVE" ]; then
    # Remove old paths
    export PATH=$(echo "$PATH" | tr ':' '\n' | grep -v -E "(openssl|tongsuo)" | tr '\n' ':' | sed 's/:$//')
    export LD_LIBRARY_PATH=$(echo "$LD_LIBRARY_PATH" | tr ':' '\n' | grep -v -E "(openssl|tongsuo)" | tr '\n' ':' | sed 's/:$//')
    unset OPENSSL_ROOT_DIR
    unset TONGSUO_ROOT_ACTIVE
fi

# Activate Tongsuo
export PATH="$TONGSUO_ROOT/bin:$PATH"
export LD_LIBRARY_PATH="$TONGSUO_ROOT/lib:$LD_LIBRARY_PATH"
export PKG_CONFIG_PATH="$TONGSUO_ROOT/lib/pkgconfig:$PKG_CONFIG_PATH"
export OPENSSL_CONF="$TONGSUO_ROOT/ssl/openssl.cnf"
export TONGSUO_ROOT_ACTIVE="$TONGSUO_ROOT"

# Reset shell hash
hash -r

VERSION=$($TONGSUO_ROOT/bin/openssl version 2>/dev/null)
echo "Tongsuo aktiviert: $VERSION"
echo "Pfad: $TONGSUO_ROOT"
