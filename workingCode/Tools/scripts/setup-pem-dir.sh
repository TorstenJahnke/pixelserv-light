#!/bin/bash
#
# setup-pem-dir.sh - Create pixelserv-tls PEM directory structure
#
# Usage: ./setup-pem-dir.sh [PEM_DIR]
#        Default PEM_DIR: /opt/aviontex
#

set -e

PEM_DIR="${1:-/opt/aviontex}"

echo "Creating PEM directory structure in: $PEM_DIR"

# Create base directory
mkdir -p "$PEM_DIR"

# RSA structure
mkdir -p "$PEM_DIR/RSA/certs"
mkdir -p "$PEM_DIR/RSA/index"
mkdir -p "$PEM_DIR/RSA/rootCA"
touch "$PEM_DIR/RSA/rootCA/rootca.crt"
touch "$PEM_DIR/RSA/rootCA/subca.ca.crt"
touch "$PEM_DIR/RSA/rootCA/subca.crt"
touch "$PEM_DIR/RSA/rootCA/subca.key"

# ECDSA structure
mkdir -p "$PEM_DIR/ECDSA/certs"
mkdir -p "$PEM_DIR/ECDSA/index"
mkdir -p "$PEM_DIR/ECDSA/rootCA"
touch "$PEM_DIR/ECDSA/rootCA/rootca.crt"
touch "$PEM_DIR/ECDSA/rootCA/subca.ca.crt"
touch "$PEM_DIR/ECDSA/rootCA/subca.crt"
touch "$PEM_DIR/ECDSA/rootCA/subca.key"

# SM2 structure (Chinese crypto)
mkdir -p "$PEM_DIR/SM2/certs"
mkdir -p "$PEM_DIR/SM2/index"
mkdir -p "$PEM_DIR/SM2/rootCA"
touch "$PEM_DIR/SM2/rootCA/rootca.crt"
touch "$PEM_DIR/SM2/rootCA/subca.ca.crt"
touch "$PEM_DIR/SM2/rootCA/subca.crt"
touch "$PEM_DIR/SM2/rootCA/subca.key"

# LEGACY structure (for old clients)
mkdir -p "$PEM_DIR/LEGACY/certs"
mkdir -p "$PEM_DIR/LEGACY/index"
mkdir -p "$PEM_DIR/LEGACY/rootCA"
touch "$PEM_DIR/LEGACY/rootCA/rootca.crt"
touch "$PEM_DIR/LEGACY/rootCA/rootca.key"

# Primes directory (for fast RSA key generation)
mkdir -p "$PEM_DIR/primes"
touch "$PEM_DIR/primes/prime-3072-p.bin"
touch "$PEM_DIR/primes/prime-3072-q.bin"

# Config directory
mkdir -p "$PEM_DIR/config"
touch "$PEM_DIR/config/second-level-tlds.conf"

# Set permissions
chmod 755 "$PEM_DIR"
chmod -R 755 "$PEM_DIR"/*
chmod 600 "$PEM_DIR"/*/rootCA/*.key 2>/dev/null || true

echo ""
echo "Directory structure created:"
echo ""
find "$PEM_DIR" -type d | sort | sed 's|^|  |'
echo ""
echo "Files created:"
find "$PEM_DIR" -type f | sort | sed 's|^|  |'
echo ""
echo "Done!"
