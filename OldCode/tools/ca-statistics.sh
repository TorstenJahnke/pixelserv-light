#!/bin/bash
# TLSGateNX - CA Statistics Generator
# Copyright (C) 2025 Torsten Jahnke
#
# Generates statistics about CA certificates and keys
# Output: backup/ca_statistics.txt

set -e

# Default paths
BASE_DIR="${1:-.}"
CA_DIR="${BASE_DIR}/rootCA"
BACKUP_DIR="${BASE_DIR}/backup"
OUTPUT_FILE="${BACKUP_DIR}/ca_statistics.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if CA directory exists
if [ ! -d "$CA_DIR" ]; then
    echo -e "${RED}Error: CA directory not found: $CA_DIR${NC}"
    echo "Expected structure: $BASE_DIR/rootCA/"
    exit 1
fi

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

echo -e "${GREEN}Generating CA statistics...${NC}"
echo "CA Directory: $CA_DIR"
echo "Output: $OUTPUT_FILE"
echo ""

# Start writing statistics
{
    echo "=========================================="
    echo "TLSGateNX - CA Statistik"
    echo "=========================================="
    echo "Last Backup from: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""

    # Find CA certificates
    echo "=========================================="
    echo "CA Zertifikate"
    echo "=========================================="
    echo ""

    # Detect CA type
    CA_TYPE="Unknown"
    CERT_COUNT=0

    # Look for RootCA certificate
    ROOT_CA=""
    for name in RootCA rootca.crt rootca.pem rootCA.crt rootCA.pem; do
        if [ -f "$CA_DIR/$name" ]; then
            ROOT_CA="$CA_DIR/$name"
            break
        fi
    done

    # Look for SubCA/CA certificate
    SUB_CA=""
    for name in SubCA ca.crt ca.pem subca.crt subca.pem; do
        if [ -f "$CA_DIR/$name" ]; then
            SUB_CA="$CA_DIR/$name"
            break
        fi
    done

    # Determine CA type
    if [ -n "$ROOT_CA" ] && [ -n "$SUB_CA" ]; then
        CA_TYPE="Two-Tier (RootCA + SubCA)"
        CERT_COUNT=2
    elif [ -n "$SUB_CA" ]; then
        CA_TYPE="Single-Tier"
        CERT_COUNT=1
    fi

    echo "CA Typ: $CA_TYPE"
    echo "Anzahl Zertifikate: $CERT_COUNT"
    echo ""

    # Display RootCA information
    if [ -n "$ROOT_CA" ]; then
        echo "--- RootCA ---"
        echo "Datei: $(basename "$ROOT_CA")"
        echo "Pfad: $ROOT_CA"

        # Extract certificate information using openssl
        if command -v openssl &> /dev/null; then
            echo ""
            echo "Subject:"
            openssl x509 -in "$ROOT_CA" -noout -subject 2>/dev/null | sed 's/subject=/  /'

            echo "Issuer:"
            openssl x509 -in "$ROOT_CA" -noout -issuer 2>/dev/null | sed 's/issuer=/  /'

            echo "Validity:"
            openssl x509 -in "$ROOT_CA" -noout -dates 2>/dev/null | sed 's/^/  /'

            echo "Serial:"
            openssl x509 -in "$ROOT_CA" -noout -serial 2>/dev/null | sed 's/serial=/  /'
        fi
        echo ""
    fi

    # Display SubCA/CA information
    if [ -n "$SUB_CA" ]; then
        if [ -n "$ROOT_CA" ]; then
            echo "--- SubCA ---"
        else
            echo "--- CA ---"
        fi
        echo "Datei: $(basename "$SUB_CA")"
        echo "Pfad: $SUB_CA"

        # Extract certificate information using openssl
        if command -v openssl &> /dev/null; then
            echo ""
            echo "Subject:"
            openssl x509 -in "$SUB_CA" -noout -subject 2>/dev/null | sed 's/subject=/  /'

            echo "Issuer:"
            openssl x509 -in "$SUB_CA" -noout -issuer 2>/dev/null | sed 's/issuer=/  /'

            echo "Validity:"
            openssl x509 -in "$SUB_CA" -noout -dates 2>/dev/null | sed 's/^/  /'

            echo "Serial:"
            openssl x509 -in "$SUB_CA" -noout -serial 2>/dev/null | sed 's/serial=/  /'
        fi
        echo ""
    fi

    # Find and list private keys
    echo "=========================================="
    echo "Private Keys"
    echo "=========================================="
    echo ""

    # Look for key files
    KEY_FILES=()
    for name in ca.key ca-key.pem SubCA.key subca.key; do
        if [ -f "$CA_DIR/$name" ]; then
            KEY_FILES+=("$CA_DIR/$name")
        fi
    done

    echo "Anzahl Keys: ${#KEY_FILES[@]}"
    echo ""

    if [ ${#KEY_FILES[@]} -gt 0 ]; then
        echo "Gefundene Keys:"
        for key in "${KEY_FILES[@]}"; do
            echo "  - $(basename "$key")"
            echo "    Pfad: $key"

            # Check if key is encrypted
            if command -v openssl &> /dev/null; then
                if grep -q "ENCRYPTED" "$key" 2>/dev/null; then
                    echo "    Status: Verschlüsselt (Passphrase erforderlich)"
                else
                    echo "    Status: Unverschlüsselt"
                fi

                # Try to get key type (may fail if encrypted without passphrase)
                KEY_TYPE=$(openssl pkey -in "$key" -noout -text 2>/dev/null | head -1 || echo "Unknown")
                if [ "$KEY_TYPE" != "Unknown" ]; then
                    echo "    Typ: $KEY_TYPE"
                fi
            fi
            echo ""
        done
    else
        echo "Keine Keys gefunden!"
        echo ""
    fi

    # Additional files
    echo "=========================================="
    echo "Zusätzliche Dateien"
    echo "=========================================="
    echo ""

    # Check for passphrase file
    if [ -f "$CA_DIR/ca.key.passphrase" ]; then
        echo "  - ca.key.passphrase (Passphrase-Datei vorhanden)"
    fi

    # List other files in CA directory
    OTHER_FILES=$(find "$CA_DIR" -maxdepth 1 -type f ! -name "*.crt" ! -name "*.pem" ! -name "*.key" ! -name "ca.key.passphrase" 2>/dev/null || true)
    if [ -n "$OTHER_FILES" ]; then
        echo "$OTHER_FILES" | while read -r file; do
            echo "  - $(basename "$file")"
        done
    fi

    echo ""
    echo "=========================================="
    echo "Ende der Statistik"
    echo "=========================================="

} > "$OUTPUT_FILE"

echo -e "${GREEN}✓ Statistik erfolgreich erstellt: $OUTPUT_FILE${NC}"
echo ""
echo "Inhalt:"
cat "$OUTPUT_FILE"
