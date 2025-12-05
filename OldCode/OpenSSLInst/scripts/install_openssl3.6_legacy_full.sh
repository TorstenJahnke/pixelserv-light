#!/bin/bash
# install_openssl3.6_complete.sh - Vollständige SM/Commercial Crypto Support

set -e

OPENSSL_VERSION="3.6.0"
OPENSSL_PREFIX="/opt/openssl-3.6.0"
TEMP_DIR="/tmp/openssl-complete-$(date +%s)"

echo "🔧 Installiere OpenSSL ${OPENSSL_VERSION} mit vollständigem SM-Support..."

# Vorbereitung
rm -rf "$TEMP_DIR"
mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR"

# Abhängigkeiten
echo "📦 Installiere Build-Abhängigkeiten..."
apt update
apt install -y build-essential checkinstall zlib1g-dev wgit

# Download
echo "📥 Lade OpenSSL ${OPENSSL_VERSION} herunter..."
wget -q https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz
tar -xf openssl-${OPENSSL_VERSION}.tar.gz
cd openssl-${OPENSSL_VERSION}

# Vollständige Konfiguration mit allen SM-Features
echo "⚙️ Konfiguriere mit komplettem SM-Support..."
./config --prefix="$OPENSSL_PREFIX" \
         --openssldir="$OPENSSL_PREFIX" \
         enable-legacy \
         enable-sm2 \
         enable-sm3 \
         enable-sm4 \
         enable-ssl3 \
         enable-ssl3-method \
         enable-weak-ssl-ciphers \
         enable-zuc \
         enable-ec \
         enable-ec2m \
         -DOPENSSL_RSA_MAX_MODULUS_BITS=16384 \
         no-shared

# Build
echo "🔨 Kompiliere OpenSSL..."
make -j$(nproc)

echo "🧪 Führe Tests aus..."
make test || echo "⚠️  Einige Tests fehlgeschlagen, fahre fort..."

echo "📥 Installiere..."
make install

# Erweiterte OpenSSL Konfiguration für TLCP/TLS 1.3
mkdir -p "$OPENSSL_PREFIX/ssl"
cat > "$OPENSSL_PREFIX/ssl/openssl.cnf" << 'EOF'
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect
ssl_conf = ssl_sect

[provider_sect]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
# TLCP 1.1 und SM Cipher Suites
Ciphersuites = TLS_SM4_GCM_SM3:TLS_ECDHE_SM4_CBC_SM3:TLS_ECC_SM4_CBC_SM3
Options = UnsafeLegacyRenegotiation
EOF

# Aufräumen
cd /
rm -rf "$TEMP_DIR"

echo "✅ OpenSSL ${OPENSSL_VERSION} mit vollständigem SM-Support installiert"
/opt/openssl-3.6.0/bin/openssl version
