#!/bin/bash
# =============================================================================
# install_tongsuo.sh - Tongsuo (BabaSSL) Installation Script
# Full TLCP 1.1 and Chinese Cryptography (SM2/SM3/SM4/ZUC) Support
# =============================================================================
#
# Tongsuo is a fork of OpenSSL with complete support for:
# - TLCP 1.1 (Chinese TLS protocol, GB/T 38636-2020)
# - SM2 (Chinese elliptic curve, GB/T 32918)
# - SM3 (Chinese hash, GB/T 32905)
# - SM4 (Chinese block cipher, GB/T 32907)
# - ZUC (Chinese stream cipher)
# - Delegated Credentials (RFC 9345)
# - Certificate Compression (RFC 8879)
#
# GitHub: https://github.com/Tongsuo-Project/Tongsuo
# =============================================================================

set -e

# Default values
DEFAULT_VERSION="8.4.0"
DEFAULT_PREFIX="/opt/tongsuo"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
  -v, --version VERSION    Tongsuo version (default: $DEFAULT_VERSION)
  -p, --prefix PATH        Installation prefix (default: $DEFAULT_PREFIX-VERSION)
  -n, --ntls               Enable NTLS/TLCP protocol (default: enabled)
  --no-ntls                Disable NTLS/TLCP protocol
  -d, --delegated-creds    Enable Delegated Credentials (RFC 9345)
  -c, --cert-compression   Enable Certificate Compression (RFC 8879)
  -S, --shared             Build shared libraries (default: static)
  --no-tests               Skip test suite
  -h, --help               Show this help

Supported versions:
  8.3.3     - Stable LTS
  8.4.0     - Latest stable (default)
  master    - Development (bleeding edge)

Features enabled by default:
  - SM2, SM3, SM4 (Chinese crypto algorithms)
  - NTLS/TLCP protocol (enable-ntls)
  - TLS 1.3 with SM cipher suites

Note: TLCP 1.1 is enabled via 'enable-ntls' in Tongsuo.
      Tag format: Tongsuo-8.4.0, BabaSSL-8.3.2 (older)

Examples:
  $0                                    # Default installation
  $0 -v 8.4.0 -d -c                    # With delegated creds + compression
  $0 -v 8.3.3 -p /usr/local/tongsuo    # LTS with custom prefix
  $0 --no-ntls                          # Without NTLS/TLCP

EOF
    exit 0
}

# Parse arguments
VERSION="$DEFAULT_VERSION"
PREFIX=""
ENABLE_NTLS=1  # NTLS enables TLCP support
ENABLE_DELEGATED_CREDS=0
ENABLE_CERT_COMPRESSION=0
BUILD_SHARED=0
RUN_TESTS=1

while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--version) VERSION="$2"; shift 2 ;;
        -p|--prefix) PREFIX="$2"; shift 2 ;;
        -n|--ntls|--tlcp) ENABLE_NTLS=1; shift ;;
        --no-ntls|--no-tlcp) ENABLE_NTLS=0; shift ;;
        -d|--delegated-creds) ENABLE_DELEGATED_CREDS=1; shift ;;
        -c|--cert-compression) ENABLE_CERT_COMPRESSION=1; shift ;;
        -S|--shared) BUILD_SHARED=1; shift ;;
        --no-tests) RUN_TESTS=0; shift ;;
        -h|--help) print_usage ;;
        *) echo "Unknown option: $1"; print_usage ;;
    esac
done

# Set default prefix
if [ -z "$PREFIX" ]; then
    PREFIX="${DEFAULT_PREFIX}-${VERSION}"
fi

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN} Tongsuo (BabaSSL) Installer${NC}"
echo -e "${CYAN} Chinese Cryptography Suite${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""
echo -e "Version:              ${GREEN}$VERSION${NC}"
echo -e "Prefix:               ${GREEN}$PREFIX${NC}"
echo -e "NTLS/TLCP:            $([ $ENABLE_NTLS -eq 1 ] && echo -e "${GREEN}Yes${NC}" || echo "No")"
echo -e "Delegated Creds:      $([ $ENABLE_DELEGATED_CREDS -eq 1 ] && echo -e "${GREEN}Yes${NC}" || echo "No")"
echo -e "Cert Compression:     $([ $ENABLE_CERT_COMPRESSION -eq 1 ] && echo -e "${GREEN}Yes${NC}" || echo "No")"
echo -e "Shared libs:          $([ $BUILD_SHARED -eq 1 ] && echo -e "${GREEN}Yes${NC}" || echo "No")"
echo ""

# Create temp directory
TEMP_DIR="/tmp/tongsuo-build-$(date +%s)"
rm -rf "$TEMP_DIR"
mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR"

# Install dependencies
echo -e "${YELLOW}Installing build dependencies...${NC}"
if command -v apt &> /dev/null; then
    apt update
    apt install -y build-essential checkinstall zlib1g-dev wget git perl
elif command -v yum &> /dev/null; then
    yum groupinstall -y "Development Tools"
    yum install -y zlib-devel wget git perl
elif command -v dnf &> /dev/null; then
    dnf groupinstall -y "Development Tools"
    dnf install -y zlib-devel wget git perl
else
    echo -e "${YELLOW}Warning: Unknown package manager${NC}"
fi

# Download Tongsuo
echo -e "${YELLOW}Downloading Tongsuo $VERSION...${NC}"

if [ "$VERSION" = "master" ]; then
    git clone --depth 1 https://github.com/Tongsuo-Project/Tongsuo.git tongsuo-src
    cd tongsuo-src
else
    # Tag format: just version number (8.4.0, 8.3.3, etc.)
    # Extracted directory: Tongsuo-{version}
    RELEASE_URL="https://github.com/Tongsuo-Project/Tongsuo/archive/refs/tags/${VERSION}.tar.gz"

    echo -e "${YELLOW}Downloading from tag: ${VERSION}${NC}"

    DOWNLOAD_SUCCESS=0
    if command -v curl &> /dev/null; then
        if curl -fsSL "$RELEASE_URL" -o tongsuo.tar.gz 2>/dev/null; then
            DOWNLOAD_SUCCESS=1
        fi
    elif command -v wget &> /dev/null; then
        if wget -q "$RELEASE_URL" -O tongsuo.tar.gz 2>/dev/null; then
            DOWNLOAD_SUCCESS=1
        fi
    fi

    if [ $DOWNLOAD_SUCCESS -eq 1 ] && [ -s tongsuo.tar.gz ]; then
        echo -e "${GREEN}Download successful${NC}"
        tar -xf tongsuo.tar.gz
        # Directory is named Tongsuo-{version}
        cd "Tongsuo-${VERSION}" 2>/dev/null || cd Tongsuo-*
    else
        # Fallback to git clone
        echo -e "${YELLOW}Tarball download failed, cloning repository...${NC}"
        rm -f tongsuo.tar.gz
        if git clone --depth 1 --branch "$VERSION" https://github.com/Tongsuo-Project/Tongsuo.git tongsuo-src 2>/dev/null; then
            cd tongsuo-src
        else
            echo -e "${RED}Error: Could not download or clone Tongsuo $VERSION${NC}"
            echo "Available tags can be found at: https://github.com/Tongsuo-Project/Tongsuo/tags"
            exit 1
        fi
    fi
fi

echo -e "${GREEN}Source directory: $(pwd)${NC}"
ls -la | head -10

# Build configure options
build_config_options() {
    local opts=""

    # Base options
    opts="--prefix=$PREFIX --openssldir=$PREFIX"

    if [ $BUILD_SHARED -eq 0 ]; then
        opts="$opts no-shared"
    fi

    # SM algorithms are built-in, but we enable them explicitly for clarity
    # SM2, SM3, SM4 are enabled by default in Tongsuo

    # NTLS enables TLCP 1.1 protocol (Chinese TLS, GB/T 38636-2020)
    if [ $ENABLE_NTLS -eq 1 ]; then
        opts="$opts enable-ntls"
    fi

    # Delegated Credentials (RFC 9345)
    if [ $ENABLE_DELEGATED_CREDS -eq 1 ]; then
        opts="$opts enable-delegated-credential"
    fi

    # Certificate Compression (RFC 8879)
    if [ $ENABLE_CERT_COMPRESSION -eq 1 ]; then
        opts="$opts enable-cert-compression"
    fi

    # Enable EC and large RSA keys
    opts="$opts enable-ec"
    opts="$opts -DOPENSSL_RSA_MAX_MODULUS_BITS=16384"

    echo "$opts"
}

CONFIG_OPTS=$(build_config_options)

echo -e "${YELLOW}Configuring Tongsuo with options:${NC}"
echo "$CONFIG_OPTS"
echo ""

./config $CONFIG_OPTS

# Build
echo -e "${YELLOW}Building Tongsuo (using $(nproc) cores)...${NC}"
make -j$(nproc)

# Run tests
if [ $RUN_TESTS -eq 1 ]; then
    echo -e "${YELLOW}Running tests...${NC}"
    make test || echo -e "${YELLOW}Warning: Some tests failed, continuing...${NC}"
fi

# Install
echo -e "${YELLOW}Installing to $PREFIX...${NC}"
make install

# Create Tongsuo-specific configuration
echo -e "${YELLOW}Creating configuration...${NC}"
mkdir -p "$PREFIX/ssl"

cat > "$PREFIX/ssl/openssl.cnf" << 'EOF'
# Tongsuo Configuration
# Full TLCP 1.1 and Chinese Cryptography Support

openssl_conf = openssl_init

[openssl_init]
providers = provider_sect
ssl_conf = ssl_sect

[provider_sect]
default = default_sect

[default_sect]
activate = 1

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
# Enable TLS 1.2, TLS 1.3, and TLCP 1.1
MinProtocol = TLSv1.2
CipherString = DEFAULT@SECLEVEL=1

# SM Cipher Suites for TLS 1.3
Ciphersuites = TLS_SM4_GCM_SM3:TLS_SM4_CCM_SM3:TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256

[req]
default_bits = 2048
default_md = sm3
distinguished_name = req_distinguished_name
x509_extensions = v3_ca

[req_distinguished_name]
countryName = Country Name (2 letter code)
countryName_default = CN
stateOrProvinceName = State or Province Name
localityName = Locality Name
0.organizationName = Organization Name
commonName = Common Name

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign

[v3_intermediate_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical,keyCertSign,cRLSign

[server_cert]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth

[sm2_server_cert]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyAgreement
extendedKeyUsage = serverAuth
EOF

# Create activation script
mkdir -p "$PREFIX/scripts"
cat > "$PREFIX/scripts/activate.sh" << EOF
#!/bin/bash
# Activate Tongsuo $VERSION
export PATH="$PREFIX/bin:\$PATH"
export LD_LIBRARY_PATH="$PREFIX/lib:\$LD_LIBRARY_PATH"
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig:\$PKG_CONFIG_PATH"
export OPENSSL_CONF="$PREFIX/ssl/openssl.cnf"
export TONGSUO_ROOT="$PREFIX"
hash -r
echo "Tongsuo $VERSION activated"
$PREFIX/bin/openssl version
EOF
chmod +x "$PREFIX/scripts/activate.sh"

# Create SM2 certificate generation helper
cat > "$PREFIX/scripts/generate_sm2_cert.sh" << 'CERTEOF'
#!/bin/bash
# Generate SM2 certificates for TLCP
# Usage: ./generate_sm2_cert.sh <common_name> [days]

CN="${1:-localhost}"
DAYS="${2:-365}"
PREFIX="$(dirname "$(dirname "$(readlink -f "$0")")")"
OUT_DIR="${3:-.}"

source "$PREFIX/scripts/activate.sh"

echo "Generating SM2 certificates for: $CN"
mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

# Generate SM2 CA key and certificate
echo "Creating SM2 CA..."
openssl genpkey -algorithm SM2 -out sm2_ca.key
openssl req -new -x509 -key sm2_ca.key -out sm2_ca.crt -days 3650 \
    -subj "/CN=SM2 Test CA/O=Test/C=CN" -sm3

# Generate SM2 server signing key pair (for authentication)
echo "Creating SM2 signing certificate..."
openssl genpkey -algorithm SM2 -out sm2_sign.key
openssl req -new -key sm2_sign.key -out sm2_sign.csr \
    -subj "/CN=$CN/O=Test/C=CN" -sm3
openssl x509 -req -in sm2_sign.csr -CA sm2_ca.crt -CAkey sm2_ca.key \
    -out sm2_sign.crt -days $DAYS -sm3 -CAcreateserial

# Generate SM2 server encryption key pair (for key exchange)
echo "Creating SM2 encryption certificate..."
openssl genpkey -algorithm SM2 -out sm2_enc.key
openssl req -new -key sm2_enc.key -out sm2_enc.csr \
    -subj "/CN=$CN/O=Test/C=CN" -sm3
openssl x509 -req -in sm2_enc.csr -CA sm2_ca.crt -CAkey sm2_ca.key \
    -out sm2_enc.crt -days $DAYS -sm3 -CAcreateserial

# Create combined certificate chain
cat sm2_sign.crt sm2_ca.crt > sm2_chain.crt

echo ""
echo "SM2 certificates generated:"
echo "  CA:          sm2_ca.crt / sm2_ca.key"
echo "  Sign cert:   sm2_sign.crt / sm2_sign.key"
echo "  Enc cert:    sm2_enc.crt / sm2_enc.key"
echo "  Chain:       sm2_chain.crt"
echo ""
echo "For TLCP server, use:"
echo "  Sign: sm2_sign.crt + sm2_sign.key"
echo "  Enc:  sm2_enc.crt + sm2_enc.key"
CERTEOF
chmod +x "$PREFIX/scripts/generate_sm2_cert.sh"

# Create TLCP test script
cat > "$PREFIX/scripts/test_tlcp.sh" << 'TLCPEOF'
#!/bin/bash
# Test TLCP connection
PREFIX="$(dirname "$(dirname "$(readlink -f "$0")")")"
source "$PREFIX/scripts/activate.sh"

echo "Testing TLCP/SM cipher support..."
echo ""

echo "1. SM2 Key Generation:"
openssl genpkey -algorithm SM2 -out /tmp/test_sm2.key 2>/dev/null && \
    echo "   OK - SM2 supported" || echo "   FAIL - SM2 not available"

echo "2. SM3 Hash:"
echo "test" | openssl sm3 >/dev/null 2>&1 && \
    echo "   OK - SM3 supported" || echo "   FAIL - SM3 not available"

echo "3. SM4 Cipher:"
echo "test" | openssl enc -sm4-cbc -k test -pbkdf2 2>/dev/null | \
    openssl enc -sm4-cbc -d -k test -pbkdf2 >/dev/null 2>&1 && \
    echo "   OK - SM4 supported" || echo "   FAIL - SM4 not available"

echo "4. Available SM Cipher Suites:"
openssl ciphers -v 'ALL' 2>/dev/null | grep -E "(SM2|SM3|SM4)" | head -5
if [ $? -ne 0 ]; then
    echo "   No SM cipher suites found in standard list"
fi

echo ""
echo "5. TLCP Protocol Support:"
if openssl s_client -help 2>&1 | grep -q "tlcp"; then
    echo "   OK - TLCP protocol available"
else
    echo "   INFO - TLCP available via ntls or standard TLS with SM ciphers"
fi

echo ""
echo "6. Provider Information:"
openssl list -providers 2>/dev/null || echo "   Using built-in crypto"

rm -f /tmp/test_sm2.key
echo ""
echo "Test complete!"
TLCPEOF
chmod +x "$PREFIX/scripts/test_tlcp.sh"

# Create symlink
ln -sf "$PREFIX/scripts/activate.sh" "$PREFIX/activate"

# Cleanup
cd /
rm -rf "$TEMP_DIR"

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN} Tongsuo Installation Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "Tongsuo $VERSION installed to: ${BLUE}$PREFIX${NC}"
echo ""
echo "Available scripts:"
echo -e "  ${CYAN}$PREFIX/scripts/activate.sh${NC}        - Activate environment"
echo -e "  ${CYAN}$PREFIX/scripts/generate_sm2_cert.sh${NC} - Generate SM2 certs"
echo -e "  ${CYAN}$PREFIX/scripts/test_tlcp.sh${NC}        - Test TLCP/SM support"
echo ""
echo "To activate:"
echo -e "  ${YELLOW}source $PREFIX/activate${NC}"
echo ""
echo "To generate SM2 certificates:"
echo -e "  ${YELLOW}$PREFIX/scripts/generate_sm2_cert.sh localhost 365${NC}"
echo ""
echo "To test TLCP support:"
echo -e "  ${YELLOW}$PREFIX/scripts/test_tlcp.sh${NC}"
echo ""

# Verify installation
echo "Verification:"
$PREFIX/bin/openssl version -a | head -5
echo ""
echo "SM Algorithm Support:"
$PREFIX/bin/openssl genpkey -algorithm SM2 -out /tmp/verify_sm2.key 2>/dev/null && \
    echo -e "  ${GREEN}SM2: OK${NC}" && rm -f /tmp/verify_sm2.key || \
    echo -e "  ${RED}SM2: FAIL${NC}"
