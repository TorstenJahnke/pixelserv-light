#!/bin/bash
# =============================================================================
# install_openssl_universal.sh - Universal OpenSSL Installation Script
# Supports: OpenSSL 1.1.1, 3.0.x, 3.1.x, 3.2.x, 3.3.x, 3.4.x, 3.5.x, 3.6.x
# =============================================================================

set -e

# Default values
DEFAULT_VERSION="3.6.0"
DEFAULT_PREFIX="/opt/openssl"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
  -v, --version VERSION    OpenSSL version to install (default: $DEFAULT_VERSION)
  -p, --prefix PATH        Installation prefix (default: $DEFAULT_PREFIX-VERSION)
  -l, --legacy             Enable legacy algorithms (default: enabled)
  --no-legacy              Disable legacy algorithms
  -s, --sm                 Enable SM2/SM3/SM4 (default: enabled)
  --no-sm                  Disable SM2/SM3/SM4
  -f, --fips               Enable FIPS module (3.x only)
  -S, --shared             Build shared libraries (default: static)
  --no-tests               Skip test suite
  -h, --help               Show this help

Enabled by default:
  - Legacy algorithms (SSL3, weak ciphers)
  - SM2/SM3/SM4 (Chinese crypto)

Supported versions:
  1.1.1w    - Legacy (EOL, for compatibility only)
  3.0.15    - LTS until 2026
  3.1.7     - Regular release
  3.2.3     - Regular release
  3.3.2     - Regular release
  3.4.0     - Current
  3.5.0     - Current
  3.6.0     - Latest (default)

Examples:
  $0 -v 3.6.0                    # OpenSSL 3.6 with legacy + SM (default)
  $0 -v 3.6.0 --no-legacy        # Without legacy algorithms
  $0 -v 1.1.1w                   # OpenSSL 1.1.1w for legacy systems
  $0 -v 3.0.15 -f                # OpenSSL 3.0 LTS with FIPS
  $0 -v 3.6.0 -p /usr/local/ssl  # Custom prefix

EOF
    exit 0
}

# Parse arguments
VERSION="$DEFAULT_VERSION"
PREFIX=""
ENABLE_LEGACY=1
ENABLE_SM=1
ENABLE_FIPS=0
BUILD_SHARED=0
RUN_TESTS=1

while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--version) VERSION="$2"; shift 2 ;;
        -p|--prefix) PREFIX="$2"; shift 2 ;;
        -l|--legacy) ENABLE_LEGACY=1; shift ;;
        --no-legacy) ENABLE_LEGACY=0; shift ;;
        -s|--sm) ENABLE_SM=1; shift ;;
        --no-sm) ENABLE_SM=0; shift ;;
        -f|--fips) ENABLE_FIPS=1; shift ;;
        -S|--shared) BUILD_SHARED=1; shift ;;
        --no-tests) RUN_TESTS=0; shift ;;
        -h|--help) print_usage ;;
        *) echo "Unknown option: $1"; print_usage ;;
    esac
done

# Set default prefix if not specified
if [ -z "$PREFIX" ]; then
    PREFIX="${DEFAULT_PREFIX}-${VERSION}"
fi

# Determine major version
MAJOR_VERSION=$(echo "$VERSION" | cut -d. -f1)
MINOR_VERSION=$(echo "$VERSION" | cut -d. -f2)

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE} OpenSSL Universal Installer${NC}"
echo -e "${BLUE}============================================${NC}"
echo -e "Version:      ${GREEN}$VERSION${NC}"
echo -e "Prefix:       ${GREEN}$PREFIX${NC}"
echo -e "Legacy:       $([ $ENABLE_LEGACY -eq 1 ] && echo -e "${GREEN}Yes${NC}" || echo "No")"
echo -e "SM2/SM3/SM4:  $([ $ENABLE_SM -eq 1 ] && echo -e "${GREEN}Yes${NC}" || echo "No")"
echo -e "FIPS:         $([ $ENABLE_FIPS -eq 1 ] && echo -e "${GREEN}Yes${NC}" || echo "No")"
echo -e "Shared libs:  $([ $BUILD_SHARED -eq 1 ] && echo -e "${GREEN}Yes${NC}" || echo "No")"
echo ""

# Validate version
validate_version() {
    case "$VERSION" in
        1.1.1*)
            if [ $ENABLE_FIPS -eq 1 ]; then
                echo -e "${RED}Error: FIPS is not supported in OpenSSL 1.1.1${NC}"
                exit 1
            fi
            ;;
        3.*)
            # All 3.x versions support FIPS
            ;;
        *)
            echo -e "${RED}Error: Unsupported version $VERSION${NC}"
            echo "Supported: 1.1.1x, 3.0.x - 3.6.x"
            exit 1
            ;;
    esac
}

validate_version

# Create temp directory
TEMP_DIR="/tmp/openssl-build-$(date +%s)"
rm -rf "$TEMP_DIR"
mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR"

# Install dependencies
echo -e "${YELLOW}Installing build dependencies...${NC}"
if command -v apt &> /dev/null; then
    apt update
    apt install -y build-essential checkinstall zlib1g-dev wget perl
elif command -v yum &> /dev/null; then
    yum groupinstall -y "Development Tools"
    yum install -y zlib-devel wget perl
elif command -v dnf &> /dev/null; then
    dnf groupinstall -y "Development Tools"
    dnf install -y zlib-devel wget perl
else
    echo -e "${YELLOW}Warning: Unknown package manager, assuming dependencies are installed${NC}"
fi

# Download OpenSSL
echo -e "${YELLOW}Downloading OpenSSL $VERSION...${NC}"
DOWNLOAD_URL="https://www.openssl.org/source/openssl-${VERSION}.tar.gz"

# For older versions, try archive
if ! wget -q "$DOWNLOAD_URL" 2>/dev/null; then
    DOWNLOAD_URL="https://www.openssl.org/source/old/${MAJOR_VERSION}.${MINOR_VERSION}/openssl-${VERSION}.tar.gz"
    if ! wget -q "$DOWNLOAD_URL" 2>/dev/null; then
        echo -e "${RED}Error: Could not download OpenSSL $VERSION${NC}"
        exit 1
    fi
fi

tar -xf "openssl-${VERSION}.tar.gz"
cd "openssl-${VERSION}"

# Build configure options based on version
build_config_options() {
    local opts=""

    # Common options
    opts="--prefix=$PREFIX --openssldir=$PREFIX"

    if [ $BUILD_SHARED -eq 0 ]; then
        opts="$opts no-shared"
    fi

    # Version-specific options
    if [[ "$VERSION" == 1.1.1* ]]; then
        # OpenSSL 1.1.1 specific options
        if [ $ENABLE_LEGACY -eq 1 ]; then
            opts="$opts enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers"
        fi
        if [ $ENABLE_SM -eq 1 ]; then
            opts="$opts enable-sm2 enable-sm3 enable-sm4"
        fi
        # 1.1.1 uses different RSA bits option
        opts="$opts -DOPENSSL_RSA_MAX_MODULUS_BITS=16384"

    else
        # OpenSSL 3.x specific options
        if [ $ENABLE_LEGACY -eq 1 ]; then
            opts="$opts enable-legacy enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers"
        fi
        if [ $ENABLE_SM -eq 1 ]; then
            opts="$opts enable-sm2 enable-sm3 enable-sm4"
        fi
        if [ $ENABLE_FIPS -eq 1 ]; then
            opts="$opts enable-fips"
        fi
        opts="$opts -DOPENSSL_RSA_MAX_MODULUS_BITS=16384"
        opts="$opts enable-ec enable-ec2m"
    fi

    echo "$opts"
}

CONFIG_OPTS=$(build_config_options)

echo -e "${YELLOW}Configuring with options:${NC}"
echo "$CONFIG_OPTS"
echo ""

./config $CONFIG_OPTS

# Build
echo -e "${YELLOW}Building OpenSSL (using $(nproc) cores)...${NC}"
make -j$(nproc)

# Run tests if enabled
if [ $RUN_TESTS -eq 1 ]; then
    echo -e "${YELLOW}Running tests...${NC}"
    make test || echo -e "${YELLOW}Warning: Some tests failed, continuing...${NC}"
fi

# Install
echo -e "${YELLOW}Installing to $PREFIX...${NC}"
make install

# Create version-specific openssl.cnf
echo -e "${YELLOW}Creating configuration file...${NC}"
mkdir -p "$PREFIX/ssl"

if [[ "$VERSION" == 1.1.1* ]]; then
    # OpenSSL 1.1.1 config (no providers)
    cat > "$PREFIX/ssl/openssl.cnf" << 'EOF'
# OpenSSL 1.1.1 Configuration
HOME = .

openssl_conf = openssl_init

[openssl_init]
oid_section = new_oids
ssl_conf = ssl_sect

[new_oids]

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
MinProtocol = TLSv1
CipherString = DEFAULT@SECLEVEL=1

[req]
default_bits = 2048
default_md = sha256
distinguished_name = req_distinguished_name

[req_distinguished_name]
countryName = Country Name (2 letter code)
stateOrProvinceName = State or Province Name
localityName = Locality Name
0.organizationName = Organization Name
commonName = Common Name
EOF
else
    # OpenSSL 3.x config (with providers)
    cat > "$PREFIX/ssl/openssl.cnf" << EOF
# OpenSSL ${VERSION} Configuration
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect
ssl_conf = ssl_sect

[provider_sect]
default = default_sect
EOF

    if [ $ENABLE_LEGACY -eq 1 ]; then
        cat >> "$PREFIX/ssl/openssl.cnf" << 'EOF'
legacy = legacy_sect
EOF
    fi

    if [ $ENABLE_FIPS -eq 1 ]; then
        cat >> "$PREFIX/ssl/openssl.cnf" << 'EOF'
fips = fips_sect
EOF
    fi

    cat >> "$PREFIX/ssl/openssl.cnf" << 'EOF'

[default_sect]
activate = 1
EOF

    if [ $ENABLE_LEGACY -eq 1 ]; then
        cat >> "$PREFIX/ssl/openssl.cnf" << 'EOF'

[legacy_sect]
activate = 1
EOF
    fi

    if [ $ENABLE_FIPS -eq 1 ]; then
        cat >> "$PREFIX/ssl/openssl.cnf" << 'EOF'

[fips_sect]
activate = 1
EOF
    fi

    cat >> "$PREFIX/ssl/openssl.cnf" << 'EOF'

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
MinProtocol = TLSv1
CipherString = DEFAULT@SECLEVEL=1
EOF

    if [ $ENABLE_SM -eq 1 ]; then
        cat >> "$PREFIX/ssl/openssl.cnf" << 'EOF'
# SM Cipher Suites for TLCP
Ciphersuites = TLS_SM4_GCM_SM3:TLS_SM4_CCM_SM3
EOF
    fi
fi

# Create activation script
mkdir -p "$PREFIX/scripts"
cat > "$PREFIX/scripts/activate.sh" << EOF
#!/bin/bash
# Activate OpenSSL $VERSION
export PATH="$PREFIX/bin:\$PATH"
export LD_LIBRARY_PATH="$PREFIX/lib:\$LD_LIBRARY_PATH"
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig:\$PKG_CONFIG_PATH"
export OPENSSL_CONF="$PREFIX/ssl/openssl.cnf"
export OPENSSL_ROOT_DIR="$PREFIX"
hash -r
echo "OpenSSL $VERSION activated"
$PREFIX/bin/openssl version
EOF
chmod +x "$PREFIX/scripts/activate.sh"

# Create symlink
ln -sf "$PREFIX/scripts/activate.sh" "$PREFIX/activate"

# Cleanup
cd /
rm -rf "$TEMP_DIR"

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN} Installation Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "OpenSSL $VERSION installed to: ${BLUE}$PREFIX${NC}"
echo ""
echo "To activate, run:"
echo -e "  ${YELLOW}source $PREFIX/activate${NC}"
echo ""
echo "Or add to your shell profile:"
echo -e "  ${YELLOW}echo 'source $PREFIX/activate' >> ~/.bashrc${NC}"
echo ""

# Verify installation
echo "Verification:"
$PREFIX/bin/openssl version -a | head -5
