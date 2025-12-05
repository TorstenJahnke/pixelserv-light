# Tongsuo Installation Scripts

Tongsuo (formerly BabaSSL) installation scripts with full TLCP and Chinese cryptography support.

## What is Tongsuo?

Tongsuo is a Chinese fork of OpenSSL maintained by Alibaba, providing:

- **TLCP 1.1** - Chinese TLS protocol (GB/T 38636-2020)
- **SM2** - Chinese elliptic curve cryptography (GB/T 32918)
- **SM3** - Chinese hash algorithm (GB/T 32905)
- **SM4** - Chinese block cipher (GB/T 32907)
- **ZUC** - Chinese stream cipher
- **Delegated Credentials** (RFC 9345)
- **Certificate Compression** (RFC 8879)

GitHub: https://github.com/Tongsuo-Project/Tongsuo

## Quick Start

```bash
# Install Tongsuo 8.4.0 with TLCP support
sudo ./scripts/install_tongsuo.sh -v 8.4.0

# Activate
source /opt/tongsuo-8.4.0/activate

# Test SM support
./scripts/test_tlcp.sh

# Generate SM2 certificates
./scripts/generate_sm2_certs.sh myserver.example.com ./certs
```

## Scripts

| Script | Description |
|--------|-------------|
| `install_tongsuo.sh` | Main installer |
| `activate.sh` | Activate Tongsuo in current shell |
| `test_tlcp.sh` | Test TLCP/SM crypto support |
| `generate_sm2_certs.sh` | Generate SM2 certificate pairs for TLCP |

## Installer Options

```bash
./scripts/install_tongsuo.sh [OPTIONS]

Options:
  -v, --version VERSION    Tongsuo version (default: 8.4.0)
  -p, --prefix PATH        Installation prefix
  -n, --ntls               Enable NTLS/TLCP protocol (default: enabled)
  --no-ntls                Disable NTLS/TLCP protocol
  -d, --delegated-creds    Enable Delegated Credentials
  -c, --cert-compression   Enable Certificate Compression
  -S, --shared             Build shared libraries
  --no-tests               Skip test suite
```

**Note:** TLCP 1.1 support is enabled via `enable-ntls` in Tongsuo.
GitHub tag format uses simple version numbers: `8.4.0`, `8.3.3`

## Supported Versions

| Version | Status |
|---------|--------|
| 8.3.3 | Stable LTS |
| 8.4.0 | Latest stable (recommended) |
| master | Development |

## TLCP Certificate Requirements

TLCP requires **two certificate pairs** per entity:

1. **Sign Certificate** - For digital signature/authentication
2. **Enc Certificate** - For key exchange/encryption

Use the `generate_sm2_certs.sh` script to create both:

```bash
./scripts/generate_sm2_certs.sh myserver.example.com ./certs 365

# Generated files:
# - sm2_ca.crt, sm2_ca.key       (CA)
# - sm2_sign.crt, sm2_sign.key   (Signing)
# - sm2_enc.crt, sm2_enc.key     (Encryption)
# - sm2_sign_chain.crt           (Signing + CA chain)
# - sm2_enc_chain.crt            (Encryption + CA chain)
```

## Switching Between Tongsuo and OpenSSL

Use the SSL switcher tool:

```bash
source ../tools/ssl-switch.sh list        # Show all installations
source ../tools/ssl-switch.sh tongsuo     # Activate latest Tongsuo
source ../tools/ssl-switch.sh openssl     # Switch to OpenSSL
source ../tools/ssl-switch.sh system      # Revert to system SSL
```

## TLSGateNG Integration

To use Tongsuo with TLSGateNG for TLCP/SM support:

1. Install Tongsuo with TLCP enabled
2. Activate Tongsuo environment
3. Build TLSGateNG with Tongsuo:

```bash
source /opt/tongsuo-8.4.0/activate
make clean
make OPENSSL_ROOT=/opt/tongsuo-8.4.0
```

## Testing SM Support

```bash
# Quick test
./scripts/test_tlcp.sh

# Manual tests
openssl genpkey -algorithm SM2 -out test.key
echo "test" | openssl dgst -sm3
echo "test" | openssl enc -sm4-cbc -k pass -pbkdf2 | openssl enc -sm4-cbc -d -k pass -pbkdf2
```

## Cipher Suites

Available SM cipher suites for TLS 1.3:
- `TLS_SM4_GCM_SM3`
- `TLS_SM4_CCM_SM3`

For TLCP 1.1:
- `ECC_SM4_CBC_SM3`
- `ECDHE_SM4_CBC_SM3`
