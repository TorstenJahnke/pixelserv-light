# OpenSSL Installation Scripts

Universal OpenSSL installation scripts supporting versions 1.1.1 through 3.6.x.

## Quick Start

```bash
# Install latest OpenSSL 3.6 with SM support
sudo ./scripts/install_openssl_universal.sh -v 3.6.0 -l -s

# Activate
source /opt/openssl-3.6.0/activate
```

## Scripts

| Script | Description |
|--------|-------------|
| `install_openssl_universal.sh` | Universal installer for all OpenSSL versions |
| `install_openssl3.6_legacy_full.sh` | Legacy script for OpenSSL 3.6 only |
| `activate.sh` | Activate OpenSSL in current shell |
| `activate_force.sh` | Force-activate (removes system paths) |
| `test_legacy_compatibility.sh` | Test legacy crypto support |
| `clean_old_install.sh` | Remove old installations |
| `openssl_benchmark_epyc.sh` | Performance benchmarks |
| `live_monitor.sh` | System monitoring |
| `install_benchmark_tools.sh` | Install benchmark dependencies |

## Universal Installer Usage

```bash
./scripts/install_openssl_universal.sh [OPTIONS]

Options:
  -v, --version VERSION    OpenSSL version (default: 3.6.0)
  -p, --prefix PATH        Installation prefix
  -l, --legacy             Enable legacy algorithms (SSL3, weak ciphers)
  -s, --sm                 Enable SM2/SM3/SM4
  -f, --fips               Enable FIPS module (3.x only)
  -S, --shared             Build shared libraries
  --no-tests               Skip test suite
```

## Supported Versions

| Version | Status | Notes |
|---------|--------|-------|
| 1.1.1w | EOL | Legacy systems only |
| 3.0.15 | LTS | Until 2026, FIPS available |
| 3.1.7 | Stable | Regular release |
| 3.2.3 | Stable | Regular release |
| 3.3.2 | Stable | Regular release |
| 3.4.0 | Current | |
| 3.5.0 | Current | |
| 3.6.0 | Latest | Recommended |

## Examples

```bash
# OpenSSL 3.6 with full features
sudo ./scripts/install_openssl_universal.sh -v 3.6.0 -l -s

# OpenSSL 1.1.1 for legacy compatibility
sudo ./scripts/install_openssl_universal.sh -v 1.1.1w -l

# OpenSSL 3.0 LTS with FIPS
sudo ./scripts/install_openssl_universal.sh -v 3.0.15 -f

# Custom prefix
sudo ./scripts/install_openssl_universal.sh -v 3.6.0 -p /usr/local/ssl
```

## Switching Between Versions

Use the SSL switcher tool:

```bash
source ../tools/ssl-switch.sh list      # Show all installations
source ../tools/ssl-switch.sh openssl 3.6.0  # Activate specific version
source ../tools/ssl-switch.sh system    # Revert to system OpenSSL
```

## Version Differences

### OpenSSL 1.1.1
- No provider system
- SM2/SM3/SM4 built-in (no `enable-legacy` needed)
- Different config syntax

### OpenSSL 3.x
- Provider-based architecture
- Legacy algorithms require `enable-legacy`
- FIPS module available
- New openssl.cnf format with providers
