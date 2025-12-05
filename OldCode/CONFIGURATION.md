# TLSGateNG Configuration Guide

Complete reference for all configuration options in `tlsgateNG.conf`.

**Config file location:**
- Linux/Debian: `/etc/tlsgateNG/tlsgateNG.conf`
- BSD/FreeBSD: `/usr/local/etc/tlsgateNG/tlsgateNG.conf`

---

## [version] Section

Version number that must match the application version.

### version (Required)
- **Format:** `MAJOR.MINOR.PATCH.BUILD` or just `MAJOR.MINOR`
- **Example:** `4.36` or `4.36.0.0`
- **Purpose:** Application version validation
- **Default:** None (auto-created)
- **Note:** Version mismatch will be warned or cause startup failure

---

## [prime] Section

Prime pool configuration for cryptographic operations.

### path
- **Type:** File path
- **Format:** Full absolute path to directory
- **Example:** `/usr/local/etc/TLSGateNX/server/primes`
- **Purpose:** Directory containing pre-computed prime numbers
- **Default:** Empty (disabled)
- **Note:** Empty means prime generation disabled; primes computed on-demand instead

---

## [keypool] Section

Keypool configuration for RSA/ECDSA key pre-generation.

### path
- **Type:** File path
- **Format:** Full absolute path to directory
- **Example:** `/usr/local/etc/TLSGateNX/server/keypool`
- **Purpose:** Directory containing pre-generated private keys for fast certificate generation
- **Default:** Empty (disabled)
- **Critical:** Empty means no key pre-generation; significantly slower certificate generation

---

## [backup] Section

Automatic backup configuration for keypool.

### enable
- **Type:** Boolean
- **Values:** `true` or `false` (also accepts `1` or `0`)
- **Default:** `false`
- **Purpose:** Enable automatic keypool backups (every 30 minutes)
- **Note:** Requires `path` to be configured if enabled

### path
- **Type:** File path
- **Format:** Full absolute path to directory
- **Example:** `/usr/local/etc/tlsgateNG/backup`
- **Purpose:** Directory where backups are stored
- **Default:** Empty (disabled)
- **Auto-created:** Yes, if parent directory exists

### encrypt
- **Type:** Boolean
- **Values:** `true` or `false`
- **Default:** `false`
- **Purpose:** Encrypt backups with AES-256-GCM
- **Requirements:** Requires `ca_key` and `curve` to be configured
- **Note:** Provides security for stored backups

### ca_key
- **Type:** File path
- **Format:** Full absolute path to CA private key PEM file
- **Example:** `/etc/tlsgateNG/certs/ca-key.pem`
- **Purpose:** CA private key used for backup encryption/decryption
- **Required if:** `encrypt=true`
- **Note:** Usually same as the server's CA key

### curve
- **Type:** Integer
- **Format:** 6-digit number (LLPPXX format)
  - **LL** = Line number (2-9)
  - **PP** = Position in line (5-30)
  - **XX** = Length to extract (16-24)
- **Example:** `30916` = Line 3, Position 09, Length 16
- **Purpose:** Derives encryption key from elliptic curve parameters
- **Default:** `0` (disabled)
- **Generator:** `python3 -c 'import random; l=random.randint(2,9); p=random.randint(5,30); n=random.randint(16,24); print(f"{l*10000+p*100+n}")'`
- **Required if:** `encrypt=true`
- **Security:** Change this value to create unique encryption keys

---

## [security] Section

Security and legacy client support options.

### legacy_crypto
- **Type:** Boolean
- **Values:** `true` or `false`
- **Default:** `false`
- **Purpose:** Enable legacy/weak cryptography (RSA-1024/2048, SHA1)
- **Use cases:**
  - MS-DOS clients
  - Windows 3.11, Windows 95/98
  - Very old browsers
  - AS/400 systems
  - Testing and honeypot deployments
- **WARNING:** Severely weakens security; only use when necessary

---

## [none-sni] Section

Controls handling of clients that don't send SNI (Server Name Indication) in TLS ClientHello.

### mode
- **Type:** String
- **Values:** `auto`, `static`, `disabled`
- **Default:** `auto`
- **Purpose:** How to handle SNI-less clients

**Modes explained:**

| Mode | Behavior |
|------|----------|
| `auto` | `default_domain` is updated to current SNI in realtime. SNI-less clients get the last seen SNI domain. |
| `static` | `default_domain` is a fixed value from config. |
| `disabled` | SNI-less clients are rejected (no certificate generated). |

### default-domain
- **Type:** String (domain name)
- **Format:** Valid domain name (FQDN or hostname)
- **Example:** `firma.local` or `internal.example.com`
- **Default:** Empty
- **Purpose:** Domain for SNI-less clients when `mode=static`
- **Note:** Only used when `mode=static`

### Example configurations

**Auto mode (default, recommended for modern deployments):**
```ini
[none-sni]
mode=auto
# No default-domain needed - uses current SNI
```

**Static mode (for legacy/controlled environments):**
```ini
[none-sni]
mode=static
default-domain=legacy.firma.local
```

**Disabled mode (reject all SNI-less clients):**
```ini
[none-sni]
mode=disabled
```

---

## [certificate] Section

Certificate generation options. Controls how on-demand certificates are created.

### enable_wildcards
- **Type:** Boolean
- **Values:** `true` or `false`
- **Default:** `true`
- **Purpose:** Generate wildcard certificates for subdomains
- **Behavior when `true`:**
  ```
  Request: www.example.com
  Result: CN=example.com, SAN=DNS:*.example.com,DNS:example.com
  ```
- **Behavior when `false`:**
  ```
  Request: www.example.com
  Result: CN=www.example.com, SAN=DNS:www.example.com
  ```
- **Impact:**
  - `true`: Single certificate covers all subdomains (better caching)
  - `false`: Separate certificate needed for each subdomain (slower)
- **Auto-disabled for:** RSA-1024/2048 (legacy algorithms can't use wildcards)

### enable_san
- **Type:** Boolean
- **Values:** `true` or `false`
- **Default:** `true`
- **Purpose:** Add Subject Alternative Names (SAN) extension to certificates
- **Requirements:** Modern browsers require SAN
- **Behavior when `true`:**
  ```
  Example: www.example.com → SAN=DNS:www.example.com,DNS:*.example.com
  ```
- **Behavior when `false`:**
  ```
  Only CN is set, no SAN extension (ancient clients only)
  ```
- **WARNING:** Disabling SAN breaks most modern browsers
- **Auto-disabled for:** RSA-1024/2048 (ultra-legacy compatibility)

### validity_days
- **Type:** Integer
- **Range:** 1-398 days
- **Default:** `200`
- **Purpose:** Certificate validity period in days
- **Browser CA Baseline:** 398 days maximum (enforced since 2020)
- **Common values:**
  - `90`: 3 months (frequently regenerated certificates)
  - `200`: Conservative default (browser compatible)
  - `365`: 1 year (long-lived certificates)
  - `398`: Maximum browser-allowed value
- **Example:** `validity_days=365`
- **Note:** Each certificate is randomly backdated 2-14 days to appear natural

### cache_certificates
- **Type:** Boolean
- **Values:** `true` or `false`
- **Default:** `true`
- **Purpose:** Cache generated certificates in memory
- **Impact when `true`:**
  - Massive performance improvement (80-95% fewer generations)
  - Reuse certificates for repeated domain requests
- **Impact when `false`:**
  - Generate new certificate for every domain request
  - Extremely slow for production
- **Recommendation:** Always `true` in production

### second_level_tld_file
- **Type:** File path
- **Format:** Full absolute path to 2nd-level TLD configuration file
- **Example:** `/etc/tlsgateNG/second-level-tlds.conf`
- **Default:** Empty (auto-detect at `/etc/tlsgateNG/second-level-tlds.conf`)
- **Purpose:** Handle special multi-part TLDs correctly
- **Used for:**
  ```
  api.example.co.uk → Creates wildcard for *.example.co.uk
  (NOT *.example.co.uk which would be wrong)
  ```
- **Supported TLDs:**
  - `.co.uk`, `.org.uk`, `.gov.uk`
  - `.com.au`, `.gov.au`, `.edu.au`
  - `.co.jp`, `.or.jp`
  - `.com.br`, `.gov.br`
  - And 1000+ others
- **Format:** One TLD per line, simple text file
- **Note:** Leave empty for automatic detection and generation

---

## [ca] Section (Legacy)

**DEPRECATED** - Use algorithm-specific sections instead.

Generic CA certificate configuration (fallback).

### sub_cert_path
- **Type:** File path
- **Format:** Full absolute path to SubCA certificate PEM file
- **Purpose:** Intermediate CA certificate (Multi Mode)
- **Example:** `/opt/TLSGateNX/certs/subca.crt`

### sub_key_path
- **Type:** File path
- **Format:** Full absolute path to SubCA private key PEM file
- **Purpose:** Intermediate CA private key (Multi Mode)
- **Example:** `/opt/TLSGateNX/certs/subca.key`

### root_cert_path
- **Type:** File path
- **Format:** Full absolute path to Root CA certificate PEM file
- **Purpose:** Root CA certificate for chain validation
- **Example:** `/opt/TLSGateNX/certs/rootca.crt`

### sub_cs_cert_path (Optional)
- **Type:** File path
- **Format:** Full absolute path to cross-signed SubCA certificate PEM file
- **Purpose:** Cross-signed SubCA for maximum compatibility
- **Example:** `/opt/TLSGateNX/certs/subca.cs.crt`
- **Optional:** Yes, only needed for special deployments

---

## [ca-RSA], [ca-ECDSA], [ca-SM2], [ca-LEGACY] Sections

**RECOMMENDED** - Algorithm-specific CA configuration.

Same options as `[ca]` section, but per algorithm:

### Example: [ca-RSA]
```ini
[ca-RSA]
sub_cert_path = /opt/TLSGateNX/certs/RSA/subca.crt
sub_key_path = /opt/TLSGateNX/certs/RSA/subca.key
root_cert_path = /opt/TLSGateNX/certs/RSA/rootca.crt
```

### Example: [ca-ECDSA]
```ini
[ca-ECDSA]
sub_cert_path = /opt/TLSGateNX/certs/ECDSA/subca.crt
sub_key_path = /opt/TLSGateNX/certs/ECDSA/subca.key
root_cert_path = /opt/TLSGateNX/certs/ECDSA/rootca.crt
```

### Supported algorithms
- **RSA:** RSA-3072, RSA-4096 (and RSA-1024/2048 if `legacy_crypto=true`)
- **ECDSA:** P-256, P-384, P-521
- **SM2:** Chinese cryptography standard
- **LEGACY:** Old algorithms for compatibility

---

## [license] Section

Reserved for future use. Not implemented yet.

### key
- **Type:** String
- **Purpose:** License key (future feature)
- **Default:** Empty

---

## Configuration Examples

### Production Setup (Recommended)
```ini
[version]
4.36

[prime]
path=/usr/local/etc/TLSGateNX/server/primes

[keypool]
path=/usr/local/etc/TLSGateNX/server/keypool

[backup]
enable=true
path=/usr/local/etc/tlsgateNG/backup
encrypt=true
ca_key=/etc/tlsgateNG/certs/ca-key.pem
curve=50918

[security]
legacy_crypto=false
default_domain=default.local

[certificate]
enable_wildcards=true
enable_san=true
validity_days=200
cache_certificates=true

[ca-RSA]
sub_cert_path=/opt/TLSGateNX/certs/RSA/subca.crt
sub_key_path=/opt/TLSGateNX/certs/RSA/subca.key
root_cert_path=/opt/TLSGateNX/certs/RSA/rootca.crt

[ca-ECDSA]
sub_cert_path=/opt/TLSGateNX/certs/ECDSA/subca.crt
sub_key_path=/opt/TLSGateNX/certs/ECDSA/subca.key
root_cert_path=/opt/TLSGateNX/certs/ECDSA/rootca.crt
```

### Testing/Development Setup
```ini
[version]
4.36

[security]
legacy_crypto=false

[certificate]
enable_wildcards=true
enable_san=true
validity_days=90
cache_certificates=true

[ca-RSA]
sub_cert_path=/tmp/testca/RSA/rootCA/subca.crt
sub_key_path=/tmp/testca/RSA/rootCA/subca.key
root_cert_path=/tmp/testca/RSA/rootCA/rootca.crt
```

### Legacy Client Support
```ini
[security]
legacy_crypto=true
default_domain=legacyhost.local

[certificate]
enable_wildcards=false
enable_san=false
validity_days=365
```

---

## Troubleshooting

### Certificate Issues
**Problem:** Different certificates for `www.example.com` and `example.com`
- **Cause:** `enable_wildcards=false`
- **Solution:** Set `enable_wildcards=true`

**Problem:** Browsers reject certificate as invalid
- **Cause:** `enable_san=false`
- **Solution:** Set `enable_san=true`

**Problem:** Certificate generation is very slow
- **Cause:** `cache_certificates=false` or empty keypool
- **Solution:** Enable caching and configure keypool

### Backup Issues
**Problem:** Backup encryption fails
- **Cause:** Missing or invalid `ca_key` or `curve`
- **Solution:** Set both `ca_key` and `curve` values

**Problem:** Can't decrypt backups
- **Cause:** Changed `curve` value or different `ca_key`
- **Solution:** Keep `curve` and `ca_key` consistent

---

## Default Values Quick Reference

| Option | Section | Default | Type |
|--------|---------|---------|------|
| `enable_wildcards` | certificate | `true` | bool |
| `enable_san` | certificate | `true` | bool |
| `validity_days` | certificate | `200` | int |
| `cache_certificates` | certificate | `true` | bool |
| `legacy_crypto` | security | `false` | bool |
| `mode` | none-sni | `auto` | string |
| `default-domain` | none-sni | (empty) | string |
| `backup_enabled` | backup | `false` | bool |
| `backup_encrypt` | backup | `false` | bool |

---

**Last Updated:** 2025-12-02
