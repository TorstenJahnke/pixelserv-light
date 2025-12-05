# TLSGateNG4 v4.36 GEN4 (2026) - Setup Guide

**国密/商用密码 Support - SM2/SM3/SM4 Chinese Commercial Cryptography**

## Multi-SubCA Directory Structure

TLSGateNG4 requires a specific directory structure for multi-SubCA support with RSA, ECDSA, and SM2 algorithms.

### Directory Layout

```
/opt/TLSGateNXv3/           ← Base directory
├── RSA/                    ← RSA SubCA
│   ├── root.crt           (Shared RootCA)
│   ├── ca.crt             (RSA SubCA certificate)
│   ├── ca.key             (RSA SubCA private key)
│   └── certs/             (Generated RSA certificates)
│       └── .index         (Certificate index)
├── ECDSA/                 ← ECDSA SubCA
│   ├── root.crt           (Same RootCA as RSA)
│   ├── ca.crt             (ECDSA SubCA certificate)
│   ├── ca.key             (ECDSA SubCA private key)
│   └── certs/             (Generated ECDSA certificates)
│       └── .index         (Certificate index)
└── SM2/                   ← SM2 SubCA
    ├── root.crt           (Same RootCA as RSA/ECDSA)
    ├── ca.crt             (SM2 SubCA certificate)
    ├── ca.key             (SM2 SubCA private key)
    └── certs/             (Generated SM2 certificates)
        └── .index         (Certificate index)
```

## Quick Start

### 1. Prepare CA Certificates

First, you need to generate or obtain:
- **One RootCA certificate** (used by all SubCAs)
- **Three SubCA certificates** (one for RSA, one for ECDSA, one for SM2)
- **Three SubCA private keys** (one for each SubCA)

All SubCAs must be signed by the same RootCA!

### 2. Run Setup Script

```bash
cd /home/user/TLSGateNXv3

# Setup with default location (./)
./setup.sh

# Or specify base directory
./setup.sh /opt/TLSGateNXv3

# Verbose mode (shows all steps)
./setup.sh /opt/TLSGateNXv3 1
```

### 3. Add Your Certificates

Copy your certificates to the appropriate directories:

```bash
# Copy RootCA (same for all)
cp your_root.crt /opt/TLSGateNXv3/RSA/root.crt
cp your_root.crt /opt/TLSGateNXv3/ECDSA/root.crt
cp your_root.crt /opt/TLSGateNXv3/SM2/root.crt

# Copy RSA SubCA
cp your_rsa_subca.crt /opt/TLSGateNXv3/RSA/ca.crt
cp your_rsa_subca.key /opt/TLSGateNXv3/RSA/ca.key

# Copy ECDSA SubCA
cp your_ecdsa_subca.crt /opt/TLSGateNXv3/ECDSA/ca.crt
cp your_ecdsa_subca.key /opt/TLSGateNXv3/ECDSA/ca.key

# Copy SM2 SubCA
cp your_sm2_subca.crt /opt/TLSGateNXv3/SM2/ca.crt
cp your_sm2_subca.key /opt/TLSGateNXv3/SM2/ca.key
```

### 4. Verify Setup

Run setup script again to verify:

```bash
./setup.sh /opt/TLSGateNXv3
```

Should show:
```
✅ ALL CHECKS PASSED!
```

## Generating Test Certificates (Development Only)

For testing, you can generate test certificates:

```bash
# Generate RootCA
openssl genrsa -out root.key 4096
openssl req -new -x509 -days 3650 -key root.key -out root.crt \
  -subj "/C=US/ST=State/L=City/O=Org/CN=TLSGateNX-Root"

# Generate RSA SubCA
openssl genrsa -out rsa_subca.key 3072
openssl req -new -key rsa_subca.key -out rsa_subca.csr \
  -subj "/C=US/ST=State/L=City/O=Org/CN=TLSGateNX-RSA-SubCA"
openssl x509 -req -days 1825 -in rsa_subca.csr \
  -CA root.crt -CAkey root.key -CAcreateserial \
  -out rsa_subca.crt

# Generate ECDSA SubCA
openssl ecparam -name prime256v1 -genkey -noout -out ecdsa_subca.key
openssl req -new -key ecdsa_subca.key -out ecdsa_subca.csr \
  -subj "/C=US/ST=State/L=City/O=Org/CN=TLSGateNX-ECDSA-SubCA"
openssl x509 -req -days 1825 -in ecdsa_subca.csr \
  -CA root.crt -CAkey root.key -CAcreateserial \
  -out ecdsa_subca.crt

# Generate SM2 SubCA (if OpenSSL supports SM2)
openssl ecparam -name SM2 -genkey -noout -out sm2_subca.key
openssl req -new -key sm2_subca.key -out sm2_subca.csr \
  -subj "/C=US/ST=State/L=City/O=Org/CN=TLSGateNX-SM2-SubCA"
openssl x509 -req -days 1825 -in sm2_subca.csr \
  -CA root.crt -CAkey root.key -CAcreateserial \
  -out sm2_subca.crt
```

Then copy the certificates as shown above.

## Certificate Maintenance

### Daily Maintenance (Automatic)

The maintenance system runs every 12 hours and:
1. Generates an index of all certificates
2. Identifies certificates expiring within 7 days
3. Automatically renews expiring certificates
4. Atomically replaces old with new certificates

### Certificate Index Format

Each SubCA directory contains a `.index` file:

```
# domain|expiration_timestamp|algorithm|days_remaining
example.com|1734825600|RSA|5
api.example.com|1735430400|ECDSA|10
cdn.example.com|1734604800|SM2|3
```

### Manual Renewal

To manually check certificate status:

```bash
# Check RSA SubCA
cat /opt/TLSGateNXv3/RSA/certs/.index

# Check ECDSA SubCA
cat /opt/TLSGateNXv3/ECDSA/certs/.index

# Check SM2 SubCA
cat /opt/TLSGateNXv3/SM2/certs/.index
```

## Important Notes

### RootCA Consistency
- All SubCAs MUST be signed by the **same RootCA**
- The `root.crt` file must be IDENTICAL in all three directories
- Mismatched RootCA certificates will cause certificate validation failures

### File Permissions
- `ca.key` files are set to `0600` (read/write owner only)
- Directories are set to `0755`
- Certificate files are set to `0644`

### Certificate Storage
- Generated certificates are stored in `certs/` subdirectory
- Each certificate is named: `domain.pem`
- Backups during renewal: `domain.pem.old`
- Temporary files during renewal: `domain.pem.tmp`

## Troubleshooting

### Missing RootCA Files
```
⚠️  Missing: /opt/TLSGateNXv3/RSA/root.crt (required)
```
**Solution:** Copy the RootCA certificate to all three SubCA directories.

### RootCA Mismatch
```
⚠️  WARNING: RootCA files differ between SubCAs!
```
**Solution:** Ensure all three `root.crt` files are identical copies.

### Missing SubCA Files
```
⚠️  Missing: /opt/TLSGateNXv3/ECDSA/ca.crt (required)
```
**Solution:** Generate or copy the SubCA certificate and key to the directory.

### Permission Issues
```
ERROR: Cannot write to certs/ directory
```
**Solution:** Check permissions and ownership. Run setup script again to fix.

## Production Checklist

Before running in production:

- [ ] RootCA certificate is installed and backed up
- [ ] Three SubCA certificates (RSA/ECDSA/SM2) are installed
- [ ] Three SubCA private keys are installed securely
- [ ] `setup.sh` runs without errors
- [ ] All files in checklist show ✓
- [ ] RootCA certificates are identical across all SubCAs
- [ ] File permissions are correct (0600 for keys, 0644 for certs)
- [ ] `certs/` directories are writable by TLSGateNXv3 process
- [ ] Backup copies of all certificates exist in separate location
- [ ] 12-hour maintenance cycle is enabled in main loop

## Next Steps

1. Complete the directory setup
2. Add your certificates
3. Verify with `./setup.sh`
4. Configure TLSGateNXv3 to use `/opt/TLSGateNXv3/` as base directory
5. Enable 12-hour maintenance cycle in main()
6. Monitor certificate index files for renewals

---

For more information, see:
- Multi-SubCA Implementation: `src/cert/ca_loader.c`
- Certificate Generation: `src/cert/cert_generator.c`
- Certificate Maintenance: `src/cert/cert_maintenance.c`
