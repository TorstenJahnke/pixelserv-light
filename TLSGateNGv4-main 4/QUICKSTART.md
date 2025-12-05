# TLSGateNG4 v4.36 GEN4 (2026) - Quick Start

**国密/商用密码 Support - SM2/SM3/SM4 Chinese Commercial Cryptography**

## 5-Minute Setup

### Step 1: Create Directory Structure
```bash
./setup.sh /opt/TLSGateNXv3
```

### Step 2: Add Your Certificates

Copy your RootCA (same for all SubCAs):
```bash
cp your_root.crt /opt/TLSGateNXv3/{RSA,ECDSA,SM2}/root.crt
```

Copy SubCA certificates and keys:
```bash
# RSA
cp your_rsa_subca.crt /opt/TLSGateNXv3/RSA/ca.crt
cp your_rsa_subca.key /opt/TLSGateNXv3/RSA/ca.key

# ECDSA
cp your_ecdsa_subca.crt /opt/TLSGateNXv3/ECDSA/ca.crt
cp your_ecdsa_subca.key /opt/TLSGateNXv3/ECDSA/ca.key

# SM2
cp your_sm2_subca.crt /opt/TLSGateNXv3/SM2/ca.crt
cp your_sm2_subca.key /opt/TLSGateNXv3/SM2/ca.key
```

### Step 3: Verify Setup
```bash
./setup.sh /opt/TLSGateNXv3
```

Should show: `✅ ALL CHECKS PASSED!`

### Step 4: Build TLSGateNG4
```bash
gcc -Wall -Wextra -O2 -std=gnu11 \
  -Iinclude -Isrc \
  -o build/tlsgateNGv4 \
  src/tlsgateNG.c src/core/worker.c src/core/connection.c \
  src/http/response.c src/http/extension_lookup.c \
  src/anti_adblock/anti_adblock.c \
  src/anti_adblock/browser_detection.c \
  src/anti_adblock/timing_jitter.c \
  src/tls/sni_extractor.c \
  src/cert/ca_loader.c src/cert/cert_cache.c \
  src/cert/cert_generator.c src/cert/cert_maintenance.c \
  src/cert/cert_index.c \
  src/crypto/keypool.c \
  src/pki/pki_manager.c \
  src/util/logger.c src/util/util.c \
  src/ipc/shm_manager.c \
  src/config/config_file.c src/config/config_generator.c \
  -pthread -lssl -lcrypto -lz -lrt
```

### Step 5: Run TLSGateNG4
```bash
./build/tlsgateNGv4 --base-dir /opt/TLSGateNXv3
```

## What Happens Now

### Auto-Detection
When a client connects with TLS ClientHello:
- System detects: RSA? ECDSA? SM2?
- Selects matching SubCA automatically
- Generates certificate
- Returns with correct SubCA signature

### Maintenance (Every 12 Hours)
- Scans all certificates
- Finds ones expiring < 7 days
- Auto-renews them
- Updates certificate index

## Monitoring

### Check Certificate Status
```bash
# RSA certificates
cat /opt/TLSGateNXv3/RSA/certs/.index

# ECDSA certificates
cat /opt/TLSGateNXv3/ECDSA/certs/.index

# SM2 certificates
cat /opt/TLSGateNXv3/SM2/certs/.index
```

Output format: `domain|expiration|algorithm|days_remaining`

### Check Generated Certificates
```bash
# List all RSA certificates
ls -lh /opt/TLSGateNXv3/RSA/certs/*.pem

# Check cert details
openssl x509 -in /opt/TLSGateNXv3/RSA/certs/example.com.pem -text -noout
```

## Common Commands

### Verify RootCA is Shared
```bash
# All three should be identical
md5sum /opt/TLSGateNXv3/{RSA,ECDSA,SM2}/root.crt
```

### Check SubCA Certificates
```bash
# List RSA SubCA details
openssl x509 -in /opt/TLSGateNXv3/RSA/ca.crt -text -noout | grep -E "Subject:|Issuer:|Public.*Key"

# List ECDSA SubCA details
openssl x509 -in /opt/TLSGateNXv3/ECDSA/ca.crt -text -noout | grep -E "Subject:|Issuer:|Public.*Key"

# List SM2 SubCA details
openssl x509 -in /opt/TLSGateNXv3/SM2/ca.crt -text -noout | grep -E "Subject:|Issuer:|Public.*Key"
```

### Verify RootCA Signed SubCAs
```bash
# Check RSA SubCA was signed by RootCA
openssl verify -CAfile /opt/TLSGateNXv3/RSA/root.crt /opt/TLSGateNXv3/RSA/ca.crt

# Check ECDSA SubCA was signed by RootCA
openssl verify -CAfile /opt/TLSGateNXv3/ECDSA/root.crt /opt/TLSGateNXv3/ECDSA/ca.crt

# Check SM2 SubCA was signed by RootCA
openssl verify -CAfile /opt/TLSGateNXv3/SM2/root.crt /opt/TLSGateNXv3/SM2/ca.crt
```

## Testing

### Generate Test Certificates (Dev Only)
See `SETUP.md` section "Generating Test Certificates"

### Verify Generated Certificates
```bash
# Check if example.com certificate was signed by RSA SubCA
openssl x509 -in /opt/TLSGateNXv3/RSA/certs/example.com.pem -issuer -noout

# Verify the signing chain
openssl verify -CAfile /opt/TLSGateNXv3/RSA/ca.crt \
  -untrusted /opt/TLSGateNXv3/RSA/root.crt \
  /opt/TLSGateNXv3/RSA/certs/example.com.pem
```

## Troubleshooting

### Setup Script Fails
```bash
./setup.sh /opt/TLSGateNXv3 1
```
(verbose mode shows what's missing)

### Missing Certificates
```
❌ SETUP INCOMPLETE
Missing files (3 errors). Please add:
  - root.crt in each SubCA directory (all identical)
  - ca.crt (SubCA certificate) in each directory
  - ca.key (SubCA private key) in each directory
```

### RootCA Mismatch
```
⚠️  WARNING: RootCA files differ between SubCAs!
```
→ Make sure all three `root.crt` files are identical copies

### No Certificates Generated
1. Check if TLSGateNG4 is running: `ps aux | grep tlsgateNG`
2. Check base directory: `ls -la /opt/TLSGateNXv3/RSA/certs/`
3. Check logs: `tail -100 /var/log/tlsgateNG/tlsgateNG.log`

## Next Steps

1. ✅ Directory structure created
2. ✅ Certificates added (RSA/ECDSA/SM2)
3. ✅ Setup verified
4. ✅ Built TLSGateNG4 with 国密/商用密码 support
5. ✅ 12h maintenance cycle enabled (automatic!)
6. ➡️ Deploy to production
7. ➡️ Monitor certificate renewals

## Documentation

- **Full Setup**: See `SETUP.md`
- **Configuration**: See `tlsgateNG.conf.example`
- **Implementation**:
  - Multi-SubCA: `src/cert/ca_loader.c`
  - Cert Generation: `src/cert/cert_generator.c`
  - Maintenance: `src/cert/cert_maintenance.c`
  - SM2 Support: `src/cert/cert_generator.c` (line ~1027)

---

**Questions?** See SETUP.md for detailed documentation.
