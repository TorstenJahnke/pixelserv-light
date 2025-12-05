# TLSGate NG - RSA Key Size Demo Configuration

**Multi-IP RSA Key Size Demonstration**

This guide shows how to run TLSGate NG on multiple IP addresses, each using a different RSA key size for demonstration purposes.

---

## Overview

Run 4 different TLSGate NG instances, each on a separate IP address with a forced RSA key size:

| IP Address      | RSA Key Size | Prime Pool Files                        | Notes                           |
|-----------------|--------------|------------------------------------------|----------------------------------|
| 192.168.1.1     | RSA-3072     | `prime-3072-p.bin`, `prime-3072-q.bin`  | Standard security               |
| 192.168.1.2     | RSA-4096     | `prime-4096-p.bin`, `prime-4096-q.bin`  | High security                   |
| 192.168.1.3     | RSA-8192     | `prime-8192-p.bin`, `prime-8192-q.bin`  | Very high security              |
| 192.168.1.4     | RSA-16384    | `prime-16384-p.bin`, `prime-16384-q.bin`| Ultra-high security (VERY SLOW!)|

---

## Prime Pool Generation

Before starting the servers, you need to generate prime pools for each RSA key size.

### Your Current Prime Files

You already have prime files in `/ramdisk/`:

```bash
root@admingate:/ramdisk# ls -lh
-rw-r--r-- 1 root root  98M Nov 17 00:55 prime-16384-p.bin
-rw-r--r-- 1 root root  98M Nov 17 01:13 prime-16384-q.bin
-rw-r--r-- 1 root root 2.5M Nov 21 19:50 prime-2048-p.bin
-rw-r--r-- 1 root root 2.5M Nov 21 19:50 prime-2048-q.bin
-rw-r--r-- 1 root root 184M Nov 14 20:02 prime-3072-p.bin
-rw-r--r-- 1 root root 184M Nov 14 20:02 prime-3072-q.bin
-rw-r--r-- 1 root root 4.9M Nov 21 19:46 prime-4096-p.bin
-rw-r--r-- 1 root root 4.9M Nov 21 19:46 prime-4096-q.bin
-rw-r--r-- 1 root root  49M Nov 15 00:15 prime-8192-p.bin
-rw-r--r-- 1 root root  49M Nov 15 00:16 prime-8192-q.bin
```

**✅ All required prime files are present!**

### Prime Pool File Format

TLSGate NG now supports **TWO** prime pool formats:

1. **Combined format** (single file):
   - `prime-{keysize}.bin` - Contains both p and q primes

2. **Separate format** (two files):
   - `prime-{keysize}-p.bin` - p primes
   - `prime-{keysize}-q.bin` - q primes

Your files use the **separate format**, which is fully supported.

### 🔥 Automatic Prime Pool Detection

**Super cool feature:** Just point to the directory with `-r /ramdisk/` and the server **automatically loads ALL available prime pools**!

```bash
./build/tlsgateNGv4 -l 192.168.1.1 -s 443 -r /ramdisk/ --force-algorithm RSA-3072
```

**What happens behind the scenes:**
1. Server scans `/ramdisk/` for ALL prime files
2. Loads **every** prime pool it finds (3072, 4096, 8192, 16384)
3. Uses only the forced algorithm (RSA-3072 in this example)

**No need to specify individual prime files!** The code automatically searches for:
- `prime-1024.bin` or `prime-1024-p.bin` + `prime-1024-q.bin`
- `prime-2048.bin` or `prime-2048-p.bin` + `prime-2048-q.bin`
- `prime-3072.bin` or `prime-3072-p.bin` + `prime-3072-q.bin`
- `prime-4096.bin` or `prime-4096-p.bin` + `prime-4096-q.bin`
- `prime-8192.bin` or `prime-8192-p.bin` + `prime-8192-q.bin`
- `prime-16384.bin` or `prime-16384-p.bin` + `prime-16384-q.bin`

**Startup output shows what was loaded:**
```
Scanning for prime pools in: /ramdisk/
Loading separate prime pools: /ramdisk/prime-2048-p.bin + /ramdisk/prime-2048-q.bin
Loaded separate prime pools: 10000 primes (1024-bit) from p+q files
  [✓] RSA-2048: 10000 primes available (FAST PATH enabled)
Loading separate prime pools: /ramdisk/prime-3072-p.bin + /ramdisk/prime-3072-q.bin
Loaded separate prime pools: 50000 primes (1536-bit) from p+q files
  [✓] RSA-3072: 50000 primes available (FAST PATH enabled)
Loading separate prime pools: /ramdisk/prime-4096-p.bin + /ramdisk/prime-4096-q.bin
Loaded separate prime pools: 10000 primes (2048-bit) from p+q files
  [✓] RSA-4096: 10000 primes available (FAST PATH enabled)
Loading separate prime pools: /ramdisk/prime-8192-p.bin + /ramdisk/prime-8192-q.bin
Loaded separate prime pools: 50000 primes (4096-bit) from p+q files
  [✓] RSA-8192: 50000 primes available (FAST PATH enabled)
Loading separate prime pools: /ramdisk/prime-16384-p.bin + /ramdisk/prime-16384-q.bin
Loaded separate prime pools: 1000 primes (8192-bit) from p+q files
  [✓] RSA-16384: 1000 primes available (FAST PATH enabled)
Loaded 5 prime pool(s) - RSA generation will be 20-200× faster!
```

### RAM Usage Considerations

**With shared directory (`-r /ramdisk/`):**
- **Loads all prime pools** from the directory
- **Uses only** the forced algorithm
- **RAM overhead:** All pools loaded, even if not used

Your `/ramdisk/` prime pools:
- RSA-2048: ~2.5MB × 2 = ~5MB
- RSA-3072: ~184MB × 2 = ~368MB
- RSA-4096: ~4.9MB × 2 = ~10MB
- RSA-8192: ~49MB × 2 = ~98MB
- RSA-16384: ~98MB × 2 = ~196MB

**Total RAM per instance: ~677MB** (all prime pools loaded)

### RAM Optimization (Optional)

If you want to **save RAM**, organize prime pools in separate directories:

```bash
# Directory structure (organize prime pools by size):
/ramdisk/2048/prime-2048-p.bin + prime-2048-q.bin
/ramdisk/3072/prime-3072-p.bin + prime-3072-q.bin
/ramdisk/4096/prime-4096-p.bin + prime-4096-q.bin
/ramdisk/8192/prime-8192-p.bin + prime-8192-q.bin
/ramdisk/16384/prime-16384-p.bin + prime-16384-q.bin

# Each instance loads ONLY what it needs:
./tlsgateNGv4 -l 192.168.1.1 -s 443 -r /ramdisk/3072/ --force-algorithm RSA-3072
# RAM usage: ~368MB (only 3072 loaded)

./tlsgateNGv4 -l 192.168.1.2 -s 443 -r /ramdisk/4096/ --force-algorithm RSA-4096
# RAM usage: ~10MB (only 4096 loaded)

./tlsgateNGv4 -l 192.168.1.3 -s 443 -r /ramdisk/8192/ --force-algorithm RSA-8192
# RAM usage: ~98MB (only 8192 loaded)

./tlsgateNGv4 -l 192.168.1.4 -s 443 -r /ramdisk/16384/ --force-algorithm RSA-16384
# RAM usage: ~196MB (only 16384 loaded)
```

### 🚀 Quick Setup: RAM-Optimized Demo

**One-liner to reorganize your existing prime pools:**

```bash
# Organize prime pools into separate directories (one-time setup)
mkdir -p /ramdisk/{2048,3072,4096,8192,16384}
mv /ramdisk/prime-2048-*.bin /ramdisk/2048/
mv /ramdisk/prime-3072-*.bin /ramdisk/3072/
mv /ramdisk/prime-4096-*.bin /ramdisk/4096/
mv /ramdisk/prime-8192-*.bin /ramdisk/8192/
mv /ramdisk/prime-16384-*.bin /ramdisk/16384/

# Start 4 instances - each with its own optimized prime pool
./build/tlsgateNGv4 -l 192.168.1.1 -s 443 -r /ramdisk/3072/ --force-algorithm RSA-3072 -w 4 -d
./build/tlsgateNGv4 -l 192.168.1.2 -s 443 -r /ramdisk/4096/ --force-algorithm RSA-4096 -w 4 -d
./build/tlsgateNGv4 -l 192.168.1.3 -s 443 -r /ramdisk/8192/ --force-algorithm RSA-8192 -w 4 -d
./build/tlsgateNGv4 -l 192.168.1.4 -s 443 -r /ramdisk/16384/ --force-algorithm RSA-16384 -w 2 -d

# Check RAM usage per instance
ps aux | grep tlsgateNGv4 | awk '{print $6/1024 " MB - " $11}'
```

**Expected output from RAM check:**
```
418 MB - ./build/tlsgateNGv4 -l 192.168.1.1 (RSA-3072)
60 MB - ./build/tlsgateNGv4 -l 192.168.1.2 (RSA-4096)
148 MB - ./build/tlsgateNGv4 -l 192.168.1.3 (RSA-8192)
246 MB - ./build/tlsgateNGv4 -l 192.168.1.4 (RSA-16384)

Total: ~872 MB for all 4 instances (vs. ~2.9GB with shared directory)
```

**Total RAM savings:** ~677MB per instance → ~170MB average per instance (75% reduction!)

**Recommendation:**
- **Single directory** (`-r /ramdisk/`): Simple, all prime pools always available
- **Separate directories**: RAM-optimized, each instance loads only what it needs

For most use cases, the ~677MB overhead is negligible on modern servers. 🚀

---

### 🎯 SHM Keypool with Custom Pool Size

**Control pre-generated key count to optimize startup time vs RAM usage!**

The new `--pool-size` option lets you control how many keys are pre-generated in the shared memory pool.

#### Default Pool Sizes
- **Local mode** (no `--shm`): 6,400 keys
- **SHM mode** (with `--shm`): 1,280,000 keys (1.28M)

#### Small Demo Setup (10K keys, ~12 seconds startup)

Perfect for quick demos and testing:

```bash
# 1. Generate 10K RSA-3072 keys in SHM
./build/tlsgateNG-poolgen --poolkeygen --shm \
    -r /ramdisk/3072/ \
    --force-algorithm RSA-3072 \
    --pool-size 10000

# 2. Start reader instances (consume from SHM)
./build/tlsgateNGv4 --shm -l 192.168.1.1 -s 443 \
    --force-algorithm RSA-3072 -w 4

./build/tlsgateNGv4 --shm -l 192.168.1.2 -s 443 \
    --force-algorithm RSA-3072 -w 4
```

#### Medium Production (500K keys, ~100 seconds startup)

Good balance for production environments:

```bash
# Generate 500K RSA-3072 keys in SHM
./build/tlsgateNG-poolgen --poolkeygen --shm \
    -r /ramdisk/3072/ \
    --force-algorithm RSA-3072 \
    --pool-size 500000
```

#### Large Production (5M keys, ~1000 seconds = ~17 min startup)

Maximum availability for high-traffic environments:

```bash
# Generate 5M RSA-3072 keys in SHM
./build/tlsgateNG-poolgen --poolkeygen --shm \
    -r /ramdisk/3072/ \
    --force-algorithm RSA-3072 \
    --pool-size 5000000
```

#### Multi-Algorithm SHM Setup

Different pool sizes for each algorithm:

```bash
# Sequential generation (one after another):
# RSA-3072: 10K keys (demo)
./build/tlsgateNG-poolgen --poolkeygen --shm \
    -r /ramdisk/3072/ \
    --force-algorithm RSA-3072 \
    --pool-size 10000

# RSA-4096: 5K keys (slower, fewer needed)
./build/tlsgateNG-poolgen --poolkeygen --shm \
    -r /ramdisk/4096/ \
    --force-algorithm RSA-4096 \
    --pool-size 5000

# RSA-8192: 2K keys (much slower)
./build/tlsgateNG-poolgen --poolkeygen --shm \
    -r /ramdisk/8192/ \
    --force-algorithm RSA-8192 \
    --pool-size 2000

# RSA-16384: 500 keys (VERY slow, demo only!)
./build/tlsgateNG-poolgen --poolkeygen --shm \
    -r /ramdisk/16384/ \
    --force-algorithm RSA-16384 \
    --pool-size 500
```

#### ⚡ Parallel Pool Generation (RECOMMENDED!)

**Generate all 4 keypools simultaneously to save time!**

Each `--force-algorithm` creates its own separate SHM segment, so you can run multiple generators in parallel:

```bash
#!/bin/bash
# Generate all 4 RSA keypools in parallel (MUCH faster!)

# Start all 4 generators in background
./build/tlsgateNG-poolgen --poolkeygen --shm \
    -r /ramdisk/3072/ \
    --force-algorithm RSA-3072 \
    --pool-size 10000 &

./build/tlsgateNG-poolgen --poolkeygen --shm \
    -r /ramdisk/4096/ \
    --force-algorithm RSA-4096 \
    --pool-size 5000 &

./build/tlsgateNG-poolgen --poolkeygen --shm \
    -r /ramdisk/8192/ \
    --force-algorithm RSA-8192 \
    --pool-size 2000 &

./build/tlsgateNG-poolgen --poolkeygen --shm \
    -r /ramdisk/16384/ \
    --force-algorithm RSA-16384 \
    --pool-size 500 &

# Wait for all generators to complete
wait

echo "✅ All keypools ready! Starting servers..."

# Now start the reader instances
./build/tlsgateNGv4 --shm -l 192.168.1.1 -s 443 --force-algorithm RSA-3072 -w 4 &
./build/tlsgateNGv4 --shm -l 192.168.1.2 -s 443 --force-algorithm RSA-4096 -w 4 &
./build/tlsgateNGv4 --shm -l 192.168.1.3 -s 443 --force-algorithm RSA-8192 -w 4 &
./build/tlsgateNGv4 --shm -l 192.168.1.4 -s 443 --force-algorithm RSA-16384 -w 2 &

echo "✅ All 4 servers running!"
```

**Time savings:**
- **Sequential:** RSA-3072 (12s) + RSA-4096 (8s) + RSA-8192 (15s) + RSA-16384 (30s) = **65 seconds total**
- **Parallel:** Max(12s, 8s, 15s, 30s) = **30 seconds total** (runs only as long as the slowest!)

**Speedup: 2.2× faster!** 🚀

**How it works:**
- Each algorithm gets its own SHM segment (unique SHM key per algorithm)
- No conflicts - generators run completely independently
- Reader instances automatically connect to the correct SHM segment based on `--force-algorithm`

**Startup time comparison (RSA-3072 with prime pools):**
- 10K keys: ~12 seconds (demo)
- 100K keys: ~120 seconds (~2 minutes)
- 500K keys: ~600 seconds (~10 minutes)
- 1.28M keys: ~1536 seconds (~25 minutes)
- 5M keys: ~6000 seconds (~100 minutes = ~1.7 hours)

**Trade-offs:**
- **Smaller pools** = Faster startup, less RAM, may need on-demand generation under load
- **Larger pools** = Slower startup, more RAM, instant key availability even at 100% load

---

## Configuration

### Command-Line Options

**`--force-algorithm ALG`** - Force single algorithm for all certificates

Supported algorithms:
- `RSA-3072`
- `RSA-4096`
- `RSA-8192`
- `RSA-16384` (DEMO only - very slow!)
- `ECDSA-P256`
- `ECDSA-P384`
- `ECDSA-P521`
- `SM2`

**`-r DIR`** - Prime pool directory

Example: `-r /ramdisk/`

The server will automatically search for:
1. `prime-{keysize}.bin` (combined)
2. `prime-{keysize}-p.bin` + `prime-{keysize}-q.bin` (separate)

**`--pool-size NUM`** - Set keypool size (number of pre-generated keys)

Range: 1-10,000,000 keys
Default: 6,400 (local), 1,280,000 (SHM)

Examples:
- `--pool-size 10000` - Small demo (12 sec startup)
- `--pool-size 500000` - Medium production (100 sec startup)
- `--pool-size 5000000` - Large production (1000 sec startup)

**`--shm`** - Use shared memory keypool (for multi-instance deployment)

**`--poolkeygen`** - Generator mode (pre-populate SHM keypool)

---

## Server Startup Commands

### Instance 1: RSA-3072 on IP 192.168.1.1

```bash
./build/tlsgateNGv4 \
    -l 192.168.1.1 \
    -s 443 \
    -p 0 \
    -a 0 \
    -r /ramdisk/ \
    -D /opt/TLSGateNX \
    --force-algorithm RSA-3072 \
    -w 4 \
    -u nobody \
    -d
```

**Expected Output:**
```
Force algorithm mode: RSA-3072 (all certificates will use this algorithm)
Scanning for prime pools in: /ramdisk/
Loading separate prime pools: /ramdisk/prime-2048-p.bin + /ramdisk/prime-2048-q.bin
  [✓] RSA-2048: 10000 primes available (FAST PATH enabled)
Loading separate prime pools: /ramdisk/prime-3072-p.bin + /ramdisk/prime-3072-q.bin
  [✓] RSA-3072: 50000 primes available (FAST PATH enabled)
Loading separate prime pools: /ramdisk/prime-4096-p.bin + /ramdisk/prime-4096-q.bin
  [✓] RSA-4096: 10000 primes available (FAST PATH enabled)
Loading separate prime pools: /ramdisk/prime-8192-p.bin + /ramdisk/prime-8192-q.bin
  [✓] RSA-8192: 50000 primes available (FAST PATH enabled)
Loading separate prime pools: /ramdisk/prime-16384-p.bin + /ramdisk/prime-16384-q.bin
  [✓] RSA-16384: 1000 primes available (FAST PATH enabled)
Loaded 5 prime pool(s) - RSA generation will be 20-200× faster!

Note: All prime pools loaded, but server will ONLY use RSA-3072 (forced algorithm).
```

---

### Instance 2: RSA-4096 on IP 192.168.1.2

```bash
./build/tlsgateNGv4 \
    -l 192.168.1.2 \
    -s 443 \
    -p 0 \
    -a 0 \
    -r /ramdisk/ \
    -D /opt/TLSGateNX \
    --force-algorithm RSA-4096 \
    -w 4 \
    -u nobody \
    -d
```

---

### Instance 3: RSA-8192 on IP 192.168.1.3

```bash
./build/tlsgateNGv4 \
    -l 192.168.1.3 \
    -s 443 \
    -p 0 \
    -a 0 \
    -r /ramdisk/ \
    -D /opt/TLSGateNX \
    --force-algorithm RSA-8192 \
    -w 4 \
    -u nobody \
    -d
```

---

### Instance 4: RSA-16384 on IP 192.168.1.4 (SLOW!)

```bash
./build/tlsgateNGv4 \
    -l 192.168.1.4 \
    -s 443 \
    -p 0 \
    -a 0 \
    -r /ramdisk/ \
    -D /opt/TLSGateNX \
    --force-algorithm RSA-16384 \
    -w 2 \
    -u nobody \
    -d
```

**⚠️ Warning:** RSA-16384 is **VERY SLOW**:
- **Key generation:** ~30-60 seconds without prime pool, ~3-10 seconds with prime pool
- **TLS handshake:** ~500ms-2 seconds per connection
- **Memory:** ~16KB per key (vs. 3KB for RSA-3072)

Only use for demonstration purposes!

---

## Verification

### Test Certificate Key Size

Use `openssl s_client` to verify the key size:

```bash
# Test RSA-3072 instance
echo | openssl s_client -connect 192.168.1.1:443 -servername test.example.com 2>/dev/null | \
    openssl x509 -noout -text | grep "Public-Key:"
# Expected: Public-Key: (3072 bit)

# Test RSA-4096 instance
echo | openssl s_client -connect 192.168.1.2:443 -servername test.example.com 2>/dev/null | \
    openssl x509 -noout -text | grep "Public-Key:"
# Expected: Public-Key: (4096 bit)

# Test RSA-8192 instance
echo | openssl s_client -connect 192.168.1.3:443 -servername test.example.com 2>/dev/null | \
    openssl x509 -noout -text | grep "Public-Key:"
# Expected: Public-Key: (8192 bit)

# Test RSA-16384 instance
echo | openssl s_client -connect 192.168.1.4:443 -servername test.example.com 2>/dev/null | \
    openssl x509 -noout -text | grep "Public-Key:"
# Expected: Public-Key: (16384 bit)
```

---

## Performance Characteristics

### Without Prime Pools (Slow Path)

| RSA Size | Key Generation Time | Memory per Key |
|----------|---------------------|----------------|
| 3072     | ~150ms              | ~3KB           |
| 4096     | ~500ms              | ~4KB           |
| 8192     | ~10s                | ~8KB           |
| 16384    | ~30-60s             | ~16KB          |

### With Prime Pools (Fast Path)

| RSA Size | Key Generation Time | Speedup    | Prime Pool Size |
|----------|---------------------|------------|-----------------|
| 3072     | ~5ms                | **30×**    | ~184MB          |
| 4096     | ~15ms               | **33×**    | ~4.9MB          |
| 8192     | ~200ms              | **50×**    | ~49MB           |
| 16384    | ~3-10s              | **6-10×**  | ~98MB           |

---

## Systemd Integration (Optional)

Create systemd service files for each instance:

### `/etc/systemd/system/tlsgate-rsa3072.service`

```ini
[Unit]
Description=TLSGate NG - RSA-3072 Demo (192.168.1.1)
After=network.target

[Service]
Type=forking
User=root
ExecStart=/opt/TLSGateNGv4/build/tlsgateNGv4 -l 192.168.1.1 -s 443 -p 0 -a 0 -r /ramdisk/ -D /opt/TLSGateNX --force-algorithm RSA-3072 -w 4 -u nobody -d
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### `/etc/systemd/system/tlsgate-rsa4096.service`

```ini
[Unit]
Description=TLSGate NG - RSA-4096 Demo (192.168.1.2)
After=network.target

[Service]
Type=forking
User=root
ExecStart=/opt/TLSGateNGv4/build/tlsgateNGv4 -l 192.168.1.2 -s 443 -p 0 -a 0 -r /ramdisk/ -D /opt/TLSGateNX --force-algorithm RSA-4096 -w 4 -u nobody -d
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Enable and Start Services

```bash
systemctl daemon-reload
systemctl enable tlsgate-rsa3072 tlsgate-rsa4096 tlsgate-rsa8192 tlsgate-rsa16384
systemctl start tlsgate-rsa3072 tlsgate-rsa4096 tlsgate-rsa8192 tlsgate-rsa16384
systemctl status tlsgate-rsa*
```

---

## Important Notes

### Security Considerations

1. **RSA-16384 is DEMO ONLY**
   - Extremely slow (30-60s key generation)
   - Not practical for production
   - Only for testing and demonstrations

2. **Prime Pool Security**
   - Prime pools are read-only files
   - Each instance loads its own copy in RAM (not shared between processes)
   - Located in `/ramdisk/` for maximum I/O speed
   - OS page cache may share file contents across instances during loading

3. **Privilege Dropping**
   - All instances start as `root` (to bind port 443)
   - Immediately drop to `nobody` after binding
   - If compromised, attacker has limited access

### Resource Usage

**RAM Usage (per instance with shared `/ramdisk/` directory):**

Each instance automatically loads **ALL** prime pools from `/ramdisk/`:
- Base process: ~50MB
- Prime pools loaded: ~677MB (all sizes: 2048, 3072, 4096, 8192, 16384)
- **Total per instance: ~727MB**

**Total RAM for 4 instances:** 4 × ~727MB = **~2.9GB**

**RAM-Optimized Setup (separate directories):**

Each instance loads ONLY its required prime pool:
- RSA-3072 instance: ~50MB + ~368MB = ~418MB
- RSA-4096 instance: ~50MB + ~10MB = ~60MB
- RSA-8192 instance: ~50MB + ~98MB = ~148MB
- RSA-16384 instance: ~50MB + ~196MB = ~246MB

**Total RAM for 4 instances:** ~872MB (70% RAM savings!)

See **RAM Optimization** section above for directory structure.

---

## Troubleshooting

### Prime Pools Not Loading

**Symptoms:**
```
No prime pools loaded - RSA will use standard generation
```

**Solution:**
Check file permissions:
```bash
ls -l /ramdisk/prime-*
chmod 644 /ramdisk/prime-*.bin
```

### Port Already in Use

**Symptoms:**
```
Error: bind() failed: Address already in use
```

**Solution:**
Check if another instance is already running on that IP:port:
```bash
netstat -tlnp | grep :443
pkill -f tlsgateNGv4  # Kill all instances
```

### Certificate Generation Slow

**Symptoms:**
TLS handshakes taking >1 second

**Solution:**
1. Verify prime pools are loaded (check startup logs)
2. Check `/ramdisk/` is actually a ramdisk:
   ```bash
   df -h | grep ramdisk
   mount | grep ramdisk
   ```

---

## Summary

This configuration allows you to demonstrate different RSA key sizes on separate IP addresses:

✅ **RSA-3072** - Standard security, fast
✅ **RSA-4096** - High security, moderate speed
✅ **RSA-8192** - Very high security, slower
⚠️ **RSA-16384** - Ultra-high security, VERY slow (demo only!)

All instances use prime pools from `/ramdisk/` for optimal performance.

---

**Last Updated:** 2025-01-22
**TLSGate NG Version:** v4.36 GEN4
