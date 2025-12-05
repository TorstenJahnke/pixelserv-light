# TLSGate NX v3 - Debian Build Guide

## Schnellstart (Copy & Paste)

```bash
# 1. Dependencies installieren
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev zlib1g-dev liburing-dev pkg-config git

# 2. Repository klonen (falls noch nicht vorhanden)
cd /opt
sudo git clone https://github.com/TorstenJahnke/TLSGateNXv3.git
cd TLSGateNXv3

# 3. Build
make clean && make

# 4. Testen
./build/tlsgateNG --version
```

---

## Vollständige Anleitung

### 1. System-Requirements

**Minimum:**
- Debian 10+ / Ubuntu 20.04+
- Kernel 5.1+ (für io_uring Support - empfohlen!)
- 2 GB RAM
- GCC 7+

**Empfohlen für Production:**
- Debian 12 / Ubuntu 22.04+
- Kernel 5.15+
- 8+ GB RAM
- GCC 11+

**Kernel-Version prüfen:**
```bash
uname -r
# Sollte >= 5.1 sein für io_uring
```

---

### 2. Dependencies installieren

#### Basis-Dependencies (ERFORDERLICH)

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    libssl-dev \
    zlib1g-dev \
    pkg-config \
    git
```

#### io_uring Support (STARK EMPFOHLEN)

**Für 200K+ Connections pro Prozess:**
```bash
sudo apt-get install -y liburing-dev
```

**Status prüfen:**
```bash
pkg-config --modversion liburing
# Sollte z.B. "2.3" oder höher zeigen
```

#### Optional: Development Tools

```bash
# Für Debugging und Profiling
sudo apt-get install -y \
    valgrind \
    gdb \
    strace \
    htop \
    iotop
```

---

### 3. Build-Varianten

#### Standard Build (Production)

```bash
make clean
make
```

**Erzeugt:** `build/tlsgateNG`
- Optimiert (`-O2`)
- io_uring support (falls liburing vorhanden)
- Alle Warnungen aktiviert
- Production-ready

#### Backend-Status prüfen

```bash
make check-iouring
```

**Ausgabe bei io_uring:**
```
Current backend: io_uring
✅ io_uring is available and enabled
   liburing version: 2.3
   Kernel version: 5.15.0-91-generic
```

**Ausgabe OHNE io_uring:**
```
Current backend: epoll
⚠️  WARNING: For 200K+ connections, io_uring is ESSENTIAL!
```

---

### 4. Build-Optionen (Makefile Targets)

#### a) Debug Build mit AddressSanitizer

**Findet:** Memory Leaks, Buffer Overflows, Use-After-Free
```bash
make address
```

**Ausführen:**
```bash
ASAN_OPTIONS=detect_leaks=1 ./build/tlsgateNG -p 8080 -D /opt/tlsgateNG
```

#### b) ThreadSanitizer (Race Conditions)

**Findet:** Data Races, Deadlocks
```bash
make thread
```

**Ausführen:**
```bash
TSAN_OPTIONS=second_deadlock_stack=1 ./build/tlsgateNG -p 8080 -D /opt/tlsgateNG
```

#### c) Security Hardening Build

**Features:**
- Stack Protector
- FORTIFY_SOURCE
- RELRO + NOW Binding
- Format String Protection

```bash
make secure
```

#### d) Full Check (Alle Sanitizer)

**Läuft nacheinander:**
1. AddressSanitizer
2. ThreadSanitizer
3. UndefinedBehaviorSanitizer
4. Security Build
5. Valgrind Memcheck

```bash
make fullcheck
```

---

### 5. Optimierte Production Build

#### Für maximale Performance:

```bash
# io_uring sicherstellen
sudo apt-get install -y liburing-dev

# Build mit allen Optimierungen
make clean
CFLAGS="-O3 -march=native -flto" make

# Optional: Strip Debug Symbols (kleinere Binary)
strip build/tlsgateNG

# Size prüfen
ls -lh build/tlsgateNG
```

**Ergebnis:** ~500KB Binary (ohne debug symbols)

---

### 6. Multi-Instance Setup (Production)

#### a) CA Verzeichnis erstellen

```bash
sudo mkdir -p /opt/tlsgateNG/rootCA
sudo mkdir -p /opt/tlsgateNG/cache
sudo mkdir -p /opt/tlsgateNG/bundles

# CA-Zertifikat erstellen (einmalig)
sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout /opt/tlsgateNG/rootCA/ca-key.pem \
    -out /opt/tlsgateNG/rootCA/ca.crt \
    -days 3650 -nodes \
    -subj '/CN=TLSGate Root CA/O=YourOrg/C=DE'

sudo chmod 600 /opt/tlsgateNG/rootCA/ca-key.pem
sudo chmod 644 /opt/tlsgateNG/rootCA/ca.crt
```

#### b) Systemd Service erstellen

**Datei:** `/etc/systemd/system/tlsgateNG.service`

```ini
[Unit]
Description=TLSGate NX v3 - Ad-Blocking HTTPS Proxy
After=network.target

[Service]
Type=simple
User=tlsgateNG
Group=tlsgateNG
ExecStart=/opt/tlsgateNG/build/tlsgateNG \
    -p 80 \
    -s 443 \
    -a 8080 \
    -D /opt/tlsgateNG \
    -w 8 \
    -m 10000

# Security Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/tlsgateNG/cache

# Capabilities (für Port 80/443 ohne root)
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Restart Policy
Restart=always
RestartSec=5

# Limits
LimitNOFILE=500000

[Install]
WantedBy=multi-user.target
```

**User erstellen:**
```bash
sudo useradd -r -s /bin/false tlsgateNG
sudo chown -R tlsgateNG:tlsgateNG /opt/tlsgateNG
```

**Service aktivieren:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable tlsgateNG
sudo systemctl start tlsgateNG
sudo systemctl status tlsgateNG
```

---

### 7. Kernel Tuning (für hohe Last)

**Datei:** `/etc/sysctl.d/99-tlsgateNG.conf`

```ini
# TCP Stack Tuning
net.ipv4.tcp_max_syn_backlog = 8192
net.core.somaxconn = 8192
net.core.netdev_max_backlog = 8192

# Connection Tracking
net.netfilter.nf_conntrack_max = 1000000
net.netfilter.nf_conntrack_tcp_timeout_established = 600

# File Descriptors
fs.file-max = 2000000

# io_uring Memory
vm.max_map_count = 262144

# TCP Performance
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fastopen = 3
```

**Aktivieren:**
```bash
sudo sysctl -p /etc/sysctl.d/99-tlsgateNG.conf
```

**User Limits:** `/etc/security/limits.conf`
```
tlsgateNG soft nofile 500000
tlsgateNG hard nofile 500000
```

---

### 8. Verifikation & Testing

#### Build Verifikation
```bash
# Version prüfen
./build/tlsgateNG --version

# Backend prüfen
make backend-info

# Dependencies prüfen
ldd build/tlsgateNG
```

#### Funktionstest
```bash
# Test-Server starten
./build/tlsgateNG -p 8080 -s 8443 -D /opt/tlsgateNG -w 4 &

# HTTP Test
curl -v http://localhost:8080/

# HTTPS Test
curl -v -k https://localhost:8443/

# Server stoppen
pkill tlsgateNG
```

#### Load Test (optional)
```bash
# Apache Bench installieren
sudo apt-get install -y apache2-utils

# HTTP Load Test
ab -n 10000 -c 100 http://localhost:8080/

# HTTPS Load Test
ab -n 10000 -c 100 -k https://localhost:8443/
```

---

### 9. Troubleshooting

#### Problem: "io_uring not available"
```bash
# Kernel-Version prüfen
uname -r
# Sollte >= 5.1 sein

# liburing installieren
sudo apt-get install -y liburing-dev

# Rebuild
make clean && make

# Verify
make check-iouring
```

#### Problem: "Cannot bind to port 80"
```bash
# Option 1: Mit sudo starten
sudo ./build/tlsgateNG -p 80 -s 443 -D /opt/tlsgateNG

# Option 2: Capabilities setzen
sudo setcap 'cap_net_bind_service=+ep' /opt/tlsgateNG/build/tlsgateNG

# Option 3: Systemd Service (siehe oben)
```

#### Problem: "Too many open files"
```bash
# Aktuelles Limit prüfen
ulimit -n

# Temporär erhöhen
ulimit -n 100000

# Permanent: /etc/security/limits.conf editieren
```

#### Problem: Compilation Errors
```bash
# Dependencies neu installieren
sudo apt-get update
sudo apt-get install --reinstall build-essential libssl-dev zlib1g-dev

# Clean build
make clean
rm -rf build/
make
```

---

### 10. Performance Benchmarks

**Getestet auf:**
- Debian 12, Kernel 6.1
- Intel Xeon E5-2680 v4 @ 2.4 GHz (8 Cores)
- 16 GB RAM

**Ergebnisse:**

| Config | Backend | Workers | Throughput | Latency (p99) |
|--------|---------|---------|------------|---------------|
| Standard | epoll | 4 | 50,000 req/s | 2ms |
| io_uring | io_uring | 8 | 500,000 req/s | <1ms |
| io_uring | io_uring | 16 | 800,000 req/s | <1ms |

**3-Port Architektur Tests:**
- Port 80 (HTTP): ✓ 100% success (2000 req)
- Port 443 (HTTPS): ✓ 100% success (2000 req)
- Port 8080 (AUTO): ✓ 100% success (2000 req HTTP + HTTPS)

---

### 11. Weiterführende Dokumentation

- **Architecture:** `docs/ARCHITECTURE.md`
- **SSL Detection:** `docs/SSL_DETECTION_ANALYSIS.md`
- **Security:** `docs/SECURITY_REQUIREMENTS.md`
- **Configuration:** `examples/tlsgateNG.conf.example`

---

## Quick Reference

```bash
# Build Kommandos
make                    # Standard production build
make clean              # Clean
make secure             # Security hardening
make check-iouring      # Check io_uring status
make help               # Alle Targets zeigen

# Ausführung
./build/tlsgateNG -p 80 -s 443 -a 8080 -D /opt/tlsgateNG -w 8

# Systemd
sudo systemctl start tlsgateNG
sudo systemctl status tlsgateNG
sudo journalctl -u tlsgateNG -f

# Statistiken
kill -USR1 $(pidof tlsgateNG)    # Worker stats anzeigen
```

---

**Fertig!** 🚀

TLSGate NX v3 ist jetzt bereit für Production auf Debian/Ubuntu!
