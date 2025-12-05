# TLSGate NX v3 - Multi-Instance Production Setup

## Szenario: 2 Server mit mehreren Instanzen

**Server 1:** 20 Instanzen (4 Worker je)
**Server 2:** 6 Instanzen (4 Worker je)

Alle Instanzen teilen sich einen **Shared Memory Keypool** pro Server.

---

## Architektur

```
┌─────────────────────────────────────────────────────────────┐
│                       SERVER 1                              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────┐                   │
│  │  Keypool Generator (1× pro Server)  │                   │
│  │  - Füllt Shared Memory mit Keys     │                   │
│  │  - Läuft dauerhaft im Hintergrund   │                   │
│  └─────────────────────────────────────┘                   │
│                       ↓ SHM                                 │
│  ┌───────────────────────────────────────────────────────┐ │
│  │  20 Reader Instances (je 4 Worker)                    │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐             │ │
│  │  │Instance 1│ │Instance 2│ │Instance 3│ ... [20]    │ │
│  │  │Port 443  │ │Port 8443 │ │Port 9443 │             │ │
│  │  │4 Workers │ │4 Workers │ │4 Workers │             │ │
│  │  └──────────┘ └──────────┘ └──────────┘             │ │
│  └───────────────────────────────────────────────────────┘ │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                       SERVER 2                              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────┐                   │
│  │  Keypool Generator (1× pro Server)  │                   │
│  └─────────────────────────────────────┘                   │
│                       ↓ SHM                                 │
│  ┌───────────────────────────────────────────────────────┐ │
│  │  6 Reader Instances (je 4 Worker)                     │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐             │ │
│  │  │Instance 1│ │Instance 2│ │Instance 3│ ... [6]     │ │
│  │  │Port 443  │ │Port 8443 │ │Port 9443 │             │ │
│  │  └──────────┘ └──────────┘ └──────────┘             │ │
│  └───────────────────────────────────────────────────────┘ │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 1. Verzeichnisstruktur (Pro Server)

```bash
sudo mkdir -p /opt/tlsgateNG/{rootCA,bundles,cache,primes,logs}

# CA-Zertifikat (einmalig pro Server)
sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout /opt/tlsgateNG/rootCA/ca-key.pem \
    -out /opt/tlsgateNG/rootCA/ca.crt \
    -days 3650 -nodes \
    -subj '/CN=TLSGate Root CA/O=Production/C=DE'

sudo chmod 600 /opt/tlsgateNG/rootCA/ca-key.pem
sudo chmod 644 /opt/tlsgateNG/rootCA/ca.crt

# Separate Cache-Verzeichnisse für jede Instanz
for i in {1..20}; do
    sudo mkdir -p /opt/tlsgateNG/cache/instance$i
done

# User erstellen
sudo useradd -r -s /bin/false -d /opt/tlsgateNG tlsgate
sudo chown -R tlsgateNG:tlsgateNG /opt/tlsgateNG
```

---

## 2. Keypool Generator (1× pro Server)

**Start als Service:**

**Datei:** `/etc/systemd/system/tlsgateNG-poolgen.service`

```ini
[Unit]
Description=TLSGate NX - Shared Memory Keypool Generator
After=network.target
Before=tlsgateNG-instance@.service

[Service]
Type=simple
User=tlsgateNG
Group=tlsgateNG
ExecStart=/opt/tlsgateNG/build/tlsgateNG \
    --poolkeygen \
    --shm \
    -b /opt/tlsgateNG/bundles \
    -r /opt/tlsgateNG/primes \
    -w 2

Restart=always
RestartSec=5
LimitNOFILE=100000

# Shared Memory bleibt nach Exit bestehen
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

**Aktivieren:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable tlsgateNG-poolgen
sudo systemctl start tlsgateNG-poolgen
sudo systemctl status tlsgateNG-poolgen
```

---

## 3. Reader Instances (20× auf Server 1, 6× auf Server 2)

### Instanz-Template Service

**Datei:** `/etc/systemd/system/tlsgateNG-instance@.service`

```ini
[Unit]
Description=TLSGate NX - Instance %i
After=network.target tlsgateNG-poolgen.service
Requires=tlsgateNG-poolgen.service

[Service]
Type=simple
User=tlsgateNG
Group=tlsgateNG

# %i = Instance Number (z.B. 1, 2, 3, ...)
ExecStart=/opt/tlsgateNG/build/tlsgateNG \
    --shm \
    -p 80 \
    -s 443 \
    -a 8080 \
    -D /opt/tlsgateNG \
    -C /opt/tlsgateNG/cache/instance%i \
    -w 4 \
    -m 5000 \
    -l 0.0.0.0

# Security Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/tlsgateNG/cache/instance%i

# Port Binding ohne Root
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Restart Policy
Restart=always
RestartSec=5

# Limits
LimitNOFILE=100000

[Install]
WantedBy=multi-user.target
```

---

## 4. Optimale Parameter pro Instanz

### Basis-Konfiguration (Alle Instanzen)

```bash
/opt/tlsgateNG/build/tlsgateNG \
    --shm \                          # Shared Memory Keypool nutzen
    -D /opt/tlsgateNG \              # CA-Verzeichnis
    -C /opt/tlsgateNG/cache/instanceN \  # Eigener Cache
    -w 4 \                           # 4 Worker Threads
    -m 5000 \                        # Max 5000 Connections pro Instanz
    -l 0.0.0.0                       # Auf allen IPs lauschen
```

### Port-Konfiguration

**Variante A: Alle Instanzen auf Standard-Ports (mit SO_REUSEPORT)**
```bash
# Alle Instanzen auf Port 80 + 443
-p 80 -s 443 -a 8080
```

**Variante B: Separate Ports pro Instanz**
```bash
# Instance 1:  Ports 443, 8443
# Instance 2:  Ports 9443, 10443
# Instance 3:  Ports 11443, 12443
# ... usw.
```

**Empfehlung:** Variante A mit `SO_REUSEPORT` - Kernel verteilt Connections automatisch!

---

## 5. Start Scripts

### Server 1: 20 Instanzen starten

**Datei:** `/usr/local/bin/tlsgateNG-start-all-server1.sh`

```bash
#!/bin/bash

echo "Starting TLSGate NX - Server 1 (20 Instances)"
echo "=============================================="

# 1. Keypool Generator starten
echo "Starting Keypool Generator..."
sudo systemctl start tlsgateNG-poolgen
sleep 3

# 2. Alle 20 Instanzen starten
for i in {1..20}; do
    echo "Starting Instance $i/20..."
    sudo systemctl start tlsgateNG-instance@$i
    sleep 0.5
done

echo ""
echo "✅ All instances started!"
echo ""
echo "Status:"
sudo systemctl status tlsgateNG-poolgen --no-pager
echo ""
for i in {1..20}; do
    STATUS=$(sudo systemctl is-active tlsgateNG-instance@$i)
    if [ "$STATUS" = "active" ]; then
        echo "  ✓ Instance $i: $STATUS"
    else
        echo "  ✗ Instance $i: $STATUS"
    fi
done
```

### Server 2: 6 Instanzen starten

**Datei:** `/usr/local/bin/tlsgateNG-start-all-server2.sh`

```bash
#!/bin/bash

echo "Starting TLSGate NX - Server 2 (6 Instances)"
echo "============================================="

# 1. Keypool Generator starten
echo "Starting Keypool Generator..."
sudo systemctl start tlsgateNG-poolgen
sleep 3

# 2. Alle 6 Instanzen starten
for i in {1..6}; do
    echo "Starting Instance $i/6..."
    sudo systemctl start tlsgateNG-instance@$i
    sleep 0.5
done

echo ""
echo "✅ All instances started!"
echo ""
echo "Status:"
sudo systemctl status tlsgateNG-poolgen --no-pager
echo ""
for i in {1..6}; do
    STATUS=$(sudo systemctl is-active tlsgateNG-instance@$i)
    if [ "$STATUS" = "active" ]; then
        echo "  ✓ Instance $i: $STATUS"
    else
        echo "  ✗ Instance $i: $STATUS"
    fi
done
```

**Executable machen:**
```bash
sudo chmod +x /usr/local/bin/tlsgateNG-start-all-server*.sh
```

---

## 6. Manuelle Instanz-Starts (für Testing)

### Server 1 - Instance 1 (manuell)

```bash
sudo -u tlsgateNG /opt/tlsgateNG/build/tlsgateNG \
    --shm \
    -p 80 \
    -s 443 \
    -a 8080 \
    -D /opt/tlsgateNG \
    -C /opt/tlsgateNG/cache/instance1 \
    -w 4 \
    -m 5000 \
    -l 0.0.0.0 \
    -v > /opt/tlsgateNG/logs/instance1.log 2>&1 &
```

### Server 1 - Instance 2

```bash
sudo -u tlsgateNG /opt/tlsgateNG/build/tlsgateNG \
    --shm \
    -p 80 \
    -s 443 \
    -a 8080 \
    -D /opt/tlsgateNG \
    -C /opt/tlsgateNG/cache/instance2 \
    -w 4 \
    -m 5000 \
    -l 0.0.0.0 \
    > /opt/tlsgateNG/logs/instance2.log 2>&1 &
```

**... (20× für Server 1, 6× für Server 2)**

---

## 7. Kernel Tuning (CRITICAL für Multi-Instance!)

**Datei:** `/etc/sysctl.d/99-tlsgateNG-multi.conf`

```ini
# TCP Stack für 20 Instanzen (100K connections total)
net.ipv4.tcp_max_syn_backlog = 65536
net.core.somaxconn = 65536
net.core.netdev_max_backlog = 65536

# File Descriptors (20 Instanzen × 5000 connections)
fs.file-max = 5000000

# Shared Memory (für Keypool + Cert Cache)
kernel.shmmax = 2147483648
kernel.shmall = 2097152

# TCP Performance
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0

# Connection Tracking
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_timeout_established = 600

# io_uring
vm.max_map_count = 524288
```

**Aktivieren:**
```bash
sudo sysctl -p /etc/sysctl.d/99-tlsgateNG-multi.conf
```

**User Limits:** `/etc/security/limits.conf`
```
tlsgateNG soft nofile 1000000
tlsgateNG hard nofile 1000000
tlsgateNG soft nproc 8192
tlsgateNG hard nproc 8192
```

---

## 8. Monitoring & Management

### Status aller Instanzen prüfen

```bash
# Server 1 (20 Instanzen)
for i in {1..20}; do
    sudo systemctl status tlsgateNG-instance@$i | grep Active
done

# Server 2 (6 Instanzen)
for i in {1..6}; do
    sudo systemctl status tlsgateNG-instance@$i | grep Active
done
```

### Logs ansehen

```bash
# Keypool Generator
sudo journalctl -u tlsgateNG-poolgen -f

# Instanz 1
sudo journalctl -u tlsgateNG-instance@1 -f

# Alle Instanzen
sudo journalctl -u 'tlsgateNG-instance@*' -f
```

### Statistiken (per USR1 Signal)

```bash
# Stats für Instanz 1
sudo pkill -USR1 -f "cache/instance1"

# Stats für alle
for i in {1..20}; do
    sudo pkill -USR1 -f "cache/instance$i"
done
```

---

## 9. Load Balancing (Optional)

### HAProxy Frontend

**Datei:** `/etc/haproxy/haproxy.cfg`

```cfg
global
    maxconn 500000
    nbthread 8

defaults
    mode http
    timeout connect 5s
    timeout client 30s
    timeout server 30s

# HTTP
frontend http_front
    bind *:80
    default_backend tlsgateNG_http

backend tlsgateNG_http
    balance leastconn
    server instance1 127.0.0.1:80 check
    server instance2 127.0.0.1:80 check
    # ... alle 20 Instanzen

# HTTPS
frontend https_front
    bind *:443 ssl crt /opt/tlsgateNG/rootCA/combined.pem
    default_backend tlsgateNG_https

backend tlsgateNG_https
    balance leastconn
    server instance1 127.0.0.1:443 check
    server instance2 127.0.0.1:443 check
    # ... alle 20 Instanzen
```

**ABER:** Mit `SO_REUSEPORT` ist HAProxy NICHT nötig - Kernel macht LB!

---

## 10. Performance-Optimierung

### CPU Affinity setzen

```bash
# Instance 1 auf CPU 0-3
taskset -c 0-3 /opt/tlsgateNG/build/tlsgateNG ...

# Instance 2 auf CPU 4-7
taskset -c 4-7 /opt/tlsgateNG/build/tlsgateNG ...

# ... usw.
```

### Huge Pages (für Shared Memory)

```bash
# /etc/sysctl.d/99-hugepages.conf
vm.nr_hugepages = 1024

# Aktivieren
sudo sysctl -p
```

---

## 11. Testing

### Funktionstest

```bash
# HTTP
curl -v http://localhost/

# HTTPS
curl -v -k https://localhost/

# AUTO Port
curl -v http://localhost:8080/
curl -v -k https://localhost:8080/
```

### Load Test (alle Instanzen)

```bash
# Server 1: 20 Instanzen × 5000 connections = 100K total
ab -n 1000000 -c 10000 https://localhost/

# Server 2: 6 Instanzen × 5000 connections = 30K total
ab -n 300000 -c 3000 https://localhost/
```

---

## 12. Kapazitätsplanung

### Server 1 (20 Instanzen)

| Parameter | Wert |
|-----------|------|
| Instanzen | 20 |
| Worker/Instanz | 4 |
| Max Conn/Instanz | 5,000 |
| **Total Capacity** | **100,000 connections** |
| Throughput | ~500K req/s (io_uring) |

### Server 2 (6 Instanzen)

| Parameter | Wert |
|-----------|------|
| Instanzen | 6 |
| Worker/Instanz | 4 |
| Max Conn/Instanz | 5,000 |
| **Total Capacity** | **30,000 connections** |
| Throughput | ~150K req/s (io_uring) |

---

## Quick Reference

```bash
# Server 1: Alle starten
/usr/local/bin/tlsgateNG-start-all-server1.sh

# Server 2: Alle starten
/usr/local/bin/tlsgateNG-start-all-server2.sh

# Status
sudo systemctl status tlsgateNG-poolgen
for i in {1..20}; do systemctl status tlsgateNG-instance@$i; done

# Logs
sudo journalctl -u 'tlsgate-*' -f

# Stoppen
sudo systemctl stop 'tlsgateNG-instance@*'
sudo systemctl stop tlsgateNG-poolgen
```

---

**Fertig!** 🚀

Dein Multi-Instance Setup ist production-ready für 100K+ connections!
