# TLSGate NX v3 - Single Server Multi-Instance Setup

## Szenario: 1 physikalischer Server, 26 Instanzen

**Setup:**
- **Gruppe 1:** 20 Instanzen (z.B. IP 1, VLAN 1)
- **Gruppe 2:** 6 Instanzen (z.B. IP 2, VLAN 2)
- **Alle teilen:** 1× Shared Memory Keypool
- **Pro Instanz:** 4 Worker Threads

**Total Capacity:** 26 × 5000 = **130,000 simultane Connections**

---

## Architektur (1 Server)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    PHYSIKALISCHER SERVER                            │
│                                                                     │
│  ┌──────────────────────────────────────────┐                      │
│  │   Keypool Generator (1×)                 │                      │
│  │   - Füllt SHM mit Pre-Generated Keys     │                      │
│  │   - Shared von ALLEN 26 Instanzen        │                      │
│  └──────────────────────────────────────────┘                      │
│                         ↓                                           │
│                   Shared Memory                                     │
│                         ↓                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Gruppe 1: 20 Instanzen (IP 192.168.1.10)                   │   │
│  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐                       │   │
│  │  │Inst 1│ │Inst 2│ │Inst 3│ │ ...  │ [20 total]            │   │
│  │  │Port  │ │Port  │ │Port  │ │Port  │                       │   │
│  │  │80/443│ │80/443│ │80/443│ │80/443│                       │   │
│  │  │4 Work│ │4 Work│ │4 Work│ │4 Work│                       │   │
│  │  └──────┘ └──────┘ └──────┘ └──────┘                       │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Gruppe 2: 6 Instanzen (IP 192.168.2.10)                    │   │
│  │  ┌──────┐ ┌──────┐ ┌──────┐                                │   │
│  │  │Inst21│ │Inst22│ │Inst23│ [24-26]                        │   │
│  │  │Port  │ │Port  │ │Port  │                                │   │
│  │  │80/443│ │80/443│ │80/443│                                │   │
│  │  │4 Work│ │4 Work│ │4 Work│                                │   │
│  │  └──────┘ └──────┘ └──────┘                                │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  Hardware: 16+ CPU Cores, 32+ GB RAM, NVMe SSD                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 1. Hardware-Requirements

### Minimum
- **CPU:** 16 Cores (26 Instanzen × 4 Worker = 104 Threads + Overhead)
- **RAM:** 32 GB
- **Disk:** 500 GB SSD
- **Network:** 10 Gbit/s

### Empfohlen
- **CPU:** 32 Cores (z.B. AMD EPYC 7502P oder Intel Xeon Gold 6248)
- **RAM:** 64 GB (mit Hugepages)
- **Disk:** 1 TB NVMe SSD
- **Network:** 25 Gbit/s

---

## 2. Verzeichnisstruktur

```bash
sudo mkdir -p /opt/tlsgateNG/{rootCA,bundles,cache,primes,logs}

# CA-Zertifikat (einmalig)
sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout /opt/tlsgateNG/rootCA/ca-key.pem \
    -out /opt/tlsgateNG/rootCA/ca.crt \
    -days 3650 -nodes \
    -subj '/CN=TLSGate Production CA/O=YourOrg/C=DE'

sudo chmod 600 /opt/tlsgateNG/rootCA/ca-key.pem
sudo chmod 644 /opt/tlsgateNG/rootCA/ca.crt

# Separate Cache-Verzeichnisse (26 Instanzen)
for i in {1..26}; do
    sudo mkdir -p /opt/tlsgateNG/cache/instance$i
done

# User erstellen
sudo useradd -r -s /bin/false -d /opt/tlsgateNG tlsgate
sudo chown -R tlsgateNG:tlsgateNG /opt/tlsgateNG
```

---

## 3. Keypool Generator (1×)

**Systemd Service:** `/etc/systemd/system/tlsgateNG-poolgen.service`

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
    -w 4

Restart=always
RestartSec=5
LimitNOFILE=100000

[Install]
WantedBy=multi-user.target
```

---

## 4. Reader Instances (26×)

### Systemd Template Service

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

# Dynamische IP-Bindung basierend auf Instanz-Nummer
# Instanz 1-20  → IP 192.168.1.10 (Gruppe 1)
# Instanz 21-26 → IP 192.168.2.10 (Gruppe 2)
# Wird über EnvironmentFile gesteuert

EnvironmentFile=/etc/tlsgateNG/instance%i.env

ExecStart=/opt/tlsgateNG/build/tlsgateNG \
    --shm \
    -p 80 \
    -s 443 \
    -a 8080 \
    -D /opt/tlsgateNG \
    -C /opt/tlsgateNG/cache/instance%i \
    -w 4 \
    -m 5000 \
    -l ${BIND_IP} \
    ${HTML_TEMPLATE:+-H} ${HTML_TEMPLATE}

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/tlsgateNG/cache/instance%i

AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

Restart=always
RestartSec=5
LimitNOFILE=100000

[Install]
WantedBy=multi-user.target
```

---

## 5. IP-Konfiguration (Environment Files)

### Gruppe 1 (Instanzen 1-20) → IP 192.168.1.10

```bash
sudo mkdir -p /etc/tlsgateNG

# Erstelle Environment Files für Instanz 1-20
for i in {1..20}; do
    cat <<EOF | sudo tee /etc/tlsgateNG/instance$i.env
BIND_IP=192.168.1.10
# Optional: HTML_TEMPLATE=/opt/tlsgateNG/examples/templates/default.html
EOF
done
```

### Gruppe 2 (Instanzen 21-26) → IP 192.168.2.10

```bash
# Erstelle Environment Files für Instanz 21-26
for i in {21..26}; do
    cat <<EOF | sudo tee /etc/tlsgateNG/instance$i.env
BIND_IP=192.168.2.10
# Optional: HTML_TEMPLATE=/opt/tlsgateNG/examples/templates/default.html
EOF
done
```

### Network Interface Setup (wenn IPs noch nicht existieren)

```bash
# Gruppe 1 IP
sudo ip addr add 192.168.1.10/24 dev eth0

# Gruppe 2 IP
sudo ip addr add 192.168.2.10/24 dev eth0

# Persistent machen: /etc/network/interfaces (Debian)
# oder /etc/netplan/*.yaml (Ubuntu)
```

---

## 6. Optimale Start-Reihenfolge

### Komplettes Start-Script

**Datei:** `/usr/local/bin/tlsgateNG-start-all.sh`

```bash
#!/bin/bash

echo "╔════════════════════════════════════════════════════════╗"
echo "║   TLSGate NX - Multi-Instance Startup (26 Total)      ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# 1. Keypool Generator starten
echo "Step 1: Starting Keypool Generator..."
sudo systemctl start tlsgateNG-poolgen

# Warten bis Keypool gefüllt ist
sleep 5

echo "✓ Keypool Generator running"
echo ""

# 2. Gruppe 1 starten (Instanzen 1-20)
echo "Step 2: Starting Group 1 (20 instances on 192.168.1.10)..."
for i in {1..20}; do
    sudo systemctl start tlsgateNG-instance@$i
    # Kurze Pause um CPU Spikes zu vermeiden
    sleep 0.2
done
echo "✓ Group 1 started (20 instances)"
echo ""

# 3. Gruppe 2 starten (Instanzen 21-26)
echo "Step 3: Starting Group 2 (6 instances on 192.168.2.10)..."
for i in {21..26}; do
    sudo systemctl start tlsgateNG-instance@$i
    sleep 0.2
done
echo "✓ Group 2 started (6 instances)"
echo ""

# 4. Warten auf Stabilisierung
echo "Waiting for stabilization (5s)..."
sleep 5

# 5. Status Report
echo ""
echo "╔════════════════════════════════════════════════════════╗"
echo "║                   STATUS REPORT                        ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# Keypool Status
KEYGEN_STATUS=$(sudo systemctl is-active tlsgateNG-poolgen)
if [ "$KEYGEN_STATUS" = "active" ]; then
    echo "✓ Keypool Generator: RUNNING"
else
    echo "✗ Keypool Generator: FAILED ($KEYGEN_STATUS)"
fi
echo ""

# Group 1 Status
echo "Group 1 (192.168.1.10):"
RUNNING_G1=0
for i in {1..20}; do
    STATUS=$(sudo systemctl is-active tlsgateNG-instance@$i)
    if [ "$STATUS" = "active" ]; then
        RUNNING_G1=$((RUNNING_G1 + 1))
    fi
done
echo "  Running: $RUNNING_G1 / 20"

# Group 2 Status
echo "Group 2 (192.168.2.10):"
RUNNING_G2=0
for i in {21..26}; do
    STATUS=$(sudo systemctl is-active tlsgateNG-instance@$i)
    if [ "$STATUS" = "active" ]; then
        RUNNING_G2=$((RUNNING_G2 + 1))
    fi
done
echo "  Running: $RUNNING_G2 / 6"

TOTAL_RUNNING=$((RUNNING_G1 + RUNNING_G2))
echo ""
echo "═══════════════════════════════════════════════════════"
echo "Total Running: $TOTAL_RUNNING / 26"
echo "═══════════════════════════════════════════════════════"

if [ $TOTAL_RUNNING -eq 26 ]; then
    echo ""
    echo "✅ ALL SYSTEMS OPERATIONAL!"
    echo ""
    echo "Capacity:"
    echo "  - Max Connections: 130,000 (26 × 5,000)"
    echo "  - Worker Threads: 104 (26 × 4)"
    echo "  - Estimated Throughput: ~650K req/s"
else
    echo ""
    echo "⚠️  WARNING: Not all instances running!"
    echo ""
    echo "Failed instances:"
    for i in {1..26}; do
        STATUS=$(sudo systemctl is-active tlsgateNG-instance@$i)
        if [ "$STATUS" != "active" ]; then
            echo "  ✗ Instance $i: $STATUS"
        fi
    done
fi

echo ""
```

**Executable machen:**
```bash
sudo chmod +x /usr/local/bin/tlsgateNG-start-all.sh
```

---

## 7. Stop Script

**Datei:** `/usr/local/bin/tlsgateNG-stop-all.sh`

```bash
#!/bin/bash

echo "Stopping all TLSGate instances..."

# Stop alle Reader Instances
for i in {1..26}; do
    echo "Stopping instance $i..."
    sudo systemctl stop tlsgateNG-instance@$i
done

# Stop Keypool Generator
echo "Stopping Keypool Generator..."
sudo systemctl stop tlsgateNG-poolgen

echo "✓ All instances stopped"
```

```bash
sudo chmod +x /usr/local/bin/tlsgateNG-stop-all.sh
```

---

## 8. Kernel Tuning (CRITICAL!)

**Datei:** `/etc/sysctl.d/99-tlsgateNG.conf`

```ini
# ============================================================================
# TLSGate NX - Kernel Tuning (26 Instanzen, 130K Connections)
# ============================================================================

# TCP Stack
net.ipv4.tcp_max_syn_backlog = 131072
net.core.somaxconn = 131072
net.core.netdev_max_backlog = 131072

# File Descriptors (26 × 5000 + Overhead)
fs.file-max = 10000000

# Shared Memory (Keypool + 26× Cert Cache)
kernel.shmmax = 4294967296
kernel.shmall = 4194304

# TCP Optimization
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# Connection Tracking (für 130K connections)
net.netfilter.nf_conntrack_max = 5000000
net.netfilter.nf_conntrack_tcp_timeout_established = 432000

# io_uring
vm.max_map_count = 1048576

# Memory Management
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5

# Network Buffers
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 33554432
net.core.wmem_default = 33554432
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728

# Congestion Control
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
```

**Aktivieren:**
```bash
sudo sysctl -p /etc/sysctl.d/99-tlsgateNG.conf
```

---

## 9. User Limits

**Datei:** `/etc/security/limits.conf`

```
# TLSGate NX - 26 Instanzen
tlsgateNG soft nofile 2000000
tlsgateNG hard nofile 2000000
tlsgateNG soft nproc 16384
tlsgateNG hard nproc 16384
tlsgateNG soft memlock unlimited
tlsgateNG hard memlock unlimited
```

**Reload:**
```bash
# Logout/Login oder:
sudo pam_limits.so
```

---

## 10. CPU Affinity (Optional, aber empfohlen)

### Instanzen auf CPU Cores verteilen

Annahme: 32 CPU Cores

```bash
# Gruppe 1: Instanz 1-20 → CPU 0-19
for i in {1..20}; do
    CORE=$((i - 1))
    sudo systemctl set-property tlsgateNG-instance@$i.service \
        CPUAffinity=$CORE
done

# Gruppe 2: Instanz 21-26 → CPU 20-25
for i in {21..26}; do
    CORE=$((i - 1))
    sudo systemctl set-property tlsgateNG-instance@$i.service \
        CPUAffinity=$CORE
done

# Keypool Generator → CPU 26-27
sudo systemctl set-property tlsgateNG-poolgen.service \
    CPUAffinity=26,27
```

---

## 11. Monitoring

### Echtzeit-Status Dashboard

**Datei:** `/usr/local/bin/tlsgateNG-status.sh`

```bash
#!/bin/bash

while true; do
    clear
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║      TLSGate NX - Real-Time Status Dashboard          ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo ""

    # Keypool
    KEYGEN=$(systemctl is-active tlsgateNG-poolgen)
    echo "Keypool Generator: $KEYGEN"
    echo ""

    # Gruppe 1
    echo "Group 1 (192.168.1.10): "
    RUNNING_G1=0
    for i in {1..20}; do
        if systemctl is-active --quiet tlsgateNG-instance@$i; then
            RUNNING_G1=$((RUNNING_G1 + 1))
        fi
    done
    echo "  ✓ Running: $RUNNING_G1 / 20"

    # Gruppe 2
    echo "Group 2 (192.168.2.10): "
    RUNNING_G2=0
    for i in {21..26}; do
        if systemctl is-active --quiet tlsgateNG-instance@$i; then
            RUNNING_G2=$((RUNNING_G2 + 1))
        fi
    done
    echo "  ✓ Running: $RUNNING_G2 / 6"

    echo ""
    echo "Total: $((RUNNING_G1 + RUNNING_G2)) / 26"
    echo ""

    # System Stats
    echo "System:"
    echo "  CPU Load: $(uptime | awk -F'load average:' '{print $2}')"
    echo "  Memory: $(free -h | awk '/^Mem:/ {print $3 "/" $2}')"
    echo "  Connections: $(ss -s | grep TCP | awk '{print $2}')"

    sleep 2
done
```

```bash
sudo chmod +x /usr/local/bin/tlsgateNG-status.sh
```

---

## 12. Performance Testing

### Test auf beiden IP-Gruppen

```bash
# Gruppe 1 (192.168.1.10)
ab -n 100000 -c 1000 http://192.168.1.10/

# Gruppe 2 (192.168.2.10)
ab -n 100000 -c 1000 http://192.168.2.10/

# Parallel (beide gleichzeitig)
ab -n 100000 -c 1000 http://192.168.1.10/ &
ab -n 100000 -c 1000 http://192.168.2.10/ &
wait
```

---

## 13. Kapazitätsplanung

### Single Server Stats

| Metric | Wert |
|--------|------|
| **Instanzen Total** | 26 |
| **Gruppe 1** | 20 Instanzen (192.168.1.10) |
| **Gruppe 2** | 6 Instanzen (192.168.2.10) |
| **Worker Threads** | 104 (26 × 4) |
| **Max Connections** | 130,000 (26 × 5,000) |
| **Estimated Throughput** | 650,000 req/s (io_uring) |
| **Memory Usage** | ~8-12 GB |
| **CPU Cores Required** | 16-32 |

---

## 14. Per-Instance HTML Templates (Optional)

### Warum unterschiedliche Templates?

Jede Instanz kann eine **eigene HTML-Vorlage** für index/default-Seiten haben:
- Gruppe 1 (IP 192.168.1.10): Eine Vorlage
- Gruppe 2 (IP 192.168.2.10): Eine andere Vorlage
- Oder jede Instanz individuell

### Template gilt für:
- `/` (root)
- `/index.*` (html, php, jsp, asp, aspx, htm, etc.)
- `/default.*` (html, php, jsp, asp, aspx, htm, etc.)

### Beispiel-Templates

TLSGate NX enthält fertige Templates in `examples/templates/`:
- `blank.html` - Leere Seite (minimal blocking)
- `zero.html` - Null-Byte Response (maximales blocking)
- `minimal.html` - Minimales gestyltes Layout
- `default.html` - Modernes Glass-Morphism Design

### Setup: Gleiche Template für alle Instanzen

**Systemd Service anpassen:** `/etc/systemd/system/tlsgateNG-instance@.service`

```ini
ExecStart=/opt/tlsgateNG/build/tlsgateNG \
    --shm \
    -p 80 \
    -s 443 \
    -a 8080 \
    -D /opt/tlsgateNG \
    -C /opt/tlsgateNG/cache/instance%i \
    -H /opt/tlsgateNG/examples/templates/default.html \
    -w 4 \
    -m 5000 \
    -l ${BIND_IP}
```

### Setup: Unterschiedliche Templates pro Gruppe

**Option 1: Environment-Variable verwenden**

Systemd Service:
```ini
EnvironmentFile=/etc/tlsgateNG/instance%i.env

ExecStart=/opt/tlsgateNG/build/tlsgateNG \
    --shm \
    -p 80 \
    -s 443 \
    -a 8080 \
    -D /opt/tlsgateNG \
    -C /opt/tlsgateNG/cache/instance%i \
    -H ${HTML_TEMPLATE} \
    -w 4 \
    -m 5000 \
    -l ${BIND_IP}
```

Environment Files:

```bash
# Gruppe 1 (Instanzen 1-20): Default Template
for i in {1..20}; do
    cat <<EOF | sudo tee /etc/tlsgateNG/instance$i.env
BIND_IP=192.168.1.10
HTML_TEMPLATE=/opt/tlsgateNG/examples/templates/default.html
EOF
done

# Gruppe 2 (Instanzen 21-26): Blank Template
for i in {21..26}; do
    cat <<EOF | sudo tee /etc/tlsgateNG/instance$i.env
BIND_IP=192.168.2.10
HTML_TEMPLATE=/opt/tlsgateNG/examples/templates/blank.html
EOF
done
```

**Option 2: Individuelle Templates pro Instanz**

```bash
# Jede Instanz eigenes Template
for i in {1..26}; do
    cat <<EOF | sudo tee /etc/tlsgateNG/instance$i.env
BIND_IP=$([ $i -le 20 ] && echo "192.168.1.10" || echo "192.168.2.10")
HTML_TEMPLATE=/opt/tlsgateNG/templates/instance$i.html
EOF
done

# Templates kopieren/erstellen
sudo mkdir -p /opt/tlsgateNG/templates
for i in {1..26}; do
    sudo cp /opt/tlsgateNG/examples/templates/default.html \
           /opt/tlsgateNG/templates/instance$i.html
    # Jetzt individuell anpassen...
done
```

### Eigene Templates erstellen

**Template-Format:**
```html
<!DOCTYPE html>
<html>
<head>
    <title>Meine Instanz</title>
</head>
<body>
    <h1>Willkommen</h1>
    <p>Server Zeit: %s</p>
</body>
</html>
```

**Wichtig:**
- `%s` wird durch aktuelle Server-Zeit ersetzt
- Max. Größe: **1 MB** (empfohlen: < 100 KB)
- Template wird beim Start einmalig geladen

### Services neu laden

```bash
# Nach Änderung an systemd service:
sudo systemctl daemon-reload

# Alle Instanzen neu starten:
sudo systemctl restart tlsgateNG-poolgen
for i in {1..26}; do
    sudo systemctl restart tlsgateNG-instance@$i
done
```

---

## Quick Start Commands

```bash
# Alles starten
/usr/local/bin/tlsgateNG-start-all.sh

# Status prüfen
/usr/local/bin/tlsgateNG-status.sh

# Alles stoppen
/usr/local/bin/tlsgateNG-stop-all.sh

# Logs (alle Instanzen)
sudo journalctl -u 'tlsgate-*' -f

# Restart einzelne Instanz
sudo systemctl restart tlsgateNG-instance@5
```

---

**Fertig!** 🚀

Dein Single-Server Multi-Instance Setup ist bereit für **130K simultane Connections**!
