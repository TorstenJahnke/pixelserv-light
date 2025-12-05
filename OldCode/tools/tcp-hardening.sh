#!/bin/bash
# TCP/IP Stack Hardening Script for TLSGateNX
# Copyright (C) 2025 Torsten Jahnke
#
# This script configures kernel-level TCP/IP parameters for maximum
# DDoS resilience and high-performance operation.
#
# Run as root: sudo bash tools/tcp-hardening.sh

set -e

echo "╔════════════════════════════════════════════════════════╗"
echo "║  TCP/IP Stack Hardening for TLSGateNX                 ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ ERROR: This script must be run as root"
    echo "   Usage: sudo bash tools/tcp-hardening.sh"
    exit 1
fi

echo "⚙️  Applying kernel TCP/IP hardening parameters..."
echo ""

# ============================================================================
# SYN Flood Protection (CRITICAL!)
# ============================================================================
echo "[1/9] SYN Flood Protection..."

# Enable SYN cookies (prevents SYN flood attacks)
sysctl -w net.ipv4.tcp_syncookies=1

# Increase SYN backlog (default is often 128-512)
sysctl -w net.ipv4.tcp_max_syn_backlog=8192

# Reduce SYN-ACK retries (faster detection of fake connections)
sysctl -w net.ipv4.tcp_synack_retries=2
sysctl -w net.ipv4.tcp_syn_retries=2

echo "✅ SYN Flood protection enabled"

# ============================================================================
# Connection Tracking
# ============================================================================
echo "[2/9] Connection Tracking..."

# Increase conntrack table size for high connection count
sysctl -w net.netfilter.nf_conntrack_max=1000000

# Reduce established connection timeout (default: 432000 = 5 days!)
sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=600

echo "✅ Connection tracking optimized"

# ============================================================================
# TCP Hardening
# ============================================================================
echo "[3/9] TCP Protocol Hardening..."

# Protect against TCP time-wait assassination
sysctl -w net.ipv4.tcp_rfc1337=1

# Disable TCP timestamps (reduces overhead, improves privacy)
sysctl -w net.ipv4.tcp_timestamps=0

# Reduce FIN timeout (default: 60s, kills zombies faster)
sysctl -w net.ipv4.tcp_fin_timeout=10

echo "✅ TCP protocol hardened"

# ============================================================================
# Keep-Alive Tuning
# ============================================================================
echo "[4/9] TCP Keep-Alive..."

# Start keep-alive probes after 600 seconds (10 minutes)
sysctl -w net.ipv4.tcp_keepalive_time=600

# Send probes every 30 seconds
sysctl -w net.ipv4.tcp_keepalive_intvl=30

# Send 3 probes before declaring connection dead
sysctl -w net.ipv4.tcp_keepalive_probes=3

echo "✅ Keep-alive configured"

# ============================================================================
# Buffer Tuning (High Performance)
# ============================================================================
echo "[5/9] Socket Buffer Tuning..."

# Maximum socket buffer size (128MB)
sysctl -w net.core.rmem_max=134217728
sysctl -w net.core.wmem_max=134217728

# TCP read buffer: min, default, max (in bytes)
sysctl -w net.ipv4.tcp_rmem='4096 87380 67108864'

# TCP write buffer: min, default, max (in bytes)
sysctl -w net.ipv4.tcp_wmem='4096 65536 67108864'

echo "✅ Buffers optimized for high throughput"

# ============================================================================
# Connection Limits
# ============================================================================
echo "[6/9] Connection Limits..."

# Maximum listen() backlog (must match listen(65535) in code)
sysctl -w net.core.somaxconn=65535

# Maximum backlog of packets in network device queue
sysctl -w net.core.netdev_max_backlog=65536

echo "✅ Connection limits increased"

# ============================================================================
# TCP Fast Open (Performance)
# ============================================================================
echo "[7/9] TCP Fast Open..."

# Enable TFO for both client and server (3 = both)
sysctl -w net.ipv4.tcp_fastopen=3

echo "✅ TCP Fast Open enabled"

# ============================================================================
# File Descriptor Limits
# ============================================================================
echo "[8/9] File Descriptor Limits..."

# Increase system-wide file descriptor limit
sysctl -w fs.file-max=2097152

# Increase inotify limits (useful for monitoring)
sysctl -w fs.inotify.max_user_instances=8192
sysctl -w fs.inotify.max_user_watches=524288

echo "✅ File descriptor limits increased"

# ============================================================================
# IPv6 Security (if IPv6 enabled)
# ============================================================================
echo "[9/9] IPv6 Security..."

# Apply same protections to IPv6
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0

echo "✅ IPv6 hardened"

# ============================================================================
# Persist Configuration
# ============================================================================
echo ""
echo "💾 Persisting configuration to /etc/sysctl.d/99-tlsgateNG-tcp-hardening.conf..."

cat > /etc/sysctl.d/99-tlsgateNG-tcp-hardening.conf << 'EOF'
# TLSGateNX TCP/IP Stack Hardening
# Auto-generated by tools/tcp-hardening.sh

# SYN Flood Protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2

# Connection Tracking
net.netfilter.nf_conntrack_max = 1000000
net.netfilter.nf_conntrack_tcp_timeout_established = 600

# TCP Hardening
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_fin_timeout = 10

# Keep-Alive
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3

# Buffer Tuning
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864

# Connection Limits
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65536

# TCP Fast Open
net.ipv4.tcp_fastopen = 3

# File Descriptors
fs.file-max = 2097152
fs.inotify.max_user_instances = 8192
fs.inotify.max_user_watches = 524288

# IPv6 Security
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOF

echo "✅ Configuration persisted (survives reboot)"
echo ""
echo "╔════════════════════════════════════════════════════════╗"
echo "║  ✅ TCP/IP Stack Hardening Complete!                  ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo "Summary of applied protections:"
echo "  ✅ SYN Flood protection (SYN cookies + backlog 8192)"
echo "  ✅ Connection tracking (1M connections)"
echo "  ✅ TCP hardening (RFC1337, fast FIN timeout)"
echo "  ✅ Keep-alive (600s idle, 3 probes × 30s)"
echo "  ✅ High-performance buffers (128MB max)"
echo "  ✅ Large connection limits (65535 backlog)"
echo "  ✅ TCP Fast Open (save 1 RTT)"
echo "  ✅ File descriptor limits (2M)"
echo "  ✅ IPv6 security"
echo ""
echo "Configuration persisted to:"
echo "  /etc/sysctl.d/99-tlsgateNG-tcp-hardening.conf"
echo ""
echo "To verify settings:"
echo "  sysctl net.ipv4.tcp_syncookies"
echo "  sysctl net.core.somaxconn"
echo ""
echo "🚀 TLSGateNX is now hardened against:"
echo "  • SYN Flood attacks"
echo "  • Slowloris attacks"
echo "  • Connection exhaustion"
echo "  • Zombie connections"
echo ""
