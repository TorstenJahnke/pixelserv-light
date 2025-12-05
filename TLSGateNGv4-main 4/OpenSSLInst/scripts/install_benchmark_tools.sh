#!/bin/bash
# Install Benchmark Tools
# Ausführung: sudo /opt/openssl-3.6.0/scripts/install_benchmark_tools.sh

set -e

echo "📦 Installiere Benchmark-Tools..."

apt update
apt install -y bc sysstat htop iotop python3 python3-pip

# Python Tools für erweiterte Benchmarks
pip3 install psutil matplotlib numpy 2>/dev/null || echo "⚠️  Python Tools optional"

# Erstelle Benchmark-Verzeichnis
mkdir -p /opt/openssl-3.6.0/benchmark

echo "✅ Benchmark-Tools installiert"
echo "📊 Verfügbare Tools: bc, sysstat, htop, iotop, python3"
