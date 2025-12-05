#!/bin/bash
# Live System Monitor
# Ausführung: /opt/openssl-3.6.0/scripts/live_monitor.sh

echo "📊 Live System Monitor - Drücke Ctrl+C zum Beenden"
echo "🖥️  AMD EPYC 32-Core - 256GB RAM"
echo "=========================================="

while true; do
    clear
    
    # CPU
    echo "💻 CPU:"
    echo "  Auslastung: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}')%"
    echo "  Load: $(uptime | awk -F'load average:' '{print $2}')"
    
    # Memory
    echo "💾 RAM:"
    free -h | grep Mem | awk '{print "  Total: " $2, "Used: " $3, "Free: " $4}'
    
    # OpenSSL Prozesse
    echo "🔐 OpenSSL Prozesse:"
    pgrep -x openssl >/dev/null && ps -o pid,pcpu,pmem,cmd -p $(pgrep -x openssl) | tail -n +2
    
    # Systemprozesse
    echo "📈 Top Prozesse:"
    ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -6
    
    echo "=========================================="
    sleep 3
done
