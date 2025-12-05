# TLSGateNG4 v4.36 GEN4 - Performance Tuning Guide

**System Optimization for Maximum Throughput & Latency**

---

## Table of Contents

1. [Baseline Performance](#baseline-performance)
2. [System Tuning](#system-tuning)
3. [Linux Kernel Parameters](#linux-kernel-parameters)
4. [Network Optimization](#network-optimization)
5. [CPU Affinity & Isolation](#cpu-affinity--isolation)
6. [Memory Optimization](#memory-optimization)
7. [I/O Backend Selection](#io-backend-selection)
8. [Monitoring & Profiling](#monitoring--profiling)
9. [Troubleshooting](#troubleshooting)

---

## Baseline Performance

### Single Instance (Default Config)
```
Configuration: 4 workers, 1,000 max connections per worker
Concurrent Connections:  160,000
HTTP Requests/sec:       10-20,000
HTTPS Requests/sec:      5-10,000
Latency (p99):           < 10ms
Memory Usage:            ~3GB
```

### Multi-Instance (60 Instances)
```
Total Concurrent:        10M+ connections
Total HTTP:              200-400K req/s
Total HTTPS:             100-200K req/s
Total Memory:            180GB
CPU Usage:               70-90%
```

### Expected Gains from Tuning
- **30-50% throughput increase** (system tuning)
- **20-40% latency reduction** (network tuning)
- **15-25% memory efficiency** (allocation tuning)

---

## System Tuning

### File Descriptor Limits

**Check Current Limits**
```bash
# Display current limits
ulimit -a

# Check hard limit
ulimit -Hn

# Check soft limit
ulimit -Sn
```

**Increase Limits (Permanent)**

Edit `/etc/security/limits.conf`:
```
*       soft    nofile  1048576
*       hard    nofile  1048576
*       soft    nproc   65536
*       hard    nproc   65536
```

**Verify Changes**
```bash
# Relogin and check
ulimit -n  # Should be 1048576
```

### System-Wide File Descriptors

Edit `/etc/sysctl.conf`:
```bash
# Increase file descriptor limit
fs.file-max = 2097152

# Per-socket receive buffer
net.core.rmem_max = 134217728

# Per-socket send buffer
net.core.wmem_max = 134217728

# TCP receive buffers (min avg max)
net.ipv4.tcp_rmem = 4096 87380 134217728

# TCP send buffers (min avg max)
net.ipv4.tcp_wmem = 4096 65536 134217728
```

**Apply Changes**
```bash
sysctl -p
```

### Connection Backlog

Edit `/etc/sysctl.conf`:
```bash
# Listen backlog
net.core.somaxconn = 4096

# TCP SYN backlog
net.ipv4.tcp_max_syn_backlog = 8192

# Connection keep-alive
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 3
```

---

## Linux Kernel Parameters

### Network Performance

**TCP Window Scaling**
```bash
# Enable window scaling (improves throughput)
net.ipv4.tcp_window_scaling = 1
```

**TCP Fast Open**
```bash
# Enable TCP Fast Open (TFO)
# 3 = Client + Server
net.ipv4.tcp_fastopen = 3
```

**TCP Selective Acknowledgment**
```bash
# Enable SACK (reduces retransmissions)
net.ipv4.tcp_sack = 1
```

**TCP Timestamps**
```bash
# Disable timestamps (saves bandwidth on fast networks)
net.ipv4.tcp_timestamps = 0
```

### Connection Handling

**TIME_WAIT Reuse**
```bash
# Reuse TIME_WAIT sockets
net.ipv4.tcp_tw_reuse = 1
```

**Fast Recycling (Caution!)**
```bash
# Fast recycle TIME_WAIT sockets (may cause issues with NAT)
# Only enable on non-NAT networks
net.ipv4.tcp_tw_recycle = 0  # Disabled by default (recommended)
```

**SYN Cookies**
```bash
# Protect against SYN flood attacks
net.ipv4.tcp_syncookies = 1
```

### TCP Congestion Control

**Check Available Algorithms**
```bash
cat /proc/sys/net/ipv4/tcp_available_congestion_control
```

**Select Best Algorithm**
```bash
# Modern: BBR (Google's Bottleneck Bandwidth and RTT)
# Requires Linux 4.9+ (Best for WAN, high latency)
net.ipv4.tcp_congestion_control = bbr

# Alternative: CUBIC (Default, good for most)
net.ipv4.tcp_congestion_control = cubic

# For LAN (Low latency networks)
net.ipv4.tcp_congestion_control = htcp
```

### QDisc (Queue Discipline)

**Modern Kernel (4.1+)**
```bash
# Enable fq (Fair Queuing)
net.core.default_qdisc = fq
```

**Check Current Setting**
```bash
sysctl net.core.default_qdisc
```

---

## Network Optimization

### Network Card Tuning

**Check NIC Status**
```bash
ethtool eth0
```

**Increase Ring Buffers**
```bash
# Check current
ethtool -g eth0

# Increase RX/TX rings
ethtool -G eth0 rx 4096 tx 4096
```

**Enable Hardware Offloading**
```bash
# Check offloading
ethtool -k eth0

# Enable TSO (TCP Segmentation Offload)
ethtool -K eth0 tso on

# Enable GSO (Generic Segmentation Offload)
ethtool -K eth0 gso on

# Enable LRO (Large Receive Offload) - if available
ethtool -K eth0 lro on
```

### Interrupt Handling

**Check IRQ Affinity**
```bash
# View current CPU affinity
cat /proc/irq/*/smp_affinity

# Bind NIC IRQs to specific CPUs
echo f > /proc/irq/40/smp_affinity  # Cores 0-3 (hex)
```

**Interrupt Coalescing**
```bash
# Check current settings
ethtool -c eth0

# Increase RX/TX coalescing (reduce interrupts)
ethtool -C eth0 rx-usecs 500 rx-frames 500
```

---

## CPU Affinity & Isolation

### Check CPU Information

```bash
# Display CPU info
lscpu

# Check CPU cores
nproc

# Check CPU frequencies
cat /proc/cpuinfo | grep MHz
```

### Bind Processes to Cores

**Manual CPU Binding**
```bash
# Run single instance on cores 0-3
taskset -c 0-3 ./tlsgateNGv4 -l 192.168.1.100 -p 80 -s 443 -w 4

# Run multiple instances (cores 4-7, 8-11, 12-15, etc.)
taskset -c 4-7 ./tlsgateNGv4 -l 192.168.1.101 -p 80 -s 443 -w 4
taskset -c 8-11 ./tlsgateNGv4 -l 192.168.1.102 -p 80 -s 443 -w 4
```

### CPU Isolation (Linux)

**Isolate CPUs from Kernel**

Edit kernel boot parameters `/etc/default/grub`:
```bash
GRUB_CMDLINE_LINUX="... isolcpus=4-15"
```

**Apply Changes**
```bash
grub-mkconfig -o /boot/grub/grub.cfg
reboot
```

**Verify Isolation**
```bash
cat /sys/devices/system/cpu/isolated
```

### CPU Frequency Management

**Check Current Governor**
```bash
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
```

**Set to Performance Mode**
```bash
# Disable frequency scaling (high performance)
echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

**Set to Power Save (if needed)**
```bash
echo powersave | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

### Disable CPU Power Features

```bash
# Disable C-states (CPU idle states)
# Add to kernel boot: intel_idle.max_cstate=0

# Disable P-states (frequency scaling)
# Add to kernel boot: intel_pstate=disable
```

---

## Memory Optimization

### Memory Information

**Check Available Memory**
```bash
free -h

# Detailed memory info
cat /proc/meminfo
```

### Huge Pages

**Enable Huge Pages**
```bash
# Allocate 2GB of 1GB huge pages
echo 2 > /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages

# Or 2GB via 2MB pages (1024 pages)
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
```

**Verify Huge Pages**
```bash
grep HugePages /proc/meminfo
```

### Memory Swapping

**Disable Swap (if sufficient RAM)**
```bash
# Check swap usage
free -h

# Disable swap
swapoff -a

# Comment out in /etc/fstab
# /swapfile none swap sw 0 0
```

**Reduce Swappiness**
```bash
# Check current value
cat /proc/sys/vm/swappiness

# Reduce swappiness (lower = less swap)
echo 10 > /proc/sys/vm/swappiness
```

### Memory Allocation

**Check NUMA Configuration**
```bash
# View NUMA nodes
numactl --hardware

# Bind to local NUMA node
numactl --localalloc ./tlsgateNGv4 ...
```

---

## I/O Backend Selection

### Check Kernel Support

**Check io_uring Availability**
```bash
# Check kernel version
uname -r

# Check liburing installed
dpkg -l | grep liburing

# Check io_uring support
./build/tlsgateNGv4 --help | grep io_uring
```

**Check epoll Availability**
```bash
# Default on modern Linux
# No special checks needed
```

### Compile for Different Backends

**io_uring (Recommended for Linux 5.1+)**
```bash
# Install liburing development files
apt-get install liburing-dev

# Compile with io_uring
make clean && make

# Verify io_uring enabled
./build/tlsgateNGv4 --help | grep io_uring
```

**epoll (Fallback)**
```bash
# Default if io_uring not available
# No special compilation needed
make clean && make
```

---

## Monitoring & Profiling

### Real-Time Metrics

**Query /metrics Endpoint**
```bash
# Prometheus format
curl http://localhost/metrics

# Check request rates
curl http://localhost/metrics | grep req_

# Check connection count
curl http://localhost/metrics | grep connections
```

**Query /stats Endpoint**
```bash
# JSON format
curl http://localhost/stats | jq .
```

### System Monitoring

**Monitor CPU Usage**
```bash
# Real-time CPU and memory
top -p $(pidof tlsgateNGv4)

# Per-core CPU usage
mpstat -P ALL 1
```

**Monitor Network**
```bash
# Real-time network statistics
iftop -i eth0

# Connection count per IP
netstat -antp | grep tlsgateNG | wc -l

# Connections per state
netstat -antp | grep tlsgateNG | awk '{print $6}' | sort | uniq -c
```

**Monitor Disk I/O**
```bash
# I/O statistics
iostat -x 1

# Per-process I/O
iotop -p $(pidof tlsgateNGv4)
```

### Profiling & Tracing

**Enable Verbose Logging**
```bash
# Run with verbose logging
./tlsgateNGv4 -l 192.168.1.100 -p 80 -s 443 -v

# Monitor output
tail -f /var/log/tlsgateNG.log
```

**System Call Tracing**
```bash
# Trace system calls
strace -p $(pidof tlsgateNGv4) -e trace=network

# Count syscalls
strace -p $(pidof tlsgateNGv4) -c
```

**Performance Profiling (with perf)**
```bash
# Profile for 10 seconds
perf record -p $(pidof tlsgateNGv4) -F 99 -- sleep 10

# Display results
perf report

# Flame graph (install flamegraph)
perf script | stackcollapse-perf.pl | flamegraph.pl > perf.svg
```

---

## Troubleshooting

### High CPU Usage

**Diagnosis**
```bash
# Identify if it's user or system CPU
top -p $(pidof tlsgateNGv4)

# Check process threads
ps -eLf | grep tlsgateNGv4

# Profile to find bottleneck
perf record -p $(pidof tlsgateNGv4) -- sleep 10
perf report
```

**Solutions**
- Reduce worker count (-w flag)
- Increase max connections per worker (-m flag)
- Enable io_uring (if available)
- Check for CPU contention

### High Memory Usage

**Diagnosis**
```bash
# Check memory per process
ps aux | grep tlsgateNGv4

# Check detailed memory info
cat /proc/$(pidof tlsgateNGv4)/status | grep VmPeak

# Check page faults
cat /proc/$(pidof tlsgateNGv4)/stat | awk '{print "Major faults:", $11, "Minor faults:", $9}'
```

**Solutions**
- Reduce max connections per worker (-m flag)
- Enable huge pages (if kernel supports)
- Reduce cache size (cert caching)
- Check for memory leaks

### Low Throughput

**Diagnosis**
```bash
# Check request rate
curl http://localhost/metrics | grep req_total

# Check connection count
curl http://localhost/metrics | grep connections

# Check latency
curl -w "Time: %{time_total}\n" http://localhost/
```

**Solutions**
- Increase worker threads (-w flag)
- Increase max connections (-m flag)
- Check network interface saturation
- Enable io_uring backend
- Check for CPU throttling

### Connection Timeouts

**Diagnosis**
```bash
# Check active connections
netstat -antp | grep tlsgateNG | wc -l

# Check connections in TIME_WAIT
netstat -antp | grep TIME_WAIT | wc -l

# Check limits
ulimit -n
```

**Solutions**
- Increase file descriptor limit
- Enable TCP fast open
- Reduce timeouts (if appropriate)
- Check network latency

### Packet Loss / Retransmissions

**Diagnosis**
```bash
# Check network stats
netstat -i

# Monitor dropped packets
watch -n 1 'netstat -i | grep eth0'

# Check TCP retransmissions
tail -f /proc/net/snmp | grep -i tcp
```

**Solutions**
- Increase network buffers
- Reduce interrupt coalescing
- Check NIC driver version
- Check for hardware errors

---

## Optimization Checklist

### Pre-Deployment

- [ ] File descriptors increased (ulimit -n >= 1M)
- [ ] TCP buffer sizes tuned (rmem/wmem)
- [ ] TCP congestion control selected (bbr/cubic/htcp)
- [ ] SYN cookies enabled
- [ ] TIME_WAIT reuse enabled
- [ ] Network offloading enabled (TSO, GSO, LRO)
- [ ] Swap disabled or swappiness reduced
- [ ] CPUs isolated (if NUMA)
- [ ] io_uring available (if Linux 5.1+)

### Deployment

- [ ] Worker threads (-w) configured per CPU cores
- [ ] Max connections (-m) set appropriately
- [ ] CPU affinity applied (taskset)
- [ ] Metrics monitoring enabled (/metrics, /stats)
- [ ] Verbose logging disabled (except debugging)

### Post-Deployment

- [ ] Monitor /metrics endpoint regularly
- [ ] Check per-IP request rates
- [ ] Monitor connection pool usage
- [ ] Alert on connection exhaustion
- [ ] Review latency percentiles (p50, p95, p99)
- [ ] Monitor CPU/memory usage
- [ ] Check network interface saturation

---

## Expected Performance Gains

### Before Tuning
- Throughput: 10-20K req/s (HTTPS)
- Latency p99: 10-50ms
- CPU Efficiency: 40-60%

### After Full Tuning
- Throughput: 15-30K req/s (HTTPS)
- Latency p99: 2-10ms
- CPU Efficiency: 80-90%

### Gains
- **50-100% throughput increase**
- **75-80% latency reduction**
- **25-50% CPU efficiency improvement**

---

## References

- Linux kernel TCP tuning: https://wiki.linuxfoundation.org/networking/kernel_flow_probes
- io_uring documentation: https://kernel.dk/io_uring.pdf
- ethtool documentation: man ethtool
- sysctl tuning: https://access.redhat.com/documentation/

---

**For more information:**
- Code architecture: docs/ARCHITECTURE.md
- Security details: docs/SECURITY_FRAMEWORK.md
- Feature list: docs/FEATURES.md
