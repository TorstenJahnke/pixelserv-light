#!/bin/bash
# OpenSSL Benchmark for AMD EPYC
# Usage: ./openssl_benchmark_epyc.sh [openssl_root]

# Find OpenSSL installation
if [ -n "$1" ]; then
    OPENSSL_ROOT="$1"
elif [ -n "$OPENSSL_ROOT_DIR" ]; then
    OPENSSL_ROOT="$OPENSSL_ROOT_DIR"
elif [ -d "/opt/openssl-3.6.0" ]; then
    OPENSSL_ROOT="/opt/openssl-3.6.0"
else
    OPENSSL_ROOT=$(ls -d /opt/openssl-* 2>/dev/null | sort -V | tail -1)
fi

if [ -z "$OPENSSL_ROOT" ] || [ ! -x "$OPENSSL_ROOT/bin/openssl" ]; then
    echo "Error: No OpenSSL installation found"
    exit 1
fi

# Activate OpenSSL
export PATH="$OPENSSL_ROOT/bin:$PATH"
export LD_LIBRARY_PATH="$OPENSSL_ROOT/lib:$LD_LIBRARY_PATH"

BENCH_DIR="$OPENSSL_ROOT/benchmark"
mkdir -p "$BENCH_DIR"
cd "$BENCH_DIR"

RESULTS_FILE="benchmark_$(date +%Y%m%d_%H%M%S).txt"

echo "OpenSSL Benchmark - AMD EPYC" | tee "$RESULTS_FILE"
echo "OpenSSL: $(openssl version)" | tee -a "$RESULTS_FILE"
echo "Cores: $(nproc), RAM: $(free -h | grep Mem | awk '{print $2}')" | tee -a "$RESULTS_FILE"
echo "==========================================" | tee -a "$RESULTS_FILE"

# RSA Key Generation Benchmark
echo "1. RSA Key Generation" | tee -a "$RESULTS_FILE"
for size in 1024 2048 4096 8192 16384; do
    echo "   RSA-$size..." | tee -a "$RESULTS_FILE"
    start=$(date +%s.%N)
    openssl genrsa -out "rsa_${size}.pem" "$size" 2>/dev/null
    end=$(date +%s.%N)
    duration=$(echo "$end - $start" | bc)
    size_kb=$(du -k "rsa_${size}.pem" | cut -f1)
    echo "   OK ${duration}s, ${size_kb}KB" | tee -a "$RESULTS_FILE"
done

# SM2/SM3 Benchmark
echo "2. SM Algorithms" | tee -a "$RESULTS_FILE"
start=$(date +%s.%N)
if openssl genpkey -algorithm SM2 -out "sm2.pem" 2>/dev/null; then
    end=$(date +%s.%N)
    echo "   SM2: $(echo "$end - $start" | bc)s" | tee -a "$RESULTS_FILE"
else
    echo "   SM2: Not available" | tee -a "$RESULTS_FILE"
fi

# Legacy Features Test
echo "3. Legacy Features" | tee -a "$RESULTS_FILE"
openssl ciphers -v 'ALL' 2>/dev/null | grep -E "(SSLv3|TLSv1)" | head -3 | tee -a "$RESULTS_FILE"

echo "Benchmark complete: $RESULTS_FILE" | tee -a "$RESULTS_FILE"
