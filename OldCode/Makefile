# ============================================================================
# TLSGate NG v4.36 GEN4 - Ultra-High Performance Build System
# ============================================================================
#
# Three specialized binaries:
#   - tlsgateNG-poolgen: Pure keypool generator (no network)
#   - tlsgateNGv4:     IPv4-optimized network server
#   - tlsgateNGv6:     IPv6-optimized network server
#
# Copyright (C) 2026 Torsten Jahnke
# ============================================================================

# ============================================================================
# OpenSSL / Tongsuo Configuration
# ============================================================================
# Auto-detection priority:
#   1. OPENSSL_DIR from command line (make OPENSSL_DIR=/path)
#   2. TONGSUO_ROOT_ACTIVE environment variable (from ssl-switch.sh)
#   3. OPENSSL_ROOT_DIR environment variable (from ssl-switch.sh)
#   4. Default paths: /opt/openssl-3.6.0, /opt/tongsuo-8.4.0
#   5. System OpenSSL
#
# Usage:
#   source tools/ssl-switch.sh tongsuo   # Activate Tongsuo
#   make clean && make                    # Auto-detects Tongsuo
#
#   source tools/ssl-switch.sh openssl   # Activate OpenSSL
#   make clean && make                    # Auto-detects OpenSSL

# Check for environment variables from ssl-switch.sh
ifdef TONGSUO_ROOT_ACTIVE
    OPENSSL_DIR ?= $(TONGSUO_ROOT_ACTIVE)
    SSL_TYPE = Tongsuo
else ifdef OPENSSL_ROOT_DIR
    OPENSSL_DIR ?= $(OPENSSL_ROOT_DIR)
    SSL_TYPE = OpenSSL
else
    # Default fallback paths
    OPENSSL_DIR ?= $(firstword $(wildcard /opt/openssl-3.6.0 /opt/tongsuo-8.4.0))
    SSL_TYPE = OpenSSL
endif

# Detect SSL library type from path
ifneq (,$(findstring tongsuo,$(OPENSSL_DIR)))
    SSL_TYPE = Tongsuo
endif

# Check if SSL installation exists, otherwise use system default
ifneq ($(wildcard $(OPENSSL_DIR)/include/openssl/opensslv.h),)
    $(info ✅ Using $(SSL_TYPE) from: $(OPENSSL_DIR))
    OPENSSL_CFLAGS = -I$(OPENSSL_DIR)/include
    OPENSSL_LDFLAGS = -L$(OPENSSL_DIR)/lib -Wl,-rpath,$(OPENSSL_DIR)/lib
else ifneq ($(OPENSSL_DIR),)
    $(info ⚠️  $(SSL_TYPE) not found at $(OPENSSL_DIR), using system OpenSSL)
    OPENSSL_CFLAGS =
    OPENSSL_LDFLAGS =
    SSL_TYPE = System
else
    $(info ⚠️  No custom SSL found, using system OpenSSL)
    OPENSSL_CFLAGS =
    OPENSSL_LDFLAGS =
    SSL_TYPE = System
endif

CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -O2 -std=gnu11 -Iinclude -Isrc $(OPENSSL_CFLAGS)
LDFLAGS = -pthread $(OPENSSL_LDFLAGS) -lssl -lcrypto -lz -lrt -lm

# ============================================================================
# libcurl Detection (for optional origin forwarding)
# ============================================================================
# Note: TLSGate NG is an IP Abyss Controller (IP Termination Server).
# libcurl is optional for forwarding requests to analysis servers (silent blocker feature only).
HAS_CURL := $(shell pkg-config --exists libcurl && echo yes)
ifeq ($(HAS_CURL),yes)
    CFLAGS += -DHAVE_CURL $(shell pkg-config --cflags libcurl)
    LDFLAGS += $(shell pkg-config --libs libcurl)
    $(info ✅ libcurl support enabled (optional origin forwarding))
else
    $(info ⚠️  libcurl NOT available - origin forwarding disabled)
    $(info    To enable origin forwarding: apt-get install libcurl4-openssl-dev)
endif

# ============================================================================
# I/O Backend Detection (ESSENTIAL for 200K+ connections)
# ============================================================================
# Detect io_uring support (Linux 5.1+)
HAS_IOURING := $(shell pkg-config --exists liburing && echo yes)
ifeq ($(HAS_IOURING),yes)
    CFLAGS += -DHAVE_IOURING $(shell pkg-config --cflags liburing)
    LDFLAGS += $(shell pkg-config --libs liburing)
    IO_BACKEND = io_uring
    $(info ✅ io_uring support enabled (high performance I/O))
else
    IO_BACKEND = epoll
    $(info ⚠️  io_uring NOT available - using epoll fallback)
    $(info    For optimal performance install: apt-get install liburing-dev)
    $(info    io_uring required for 200K+ connections target)
endif

# Detect kqueue support (BSD/macOS)
UNAME := $(shell uname -s)
ifeq ($(UNAME),Darwin)
    CFLAGS += -DHAVE_KQUEUE
    IO_BACKEND = kqueue
    $(info ✅ kqueue support enabled (BSD/macOS))
else ifeq ($(UNAME),FreeBSD)
    CFLAGS += -DHAVE_KQUEUE
    IO_BACKEND = kqueue
    $(info ✅ kqueue support enabled (BSD/macOS))
endif


# ============================================================================
# HTML Template (Compiled into binary - SECURE!)
# ============================================================================
# Template: include/html_index.h (unsigned char index_html[])
# To change template: Edit html_index.h and rebuild
# ============================================================================
# ============================================================================
# Directory Structure
# ============================================================================
SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR = build
TEST_DIR = tests

# Source organization (ready for TLS integration)
CORE_DIR = $(SRC_DIR)/core
HTTP_DIR = $(SRC_DIR)/http
ANTI_ADBLOCK_DIR = $(SRC_DIR)/anti_adblock
TLS_DIR = $(SRC_DIR)/tls

# ============================================================================
# Source Files
# ============================================================================

# Core engine
CORE_SOURCES = \
	$(CORE_DIR)/worker.c \
	$(CORE_DIR)/connection.c

# HTTP engine
HTTP_SOURCES = \
	$(HTTP_DIR)/response.c \
	$(HTTP_DIR)/extension_lookup.c \
	$(HTTP_DIR)/silent_blocker.c \
	$(HTTP_DIR)/reverse_proxy.c

# Anti-adblock system
ANTI_ADBLOCK_SOURCES = \
	$(ANTI_ADBLOCK_DIR)/anti_adblock.c \
	$(ANTI_ADBLOCK_DIR)/browser_detection.c \
	$(ANTI_ADBLOCK_DIR)/timing_jitter.c

# TLS layer (v1 integration)
TLS_SOURCES = \
	$(SRC_DIR)/version.c \
	$(SRC_DIR)/tls/sni_extractor.c \
	$(SRC_DIR)/cert/ca_loader.c \
	$(SRC_DIR)/cert/cert_cache.c \
	$(SRC_DIR)/cert/cert_generator.c \
	$(SRC_DIR)/cert/cert_index.c \
	$(SRC_DIR)/cert/cert_maintenance.c \
	$(SRC_DIR)/cert/second_level_tlds.c \
	$(SRC_DIR)/crypto/keypool.c \
	$(SRC_DIR)/pki/pki_manager.c \
	$(SRC_DIR)/util/logger.c \
	$(SRC_DIR)/util/util.c \
	$(SRC_DIR)/util/address_validation.c \
	$(SRC_DIR)/util/html_loader.c \
	$(SRC_DIR)/ipc/shm_manager.c \
	$(SRC_DIR)/ipc/ha_leader.c \
	$(SRC_DIR)/config/config_file.c \
	$(SRC_DIR)/config/config_generator.c \
	$(SRC_DIR)/security/security_intel.c

# Main sources
TLSGATENG_SOURCES = \
	$(SRC_DIR)/tlsgateNG.c \
	$(CORE_SOURCES) \
	$(HTTP_SOURCES) \
	$(ANTI_ADBLOCK_SOURCES) \
	$(TLS_SOURCES)

# ============================================================================
# Headers
# ============================================================================
HEADERS = \
	$(INCLUDE_DIR)/favicon.h \
	$(INCLUDE_DIR)/extension_hash_table.h \
	$(INCLUDE_DIR)/extension_lookup.h \
	$(INCLUDE_DIR)/connection.h \
	$(INCLUDE_DIR)/worker.h \
	$(INCLUDE_DIR)/response.h \
	$(INCLUDE_DIR)/anti_adblock.h \
	$(INCLUDE_DIR)/browser_detection.h \
	$(INCLUDE_DIR)/timing_jitter.h

# ============================================================================
# Build Targets (3 specialized binaries)
# ============================================================================
TLSGATE_POOLGEN = $(BUILD_DIR)/tlsgateNG-poolgen
TLSGATENGV4 = $(BUILD_DIR)/tlsgateNGv4
TLSGATENGV6 = $(BUILD_DIR)/tlsgateNGv6

# Sanitizer flags
ASAN_FLAGS = -fsanitize=address -fno-omit-frame-pointer -g
TSAN_FLAGS = -fsanitize=thread -g
UBSAN_FLAGS = -fsanitize=undefined -g

# ============================================================================
# EXTREME OPTIMIZATION FLAGS (Experimental - use at your own risk!)
# ============================================================================
# Base optimization flags
BASE_OPT = -O3 -march=native -mtune=native -flto=auto -DNDEBUG

# Aggressive optimization flags (may break on some systems)
AGGRESSIVE_OPT = \
	-fomit-frame-pointer \
	-ffast-math \
	-funroll-loops \
	-finline-functions \
	-fmerge-all-constants \
	-fno-semantic-interposition \
	-fno-plt \
	-fprefetch-loop-arrays \
	-fgcse-after-reload \
	-ftree-vectorize \
	-fipa-pta \
	-fdevirtualize-at-ltrans \
	-floop-nest-optimize

# SIMD optimizations (x86_64 with SSE4.2/AVX/AVX2)
SIMD_FLAGS = -msse4.2 -mavx -mavx2 -mfma

# Stack and security flags (PRODUCTION HARDENING!)
STACK_SEC_FLAGS = -fstack-protector-strong -Wl,-z,stack-size=2097152

# Maximum security hardening flags for production
# These add <1% overhead but provide massive security gains
SECURITY_HARDENING = \
	-D_FORTIFY_SOURCE=2 \
	-fPIE \
	-Wformat \
	-Werror=format-security \
	-fno-delete-null-pointer-checks

# Full production optimization (INSANE PERFORMANCE + MAXIMUM SECURITY!)
PRODUCTION_FLAGS = $(BASE_OPT) $(AGGRESSIVE_OPT) $(SIMD_FLAGS) $(STACK_SEC_FLAGS) $(SECURITY_HARDENING)

# LTO linker flags (aggressive link-time optimization + security hardening)
LTO_LDFLAGS = \
	-flto=auto \
	-fuse-linker-plugin \
	-Wl,-O3 \
	-Wl,--as-needed \
	-Wl,-z,relro \
	-Wl,-z,now \
	-Wl,-z,noexecstack \
	-pie

.PHONY: all clean install uninstall dirs help address thread analyze production secure jitter memcheck fullcheck \
        check-iouring install-iouring-deps backend-info setup-test-ca headercheck

all: dirs $(TLSGATE_POOLGEN) $(TLSGATENGV4) $(TLSGATENGV6)

dirs:
	@mkdir -p $(BUILD_DIR)

# ============================================================================
# PRODUCTION BUILD (3 specialized binaries with EXTREME optimization)
# ============================================================================

# Build production flags with conditional curl/iouring support
PROD_BASE_CFLAGS = -Wall -Wextra -Wpedantic -std=gnu11 -Iinclude -Isrc $(OPENSSL_CFLAGS) $(PRODUCTION_FLAGS)
PROD_BASE_LDFLAGS = -pthread $(OPENSSL_LDFLAGS) -lssl -lcrypto -lz -lrt -lm $(LTO_LDFLAGS)

# Add curl flags if available
ifeq ($(HAS_CURL),yes)
    PROD_BASE_CFLAGS += -DHAVE_CURL $(shell pkg-config --cflags libcurl)
    PROD_BASE_LDFLAGS += $(shell pkg-config --libs libcurl)
endif

# Add io_uring flags if available
ifeq ($(HAS_IOURING),yes)
    PROD_BASE_CFLAGS += -DHAVE_IOURING $(shell pkg-config --cflags liburing)
    PROD_BASE_LDFLAGS += $(shell pkg-config --libs liburing)
endif

production: clean dirs
	@echo "╔════════════════════════════════════════════════════════╗"
	@echo "║  🚀 EXTREME PRODUCTION BUILD - INSANE PERFORMANCE!    ║"
	@echo "╚════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Optimizations:"
	@echo "  - Base:     -O3 -march=native -mtune=native -flto=auto"
	@echo "  - Inlining: -finline-functions -fdevirtualize-at-ltrans"
	@echo "  - Math:     -ffast-math -fmerge-all-constants"
	@echo "  - Loops:    -funroll-loops -fprefetch-loop-arrays"
	@echo "  - SIMD:     -msse4.2 -mavx -mavx2 -mfma"
	@echo "  - LTO:      -fuse-linker-plugin -Wl,-O3"
	@echo "  - IPA:      -fipa-pta -fgcse-after-reload"
	@echo "  - Stack:    2MB per thread (optimized)"
	@echo ""
	@echo "Backend: $(IO_BACKEND)"
	@echo ""
	@echo "Building tlsgateNG-poolgen (pure keypool generator)..."
	$(CC) $(PROD_BASE_CFLAGS) -DPOOLGEN_ONLY -o $(TLSGATE_POOLGEN) $(TLSGATENG_SOURCES) $(PROD_BASE_LDFLAGS)
	@strip --strip-all $(TLSGATE_POOLGEN)
	@echo "✅ Poolgen: $(TLSGATE_POOLGEN) ($$(du -h $(TLSGATE_POOLGEN) | cut -f1))"
	@echo ""
	@echo "Building tlsgateNGv4 (IPv4-optimized network server)..."
	$(CC) $(PROD_BASE_CFLAGS) -DIPV4_OPTIMIZED -o $(TLSGATENGV4) $(TLSGATENG_SOURCES) $(PROD_BASE_LDFLAGS)
	@strip --strip-all $(TLSGATENGV4)
	@echo "✅ IPv4:    $(TLSGATENGV4) ($$(du -h $(TLSGATENGV4) | cut -f1))"
	@echo ""
	@echo "Building tlsgateNGv6 (IPv6-optimized network server)..."
	$(CC) $(PROD_BASE_CFLAGS) -DIPV6_OPTIMIZED -o $(TLSGATENGV6) $(TLSGATENG_SOURCES) $(PROD_BASE_LDFLAGS)
	@strip --strip-all $(TLSGATENGV6)
	@echo "✅ IPv6:    $(TLSGATENGV6) ($$(du -h $(TLSGATENGV6) | cut -f1))"
	@echo ""
	@echo "╔════════════════════════════════════════════════════════╗"
	@echo "║  ✅ EXTREME PRODUCTION BUILD COMPLETE!                ║"
	@echo "╚════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Architecture:"
	@echo "  1× Poolgen:  $(TLSGATE_POOLGEN)"
	@echo "                 └─ Pure keypool generator (no network ports)"
	@echo "                 └─ Fills shared memory with pre-generated keys"
	@echo ""
	@echo "  N× IPv4:     $(TLSGATENGV4)"
	@echo "                 └─ IPv4-optimized network server"
	@echo "                 └─ Consumes keys from shared memory pool"
	@echo ""
	@echo "  N× IPv6:     $(TLSGATENGV6)"
	@echo "                 └─ IPv6-optimized network server"
	@echo "                 └─ Consumes keys from shared memory pool"
	@echo ""
	@echo "Optimizations: $(IO_BACKEND) backend + SIMD + LTO + IPA + Loop Unrolling"
	@echo "Stack: 2MB per thread (hardened)"
	@echo ""
	@echo "🎯 Ready for EXTREME production deployment!"
	@echo ""

# ============================================================================
# Individual Binary Targets (for development/testing)
# ============================================================================

$(TLSGATE_POOLGEN): $(TLSGATENG_SOURCES) $(HEADERS)
	@echo "╔════════════════════════════════════════════════════════╗"
	@echo "║  Building Keypool Generator (Pure Generator)          ║"
	@echo "╚════════════════════════════════════════════════════════╝"
	@echo ""
	$(CC) $(CFLAGS) $(STACK_SEC_FLAGS) -DPOOLGEN_ONLY -o $@ $(filter %.c,$^) $(LDFLAGS)
	@echo ""
	@echo "✅ Built: $@"
	@echo "   Role: Pure keypool generator (no network ports)"
	@echo "   Run: $@ --poolkeygen --shm -D /opt/TLSGateNX"
	@echo ""

$(TLSGATENGV4): $(TLSGATENG_SOURCES) $(HEADERS)
	@echo "╔════════════════════════════════════════════════════════╗"
	@echo "║  Building TLSGate NX - IPv4 Optimized                 ║"
	@echo "╚════════════════════════════════════════════════════════╝"
	@echo ""
	$(CC) $(CFLAGS) $(STACK_SEC_FLAGS) -DIPV4_OPTIMIZED -o $@ $(filter %.c,$^) $(LDFLAGS)
	@echo ""
	@echo "✅ Built: $@"
	@echo "   Backend: $(IO_BACKEND)"
	@echo "   Stack: 2MB per thread (optimized)"
	@echo "   IPv4: Optimized for IPv4 traffic"
	@echo "   Capacity: 200K connections (4 workers × 50K)"
	@echo ""

$(TLSGATENGV6): $(TLSGATENG_SOURCES) $(HEADERS)
	@echo "╔════════════════════════════════════════════════════════╗"
	@echo "║  Building TLSGate NX - IPv6 Optimized                 ║"
	@echo "╚════════════════════════════════════════════════════════╝"
	@echo ""
	$(CC) $(CFLAGS) $(STACK_SEC_FLAGS) -DIPV6_OPTIMIZED -o $@ $(filter %.c,$^) $(LDFLAGS)
	@echo ""
	@echo "✅ Built: $@"
	@echo "   Backend: $(IO_BACKEND)"
	@echo "   Stack: 2MB per thread (optimized)"
	@echo "   IPv6: Optimized for IPv6 traffic"
	@echo "   Capacity: 200K connections (4 workers × 50K)"
	@echo ""

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "✅ Clean complete"

# ============================================================================
# Benchmark Targets
# ============================================================================

benchmark: $(BUILD_DIR)/cert-benchmark
	@echo ""
	@echo "╔════════════════════════════════════════════════════════╗"
	@echo "║  🔬 Running Certificate Generation Benchmark           ║"
	@echo "║     (RSA, Transparent Optimization)                    ║"
	@echo "╚════════════════════════════════════════════════════════╝"
	@echo ""
	@$(BUILD_DIR)/cert-benchmark
	@echo ""

$(BUILD_DIR)/cert-benchmark: tools/cert_benchmark.c
	@mkdir -p $(BUILD_DIR)
	@echo "Building certificate benchmark..."
	@$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "✅ Built: $@"

# ============================================================================
# Installation Targets
# ============================================================================

# Installation paths (customizable via PREFIX)
PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
SYSCONFDIR = /etc/tlsgateNG
DATADIR = $(PREFIX)/share/tlsgateNG

install: all
	@echo "╔════════════════════════════════════════════════════════╗"
	@echo "║  📦 Installing TLSGate NX                             ║"
	@echo "╚════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Installing binaries to $(BINDIR)..."
	@install -D -m 755 $(TLSGATE_POOLGEN) $(BINDIR)/tlsgateNG-poolgen
	@install -D -m 755 $(TLSGATENGV4) $(BINDIR)/tlsgateNGv4
	@install -D -m 755 $(TLSGATENGV6) $(BINDIR)/tlsgateNGv6
	@echo "✅ Binaries installed"
	@echo ""
	@echo "Creating system configuration directory..."
	@install -d -m 755 $(SYSCONFDIR)
	@echo "✅ Created $(SYSCONFDIR)"
	@echo ""
	@echo "Installing TLD list (second-level TLDs)..."
	@if [ -f tld-liste ]; then \
		install -D -m 644 tld-liste $(SYSCONFDIR)/second-level-tlds.dat; \
		echo "✅ Installed $(SYSCONFDIR)/second-level-tlds.dat"; \
	else \
		echo "⚠️  Warning: tld-liste file not found in repository"; \
	fi
	@echo ""
	@echo "Installing example configuration..."
	@if [ -f examples/tlsgateNG.conf.example ] && [ ! -f $(SYSCONFDIR)/tlsgateNG.conf ]; then \
		install -D -m 644 examples/tlsgateNG.conf.example $(SYSCONFDIR)/tlsgateNG.conf.example; \
		echo "✅ Installed $(SYSCONFDIR)/tlsgateNG.conf.example"; \
		echo "   Edit and rename to tlsgateNG.conf to activate"; \
	else \
		echo "ℹ️  Skipped config (already exists or example not found)"; \
	fi
	@echo ""
	@echo "Installing silent-blocks configuration..."
	@if [ -f silent-blocks.conf ] && [ ! -f $(SYSCONFDIR)/silent-blocks.conf ]; then \
		install -D -m 644 silent-blocks.conf $(SYSCONFDIR)/silent-blocks.conf; \
		echo "✅ Installed $(SYSCONFDIR)/silent-blocks.conf"; \
	else \
		echo "ℹ️  Skipped silent-blocks.conf (already exists or not found)"; \
	fi
	@echo ""
	@echo "╔════════════════════════════════════════════════════════╗"
	@echo "║  ✅ Installation Complete!                            ║"
	@echo "╚════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Installed files:"
	@echo "  Binaries:"
	@echo "    - $(BINDIR)/tlsgateNG-poolgen"
	@echo "    - $(BINDIR)/tlsgateNGv4"
	@echo "    - $(BINDIR)/tlsgateNGv6"
	@echo ""
	@echo "  Configuration:"
	@echo "    - $(SYSCONFDIR)/second-level-tlds.dat"
	@echo "    - $(SYSCONFDIR)/tlsgateNG.conf.example"
	@echo "    - $(SYSCONFDIR)/silent-blocks.conf"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Edit $(SYSCONFDIR)/tlsgateNG.conf.example"
	@echo "  2. Copy to $(SYSCONFDIR)/tlsgateNG.conf"
	@echo "  3. Setup CA certificates (see documentation)"
	@echo "  4. Run: tlsgateNGv4 --help"
	@echo ""

uninstall:
	@echo "╔════════════════════════════════════════════════════════╗"
	@echo "║  🗑️  Uninstalling TLSGate NX                          ║"
	@echo "╚════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Removing binaries..."
	@rm -f $(BINDIR)/tlsgateNG-poolgen
	@rm -f $(BINDIR)/tlsgateNGv4
	@rm -f $(BINDIR)/tlsgateNGv6
	@echo "✅ Binaries removed"
	@echo ""
	@echo "⚠️  Configuration files in $(SYSCONFDIR) were NOT removed"
	@echo "   To remove configuration:"
	@echo "   sudo rm -rf $(SYSCONFDIR)"
	@echo ""
	@echo "✅ Uninstall complete"
	@echo ""

# ============================================================================
# Sanitizer & Analysis Targets
# ============================================================================

address: CFLAGS += $(ASAN_FLAGS)
address: LDFLAGS += $(ASAN_FLAGS)
address: clean dirs
	@echo "🔍 Building with AddressSanitizer..."
	$(CC) $(CFLAGS) -o $(TLSGATENGV4) $(TLSGATENG_SOURCES) $(LDFLAGS)
	@echo "✅ AddressSanitizer build complete: $(TLSGATENGV4)"
	@echo "   Run: ASAN_OPTIONS=detect_leaks=1 $(TLSGATENGV4) -p 8080 -l 127.0.0.1 -D /opt/TLSGateNX"

thread: CFLAGS += $(TSAN_FLAGS)
thread: LDFLAGS += $(TSAN_FLAGS)
thread: clean dirs
	@echo "🔍 Building with ThreadSanitizer..."
	$(CC) $(CFLAGS) -o $(TLSGATENGV4) $(TLSGATENG_SOURCES) $(LDFLAGS)
	@echo "✅ ThreadSanitizer build complete: $(TLSGATENGV4)"
	@echo "   Run: TSAN_OPTIONS=second_deadlock_stack=1 $(TLSGATENGV4) -p 8080 -l 127.0.0.1 -D /opt/TLSGateNX"

analyze: CFLAGS += $(UBSAN_FLAGS)
analyze: LDFLAGS += $(UBSAN_FLAGS)
analyze: clean dirs
	@echo "🔍 Building with UndefinedBehaviorSanitizer..."
	$(CC) $(CFLAGS) -o $(TLSGATENGV4) $(TLSGATENG_SOURCES) $(LDFLAGS)
	@echo "✅ UndefinedBehaviorSanitizer build complete: $(TLSGATENGV4)"
	@echo "   Run: $(TLSGATENGV4) -p 8080 -l 127.0.0.1 -D /opt/TLSGateNX"

secure: CFLAGS += -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wformat -Werror=format-security
secure: LDFLAGS += -Wl,-z,relro -Wl,-z,now
secure: clean dirs
	@echo "🔒 Building with security hardening..."
	$(CC) $(CFLAGS) -o $(TLSGATENGV4) $(TLSGATENG_SOURCES) $(LDFLAGS)
	@echo "✅ Secure build complete: $(TLSGATENGV4)"
	@echo "   Hardening: Stack protector, FORTIFY_SOURCE, RELRO, NOW binding"

jitter: CFLAGS += -DENABLE_TIMING_JITTER
jitter: clean dirs
	@echo "⏱️  Building with Timing Jitter enabled..."
	$(CC) $(CFLAGS) -o $(TLSGATENGV4) $(TLSGATENG_SOURCES) $(LDFLAGS)
	@echo "✅ Timing Jitter build complete: $(TLSGATENGV4)"
	@echo "   Jitter: Index/Favicon 80% instant, 20% 0-10ms | Others 5-20ms"
	@echo "   Enable at runtime: Set timing_jitter_enabled = 1"

memcheck: all
	@echo "🔍 Running Valgrind memcheck..."
	@command -v valgrind >/dev/null 2>&1 || { echo "❌ Error: valgrind not installed. Install with: apt-get install valgrind"; exit 1; }
	@echo "   Starting server on port 9999 (Ctrl+C to stop after testing)"
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \
		--verbose --log-file=valgrind-report.txt \
		$(TLSGATENGV4) -p 9999 -l 127.0.0.1 -D /tmp/testca &
	@sleep 2
	@echo "   Sending test request..."
	@curl -s http://127.0.0.1:9999/ > /dev/null || true
	@sleep 1
	@pkill -INT tlsgateNGv4 || true
	@sleep 1
	@echo "✅ Valgrind report saved to: valgrind-report.txt"
	@grep "ERROR SUMMARY" valgrind-report.txt || true

# Setup test CA for fullcheck (always regenerates for fresh test environment)
# Creates: Offline RootCA + Online SubCA (signed by RootCA)
# Structure: /ALGORITHM/rootCA/ contains rootca.crt (chain), subca.crt + subca.key (online signing)
setup-test-ca:
	@echo "🔧 Setting up test CA (SubCA mode)..."
	@rm -rf /tmp/testca /tmp/root-test-ca
	@mkdir -p /tmp/testca /tmp/root-test-ca
	@echo "   1. Generating offline RootCA (for chain validation only)..."
	@openssl ecparam -genkey -name prime256v1 -out /tmp/root-test-ca/rootca.key 2>/dev/null || \
		openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /tmp/root-test-ca/rootca.key 2>/dev/null || \
		(echo "❌ Error: Failed to generate root CA key"; exit 1)
	@openssl req -x509 -key /tmp/root-test-ca/rootca.key -out /tmp/root-test-ca/rootca.crt \
		-days 3650 -subj '/CN=TLSGate NX Root CA' -sha256 2>/dev/null || \
		(echo "❌ Error: Failed to create root CA certificate"; exit 1)
	@echo "   2. Generating SubCA CSR for each algorithm..."
	@echo "basicConstraints = CA:TRUE" > /tmp/ca_ext.txt
	@for subca in RSA ECDSA SM2; do \
		mkdir -p /tmp/testca/$$subca/rootCA; \
		mkdir -p /tmp/testca/$$subca/certs; \
		mkdir -p /tmp/testca/$$subca/index; \
		echo "      Generating $$subca SubCA..."; \
		(openssl ecparam -genkey -name prime256v1 -out /tmp/testca/$$subca/rootCA/subca.key 2>/dev/null || \
		 openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /tmp/testca/$$subca/rootCA/subca.key 2>/dev/null) && \
		openssl req -new -key /tmp/testca/$$subca/rootCA/subca.key \
			-out /tmp/testca/$$subca/rootCA/subca.csr \
			-subj "/CN=TLSGate NX SubCA $$subca" -sha256 2>/dev/null && \
		openssl x509 -req -in /tmp/testca/$$subca/rootCA/subca.csr \
			-CA /tmp/root-test-ca/rootca.crt -CAkey /tmp/root-test-ca/rootca.key \
			-CAcreateserial -extfile /tmp/ca_ext.txt \
			-out /tmp/testca/$$subca/rootCA/subca.crt \
			-days 3650 -sha256 2>/dev/null || true; \
		cp /tmp/root-test-ca/rootca.crt /tmp/testca/$$subca/rootCA/rootca.crt; \
		chmod 644 /tmp/testca/$$subca/rootCA/*; \
		rm -f /tmp/testca/$$subca/rootCA/subca.csr; \
	done
	@rm -f /tmp/ca_ext.txt
	@echo "✅ Test SubCA structure created:"
	@echo "   - Offline RootCA in /tmp/root-test-ca/ (not used by server)"
	@echo "   - Online SubCAs in /tmp/testca/{RSA,ECDSA,SM2}/"
	@echo "     Each with: rootCA/, certs/, index/"
	@echo "   - Config is read from /etc/tlsgateNG/tlsgateNG.conf (must exist)"
	@echo "   - Config section [ca-TEST] points to /tmp/testca for testing"
	@echo "   - Each algorithm has its own: rootca.crt (chain), subca.crt + subca.key"
	@rm -rf /tmp/root-test-ca
	@echo ""

fullcheck: clean setup-test-ca
	@echo "🚀 Running full sanitizer suite..."
	@echo ""
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "1/5: AddressSanitizer (Memory errors, leaks)"
	@echo "═══════════════════════════════════════════════════════════════"
	@$(MAKE) address --no-print-directory
	@echo ""
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "2/5: ThreadSanitizer (Race conditions, deadlocks)"
	@echo "═══════════════════════════════════════════════════════════════"
	@$(MAKE) thread --no-print-directory
	@echo ""
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "3/5: UndefinedBehaviorSanitizer (UB detection)"
	@echo "═══════════════════════════════════════════════════════════════"
	@$(MAKE) analyze --no-print-directory
	@echo ""
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "4/5: Security Hardening Build"
	@echo "═══════════════════════════════════════════════════════════════"
	@$(MAKE) secure --no-print-directory
	@echo ""
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "5/5: Valgrind Memcheck"
	@echo "═══════════════════════════════════════════════════════════════"
	@$(MAKE) memcheck --no-print-directory
	@echo ""
	@echo "✅ Full sanitizer suite complete!"
	@echo "   Review valgrind-report.txt for detailed memory analysis"

# ============================================================================
# I/O Backend Setup & Requirements
# ============================================================================

check-iouring:
	@echo "Checking I/O backend requirements..."
	@echo ""
	@echo "Current backend: $(IO_BACKEND)"
ifeq ($(HAS_IOURING),yes)
	@echo "✅ io_uring is available and enabled"
	@pkg-config --modversion liburing | sed 's/^/   liburing version: /'
	@uname -r | sed 's/^/   Kernel version: /'
else
	@echo "❌ io_uring is NOT available"
	@echo ""
	@echo "⚠️  WARNING: For 200K+ connections, io_uring is ESSENTIAL!"
	@echo ""
	@echo "To install io_uring support:"
	@echo "  1. Check kernel version (need 5.1+): uname -r"
	@echo "  2. Install liburing:"
	@echo "     Ubuntu/Debian: apt-get install liburing-dev"
	@echo "     Fedora/RHEL:   dnf install liburing-devel"
	@echo "     Arch:          pacman -S liburing"
	@echo "  3. Rebuild: make clean && make"
	@echo ""
	@echo "Current fallback: epoll (limited to ~10K connections per process)"
endif

install-iouring-deps:
	@echo "Installing io_uring dependencies..."
	@if command -v apt-get >/dev/null 2>&1; then \
		sudo apt-get update && sudo apt-get install -y liburing-dev; \
	elif command -v dnf >/dev/null 2>&1; then \
		sudo dnf install -y liburing-devel; \
	elif command -v pacman >/dev/null 2>&1; then \
		sudo pacman -S --noconfirm liburing; \
	else \
		echo "❌ Unsupported package manager. Install liburing manually."; \
		exit 1; \
	fi
	@echo "✅ io_uring dependencies installed. Run 'make clean && make' to rebuild."

# ============================================================================
# Header Check (Missing Header Detection)
# ============================================================================

headercheck:
	@echo "╔════════════════════════════════════════════════════════╗"
	@echo "║  🔍 Header Check - Missing Header Detection            ║"
	@echo "╚════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Step 1: Checking OS and installing dependencies..."
	@if [ -f /etc/debian_version ]; then \
		echo "   Detected: Debian/Ubuntu"; \
		echo "   Installing required development packages..."; \
		sudo apt-get update -qq 2>/dev/null || true; \
		sudo apt-get install -y -qq build-essential libssl-dev libz-dev 2>/dev/null || true; \
		if pkg-config --exists liburing 2>/dev/null; then \
			sudo apt-get install -y -qq liburing-dev 2>/dev/null || true; \
		fi; \
		if pkg-config --exists libcurl 2>/dev/null; then \
			sudo apt-get install -y -qq libcurl4-openssl-dev 2>/dev/null || true; \
		fi; \
		echo "   ✅ Debian dependencies installed"; \
	elif [ "$$(uname)" = "FreeBSD" ]; then \
		echo "   Detected: FreeBSD"; \
		echo "   Installing required development packages..."; \
		sudo pkg install -y openssl liburing curl 2>/dev/null || true; \
		echo "   ✅ FreeBSD dependencies installed"; \
	else \
		echo "   ⚠️  Unknown OS - skipping automatic dependency installation"; \
		echo "   Supported: Debian/Ubuntu, FreeBSD"; \
	fi
	@echo ""
	@echo "Step 2: Checking for missing headers in source files..."
	@echo ""
	@ERRORS=0; \
	for src in $(TLSGATENG_SOURCES); do \
		OUTPUT=$$($(CC) -fsyntax-only $(CFLAGS) $$src 2>&1 | grep -E "(No such file|fatal error|not found)" || true); \
		if [ -n "$$OUTPUT" ]; then \
			echo "❌ $$src:"; \
			echo "$$OUTPUT" | sed 's/^/   /'; \
			ERRORS=$$((ERRORS + 1)); \
		fi; \
	done; \
	echo ""; \
	if [ $$ERRORS -eq 0 ]; then \
		echo "✅ All headers found! No missing dependencies."; \
	else \
		echo "❌ Found $$ERRORS file(s) with missing headers."; \
		echo "   Install the required development packages and re-run."; \
		exit 1; \
	fi
	@echo ""

backend-info:
	@echo "TLSGate NX I/O Backend Information"
	@echo "===================================="
	@echo ""
	@echo "Current backend:     $(IO_BACKEND)"
	@echo "io_uring available:  $(HAS_IOURING)"
	@echo "Operating system:    $(UNAME)"
	@echo ""
	@echo "Performance targets:"
	@echo "  io_uring:  200K+ connections per process (zero-copy I/O)"
	@echo "  kqueue:    100K+ connections per process (BSD/macOS)"
	@echo "  epoll:     10K connections per process (fallback)"

# ============================================================================
# Help
# ============================================================================

help:
	@echo "TLSGate NG v4.36 GEN4 - EXTREME Performance Build System"
	@echo "═══════════════════════════════════════════════════════════"
	@echo ""
	@echo "Current I/O Backend: $(IO_BACKEND)"
	@echo "SSL Library:         $(SSL_TYPE) ($(OPENSSL_DIR))"
	@echo ""
	@echo "Build Targets:"
	@echo "  all        - Build all 3 binaries (poolgen + v4 + v6)"
	@echo "  production - EXTREME optimization build (INSANE PERFORMANCE!)"
	@echo "  clean      - Remove build artifacts"
	@echo "  help       - Show this help"
	@echo ""
	@echo "Sanitizer & Analysis:"
	@echo "  address    - Build with AddressSanitizer (memory errors, leaks)"
	@echo "  thread     - Build with ThreadSanitizer (race conditions)"
	@echo "  analyze    - Build with UndefinedBehaviorSanitizer"
	@echo "  secure     - Build with security hardening flags"
	@echo "  jitter     - Build with Timing Jitter enabled (anti-fingerprinting)"
	@echo "  memcheck   - Run Valgrind memory analysis"
	@echo "  fullcheck  - Run all sanitizers sequentially"
	@echo ""
	@echo "I/O Backend Management:"
	@echo "  check-iouring        - Check io_uring availability"
	@echo "  install-iouring-deps - Install io_uring dependencies"
	@echo "  backend-info         - Show I/O backend information"
	@echo ""
	@echo "Development Tools:"
	@echo "  headercheck  - Check for missing headers (auto-installs deps)"
	@echo ""
	@echo "Binaries (3 specialized builds):"
	@echo "  $(TLSGATE_POOLGEN)  - Pure keypool generator (no network)"
	@echo "  $(TLSGATENGV4)      - IPv4 optimized server (2MB stack)"
	@echo "  $(TLSGATENGV6)      - IPv6 optimized server (2MB stack)"
	@echo ""
	@echo "Architecture:"
	@echo "  1× Poolgen: Fills shared memory keypool"
	@echo "  N× IPv4:    Consumes from shared memory keypool"
	@echo "  N× IPv6:    Consumes from shared memory keypool"
	@echo ""
	@echo "Examples:"
	@echo "  make production                        # EXTREME optimization build"
	@echo "  make all                               # Development build"
	@echo "  make check-iouring                     # Check I/O backend status"
	@echo "  make fullcheck                         # Run all sanitizers"
	@echo "  make OPENSSL_DIR=/custom/path all      # Build with custom OpenSSL"
	@echo ""
	@echo "Deployment:"
	@echo "  $(TLSGATE_POOLGEN) --poolkeygen --shm -D /opt/TLSGateNX"
	@echo "  $(TLSGATENGV4) -l 192.168.1.1 -p 80 -s 443 --shm -D /opt/TLSGateNX"
	@echo "  $(TLSGATENGV6) -l 2001:db8::1 -p 80 -s 443 --shm -D /opt/TLSGateNX"
	@echo ""
	@echo "Statistics:"
	@echo "  kill -USR1 <pid>  # Print worker statistics"
	@echo ""
	@echo "═══════════════════════════════════════════════════════════"
