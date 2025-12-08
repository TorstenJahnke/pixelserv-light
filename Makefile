# =============================================================================
# tlsgate Makefile
# =============================================================================
#
# Targets:
#   all          - Build tlsgate binary
#   clean        - Remove build artifacts
#   install      - Install binary to PREFIX
#
# Analysis & Sanitizers:
#   address      - Build with AddressSanitizer (memory errors)
#   thread       - Build with ThreadSanitizer (data races)
#   ubsan        - Build with UndefinedBehaviorSanitizer
#   analyze      - Static analysis with GCC -fanalyzer
#   secure       - Security hardened build (stack protector, FORTIFY, PIE)
#   memcheck     - Build for Valgrind memcheck
#   fullcheck    - Run all analysis tools
#   headercheck  - Check for missing headers
#
# Production:
#   production   - Extreme optimized build (LTO, SIMD, aggressive opts)
#   debug        - Debug build with symbols
#
# SSL Variants:
#   tongchou     - Enable SM2/SM3/SM4 ciphers
#   bsi-strict   - BSI TR-02102-2 compliant ciphers
#
# Testing:
#   setup-test-ca - Create test CA structure
#   clean-test-ca - Remove test CA
#
# Configuration:
#   TONGSUO_PATH - Path to Tongsuo installation (enables SM2/SM3/SM4, static)
#   OPENSSL_PATH - Path to custom OpenSSL installation
#   STATIC_SSL   - Set to 1 for static SSL linking (OpenSSL only)
#   STATIC       - Set to 1 for fully static binary
#   DEBUG        - Set to 1 for debug build
#
# Examples:
#   make                                    # Dynamic, system OpenSSL
#   make TONGSUO_PATH=/opt/tongsuo          # Static Tongsuo (SM2/SM3/SM4)
#   make OPENSSL_PATH=/opt/openssl STATIC_SSL=1  # Static custom OpenSSL
#   make production                         # Extreme optimization
#   make fullcheck                          # All sanitizers + analysis
#
# =============================================================================

# Binary name
PROGNAME := tlsgate

# Version
VERSION ?= 2.5.6

# Installation paths
PREFIX      ?= /usr/local
BINDIR      ?= $(PREFIX)/bin
MANDIR      ?= $(PREFIX)/share/man/man1
PEM_PATH    ?= /var/cache/pixelserv

# Compiler
CC ?= gcc

# =============================================================================
# OS Detection
# =============================================================================
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
    OS = linux
    EXTRA_LDFLAGS = -lrt
endif
ifeq ($(UNAME_S),FreeBSD)
    OS = freebsd
endif
ifeq ($(UNAME_S),OpenBSD)
    OS = openbsd
endif
ifeq ($(UNAME_S),NetBSD)
    OS = netbsd
endif
ifeq ($(UNAME_S),Darwin)
    OS = macos
    EXTRA_LDFLAGS = -framework Security
endif

# =============================================================================
# SSL/TLS Library Configuration
# =============================================================================

# Default: system OpenSSL via pkg-config
SSL_CFLAGS  := $(shell pkg-config --cflags openssl 2>/dev/null)
SSL_LDFLAGS :=
SSL_LIBS    := $(shell pkg-config --libs openssl 2>/dev/null)

# Fallback if pkg-config fails
ifeq ($(SSL_LIBS),)
    SSL_CFLAGS  = -I/usr/include -I/usr/local/include
    SSL_LIBS    = -lssl -lcrypto
endif

# Tongsuo (SM2/SM3/SM4 support) - always static linked
ifdef TONGSUO_PATH
    # Auto-detect lib vs lib64 (use wildcard for portability), allow override
    TONGSUO_LIBDIR ?= $(if $(wildcard $(TONGSUO_PATH)/lib64/libssl.a),lib64,lib)
    SSL_CFLAGS  := -I$(TONGSUO_PATH)/include -DENABLE_TONGCHOU -DHAVE_SM2 -DHAVE_SM3 -DHAVE_SM4
    SSL_LDFLAGS := -L$(TONGSUO_PATH)/$(TONGSUO_LIBDIR)
    SSL_LIBS    := $(TONGSUO_PATH)/$(TONGSUO_LIBDIR)/libssl.a $(TONGSUO_PATH)/$(TONGSUO_LIBDIR)/libcrypto.a -ldl
    $(info Using Tongsuo (static) from $(TONGSUO_PATH)/$(TONGSUO_LIBDIR))
endif

# Custom OpenSSL path
ifdef OPENSSL_PATH
ifndef TONGSUO_PATH
    # Auto-detect lib vs lib64 (use wildcard for portability), allow override
    OPENSSL_LIBDIR ?= $(if $(wildcard $(OPENSSL_PATH)/lib64/libssl.a),lib64,lib)
    SSL_CFLAGS  := -I$(OPENSSL_PATH)/include
    SSL_LDFLAGS := -L$(OPENSSL_PATH)/$(OPENSSL_LIBDIR)
    ifeq ($(STATIC_SSL),1)
        SSL_LIBS := $(OPENSSL_PATH)/$(OPENSSL_LIBDIR)/libssl.a $(OPENSSL_PATH)/$(OPENSSL_LIBDIR)/libcrypto.a -ldl
        $(info Using OpenSSL (static) from $(OPENSSL_PATH)/$(OPENSSL_LIBDIR))
    else
        SSL_LIBS := -lssl -lcrypto -Wl,-rpath,$(OPENSSL_PATH)/$(OPENSSL_LIBDIR)
        $(info Using OpenSSL (dynamic) from $(OPENSSL_PATH)/$(OPENSSL_LIBDIR))
    endif
endif
endif

# =============================================================================
# Source Files
# =============================================================================

# Common sources for all platforms
SRCS := tlsgate_async.c certs.c logger.c util.c async_connection.c

# UDP Index support for high-throughput DGA scenarios
# Enabled by default - disable with DISABLE_UDP_INDEX=1
ifndef DISABLE_UDP_INDEX
    SRCS += src/index_udp.c src/cert_index_sharded.c src/cert_index.c
    BASE_CFLAGS += -DENABLE_UDP_INDEX
    $(info UDP index support: enabled)
else
    $(info UDP index support: disabled)
endif

# Platform-specific event loop backend
ifeq ($(UNAME_S),Linux)
    # Check if liburing is available
    ifneq ($(wildcard /usr/include/liburing.h),)
        SRCS += io_uring_backend.c
        CFLAGS += -DHAVE_IO_URING
        LDLIBS += -luring
        $(info Using io_uring backend for Linux)
    else
        SRCS += poll_backend.c
        CFLAGS += -DHAVE_POLL_BACKEND
        $(info Using poll backend for Linux - liburing not available)
    endif
else ifeq ($(UNAME_S),FreeBSD)
    SRCS += kqueue_backend.c
    CFLAGS += -DHAVE_KQUEUE
    $(info Using kqueue backend for FreeBSD)
else ifeq ($(UNAME_S),Darwin)
    SRCS += kqueue_backend.c
    CFLAGS += -DHAVE_KQUEUE
    $(info Using kqueue backend for macOS)
else
    $(error Unsupported platform: $(UNAME_S). Supported: Linux, FreeBSD, Darwin)
endif

OBJS := $(SRCS:.c=.o)

# TLSGate (ultra-scale architecture) - Alternative implementation in src/
# Use "make tlsgate-alt" to build this version
TLSGATE_SRCS := src/tlsgate.c src/connection.c src/buffer_pool.c src/worker.c src/response.c
TLSGATE_OBJS := $(TLSGATE_SRCS:.c=.o)
TLSGATE_BIN := tlsgate-alt

# Build directory for sanitizer builds
OBJDIR := build

# =============================================================================
# Compiler Flags
# =============================================================================

# Base flags
BASE_CFLAGS := -std=gnu11 -Wall -Wextra -Wno-unused-parameter
BASE_CFLAGS += -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L
BASE_CFLAGS += -DDROP_ROOT
BASE_CFLAGS += -ffunction-sections -fdata-sections
BASE_CFLAGS += $(SSL_CFLAGS)

# Release vs Debug
ifeq ($(DEBUG),1)
    OPT_CFLAGS := -g -O0 -DDEBUG
    $(info Debug build enabled)
else
    OPT_CFLAGS := -O2
endif

# Production build flags (set via target)
ifdef PRODUCTION
    OPT_CFLAGS := -O3 -DNDEBUG -DPRODUCTION_BUILD
endif

CFLAGS := $(BASE_CFLAGS) $(OPT_CFLAGS)

# =============================================================================
# Linker Flags
# =============================================================================

LDFLAGS := $(SSL_LDFLAGS) $(SSL_LIBS) -lpthread $(EXTRA_LDFLAGS)

ifeq ($(STATIC),1)
    LDFLAGS += -static
    $(info Building fully static binary)
endif

# Strip for release builds
ifneq ($(DEBUG),1)
ifndef PRODUCTION
    # Don't strip here, do it in production target
endif
endif

# =============================================================================
# io_uring Detection (Linux only)
# =============================================================================
ifeq ($(OS),linux)
    LIBURING_LIBS := $(shell pkg-config --libs liburing 2>/dev/null)
    ifneq ($(LIBURING_LIBS),)
        CFLAGS += -DHAVE_IO_URING $(shell pkg-config --cflags liburing 2>/dev/null)
        LDFLAGS += $(LIBURING_LIBS)
        HAS_IO_URING = 1
    endif
endif

# =============================================================================
# Build Targets
# =============================================================================

.PHONY: all clean install uninstall debug info help
.PHONY: address thread ubsan analyze secure memcheck fullcheck headercheck
.PHONY: production static static-ssl tongchou bsi-strict
.PHONY: setup-test-ca clean-test-ca
.PHONY: tlsgate tlsgate-debug tlsgate-production

all: $(PROGNAME)
	@echo ""
	@echo "Built $(PROGNAME) for $(UNAME_S)"
ifdef HAS_IO_URING
	@echo "  io_uring: enabled"
else
	@echo "  io_uring: disabled (install liburing-dev for best performance)"
endif
ifdef TONGSUO_PATH
	@echo "  SSL: Tongsuo (SM2/SM3/SM4 enabled)"
else ifdef OPENSSL_PATH
	@echo "  SSL: OpenSSL from $(OPENSSL_PATH)"
else
	@echo "  SSL: System OpenSSL"
endif
	@echo ""

$(PROGNAME): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Debug build
debug:
	$(MAKE) DEBUG=1 all

# =============================================================================
# TLSGate - Ultra-Scale Architecture (10M+ concurrent connections)
# =============================================================================

tlsgate-alt: $(TLSGATE_OBJS)
	$(CC) $(CFLAGS) -o $(TLSGATE_BIN) $^ $(LDFLAGS)
	@echo ""
	@echo "Built $(TLSGATE_BIN) - Ultra-Scale TLS Server (Alternative)"
	@echo "  Architecture: Event-driven, lock-free"
	@echo "  Target: 10M+ concurrent connections"
	@echo ""

tlsgate-alt-debug:
	$(MAKE) DEBUG=1 tlsgate-alt

tlsgate-production: CFLAGS += -O3 -march=native -flto -DNDEBUG
tlsgate-production: LDFLAGS += -flto
tlsgate-production: tlsgate
	strip $(TLSGATE_BIN)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -I include -c -o $@ $<

# =============================================================================
# Static Builds
# =============================================================================

static: LDFLAGS += -static
static: all

static-ssl:
	$(MAKE) OPENSSL_LIBS="-l:libssl.a -l:libcrypto.a -ldl" all

# =============================================================================
# Cipher Suite Variants
# =============================================================================

bsi-strict: CFLAGS += -DBSI_STRICT_CIPHERS
bsi-strict: all

tongchou: CFLAGS += -DENABLE_TONGCHOU
tongchou: all

static-tongchou: CFLAGS += -DENABLE_TONGCHOU
static-tongchou: LDFLAGS += -static
static-tongchou: all

# =============================================================================
# Sanitizers and Analysis
# =============================================================================

# Test binary name for sanitizer builds
TEST_BIN := $(PROGNAME)-test

# AddressSanitizer - detect memory errors
address:
	@echo ""
	@echo "=== AddressSanitizer Build ==="
	@echo ""
	$(MAKE) clean
	$(CC) $(BASE_CFLAGS) -g -O1 -fsanitize=address -fno-omit-frame-pointer \
		$(SRCS) $(LDFLAGS) -fsanitize=address -o $(TEST_BIN)
	@echo ""
	@echo "Binary: $(TEST_BIN)"
	@echo "Run with: ASAN_OPTIONS=detect_leaks=1 ./$(TEST_BIN) [args]"
	@echo ""

# ThreadSanitizer - detect data races
thread:
	@echo ""
	@echo "=== ThreadSanitizer Build ==="
	@echo ""
	$(MAKE) clean
	$(CC) $(BASE_CFLAGS) -g -O1 -fsanitize=thread -fno-omit-frame-pointer \
		$(SRCS) $(LDFLAGS) -fsanitize=thread -o $(TEST_BIN)
	@echo ""
	@echo "Binary: $(TEST_BIN)"
	@echo "Run with: TSAN_OPTIONS=second_deadlock_stack=1 ./$(TEST_BIN) [args]"
	@echo ""

# UndefinedBehaviorSanitizer - detect undefined behavior
ubsan:
	@echo ""
	@echo "=== UndefinedBehaviorSanitizer Build ==="
	@echo ""
	$(MAKE) clean
	$(CC) $(BASE_CFLAGS) -g -O1 -fsanitize=undefined -fno-omit-frame-pointer \
		$(SRCS) $(LDFLAGS) -fsanitize=undefined -o $(TEST_BIN)
	@echo ""
	@echo "Binary: $(TEST_BIN)"
	@echo "Run with: UBSAN_OPTIONS=print_stacktrace=1 ./$(TEST_BIN) [args]"
	@echo ""

# Static analysis with GCC -fanalyzer
analyze:
	@echo ""
	@echo "=== Static Analysis (GCC -fanalyzer) ==="
	@echo ""
	$(MAKE) clean
	@for src in $(SRCS); do \
		echo "Analyzing $$src..."; \
		$(CC) $(BASE_CFLAGS) -fanalyzer -Wconversion -Wshadow -Wformat=2 \
			-Wcast-qual -Wlogical-op -Wmissing-declarations \
			-Wstrict-prototypes -c $$src -o /dev/null 2>&1 || true; \
	done
	@echo ""
	@echo "=== Analysis Complete ==="
	@echo ""

# Security hardened build
secure:
	@echo ""
	@echo "=== Security Hardened Build ==="
	@echo ""
	$(MAKE) clean
	$(CC) $(BASE_CFLAGS) -g -O2 \
		-fstack-protector-strong \
		-D_FORTIFY_SOURCE=2 \
		-Wformat -Wformat-security \
		-fPIE \
		$(SRCS) $(LDFLAGS) -pie -Wl,-z,relro,-z,now -o $(TEST_BIN)
	@echo ""
	@echo "Security features enabled:"
	@echo "  - Stack protector (strong)"
	@echo "  - FORTIFY_SOURCE=2"
	@echo "  - Position Independent Executable (PIE)"
	@echo "  - Full RELRO"
	@echo ""
	@if command -v checksec >/dev/null 2>&1; then \
		checksec --file=$(TEST_BIN); \
	fi
	@echo ""

# Valgrind memcheck preparation
memcheck:
	@echo ""
	@echo "=== Valgrind Memcheck Build ==="
	@echo ""
	$(MAKE) clean
	$(CC) $(BASE_CFLAGS) -g -O0 $(SRCS) $(LDFLAGS) -o $(TEST_BIN)
	@echo ""
	@echo "Binary: $(TEST_BIN)"
	@if command -v valgrind >/dev/null 2>&1; then \
		echo "Run: valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./$(TEST_BIN) [args]"; \
	else \
		echo "ERROR: valgrind not installed. Install with: apt install valgrind"; \
	fi
	@echo ""

# Header check - find missing includes
headercheck:
	@echo ""
	@echo "=== Header Check ==="
	@echo ""
	@ERRORS=0; \
	for src in $(SRCS); do \
		OUTPUT=$$($(CC) -fsyntax-only $(BASE_CFLAGS) $$src 2>&1 | grep -E "(No such file|fatal error|not found)" || true); \
		if [ -n "$$OUTPUT" ]; then \
			echo "ERROR: $$src"; \
			echo "$$OUTPUT" | sed 's/^/  /'; \
			ERRORS=$$((ERRORS + 1)); \
		fi; \
	done; \
	echo ""; \
	if [ $$ERRORS -eq 0 ]; then \
		echo "All headers found."; \
	else \
		echo "Found $$ERRORS file(s) with missing headers."; \
		exit 1; \
	fi
	@echo ""

# Full check - run all analysis tools
fullcheck: setup-test-ca
	@echo ""
	@echo "######################################################"
	@echo "#           FULL CODE ANALYSIS                       #"
	@echo "######################################################"
	@echo ""
	$(MAKE) headercheck
	@echo ""
	$(MAKE) analyze
	@echo ""
	$(MAKE) address
	@echo ""
	$(MAKE) thread
	@echo ""
	$(MAKE) ubsan
	@echo ""
	$(MAKE) secure
	@echo ""
	$(MAKE) memcheck
	@echo ""
	@echo "######################################################"
	@echo "#           FULL CHECK COMPLETE                      #"
	@echo "######################################################"
	@echo ""
	@echo "Test CA: $(TEST_CA_DIR)"
	@echo ""
	@echo "Run sanitizer binaries manually:"
	@echo "  AddressSanitizer: ASAN_OPTIONS=detect_leaks=1 ./$(TEST_BIN) -D $(TEST_CA_DIR)"
	@echo "  ThreadSanitizer:  TSAN_OPTIONS=second_deadlock_stack=1 ./$(TEST_BIN) -D $(TEST_CA_DIR)"
	@echo "  UBSan:            UBSAN_OPTIONS=print_stacktrace=1 ./$(TEST_BIN) -D $(TEST_CA_DIR)"
	@echo "  Valgrind:         valgrind --leak-check=full ./$(TEST_BIN) -D $(TEST_CA_DIR)"
	@echo ""

# =============================================================================
# Production Build (Extreme Optimization)
# =============================================================================

# Aggressive optimization flags
PROD_OPT := -O3 -march=native -mtune=native -flto=auto -DNDEBUG -DPRODUCTION_BUILD
PROD_OPT += -fomit-frame-pointer -funroll-loops -finline-functions
PROD_OPT += -fmerge-all-constants -fno-plt
PROD_OPT += -ftree-vectorize

# LTO linker flags
LTO_LDFLAGS := -flto=auto -Wl,-O3 -Wl,--gc-sections -Wl,--as-needed

production:
	@echo ""
	@echo "######################################################"
	@echo "#     PRODUCTION BUILD - EXTREME OPTIMIZATION        #"
	@echo "######################################################"
	@echo ""
	$(MAKE) clean
	$(CC) $(BASE_CFLAGS) $(PROD_OPT) $(SRCS) $(LDFLAGS) $(LTO_LDFLAGS) -o $(PROGNAME)
	@strip --strip-all $(PROGNAME) 2>/dev/null || strip $(PROGNAME)
	@echo ""
	@echo "Optimizations applied:"
	@echo "  - LTO (Link Time Optimization)"
	@echo "  - Native CPU tuning (-march=native)"
	@echo "  - Loop unrolling"
	@echo "  - Function inlining"
	@echo "  - Tree vectorization"
	@echo "  - Stripped symbols"
	@echo ""
	@ls -la $(PROGNAME)
	@echo ""

# =============================================================================
# Test CA Setup
# =============================================================================

TEST_CA_DIR := /tmp/pixelserv-test-ca

setup-test-ca:
	@echo ""
	@echo "=== Setting up Test CA ==="
	@echo ""
	@rm -rf $(TEST_CA_DIR)
	@mkdir -p $(TEST_CA_DIR)/certs
	@echo "Creating CA key and certificate..."
	@openssl ecparam -genkey -name prime256v1 -out $(TEST_CA_DIR)/ca.key 2>/dev/null
	@openssl req -x509 -new -key $(TEST_CA_DIR)/ca.key -out $(TEST_CA_DIR)/ca.crt \
		-days 3650 -subj '/CN=pixelserv Test CA/O=pixelserv/C=DE' -sha256 2>/dev/null
	@chmod 600 $(TEST_CA_DIR)/ca.key
	@chmod 644 $(TEST_CA_DIR)/ca.crt
	@echo ""
	@echo "Test CA created at: $(TEST_CA_DIR)"
	@echo "  CA Cert: $(TEST_CA_DIR)/ca.crt"
	@echo "  CA Key:  $(TEST_CA_DIR)/ca.key"
	@echo ""
	@echo "Usage: ./$(PROGNAME) -p 80 -k 443 -D $(TEST_CA_DIR)"
	@echo ""

clean-test-ca:
	@rm -rf $(TEST_CA_DIR)
	@echo "Test CA removed."

# =============================================================================
# Installation
# =============================================================================

install: $(PROGNAME)
	@echo "Installing to $(BINDIR)..."
	@mkdir -p $(DESTDIR)$(BINDIR)
	@install -m 755 $(PROGNAME) $(DESTDIR)$(BINDIR)/
	@if [ -f tlsgate.1 ]; then \
		mkdir -p $(DESTDIR)$(MANDIR); \
		install -m 644 tlsgate.1 $(DESTDIR)$(MANDIR)/; \
	fi
	@echo "Installed $(PROGNAME) to $(BINDIR)"

uninstall:
	@rm -f $(DESTDIR)$(BINDIR)/$(PROGNAME)
	@rm -f $(DESTDIR)$(MANDIR)/tlsgate.1
	@echo "Uninstalled $(PROGNAME)"

# =============================================================================
# Cleanup
# =============================================================================

clean:
	@rm -f $(OBJS) $(PROGNAME) $(TEST_BIN) config.h analyze.log
	@rm -f $(TLSGATE_OBJS) $(TLSGATE_BIN)
	@rm -rf $(OBJDIR)
	@echo "Cleaned."

distclean: clean clean-test-ca
	@rm -f config.status config.log
	@rm -rf autom4te.cache .deps

# =============================================================================
# Info & Help
# =============================================================================

info:
	@echo ""
	@echo "tlsgate $(VERSION) Build Configuration"
	@echo "============================================"
	@echo ""
	@echo "Compiler:      $(CC)"
	@echo "OS:            $(UNAME_S)"
ifdef TONGSUO_PATH
	@echo "SSL Library:   Tongsuo ($(TONGSUO_PATH))"
else ifdef OPENSSL_PATH
	@echo "SSL Library:   OpenSSL ($(OPENSSL_PATH))"
else
	@echo "SSL Library:   System OpenSSL"
endif
ifdef HAS_IO_URING
	@echo "io_uring:      enabled"
else
	@echo "io_uring:      disabled"
endif
	@echo "Static:        $(if $(filter 1,$(STATIC)),yes,no)"
	@echo "Debug:         $(if $(filter 1,$(DEBUG)),yes,no)"
	@echo "Install:       $(BINDIR)"
	@echo ""

help:
	@echo ""
	@echo "tlsgate $(VERSION) - Build targets:"
	@echo ""
	@echo "  Building:"
	@echo "    make              - Build with default settings"
	@echo "    make debug        - Build with debug symbols"
	@echo "    make production   - Extreme optimized build (LTO, native)"
	@echo "    make static       - Fully static binary"
	@echo "    make static-ssl   - Static OpenSSL, dynamic libc"
	@echo ""
	@echo "  Cipher Suites:"
	@echo "    make bsi-strict   - BSI TR-02102-2 compliant ciphers"
	@echo "    make tongchou     - Enable SM2/SM3/SM4 ciphers"
	@echo ""
	@echo "  Analysis & Sanitizers:"
	@echo "    make address      - AddressSanitizer (memory errors)"
	@echo "    make thread       - ThreadSanitizer (data races)"
	@echo "    make ubsan        - UndefinedBehaviorSanitizer"
	@echo "    make analyze      - GCC static analyzer"
	@echo "    make secure       - Security hardened build"
	@echo "    make memcheck     - Valgrind preparation"
	@echo "    make headercheck  - Check for missing headers"
	@echo "    make fullcheck    - Run ALL analysis tools"
	@echo ""
	@echo "  Testing:"
	@echo "    make setup-test-ca  - Create test CA"
	@echo "    make clean-test-ca  - Remove test CA"
	@echo ""
	@echo "  Other:"
	@echo "    make clean        - Remove build artifacts"
	@echo "    make install      - Install to $(BINDIR)"
	@echo "    make info         - Show build configuration"
	@echo ""
	@echo "  Configuration Variables:"
	@echo "    TONGSUO_PATH=/path  - Use Tongsuo for SM2/SM3/SM4"
	@echo "    OPENSSL_PATH=/path  - Use custom OpenSSL"
	@echo "    STATIC_SSL=1        - Static link SSL library"
	@echo "    STATIC=1            - Fully static binary"
	@echo "    DEBUG=1             - Debug build"
	@echo ""

# =============================================================================
# Dependencies
# =============================================================================

tlsgate_async.o: tlsgate_async.c event_loop.h async_connection.h util.h certs.h logger.h compat.h
async_connection.o: async_connection.c async_connection.h util.h logger.h
io_uring_backend.o: io_uring_backend.c event_loop.h async_connection.h logger.h compat.h
kqueue_backend.o: kqueue_backend.c event_loop.h async_connection.h logger.h compat.h
certs.o: certs.c certs.h util.h logger.h compat.h
logger.o: logger.c logger.h
util.o: util.c util.h compat.h
