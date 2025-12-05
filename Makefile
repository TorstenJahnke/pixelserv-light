# =============================================================================
# pixelserv-light - High-Performance TLS Pixel Server
# Portable Makefile for Linux, FreeBSD, OpenBSD, NetBSD, macOS
# =============================================================================

# Binary name
PROGNAME = pixelserv-tls

# Version (extracted from util.h or set manually)
VERSION ?= 2.5.6

# Source files
SRCS = pixelserv.c socket_handler.c certs.c logger.c util.c eventloop.c
OBJS = $(SRCS:.c=.o)

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
# Compiler and Flags
# =============================================================================
CC ?= cc
CFLAGS = -std=gnu11 -O2 -Wall -Wextra -Wno-unused-parameter
CFLAGS += -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L

# Debug build
ifdef DEBUG
    CFLAGS += -g -O0 -DDEBUG
endif

# Production build (no logging in hot paths)
ifdef PRODUCTION
    CFLAGS += -O3 -DNDEBUG -DPRODUCTION_BUILD
endif

# =============================================================================
# OpenSSL Detection
# =============================================================================
# Try pkg-config first
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null)

# Fallback if pkg-config fails
ifeq ($(OPENSSL_LIBS),)
    OPENSSL_CFLAGS = -I/usr/include -I/usr/local/include
    OPENSSL_LIBS = -lssl -lcrypto
endif

CFLAGS += $(OPENSSL_CFLAGS)
LDFLAGS += $(OPENSSL_LIBS)

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
# Pthread
# =============================================================================
LDFLAGS += -lpthread $(EXTRA_LDFLAGS)

# =============================================================================
# Build Targets
# =============================================================================
.PHONY: all clean install debug static static-ssl help info address thread analyze secure memcheck

all: $(PROGNAME)

$(PROGNAME): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Built $(PROGNAME) for $(UNAME_S)"
ifdef HAS_IO_URING
	@echo "  io_uring: enabled"
else
	@echo "  io_uring: disabled (install liburing-dev for best performance)"
endif

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Debug build with symbols and no optimization
debug:
	$(MAKE) DEBUG=1 all

# Production build - maximum performance, no logging
production:
	$(MAKE) PRODUCTION=1 CFLAGS="$(CFLAGS) -march=native -flto" all

# Static binary (for containers)
static: LDFLAGS += -static
static: all

# Static OpenSSL only (dynamic libc)
static-ssl:
	$(MAKE) OPENSSL_LIBS="-l:libssl.a -l:libcrypto.a -ldl" all

# BSI TR-02102-2 compliant build (strict cipher suite)
bsi-strict: CFLAGS += -DBSI_STRICT_CIPHERS
bsi-strict: all

# Chinese SM2/SM3/SM4 (Tongchou) build
tongchou: CFLAGS += -DENABLE_TONGCHOU
tongchou: all

# Combined static + tongchou
static-tongchou: CFLAGS += -DENABLE_TONGCHOU
static-tongchou: LDFLAGS += -static
static-tongchou: all

# =============================================================================
# Sanitizer and Analysis Targets
# =============================================================================

# AddressSanitizer - detect memory errors (buffer overflow, use-after-free, etc.)
address:
	$(MAKE) clean
	$(MAKE) CFLAGS="$(CFLAGS) -g -O1 -fsanitize=address -fno-omit-frame-pointer" \
		LDFLAGS="$(LDFLAGS) -fsanitize=address" all
	@echo "Built with AddressSanitizer - run binary to detect memory errors"

# ThreadSanitizer - detect data races
thread:
	$(MAKE) clean
	$(MAKE) CFLAGS="$(CFLAGS) -g -O1 -fsanitize=thread -fno-omit-frame-pointer" \
		LDFLAGS="$(LDFLAGS) -fsanitize=thread" all
	@echo "Built with ThreadSanitizer - run binary to detect data races"

# Static analysis with compiler warnings maxed out
analyze:
	$(MAKE) clean
	@echo "=== Static Analysis ==="
	$(MAKE) CFLAGS="$(CFLAGS) -g -O0 -fanalyzer -Wconversion -Wshadow -Wformat=2 \
		-Wcast-qual -Wcast-align -Wlogical-op -Wmissing-declarations \
		-Wredundant-decls -Wstrict-prototypes -Wold-style-definition" all 2>&1 | tee analyze.log
	@echo "Analysis complete. See analyze.log for details."

# Security-hardened build
secure:
	$(MAKE) clean
	$(MAKE) CFLAGS="$(CFLAGS) -g -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
		-fPIE -Wformat -Wformat-security" \
		LDFLAGS="$(LDFLAGS) -pie -Wl,-z,relro,-z,now" all
	@echo "Built with security hardening (FORTIFY_SOURCE, stack protector, PIE, RELRO)"

# Valgrind memcheck wrapper
memcheck: debug
	@echo "=== Valgrind Memcheck ==="
	@if command -v valgrind >/dev/null 2>&1; then \
		echo "Run: valgrind --leak-check=full --show-leak-kinds=all ./$(PROGNAME) [args]"; \
	else \
		echo "ERROR: valgrind not installed. Install with: apt install valgrind"; \
		exit 1; \
	fi

clean:
	rm -f $(OBJS) $(PROGNAME) config.h

install: $(PROGNAME)
	install -m 755 $(PROGNAME) /usr/local/bin/
	install -m 644 pixelserv-tls.1 /usr/local/share/man/man1/ 2>/dev/null || true
	@echo "Installed $(PROGNAME) to /usr/local/bin/"

# Show build configuration
info:
	@echo "=== pixelserv-light Build Info ==="
	@echo "OS:           $(UNAME_S)"
	@echo "CC:           $(CC)"
	@echo "CFLAGS:       $(CFLAGS)"
	@echo "LDFLAGS:      $(LDFLAGS)"
	@echo "OpenSSL:      $(OPENSSL_LIBS)"
ifdef HAS_IO_URING
	@echo "io_uring:     enabled"
else
	@echo "io_uring:     not available"
endif

help:
	@echo "pixelserv-light $(VERSION) - Build targets:"
	@echo ""
	@echo "  make              - Build with default settings"
	@echo "  make debug        - Build with debug symbols"
	@echo "  make production   - Build for production (max perf, no logs)"
	@echo "  make static       - Fully static binary"
	@echo "  make static-ssl   - Static OpenSSL, dynamic libc"
	@echo "  make bsi-strict   - BSI TR-02102-2 compliant ciphers"
	@echo "  make tongchou     - Enable SM2/SM3/SM4 ciphers"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make install      - Install to /usr/local/bin"
	@echo "  make info         - Show build configuration"
	@echo ""
	@echo "Environment variables:"
	@echo "  CC=clang          - Use different compiler"
	@echo "  DEBUG=1           - Enable debug build"
	@echo "  PRODUCTION=1      - Enable production build"

# Dependencies (auto-generated would be better, but this works)
pixelserv.o: pixelserv.c util.h certs.h socket_handler.h logger.h eventloop.h compat.h
socket_handler.o: socket_handler.c util.h certs.h socket_handler.h logger.h compat.h
certs.o: certs.c certs.h util.h logger.h compat.h
logger.o: logger.c logger.h
util.o: util.c util.h compat.h
eventloop.o: eventloop.c eventloop.h compat.h
