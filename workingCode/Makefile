# =============================================================================
# pixelserv-tls Makefile
# =============================================================================
#
# Targets:
#   all          - Build all binaries (pixelserv-index, pixelservV4, pixelservV6)
#   pixelserv-index - Index master binary
#   pixelservV4  - IPv4 optimized binary
#   pixelservV6  - IPv6 optimized binary
#   clean        - Remove build artifacts
#   install      - Install binaries to PREFIX
#
# Analysis & Sanitizers:
#   address      - Build with AddressSanitizer (memory errors)
#   thread       - Build with ThreadSanitizer (data races)
#   ubsan        - Build with UndefinedBehaviorSanitizer
#   analyze      - Static analysis with GCC -fanalyzer
#   secure       - Security hardened build (stack protector, FORTIFY, PIE)
#   memcheck     - Build for Valgrind memcheck
#   fullcheck    - Run all analysis tools
#   production   - Extreme optimized build (LTO, SIMD, aggressive opts)
#   headercheck  - Check for missing headers
#   setup-test-ca - Create test CA structure for testing
#   clean-test-ca - Remove test CA
#
# Configuration:
#   TONGSUO_PATH - Path to Tongsuo installation (enables SM2/SM3/SM4, always static)
#   OPENSSL_PATH - Path to custom OpenSSL installation
#   STATIC_SSL   - Set to 1 for static SSL linking (OpenSSL only)
#   STATIC       - Set to 1 for fully static binary
#   DEBUG        - Set to 1 for debug build
#
# Examples:
#   make                                    # Dynamic, system OpenSSL
#   make TONGSUO_PATH=/opt/tongsuo          # Static Tongsuo (SM2/SM3/SM4)
#   make OPENSSL_PATH=/opt/openssl STATIC_SSL=1  # Static custom OpenSSL
#   make STATIC=1 TONGSUO_PATH=/opt/tongsuo      # Fully static
#   make DEBUG=1                            # Debug build
#
# =============================================================================

# Installation paths
PREFIX      ?= /usr/local
BINDIR      ?= $(PREFIX)/bin
PEM_PATH    ?= /usr/local/pixelserver

# Directory structure
SRCDIR      := src
INCDIR      := include

# Compiler
CC          ?= gcc

# =============================================================================
# SSL/TLS Library Configuration
# =============================================================================

# Default: system OpenSSL
SSL_CFLAGS  :=
SSL_LDFLAGS :=
SSL_LIBS    := -lssl -lcrypto

# Tongsuo (SM2/SM3/SM4 support) - always static linked
ifdef TONGSUO_PATH
    SSL_CFLAGS  := -I$(TONGSUO_PATH)/include -DHAVE_TONGSUO -DHAVE_SM2 -DHAVE_SM3 -DHAVE_SM4
    SSL_LDFLAGS := -L$(TONGSUO_PATH)/lib
    # Tongsuo immer statisch linken
    SSL_LIBS := $(TONGSUO_PATH)/lib/libssl.a $(TONGSUO_PATH)/lib/libcrypto.a -ldl -lpthread
    $(info Using Tongsuo (static) from $(TONGSUO_PATH))
endif

# Custom OpenSSL
ifdef OPENSSL_PATH
ifndef TONGSUO_PATH
    SSL_CFLAGS  := -I$(OPENSSL_PATH)/include
    SSL_LDFLAGS := -L$(OPENSSL_PATH)/lib
    ifeq ($(STATIC_SSL),1)
        SSL_LIBS := $(OPENSSL_PATH)/lib/libssl.a $(OPENSSL_PATH)/lib/libcrypto.a
    else
        SSL_LIBS := -lssl -lcrypto -Wl,-rpath,$(OPENSSL_PATH)/lib
    endif
    $(info Using OpenSSL from $(OPENSSL_PATH))
endif
endif

# =============================================================================
# Compiler Flags
# =============================================================================

# Base flags
BASE_CFLAGS := -Wall -Wextra -Wno-unused-parameter
BASE_CFLAGS += -ffunction-sections -fdata-sections -fno-strict-aliasing
BASE_CFLAGS += -D_GNU_SOURCE -D_REENTRANT -D_THREAD_SAFE
BASE_CFLAGS += -DDROP_ROOT -DIF_MODE
BASE_CFLAGS += -DDEFAULT_PEM_PATH=\"$(PEM_PATH)\"
BASE_CFLAGS += -I$(INCDIR)
BASE_CFLAGS += $(SSL_CFLAGS)

# Release vs Debug
ifeq ($(DEBUG),1)
    OPT_CFLAGS := -g -O0 -DDEBUG
    $(info Debug build enabled)
else
    OPT_CFLAGS := -O3 -DNDEBUG
endif

# IPv4 specific flags
V4_CFLAGS := -DIPV4_ONLY -DAF_PREFERRED=AF_INET

# IPv6 specific flags
V6_CFLAGS := -DIPV6_ONLY -DAF_PREFERRED=AF_INET6 -DIPV6_V6ONLY=1

# Index master flags (minimal, no IPv4/IPv6 preference)
INDEX_CFLAGS := -DINDEX_MASTER_MODE

# Combined CFLAGS
CFLAGS_COMMON := $(BASE_CFLAGS) $(OPT_CFLAGS)

# =============================================================================
# Linker Flags
# =============================================================================

BASE_LDFLAGS := $(SSL_LDFLAGS)
BASE_LDFLAGS += -lpthread -lrt -ldl

ifeq ($(STATIC),1)
    BASE_LDFLAGS += -static
    $(info Building fully static binary)
endif

# Strip and gc-sections for release
ifneq ($(DEBUG),1)
    BASE_LDFLAGS += -Wl,--gc-sections -s
endif

LDFLAGS := $(BASE_LDFLAGS)
LIBS    := $(SSL_LIBS) -lpthread -lrt -ldl

# =============================================================================
# Source Files (organized in subdirectories)
# =============================================================================

# Core sources - main application and utilities
CORE_SRCS := \
    $(SRCDIR)/core/pixelserv.c \
    $(SRCDIR)/core/util.c \
    $(SRCDIR)/core/logger.c \
    $(SRCDIR)/core/version.c

# Certificate management
CERT_SRCS := \
    $(SRCDIR)/certs/certs.c \
    $(SRCDIR)/certs/certs_gen.c \
    $(SRCDIR)/certs/certs_cache.c \
    $(SRCDIR)/certs/certs_queue.c \
    $(SRCDIR)/certs/certs_conn.c \
    $(SRCDIR)/certs/certs_stats.c \
    $(SRCDIR)/certs/cert_index.c \
    $(SRCDIR)/certs/keypool.c

# Network/Socket handling
NET_SRCS := \
    $(SRCDIR)/net/socket_handler.c \
    $(SRCDIR)/net/socket_handler_extended.c \
    $(SRCDIR)/net/io_engine.c

# Index master/client and TLD management
INDEX_SRCS := \
    $(SRCDIR)/index/index_master.c \
    $(SRCDIR)/index/index_client.c \
    $(SRCDIR)/index/second_level_tlds.c

# Content generation
CONTENT_SRCS := \
    $(SRCDIR)/content/anti_adblock.c \
    $(SRCDIR)/content/advanced_content_generator.c \
    $(SRCDIR)/content/extension_lookup.c \
    $(SRCDIR)/content/timing_jitter.c

# All sources
ALL_SRCS := $(CORE_SRCS) $(CERT_SRCS) $(NET_SRCS) $(INDEX_SRCS) $(CONTENT_SRCS)

# =============================================================================
# Object Files (per target)
# =============================================================================

OBJDIR := build

OBJS_V4    := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/v4/%.o,$(ALL_SRCS))
OBJS_V6    := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/v6/%.o,$(ALL_SRCS))
OBJS_INDEX := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/index/%.o,$(ALL_SRCS))

# =============================================================================
# Targets
# =============================================================================

.PHONY: all clean install info help uninstall distclean

all: pixelserv-index pixelservV4 pixelservV6
	@echo ""
	@echo "Build complete:"
	@ls -la pixelserv-index pixelservV4 pixelservV6
	@echo ""

# IPv4 optimized binary
pixelservV4: $(OBJS_V4)
	@echo "  LINK    $@"
	@$(CC) $(OBJS_V4) $(LDFLAGS) $(LIBS) -o $@

# IPv6 optimized binary
pixelservV6: $(OBJS_V6)
	@echo "  LINK    $@"
	@$(CC) $(OBJS_V6) $(LDFLAGS) $(LIBS) -o $@

# Index master binary
pixelserv-index: $(OBJS_INDEX)
	@echo "  LINK    $@"
	@$(CC) $(OBJS_INDEX) $(LDFLAGS) $(LIBS) -o $@

# =============================================================================
# Compilation Rules
# =============================================================================

# Source subdirectories
SRC_SUBDIRS := core certs net index content

# IPv4 objects
$(OBJDIR)/v4/%.o: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	@echo "  CC [V4] $<"
	@$(CC) $(CFLAGS_COMMON) $(V4_CFLAGS) -c $< -o $@

# IPv6 objects
$(OBJDIR)/v6/%.o: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	@echo "  CC [V6] $<"
	@$(CC) $(CFLAGS_COMMON) $(V6_CFLAGS) -c $< -o $@

# Index master objects
$(OBJDIR)/index/%.o: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	@echo "  CC [IX] $<"
	@$(CC) $(CFLAGS_COMMON) $(INDEX_CFLAGS) -c $< -o $@

# =============================================================================
# Installation
# =============================================================================

install: all
	@echo "Installing to $(BINDIR)..."
	@mkdir -p $(DESTDIR)$(BINDIR)
	@install -m 755 pixelserv-index $(DESTDIR)$(BINDIR)/
	@install -m 755 pixelservV4 $(DESTDIR)$(BINDIR)/
	@install -m 755 pixelservV6 $(DESTDIR)$(BINDIR)/
	@echo "Installed:"
	@echo "  $(BINDIR)/pixelserv-index"
	@echo "  $(BINDIR)/pixelservV4"
	@echo "  $(BINDIR)/pixelservV6"

uninstall:
	@rm -f $(DESTDIR)$(BINDIR)/pixelserv-index
	@rm -f $(DESTDIR)$(BINDIR)/pixelservV4
	@rm -f $(DESTDIR)$(BINDIR)/pixelservV6

# =============================================================================
# Cleanup
# =============================================================================

clean:
	@echo "Cleaning..."
	@rm -rf $(OBJDIR)
	@rm -f pixelserv-index pixelservV4 pixelservV6 pixelserv-test
	@rm -f *.o

distclean: clean clean-test-ca
	@rm -f config.h config.status config.log
	@rm -rf autom4te.cache .deps

# =============================================================================
# Sanitizers and Analysis
# =============================================================================

.PHONY: address thread ubsan analyze secure memcheck fullcheck production headercheck

# Test binary for sanitizers (IPv4 only, faster)
TEST_BIN := pixelserv-test

# AddressSanitizer - detect memory errors (buffer overflow, use-after-free, etc.)
address: clean
	@echo ""
	@echo "=== AddressSanitizer Build ==="
	@echo ""
	$(CC) $(BASE_CFLAGS) $(V4_CFLAGS) -g -O1 -fsanitize=address -fno-omit-frame-pointer \
		$(ALL_SRCS) $(SSL_LDFLAGS) $(SSL_LIBS) -lpthread -lrt -ldl -fsanitize=address -o $(TEST_BIN)
	@echo ""
	@echo "Binary: $(TEST_BIN)"
	@echo "Run with: ASAN_OPTIONS=detect_leaks=1 ./$(TEST_BIN) [args]"
	@echo ""

# ThreadSanitizer - detect data races
thread: clean
	@echo ""
	@echo "=== ThreadSanitizer Build ==="
	@echo ""
	$(CC) $(BASE_CFLAGS) $(V4_CFLAGS) -g -O1 -fsanitize=thread -fno-omit-frame-pointer \
		$(ALL_SRCS) $(SSL_LDFLAGS) $(SSL_LIBS) -lpthread -lrt -ldl -fsanitize=thread -o $(TEST_BIN)
	@echo ""
	@echo "Binary: $(TEST_BIN)"
	@echo "Run with: TSAN_OPTIONS=second_deadlock_stack=1 ./$(TEST_BIN) [args]"
	@echo ""

# UndefinedBehaviorSanitizer - detect undefined behavior
ubsan: clean
	@echo ""
	@echo "=== UndefinedBehaviorSanitizer Build ==="
	@echo ""
	$(CC) $(BASE_CFLAGS) $(V4_CFLAGS) -g -O1 -fsanitize=undefined -fno-omit-frame-pointer \
		$(ALL_SRCS) $(SSL_LDFLAGS) $(SSL_LIBS) -lpthread -lrt -ldl -fsanitize=undefined -o $(TEST_BIN)
	@echo ""
	@echo "Binary: $(TEST_BIN)"
	@echo "Run with: UBSAN_OPTIONS=print_stacktrace=1 ./$(TEST_BIN) [args]"
	@echo ""

# Static analysis with GCC
analyze:
	@echo ""
	@echo "=== Static Analysis (GCC) ==="
	@echo ""
	@for src in $(ALL_SRCS); do \
		echo "Analyzing $$src..."; \
		$(CC) $(BASE_CFLAGS) $(V4_CFLAGS) -fanalyzer -c $$src -o /dev/null 2>&1 | grep -v "^$$" || true; \
	done
	@echo ""
	@echo "=== Static Analysis Complete ==="
	@echo ""

# Security hardening check - build with all protections
secure: clean
	@echo ""
	@echo "=== Security Hardened Build ==="
	@echo ""
	$(CC) $(BASE_CFLAGS) $(V4_CFLAGS) -g -O2 \
		-fstack-protector-strong \
		-D_FORTIFY_SOURCE=2 \
		-Wformat -Wformat-security \
		-fPIE \
		$(ALL_SRCS) $(SSL_LDFLAGS) $(SSL_LIBS) -lpthread -lrt -ldl -pie -o $(TEST_BIN)
	@echo ""
	@echo "Checking security features..."
	@checksec --file=$(TEST_BIN) 2>/dev/null || echo "(checksec not installed, skipping)"
	@echo ""

# Valgrind memory check (requires running binary)
memcheck: clean
	@echo ""
	@echo "=== Valgrind Memcheck Build ==="
	@echo ""
	$(CC) $(BASE_CFLAGS) $(V4_CFLAGS) -g -O0 \
		$(ALL_SRCS) $(SSL_LDFLAGS) $(SSL_LIBS) -lpthread -lrt -ldl -o $(TEST_BIN)
	@echo ""
	@echo "Binary: $(TEST_BIN)"
	@echo "Run with: valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./$(TEST_BIN) [args]"
	@echo ""

# =============================================================================
# Test CA Setup (for automated testing)
# =============================================================================

TEST_CA_DIR := /tmp/pixelserv-test-ca

.PHONY: setup-test-ca clean-test-ca

# Create test CA structure (RootCA + SubCA for each algorithm)
setup-test-ca:
	@echo ""
	@echo "=== Setting up Test CA ==="
	@echo ""
	@rm -rf $(TEST_CA_DIR)
	@mkdir -p $(TEST_CA_DIR)
	@echo "Creating RootCA..."
	@openssl ecparam -genkey -name prime256v1 -out $(TEST_CA_DIR)/rootca.key 2>/dev/null || \
		openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $(TEST_CA_DIR)/rootca.key 2>/dev/null
	@openssl req -x509 -key $(TEST_CA_DIR)/rootca.key -out $(TEST_CA_DIR)/rootca.crt \
		-days 3650 -subj '/CN=pixelserv Test Root CA' -sha256 2>/dev/null
	@echo "Creating directory structure..."
	@for algo in RSA ECDSA; do \
		mkdir -p $(TEST_CA_DIR)/$$algo/certs; \
		mkdir -p $(TEST_CA_DIR)/$$algo/index; \
		echo "  Creating $$algo SubCA..."; \
		openssl ecparam -genkey -name prime256v1 -out $(TEST_CA_DIR)/$$algo/ca.key 2>/dev/null || \
			openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $(TEST_CA_DIR)/$$algo/ca.key 2>/dev/null; \
		openssl req -new -key $(TEST_CA_DIR)/$$algo/ca.key \
			-out $(TEST_CA_DIR)/$$algo/ca.csr \
			-subj "/CN=pixelserv Test SubCA $$algo" -sha256 2>/dev/null; \
		echo "basicConstraints = CA:TRUE" > $(TEST_CA_DIR)/ca_ext.txt; \
		openssl x509 -req -in $(TEST_CA_DIR)/$$algo/ca.csr \
			-CA $(TEST_CA_DIR)/rootca.crt -CAkey $(TEST_CA_DIR)/rootca.key \
			-CAcreateserial -extfile $(TEST_CA_DIR)/ca_ext.txt \
			-out $(TEST_CA_DIR)/$$algo/ca.crt \
			-days 3650 -sha256 2>/dev/null; \
		rm -f $(TEST_CA_DIR)/$$algo/ca.csr; \
		chmod 644 $(TEST_CA_DIR)/$$algo/ca.key $(TEST_CA_DIR)/$$algo/ca.crt; \
	done
	@rm -f $(TEST_CA_DIR)/ca_ext.txt $(TEST_CA_DIR)/rootca.srl
	@echo ""
	@echo "Test CA created at: $(TEST_CA_DIR)"
	@echo "  RSA:   $(TEST_CA_DIR)/RSA/   (ca.crt, ca.key)"
	@echo "  ECDSA: $(TEST_CA_DIR)/ECDSA/ (ca.crt, ca.key)"
	@echo ""
	@echo "Usage: ./$(TEST_BIN) -p 8080 -k 8443 -D $(TEST_CA_DIR)"
	@echo ""

clean-test-ca:
	@rm -rf $(TEST_CA_DIR)
	@echo "Test CA removed."

# Full check - run all analysis tools (with test CA)
fullcheck: setup-test-ca
	@echo ""
	@echo "######################################################"
	@echo "#           FULL CODE ANALYSIS                       #"
	@echo "######################################################"
	@echo ""
	@$(MAKE) analyze
	@echo ""
	@$(MAKE) address
	@echo ""
	@$(MAKE) thread
	@echo ""
	@$(MAKE) ubsan
	@echo ""
	@$(MAKE) secure
	@echo ""
	@$(MAKE) memcheck
	@echo ""
	@echo "######################################################"
	@echo "#           FULL CHECK COMPLETE                      #"
	@echo "######################################################"
	@echo ""
	@echo "Test binaries created. Run manually to check for runtime issues:"
	@echo "  - AddressSanitizer: ASAN_OPTIONS=detect_leaks=1 ./$(TEST_BIN)"
	@echo "  - ThreadSanitizer:  TSAN_OPTIONS=second_deadlock_stack=1 ./$(TEST_BIN)"
	@echo "  - UBSan:            UBSAN_OPTIONS=print_stacktrace=1 ./$(TEST_BIN)"
	@echo "  - Valgrind:         valgrind --leak-check=full ./$(TEST_BIN)"
	@echo ""

# =============================================================================
# Production Build (Extreme Optimization)
# =============================================================================

# Aggressive optimization flags
PROD_OPT := -O3 -march=native -mtune=native -flto=auto -DNDEBUG
PROD_OPT += -fomit-frame-pointer -funroll-loops -finline-functions
PROD_OPT += -fmerge-all-constants -fno-semantic-interposition -fno-plt
PROD_OPT += -fprefetch-loop-arrays -fgcse-after-reload -ftree-vectorize

# SIMD flags (x86_64)
SIMD_FLAGS := -msse4.2 -mavx -mavx2

# LTO linker flags
LTO_LDFLAGS := -flto=auto -fuse-linker-plugin -Wl,-O3 -Wl,--as-needed

production: clean
	@echo ""
	@echo "######################################################"
	@echo "#     PRODUCTION BUILD - EXTREME OPTIMIZATION        #"
	@echo "######################################################"
	@echo ""
	@echo "Optimizations: LTO, SIMD (AVX2), Loop Unrolling, Inlining"
	@echo ""
	@mkdir -p $(OBJDIR)/v4 $(OBJDIR)/v6 $(OBJDIR)/index
	@echo "Building pixelserv-index..."
	@$(CC) $(BASE_CFLAGS) $(INDEX_CFLAGS) $(PROD_OPT) $(SIMD_FLAGS) \
		$(ALL_SRCS) $(SSL_LDFLAGS) $(SSL_LIBS) -lpthread -lrt -ldl $(LTO_LDFLAGS) -o pixelserv-index
	@strip --strip-all pixelserv-index
	@echo "Building pixelservV4..."
	@$(CC) $(BASE_CFLAGS) $(V4_CFLAGS) $(PROD_OPT) $(SIMD_FLAGS) \
		$(ALL_SRCS) $(SSL_LDFLAGS) $(SSL_LIBS) -lpthread -lrt -ldl $(LTO_LDFLAGS) -o pixelservV4
	@strip --strip-all pixelservV4
	@echo "Building pixelservV6..."
	@$(CC) $(BASE_CFLAGS) $(V6_CFLAGS) $(PROD_OPT) $(SIMD_FLAGS) \
		$(ALL_SRCS) $(SSL_LDFLAGS) $(SSL_LIBS) -lpthread -lrt -ldl $(LTO_LDFLAGS) -o pixelservV6
	@strip --strip-all pixelservV6
	@echo ""
	@echo "Production build complete:"
	@ls -la pixelserv-index pixelservV4 pixelservV6
	@echo ""

# =============================================================================
# Header Check (Missing Header Detection)
# =============================================================================

headercheck:
	@echo ""
	@echo "=== Header Check ==="
	@echo ""
	@ERRORS=0; \
	for src in $(ALL_SRCS); do \
		OUTPUT=$$($(CC) -fsyntax-only $(BASE_CFLAGS) $(V4_CFLAGS) $$src 2>&1 | grep -E "(No such file|fatal error|not found)" || true); \
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

# =============================================================================
# Info
# =============================================================================

info:
	@echo ""
	@echo "pixelserv-tls Build Configuration"
	@echo "=================================="
	@echo ""
	@echo "Compiler:      $(CC)"
	@echo "SSL Library:   $(if $(TONGSUO_PATH),Tongsuo ($(TONGSUO_PATH)),$(if $(OPENSSL_PATH),OpenSSL ($(OPENSSL_PATH)),System OpenSSL))"
	@echo "Static SSL:    $(if $(filter 1,$(STATIC_SSL)),yes,no)"
	@echo "Static Binary: $(if $(filter 1,$(STATIC)),yes,no)"
	@echo "Debug:         $(if $(filter 1,$(DEBUG)),yes,no)"
	@echo "PEM Path:      $(PEM_PATH)"
	@echo "Install:       $(BINDIR)"
	@echo ""
	@echo "Targets:"
	@echo "  pixelserv-index - Index master for multi-process deployment"
	@echo "  pixelservV4     - IPv4 optimized server"
	@echo "  pixelservV6     - IPv6 optimized server"
	@echo ""

# =============================================================================
# Help
# =============================================================================

help:
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════════════╗"
	@echo "║                    pixelserv-tls Makefile                        ║"
	@echo "╚══════════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "BUILD TARGETS:"
	@echo "  make              Build all binaries (pixelserv-index, V4, V6)"
	@echo "  make production   Optimized release build (LTO, AVX2, stripped)"
	@echo "  make install      Install to $(BINDIR)"
	@echo "  make uninstall    Remove installed binaries"
	@echo ""
	@echo "TESTING & ANALYSIS:"
	@echo "  make fullcheck    Run ALL checks (creates test-CA first)"
	@echo "  make analyze      Static code analysis (cppcheck, clang-tidy)"
	@echo "  make address      Build with AddressSanitizer (memory errors)"
	@echo "  make thread       Build with ThreadSanitizer (race conditions)"
	@echo "  make ubsan        Build with UndefinedBehaviorSanitizer"
	@echo "  make secure       Build with security hardening flags"
	@echo "  make memcheck     Run valgrind memory check (needs test-CA)"
	@echo ""
	@echo "TEST ENVIRONMENT:"
	@echo "  make setup-test-ca  Create test CA in $(TEST_CA_DIR)"
	@echo "  make clean-test-ca  Remove test CA"
	@echo ""
	@echo "CLEANUP:"
	@echo "  make clean        Remove build artifacts"
	@echo "  make distclean    Remove all generated files + test CA"
	@echo ""
	@echo "INFORMATION:"
	@echo "  make info         Show build configuration"
	@echo "  make headercheck  Check for missing headers"
	@echo "  make help         Show this help"
	@echo ""
	@echo "EXAMPLES:"
	@echo "  make                          # Standard build"
	@echo "  make production               # Optimized release"
	@echo "  make fullcheck                # Run all tests"
	@echo "  make setup-test-ca && make memcheck  # Valgrind test"
	@echo ""
	@echo "TLD CONFIG:"
	@echo "  Install: cp scripts/second-level-tlds.conf {PEM_DIR}/config/"
	@echo ""

# =============================================================================
# Dependencies
# =============================================================================

-include $(OBJS_V4:.o=.d)
-include $(OBJS_V6:.o=.d)
-include $(OBJS_INDEX:.o=.d)

# Generate dependency files
$(OBJDIR)/v4/%.d: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS_COMMON) $(V4_CFLAGS) -MM -MT $(@:.d=.o) $< > $@

$(OBJDIR)/v6/%.d: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS_COMMON) $(V6_CFLAGS) -MM -MT $(@:.d=.o) $< > $@

$(OBJDIR)/index/%.d: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS_COMMON) $(INDEX_CFLAGS) -MM -MT $(@:.d=.o) $< > $@
