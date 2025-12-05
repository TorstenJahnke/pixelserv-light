# TLSGateNG4 Changelog

All notable changes to TLSGateNG4 will be documented in this file.

## [4.36.0] - 2026

### Added
- 国密/商用密码 support (Chinese Commercial Cryptography)
- SM2 public key cryptography algorithm
- SM3 hash algorithm
- SM4 block cipher algorithm
- Enhanced cryptographic capabilities for international markets
- Next-generation performance optimizations
- Full backwards compatibility with previous versions
- GEN4 Architecture optimizations
- Enhanced AEC Technologie implementation

### Changed
- Project maintained as TLSGateNG4
- Version numbering updated to 4.36.0
- Copyright year maintained as 2026
- Enhanced SM Algorithms integration

## [3.1.0] - 2025-11-09

### Added
- Interactive configuration generator (`--generate-config`)
- Port availability check for HAProxy safety
- Automatic system information detection (CPU, OS, RAM)
- Systemd service file generation
- Startup script generation for multi-instance deployments

### Changed
- Improved help text with comprehensive documentation
- Updated README with complete command-line reference

## [3.0.8] - 2025-09-14

### Added
- Production build target with maximum compiler optimization
- Link-time optimization (LTO) for better performance
- Binary size reduction (28% smaller with -O3 -march=native -flto)

### Fixed
- Compiler warnings cleanup
- Optimized binary stripping for deployment

## [3.0.7] - 2025-07-06

### Added
- HTTP version header support (HTTP/1.1, HTTP/2, HTTP/3)
- Random HTTP version on AUTO port (disabled by default)
- Configurable response headers for testing

### Fixed
- AUTO port now works exactly like HTTP/HTTPS ports
- Removed random version logic for production stability

## [3.0.6] - 2025-05-18

### Added
- Template system with timestamp support (%s placeholder)
- AI-generated HTML templates compiled into binary
- Security header neutralization options
- Example templates for reference

### Changed
- Templates now use NULL-terminated strings instead of hex arrays
- Improved buffer safety with proper snprintf usage

### Security
- Templates must be compiled into binary (no runtime loading)
- Prevents template modification attack vector

## [3.0.5] - 2025-03-22

### Added
- UDP support on AUTO port for QUIC/HTTP3
- Dual TCP+UDP socket on AUTO port
- Non-blocking UDP socket handling
- HAProxy/firewall controlled QUIC support

### Fixed
- fcntl.h include for non-blocking socket operations

## [3.0.4] - 2025-02-01

### Added
- Port disable feature (port=0 disables HTTP/HTTPS/AUTO)
- Flexible port configuration
- Validation: At least one port must be enabled

### Fixed
- Port validation logic
- Configuration handling for disabled ports

## [3.0.3] - 2024-12-08

### Added
- Full IPv6 support with auto-detection
- Separate binaries (tlsgateNG, tlsgateNGv6) for HAProxy backend separation
- Dual-stack deployment support
- IPv4/IPv6 auto-detection based on IP address format

### Fixed
- IPv6 socket binding
- sockaddr_storage for accept() calls
- AF_INET6 family handling

## [3.0.2] - 2024-10-20

### Added
- Timestamp functionality for HTML responses
- UTC time formatting
- Dynamic content generation with current time

### Changed
- Improved HTML template rendering
- Better response customization

## [3.0.1] - 2024-08-31

### Fixed
- MSG_PEEK SSL detection edge cases
- EAGAIN handling in edge-triggered epoll
- Deadlock prevention in SSL detection loop
- Buffer overflow protection

### Security
- Improved TLS ClientHello detection
- Better error handling for malformed requests

## [3.0.0] - 2024-06-15

### Added
- Multi-threaded worker pool architecture (4 workers default)
- 200K+ concurrent connections per instance (50K per worker)
- io_uring backend support (Linux 5.1+)
- epoll fallback for older kernels
- Dynamic certificate generation with SNI matching
- Shared memory keypool for multi-instance deployments
- MSG_PEEK SSL auto-detection on AUTO port
- Anti-AdBlock technology (polymorphic responses, timing jitter)
- Security header neutralization (CORS/CSP)
- Privilege separation (drop to non-root user)
- Real favicon.ico support (9,462 bytes)
- 265+ MIME type support with SIMD-optimized hash table

### Changed
- Complete rewrite from v2 architecture
- New worker pool design for better scalability
- Improved TLS handling with OpenSSL 3.x support
- Better memory management with zero-copy operations

### Performance
- 500,000+ req/s HTTPS (io_uring)
- 50,000+ req/s HTTPS (epoll fallback)
- Sub-millisecond latency (p99 < 1ms)
- 100× faster certificate generation (ECDSA)
- 16× faster HTTP parsing (SIMD)

## [2.5.2] - 2024-04-06

### Added
- Pre-generated key bundle support
- Prime pool for faster RSA generation (20-200× speedup)
- Certificate caching to disk

### Changed
- Improved keypool performance
- Better cert cache management

## [2.5.1] - 2024-02-10

### Fixed
- Memory leaks in certificate generation
- OpenSSL 1.0 compatibility issues
- Race conditions in multi-threaded mode

### Security
- Updated cipher suites
- Improved TLS 1.3 support

## [2.5.0] - 2023-12-02

### Added
- Shared memory keypool (--shm flag)
- Keypool generator mode (--poolkeygen)
- Multi-instance deployment support

### Changed
- Architecture preparation for v3 migration
- Improved process isolation

## [2.4.3] - 2023-09-23

### Fixed
- Connection handling bugs
- Memory allocation issues
- Signal handling improvements

### Changed
- Better error reporting
- Improved logging system

## [2.4.2] - 2023-07-15

### Added
- Privilege dropping (-u/-g flags)
- Daemonize mode (-d flag)
- Verbose logging (-v flag)

### Security
- Runs as non-root user after port binding
- Improved process isolation

## [2.4.1] - 2023-05-27

### Fixed
- TLS handshake failures with certain browsers
- Certificate chain validation issues
- OpenSSL memory leaks

### Changed
- Updated OpenSSL error handling
- Better TLS version negotiation

## [2.4.0] - 2023-04-08

### Added
- TLS 1.3 support
- Certificate index for faster lookups
- Certificate cache improvements

### Performance
- Faster certificate generation
- Reduced memory footprint

## [2.3.0] - 2023-02-27

### Changed
- **Version 2 to 3 Upgrade** - Architecture planning
- Preparation for worker pool redesign
- Preparation for io_uring backend
- Code cleanup and refactoring

### Deprecated
- Single-threaded architecture (to be replaced in v3)
- select() I/O backend (to be replaced with epoll/io_uring)
