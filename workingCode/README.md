# pixelserv-tls

A high-performance HTTP/HTTPS pixel server with TLS support for ad blocking and tracker interception.

## Features

### Netzwerk & TLS
- **HTTP/1.1 and HTTPS** with SNI support
- **TLSv1.0, TLSv1.2, TLSv1.3** support
- **TCP Fast Open** support (Linux 3.7+)
- **IPv4 and IPv6** support
- **Auto-detect HTTP/HTTPS** on same port (-a option)

### Architektur
- **Index Master/Worker Architecture** for multi-process deployments
- **Sharded certificate storage** with 256 shards for parallel access
- **Lock-free keypool** for high-performance certificate generation
- **Automatic certificate generation** on first use

### Ad-Blocking Kompatibilität
- **Maximal permissive CORS** - dynamisch gespiegelte Header
- **Keine restriktiven Security-Header** (kein X-Frame-Options, CSP, etc.)
- **Cross-Origin Policies deaktiviert** (COEP, COOP, CORP)
- **Private Network Access** erlaubt (Chrome 94+)
- **Timing API** erlaubt für Performance-Messungen
- **Legacy Flash/Silverlight** Cross-Domain Support

### Content
- **External HTML file support** (-H option)
- **Second-Level TLD Support** für korrekte Wildcard-Zertifikate
- **Minimale Responses**: 1x1 Pixel (GIF/PNG/JPG), leere Scripts, etc.

```bash
# Ein Index-Master für alle Algorithmen:
pixelserv-tls -M -z /path/to/aviontex -l 3

# Worker verbinden sich zum selben Master:
pixelserv-tls 192.168.1.1 -p 80 -k 443 \
    -m /path/to/aviontex/pixelserv-index.sock \
    -z /path/to/aviontex
```

## Build from Source

### Linux

```bash
autoreconf -i
./configure CFLAGS="-O3 -Wall -pthread -D_REENTRANT -D_THREAD_SAFE" LDFLAGS="-pthread -Wl,-z,noexecstack"
make
```

### FreeBSD 14.2

```bash
autoreconf -i
env CONFIG_SHELL=/usr/local/bin/bash ./configure \
    CFLAGS="-O3 -Wall -march=native -mtune=native -pthread -D_REENTRANT -D_THREAD_SAFE -D_GNU_SOURCE -DSCALABLE -DNDEBUG -ffunction-sections -fdata-sections -fno-strict-aliasing -flto" \
    LDFLAGS="-pthread -Wl,-z,noexecstack -Wl,-O1 -Wl,--as-needed -Wl,--gc-sections -flto" \
    --enable-tcp-fastopen
gmake -j$(sysctl -n hw.ncpu)
```

## Installation

```bash
sudo make install
```

Default installation paths:
- Binary: `/usr/local/bin/pixelserv-tls`
- Certificates: `/usr/local/pixelserver/`

## Command Line Options

```
Usage: pixelserv-tls [OPTION]

options:
    ip_addr/hostname    (default: 0.0.0.0)
    -2                  (disable HTTP 204 reply to generate_204 URLs)
    -A  ADMIN_PORT      (HTTPS only. Default is none)
    -a  AUTO_PORT       (auto-detect HTTP/HTTPS on same port)
    -B  [CERT_FILE]     (Benchmark crypto and disk then quit)
    -c  CERT_CACHE_SIZE (default: 500)
    -f                  (stay in foreground/don't daemonize)
    -H  HTML_FILE       (external HTML file for default response)
    -k  HTTPS_PORT      (default: 1433)
    -l  LEVEL           (0:critical 1:error 2:warning 3:notice 4:info 5:debug)
    -M                  (run as index master - owns cert index, workers connect via -m)
    -m  SOCKET_PATH     (connect to index master at SOCKET_PATH as worker)
    -n  IFACE           (default: all interfaces)
    -O  KEEPALIVE_TIME  (for HTTP/1.1 connections; default: 120s)
    -p  HTTP_PORT       (default: 1080)
    -R                  (enable redirect to encoded path in URLs)
    -s  STATS_HTML_URL  (default: /servstats)
    -t  STATS_TXT_URL   (default: /servstats.txt)
    -T  MAX_THREADS     (default: 1200)
    -u  USER            (default: "nobody")
    -z  CERT_PATH       (default: /usr/local/pixelserver)
```

## Usage Examples

### Standalone Mode (Single Instance)

Simple standalone server:

```bash
pixelserv-tls 192.168.1.100 -p 80 -k 443 -z /usr/local/pixelserver -l 3 -f
```

### Multi-Port with Auto-Detect

Using auto-detect port for HTTP and HTTPS on same port:

```bash
pixelserv-tls 192.168.1.100 -p 80 -k 443 -a 8080 -z /usr/local/pixelserver -l 3 -f
```

The `-a` option enables auto-detection: the server peeks at the first byte of incoming connections to determine if it's HTTP or HTTPS (TLS handshake starts with 0x16).

### External HTML Response

Use a custom HTML file for responses instead of the built-in template:

```bash
pixelserv-tls 192.168.1.100 -p 80 -k 443 -H /path/to/custom.html -z /usr/local/pixelserver -f
```

Maximum file size: 1 MB

## Index Master/Worker Architecture

For high-traffic deployments or HAProxy setups with multiple workers on the same IP but different ports, use the master/worker architecture. The master process owns the certificate index, while workers request certificates via Unix socket IPC.

### Index Master Mode

The index master manages the certificate index and provides certificates to workers:

```bash
# Using -M flag
pixelserv-tls -M -z /usr/local/pixelserver -l 3

# Or using symlink (auto-detection)
ln -s /usr/local/bin/pixelserv-tls /usr/local/bin/pixelserv-index
/usr/local/bin/pixelserv-index -z /usr/local/pixelserver -l 3
```

The master creates a Unix socket at `<cert_path>/pixelserv-index.sock`.

### Worker Mode

Workers connect to the index master for certificate lookups:

```bash
pixelserv-tls 192.168.1.100 -p 80 -k 443 \
    -m /usr/local/pixelserver/pixelserv-index.sock \
    -z /usr/local/pixelserver -u nobody -l 3
```

### Example: HAProxy Multi-Worker Setup

```
                    ┌──────────────┐
                    │   HAProxy    │
                    │  (Frontend)  │
                    └──────┬───────┘
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
         ▼                 ▼                 ▼
┌────────────────┐ ┌────────────────┐ ┌────────────────┐
│   Worker #1    │ │   Worker #2    │ │   Worker #3    │
│  :80 / :443    │ │ :8080 / :8443  │ │ :1080 / :1443  │
└────────┬───────┘ └────────┬───────┘ └────────┬───────┘
         │                  │                  │
         └──────────────────┼──────────────────┘
                            │
                    ┌───────▼───────┐
                    │  Index Master │
                    │  (Unix Socket)│
                    └───────────────┘
```

## Systemd Services

Service files are provided in the `systemd/` directory.

### Index Master Service

Install `/systemd/pixelserv-index.service` to `/etc/systemd/system/`:

```bash
sudo cp systemd/pixelserv-index.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable pixelserv-index
sudo systemctl start pixelserv-index
```

### Worker Services (Template-based)

For multiple workers, use the template service `/systemd/pixelserv-tls@.service`:

```bash
sudo cp systemd/pixelserv-tls@.service /etc/systemd/system/
sudo mkdir -p /etc/pixelserv/workers
```

Create a configuration file for each worker in `/etc/pixelserv/workers/<name>.conf`:

```bash
# /etc/pixelserv/workers/web1.conf
IP=192.168.1.100
HTTP_PORT=80
HTTPS_PORT=443
```

```bash
# /etc/pixelserv/workers/web2.conf
IP=192.168.1.100
HTTP_PORT=8080
HTTPS_PORT=8443
```

Start workers:

```bash
sudo systemctl daemon-reload
sudo systemctl enable pixelserv-tls@web1 pixelserv-tls@web2
sudo systemctl start pixelserv-tls@web1 pixelserv-tls@web2
```

### Single Worker Service

For simpler setups, use `/systemd/pixelserv-tls.service` with `/etc/pixelserv/worker.conf`:

```bash
sudo cp systemd/pixelserv-tls.service /etc/systemd/system/
sudo mkdir -p /etc/pixelserv
sudo cp systemd/worker.conf.example /etc/pixelserv/worker.conf
# Edit /etc/pixelserv/worker.conf with your settings
sudo systemctl daemon-reload
sudo systemctl enable pixelserv-tls
sudo systemctl start pixelserv-tls
```

## Certificate Storage

Certificates are stored in a sharded directory structure:

```
/usr/local/pixelserver/
├── ca.crt                 # Root CA certificate
├── ca.key                 # Root CA private key
├── pixelserv-index.sock   # Unix socket (master mode)
└── RSA/
    ├── certs/
    │   ├── 00/            # Shard 00 (00-ff)
    │   │   ├── cert_000001.pem
    │   │   ├── cert_000002.pem
    │   │   └── ...
    │   ├── 01/
    │   └── ...
    └── primes/            # Pre-computed RSA primes
        └── primes.bin
```

## Statistics

Access server statistics via HTTP:

- HTML format: `http://<ip>:<port>/servstats`
- Text format: `http://<ip>:<port>/servstats.txt`

## Custom HTML Template

To create a custom HTML template file (`html_index.h`) at compile time:

1. Create your `index.html` file
2. Convert to C header: `xxd -i index.html > html_index.h`
3. Füge manuell `'\0'` am Ende des Arrays hinzu (für String-Sicherheit)
4. Recompile

Or use the `-H` option at runtime to load an external HTML file.

## CORS/Security Headers

pixelserv ist als Ad-Blocker konzipiert und sendet **maximal permissive** HTTP-Header, damit blockierte Ad-Requests nicht durch Browser-Security fehlschlagen.

### Statische Responses (alle Bilder, Scripts, etc.)

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Access-Control-Expose-Headers: *
Access-Control-Allow-Private-Network: true
Cross-Origin-Resource-Policy: cross-origin
Timing-Allow-Origin: *
```

### OPTIONS Preflight (dynamisch gespiegelt)

Der Server spiegelt exakt was der Browser anfragt:

| Browser Request Header | Server Response Header |
|------------------------|------------------------|
| `Origin: https://example.com` | `Access-Control-Allow-Origin: https://example.com` |
| `Access-Control-Request-Method: PUT` | `Access-Control-Allow-Methods: PUT` |
| `Access-Control-Request-Headers: X-Custom` | `Access-Control-Allow-Headers: X-Custom` |

Zusätzliche OPTIONS-Header:
```
Access-Control-Expose-Headers: *
Access-Control-Max-Age: 86400
Access-Control-Allow-Private-Network: true
Cross-Origin-Resource-Policy: cross-origin
Cross-Origin-Embedder-Policy: unsafe-none
Cross-Origin-Opener-Policy: unsafe-none
Timing-Allow-Origin: *
X-Permitted-Cross-Domain-Policies: all
```

### Entfernte restriktive Header

Diese Header werden **NICHT** gesendet (würden Ad-Blocking stören):
- ~~X-Frame-Options~~ (blockiert iframes)
- ~~X-Content-Type-Options~~ (verhindert MIME-Sniffing)
- ~~Referrer-Policy~~ (versteckt Referrer)
- ~~Content-Security-Policy~~ (blockiert Ressourcen)

## Second-Level TLD Support

Für korrekte Wildcard-Zertifikate bei Domains wie `www.amazon.co.uk`:

| Ohne TLD-Support | Mit TLD-Support |
|------------------|-----------------|
| `*.co.uk` (FALSCH!) | `*.amazon.co.uk` (KORREKT) |

Die TLD-Liste liegt in `<cert_path>/config/second-level-tlds.conf` und enthält ca. 9000 Einträge wie:
```
co.uk
com.au
co.jp
org.uk
...
```

## Response-Typen

| Extension | Content-Type | Größe | Beschreibung |
|-----------|--------------|-------|--------------|
| .gif | image/gif | 42 Bytes | 1x1 transparentes GIF |
| .png | image/png | 67 Bytes | 1x1 transparentes PNG |
| .jpg/.jpeg | image/jpeg | 159 Bytes | 1x1 weißes JPEG |
| .ico | image/x-icon | 70 Bytes | 1x1 transparentes Icon |
| .swf | application/x-shockwave-flash | 25 Bytes | Leeres Flash |
| .js | application/javascript | 0 Bytes | Leeres JavaScript |
| .css | text/css | 0 Bytes | Leeres CSS |
| .html | text/html | 0 Bytes oder -H | HTML oder externe Datei |
| .asp/.aspx/.php/.jsp | text/html | 0 Bytes | Leere Server-Response |
| * | text/html | 0 Bytes | Standard Response |

## Build-Targets

```bash
make              # Standard Build (alle 3 Binaries)
make clean        # Aufräumen
make help         # Alle verfügbaren Targets anzeigen
make debug        # Mit Debug-Symbolen
make release      # Optimiert für Release
make address      # AddressSanitizer (Memory-Bugs)
make thread       # ThreadSanitizer (Race-Conditions)
make analyze      # Static Analyzer
make secure       # Security-hardened Build
make memcheck     # Für Valgrind
make fullcheck    # Alle Sanitizer + Tests (erstellt Test-CA)
```

## Changelog

### Version 3.0.x

- Index Master/Worker architecture for multi-process deployments
- Auto-detect HTTP/HTTPS on same port (`-a` option)
- External HTML file support (`-H` option)
- Lock-free keypool for RSA key generation
- Sharded certificate storage (256 shards)
- Changed default ports to 1080 (HTTP) and 1433 (HTTPS)
- Changed default path to `/usr/local/pixelserver`
- Systemd service templates for multi-worker deployments
- Extended MIME type support (JSON, XML, WebP, SVG, fonts, video, audio, etc.)
- Fixed CORS errors
- Fixed IPv6 connections
- Fixed memory leaks

## License

See LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## Related Projects

- Original pixelserv-tls: https://github.com/kvic-z/pixelserv-tls
