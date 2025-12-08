/*
 * socket_handler.c - Minimal bereinigt mit ASP-Unterstützung
 * 
 * KORRIGIERT:
 * - html_index.h Integration hinzugefügt
 * - favicon.h doppelte Definition entfernt
 * - Alle HTTP-Templates verwenden jetzt dynamische Content-Length
 * - asprintf() Calls korrigiert für get_index_html_len() Parameter
 * - Content-Sending nach Header korrigiert
 */
#include "core/util.h"
#include <stdio.h>   // Für asprintf
#include <string.h>  // Für strcasestr

#include <ctype.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdint.h>  // Fix: für uintptr_t

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

#include "net/socket_handler.h"
#include "certs/certs.h"
#include "core/logger.h"
#include "content/favicon.h"
#include "content/html_index.h"

/* External HTML override (loaded from file via -H option) */
static unsigned char *external_html = NULL;
static unsigned int external_html_len = 0;

/* Accessor functions for external HTML */
unsigned char *get_index_html(void) {
    return external_html ? external_html : index_html;
}

unsigned int get_index_html_len(void) {
    return external_html ? external_html_len : index_html_len;
}

/* Load external HTML file */
int load_external_html(const char *filepath) {
    if (!filepath) return -1;

    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        fprintf(stderr, "Cannot open external HTML file: %s\n", filepath);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size <= 0 || size > 1024 * 1024) {  /* Max 1MB */
        fprintf(stderr, "Invalid external HTML file size: %ld\n", size);
        fclose(fp);
        return -1;
    }

    external_html = malloc(size);
    if (!external_html) {
        fclose(fp);
        return -1;
    }

    if (fread(external_html, 1, size, fp) != (size_t)size) {
        free(external_html);
        external_html = NULL;
        fclose(fp);
        return -1;
    }

    external_html_len = (unsigned int)size;
    fclose(fp);

    fprintf(stderr, "Loaded external HTML: %s (%u bytes)\n", filepath, external_html_len);
    return 0;
}

// KORRIGIERT: Doppelte favicon.h Definition entfernt
// Nur das #include reicht - keine zusätzliche Definition nötig!

// private data for socket_handler() use
// CORS Headers - maximal permissiv für Adblock Server
// Diese werden bei dynamischen Responses (httpnulltext etc.) eingefügt
static const char httpcors_headers[] =
  "Access-Control-Allow-Origin: %s\r\n"
  "Access-Control-Allow-Credentials: true\r\n"
  "Access-Control-Allow-Methods: *\r\n"
  "Access-Control-Allow-Headers: *\r\n"
  "Access-Control-Expose-Headers: *\r\n"
  "Access-Control-Max-Age: 86400\r\n"
  "Access-Control-Allow-Private-Network: true\r\n"
  "Cross-Origin-Resource-Policy: cross-origin\r\n"
  "Timing-Allow-Origin: *\r\n";

// OPTIONS preflight response template - fully dynamic CORS
// NOTE: Maximum permissiveness - this is an adblock server that must not trigger ANY security blocks
// Format: origin, methods, headers (all dynamically mirrored from request)
static const char httpoptions_template[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: text/plain\r\n"
  "Content-length: 0\r\n"
  "Connection: keep-alive\r\n"
  "Allow: GET,HEAD,OPTIONS,POST,PUT,DELETE,PATCH,CONNECT,TRACE\r\n"
  /* CORS - dynamically mirrored */
  "Access-Control-Allow-Origin: %s\r\n"
  "Access-Control-Allow-Methods: %s\r\n"
  "Access-Control-Allow-Headers: %s\r\n"
  "Access-Control-Allow-Credentials: true\r\n"
  "Access-Control-Expose-Headers: *\r\n"
  "Access-Control-Max-Age: 86400\r\n"
  /* Private Network Access (Chrome 94+) */
  "Access-Control-Allow-Private-Network: true\r\n"
  /* Cross-Origin Policies - maximum permissive */
  "Cross-Origin-Resource-Policy: cross-origin\r\n"
  "Cross-Origin-Embedder-Policy: unsafe-none\r\n"
  "Cross-Origin-Opener-Policy: unsafe-none\r\n"
  /* Timing API access */
  "Timing-Allow-Origin: *\r\n"
  /* Legacy Flash/Silverlight */
  "X-Permitted-Cross-Domain-Policies: all\r\n"
  "\r\n";

// KORRIGIERT: httpnulltext - keine restriktiven Security Header (Adblock Server)
static const char httpnulltext[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-Type: text/html; charset=UTF-8\r\n"
  "Connection: keep-alive\r\n"
  "Content-Length: %d\r\n"
  "%s" /* optional CORS */
  "\r\n";

// Common permissive headers for all static responses (images, etc.)
// Defined early so all templates can use it
#define PERMISSIVE_HEADERS \
  "Access-Control-Allow-Origin: *\r\n" \
  "Access-Control-Allow-Credentials: true\r\n" \
  "Access-Control-Expose-Headers: *\r\n" \
  "Access-Control-Allow-Private-Network: true\r\n" \
  "Cross-Origin-Resource-Policy: cross-origin\r\n" \
  "Timing-Allow-Origin: *\r\n"

// HTTP 204 No Content for Google generate_204 URLs
// NOTE: HTTP 204 MUST NOT have Content-Type or Content-Length per RFC 7231
static const char http204[] =
  "HTTP/1.1 204 No Content\r\n"
  "Connection: keep-alive\r\n"
  PERMISSIVE_HEADERS
  "\r\n";

// HTML stats response pieces
static const char httpstats1[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: text/html\r\n"
  "Content-length: ";
// total content length goes between these two strings
static const char httpstats2[] =
  "\r\n"
  "Connection: keep-alive\r\n"
  "\r\n";
// split here because we care about the length of what follows
static const char httpstats3[] =
  "<!DOCTYPE html><html><head><link rel='icon' href='/favicon.ico' type='image/x-icon'/><meta name='viewport' content='width=device-width'><title>pixelserv statistics</title><style>body {font-family:monospace;} table {min-width: 75%; border-collapse: collapse;} th { height:18px; } td {border: 1px solid #e0e0e0; background-color: #f9f9f9;} td:first-child {width: 7%;} td:nth-child(2) {width: 15%; background-color: #ebebeb; border: 1px solid #f9f9f9;}</style></head><body>";
// stats text goes between these two strings
static const char httpstats4[] =
  "</body></html>\r\n";

// note: the -2 is to avoid counting the last line ending characters
static const unsigned int statsbaselen = sizeof httpstats3 + sizeof httpstats4 - 2;

// TXT stats response pieces
static const char txtstats1[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: text/plain\r\n"
  "Content-length: ";
// total content length goes between these two strings
static const char txtstats2[] =
  "\r\n"
  "Connection: keep-alive\r\n"
  "\r\n";
// split here because we care about the length of what follows
static const char txtstats3[] =
  "\r\n";

static const char httpredirect[] =
  "HTTP/1.1 307 Temporary Redirect\r\n"
  "Location: %s\r\n"
  "Content-type: text/plain\r\n"
  "Content-length: 0\r\n"
  "Connection: keep-alive\r\n"
  "%s" /* optional CORS */
  "\r\n";

static const char httpnullpixel[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: image/gif\r\n"
  "Content-length: 42\r\n"
  "Connection: keep-alive\r\n"
  PERMISSIVE_HEADERS
  "\r\n"
  "GIF89a" // header
  "\1\0\1\0"  // little endian width, height
  "\x80"    // Global Colour Table flag
  "\0"    // background colour
  "\0"    // default pixel aspect ratio
  "\1\1\1"  // RGB
  "\0\0\0"  // RBG black
  "!\xf9"  // Graphical Control Extension
  "\4"  // 4 byte GCD data follow
  "\1"  // there is transparent background color
  "\0\0"  // delay for animation
  "\0"  // transparent colour
  "\0"  // end of GCE block
  ","  // image descriptor
  "\0\0\0\0"  // NW corner
  "\1\0\1\0"  // height * width
  "\0"  // no local color table
  "\2"  // start of image LZW size
  "\1"  // 1 byte of LZW encoded image data
  "D"    // image data
  "\0"  // end of image data
  ";";  // GIF file terminator

static const char http501[] =
  "HTTP/1.1 501 Method Not Implemented\r\n"
  "Content-Type: text/plain\r\n"
  "Content-Length: 0\r\n"
  "Connection: keep-alive\r\n"
  PERMISSIVE_HEADERS
  "\r\n";

static const char httpnull_png[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: image/png\r\n"
  "Content-length: 67\r\n"
  "Connection: keep-alive\r\n"
  PERMISSIVE_HEADERS
  "\r\n"
  "\x89"
  "PNG"
  "\r\n"
  "\x1a\n"  // EOF
  "\0\0\0\x0d" // 13 bytes length
  "IHDR"
  "\0\0\0\1\0\0\0\1"  // width x height
  "\x08"  // bit depth
  "\x06"  // Truecolour with alpha
  "\0\0\0"  // compression, filter, interlace
  "\x1f\x15\xc4\x89"  // CRC
  "\0\0\0\x0a"  // 10 bytes length
  "IDAT"
  "\x78\x9c\x63\0\1\0\0\5\0\1"
  "\x0d\x0a\x2d\xb4"  // CRC
  "\0\0\0\0"  // 0 length
  "IEND"
  "\xae\x42\x60\x82";  // CRC

static const char httpnull_jpg[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: image/jpeg\r\n"
  "Content-length: 159\r\n"
  "Connection: close\r\n"
  PERMISSIVE_HEADERS
  "\r\n"
  "\xff\xd8"  // SOI, Start Of Image
  "\xff\xe0"  // APP0
  "\x00\x10"  // length of section 16
  "JFIF\0"
  "\x01\x01"  // version 1.1
  "\x01"      // pixel per inch
  "\x00\x48"  // horizontal density 72
  "\x00\x48"  // vertical density 72
  "\x00\x00"  // size of thumbnail 0 x 0
  "\xff\xdb"  // DQT
  "\x00\x43"  // length of section 3+64
  "\x00"      // 0 QT 8 bit
  "\xff\xff\xff\xff\xff\xff\xff\xff"
  "\xff\xff\xff\xff\xff\xff\xff\xff"
  "\xff\xff\xff\xff\xff\xff\xff\xff"
  "\xff\xff\xff\xff\xff\xff\xff\xff"
  "\xff\xff\xff\xff\xff\xff\xff\xff"
  "\xff\xff\xff\xff\xff\xff\xff\xff"
  "\xff\xff\xff\xff\xff\xff\xff\xff"
  "\xff\xff\xff\xff\xff\xff\xff\xff"
  "\xff\xc0"  // SOF
  "\x00\x0b"  // length 11
  "\x08\x00\x01\x00\x01\x01\x01\x11\x00"
  "\xff\xc4"  // DHT Define Huffman Table
  "\x00\x14"  // length 20
  "\x00\x01"  // DC table 1
  "\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x03"
  "\xff\xc4"  // DHT
  "\x00\x14"  // length 20
  "\x10\x01"  // AC table 1
  "\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00"
  "\xff\xda"  // SOS, Start of Scan
  "\x00\x08"  // length 8
  "\x01"    // 1 component
  "\x01\x00"
  "\x00\x3f\x00"  // Ss 0, Se 63, AhAl 0
  "\x37" // image
  "\xff\xd9";  // EOI, End Of image

/* Phase 3: Legacy SSL Response for Old Systems (Win3.11, Win95, OS/2, DOS) */
/* These responses are plain-text for compatibility with 16-BIT systems */
/* Declared extern so pixelserv.c can send these on SSL errors */
const char legacy_ssl_error[] =
  "PIXELSERV-LEGACY/1.0\r\n"
  "Status: 599-Legacy-SSL-Fallback\r\n"
  "Content-Type: text/plain\r\n"
  "Content-Length: 36\r\n"
  "X-Legacy-Mode: Win311-Win95-OS2-DOS\r\n"
  "Connection: close\r\n"
  "\r\n"
  "LEGACY_SSL_PROTECTION_ACTIVE_OK_v1\n";

/* Also available for use in other modules */
const char legacy_ssl_ok_response[] =
  "PIXELSERV-LEGACY/1.0\r\n"
  "Status: 200-OK-Legacy\r\n"
  "Content-Type: text/plain\r\n"
  "Content-Length: 25\r\n"
  "X-Legacy-Mode: Compatible\r\n"
  "X-Filter-Status: ACTIVE\r\n"
  "Connection: keep-alive\r\n"
  "\r\n"
  "FILTER_PROTECTION_ACTIVE\n";

static const char httpnull_swf[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: application/x-shockwave-flash\r\n"
  "Content-length: 25\r\n"
  "Connection: keep-alive\r\n"
  PERMISSIVE_HEADERS
  /* Legacy Flash cross-domain */
  "X-Permitted-Cross-Domain-Policies: all\r\n"
  "\r\n"
  "FWS"
  "\x05"  // File version
  "\x19\x00\x00\x00"  // litle endian size 16+9=25
  "\x30\x0A\x00\xA0"  // Frame size 1 x 1
  "\x00\x01"  // frame rate 1 fps
  "\x01\x00"  // 1 frame
  "\x43\x02"  // tag type is 9 = SetBackgroundColor block 3 bytes long
  "\x00\x00\x00"  // black
  "\x40\x00"  // tag type 1 = show frame
  "\x00\x00";  // tag type 0 - end file

static const char httpnull_ico[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: image/x-icon\r\n"
  "Cache-Control: max-age=2592000\r\n"
  "Content-length: 70\r\n"
  "Connection: keep-alive\r\n"
  PERMISSIVE_HEADERS
  "\r\n"
  "\x00\x00" // reserved 0
  "\x01\x00" // ico
  "\x01\x00" // 1 image
  "\x01\x01\x00" // 1 x 1 x >8bpp colour
  "\x00" // reserved 0
  "\x01\x00" // 1 colour plane
  "\x20\x00" // 32 bits per pixel
  "\x30\x00\x00\x00" // size 48 bytes
  "\x16\x00\x00\x00" // start of image 22 bytes in
  "\x28\x00\x00\x00" // size of DIB header 40 bytes
  "\x01\x00\x00\x00" // width
  "\x02\x00\x00\x00" // height
  "\x01\x00" // colour planes
  "\x20\x00" // bits per pixel
  "\x00\x00\x00\x00" // no compression
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00" // end of header
  "\x00\x00\x00\x00" // Colour table
  "\x00\x00\x00\x00" // XOR B G R
  "\x80\xF8\x9C\x41"; // AND ?

// === KORRIGIERTE ASP/SERVER-SIDE SCRIPT RESPONSES ===

// ASP Classic Response - maximal permissive headers
static const char httpnull_asp[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: text/html; charset=UTF-8\r\n"
  "Content-length: %d\r\n"
  "Connection: keep-alive\r\n"
  "Cache-Control: no-cache, no-store, must-revalidate\r\n"
  "Pragma: no-cache\r\n"
  "Expires: 0\r\n"
  PERMISSIVE_HEADERS
  "\r\n";

// ASPX Response - maximal permissive headers
static const char httpnull_aspx[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: text/html; charset=UTF-8\r\n"
  "Content-length: %d\r\n"
  "Connection: keep-alive\r\n"
  "Cache-Control: no-cache, no-store, must-revalidate\r\n"
  "Pragma: no-cache\r\n"
  "Expires: 0\r\n"
  PERMISSIVE_HEADERS
  "\r\n";

// ASHX Response - maximal permissive headers
static const char httpnull_ashx[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: application/octet-stream\r\n"
  "Content-length: %d\r\n"
  "Connection: keep-alive\r\n"
  "Cache-Control: no-cache, no-store, must-revalidate\r\n"
  "Pragma: no-cache\r\n"
  "Expires: 0\r\n"
  PERMISSIVE_HEADERS
  "\r\n";

// PHP Response - maximal permissive headers
static const char httpnull_php[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: text/html; charset=UTF-8\r\n"
  "Content-length: %d\r\n"
  "Connection: keep-alive\r\n"
  "Cache-Control: no-cache, no-store, must-revalidate\r\n"
  "Pragma: no-cache\r\n"
  "Expires: 0\r\n"
  PERMISSIVE_HEADERS
  "\r\n";

// JSP Response - maximal permissive headers
static const char httpnull_jsp[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: text/html; charset=UTF-8\r\n"
  "Content-length: %d\r\n"
  "Connection: keep-alive\r\n"
  "Cache-Control: no-cache, no-store, must-revalidate\r\n"
  "Pragma: no-cache\r\n"
  "Expires: 0\r\n"
  PERMISSIVE_HEADERS
  "\r\n";

// JavaScript Response - maximal permissive headers
static const char httpnull_js[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: application/javascript; charset=UTF-8\r\n"
  "Content-length: %d\r\n"
  "Connection: keep-alive\r\n"
  "Cache-Control: no-cache, no-store, must-revalidate\r\n"
  "Pragma: no-cache\r\n"
  "Expires: 0\r\n"
  PERMISSIVE_HEADERS
  "\r\n";

// Removed: static httpoptions is now httpoptions_template (defined above with dynamic CORS headers)

static const char httpcacert[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-Type: application/x-x509-ca-cert\r\n"
  "Accept-Ranges: bytes\r\n"
  "Content-Length: ";
static const char httpcacert2[] =
  "\r\n"
  PERMISSIVE_HEADERS
  "\r\n";

#ifdef HEX_DUMP
static void hex_dump(void *data, int size)
{
  if (!data || size <= 0) return;

  char *p = data;
  char c;
  int n;
  char bytestr[4] = {0};
  char addrstr[10] = {0};
  char hexstr[16*3 + 5] = {0};
  char charstr[16*1 + 5] = {0};
  
  flockfile(stdout);
  
  for (n = 1; n <= size; n++) {
    if (n%16 == 1) {
      snprintf(addrstr, sizeof addrstr, "%.4x",
         (unsigned int)((uintptr_t)p - (uintptr_t)data) );
    }

    c = *p;
    if (isprint(c) == 0) {
      c = '.';
    }

    snprintf(bytestr, sizeof bytestr, "%02X ", (unsigned char)*p);
    strncat(hexstr, bytestr, sizeof hexstr - strlen(hexstr) - 1);

    snprintf(bytestr, sizeof bytestr, "%c", c);
    strncat(charstr, bytestr, sizeof charstr - strlen(charstr) - 1);

    if (n%16 == 0) {
      printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
      hexstr[0] = 0;
      charstr[0] = 0;
    } else if (n%8 == 0) {
      strncat(hexstr, "  ", sizeof hexstr - strlen(hexstr) - 1);
      strncat(charstr, " ", sizeof charstr - strlen(charstr) - 1);
    }

    p++;
  }

  if (strlen(hexstr) > 0) {
    printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
  }
  
  funlockfile(stdout);
}
#endif // HEX_DUMP

// redirect utility functions
char* strstr_last(const char* const str1, const char* const str2) {
  char *strp;
  int len1, len2;
  len2 = strlen(str2);
  if (len2==0) {
    return (char *) str1;
  }
  len1 = strlen(str1);
  if (len1 - len2 <= 0) {
    return 0;
  }
  strp = (char *)(str1 + len1 - len2);
  while (strp != str1) {
    if (*strp == *str2 && strncmp(strp, str2, len2) == 0) {
      return strp;
    }
    strp--;
  }
  return 0;
}

char* strstr_first(const char* const str1, const char* const str2) {
  if (!str1) return NULL;
  if (!str2) return (char*)str1;
  return strstr(str1, str2);
}

char from_hex(const char ch) {
  return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

void urldecode(char* const decoded, char* const encoded) {
  char* pstr = encoded;
  char* pbuf = decoded;

  while (*pstr) {
    if (*pstr == '%') {
      if (pstr[1] && pstr[2]) {
        *pbuf++ = from_hex(pstr[1]) << 4 | from_hex(pstr[2]);
        pstr += 2;
      }
    } else {
      *pbuf++ = *pstr;
    }
    pstr++;
  }
  *pbuf = '\0';
}

#ifdef DEBUG
void child_signal_handler(int sig)
{
  if (sig != SIGTERM && sig != SIGUSR2) {
    return;
  }

  if (sig == SIGTERM) {
    signal(SIGTERM, SIG_IGN);
  }

  if (sig == SIGTERM) {
    exit(EXIT_SUCCESS);
  }

  return;
}

#define TIME_CHECK(x) {\
  if (do_warning) {\
    do_warning = 0;\
    double time_msec = 0.0;\
    time_msec = elapsed_time_msec(start_time);\
    if (time_msec > config.warning_time) {\
    }\
  }\
}

#define ELAPSED_TIME(op) {\
    double time_msec = 0.0;\
    time_msec = elapsed_time_msec(start_time);\
}
#else
#define TIME_CHECK(x) ((void)0)
#define ELAPSED_TIME(x) ((void)0)
#endif //DEBUG

extern struct Global *g;
static struct timespec start_time = {0, 0};

static int peek_socket(int fd, SSL *ssl) {
  char buf[10];
  int rv = -1;

  if (!ssl)
    rv = recv(fd, buf, 10, MSG_PEEK);
  else
    rv = SSL_peek(ssl, buf, 10);
  TESTPRINT("%s rv:%d\n", __FUNCTION__, rv);
  return rv;
}

static int ssl_read(SSL *ssl, char *buf, int len) {
  int ssl_attempt = 1, ret;

redo_ssl_read:

  ERR_clear_error();
  ret = SSL_read(ssl, (char *)buf, len);
  if (ret <= 0) {
    int sslerr = SSL_get_error(ssl, ret);
    switch(sslerr) {
      case SSL_ERROR_WANT_READ:
        ssl_attempt--;
        if (ssl_attempt > 0) goto redo_ssl_read;
        break;
      case SSL_ERROR_SSL:
        break;
      case SSL_ERROR_SYSCALL:
      default:
        ;
    }
  }
  return ret;
}

static int read_socket(int fd, char **msg, SSL *ssl, char *early_data)
{
  if (early_data) {
    *msg = early_data;
    return strlen(early_data);
  }

  /* FIX: Save old pointer to avoid leak on realloc failure */
  char *old_msg = *msg;
  char *new_msg = realloc(old_msg, CHAR_BUF_SIZE + 1);
  if (!new_msg) {
    /* Keep old buffer, don't lose it */
    return -1;
  }
  *msg = new_msg;

  int i, rv, msg_len = 0;
  char *bufptr = *msg;
  for (i=1; i<=MAX_CHAR_BUF_LOTS;) {
    if (!ssl)
      rv = recv(fd, bufptr, CHAR_BUF_SIZE, 0);
    else
      rv = ssl_read(ssl, (char *)bufptr, CHAR_BUF_SIZE);

    if (rv <= 0) break;

    msg_len += rv;
    if (rv < CHAR_BUF_SIZE)
      break;
    else {
      ++i;
      /* FIX: Safe realloc - don't lose existing data on failure */
      new_msg = realloc(*msg, CHAR_BUF_SIZE * i + 1);
      if (!new_msg) {
          /* Return what we have so far, buffer is still valid */
          (*msg)[msg_len] = '\0';
          return msg_len;
      }
      *msg = new_msg;
      bufptr = *msg + CHAR_BUF_SIZE * (i - 1);
    }
  }
  TESTPRINT("%s: fd:%d msg_len:%d ssl:%p\n", __FUNCTION__, fd, msg_len, ssl);
  return msg_len;
}

static int ssl_write(SSL *ssl, const char *buf, int len) {
  int ssl_attempt = 1, ret;
redo_ssl_write:
  ERR_clear_error();
  ret = SSL_write(ssl, (char *)buf, len);
  if (ret <= 0) {
    int sslerr = SSL_get_error(ssl, ret);
    switch(sslerr) {
      case SSL_ERROR_WANT_WRITE:
        ssl_attempt--;
        if (ssl_attempt > 0) goto redo_ssl_write;
        break;
      case SSL_ERROR_SSL:
        break;
      case SSL_ERROR_SYSCALL:
      default:
        ;
    }
  }
  return ret;
}

// KORRIGIERTE write_socket Funktion mit html_index Content-Sending
static int write_socket(int fd, const char *msg, int msg_len, SSL *ssl, char **early_data)
{
  int rv;
  int needs_html_content = 0;
  
  // Prüfe ob diese Response html_index Content braucht
  if (strstr(msg, "Content-Length:") && (
      strstr(msg, "text/html") || 
      strstr(msg, "application/javascript") ||
      strstr(msg, "application/octet-stream"))) {
    needs_html_content = 1;
  }
  
  // Sende Header
  if (ssl) {
#ifdef TLS1_3_VERSION
    if (*early_data) {
      int early_rv = SSL_write_early_data(ssl, msg, msg_len, (size_t*)&rv);
      if (early_rv <= 0) {
        return -1;
      }

      if (SSL_accept(ssl) <= 0) {
        return -1;
      }

      *early_data = NULL;

    } else
#endif
      rv = ssl_write(ssl, msg, msg_len);
  } else {
    rv = send(fd, msg, msg_len, 0);
  }
  
  // KORRIGIERT: Sende html_index Content (falls vorhanden und erforderlich)
  if (rv > 0 && needs_html_content && get_index_html_len() > 0) {
    if (ssl) {
      ssl_write(ssl, (const char*)get_index_html(), get_index_html_len());
    } else {
      send(fd, (const char*)get_index_html(), get_index_html_len(), 0);
    }
  }
  
  return rv;
}

static int write_pipe(int fd, response_struct *pipedata) {
  int attempts = 3;
  while (attempts--) {
    int rv = write(fd, pipedata, sizeof(*pipedata));
    
    if (rv == sizeof(*pipedata)) {
      return rv;
    }
    
    if (rv < 0) {
      if (errno == EINTR || errno == EAGAIN) {
        continue;
      }
      return rv;
    } else if (rv == 0) {
      return rv;
    } else {
      continue;
    }
  }
  
  return -1;
}

/* ========== Extension Lookup Table ========== */
/* Fast O(1) lookup for file extensions without strcasecmp chains */

typedef struct {
    const char *ext;           /* Extension without dot (e.g., "gif", "ico") */
    response_enum type;        /* Response type for this extension */
    const char *response_data; /* Pointer to HTTP response data (NULL = httpnulltext) */
    int response_size;         /* Size of response data (-1 = sizeof(data)-1) */
} ext_entry_t;

/* Extension lookup table - covers all common file types with response data */
static const ext_entry_t ext_table[] = {
    /* Images with specific response templates */
    {"gif", SEND_GIF, (const char *)httpnullpixel, sizeof(httpnullpixel) - 1},
    {"png", SEND_PNG, (const char *)httpnull_png, sizeof(httpnull_png) - 1},
    {"jpg", SEND_JPG, (const char *)httpnull_jpg, sizeof(httpnull_jpg) - 1},
    {"jpeg", SEND_JPG, (const char *)httpnull_jpg, sizeof(httpnull_jpg) - 1},
    {"jp2", SEND_JPG, (const char *)httpnull_jpg, sizeof(httpnull_jpg) - 1},
    {"jpe", SEND_JPG, (const char *)httpnull_jpg, sizeof(httpnull_jpg) - 1},
    {"swf", SEND_SWF, (const char *)httpnull_swf, sizeof(httpnull_swf) - 1},
    {"ico", SEND_ICO, (const char *)httpnull_ico, sizeof(httpnull_ico) - 1},

    /* Server-side Scripts with specific response templates */
    {"asp", SEND_ASP, (const char *)httpnull_asp, sizeof(httpnull_asp) - 1},
    {"aspx", SEND_ASPX, (const char *)httpnull_aspx, sizeof(httpnull_aspx) - 1},
    {"ashx", SEND_ASHX, (const char *)httpnull_ashx, sizeof(httpnull_ashx) - 1},
    {"php", SEND_PHP, (const char *)httpnull_php, sizeof(httpnull_php) - 1},
    {"jsp", SEND_JSP, (const char *)httpnull_jsp, sizeof(httpnull_jsp) - 1},
    {"js", SEND_JS, (const char *)httpnull_js, sizeof(httpnull_js) - 1},

    {"%", SEND_TXT, httpnulltext, -1},
    {"123", SEND_TXT, httpnulltext, -1},
    {"1905.1", SEND_TXT, httpnulltext, -1},
    {"1clr", SEND_TXT, httpnulltext, -1},
    {"1km", SEND_TXT, httpnulltext, -1},
    {"210", SEND_TXT, httpnulltext, -1},
    {"3dm", SEND_TXT, httpnulltext, -1},
    {"3dml", SEND_TXT, httpnulltext, -1},
    {"3mf", SEND_TXT, httpnulltext, -1},
    {"3tz", SEND_TXT, httpnulltext, -1},
    {"726", SEND_TXT, httpnulltext, -1},
    {"7z", SEND_TXT, httpnulltext, -1},
    {"AMR", SEND_TXT, httpnulltext, -1},
    {"AWB", SEND_TXT, httpnulltext, -1},
    {"CQL", SEND_TXT, httpnulltext, -1},
    {"ELN", SEND_TXT, httpnulltext, -1},
    {"J2C", SEND_TXT, httpnulltext, -1},
    {"J2K", SEND_TXT, httpnulltext, -1},
    {"PGB", SEND_TXT, httpnulltext, -1},
    {"QCP", SEND_TXT, httpnulltext, -1},
    {"SAR", SEND_TXT, httpnulltext, -1},
    {"VES", SEND_TXT, httpnulltext, -1},
    {"VFK", SEND_TXT, httpnulltext, -1},
    {"a", SEND_TXT, httpnulltext, -1},
    {"a2l", SEND_TXT, httpnulltext, -1},
    {"aa3", SEND_TXT, httpnulltext, -1},
    {"aac", SEND_TXT, httpnulltext, -1},
    {"aal", SEND_TXT, httpnulltext, -1},
    {"abc", SEND_TXT, httpnulltext, -1},
    {"abw", SEND_TXT, httpnulltext, -1},
    {"ac", SEND_TXT, httpnulltext, -1},
    {"ac2", SEND_TXT, httpnulltext, -1},
    {"ac3", SEND_TXT, httpnulltext, -1},
    {"acc", SEND_TXT, httpnulltext, -1},
    {"acn", SEND_TXT, httpnulltext, -1},
    {"acu", SEND_TXT, httpnulltext, -1},
    {"acutc", SEND_TXT, httpnulltext, -1},
    {"adts", SEND_TXT, httpnulltext, -1},
    {"aep", SEND_TXT, httpnulltext, -1},
    {"afp", SEND_TXT, httpnulltext, -1},
    {"age", SEND_TXT, httpnulltext, -1},
    {"ahead", SEND_TXT, httpnulltext, -1},
    {"ai", SEND_TXT, httpnulltext, -1},
    {"aif", SEND_TXT, httpnulltext, -1},
    {"aifc", SEND_TXT, httpnulltext, -1},
    {"aiff", SEND_TXT, httpnulltext, -1},
    {"aion", SEND_TXT, httpnulltext, -1},
    {"ait", SEND_TXT, httpnulltext, -1},
    {"alc", SEND_TXT, httpnulltext, -1},
    {"ami", SEND_TXT, httpnulltext, -1},
    {"aml", SEND_TXT, httpnulltext, -1},
    {"amlx", SEND_TXT, httpnulltext, -1},
    {"amr", SEND_TXT, httpnulltext, -1},
    {"anx", SEND_TXT, httpnulltext, -1},
    {"apex", SEND_TXT, httpnulltext, -1},
    {"apexlang", SEND_TXT, httpnulltext, -1},
    {"apk", SEND_TXT, httpnulltext, -1},
    {"apkg", SEND_TXT, httpnulltext, -1},
    {"apng", SEND_TXT, httpnulltext, -1},
    {"appcache", SEND_TXT, httpnulltext, -1},
    {"apr", SEND_TXT, httpnulltext, -1},
    {"apxml", SEND_TXT, httpnulltext, -1},
    {"arrow", SEND_TXT, httpnulltext, -1},
    {"arrows", SEND_TXT, httpnulltext, -1},
    {"art", SEND_TXT, httpnulltext, -1},
    {"artisan", SEND_TXT, httpnulltext, -1},
    {"asc", SEND_TXT, httpnulltext, -1},
    {"ascii", SEND_TXT, httpnulltext, -1},
    {"asf", SEND_TXT, httpnulltext, -1},
    {"asice", SEND_TXT, httpnulltext, -1},
    {"asics", SEND_TXT, httpnulltext, -1},
    {"asn", SEND_TXT, httpnulltext, -1},
    {"aso", SEND_TXT, httpnulltext, -1},
    {"ass", SEND_TXT, httpnulltext, -1},
    {"at3", SEND_TXT, httpnulltext, -1},
    {"atc", SEND_TXT, httpnulltext, -1},
    {"atf", SEND_TXT, httpnulltext, -1},
    {"atfx", SEND_TXT, httpnulltext, -1},
    {"atom", SEND_TXT, httpnulltext, -1},
    {"atomcat", SEND_TXT, httpnulltext, -1},
    {"atomdeleted", SEND_TXT, httpnulltext, -1},
    {"atomsrv", SEND_TXT, httpnulltext, -1},
    {"atomsvc", SEND_TXT, httpnulltext, -1},
    {"atx", SEND_TXT, httpnulltext, -1},
    {"atxml", SEND_TXT, httpnulltext, -1},
    {"au", SEND_TXT, httpnulltext, -1},
    {"auc", SEND_TXT, httpnulltext, -1},
    {"avci", SEND_TXT, httpnulltext, -1},
    {"avcs", SEND_TXT, httpnulltext, -1},
    {"avi", SEND_TXT, httpnulltext, -1},
    {"avif", SEND_TXT, httpnulltext, -1},
    {"awb", SEND_TXT, httpnulltext, -1},
    {"axa", SEND_TXT, httpnulltext, -1},
    {"axv", SEND_TXT, httpnulltext, -1},
    {"azf", SEND_TXT, httpnulltext, -1},
    {"azs", SEND_TXT, httpnulltext, -1},
    {"azv", SEND_TXT, httpnulltext, -1},
    {"azw3", SEND_TXT, httpnulltext, -1},
    {"b", SEND_TXT, httpnulltext, -1},
    {"b16", SEND_TXT, httpnulltext, -1},
    {"bak", SEND_TXT, httpnulltext, -1},
    {"bar", SEND_TXT, httpnulltext, -1},
    {"bary", SEND_TXT, httpnulltext, -1},
    {"bat", SEND_TXT, httpnulltext, -1},
    {"bcpio", SEND_TXT, httpnulltext, -1},
    {"bdm", SEND_TXT, httpnulltext, -1},
    {"bed", SEND_TXT, httpnulltext, -1},
    {"bh2", SEND_TXT, httpnulltext, -1},
    {"bib", SEND_TXT, httpnulltext, -1},
    {"bik", SEND_TXT, httpnulltext, -1},
    {"bin", SEND_TXT, httpnulltext, -1},
    {"bk2", SEND_TXT, httpnulltext, -1},
    {"bkm", SEND_TXT, httpnulltext, -1},
    {"bmed", SEND_TXT, httpnulltext, -1},
    {"bmi", SEND_TXT, httpnulltext, -1},
    {"bmml", SEND_TXT, httpnulltext, -1},
    {"bmp", SEND_TXT, httpnulltext, -1},
    {"bmpr", SEND_TXT, httpnulltext, -1},
    {"boo", SEND_TXT, httpnulltext, -1},
    {"book", SEND_TXT, httpnulltext, -1},
    {"box", SEND_TXT, httpnulltext, -1},
    {"bpd", SEND_TXT, httpnulltext, -1},
    {"brf", SEND_TXT, httpnulltext, -1},
    {"bsd", SEND_TXT, httpnulltext, -1},
    {"bsp", SEND_TXT, httpnulltext, -1},
    {"btf", SEND_TXT, httpnulltext, -1},
    {"btif", SEND_TXT, httpnulltext, -1},
    {"c", SEND_TXT, httpnulltext, -1},
    {"c++", SEND_TXT, httpnulltext, -1},
    {"c11amc", SEND_TXT, httpnulltext, -1},
    {"c11amz", SEND_TXT, httpnulltext, -1},
    {"c3d", SEND_TXT, httpnulltext, -1},
    {"c3ex", SEND_TXT, httpnulltext, -1},
    {"c4d", SEND_TXT, httpnulltext, -1},
    {"c4f", SEND_TXT, httpnulltext, -1},
    {"c4g", SEND_TXT, httpnulltext, -1},
    {"c4p", SEND_TXT, httpnulltext, -1},
    {"c4u", SEND_TXT, httpnulltext, -1},
    {"c9r", SEND_TXT, httpnulltext, -1},
    {"c9s", SEND_TXT, httpnulltext, -1},
    {"cab", SEND_TXT, httpnulltext, -1},
    {"cac", SEND_TXT, httpnulltext, -1},
    {"cache", SEND_TXT, httpnulltext, -1},
    {"cap", SEND_TXT, httpnulltext, -1},
    {"car", SEND_TXT, httpnulltext, -1},
    {"carjson", SEND_TXT, httpnulltext, -1},
    {"cascii", SEND_TXT, httpnulltext, -1},
    {"cat", SEND_TXT, httpnulltext, -1},
    {"cbin", SEND_TXT, httpnulltext, -1},
    {"cbor", SEND_TXT, httpnulltext, -1},
    {"cbr", SEND_TXT, httpnulltext, -1},
    {"cbz", SEND_TXT, httpnulltext, -1},
    {"cc", SEND_TXT, httpnulltext, -1},
    {"ccc", SEND_TXT, httpnulltext, -1},
    {"ccmp", SEND_TXT, httpnulltext, -1},
    {"ccxml", SEND_TXT, httpnulltext, -1},
    {"cda", SEND_TXT, httpnulltext, -1},
    {"cdbcmsg", SEND_TXT, httpnulltext, -1},
    {"cdf", SEND_TXT, httpnulltext, -1},
    {"cdfx", SEND_TXT, httpnulltext, -1},
    {"cdkey", SEND_TXT, httpnulltext, -1},
    {"cdmia", SEND_TXT, httpnulltext, -1},
    {"cdmic", SEND_TXT, httpnulltext, -1},
    {"cdmid", SEND_TXT, httpnulltext, -1},
    {"cdmio", SEND_TXT, httpnulltext, -1},
    {"cdmiq", SEND_TXT, httpnulltext, -1},
    {"cdr", SEND_TXT, httpnulltext, -1},
    {"cdt", SEND_TXT, httpnulltext, -1},
    {"cdx", SEND_TXT, httpnulltext, -1},
    {"cdxml", SEND_TXT, httpnulltext, -1},
    {"cdy", SEND_TXT, httpnulltext, -1},
    {"cea", SEND_TXT, httpnulltext, -1},
    {"cef", SEND_TXT, httpnulltext, -1},
    {"cellml", SEND_TXT, httpnulltext, -1},
    {"cer", SEND_TXT, httpnulltext, -1},
    {"cgm", SEND_TXT, httpnulltext, -1},
    {"chm", SEND_TXT, httpnulltext, -1},
    {"chrt", SEND_TXT, httpnulltext, -1},
    {"cif", SEND_TXT, httpnulltext, -1},
    {"cii", SEND_TXT, httpnulltext, -1},
    {"cil", SEND_TXT, httpnulltext, -1},
    {"cl", SEND_TXT, httpnulltext, -1},
    {"cla", SEND_TXT, httpnulltext, -1},
    {"class", SEND_TXT, httpnulltext, -1},
    {"cld", SEND_TXT, httpnulltext, -1},
    {"clkk", SEND_TXT, httpnulltext, -1},
    {"clkp", SEND_TXT, httpnulltext, -1},
    {"clkt", SEND_TXT, httpnulltext, -1},
    {"clkw", SEND_TXT, httpnulltext, -1},
    {"clkx", SEND_TXT, httpnulltext, -1},
    {"cls", SEND_TXT, httpnulltext, -1},
    {"clue", SEND_TXT, httpnulltext, -1},
    {"cmc", SEND_TXT, httpnulltext, -1},
    {"cmdf", SEND_TXT, httpnulltext, -1},
    {"cml", SEND_TXT, httpnulltext, -1},
    {"cmp", SEND_TXT, httpnulltext, -1},
    {"cmsc", SEND_TXT, httpnulltext, -1},
    {"cnd", SEND_TXT, httpnulltext, -1},
    {"cod", SEND_TXT, httpnulltext, -1},
    {"coffee", SEND_TXT, httpnulltext, -1},
    {"com", SEND_TXT, httpnulltext, -1},
    {"copyright", SEND_TXT, httpnulltext, -1},
    {"coswid", SEND_TXT, httpnulltext, -1},
    {"cpa", SEND_TXT, httpnulltext, -1},
    {"cpio", SEND_TXT, httpnulltext, -1},
    {"cpkg", SEND_TXT, httpnulltext, -1},
    {"cpl", SEND_TXT, httpnulltext, -1},
    {"cpp", SEND_TXT, httpnulltext, -1},
    {"cpt", SEND_TXT, httpnulltext, -1},
    {"cr2", SEND_TXT, httpnulltext, -1},
    {"crl", SEND_TXT, httpnulltext, -1},
    {"crt", SEND_TXT, httpnulltext, -1},
    {"crtr", SEND_TXT, httpnulltext, -1},
    {"crw", SEND_TXT, httpnulltext, -1},
    {"cryptomator", SEND_TXT, httpnulltext, -1},
    {"cryptonote", SEND_TXT, httpnulltext, -1},
    {"csd", SEND_TXT, httpnulltext, -1},
    {"csf", SEND_TXT, httpnulltext, -1},
    {"csh", SEND_TXT, httpnulltext, -1},
    {"csl", SEND_TXT, httpnulltext, -1},
    {"csm", SEND_TXT, httpnulltext, -1},
    {"csml", SEND_TXT, httpnulltext, -1},
    {"csp", SEND_TXT, httpnulltext, -1},
    {"csrattrs", SEND_TXT, httpnulltext, -1},
    {"css", SEND_TXT, httpnulltext, -1},
    {"cst", SEND_TXT, httpnulltext, -1},
    {"csv", SEND_TXT, httpnulltext, -1},
    {"csvs", SEND_TXT, httpnulltext, -1},
    {"ctab", SEND_TXT, httpnulltext, -1},
    {"ctx", SEND_TXT, httpnulltext, -1},
    {"cu", SEND_TXT, httpnulltext, -1},
    {"cub", SEND_TXT, httpnulltext, -1},
    {"cuc", SEND_TXT, httpnulltext, -1},
    {"curl", SEND_TXT, httpnulltext, -1},
    {"cw", SEND_TXT, httpnulltext, -1},
    {"cwl", SEND_TXT, httpnulltext, -1},
    {"cwl.json", SEND_TXT, httpnulltext, -1},
    {"cww", SEND_TXT, httpnulltext, -1},
    {"cxf", SEND_TXT, httpnulltext, -1},
    {"cxx", SEND_TXT, httpnulltext, -1},
    {"d", SEND_TXT, httpnulltext, -1},
    {"dae", SEND_TXT, httpnulltext, -1},
    {"daf", SEND_TXT, httpnulltext, -1},
    {"dart", SEND_TXT, httpnulltext, -1},
    {"dataless", SEND_TXT, httpnulltext, -1},
    {"davmount", SEND_TXT, httpnulltext, -1},
    {"dbf", SEND_TXT, httpnulltext, -1},
    {"dcd", SEND_TXT, httpnulltext, -1},
    {"dcm", SEND_TXT, httpnulltext, -1},
    {"dcr", SEND_TXT, httpnulltext, -1},
    {"dd2", SEND_TXT, httpnulltext, -1},
    {"ddd", SEND_TXT, httpnulltext, -1},
    {"ddeb", SEND_TXT, httpnulltext, -1},
    {"ddf", SEND_TXT, httpnulltext, -1},
    {"deb", SEND_TXT, httpnulltext, -1},
    {"deploy", SEND_TXT, httpnulltext, -1},
    {"dfac", SEND_TXT, httpnulltext, -1},
    {"dif", SEND_TXT, httpnulltext, -1},
    {"diff", SEND_TXT, httpnulltext, -1},
    {"dii", SEND_TXT, httpnulltext, -1},
    {"dim", SEND_TXT, httpnulltext, -1},
    {"dir", SEND_TXT, httpnulltext, -1},
    {"dis", SEND_TXT, httpnulltext, -1},
    {"dist", SEND_TXT, httpnulltext, -1},
    {"distz", SEND_TXT, httpnulltext, -1},
    {"dit", SEND_TXT, httpnulltext, -1},
    {"dive", SEND_TXT, httpnulltext, -1},
    {"djv", SEND_TXT, httpnulltext, -1},
    {"djvu", SEND_TXT, httpnulltext, -1},
    {"dl", SEND_TXT, httpnulltext, -1},
    {"dll", SEND_TXT, httpnulltext, -1},
    {"dls", SEND_TXT, httpnulltext, -1},
    {"dmg", SEND_TXT, httpnulltext, -1},
    {"dmp", SEND_TXT, httpnulltext, -1},
    {"dms", SEND_TXT, httpnulltext, -1},
    {"dna", SEND_TXT, httpnulltext, -1},
    {"doc", SEND_TXT, httpnulltext, -1},
    {"docjson", SEND_TXT, httpnulltext, -1},
    {"docm", SEND_TXT, httpnulltext, -1},
    {"docx", SEND_TXT, httpnulltext, -1},
    {"dor", SEND_TXT, httpnulltext, -1},
    {"dot", SEND_TXT, httpnulltext, -1},
    {"dotm", SEND_TXT, httpnulltext, -1},
    {"dotx", SEND_TXT, httpnulltext, -1},
    {"dp", SEND_TXT, httpnulltext, -1},
    {"dpg", SEND_TXT, httpnulltext, -1},
    {"dpgraph", SEND_TXT, httpnulltext, -1},
    {"dpkg", SEND_TXT, httpnulltext, -1},
    {"dpx", SEND_TXT, httpnulltext, -1},
    {"drle", SEND_TXT, httpnulltext, -1},
    {"dsc", SEND_TXT, httpnulltext, -1},
    {"dsm", SEND_TXT, httpnulltext, -1},
    {"dssc", SEND_TXT, httpnulltext, -1},
    {"dtd", SEND_TXT, httpnulltext, -1},
    {"dts", SEND_TXT, httpnulltext, -1},
    {"dtshd", SEND_TXT, httpnulltext, -1},
    {"dv", SEND_TXT, httpnulltext, -1},
    {"dvb", SEND_TXT, httpnulltext, -1},
    {"dvc", SEND_TXT, httpnulltext, -1},
    {"dvi", SEND_TXT, httpnulltext, -1},
    {"dwd", SEND_TXT, httpnulltext, -1},
    {"dwf", SEND_TXT, httpnulltext, -1},
    {"dwg", SEND_TXT, httpnulltext, -1},
    {"dx", SEND_TXT, httpnulltext, -1},
    {"dxf", SEND_TXT, httpnulltext, -1},
    {"dxp", SEND_TXT, httpnulltext, -1},
    {"dxr", SEND_TXT, httpnulltext, -1},
    {"dzr", SEND_TXT, httpnulltext, -1},
    {"ebuild", SEND_TXT, httpnulltext, -1},
    {"ecelp4800", SEND_TXT, httpnulltext, -1},
    {"ecelp7470", SEND_TXT, httpnulltext, -1},
    {"ecelp9600", SEND_TXT, httpnulltext, -1},
    {"ecig", SEND_TXT, httpnulltext, -1},
    {"ecigprofile", SEND_TXT, httpnulltext, -1},
    {"ecigtheme", SEND_TXT, httpnulltext, -1},
    {"eclass", SEND_TXT, httpnulltext, -1},
    {"edm", SEND_TXT, httpnulltext, -1},
    {"edx", SEND_TXT, httpnulltext, -1},
    {"efi", SEND_TXT, httpnulltext, -1},
    {"efif", SEND_TXT, httpnulltext, -1},
    {"ei6", SEND_TXT, httpnulltext, -1},
    {"emb", SEND_TXT, httpnulltext, -1},
    {"embl", SEND_TXT, httpnulltext, -1},
    {"emf", SEND_TXT, httpnulltext, -1},
    {"eml", SEND_TXT, httpnulltext, -1},
    {"emm", SEND_TXT, httpnulltext, -1},
    {"emma", SEND_TXT, httpnulltext, -1},
    {"emotionml", SEND_TXT, httpnulltext, -1},
    {"ent", SEND_TXT, httpnulltext, -1},
    {"entity", SEND_TXT, httpnulltext, -1},
    {"enw", SEND_TXT, httpnulltext, -1},
    {"eol", SEND_TXT, httpnulltext, -1},
    {"eot", SEND_TXT, httpnulltext, -1},
    {"ep", SEND_TXT, httpnulltext, -1},
    {"eps", SEND_TXT, httpnulltext, -1},
    {"eps2", SEND_TXT, httpnulltext, -1},
    {"eps3", SEND_TXT, httpnulltext, -1},
    {"epsf", SEND_TXT, httpnulltext, -1},
    {"epsi", SEND_TXT, httpnulltext, -1},
    {"epub", SEND_TXT, httpnulltext, -1},
    {"erf", SEND_TXT, httpnulltext, -1},
    {"es", SEND_TXT, httpnulltext, -1},
    {"es3", SEND_TXT, httpnulltext, -1},
    {"esa", SEND_TXT, httpnulltext, -1},
    {"esf", SEND_TXT, httpnulltext, -1},
    {"espass", SEND_TXT, httpnulltext, -1},
    {"et3", SEND_TXT, httpnulltext, -1},
    {"etx", SEND_TXT, httpnulltext, -1},
    {"evb", SEND_TXT, httpnulltext, -1},
    {"evc", SEND_TXT, httpnulltext, -1},
    {"evw", SEND_TXT, httpnulltext, -1},
    {"exe", SEND_TXT, httpnulltext, -1},
    {"exi", SEND_TXT, httpnulltext, -1},
    {"exp", SEND_TXT, httpnulltext, -1},
    {"exr", SEND_TXT, httpnulltext, -1},
    {"ext", SEND_TXT, httpnulltext, -1},
    {"ez", SEND_TXT, httpnulltext, -1},
    {"ez2", SEND_TXT, httpnulltext, -1},
    {"ez3", SEND_TXT, httpnulltext, -1},
    {"fb", SEND_TXT, httpnulltext, -1},
    {"fbdoc", SEND_TXT, httpnulltext, -1},
    {"fbs", SEND_TXT, httpnulltext, -1},
    {"fcdt", SEND_TXT, httpnulltext, -1},
    {"fch", SEND_TXT, httpnulltext, -1},
    {"fchk", SEND_TXT, httpnulltext, -1},
    {"fcs", SEND_TXT, httpnulltext, -1},
    {"fdf", SEND_TXT, httpnulltext, -1},
    {"fdt", SEND_TXT, httpnulltext, -1},
    {"fe_launch", SEND_TXT, httpnulltext, -1},
    {"fg5", SEND_TXT, httpnulltext, -1},
    {"fig", SEND_TXT, httpnulltext, -1},
    {"finf", SEND_TXT, httpnulltext, -1},
    {"fit", SEND_TXT, httpnulltext, -1},
    {"fits", SEND_TXT, httpnulltext, -1},
    {"fla", SEND_TXT, httpnulltext, -1},
    {"flac", SEND_TXT, httpnulltext, -1},
    {"flb", SEND_TXT, httpnulltext, -1},
    {"fli", SEND_TXT, httpnulltext, -1},
    {"flo", SEND_TXT, httpnulltext, -1},
    {"flt", SEND_TXT, httpnulltext, -1},
    {"flv", SEND_TXT, httpnulltext, -1},
    {"flw", SEND_TXT, httpnulltext, -1},
    {"flx", SEND_TXT, httpnulltext, -1},
    {"fly", SEND_TXT, httpnulltext, -1},
    {"fm", SEND_TXT, httpnulltext, -1},
    {"fo", SEND_TXT, httpnulltext, -1},
    {"fpx", SEND_TXT, httpnulltext, -1},
    {"frame", SEND_TXT, httpnulltext, -1},
    {"frm", SEND_TXT, httpnulltext, -1},
    {"fsc", SEND_TXT, httpnulltext, -1},
    {"fst", SEND_TXT, httpnulltext, -1},
    {"ftc", SEND_TXT, httpnulltext, -1},
    {"fti", SEND_TXT, httpnulltext, -1},
    {"fts", SEND_TXT, httpnulltext, -1},
    {"fvt", SEND_TXT, httpnulltext, -1},
    {"fxp", SEND_TXT, httpnulltext, -1},
    {"fxpl", SEND_TXT, httpnulltext, -1},
    {"fzs", SEND_TXT, httpnulltext, -1},
    {"g2w", SEND_TXT, httpnulltext, -1},
    {"g3w", SEND_TXT, httpnulltext, -1},
    {"gac", SEND_TXT, httpnulltext, -1},
    {"gal", SEND_TXT, httpnulltext, -1},
    {"gam", SEND_TXT, httpnulltext, -1},
    {"gamin", SEND_TXT, httpnulltext, -1},
    {"gan", SEND_TXT, httpnulltext, -1},
    {"gau", SEND_TXT, httpnulltext, -1},
    {"gbr", SEND_TXT, httpnulltext, -1},
    {"gcd", SEND_TXT, httpnulltext, -1},
    {"gcf", SEND_TXT, httpnulltext, -1},
    {"gcg", SEND_TXT, httpnulltext, -1},
    {"gdl", SEND_TXT, httpnulltext, -1},
    {"gdz", SEND_TXT, httpnulltext, -1},
    {"ged", SEND_TXT, httpnulltext, -1},
    {"gen", SEND_TXT, httpnulltext, -1},
    {"genozip", SEND_TXT, httpnulltext, -1},
    {"geo", SEND_TXT, httpnulltext, -1},
    {"geojson", SEND_TXT, httpnulltext, -1},
    {"gex", SEND_TXT, httpnulltext, -1},
    {"gf", SEND_TXT, httpnulltext, -1},
    {"gff3", SEND_TXT, httpnulltext, -1},
    {"ggb", SEND_TXT, httpnulltext, -1},
    {"ggs", SEND_TXT, httpnulltext, -1},
    {"ggt", SEND_TXT, httpnulltext, -1},
    {"ghf", SEND_TXT, httpnulltext, -1},
    {"gim", SEND_TXT, httpnulltext, -1},
    {"gjc", SEND_TXT, httpnulltext, -1},
    {"gjf", SEND_TXT, httpnulltext, -1},
    {"gl", SEND_TXT, httpnulltext, -1},
    {"glb", SEND_TXT, httpnulltext, -1},
    {"glbin", SEND_TXT, httpnulltext, -1},
    {"glbuf", SEND_TXT, httpnulltext, -1},
    {"gltf", SEND_TXT, httpnulltext, -1},
    {"gml", SEND_TXT, httpnulltext, -1},
    {"gnumeric", SEND_TXT, httpnulltext, -1},
    {"gph", SEND_TXT, httpnulltext, -1},
    {"gpkg", SEND_TXT, httpnulltext, -1},
    {"gpkg.tar", SEND_TXT, httpnulltext, -1},
    {"gpt", SEND_TXT, httpnulltext, -1},
    {"gqf", SEND_TXT, httpnulltext, -1},
    {"gqs", SEND_TXT, httpnulltext, -1},
    {"gram", SEND_TXT, httpnulltext, -1},
    {"grd", SEND_TXT, httpnulltext, -1},
    {"gre", SEND_TXT, httpnulltext, -1},
    {"grv", SEND_TXT, httpnulltext, -1},
    {"grxml", SEND_TXT, httpnulltext, -1},
    {"gsf", SEND_TXT, httpnulltext, -1},
    {"gsheet", SEND_TXT, httpnulltext, -1},
    {"gsm", SEND_TXT, httpnulltext, -1},
    {"gtar", SEND_TXT, httpnulltext, -1},
    {"gtm", SEND_TXT, httpnulltext, -1},
    {"gtw", SEND_TXT, httpnulltext, -1},
    {"gv", SEND_TXT, httpnulltext, -1},
    {"gxt", SEND_TXT, httpnulltext, -1},
    {"gz", SEND_TXT, httpnulltext, -1},
    {"h", SEND_TXT, httpnulltext, -1},
    {"h++", SEND_TXT, httpnulltext, -1},
    {"hal", SEND_TXT, httpnulltext, -1},
    {"hans", SEND_TXT, httpnulltext, -1},
    {"hbc", SEND_TXT, httpnulltext, -1},
    {"hbci", SEND_TXT, httpnulltext, -1},
    {"hdf", SEND_TXT, httpnulltext, -1},
    {"hdr", SEND_TXT, httpnulltext, -1},
    {"hdt", SEND_TXT, httpnulltext, -1},
    {"heic", SEND_TXT, httpnulltext, -1},
    {"heics", SEND_TXT, httpnulltext, -1},
    {"heif", SEND_TXT, httpnulltext, -1},
    {"heifs", SEND_TXT, httpnulltext, -1},
    {"hej2", SEND_TXT, httpnulltext, -1},
    {"held", SEND_TXT, httpnulltext, -1},
    {"hgl", SEND_TXT, httpnulltext, -1},
    {"hh", SEND_TXT, httpnulltext, -1},
    {"hif", SEND_TXT, httpnulltext, -1},
    {"hin", SEND_TXT, httpnulltext, -1},
    {"hpgl", SEND_TXT, httpnulltext, -1},
    {"hpi", SEND_TXT, httpnulltext, -1},
    {"hpid", SEND_TXT, httpnulltext, -1},
    {"hpp", SEND_TXT, httpnulltext, -1},
    {"hps", SEND_TXT, httpnulltext, -1},
    {"hpub", SEND_TXT, httpnulltext, -1},
    {"hqx", SEND_TXT, httpnulltext, -1},
    {"hs", SEND_TXT, httpnulltext, -1},
    {"hsj2", SEND_TXT, httpnulltext, -1},
    {"hsl", SEND_TXT, httpnulltext, -1},
    {"hta", SEND_TXT, httpnulltext, -1},
    {"htc", SEND_TXT, httpnulltext, -1},
    {"htke", SEND_TXT, httpnulltext, -1},
    {"htm", SEND_TXT, httpnulltext, -1},
    {"html", SEND_TXT, httpnulltext, -1},
    {"hvd", SEND_TXT, httpnulltext, -1},
    {"hvp", SEND_TXT, httpnulltext, -1},
    {"hvs", SEND_TXT, httpnulltext, -1},
    {"hwp", SEND_TXT, httpnulltext, -1},
    {"hxx", SEND_TXT, httpnulltext, -1},
    {"i2g", SEND_TXT, httpnulltext, -1},
    {"ic0", SEND_TXT, httpnulltext, -1},
    {"ic1", SEND_TXT, httpnulltext, -1},
    {"ic2", SEND_TXT, httpnulltext, -1},
    {"ic3", SEND_TXT, httpnulltext, -1},
    {"ic4", SEND_TXT, httpnulltext, -1},
    {"ic5", SEND_TXT, httpnulltext, -1},
    {"ic6", SEND_TXT, httpnulltext, -1},
    {"ic7", SEND_TXT, httpnulltext, -1},
    {"ic8", SEND_TXT, httpnulltext, -1},
    {"ica", SEND_TXT, httpnulltext, -1},
    {"icc", SEND_TXT, httpnulltext, -1},
    {"icd", SEND_TXT, httpnulltext, -1},
    {"icf", SEND_TXT, httpnulltext, -1},
    {"icm", SEND_TXT, httpnulltext, -1},
    {"ics", SEND_TXT, httpnulltext, -1},
    {"ief", SEND_TXT, httpnulltext, -1},
    {"ifb", SEND_TXT, httpnulltext, -1},
    {"ifc", SEND_TXT, httpnulltext, -1},
    {"ifm", SEND_TXT, httpnulltext, -1},
    {"iges", SEND_TXT, httpnulltext, -1},
    {"igl", SEND_TXT, httpnulltext, -1},
    {"igm", SEND_TXT, httpnulltext, -1},
    {"ign", SEND_TXT, httpnulltext, -1},
    {"ignition", SEND_TXT, httpnulltext, -1},
    {"igs", SEND_TXT, httpnulltext, -1},
    {"igx", SEND_TXT, httpnulltext, -1},
    {"iif", SEND_TXT, httpnulltext, -1},
    {"iii", SEND_TXT, httpnulltext, -1},
    {"imf", SEND_TXT, httpnulltext, -1},
    {"imgcal", SEND_TXT, httpnulltext, -1},
    {"imi", SEND_TXT, httpnulltext, -1},
    {"imp", SEND_TXT, httpnulltext, -1},
    {"ims", SEND_TXT, httpnulltext, -1},
    {"imscc", SEND_TXT, httpnulltext, -1},
    {"info", SEND_TXT, httpnulltext, -1},
    {"ink", SEND_TXT, httpnulltext, -1},
    {"inkml", SEND_TXT, httpnulltext, -1},
    {"inp", SEND_TXT, httpnulltext, -1},
    {"ins", SEND_TXT, httpnulltext, -1},
    {"iota", SEND_TXT, httpnulltext, -1},
    {"ipfix", SEND_TXT, httpnulltext, -1},
    {"ipk", SEND_TXT, httpnulltext, -1},
    {"ipns-record", SEND_TXT, httpnulltext, -1},
    {"irm", SEND_TXT, httpnulltext, -1},
    {"irp", SEND_TXT, httpnulltext, -1},
    {"ism", SEND_TXT, httpnulltext, -1},
    {"iso", SEND_TXT, httpnulltext, -1},
    {"isp", SEND_TXT, httpnulltext, -1},
    {"ist", SEND_TXT, httpnulltext, -1},
    {"istc", SEND_TXT, httpnulltext, -1},
    {"istr", SEND_TXT, httpnulltext, -1},
    {"isws", SEND_TXT, httpnulltext, -1},
    {"itp", SEND_TXT, httpnulltext, -1},
    {"its", SEND_TXT, httpnulltext, -1},
    {"ivp", SEND_TXT, httpnulltext, -1},
    {"ivu", SEND_TXT, httpnulltext, -1},
    {"j2c", SEND_TXT, httpnulltext, -1},
    {"j2k", SEND_TXT, httpnulltext, -1},
    {"jad", SEND_TXT, httpnulltext, -1},
    {"jam", SEND_TXT, httpnulltext, -1},
    {"jar", SEND_TXT, httpnulltext, -1},
    {"java", SEND_TXT, httpnulltext, -1},
    {"jdx", SEND_TXT, httpnulltext, -1},
    {"jfif", SEND_TXT, httpnulltext, -1},
    {"jhc", SEND_TXT, httpnulltext, -1},
    {"jisp", SEND_TXT, httpnulltext, -1},
    {"jls", SEND_TXT, httpnulltext, -1},
    {"jlt", SEND_TXT, httpnulltext, -1},
    {"jmz", SEND_TXT, httpnulltext, -1},
    {"jng", SEND_TXT, httpnulltext, -1},
    {"jnlp", SEND_TXT, httpnulltext, -1},
    {"joda", SEND_TXT, httpnulltext, -1},
    {"jpf", SEND_TXT, httpnulltext, -1},
    {"jpg2", SEND_TXT, httpnulltext, -1},
    {"jpgm", SEND_TXT, httpnulltext, -1},
    {"jph", SEND_TXT, httpnulltext, -1},
    {"jphc", SEND_TXT, httpnulltext, -1},
    {"jpm", SEND_TXT, httpnulltext, -1},
    {"jpx", SEND_TXT, httpnulltext, -1},
    {"jrd", SEND_TXT, httpnulltext, -1},
    {"json", SEND_TXT, httpnulltext, -1},
    {"json-patch", SEND_TXT, httpnulltext, -1},
    {"jsonld", SEND_TXT, httpnulltext, -1},
    {"jsontd", SEND_TXT, httpnulltext, -1},
    {"jsontm", SEND_TXT, httpnulltext, -1},
    {"jt", SEND_TXT, httpnulltext, -1},
    {"jtd", SEND_TXT, httpnulltext, -1},
    {"jxl", SEND_TXT, httpnulltext, -1},
    {"jxr", SEND_TXT, httpnulltext, -1},
    {"jxra", SEND_TXT, httpnulltext, -1},
    {"jxrs", SEND_TXT, httpnulltext, -1},
    {"jxs", SEND_TXT, httpnulltext, -1},
    {"jxsc", SEND_TXT, httpnulltext, -1},
    {"jxsi", SEND_TXT, httpnulltext, -1},
    {"jxss", SEND_TXT, httpnulltext, -1},
    {"karbon", SEND_TXT, httpnulltext, -1},
    {"kcm", SEND_TXT, httpnulltext, -1},
    {"key", SEND_TXT, httpnulltext, -1},
    {"keynote", SEND_TXT, httpnulltext, -1},
    {"kfo", SEND_TXT, httpnulltext, -1},
    {"kia", SEND_TXT, httpnulltext, -1},
    {"kil", SEND_TXT, httpnulltext, -1},
    {"kin", SEND_TXT, httpnulltext, -1},
    {"kml", SEND_TXT, httpnulltext, -1},
    {"kmz", SEND_TXT, httpnulltext, -1},
    {"kne", SEND_TXT, httpnulltext, -1},
    {"knp", SEND_TXT, httpnulltext, -1},
    {"kom", SEND_TXT, httpnulltext, -1},
    {"kon", SEND_TXT, httpnulltext, -1},
    {"koz", SEND_TXT, httpnulltext, -1},
    {"kpr", SEND_TXT, httpnulltext, -1},
    {"kpt", SEND_TXT, httpnulltext, -1},
    {"ksp", SEND_TXT, httpnulltext, -1},
    {"ktr", SEND_TXT, httpnulltext, -1},
    {"ktx", SEND_TXT, httpnulltext, -1},
    {"ktx2", SEND_TXT, httpnulltext, -1},
    {"ktz", SEND_TXT, httpnulltext, -1},
    {"kwd", SEND_TXT, httpnulltext, -1},
    {"kwt", SEND_TXT, httpnulltext, -1},
    {"l16", SEND_TXT, httpnulltext, -1},
    {"las", SEND_TXT, httpnulltext, -1},
    {"lasjson", SEND_TXT, httpnulltext, -1},
    {"lasxml", SEND_TXT, httpnulltext, -1},
    {"latex", SEND_TXT, httpnulltext, -1},
    {"lbc", SEND_TXT, httpnulltext, -1},
    {"lbd", SEND_TXT, httpnulltext, -1},
    {"lbe", SEND_TXT, httpnulltext, -1},
    {"lca", SEND_TXT, httpnulltext, -1},
    {"lcs", SEND_TXT, httpnulltext, -1},
    {"le", SEND_TXT, httpnulltext, -1},
    {"les", SEND_TXT, httpnulltext, -1},
    {"lgr", SEND_TXT, httpnulltext, -1},
    {"lha", SEND_TXT, httpnulltext, -1},
    {"lhs", SEND_TXT, httpnulltext, -1},
    {"lhzd", SEND_TXT, httpnulltext, -1},
    {"lhzl", SEND_TXT, httpnulltext, -1},
    {"lin", SEND_TXT, httpnulltext, -1},
    {"line", SEND_TXT, httpnulltext, -1},
    {"link66", SEND_TXT, httpnulltext, -1},
    {"list3820", SEND_TXT, httpnulltext, -1},
    {"listafp", SEND_TXT, httpnulltext, -1},
    {"lmp", SEND_TXT, httpnulltext, -1},
    {"loas", SEND_TXT, httpnulltext, -1},
    {"loom", SEND_TXT, httpnulltext, -1},
    {"lostsyncxml", SEND_TXT, httpnulltext, -1},
    {"lostxml", SEND_TXT, httpnulltext, -1},
    {"lpf", SEND_TXT, httpnulltext, -1},
    {"lrm", SEND_TXT, httpnulltext, -1},
    {"lsf", SEND_TXT, httpnulltext, -1},
    {"lsx", SEND_TXT, httpnulltext, -1},
    {"ltx", SEND_TXT, httpnulltext, -1},
    {"lvp", SEND_TXT, httpnulltext, -1},
    {"lwp", SEND_TXT, httpnulltext, -1},
    {"lxf", SEND_TXT, httpnulltext, -1},
    {"ly", SEND_TXT, httpnulltext, -1},
    {"lyx", SEND_TXT, httpnulltext, -1},
    {"lzh", SEND_TXT, httpnulltext, -1},
    {"lzx", SEND_TXT, httpnulltext, -1},
    {"m", SEND_TXT, httpnulltext, -1},
    {"m1v", SEND_TXT, httpnulltext, -1},
    {"m21", SEND_TXT, httpnulltext, -1},
    {"m2v", SEND_TXT, httpnulltext, -1},
    {"m3g", SEND_TXT, httpnulltext, -1},
    {"m3u", SEND_TXT, httpnulltext, -1},
    {"m3u8", SEND_TXT, httpnulltext, -1},
    {"m4a", SEND_TXT, httpnulltext, -1},
    {"m4s", SEND_TXT, httpnulltext, -1},
    {"m4u", SEND_TXT, httpnulltext, -1},
    {"m4v", SEND_TXT, httpnulltext, -1},
    {"ma", SEND_TXT, httpnulltext, -1},
    {"mads", SEND_TXT, httpnulltext, -1},
    {"maei", SEND_TXT, httpnulltext, -1},
    {"mag", SEND_TXT, httpnulltext, -1},
    {"mail", SEND_TXT, httpnulltext, -1},
    {"maker", SEND_TXT, httpnulltext, -1},
    {"man", SEND_TXT, httpnulltext, -1},
    {"manifest", SEND_TXT, httpnulltext, -1},
    {"markdown", SEND_TXT, httpnulltext, -1},
    {"mb", SEND_TXT, httpnulltext, -1},
    {"mbk", SEND_TXT, httpnulltext, -1},
    {"mbox", SEND_TXT, httpnulltext, -1},
    {"mbsdf", SEND_TXT, httpnulltext, -1},
    {"mc1", SEND_TXT, httpnulltext, -1},
    {"mc2", SEND_TXT, httpnulltext, -1},
    {"mcd", SEND_TXT, httpnulltext, -1},
    {"mcif", SEND_TXT, httpnulltext, -1},
    {"mcm", SEND_TXT, httpnulltext, -1},
    {"md", SEND_TXT, httpnulltext, -1},
    {"mdb", SEND_TXT, httpnulltext, -1},
    {"mdc", SEND_TXT, httpnulltext, -1},
    {"mdi", SEND_TXT, httpnulltext, -1},
    {"mdl", SEND_TXT, httpnulltext, -1},
    {"me", SEND_TXT, httpnulltext, -1},
    {"mesh", SEND_TXT, httpnulltext, -1},
    {"meta4", SEND_TXT, httpnulltext, -1},
    {"mets", SEND_TXT, httpnulltext, -1},
    {"mf4", SEND_TXT, httpnulltext, -1},
    {"mfm", SEND_TXT, httpnulltext, -1},
    {"mft", SEND_TXT, httpnulltext, -1},
    {"mgp", SEND_TXT, httpnulltext, -1},
    {"mgz", SEND_TXT, httpnulltext, -1},
    {"mhas", SEND_TXT, httpnulltext, -1},
    {"mid", SEND_TXT, httpnulltext, -1},
    {"mif", SEND_TXT, httpnulltext, -1},
    {"miz", SEND_TXT, httpnulltext, -1},
    {"mj2", SEND_TXT, httpnulltext, -1},
    {"mjp2", SEND_TXT, httpnulltext, -1},
    {"mjs", SEND_TXT, httpnulltext, -1},
    {"mkv", SEND_TXT, httpnulltext, -1},
    {"ml2", SEND_TXT, httpnulltext, -1},
    {"mlp", SEND_TXT, httpnulltext, -1},
    {"mm", SEND_TXT, httpnulltext, -1},
    {"mmd", SEND_TXT, httpnulltext, -1},
    {"mmdb", SEND_TXT, httpnulltext, -1},
    {"mmf", SEND_TXT, httpnulltext, -1},
    {"mml", SEND_TXT, httpnulltext, -1},
    {"mmod", SEND_TXT, httpnulltext, -1},
    {"mmr", SEND_TXT, httpnulltext, -1},
    {"mng", SEND_TXT, httpnulltext, -1},
    {"moc", SEND_TXT, httpnulltext, -1},
    {"mod", SEND_TXT, httpnulltext, -1},
    {"model-inter", SEND_TXT, httpnulltext, -1},
    {"modl", SEND_TXT, httpnulltext, -1},
    {"mods", SEND_TXT, httpnulltext, -1},
    {"mol", SEND_TXT, httpnulltext, -1},
    {"mol2", SEND_TXT, httpnulltext, -1},
    {"moml", SEND_TXT, httpnulltext, -1},
    {"moo", SEND_TXT, httpnulltext, -1},
    {"mop", SEND_TXT, httpnulltext, -1},
    {"mopcrt", SEND_TXT, httpnulltext, -1},
    {"mov", SEND_TXT, httpnulltext, -1},
    {"movie", SEND_TXT, httpnulltext, -1},
    {"mp1", SEND_TXT, httpnulltext, -1},
    {"mp2", SEND_TXT, httpnulltext, -1},
    {"mp21", SEND_TXT, httpnulltext, -1},
    {"mp3", SEND_TXT, httpnulltext, -1},
    {"mp4", SEND_TXT, httpnulltext, -1},
    {"mpc", SEND_TXT, httpnulltext, -1},
    {"mpd", SEND_TXT, httpnulltext, -1},
    {"mpdd", SEND_TXT, httpnulltext, -1},
    {"mpe", SEND_TXT, httpnulltext, -1},
    {"mpeg", SEND_TXT, httpnulltext, -1},
    {"mpega", SEND_TXT, httpnulltext, -1},
    {"mpf", SEND_TXT, httpnulltext, -1},
    {"mpg", SEND_TXT, httpnulltext, -1},
    {"mpg4", SEND_TXT, httpnulltext, -1},
    {"mpga", SEND_TXT, httpnulltext, -1},
    {"mph", SEND_TXT, httpnulltext, -1},
    {"mpkg", SEND_TXT, httpnulltext, -1},
    {"mpm", SEND_TXT, httpnulltext, -1},
    {"mpn", SEND_TXT, httpnulltext, -1},
    {"mpp", SEND_TXT, httpnulltext, -1},
    {"mpt", SEND_TXT, httpnulltext, -1},
    {"mpv", SEND_TXT, httpnulltext, -1},
    {"mpw", SEND_TXT, httpnulltext, -1},
    {"mpy", SEND_TXT, httpnulltext, -1},
    {"mqy", SEND_TXT, httpnulltext, -1},
    {"mrc", SEND_TXT, httpnulltext, -1},
    {"mrcx", SEND_TXT, httpnulltext, -1},
    {"ms", SEND_TXT, httpnulltext, -1},
    {"msa", SEND_TXT, httpnulltext, -1},
    {"msd", SEND_TXT, httpnulltext, -1},
    {"mseed", SEND_TXT, httpnulltext, -1},
    {"mseq", SEND_TXT, httpnulltext, -1},
    {"msf", SEND_TXT, httpnulltext, -1},
    {"msh", SEND_TXT, httpnulltext, -1},
    {"msi", SEND_TXT, httpnulltext, -1},
    {"msl", SEND_TXT, httpnulltext, -1},
    {"msm", SEND_TXT, httpnulltext, -1},
    {"msp", SEND_TXT, httpnulltext, -1},
    {"msty", SEND_TXT, httpnulltext, -1},
    {"msu", SEND_TXT, httpnulltext, -1},
    {"mtl", SEND_TXT, httpnulltext, -1},
    {"mts", SEND_TXT, httpnulltext, -1},
    {"multitrack", SEND_TXT, httpnulltext, -1},
    {"mus", SEND_TXT, httpnulltext, -1},
    {"musd", SEND_TXT, httpnulltext, -1},
    {"mvb", SEND_TXT, httpnulltext, -1},
    {"mvt", SEND_TXT, httpnulltext, -1},
    {"mwc", SEND_TXT, httpnulltext, -1},
    {"mwf", SEND_TXT, httpnulltext, -1},
    {"mxf", SEND_TXT, httpnulltext, -1},
    {"mxi", SEND_TXT, httpnulltext, -1},
    {"mxl", SEND_TXT, httpnulltext, -1},
    {"mxmf", SEND_TXT, httpnulltext, -1},
    {"mxml", SEND_TXT, httpnulltext, -1},
    {"mxs", SEND_TXT, httpnulltext, -1},
    {"mxu", SEND_TXT, httpnulltext, -1},
    {"n3", SEND_TXT, httpnulltext, -1},
    {"nb", SEND_TXT, httpnulltext, -1},
    {"nbp", SEND_TXT, httpnulltext, -1},
    {"nc", SEND_TXT, httpnulltext, -1},
    {"ndc", SEND_TXT, httpnulltext, -1},
    {"ndl", SEND_TXT, httpnulltext, -1},
    {"nds", SEND_TXT, httpnulltext, -1},
    {"nebul", SEND_TXT, httpnulltext, -1},
    {"nef", SEND_TXT, httpnulltext, -1},
    {"ngdat", SEND_TXT, httpnulltext, -1},
    {"nim", SEND_TXT, httpnulltext, -1},
    {"nimn", SEND_TXT, httpnulltext, -1},
    {"nitf", SEND_TXT, httpnulltext, -1},
    {"nlu", SEND_TXT, httpnulltext, -1},
    {"nml", SEND_TXT, httpnulltext, -1},
    {"nnd", SEND_TXT, httpnulltext, -1},
    {"nns", SEND_TXT, httpnulltext, -1},
    {"nnw", SEND_TXT, httpnulltext, -1},
    {"notebook", SEND_TXT, httpnulltext, -1},
    {"nq", SEND_TXT, httpnulltext, -1},
    {"ns2", SEND_TXT, httpnulltext, -1},
    {"ns3", SEND_TXT, httpnulltext, -1},
    {"ns4", SEND_TXT, httpnulltext, -1},
    {"nsf", SEND_TXT, httpnulltext, -1},
    {"nsg", SEND_TXT, httpnulltext, -1},
    {"nsh", SEND_TXT, httpnulltext, -1},
    {"nt", SEND_TXT, httpnulltext, -1},
    {"ntf", SEND_TXT, httpnulltext, -1},
    {"numbers", SEND_TXT, httpnulltext, -1},
    {"nwc", SEND_TXT, httpnulltext, -1},
    {"o", SEND_TXT, httpnulltext, -1},
    {"oa2", SEND_TXT, httpnulltext, -1},
    {"oa3", SEND_TXT, httpnulltext, -1},
    {"oas", SEND_TXT, httpnulltext, -1},
    {"ob", SEND_TXT, httpnulltext, -1},
    {"obg", SEND_TXT, httpnulltext, -1},
    {"obgx", SEND_TXT, httpnulltext, -1},
    {"obj", SEND_TXT, httpnulltext, -1},
    {"oda", SEND_TXT, httpnulltext, -1},
    {"odb", SEND_TXT, httpnulltext, -1},
    {"odc", SEND_TXT, httpnulltext, -1},
    {"odd", SEND_TXT, httpnulltext, -1},
    {"odf", SEND_TXT, httpnulltext, -1},
    {"odg", SEND_TXT, httpnulltext, -1},
    {"odi", SEND_TXT, httpnulltext, -1},
    {"odm", SEND_TXT, httpnulltext, -1},
    {"odp", SEND_TXT, httpnulltext, -1},
    {"ods", SEND_TXT, httpnulltext, -1},
    {"odt", SEND_TXT, httpnulltext, -1},
    {"odx", SEND_TXT, httpnulltext, -1},
    {"oeb", SEND_TXT, httpnulltext, -1},
    {"oga", SEND_TXT, httpnulltext, -1},
    {"ogex", SEND_TXT, httpnulltext, -1},
    {"ogg", SEND_TXT, httpnulltext, -1},
    {"ogv", SEND_TXT, httpnulltext, -1},
    {"ogx", SEND_TXT, httpnulltext, -1},
    {"old", SEND_TXT, httpnulltext, -1},
    {"omg", SEND_TXT, httpnulltext, -1},
    {"one", SEND_TXT, httpnulltext, -1},
    {"onepkg", SEND_TXT, httpnulltext, -1},
    {"onetmp", SEND_TXT, httpnulltext, -1},
    {"onetoc2", SEND_TXT, httpnulltext, -1},
    {"opf", SEND_TXT, httpnulltext, -1},
    {"oprc", SEND_TXT, httpnulltext, -1},
    {"opus", SEND_TXT, httpnulltext, -1},
    {"or2", SEND_TXT, httpnulltext, -1},
    {"or3", SEND_TXT, httpnulltext, -1},
    {"orc", SEND_TXT, httpnulltext, -1},
    {"orf", SEND_TXT, httpnulltext, -1},
    {"org", SEND_TXT, httpnulltext, -1},
    {"orq", SEND_TXT, httpnulltext, -1},
    {"ors", SEND_TXT, httpnulltext, -1},
    {"osf", SEND_TXT, httpnulltext, -1},
    {"osm", SEND_TXT, httpnulltext, -1},
    {"ota", SEND_TXT, httpnulltext, -1},
    {"otc", SEND_TXT, httpnulltext, -1},
    {"otf", SEND_TXT, httpnulltext, -1},
    {"otg", SEND_TXT, httpnulltext, -1},
    {"oth", SEND_TXT, httpnulltext, -1},
    {"oti", SEND_TXT, httpnulltext, -1},
    {"otm", SEND_TXT, httpnulltext, -1},
    {"otp", SEND_TXT, httpnulltext, -1},
    {"ots", SEND_TXT, httpnulltext, -1},
    {"ott", SEND_TXT, httpnulltext, -1},
    {"ovl", SEND_TXT, httpnulltext, -1},
    {"oxlicg", SEND_TXT, httpnulltext, -1},
    {"oxps", SEND_TXT, httpnulltext, -1},
    {"oxt", SEND_TXT, httpnulltext, -1},
    {"oza", SEND_TXT, httpnulltext, -1},
    {"p", SEND_TXT, httpnulltext, -1},
    {"p10", SEND_TXT, httpnulltext, -1},
    {"p12", SEND_TXT, httpnulltext, -1},
    {"p21", SEND_TXT, httpnulltext, -1},
    {"p2p", SEND_TXT, httpnulltext, -1},
    {"p7c", SEND_TXT, httpnulltext, -1},
    {"p7m", SEND_TXT, httpnulltext, -1},
    {"p7r", SEND_TXT, httpnulltext, -1},
    {"p7s", SEND_TXT, httpnulltext, -1},
    {"p7z", SEND_TXT, httpnulltext, -1},
    {"p8", SEND_TXT, httpnulltext, -1},
    {"p8e", SEND_TXT, httpnulltext, -1},
    {"pac", SEND_TXT, httpnulltext, -1},
    {"package", SEND_TXT, httpnulltext, -1},
    {"pages", SEND_TXT, httpnulltext, -1},
    {"pas", SEND_TXT, httpnulltext, -1},
    {"pat", SEND_TXT, httpnulltext, -1},
    {"patch", SEND_TXT, httpnulltext, -1},
    {"paw", SEND_TXT, httpnulltext, -1},
    {"pbd", SEND_TXT, httpnulltext, -1},
    {"pbm", SEND_TXT, httpnulltext, -1},
    {"pcap", SEND_TXT, httpnulltext, -1},
    {"pcf", SEND_TXT, httpnulltext, -1},
    {"pcf.Z", SEND_TXT, httpnulltext, -1},
    {"pcl", SEND_TXT, httpnulltext, -1},
    {"pcx", SEND_TXT, httpnulltext, -1},
    {"pdb", SEND_TXT, httpnulltext, -1},
    {"pdf", SEND_TXT, httpnulltext, -1},
    {"pdx", SEND_TXT, httpnulltext, -1},
    {"pem", SEND_TXT, httpnulltext, -1},
    {"pfa", SEND_TXT, httpnulltext, -1},
    {"pfb", SEND_TXT, httpnulltext, -1},
    {"pfr", SEND_TXT, httpnulltext, -1},
    {"pfx", SEND_TXT, httpnulltext, -1},
    {"pgb", SEND_TXT, httpnulltext, -1},
    {"pgm", SEND_TXT, httpnulltext, -1},
    {"pgn", SEND_TXT, httpnulltext, -1},
    {"pgp", SEND_TXT, httpnulltext, -1},
    {"pil", SEND_TXT, httpnulltext, -1},
    {"pk", SEND_TXT, httpnulltext, -1},
    {"pkd", SEND_TXT, httpnulltext, -1},
    {"pkg", SEND_TXT, httpnulltext, -1},
    {"pki", SEND_TXT, httpnulltext, -1},
    {"pkipath", SEND_TXT, httpnulltext, -1},
    {"pl", SEND_TXT, httpnulltext, -1},
    {"plb", SEND_TXT, httpnulltext, -1},
    {"plc", SEND_TXT, httpnulltext, -1},
    {"plf", SEND_TXT, httpnulltext, -1},
    {"plj", SEND_TXT, httpnulltext, -1},
    {"plp", SEND_TXT, httpnulltext, -1},
    {"pls", SEND_TXT, httpnulltext, -1},
    {"pm", SEND_TXT, httpnulltext, -1},
    {"pml", SEND_TXT, httpnulltext, -1},
    {"pnm", SEND_TXT, httpnulltext, -1},
    {"portpkg", SEND_TXT, httpnulltext, -1},
    {"pot", SEND_TXT, httpnulltext, -1},
    {"potm", SEND_TXT, httpnulltext, -1},
    {"potx", SEND_TXT, httpnulltext, -1},
    {"ppam", SEND_TXT, httpnulltext, -1},
    {"ppd", SEND_TXT, httpnulltext, -1},
    {"ppkg", SEND_TXT, httpnulltext, -1},
    {"ppm", SEND_TXT, httpnulltext, -1},
    {"pps", SEND_TXT, httpnulltext, -1},
    {"ppsm", SEND_TXT, httpnulltext, -1},
    {"ppsx", SEND_TXT, httpnulltext, -1},
    {"ppt", SEND_TXT, httpnulltext, -1},
    {"pptm", SEND_TXT, httpnulltext, -1},
    {"ppttc", SEND_TXT, httpnulltext, -1},
    {"pptx", SEND_TXT, httpnulltext, -1},
    {"pqa", SEND_TXT, httpnulltext, -1},
    {"prc", SEND_TXT, httpnulltext, -1},
    {"pre", SEND_TXT, httpnulltext, -1},
    {"preminet", SEND_TXT, httpnulltext, -1},
    {"prf", SEND_TXT, httpnulltext, -1},
    {"provn", SEND_TXT, httpnulltext, -1},
    {"provx", SEND_TXT, httpnulltext, -1},
    {"prt", SEND_TXT, httpnulltext, -1},
    {"prz", SEND_TXT, httpnulltext, -1},
    {"ps", SEND_TXT, httpnulltext, -1},
    {"psb", SEND_TXT, httpnulltext, -1},
    {"psd", SEND_TXT, httpnulltext, -1},
    {"pseg3820", SEND_TXT, httpnulltext, -1},
    {"psfs", SEND_TXT, httpnulltext, -1},
    {"psg", SEND_TXT, httpnulltext, -1},
    {"psid", SEND_TXT, httpnulltext, -1},
    {"pskcxml", SEND_TXT, httpnulltext, -1},
    {"pt", SEND_TXT, httpnulltext, -1},
    {"pti", SEND_TXT, httpnulltext, -1},
    {"ptid", SEND_TXT, httpnulltext, -1},
    {"ptrom", SEND_TXT, httpnulltext, -1},
    {"pub", SEND_TXT, httpnulltext, -1},
    {"pvb", SEND_TXT, httpnulltext, -1},
    {"pwn", SEND_TXT, httpnulltext, -1},
    {"py", SEND_TXT, httpnulltext, -1},
    {"pya", SEND_TXT, httpnulltext, -1},
    {"pyc", SEND_TXT, httpnulltext, -1},
    {"pyo", SEND_TXT, httpnulltext, -1},
    {"pyox", SEND_TXT, httpnulltext, -1},
    {"pyv", SEND_TXT, httpnulltext, -1},
    {"qam", SEND_TXT, httpnulltext, -1},
    {"qbo", SEND_TXT, httpnulltext, -1},
    {"qca", SEND_TXT, httpnulltext, -1},
    {"qcall", SEND_TXT, httpnulltext, -1},
    {"qcp", SEND_TXT, httpnulltext, -1},
    {"qfx", SEND_TXT, httpnulltext, -1},
    {"qgs", SEND_TXT, httpnulltext, -1},
    {"qps", SEND_TXT, httpnulltext, -1},
    {"qt", SEND_TXT, httpnulltext, -1},
    {"qtl", SEND_TXT, httpnulltext, -1},
    {"quiz", SEND_TXT, httpnulltext, -1},
    {"quox", SEND_TXT, httpnulltext, -1},
    {"qvd", SEND_TXT, httpnulltext, -1},
    {"qwd", SEND_TXT, httpnulltext, -1},
    {"qwt", SEND_TXT, httpnulltext, -1},
    {"qxb", SEND_TXT, httpnulltext, -1},
    {"qxd", SEND_TXT, httpnulltext, -1},
    {"qxl", SEND_TXT, httpnulltext, -1},
    {"qxt", SEND_TXT, httpnulltext, -1},
    {"ra", SEND_TXT, httpnulltext, -1},
    {"ram", SEND_TXT, httpnulltext, -1},
    {"rapd", SEND_TXT, httpnulltext, -1},
    {"rar", SEND_TXT, httpnulltext, -1},
    {"ras", SEND_TXT, httpnulltext, -1},
    {"rb", SEND_TXT, httpnulltext, -1},
    {"rcprofile", SEND_TXT, httpnulltext, -1},
    {"rct", SEND_TXT, httpnulltext, -1},
    {"rd", SEND_TXT, httpnulltext, -1},
    {"rdf", SEND_TXT, httpnulltext, -1},
    {"rdf-crypt", SEND_TXT, httpnulltext, -1},
    {"rdp", SEND_TXT, httpnulltext, -1},
    {"rdz", SEND_TXT, httpnulltext, -1},
    {"relo", SEND_TXT, httpnulltext, -1},
    {"reload", SEND_TXT, httpnulltext, -1},
    {"rep", SEND_TXT, httpnulltext, -1},
    {"request", SEND_TXT, httpnulltext, -1},
    {"rfcxml", SEND_TXT, httpnulltext, -1},
    {"rgb", SEND_TXT, httpnulltext, -1},
    {"rgbe", SEND_TXT, httpnulltext, -1},
    {"rif", SEND_TXT, httpnulltext, -1},
    {"rip", SEND_TXT, httpnulltext, -1},
    {"rl", SEND_TXT, httpnulltext, -1},
    {"rlc", SEND_TXT, httpnulltext, -1},
    {"rld", SEND_TXT, httpnulltext, -1},
    {"rlm", SEND_TXT, httpnulltext, -1},
    {"rm", SEND_TXT, httpnulltext, -1},
    {"rms", SEND_TXT, httpnulltext, -1},
    {"rnc", SEND_TXT, httpnulltext, -1},
    {"rnd", SEND_TXT, httpnulltext, -1},
    {"roa", SEND_TXT, httpnulltext, -1},
    {"roff", SEND_TXT, httpnulltext, -1},
    {"ros", SEND_TXT, httpnulltext, -1},
    {"rp9", SEND_TXT, httpnulltext, -1},
    {"rpm", SEND_TXT, httpnulltext, -1},
    {"rpss", SEND_TXT, httpnulltext, -1},
    {"rpst", SEND_TXT, httpnulltext, -1},
    {"rq", SEND_TXT, httpnulltext, -1},
    {"rs", SEND_TXT, httpnulltext, -1},
    {"rsat", SEND_TXT, httpnulltext, -1},
    {"rsheet", SEND_TXT, httpnulltext, -1},
    {"rsm", SEND_TXT, httpnulltext, -1},
    {"rss", SEND_TXT, httpnulltext, -1},
    {"rst", SEND_TXT, httpnulltext, -1},
    {"rtf", SEND_TXT, httpnulltext, -1},
    {"rusd", SEND_TXT, httpnulltext, -1},
    {"rxn", SEND_TXT, httpnulltext, -1},
    {"rxt", SEND_TXT, httpnulltext, -1},
    {"s11", SEND_TXT, httpnulltext, -1},
    {"s14", SEND_TXT, httpnulltext, -1},
    {"s1a", SEND_TXT, httpnulltext, -1},
    {"s1e", SEND_TXT, httpnulltext, -1},
    {"s1g", SEND_TXT, httpnulltext, -1},
    {"s1h", SEND_TXT, httpnulltext, -1},
    {"s1j", SEND_TXT, httpnulltext, -1},
    {"s1m", SEND_TXT, httpnulltext, -1},
    {"s1n", SEND_TXT, httpnulltext, -1},
    {"s1p", SEND_TXT, httpnulltext, -1},
    {"s1q", SEND_TXT, httpnulltext, -1},
    {"s1w", SEND_TXT, httpnulltext, -1},
    {"s3df", SEND_TXT, httpnulltext, -1},
    {"sac", SEND_TXT, httpnulltext, -1},
    {"saf", SEND_TXT, httpnulltext, -1},
    {"sam", SEND_TXT, httpnulltext, -1},
    {"sarif", SEND_TXT, httpnulltext, -1},
    {"sarif-external-properties", SEND_TXT, httpnulltext, -1},
    {"sarif-external-properties.json", SEND_TXT, httpnulltext, -1},
    {"sarif.json", SEND_TXT, httpnulltext, -1},
    {"sc", SEND_TXT, httpnulltext, -1},
    {"scala", SEND_TXT, httpnulltext, -1},
    {"scd", SEND_TXT, httpnulltext, -1},
    {"sce", SEND_TXT, httpnulltext, -1},
    {"sci", SEND_TXT, httpnulltext, -1},
    {"scim", SEND_TXT, httpnulltext, -1},
    {"scl", SEND_TXT, httpnulltext, -1},
    {"scld", SEND_TXT, httpnulltext, -1},
    {"scm", SEND_TXT, httpnulltext, -1},
    {"sco", SEND_TXT, httpnulltext, -1},
    {"scq", SEND_TXT, httpnulltext, -1},
    {"scr", SEND_TXT, httpnulltext, -1},
    {"scs", SEND_TXT, httpnulltext, -1},
    {"scsf", SEND_TXT, httpnulltext, -1},
    {"sd", SEND_TXT, httpnulltext, -1},
    {"sd2", SEND_TXT, httpnulltext, -1},
    {"sda", SEND_TXT, httpnulltext, -1},
    {"sdc", SEND_TXT, httpnulltext, -1},
    {"sdd", SEND_TXT, httpnulltext, -1},
    {"sdf", SEND_TXT, httpnulltext, -1},
    {"sdkd", SEND_TXT, httpnulltext, -1},
    {"sdkm", SEND_TXT, httpnulltext, -1},
    {"sdo", SEND_TXT, httpnulltext, -1},
    {"sdoc", SEND_TXT, httpnulltext, -1},
    {"sdp", SEND_TXT, httpnulltext, -1},
    {"sds", SEND_TXT, httpnulltext, -1},
    {"sdw", SEND_TXT, httpnulltext, -1},
    {"see", SEND_TXT, httpnulltext, -1},
    {"seed", SEND_TXT, httpnulltext, -1},
    {"sem", SEND_TXT, httpnulltext, -1},
    {"sema", SEND_TXT, httpnulltext, -1},
    {"semd", SEND_TXT, httpnulltext, -1},
    {"semf", SEND_TXT, httpnulltext, -1},
    {"seml", SEND_TXT, httpnulltext, -1},
    {"senml", SEND_TXT, httpnulltext, -1},
    {"senml-etchc", SEND_TXT, httpnulltext, -1},
    {"senml-etchj", SEND_TXT, httpnulltext, -1},
    {"senmlc", SEND_TXT, httpnulltext, -1},
    {"senmle", SEND_TXT, httpnulltext, -1},
    {"senmlx", SEND_TXT, httpnulltext, -1},
    {"sensml", SEND_TXT, httpnulltext, -1},
    {"sensmlc", SEND_TXT, httpnulltext, -1},
    {"sensmle", SEND_TXT, httpnulltext, -1},
    {"sensmlx", SEND_TXT, httpnulltext, -1},
    {"ser", SEND_TXT, httpnulltext, -1},
    {"sfc", SEND_TXT, httpnulltext, -1},
    {"sfd", SEND_TXT, httpnulltext, -1},
    {"sfd-hdstx", SEND_TXT, httpnulltext, -1},
    {"sfs", SEND_TXT, httpnulltext, -1},
    {"sfv", SEND_TXT, httpnulltext, -1},
    {"sgf", SEND_TXT, httpnulltext, -1},
    {"sgi", SEND_TXT, httpnulltext, -1},
    {"sgif", SEND_TXT, httpnulltext, -1},
    {"sgl", SEND_TXT, httpnulltext, -1},
    {"sgm", SEND_TXT, httpnulltext, -1},
    {"sgml", SEND_TXT, httpnulltext, -1},
    {"sh", SEND_TXT, httpnulltext, -1},
    {"shaclc", SEND_TXT, httpnulltext, -1},
    {"shar", SEND_TXT, httpnulltext, -1},
    {"shc", SEND_TXT, httpnulltext, -1},
    {"shex", SEND_TXT, httpnulltext, -1},
    {"shf", SEND_TXT, httpnulltext, -1},
    {"shp", SEND_TXT, httpnulltext, -1},
    {"shtml", SEND_TXT, httpnulltext, -1},
    {"shx", SEND_TXT, httpnulltext, -1},
    {"si", SEND_TXT, httpnulltext, -1},
    {"sic", SEND_TXT, httpnulltext, -1},
    {"sid", SEND_TXT, httpnulltext, -1},
    {"sieve", SEND_TXT, httpnulltext, -1},
    {"sig", SEND_TXT, httpnulltext, -1},
    {"sik", SEND_TXT, httpnulltext, -1},
    {"silo", SEND_TXT, httpnulltext, -1},
    {"sipa", SEND_TXT, httpnulltext, -1},
    {"sis", SEND_TXT, httpnulltext, -1},
    {"sit", SEND_TXT, httpnulltext, -1},
    {"sitx", SEND_TXT, httpnulltext, -1},
    {"siv", SEND_TXT, httpnulltext, -1},
    {"sjp", SEND_TXT, httpnulltext, -1},
    {"sjpg", SEND_TXT, httpnulltext, -1},
    {"skd", SEND_TXT, httpnulltext, -1},
    {"skm", SEND_TXT, httpnulltext, -1},
    {"skp", SEND_TXT, httpnulltext, -1},
    {"skt", SEND_TXT, httpnulltext, -1},
    {"sl", SEND_TXT, httpnulltext, -1},
    {"sla", SEND_TXT, httpnulltext, -1},
    {"slaz", SEND_TXT, httpnulltext, -1},
    {"slc", SEND_TXT, httpnulltext, -1},
    {"sldm", SEND_TXT, httpnulltext, -1},
    {"sldx", SEND_TXT, httpnulltext, -1},
    {"sls", SEND_TXT, httpnulltext, -1},
    {"slt", SEND_TXT, httpnulltext, -1},
    {"sm", SEND_TXT, httpnulltext, -1},
    {"smc", SEND_TXT, httpnulltext, -1},
    {"smf", SEND_TXT, httpnulltext, -1},
    {"smh", SEND_TXT, httpnulltext, -1},
    {"smht", SEND_TXT, httpnulltext, -1},
    {"smi", SEND_TXT, httpnulltext, -1},
    {"smil", SEND_TXT, httpnulltext, -1},
    {"smk", SEND_TXT, httpnulltext, -1},
    {"sml", SEND_TXT, httpnulltext, -1},
    {"smo", SEND_TXT, httpnulltext, -1},
    {"smov", SEND_TXT, httpnulltext, -1},
    {"smp", SEND_TXT, httpnulltext, -1},
    {"smp3", SEND_TXT, httpnulltext, -1},
    {"smpg", SEND_TXT, httpnulltext, -1},
    {"sms", SEND_TXT, httpnulltext, -1},
    {"smv", SEND_TXT, httpnulltext, -1},
    {"smzip", SEND_TXT, httpnulltext, -1},
    {"snd", SEND_TXT, httpnulltext, -1},
    {"soa", SEND_TXT, httpnulltext, -1},
    {"soc", SEND_TXT, httpnulltext, -1},
    {"sofa", SEND_TXT, httpnulltext, -1},
    {"sos", SEND_TXT, httpnulltext, -1},
    {"spc", SEND_TXT, httpnulltext, -1},
    {"spd", SEND_TXT, httpnulltext, -1},
    {"spdf", SEND_TXT, httpnulltext, -1},
    {"spdx", SEND_TXT, httpnulltext, -1},
    {"spdx.json", SEND_TXT, httpnulltext, -1},
    {"spf", SEND_TXT, httpnulltext, -1},
    {"spl", SEND_TXT, httpnulltext, -1},
    {"spn", SEND_TXT, httpnulltext, -1},
    {"spng", SEND_TXT, httpnulltext, -1},
    {"spo", SEND_TXT, httpnulltext, -1},
    {"spot", SEND_TXT, httpnulltext, -1},
    {"spp", SEND_TXT, httpnulltext, -1},
    {"sppt", SEND_TXT, httpnulltext, -1},
    {"spq", SEND_TXT, httpnulltext, -1},
    {"spx", SEND_TXT, httpnulltext, -1},
    {"sql", SEND_TXT, httpnulltext, -1},
    {"sqlite", SEND_TXT, httpnulltext, -1},
    {"sqlite3", SEND_TXT, httpnulltext, -1},
    {"sr", SEND_TXT, httpnulltext, -1},
    {"src", SEND_TXT, httpnulltext, -1},
    {"srt", SEND_TXT, httpnulltext, -1},
    {"sru", SEND_TXT, httpnulltext, -1},
    {"srx", SEND_TXT, httpnulltext, -1},
    {"sse", SEND_TXT, httpnulltext, -1},
    {"ssf", SEND_TXT, httpnulltext, -1},
    {"ssml", SEND_TXT, httpnulltext, -1},
    {"ssv", SEND_TXT, httpnulltext, -1},
    {"ssvc", SEND_TXT, httpnulltext, -1},
    {"ssw", SEND_TXT, httpnulltext, -1},
    {"sswf", SEND_TXT, httpnulltext, -1},
    {"st", SEND_TXT, httpnulltext, -1},
    {"stc", SEND_TXT, httpnulltext, -1},
    {"std", SEND_TXT, httpnulltext, -1},
    {"step", SEND_TXT, httpnulltext, -1},
    {"stf", SEND_TXT, httpnulltext, -1},
    {"sti", SEND_TXT, httpnulltext, -1},
    {"stif", SEND_TXT, httpnulltext, -1},
    {"stix", SEND_TXT, httpnulltext, -1},
    {"stk", SEND_TXT, httpnulltext, -1},
    {"stl", SEND_TXT, httpnulltext, -1},
    {"stml", SEND_TXT, httpnulltext, -1},
    {"stp", SEND_TXT, httpnulltext, -1},
    {"stpnc", SEND_TXT, httpnulltext, -1},
    {"stpx", SEND_TXT, httpnulltext, -1},
    {"stpxz", SEND_TXT, httpnulltext, -1},
    {"stpz", SEND_TXT, httpnulltext, -1},
    {"str", SEND_TXT, httpnulltext, -1},
    {"study-inter", SEND_TXT, httpnulltext, -1},
    {"stw", SEND_TXT, httpnulltext, -1},
    {"sty", SEND_TXT, httpnulltext, -1},
    {"sus", SEND_TXT, httpnulltext, -1},
    {"susp", SEND_TXT, httpnulltext, -1},
    {"sv4cpio", SEND_TXT, httpnulltext, -1},
    {"sv4crc", SEND_TXT, httpnulltext, -1},
    {"svc", SEND_TXT, httpnulltext, -1},
    {"svg", SEND_TXT, httpnulltext, -1},
    {"svgz", SEND_TXT, httpnulltext, -1},
    {"sw", SEND_TXT, httpnulltext, -1},
    {"swi", SEND_TXT, httpnulltext, -1},
    {"swidtag", SEND_TXT, httpnulltext, -1},
    {"sxc", SEND_TXT, httpnulltext, -1},
    {"sxd", SEND_TXT, httpnulltext, -1},
    {"sxg", SEND_TXT, httpnulltext, -1},
    {"sxi", SEND_TXT, httpnulltext, -1},
    {"sxl", SEND_TXT, httpnulltext, -1},
    {"sxls", SEND_TXT, httpnulltext, -1},
    {"sxm", SEND_TXT, httpnulltext, -1},
    {"sxw", SEND_TXT, httpnulltext, -1},
    {"sy2", SEND_TXT, httpnulltext, -1},
    {"syft.json", SEND_TXT, httpnulltext, -1},
    {"t", SEND_TXT, httpnulltext, -1},
    {"tag", SEND_TXT, httpnulltext, -1},
    {"taglet", SEND_TXT, httpnulltext, -1},
    {"tam", SEND_TXT, httpnulltext, -1},
    {"tamp", SEND_TXT, httpnulltext, -1},
    {"tamx", SEND_TXT, httpnulltext, -1},
    {"tao", SEND_TXT, httpnulltext, -1},
    {"tap", SEND_TXT, httpnulltext, -1},
    {"tar", SEND_TXT, httpnulltext, -1},
    {"tat", SEND_TXT, httpnulltext, -1},
    {"tatp", SEND_TXT, httpnulltext, -1},
    {"tatx", SEND_TXT, httpnulltext, -1},
    {"tau", SEND_TXT, httpnulltext, -1},
    {"taz", SEND_TXT, httpnulltext, -1},
    {"tcap", SEND_TXT, httpnulltext, -1},
    {"tcl", SEND_TXT, httpnulltext, -1},
    {"tcu", SEND_TXT, httpnulltext, -1},
    {"td", SEND_TXT, httpnulltext, -1},
    {"teacher", SEND_TXT, httpnulltext, -1},
    {"tei", SEND_TXT, httpnulltext, -1},
    {"teiCorpus", SEND_TXT, httpnulltext, -1},
    {"ter", SEND_TXT, httpnulltext, -1},
    {"tex", SEND_TXT, httpnulltext, -1},
    {"texi", SEND_TXT, httpnulltext, -1},
    {"texinfo", SEND_TXT, httpnulltext, -1},
    {"text", SEND_TXT, httpnulltext, -1},
    {"tfi", SEND_TXT, httpnulltext, -1},
    {"tfx", SEND_TXT, httpnulltext, -1},
    {"tgf", SEND_TXT, httpnulltext, -1},
    {"tgz", SEND_TXT, httpnulltext, -1},
    {"thmx", SEND_TXT, httpnulltext, -1},
    {"tif", SEND_TXT, httpnulltext, -1},
    {"tiff", SEND_TXT, httpnulltext, -1},
    {"tk", SEND_TXT, httpnulltext, -1},
    {"tlclient", SEND_TXT, httpnulltext, -1},
    {"tm", SEND_TXT, httpnulltext, -1},
    {"tm.json", SEND_TXT, httpnulltext, -1},
    {"tm.jsonld", SEND_TXT, httpnulltext, -1},
    {"tmo", SEND_TXT, httpnulltext, -1},
    {"tnef", SEND_TXT, httpnulltext, -1},
    {"tnf", SEND_TXT, httpnulltext, -1},
    {"torrent", SEND_TXT, httpnulltext, -1},
    {"tpl", SEND_TXT, httpnulltext, -1},
    {"tpt", SEND_TXT, httpnulltext, -1},
    {"tr", SEND_TXT, httpnulltext, -1},
    {"tra", SEND_TXT, httpnulltext, -1},
    {"tree", SEND_TXT, httpnulltext, -1},
    {"trig", SEND_TXT, httpnulltext, -1},
    {"ts", SEND_TXT, httpnulltext, -1},
    {"tsa", SEND_TXT, httpnulltext, -1},
    {"tsd", SEND_TXT, httpnulltext, -1},
    {"tsp", SEND_TXT, httpnulltext, -1},
    {"tsq", SEND_TXT, httpnulltext, -1},
    {"tsr", SEND_TXT, httpnulltext, -1},
    {"tst", SEND_TXT, httpnulltext, -1},
    {"tsv", SEND_TXT, httpnulltext, -1},
    {"ttc", SEND_TXT, httpnulltext, -1},
    {"ttf", SEND_TXT, httpnulltext, -1},
    {"ttl", SEND_TXT, httpnulltext, -1},
    {"ttml", SEND_TXT, httpnulltext, -1},
    {"tuc", SEND_TXT, httpnulltext, -1},
    {"tur", SEND_TXT, httpnulltext, -1},
    {"twd", SEND_TXT, httpnulltext, -1},
    {"twds", SEND_TXT, httpnulltext, -1},
    {"txd", SEND_TXT, httpnulltext, -1},
    {"txf", SEND_TXT, httpnulltext, -1},
    {"txt", SEND_TXT, httpnulltext, -1},
    {"u3d", SEND_TXT, httpnulltext, -1},
    {"u8dsn", SEND_TXT, httpnulltext, -1},
    {"u8hdr", SEND_TXT, httpnulltext, -1},
    {"u8mdn", SEND_TXT, httpnulltext, -1},
    {"u8msg", SEND_TXT, httpnulltext, -1},
    {"udeb", SEND_TXT, httpnulltext, -1},
    {"ufd", SEND_TXT, httpnulltext, -1},
    {"ufdl", SEND_TXT, httpnulltext, -1},
    {"uis", SEND_TXT, httpnulltext, -1},
    {"umj", SEND_TXT, httpnulltext, -1},
    {"unityweb", SEND_TXT, httpnulltext, -1},
    {"uo", SEND_TXT, httpnulltext, -1},
    {"uoml", SEND_TXT, httpnulltext, -1},
    {"upa", SEND_TXT, httpnulltext, -1},
    {"uri", SEND_TXT, httpnulltext, -1},
    {"urim", SEND_TXT, httpnulltext, -1},
    {"urimap", SEND_TXT, httpnulltext, -1},
    {"uris", SEND_TXT, httpnulltext, -1},
    {"usda", SEND_TXT, httpnulltext, -1},
    {"usdz", SEND_TXT, httpnulltext, -1},
    {"ustar", SEND_TXT, httpnulltext, -1},
    {"utz", SEND_TXT, httpnulltext, -1},
    {"uva", SEND_TXT, httpnulltext, -1},
    {"uvd", SEND_TXT, httpnulltext, -1},
    {"uvf", SEND_TXT, httpnulltext, -1},
    {"uvg", SEND_TXT, httpnulltext, -1},
    {"uvh", SEND_TXT, httpnulltext, -1},
    {"uvi", SEND_TXT, httpnulltext, -1},
    {"uvm", SEND_TXT, httpnulltext, -1},
    {"uvp", SEND_TXT, httpnulltext, -1},
    {"uvs", SEND_TXT, httpnulltext, -1},
    {"uvt", SEND_TXT, httpnulltext, -1},
    {"uvu", SEND_TXT, httpnulltext, -1},
    {"uvv", SEND_TXT, httpnulltext, -1},
    {"uvva", SEND_TXT, httpnulltext, -1},
    {"uvvd", SEND_TXT, httpnulltext, -1},
    {"uvvf", SEND_TXT, httpnulltext, -1},
    {"uvvg", SEND_TXT, httpnulltext, -1},
    {"uvvh", SEND_TXT, httpnulltext, -1},
    {"uvvi", SEND_TXT, httpnulltext, -1},
    {"uvvm", SEND_TXT, httpnulltext, -1},
    {"uvvp", SEND_TXT, httpnulltext, -1},
    {"uvvs", SEND_TXT, httpnulltext, -1},
    {"uvvt", SEND_TXT, httpnulltext, -1},
    {"uvvu", SEND_TXT, httpnulltext, -1},
    {"uvvv", SEND_TXT, httpnulltext, -1},
    {"uvvx", SEND_TXT, httpnulltext, -1},
    {"uvvz", SEND_TXT, httpnulltext, -1},
    {"uvx", SEND_TXT, httpnulltext, -1},
    {"uvz", SEND_TXT, httpnulltext, -1},
    {"val", SEND_TXT, httpnulltext, -1},
    {"vbk", SEND_TXT, httpnulltext, -1},
    {"vbox", SEND_TXT, httpnulltext, -1},
    {"vcard", SEND_TXT, httpnulltext, -1},
    {"vcd", SEND_TXT, httpnulltext, -1},
    {"vcf", SEND_TXT, httpnulltext, -1},
    {"vcg", SEND_TXT, httpnulltext, -1},
    {"vcj", SEND_TXT, httpnulltext, -1},
    {"vcs", SEND_TXT, httpnulltext, -1},
    {"vcx", SEND_TXT, httpnulltext, -1},
    {"vds", SEND_TXT, httpnulltext, -1},
    {"vew", SEND_TXT, httpnulltext, -1},
    {"vfr", SEND_TXT, httpnulltext, -1},
    {"viaframe", SEND_TXT, httpnulltext, -1},
    {"vis", SEND_TXT, httpnulltext, -1},
    {"viv", SEND_TXT, httpnulltext, -1},
    {"vmd", SEND_TXT, httpnulltext, -1},
    {"vms", SEND_TXT, httpnulltext, -1},
    {"vmt", SEND_TXT, httpnulltext, -1},
    {"vpm", SEND_TXT, httpnulltext, -1},
    {"vrm", SEND_TXT, httpnulltext, -1},
    {"vrml", SEND_TXT, httpnulltext, -1},
    {"vsc", SEND_TXT, httpnulltext, -1},
    {"vsd", SEND_TXT, httpnulltext, -1},
    {"vsf", SEND_TXT, httpnulltext, -1},
    {"vss", SEND_TXT, httpnulltext, -1},
    {"vst", SEND_TXT, httpnulltext, -1},
    {"vsw", SEND_TXT, httpnulltext, -1},
    {"vtf", SEND_TXT, httpnulltext, -1},
    {"vtnstd", SEND_TXT, httpnulltext, -1},
    {"vtt", SEND_TXT, httpnulltext, -1},
    {"vtu", SEND_TXT, httpnulltext, -1},
    {"vwx", SEND_TXT, httpnulltext, -1},
    {"vxml", SEND_TXT, httpnulltext, -1},
    {"wad", SEND_TXT, httpnulltext, -1},
    {"wadl", SEND_TXT, httpnulltext, -1},
    {"wafl", SEND_TXT, httpnulltext, -1},
    {"wasm", SEND_TXT, httpnulltext, -1},
    {"wav", SEND_TXT, httpnulltext, -1},
    {"wax", SEND_TXT, httpnulltext, -1},
    {"wbmp", SEND_TXT, httpnulltext, -1},
    {"wbs", SEND_TXT, httpnulltext, -1},
    {"wbxml", SEND_TXT, httpnulltext, -1},
    {"wcm", SEND_TXT, httpnulltext, -1},
    {"wdb", SEND_TXT, httpnulltext, -1},
    {"webm", SEND_TXT, httpnulltext, -1},
    {"webmanifest", SEND_TXT, httpnulltext, -1},
    {"webp", SEND_TXT, httpnulltext, -1},
    {"wg", SEND_TXT, httpnulltext, -1},
    {"wgsl", SEND_TXT, httpnulltext, -1},
    {"wgt", SEND_TXT, httpnulltext, -1},
    {"wif", SEND_TXT, httpnulltext, -1},
    {"win", SEND_TXT, httpnulltext, -1},
    {"wk", SEND_TXT, httpnulltext, -1},
    {"wk1", SEND_TXT, httpnulltext, -1},
    {"wk3", SEND_TXT, httpnulltext, -1},
    {"wk4", SEND_TXT, httpnulltext, -1},
    {"wks", SEND_TXT, httpnulltext, -1},
    {"wlnk", SEND_TXT, httpnulltext, -1},
    {"wm", SEND_TXT, httpnulltext, -1},
    {"wma", SEND_TXT, httpnulltext, -1},
    {"wmc", SEND_TXT, httpnulltext, -1},
    {"wmd", SEND_TXT, httpnulltext, -1},
    {"wmf", SEND_TXT, httpnulltext, -1},
    {"wml", SEND_TXT, httpnulltext, -1},
    {"wmlc", SEND_TXT, httpnulltext, -1},
    {"wmls", SEND_TXT, httpnulltext, -1},
    {"wmlsc", SEND_TXT, httpnulltext, -1},
    {"wmv", SEND_TXT, httpnulltext, -1},
    {"wmx", SEND_TXT, httpnulltext, -1},
    {"wmz", SEND_TXT, httpnulltext, -1},
    {"woff", SEND_TXT, httpnulltext, -1},
    {"woff2", SEND_TXT, httpnulltext, -1},
    {"wpd", SEND_TXT, httpnulltext, -1},
    {"wpl", SEND_TXT, httpnulltext, -1},
    {"wps", SEND_TXT, httpnulltext, -1},
    {"wqd", SEND_TXT, httpnulltext, -1},
    {"wrl", SEND_TXT, httpnulltext, -1},
    {"wsc", SEND_TXT, httpnulltext, -1},
    {"wsdl", SEND_TXT, httpnulltext, -1},
    {"wspolicy", SEND_TXT, httpnulltext, -1},
    {"wtb", SEND_TXT, httpnulltext, -1},
    {"wv", SEND_TXT, httpnulltext, -1},
    {"wvx", SEND_TXT, httpnulltext, -1},
    {"wz", SEND_TXT, httpnulltext, -1},
    {"x3d", SEND_TXT, httpnulltext, -1},
    {"x3db", SEND_TXT, httpnulltext, -1},
    {"x3dv", SEND_TXT, httpnulltext, -1},
    {"x3dvz", SEND_TXT, httpnulltext, -1},
    {"x3dz", SEND_TXT, httpnulltext, -1},
    {"x_b", SEND_TXT, httpnulltext, -1},
    {"x_t", SEND_TXT, httpnulltext, -1},
    {"xar", SEND_TXT, httpnulltext, -1},
    {"xav", SEND_TXT, httpnulltext, -1},
    {"xbd", SEND_TXT, httpnulltext, -1},
    {"xbm", SEND_TXT, httpnulltext, -1},
    {"xca", SEND_TXT, httpnulltext, -1},
    {"xcf", SEND_TXT, httpnulltext, -1},
    {"xcos", SEND_TXT, httpnulltext, -1},
    {"xcs", SEND_TXT, httpnulltext, -1},
    {"xct", SEND_TXT, httpnulltext, -1},
    {"xdd", SEND_TXT, httpnulltext, -1},
    {"xdf", SEND_TXT, httpnulltext, -1},
    {"xdm", SEND_TXT, httpnulltext, -1},
    {"xdp", SEND_TXT, httpnulltext, -1},
    {"xdssc", SEND_TXT, httpnulltext, -1},
    {"xdw", SEND_TXT, httpnulltext, -1},
    {"xel", SEND_TXT, httpnulltext, -1},
    {"xer", SEND_TXT, httpnulltext, -1},
    {"xfd", SEND_TXT, httpnulltext, -1},
    {"xfdf", SEND_TXT, httpnulltext, -1},
    {"xfdl", SEND_TXT, httpnulltext, -1},
    {"xhe", SEND_TXT, httpnulltext, -1},
    {"xht", SEND_TXT, httpnulltext, -1},
    {"xhtm", SEND_TXT, httpnulltext, -1},
    {"xhtml", SEND_TXT, httpnulltext, -1},
    {"xhvml", SEND_TXT, httpnulltext, -1},
    {"xif", SEND_TXT, httpnulltext, -1},
    {"xla", SEND_TXT, httpnulltext, -1},
    {"xlam", SEND_TXT, httpnulltext, -1},
    {"xlc", SEND_TXT, httpnulltext, -1},
    {"xlf", SEND_TXT, httpnulltext, -1},
    {"xlim", SEND_TXT, httpnulltext, -1},
    {"xlm", SEND_TXT, httpnulltext, -1},
    {"xls", SEND_TXT, httpnulltext, -1},
    {"xlsb", SEND_TXT, httpnulltext, -1},
    {"xlsm", SEND_TXT, httpnulltext, -1},
    {"xlsx", SEND_TXT, httpnulltext, -1},
    {"xlt", SEND_TXT, httpnulltext, -1},
    {"xltm", SEND_TXT, httpnulltext, -1},
    {"xltx", SEND_TXT, httpnulltext, -1},
    {"xlw", SEND_TXT, httpnulltext, -1},
    {"xml", SEND_TXT, httpnulltext, -1},
    {"xmls", SEND_TXT, httpnulltext, -1},
    {"xmt_bin", SEND_TXT, httpnulltext, -1},
    {"xmt_txt", SEND_TXT, httpnulltext, -1},
    {"xns", SEND_TXT, httpnulltext, -1},
    {"xo", SEND_TXT, httpnulltext, -1},
    {"xodp", SEND_TXT, httpnulltext, -1},
    {"xods", SEND_TXT, httpnulltext, -1},
    {"xodt", SEND_TXT, httpnulltext, -1},
    {"xop", SEND_TXT, httpnulltext, -1},
    {"xotp", SEND_TXT, httpnulltext, -1},
    {"xots", SEND_TXT, httpnulltext, -1},
    {"xott", SEND_TXT, httpnulltext, -1},
    {"xpak", SEND_TXT, httpnulltext, -1},
    {"xpi", SEND_TXT, httpnulltext, -1},
    {"xpm", SEND_TXT, httpnulltext, -1},
    {"xpr", SEND_TXT, httpnulltext, -1},
    {"xps", SEND_TXT, httpnulltext, -1},
    {"xpw", SEND_TXT, httpnulltext, -1},
    {"xpx", SEND_TXT, httpnulltext, -1},
    {"xsf", SEND_TXT, httpnulltext, -1},
    {"xsl", SEND_TXT, httpnulltext, -1},
    {"xslt", SEND_TXT, httpnulltext, -1},
    {"xsm", SEND_TXT, httpnulltext, -1},
    {"xspf", SEND_TXT, httpnulltext, -1},
    {"xtel", SEND_TXT, httpnulltext, -1},
    {"xul", SEND_TXT, httpnulltext, -1},
    {"xvm", SEND_TXT, httpnulltext, -1},
    {"xvml", SEND_TXT, httpnulltext, -1},
    {"xwd", SEND_TXT, httpnulltext, -1},
    {"xyz", SEND_TXT, httpnulltext, -1},
    {"xyze", SEND_TXT, httpnulltext, -1},
    {"xz", SEND_TXT, httpnulltext, -1},
    {"yaml", SEND_TXT, httpnulltext, -1},
    {"yang", SEND_TXT, httpnulltext, -1},
    {"yin", SEND_TXT, httpnulltext, -1},
    {"yme", SEND_TXT, httpnulltext, -1},
    {"yml", SEND_TXT, httpnulltext, -1},
    {"yt", SEND_TXT, httpnulltext, -1},
    {"zaz", SEND_TXT, httpnulltext, -1},
    {"zfc", SEND_TXT, httpnulltext, -1},
    {"zfo", SEND_TXT, httpnulltext, -1},
    {"zip", SEND_TXT, httpnulltext, -1},
    {"zir", SEND_TXT, httpnulltext, -1},
    {"zirz", SEND_TXT, httpnulltext, -1},
    {"zmm", SEND_TXT, httpnulltext, -1},
    {"zmt", SEND_TXT, httpnulltext, -1},
    {"zone", SEND_TXT, httpnulltext, -1},
    {"zst", SEND_TXT, httpnulltext, -1},
    {"~", SEND_TXT, httpnulltext, -1},

    /* Fallback for unknown extensions */
    {NULL, SEND_TXT, httpnulltext, -1}
};

#define EXT_TABLE_SIZE (sizeof(ext_table) / sizeof(ext_entry_t) - 1)

/* Lookup extension in table and return both status and response data */
static const ext_entry_t *lookup_extension(const char *ext) {
    if (!ext || ext[0] == '\0') {
        return &ext_table[EXT_TABLE_SIZE];  /* Return default entry */
    }

    /* Case-insensitive extension lookup */
    for (size_t i = 0; i < EXT_TABLE_SIZE; i++) {
        if (!strcasecmp(ext, ext_table[i].ext)) {
            return &ext_table[i];
        }
    }

    /* Unknown extension - return default */
    return &ext_table[EXT_TABLE_SIZE];
}


void get_client_ip(int socket_fd, char *ip, int ip_len, char *port, int port_len)
{
  struct sockaddr_storage sin_addr;
  socklen_t sin_addr_len = sizeof(sin_addr);

  if (ip == NULL || ip_len <= 0 || (socket_fd < 0 && (ip[0] = '\0') == '\0'))
    return;

  if (getpeername(socket_fd, (struct sockaddr*)&sin_addr, &sin_addr_len) != 0 ||
      getnameinfo((struct sockaddr *)&sin_addr, sin_addr_len,
               ip, ip_len, port, port_len, NI_NUMERICHOST | NI_NUMERICSERV ) != 0) {
    ip[0] = '\0';
  }
}

void* conn_handler( void *ptr )
{
  if (!g) {
    return NULL;
  }
  
  struct {
    int argc;
    char **argv;
    int new_fd;
    int pipefd;
    const char *stats_url;
    const char *stats_text_url;
    const char *pem_dir;
    int do_204;
    int do_redirect;
    int select_timeout;
    int http_keepalive;
#ifdef DEBUG
    int warning_time;
#endif
  } config;
  
  config.argc = GLOBAL(g, argc);
  config.argv = GLOBAL(g, argv);
  config.new_fd = CONN_TLSTOR(ptr, new_fd);
  config.pipefd = GLOBAL(g, pipefd);
  config.stats_url = GLOBAL(g, stats_url);
  config.stats_text_url = GLOBAL(g, stats_text_url);
  config.pem_dir = GLOBAL(g, pem_dir);
  config.do_204 = GLOBAL(g, do_204);
  config.do_redirect = GLOBAL(g, do_redirect);
  config.select_timeout = GLOBAL(g, select_timeout);
  config.http_keepalive = GLOBAL(g, http_keepalive);
#ifdef DEBUG
  config.warning_time = GLOBAL(g, warning_time);
#endif

  response_struct pipedata = {0};
  struct timeval timeout = {config.select_timeout, 0};
  int rv = 0;
  char *buf = NULL, *bufptr = NULL;
  char *url = NULL;
  char* aspbuf = NULL;
  const char* response;
  int rsize;
  char* version_string = NULL;
  char* stat_string = NULL;
  int num_req = 0;
  char *req_url = NULL;
  unsigned int req_len = 0;
  #define HOST_LEN_MAX 80
  char host[HOST_LEN_MAX + 1];
  char *post_buf = NULL;
  size_t post_buf_len = 0;
  unsigned int total_bytes = 0;
  #define CORS_ORIGIN_LEN_MAX 256
  char *cors_origin = NULL;
  char client_ip[INET6_ADDRSTRLEN]= {'\0'};
  char *method = NULL;

#ifdef DEBUG
  int do_warning = (config.warning_time > 0);
  {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = child_signal_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGTERM, &sa, NULL)) {
    }
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGUSR2, &sa, NULL)) {
    }
  }
  printf("%s: tid = %d\n", __FUNCTION__, (int)pthread_self());
#endif

  if (setsockopt(config.new_fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(struct timeval)) < 0) {
  }

  pipedata.ssl_ver = (CONN_TLSTOR(ptr, ssl)) ? SSL_version(CONN_TLSTOR(ptr, ssl)) : 0;
  pipedata.run_time = CONN_TLSTOR(ptr, init_time);
  get_client_ip(config.new_fd, client_ip, sizeof client_ip, NULL, 0);

  while(1) {

    if (!CONN_TLSTOR(ptr, early_data)) {

      struct pollfd pfd = { config.new_fd, POLLIN, POLLIN };
      int selrv = poll(&pfd, 1, 1000 * config.http_keepalive);
      TESTPRINT("socket:%d selrv:%d errno:%d\n", config.new_fd, selrv, errno);

      int peekrv = peek_socket(config.new_fd, CONN_TLSTOR(ptr, ssl));
      if (total_bytes == 0 && peekrv <= 0) {

        if (CONN_TLSTOR(ptr, ssl))
          pipedata.ssl = SSL_HIT_CLS;
        pipedata.status = FAIL_CLOSED;
        pipedata.rx_total = 0;
        write_pipe(config.pipefd, &pipedata);
        num_req++;
        break;
      }
      if (selrv <= 0 || peekrv <=0 )
        break;
    }

    get_time(&start_time);

    int log_verbose = log_get_verb();
    response = httpnulltext;
    rsize = 0;
    post_buf_len = 0;

    errno = 0;
    rv = read_socket(config.new_fd, &buf, CONN_TLSTOR(ptr, ssl), CONN_TLSTOR(ptr, early_data));
    if (rv <= 0) {
      if (errno == ECONNRESET || rv == 0) {
        pipedata.status = FAIL_CLOSED;
      } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
        pipedata.status = FAIL_TIMEOUT;
      } else {
        pipedata.status = FAIL_GENERAL;
      }
    } else {
      if (CONN_TLSTOR(ptr, ssl)) {
        pipedata.ssl = CONN_TLSTOR(ptr, early_data) ? SSL_HIT_RTT0 : SSL_HIT;
      } else {
        pipedata.ssl = SSL_NOT_TLS;
      }

      TIME_CHECK("initial recv()");
      buf[rv] = '\0';
      TESTPRINT("\nreceived %d bytes\n'%s'\n", rv, buf);
      pipedata.rx_total = rv;
      total_bytes += rv;

#ifdef HEX_DUMP
      hex_dump(buf, rv);
#endif
      char *body = strstr_first(buf, "\r\n\r\n");
      int body_len = (body) ? (rv + buf - body) : 0;
      char *req = strtok_r(buf, "\r\n", &bufptr);
      if (log_verbose >= LGG_INFO) {
        if (req) {
          host[0] = '\0';
          if (strlen(req) > req_len) {
            req_len = strlen(req);
            char *new_req_url = realloc(req_url, req_len + 1);
            if (new_req_url) {
              req_url = new_req_url;
              req_url[0] = '\0';
            } else {
              if (req_url) req_url[0] = '\0';
            }
          }
          if (req_url) {
            strncpy(req_url, req, req_len);
            req_url[req_len] = '\0';  // Ensure null termination
          }

          if (req_url && strstr(req_url, "/simulate-block")) {
                    const char *resp =
                      "HTTP/1.1 204 No Content\r\n"
                      "Access-Control-Allow-Origin: *\r\n"
                      "Connection: close\r\n"
                      "\r\n";

                    write_socket(config.new_fd,
                                 resp,
                                 strlen(resp),
                                 CONN_TLSTOR(ptr, ssl),
                                 &CONN_TLSTOR(ptr, early_data));

                    if (CONN_TLSTOR(ptr, early_data)) {
                      CONN_TLSTOR(ptr, early_data) = NULL;
                    }
                    free(cors_origin);
                    free(req_url);
                    free(post_buf);
                    free(aspbuf);
                    free(buf);
                    conn_stor_relinq(ptr);
                    return NULL;
          }

          char *tmph = strstr_first(bufptr, "Host: ");
          if (tmph) {
            strncpy(host, tmph + 6, HOST_LEN_MAX);
            host[HOST_LEN_MAX] = '\0';
            strtok(host, "\r\n");
            TESTPRINT("socket:%d host:%s\n", config.new_fd, host);
          }
        }
      }

      char *orig_hdr;
      orig_hdr = strstr_first(bufptr, "Origin: ");
      if (orig_hdr) {
        char *new_cors_origin = realloc(cors_origin, CORS_ORIGIN_LEN_MAX);
        if (new_cors_origin) {
          cors_origin = new_cors_origin;
          strncpy(cors_origin, orig_hdr + 8, CORS_ORIGIN_LEN_MAX - 1);
          cors_origin[CORS_ORIGIN_LEN_MAX - 1] = '\0';
          strtok(cors_origin, "\r\n");
          if (strncmp(cors_origin, "null", 4) == 0) {
              cors_origin[0] = '*';
              cors_origin[1] = '\0';
          }
        }
      }

      char *reqptr;
      method = req ? strtok_r(req, " ", &reqptr) : NULL;

      if (method == NULL) {
      } else {
        TESTPRINT("method: '%s'\n", method);
        if (!strcmp(method, "OPTIONS")) {
          pipedata.status = SEND_OPTIONS;

          // Extract Access-Control-Request-Method (mirror what browser asks for)
          char req_method[128] = "*";  // Default: allow all
          char *method_hdr = strstr_first(bufptr, "Access-Control-Request-Method:");
          if (method_hdr) {
            method_hdr += strlen("Access-Control-Request-Method:");
            while (*method_hdr == ' ') method_hdr++;  // Skip whitespace
            char *end = strpbrk(method_hdr, "\r\n");
            if (end) {
              size_t len = (size_t)(end - method_hdr);
              if (len > 0 && len < sizeof(req_method)) {
                memcpy(req_method, method_hdr, len);
                req_method[len] = '\0';
              }
            }
          }

          // Extract Access-Control-Request-Headers (mirror what browser asks for)
          char req_headers[512] = "*";  // Default: allow all
          char *headers_hdr = strstr_first(bufptr, "Access-Control-Request-Headers:");
          if (headers_hdr) {
            headers_hdr += strlen("Access-Control-Request-Headers:");
            while (*headers_hdr == ' ') headers_hdr++;  // Skip whitespace
            char *end = strpbrk(headers_hdr, "\r\n");
            if (end) {
              size_t len = (size_t)(end - headers_hdr);
              if (len > 0 && len < sizeof(req_headers)) {
                memcpy(req_headers, headers_hdr, len);
                req_headers[len] = '\0';
              }
            }
          }

          // Build fully dynamic OPTIONS response mirroring browser's request
          const char *origin = cors_origin ? cors_origin : "*";
          rsize = asprintf(&aspbuf, httpoptions_template, origin, req_method, req_headers);
          response = (rsize >= 0) ? aspbuf : httpnulltext;
        } else if (!strcmp(method, "POST")) {
          int recv_len = 0;
          int length = 0;
          int post_buf_size = 0;
          int wait_cnt = MAX_HTTP_POST_RETRY;
          char *h = strstr_first(bufptr, "Content-Length:");

          if (!h)
            goto end_post;
          h += strlen("Content-Length:");
          length = atoi(strtok(h, "\r\n"));

            if (log_verbose >= LGG_INFO) {

            post_buf_size = (length < MAX_HTTP_POST_LEN) ? length : MAX_HTTP_POST_LEN;
            char *new_post_buf = realloc(post_buf, post_buf_size + 1);
            if (!new_post_buf) {
              goto end_post;
            }
            post_buf = new_post_buf;
            post_buf[post_buf_size] = '\0';

            if (body && body_len > 4) {
              recv_len = body_len - 4;
              memcpy(post_buf, body + 4, recv_len);
              length -= recv_len;
              post_buf_size -= recv_len;
            }

            pipedata.run_time += elapsed_time_msec(start_time);

            for (; length > 0 && wait_cnt > 0;) {
              get_time(&start_time);

              if (CONN_TLSTOR(ptr, ssl))
                rv = ssl_read(CONN_TLSTOR(ptr, ssl), post_buf + recv_len, post_buf_size);
              else
                rv = recv(config.new_fd, post_buf + recv_len, post_buf_size, MSG_WAITALL);

              if (rv > 0) {
                pipedata.rx_total += rv;
                length -= rv;
                if ((recv_len + rv) < MAX_HTTP_POST_LEN) {
                  recv_len += rv;
                  post_buf_size -= rv;
                  post_buf[recv_len] = '\0';
                } else {
                  if (length > CHAR_BUF_SIZE) {
                    recv_len += rv - CHAR_BUF_SIZE;
                    post_buf_size = CHAR_BUF_SIZE;
                  } else {
                    recv_len += rv - length;
                    post_buf_size = length;
                  }
                }
                pipedata.run_time += elapsed_time_msec(start_time);
                wait_cnt = MAX_HTTP_POST_RETRY;
              } else
                --wait_cnt;
            }
          } else {
            if (post_buf == NULL) {
              post_buf = malloc(CHAR_BUF_SIZE + 1);
              if (!post_buf) {
                goto end_post;
              }
            }
            if (body && body_len > 4)
              length -= body_len - 4;

            pipedata.run_time += elapsed_time_msec(start_time);

            for (; length > 0 && wait_cnt > 0;) {
              get_time(&start_time);

              if (CONN_TLSTOR(ptr, ssl))
                rv = ssl_read(CONN_TLSTOR(ptr, ssl), post_buf, CHAR_BUF_SIZE);
              else
                rv = recv(config.new_fd, post_buf, CHAR_BUF_SIZE, 0);

              if (rv > 0) {
                pipedata.rx_total += rv;
                length -= rv;
                pipedata.run_time += elapsed_time_msec(start_time);
                wait_cnt = MAX_HTTP_POST_RETRY;
              } else
                --wait_cnt;
            }
            recv_len = 0;
          }
          get_time(&start_time);

end_post:
          post_buf_len = recv_len;
          pipedata.status = SEND_POST;
        } else if (!strcmp(method, "GET")) {
          pipedata.status = DEFAULT_REPLY;
          char *path = strtok_r(NULL, " ", &reqptr);
          if (path == NULL) {
            pipedata.status = SEND_NO_URL;
          } else if (!strncmp(path, "/favicon.ico", 12)) {
    size_t favicon_len = favicon_ico_len;
    char hdr[128];
    int hdrlen = snprintf(hdr, sizeof hdr,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: image/x-icon\r\n"
        "Content-Length: %zu\r\n"
        "Connection: keep-alive\r\n"
        "\r\n",
        favicon_len);
write_socket(config.new_fd,
             hdr,
             hdrlen,
             CONN_TLSTOR(ptr, ssl),
             &CONN_TLSTOR(ptr, early_data));

write_socket(config.new_fd,
             (const char*)favicon_ico,
             favicon_len,
             CONN_TLSTOR(ptr, ssl),
             &CONN_TLSTOR(ptr, early_data));
    pipedata.status = SEND_ICO;
    continue;
        } else if (!strncmp(path, "/log=", 5) && CONN_TLSTOR(ptr, allow_admin)) {
            if (strlen(path) <= 5) {
              pipedata.status = SEND_BAD;
            } else {
              int v = atoi(path + strlen("/log="));
              if (v > LGG_DEBUG || v < 0)
                pipedata.status = SEND_BAD;
              else {
                pipedata.status = ACTION_LOG_VERB;
                pipedata.verb = v;
              }
            }
          } else if (!strncmp(path, "/ca.crt", 7)) {
            FILE *fp;
            char *ca_file = NULL;
            response = httpnulltext;
            rsize = sizeof httpnulltext - 1;
            pipedata.status = SEND_TXT;

            if (asprintf(&ca_file, "%s%s", config.pem_dir, "/ca.crt") != -1 &&
               NULL != (fp = fopen(ca_file, "r")))
            {
              fseek(fp, 0L, SEEK_END);
              long file_sz = ftell(fp);
              rewind(fp);
              rsize = asprintf(&aspbuf, "%s%ld%s", httpcacert, file_sz, httpcacert2);
              if (rsize != -1 && (aspbuf = (char*)realloc(aspbuf, rsize + file_sz + 16)) != NULL &&
                     fread(aspbuf + rsize, 1, file_sz, fp) == (size_t)file_sz) {
                response = aspbuf;
                rsize += file_sz;
                pipedata.status = SEND_TXT;
              }
              fclose(fp);
            }
            if (ca_file) free(ca_file);
          } else if (!strcmp(path, config.stats_url) && CONN_TLSTOR(ptr, allow_admin)) {
            pipedata.status = SEND_STATS;
            version_string = get_version(config.argc, config.argv);
            stat_string = get_stats(1, 0);
            if (version_string && stat_string) {
              rsize = asprintf(&aspbuf,
                               "%s%u%s%s%s<br>%s%s",
                               httpstats1,
                               (unsigned int)(statsbaselen + strlen(version_string) + 4 + strlen(stat_string)),
                               httpstats2,
                               httpstats3,
                               version_string,
                               stat_string,
                               httpstats4);
              if (rsize == -1) {
                response = httpnulltext;
                rsize = sizeof httpnulltext - 1;
              } else {
                response = aspbuf;
              }
            }
            if (version_string) {
              free(version_string);
              version_string = NULL;
            }
            if (stat_string) {
              free(stat_string);
              stat_string = NULL;
            }
            response = aspbuf;
          } else if (!strcmp(path, config.stats_text_url) && CONN_TLSTOR(ptr, allow_admin)) {
            pipedata.status = SEND_STATSTEXT;
            version_string = get_version(config.argc, config.argv);
            stat_string = get_stats(0, 1);
            if (version_string && stat_string) {
              rsize = asprintf(&aspbuf,
                               "%s%u%s%s\n%s%s",
                               txtstats1,
                               (unsigned int)(strlen(version_string) + 1 + strlen(stat_string) + 2),
                               txtstats2,
                               version_string,
                               stat_string,
                               txtstats3);
              if (rsize == -1) {
                response = httpnulltext;
                rsize = sizeof httpnulltext - 1;
              } else {
                response = aspbuf;
              }
            }
            if (version_string) {
              free(version_string);
              version_string = NULL;
            }
            if (stat_string) {
              free(stat_string);
              stat_string = NULL;
            }
            response = aspbuf;
          } else if (config.do_204 && (!strcasecmp(path, "/generate_204") || !strcasecmp(path, "/gen_204"))) {
            pipedata.status = SEND_204;
            response = http204;
            rsize = sizeof http204 - 1;
          } else if (!strncasecmp(path, "/pagead/imgad?", 14) ||
                     !strncasecmp(path, "/pagead/conversion/", 19 ) ||
                     !strncasecmp(path, "/pcs/view?xai=AKAOj", 19 ) ||
                     !strncasecmp(path, "/daca_images/simgad/", 20)) {
            pipedata.status = SEND_GIF;
            response = httpnullpixel;
            rsize = sizeof httpnullpixel - 1;
          } else {
            if (config.do_redirect && strcasestr(path, "=http")) {
              char *decoded = malloc(strlen(path)+1);
              if (decoded) {
                urldecode(decoded, path);

                urldecode(path, decoded);
                free(decoded);
                url = strstr_last(path, "http://");
                if (url == NULL) {
                  url = strstr_last(path, "https://");
                }
                if (url) {
                  char *tok = NULL;
                  for (tok = strtok_r(NULL, "\r\n", &bufptr); tok; tok = strtok_r(NULL, "\r\n", &bufptr)) {
                    char *hkey = strtok(tok, ":");
                    char *hvalue = strtok(NULL, "\r\n");
                    if (strstr_first(hkey, "Referer") && strstr_first(hvalue, url)) {
                      url = NULL;
                      TESTPRINT("Not redirecting likely callback URL: %s:%s\n", hkey, hvalue);
                      break;
                    }
                  }
                }
              }
            }
            if (config.do_redirect && url) {
              if (!cors_origin) {
                rsize = asprintf(&aspbuf, httpredirect, url, "");
              } else {
                char *tmpcors = NULL;
                int ret = asprintf(&tmpcors, httpcors_headers, cors_origin);
                if (ret != -1) {
                  rsize = asprintf(&aspbuf, httpredirect, url, tmpcors);
                  free(tmpcors);
                }
              }
              if (rsize == -1) {
                pipedata.status = SEND_TXT;
                response = httpnulltext;
                rsize = sizeof httpnulltext - 1;
              } else {
                pipedata.status = SEND_REDIRECT;
                response = aspbuf;
              }
              url = NULL;
              TESTPRINT("Sending redirect: %s\n", url);
            } else {
              char *file = strrchr(strtok(path, "?#;="), '/');
              if (file == NULL) {
                pipedata.status = SEND_TXT;
                response = httpnulltext;
                rsize = sizeof httpnulltext - 1;
              } else {
                TESTPRINT("file: '%s'\n", file);
                char *ext = strrchr(file, '.');
                if (ext == NULL) {
                  pipedata.status = SEND_TXT;
                  response = httpnulltext;
                  rsize = sizeof httpnulltext - 1;
                } else {
                  TESTPRINT("ext: '%s'\n", ext);

                  const char *norm_ext = (ext[0] == '.') ? ext + 1 : ext;

                  /* Fast extension lookup using table instead of strcasecmp chains */
                  const ext_entry_t *ext_entry = lookup_extension(norm_ext);
                  pipedata.status = ext_entry->type;
                  response = ext_entry->response_data;
                  rsize = (ext_entry->response_size < 0) ? (int)(sizeof(httpnulltext) - 1) : ext_entry->response_size;

                  TESTPRINT("Extension '%s' -> status %d, response %p, size %d\n",
                            norm_ext, pipedata.status, response, rsize);
                }
              }
            }
          }
        } else {
          if (!strcmp(method, "HEAD")) {
            pipedata.status = SEND_HEAD;
          } else {
            pipedata.status = SEND_BAD;
          }
          response = http501;
          rsize = sizeof http501 - 1;
        }
      }
      TESTPRINT("%s: req type %d\n", __FUNCTION__, pipedata.status);

      // KORRIGIERTE httpnulltext Response-Behandlung
      if (response == httpnulltext) {
        if (!cors_origin) {
          rsize = asprintf(&aspbuf, httpnulltext, get_index_html_len(), "");  // ← KORRIGIERT: get_index_html_len() hinzugefügt
        } else {
          static const char cors_template[] = 
            "Access-Control-Allow-Origin: %.100s\r\n"
            "Access-Control-Allow-Credentials: true\r\n"
            "Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept, documentReferer\r\n";
          
          char cors_buf[256];
          int cors_len = snprintf(cors_buf, sizeof(cors_buf), cors_template, cors_origin);

          if (cors_len > 0 && (size_t)cors_len < sizeof(cors_buf)) {
            rsize = asprintf(&aspbuf, httpnulltext, get_index_html_len(), cors_buf);  // ← KORRIGIERT: get_index_html_len() hinzugefügt
          } else {
            rsize = asprintf(&aspbuf, httpnulltext, get_index_html_len(), "");  // ← KORRIGIERT: get_index_html_len() hinzugefügt
          }
        }
        if (rsize != -1) {
          response = aspbuf;
        }
      }
      
      // KORRIGIERTE ASP-Response-Behandlung
      else if (response == httpnull_asp) {
        rsize = asprintf(&aspbuf, httpnull_asp, get_index_html_len());  // ← KORRIGIERT: get_index_html_len() Parameter
        if (rsize != -1) {
          response = aspbuf;
        }
      }
      else if (response == httpnull_aspx) {
        rsize = asprintf(&aspbuf, httpnull_aspx, get_index_html_len());  // ← KORRIGIERT: get_index_html_len() Parameter
        if (rsize != -1) {
          response = aspbuf;
        }
      }
      else if (response == httpnull_ashx) {
        rsize = asprintf(&aspbuf, httpnull_ashx, get_index_html_len());  // ← KORRIGIERT: get_index_html_len() Parameter
        if (rsize != -1) {
          response = aspbuf;
        }
      }
      else if (response == httpnull_php) {
        rsize = asprintf(&aspbuf, httpnull_php, get_index_html_len());  // ← KORRIGIERT: get_index_html_len() Parameter
        if (rsize != -1) {
          response = aspbuf;
        }
      }
      else if (response == httpnull_jsp) {
        rsize = asprintf(&aspbuf, httpnull_jsp, get_index_html_len());  // ← KORRIGIERT: get_index_html_len() Parameter
        if (rsize != -1) {
          response = aspbuf;
        }
      }
      else if (response == httpnull_js) {
        rsize = asprintf(&aspbuf, httpnull_js, get_index_html_len());  // ← KORRIGIERT: get_index_html_len() Parameter
        if (rsize != -1) {
          response = aspbuf;
        }
      }
    }
#ifdef DEBUG
    if (pipedata.status != FAIL_TIMEOUT)
      TIME_CHECK("response selection");
#endif

    if (pipedata.status == FAIL_GENERAL) {
    } else if (pipedata.status != FAIL_TIMEOUT && pipedata.status != FAIL_CLOSED) {

      errno = 0;
      rv = write_socket(config.new_fd, response, rsize, CONN_TLSTOR(ptr, ssl), &CONN_TLSTOR(ptr, early_data));
      if (rv < 0) {
        if (errno == ECONNRESET || errno == EPIPE) {
          if (CONN_TLSTOR(ptr, ssl))
            strncpy(host, CONN_TLSTOR(ptr, tlsext_cb_arg)->servername, HOST_LEN_MAX);
          pipedata.status = FAIL_REPLY;
        } else {
          pipedata.status = FAIL_GENERAL;
        }
      } else if (rv != rsize) {
      }

      /* Send index_html body after httpnulltext/ASP headers if content exists */
      if (pipedata.status != FAIL_REPLY && pipedata.status != FAIL_GENERAL &&
          get_index_html_len() > 0 &&
          (response == aspbuf)) {  /* aspbuf indicates dynamic header from httpnulltext/ASP templates */
        int body_rv = write_socket(config.new_fd, (const char *)get_index_html(), get_index_html_len(),
                                   CONN_TLSTOR(ptr, ssl), &CONN_TLSTOR(ptr, early_data));
        if (body_rv < 0) {
          if (errno == ECONNRESET || errno == EPIPE) {
            pipedata.status = FAIL_REPLY;
          }
        }
      }

      if (log_verbose >= LGG_INFO) {
        log_xcs(LGG_INFO, client_ip, host, pipedata.ssl_ver, req_url, post_buf, post_buf_len);
      }

      if (aspbuf) {
        free(aspbuf);
        aspbuf = NULL;
      }
    }

    TIME_CHECK("response send()");

    pipedata.run_time += elapsed_time_msec(start_time);
    write_pipe(config.pipefd, &pipedata);
    num_req++;

    TESTPRINT("run_time %.2f\n", pipedata.run_time);
    pipedata.run_time = 0.0;

    TIME_CHECK("pipe write()");

    if (pipedata.status == FAIL_CLOSED)
      break;

  }

  if(CONN_TLSTOR(ptr, ssl)){
    SSL_set_shutdown(CONN_TLSTOR(ptr, ssl), SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    SSL_free(CONN_TLSTOR(ptr, ssl));
    CONN_TLSTOR(ptr, ssl) = NULL;
  }

  if (shutdown(config.new_fd, SHUT_RDWR) < 0) {
  }
  if (close(config.new_fd) < 0) {
  }

  TIME_CHECK("socket close()");
  
  memset(&pipedata, 0, sizeof(pipedata));
  pipedata.status = ACTION_DEC_KCC;
  pipedata.krq = num_req;
  rv = write(config.pipefd, &pipedata, sizeof(pipedata));

  if (cors_origin) {
    free(cors_origin);
    cors_origin = NULL;
  }
  if (req_url) {
    free(req_url);
    req_url = NULL;
  }
  if (post_buf) {
    free(post_buf);
    post_buf = NULL;
  }
  if (aspbuf) {
    free(aspbuf);
    aspbuf = NULL;
  }
  if (buf) {
    free(buf);
    buf = NULL;
  }

  conn_stor_relinq(ptr);
  return NULL;
}

// =============================================================================
// ASP-KONFIGURATIONSFUNKTIONEN
// =============================================================================

typedef struct {
    int enable_asp_logging;
    int enable_mime_detection;
    int cache_responses;
    char default_charset[32];
} asp_config_t;

static asp_config_t asp_config = {
    .enable_asp_logging = 1,
    .enable_mime_detection = 1,
    .cache_responses = 0,
    .default_charset = "UTF-8"
};

void socket_handler_set_asp_config(int enable_logging, int enable_mime, const char *charset) {
    asp_config.enable_asp_logging = enable_logging;
    asp_config.enable_mime_detection = enable_mime;
    
    if (charset && strlen(charset) < sizeof(asp_config.default_charset)) {
        strncpy(asp_config.default_charset, charset, sizeof(asp_config.default_charset) - 1);
        asp_config.default_charset[sizeof(asp_config.default_charset) - 1] = '\0';
    }
}

// =============================================================================
// ERWEITERTE FUNKTIONEN FÜR SKALIERBARKEIT UND MONITORING
// =============================================================================

void socket_handler_init(void) {
    asp_config.enable_asp_logging = 1;
    asp_config.enable_mime_detection = 1;
    asp_config.cache_responses = 0;
    strncpy(asp_config.default_charset, "UTF-8", sizeof(asp_config.default_charset) - 1);
    asp_config.default_charset[sizeof(asp_config.default_charset) - 1] = '\0';
}

void socket_handler_cleanup(void) {
    /* Free external HTML if loaded */
    if (external_html) {
        free(external_html);
        external_html = NULL;
        external_html_len = 0;
    }
}

void socket_handler_get_metrics(char *buffer, size_t size) {
    if (!buffer || size == 0) return;
    
    snprintf(buffer, size, 
        "ASP Support: %s\n"
        "MIME Detection: %s\n"
        "Default Charset: %s\n"
        "Cache Responses: %s\n",
        asp_config.enable_asp_logging ? "Enabled" : "Disabled",
        asp_config.enable_mime_detection ? "Enabled" : "Disabled",
        asp_config.default_charset,
        asp_config.cache_responses ? "Enabled" : "Disabled"
    );
}

void socket_handler_set_thread_pool(int enable) {
    (void)enable;
}

void socket_handler_set_rate_limit(int tokens_per_sec) {
    (void)tokens_per_sec;
}

void socket_handler_set_memory_pool_size(size_t size) {
    (void)size;
}
