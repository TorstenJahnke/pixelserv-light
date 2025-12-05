/* TLS-Gate NX - SNI Extractor Implementation
 * Copyright (C) 2025 Torsten Jahnke
 *
 * Minimal TLS parsing - only SNI extraction, nothing else!
 */

#include "sni_extractor.h"
#include <string.h>

/* TLS Content Types */
#define TLS_CONTENT_TYPE_HANDSHAKE 0x16

/* TLS Handshake Types */
#define TLS_HANDSHAKE_CLIENT_HELLO 0x01

/* TLS Extension Types */
#define TLS_EXTENSION_SERVER_NAME 0x0000

/* TLS Server Name Types */
#define TLS_SNI_TYPE_HOSTNAME 0x00

/* SNI length limit for ad-blocking IP termination (much higher than RFC 6066!)
 * We MUST handle any SNI the DNS server sends us, including very long FQDNs.
 * Example: unglaublich-langen-fqdn-mit-dummen-server-namen.irgendwas-ganz-lang.de
 * Limit: 2048 bytes (matches CONN_SNI_MAX_LEN in connection.h)
 */
#define MAX_SNI_LENGTH 2048

bool is_tls_client_hello(const uint8_t *data, size_t data_len) {
    if (data_len < 6) {
        return false;
    }

    /* Check TLS record header:
     * Byte 0: Content Type (0x16 = Handshake)
     * Byte 1-2: TLS Version (0x03 0x01 = TLS 1.0, 0x03 0x03 = TLS 1.2, etc.)
     * Byte 3-4: Record Length
     * Byte 5: Handshake Type (0x01 = ClientHello)
     */

    return (data[0] == TLS_CONTENT_TYPE_HANDSHAKE &&  /* Handshake */
            data[1] == 0x03 &&                         /* TLS version major */
            data[5] == TLS_HANDSHAKE_CLIENT_HELLO);    /* ClientHello */
}

bool extract_sni(const uint8_t *data, size_t data_len,
                 char *sni_out, size_t sni_len) {
    if (!data || !sni_out || data_len < 43 || sni_len == 0) {
        return false;
    }

    /* Quick check for TLS ClientHello */
    if (!is_tls_client_hello(data, data_len)) {
        return false;
    }

    size_t pos = 0;

    /* Skip TLS record header (5 bytes) */
    pos += 5;

    /* Skip handshake header (4 bytes):
     * - Handshake Type (1 byte)
     * - Length (3 bytes)
     */
    if (pos + 4 > data_len) return false;
    pos += 4;

    /* Skip Client Version (2 bytes) */
    if (pos + 2 > data_len) return false;
    pos += 2;

    /* Skip Random (32 bytes) */
    if (pos + 32 > data_len) return false;
    pos += 32;

    /* Session ID Length (1 byte) */
    if (pos + 1 > data_len) return false;
    uint8_t session_id_len = data[pos++];

    /* Skip Session ID */
    if (pos + session_id_len > data_len) return false;
    pos += session_id_len;

    /* Cipher Suites Length (2 bytes) */
    if (pos + 2 > data_len) return false;
    uint16_t cipher_suites_len = (data[pos] << 8) | data[pos + 1];
    pos += 2;

    /* Skip Cipher Suites */
    if (pos + cipher_suites_len > data_len) return false;
    pos += cipher_suites_len;

    /* Compression Methods Length (1 byte) */
    if (pos + 1 > data_len) return false;
    uint8_t compression_len = data[pos++];

    /* Skip Compression Methods */
    if (pos + compression_len > data_len) return false;
    pos += compression_len;

    /* Extensions Length (2 bytes) */
    if (pos + 2 > data_len) return false;
    uint16_t extensions_len = (data[pos] << 8) | data[pos + 1];
    pos += 2;

    if (pos + extensions_len > data_len) return false;

    /* Parse extensions to find SNI */
    size_t extensions_end = pos + extensions_len;

    while (pos + 4 <= extensions_end) {
        /* Extension Type (2 bytes) */
        uint16_t ext_type = (data[pos] << 8) | data[pos + 1];
        pos += 2;

        /* Extension Length (2 bytes) */
        uint16_t ext_len = (data[pos] << 8) | data[pos + 1];
        pos += 2;

        if (pos + ext_len > data_len) return false;

        /* Check if this is SNI extension */
        if (ext_type == TLS_EXTENSION_SERVER_NAME) {
            /* SNI Extension found! */
            size_t sni_pos = pos;

            /* Server Name List Length (2 bytes) */
            if (sni_pos + 2 > pos + ext_len) return false;
            sni_pos += 2;

            /* Server Name Type (1 byte) */
            if (sni_pos + 1 > pos + ext_len) return false;
            uint8_t name_type = data[sni_pos++];

            /* Only handle hostname type */
            if (name_type != TLS_SNI_TYPE_HOSTNAME) {
                pos += ext_len;
                continue;
            }

            /* Server Name Length (2 bytes) */
            if (sni_pos + 2 > pos + ext_len) return false;
            uint16_t name_len = (data[sni_pos] << 8) | data[sni_pos + 1];
            sni_pos += 2;

            /* Ad-blocking philosophy: ACCEPT EVERYTHING!
             * - Empty SNI? Accept (name_len == 0) → return empty string
             * - Long SNI? Accept (up to MAX_SNI_LENGTH) → truncate if needed
             * - Malformed? Accept → best-effort parsing
             * Rule: Always respond with 204/GIF, never reject!
             */

            /* Sanity check: Don't overflow our buffer */
            if (name_len > MAX_SNI_LENGTH) {
                /* Too long - truncate to our buffer size */
                name_len = MAX_SNI_LENGTH;
            }

            /* Extract hostname (or empty string if name_len == 0) */
            if (sni_pos + name_len > pos + ext_len) {
                /* Truncate to available data */
                name_len = (pos + ext_len) - sni_pos;
            }

            /* Copy to output buffer (with null termination) */
            size_t copy_len = (name_len < sni_len - 1) ? name_len : (sni_len - 1);
            if (copy_len > 0) {
                memcpy(sni_out, &data[sni_pos], copy_len);
            }
            sni_out[copy_len] = '\0';

            return true;  /* Always succeed! */
        }

        /* Skip to next extension */
        pos += ext_len;
    }

    /* SNI extension not found */
    return false;
}
