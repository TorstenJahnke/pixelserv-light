/* TLS-Gate NX - SNI Extractor
 * Copyright (C) 2025 Torsten Jahnke
 *
 * Minimal TLS parsing to extract SNI (Server Name Indication)
 * Zero logging, optimized for speed
 */

#ifndef TLSGATENG_SNI_EXTRACTOR_H
#define TLSGATENG_SNI_EXTRACTOR_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Extract SNI from TLS ClientHello
 *
 * Parses TLS ClientHello to find SNI extension.
 * Minimal parsing - only what's needed for SNI extraction.
 *
 * @param data      TLS ClientHello data
 * @param data_len  Data length
 * @param sni_out   Output buffer for SNI hostname
 * @param sni_len   Output buffer size
 * @return true if SNI extracted, false otherwise
 *
 * Example:
 *   char sni[256];
 *   if (extract_sni(client_hello, len, sni, sizeof(sni))) {
 *       // Use sni to generate certificate
 *   }
 */
bool extract_sni(const uint8_t *data, size_t data_len,
                 char *sni_out, size_t sni_len);

/* Check if buffer contains TLS ClientHello
 *
 * Quick check to see if data looks like TLS ClientHello.
 * Used to detect TLS vs plain HTTP traffic.
 *
 * @param data      Buffer to check
 * @param data_len  Buffer length
 * @return true if looks like TLS ClientHello
 */
bool is_tls_client_hello(const uint8_t *data, size_t data_len);

#endif /* TLSGATENG_SNI_EXTRACTOR_H */
