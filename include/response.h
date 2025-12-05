/*
 * response.h - HTTP Response Generation for TLSGate
 *
 * Features:
 * - 273+ MIME types with ultra-fast O(log n) lookup
 * - Pre-computed FNV-1a hash table
 * - Zero-copy static responses where possible
 * - Full CORS/CSP security header neutralization
 */

#ifndef RESPONSE_H
#define RESPONSE_H

#include <stddef.h>
#include <stdint.h>

/* Forward declaration */
struct connection;

/* Response buffer structure */
typedef struct response {
    const char *data;           /* Response data pointer */
    size_t len;                 /* Response length */
    int is_static;              /* 1 = static data (don't free), 0 = dynamic */
} response_t;

/* Initialize response system */
void response_init(void);

/* Generate HTTP response based on request
 * @param path      Request path (e.g., "/tracking.js")
 * @param method    HTTP method (e.g., "GET")
 * @param resp      Output response structure
 * @return          0 on success, -1 on error
 */
int response_generate(const char *path, const char *method, response_t *resp);

/* Generate response for specific extension
 * @param ext       File extension without dot (e.g., "js", "gif")
 * @param resp      Output response structure
 * @return          0 on success, -1 on error
 */
int response_for_extension(const char *ext, response_t *resp);

/* Free response buffer if dynamically allocated */
void response_free(response_t *resp);

/* Get MIME type for extension
 * @param ext       File extension without dot
 * @return          MIME type string (never NULL)
 */
const char *response_get_mime(const char *ext);

/* Pre-built static responses */
extern const response_t RESP_204_NO_CONTENT;
extern const response_t RESP_OPTIONS_CORS;
extern const response_t RESP_404_NOT_FOUND;

#endif /* RESPONSE_H */
