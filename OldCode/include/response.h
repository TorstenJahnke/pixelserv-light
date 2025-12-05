/*
 * response.h - HTTP Response Generation for TLSGate NX
 *
 * Shared response generation logic for both single-threaded and multi-threaded servers
 * - 265+ MIME types with ultra-fast lookup
 * - Anti-adblock polymorphic responses (randomized JS/CSS)
 * - Security headers (CORS, CSP neutralization)
 * - Real favicon.ico (9,462 bytes) vs minimal ICO (70 bytes)
 * - Minimal pixel responses (1x1 GIF, empty content)
 */

#ifndef RESPONSE_H
#define RESPONSE_H

#include <stddef.h>
#include "connection.h"

/* ========== Response Generation Functions ========== */

/* Generate HTTP response for a connection based on parsed request
 * Sets conn->response_buf, conn->response_len, conn->response_is_static
 * Returns: 0 on success, -1 on error
 */
int response_generate(connection_t *conn);

/* Generate specific response types
 * All functions set response_buf, response_len, response_is_static
 * Returns: 0 on success, -1 on error
 */
int response_generate_404(connection_t *conn);
int response_generate_204(connection_t *conn);
int response_generate_index(connection_t *conn);
int response_generate_favicon(connection_t *conn);
int response_generate_for_extension(connection_t *conn, const char *ext);

/* ========== Utility Functions ========== */

/* Get MIME type for file extension (265+ types supported)
 * Returns: MIME type string (never NULL, falls back to "application/octet-stream")
 */
const char* response_get_mime_type(const char *ext);

/* Initialize response system (seed random generator, etc.)
 * Call once at startup
 */
void response_init(void);

/* ========== HTML Template System ========== */

/* Load HTML template from disk at runtime
 * Allows changing templates without recompiling (critical for production!)
 *
 * SECURITY: Templates are validated before use:
 * - Must be in /etc/tlsgateNG/templates/ directory
 * - Max size: 1MB (prevents loading huge files)
 * - File must be readable and valid UTF-8
 * - Separate from application code (can't execute code)
 *
 * @param template_name: Template filename (e.g., "blocking.html")
 * @return 0 on success, -1 on error
 */
int response_load_html_template_file(const char *template_name);

/* Set template from memory buffer
 * Useful for testing or custom templates
 *
 * @param template_content: HTML content buffer
 * @param content_len: Length of content
 * @return 0 on success, -1 on error
 */
int response_set_html_template(const char *template_content, size_t content_len);

/* Get current template content
 * @return Pointer to current template (static buffer), or NULL if not set
 */
const char* response_get_html_template(void);

/* Get current template size in bytes
 * @return Template size, or 0 if not set
 */
size_t response_get_html_template_size(void);

/* ========== Anti-AdBlock Content Generation ========== */

/* Generate polymorphic JS/CSS content to evade AdBlock signatures
 * buf: Output buffer
 * size: Buffer size
 * Returns: Length of generated content
 */
size_t response_generate_random_js(char *buf, size_t size);
size_t response_generate_random_css(char *buf, size_t size);

#endif /* RESPONSE_H */
