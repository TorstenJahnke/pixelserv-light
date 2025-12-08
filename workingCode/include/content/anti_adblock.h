/* anti_adblock.h */
#ifndef ANTI_ADBLOCK_H
#define ANTI_ADBLOCK_H

#include <stdint.h>
#include <time.h>
#include "content/extension_hash_table.h"

/* Anti-AdBlock randomization seed structure */
typedef struct {
    uint32_t time_seed;
    uint32_t request_seed;
    uint32_t content_seed;
    uint32_t crypto_seed;
} adblock_seed_t;

/* Dynamic header set structure */
typedef struct {
    char server_header[64];
    char cf_ray[32];
    char cache_status[16];
    char vary_header[128];
    char etag[32];
    int has_etag;
} dynamic_headers_t;

/* CORS configuration */
typedef struct {
    char origin[256];
    int has_origin;
    int allow_credentials;
} cors_config_t;

/* CSP policy strings for different content types */
extern const char* CSP_POLICIES[];

/* Public functions */
void anti_adblock_init(void);
void anti_adblock_cleanup(void);

/* Seed generation for randomization */
adblock_seed_t anti_adblock_generate_seeds(const char *request_uri, 
                                          const char *user_agent, 
                                          const char *remote_addr);

/* Dynamic header generation */
void anti_adblock_generate_headers(const adblock_seed_t *seeds, 
                                  dynamic_headers_t *headers);

/* CORS header generation (origin-adaptive like PHP script) */
void anti_adblock_generate_cors(const char *origin, cors_config_t *cors);

/* v2: Probabilistic CORS - 70% send, 30% skip (mimics real servers) */
int anti_adblock_should_send_cors(const adblock_seed_t *seeds);

/* v2: Randomized CORS header generation (anti-fingerprinting) */
void anti_adblock_generate_random_cors(const adblock_seed_t *seeds,
                                       const char *origin_header,
                                       char *cors_header_buffer,
                                       size_t buffer_size);

/* CSP header generation based on content type */
const char* anti_adblock_get_csp_policy(csp_policy_type_t policy_type, 
                                       const adblock_seed_t *seeds);

/* Dynamic content generation for JS/CSS (randomized for AdBlock prevention) */
void anti_adblock_generate_js_content(const adblock_seed_t *seeds, 
                                     char *buffer, size_t buffer_size);

void anti_adblock_generate_css_content(const adblock_seed_t *seeds, 
                                      char *buffer, size_t buffer_size);

void anti_adblock_generate_json_content(const adblock_seed_t *seeds, 
                                       char *buffer, size_t buffer_size);

void anti_adblock_generate_xml_content(const adblock_seed_t *seeds, 
                                      char *buffer, size_t buffer_size);

/* Get randomized cache time */
int anti_adblock_get_cache_time(const adblock_seed_t *seeds, 
                               const char *extension);

/* Variable delay for unpredictable timing */
void anti_adblock_variable_delay(const adblock_seed_t *seeds);

#endif /* ANTI_ADBLOCK_H */
