/* socket_handler_extended.h */
#ifndef SOCKET_HANDLER_EXTENDED_H
#define SOCKET_HANDLER_EXTENDED_H

#include "net/socket_handler.h"
#include "content/anti_adblock.h"
#include "content/extension_lookup.h"

/* Extended response structure with anti-adblock features */
typedef struct {
    response_struct base_response;     /* Original response struct - UNCHANGED */
    
    /* New anti-adblock extensions */
    dynamic_headers_t dynamic_headers;
    cors_config_t cors_config;
    adblock_seed_t adblock_seeds;
    char content_buffer[4096];         /* For dynamic content */
    
    /* Request context for randomization */
    char request_uri[1024];
    char user_agent[512];
    char remote_addr[64];
    char origin_header[256];
} extended_response_struct;

/* Extended connection handler that wraps original conn_handler */
void* extended_conn_handler(void *ptr);

/* Header generation functions */
void generate_anti_adblock_headers(extended_response_struct *ext_resp, 
                                  char *header_buffer, size_t buffer_size);

void generate_cors_headers(extended_response_struct *ext_resp, 
                          char *header_buffer, size_t buffer_size);

void generate_csp_headers(extended_response_struct *ext_resp, 
                         const char *extension,
                         char *header_buffer, size_t buffer_size);

/* Dynamic content generation for specific response types */
void generate_dynamic_js_response(extended_response_struct *ext_resp);
void generate_dynamic_css_response(extended_response_struct *ext_resp);
void generate_dynamic_json_response(extended_response_struct *ext_resp);
void generate_dynamic_xml_response(extended_response_struct *ext_resp);

/* Extract request information for randomization */
void extract_request_context(extended_response_struct *ext_resp, 
                           const char *request_line,
                           const char *headers);

/* Initialize extended socket handler system */
void socket_handler_extended_init(void);
void socket_handler_extended_cleanup(void);

#endif /* SOCKET_HANDLER_EXTENDED_H */
