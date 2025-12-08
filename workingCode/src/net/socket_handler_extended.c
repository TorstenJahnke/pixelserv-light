/* socket_handler_extended.c */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "net/socket_handler_extended.h"

/* Global state */
static int extended_handler_initialized = 0;

/* Initialize extended socket handler */
void socket_handler_extended_init(void) {
    if (extended_handler_initialized) {
        return;
    }
    
    /* Initialize subsystems */
    extension_lookup_init();
    anti_adblock_init();
    
    extended_handler_initialized = 1;
}

/* Cleanup extended socket handler */
void socket_handler_extended_cleanup(void) {
    if (!extended_handler_initialized) {
        return;
    }
    
    extension_lookup_cleanup();
    anti_adblock_cleanup();
    
    extended_handler_initialized = 0;
}

/* Extract HTTP headers and request info */
void extract_request_context(extended_response_struct *ext_resp, 
                           const char *request_line,
                           const char *headers) {
    /* Clear context */
    memset(ext_resp->request_uri, 0, sizeof(ext_resp->request_uri));
    memset(ext_resp->user_agent, 0, sizeof(ext_resp->user_agent));
    memset(ext_resp->remote_addr, 0, sizeof(ext_resp->remote_addr));
    memset(ext_resp->origin_header, 0, sizeof(ext_resp->origin_header));
    
    /* Extract URI from request line (GET /path HTTP/1.1) */
    if (request_line) {
        const char *uri_start = strchr(request_line, ' ');
        if (uri_start) {
            uri_start++; /* Skip space */
            const char *uri_end = strchr(uri_start, ' ');
            if (uri_end) {
                size_t uri_len = uri_end - uri_start;
                if (uri_len < sizeof(ext_resp->request_uri) - 1) {
                    strncpy(ext_resp->request_uri, uri_start, uri_len);
                    ext_resp->request_uri[uri_len] = '\0';
                }
            }
        }
    }
    
    /* Extract headers if provided */
    if (headers) {
        /* Extract User-Agent */
        const char *ua_start = strstr(headers, "User-Agent:");
        if (!ua_start) ua_start = strstr(headers, "user-agent:");
        if (ua_start) {
            ua_start = strchr(ua_start, ':');
            if (ua_start) {
                ua_start++; /* Skip : */
                while (*ua_start == ' ') ua_start++; /* Skip spaces */
                const char *ua_end = strchr(ua_start, '\r');
                if (!ua_end) ua_end = strchr(ua_start, '\n');
                if (ua_end) {
                    size_t ua_len = ua_end - ua_start;
                    if (ua_len < sizeof(ext_resp->user_agent) - 1) {
                        strncpy(ext_resp->user_agent, ua_start, ua_len);
                        ext_resp->user_agent[ua_len] = '\0';
                    }
                }
            }
        }
        
        /* Extract Origin */
        const char *origin_start = strstr(headers, "Origin:");
        if (!origin_start) origin_start = strstr(headers, "origin:");
        if (origin_start) {
            origin_start = strchr(origin_start, ':');
            if (origin_start) {
                origin_start++; /* Skip : */
                while (*origin_start == ' ') origin_start++; /* Skip spaces */
                const char *origin_end = strchr(origin_start, '\r');
                if (!origin_end) origin_end = strchr(origin_start, '\n');
                if (origin_end) {
                    size_t origin_len = origin_end - origin_start;
                    if (origin_len < sizeof(ext_resp->origin_header) - 1) {
                        strncpy(ext_resp->origin_header, origin_start, origin_len);
                        ext_resp->origin_header[origin_len] = '\0';
                    }
                }
            }
        }
    }
    
    /* Get remote IP (placeholder - would need socket fd) */
    strcpy(ext_resp->remote_addr, "127.0.0.1"); /* Default */
}

/* Generate anti-adblock headers */
void generate_anti_adblock_headers(extended_response_struct *ext_resp, 
                                  char *header_buffer, size_t buffer_size) {
    char temp_buffer[2048];
    int written = 0;
    
    /* Generate dynamic headers */
    anti_adblock_generate_headers(&ext_resp->adblock_seeds, &ext_resp->dynamic_headers);
    
    /* Build header string */
    written += snprintf(temp_buffer + written, sizeof(temp_buffer) - written,
                       "Server: %s\r\n", ext_resp->dynamic_headers.server_header);
    
    written += snprintf(temp_buffer + written, sizeof(temp_buffer) - written,
                       "X-Cache: %s\r\n", ext_resp->dynamic_headers.cache_status);
    
    written += snprintf(temp_buffer + written, sizeof(temp_buffer) - written,
                       "X-Cache-Status: %s\r\n", ext_resp->dynamic_headers.cache_status);
    
    written += snprintf(temp_buffer + written, sizeof(temp_buffer) - written,
                       "CF-Cache-Status: %s\r\n", ext_resp->dynamic_headers.cache_status);
    
    written += snprintf(temp_buffer + written, sizeof(temp_buffer) - written,
                       "CF-RAY: %s\r\n", ext_resp->dynamic_headers.cf_ray);
    
    written += snprintf(temp_buffer + written, sizeof(temp_buffer) - written,
                       "Vary: %s\r\n", ext_resp->dynamic_headers.vary_header);
    
    if (ext_resp->dynamic_headers.has_etag) {
        written += snprintf(temp_buffer + written, sizeof(temp_buffer) - written,
                           "ETag: %s\r\n", ext_resp->dynamic_headers.etag);
    }
    
    /* Copy to output buffer */
    strncpy(header_buffer, temp_buffer, buffer_size - 1);
    header_buffer[buffer_size - 1] = '\0';
}

/* Generate CORS headers */
void generate_cors_headers(extended_response_struct *ext_resp, 
                          char *header_buffer, size_t buffer_size) {
    char temp_buffer[1024];
    int written = 0;
    
    /* Generate CORS config */
    const char *origin = (ext_resp->origin_header[0] != '\0') ? ext_resp->origin_header : NULL;
    anti_adblock_generate_cors(origin, &ext_resp->cors_config);
    
    /* Build CORS headers */
    if (ext_resp->cors_config.has_origin) {
        written += snprintf(temp_buffer + written, sizeof(temp_buffer) - written,
                           "Access-Control-Allow-Origin: %s\r\n", ext_resp->cors_config.origin);
    }
    
    if (ext_resp->cors_config.allow_credentials) {
        written += snprintf(temp_buffer + written, sizeof(temp_buffer) - written,
                           "Access-Control-Allow-Credentials: true\r\n");
    }
    
    written += snprintf(temp_buffer + written, sizeof(temp_buffer) - written,
                       "Access-Control-Allow-Methods: GET, POST, OPTIONS, HEAD, PUT, DELETE\r\n");
    
    written += snprintf(temp_buffer + written, sizeof(temp_buffer) - written,
                       "Access-Control-Allow-Headers: Origin, Accept, Content-Type, Authorization, X-Requested-With, Cache-Control, Pragma\r\n");
    
    written += snprintf(temp_buffer + written, sizeof(temp_buffer) - written,
                       "Cross-Origin-Resource-Policy: cross-origin\r\n");
    
    /* Copy to output buffer */
    strncpy(header_buffer, temp_buffer, buffer_size - 1);
    header_buffer[buffer_size - 1] = '\0';
}

/* Generate CSP headers */
void generate_csp_headers(extended_response_struct *ext_resp, 
                         const char *extension,
                         char *header_buffer, size_t buffer_size) {
    csp_policy_type_t csp_policy = extension_get_csp_policy(extension);
    const char *csp_value = anti_adblock_get_csp_policy(csp_policy, &ext_resp->adblock_seeds);
    
    if (csp_value) {
        snprintf(header_buffer, buffer_size, "Content-Security-Policy: %s\r\n", csp_value);
    } else {
        header_buffer[0] = '\0'; /* No CSP */
    }
}

/* Generate dynamic JS response */
void generate_dynamic_js_response(extended_response_struct *ext_resp) {
    anti_adblock_generate_js_content(&ext_resp->adblock_seeds, 
                                    ext_resp->content_buffer, 
                                    sizeof(ext_resp->content_buffer));
}

/* Generate dynamic CSS response */
void generate_dynamic_css_response(extended_response_struct *ext_resp) {
    anti_adblock_generate_css_content(&ext_resp->adblock_seeds, 
                                     ext_resp->content_buffer, 
                                     sizeof(ext_resp->content_buffer));
}

/* Generate dynamic JSON response */
void generate_dynamic_json_response(extended_response_struct *ext_resp) {
    anti_adblock_generate_json_content(&ext_resp->adblock_seeds, 
                                      ext_resp->content_buffer, 
                                      sizeof(ext_resp->content_buffer));
}

/* Generate dynamic XML response */
void generate_dynamic_xml_response(extended_response_struct *ext_resp) {
    anti_adblock_generate_xml_content(&ext_resp->adblock_seeds, 
                                     ext_resp->content_buffer, 
                                     sizeof(ext_resp->content_buffer));
}

/* Extended connection handler that wraps original conn_handler */
void* extended_conn_handler(void *ptr) {
    if (!extended_handler_initialized) {
        socket_handler_extended_init();
    }
    
    /* 
     * NOTE: This is a wrapper that would integrate with the existing
     * conn_handler function. The actual integration would require:
     * 
     * 1. Extracting request info before calling original handler
     * 2. Generating seeds and dynamic content
     * 3. Adding headers to the response
     * 4. Calling original conn_handler for the core logic
     * 
     * The existing conn_handler function remains COMPLETELY UNCHANGED.
     * This is just an extension layer.
     */
    
    /* Call original handler - EXISTING FUNCTION UNCHANGED */
    return conn_handler(ptr);
}
