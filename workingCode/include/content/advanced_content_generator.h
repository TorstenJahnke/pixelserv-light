/* advanced_content_generator.h */
#ifndef ADVANCED_CONTENT_GENERATOR_H
#define ADVANCED_CONTENT_GENERATOR_H

#include "content/anti_adblock.h"

/* Browser detection types */
typedef enum {
    BROWSER_CHROME,
    BROWSER_FIREFOX, 
    BROWSER_SAFARI,
    BROWSER_EDGE,
    BROWSER_OPERA,
    BROWSER_IE,
    BROWSER_MOBILE_CHROME,
    BROWSER_MOBILE_SAFARI,
    BROWSER_MOBILE_FIREFOX,
    BROWSER_ANDROID_WEBVIEW,
    BROWSER_SAMSUNG_BROWSER,
    BROWSER_UC_BROWSER,
    BROWSER_UNKNOWN
} browser_type_t;

/* Geographic regions */
typedef enum {
    REGION_EU,      /* Europe - GDPR */
    REGION_US,      /* United States - CCPA */
    REGION_UK,      /* United Kingdom - Brexit specific */
    REGION_DE,      /* Germany - strict privacy */
    REGION_CN,      /* China - special requirements */
    REGION_JP,      /* Japan */
    REGION_AU,      /* Australia */
    REGION_CA,      /* Canada */
    REGION_BR,      /* Brazil */
    REGION_IN,      /* India */
    REGION_RU,      /* Russia */
    REGION_UNKNOWN
} geographic_region_t;

/* Time periods for dynamic responses */
typedef enum {
    TIME_MORNING,    /* 06:00-09:00 */
    TIME_WORK,       /* 09:00-12:00 */
    TIME_LUNCH,      /* 12:00-14:00 */
    TIME_AFTERNOON,  /* 14:00-18:00 */
    TIME_EVENING,    /* 18:00-22:00 */
    TIME_NIGHT,      /* 22:00-06:00 */
    TIME_WEEKEND,    /* Saturday/Sunday */
    TIME_HOLIDAY     /* Special occasions */
} time_period_t;

/* Advanced content context */
typedef struct {
    browser_type_t browser;
    geographic_region_t region;
    time_period_t time_period;
    int is_mobile;
    int is_tablet;
    int is_bot;
    char detected_os[32];
    char browser_version[16];
} advanced_context_t;

/* Public functions */
void advanced_content_init(void);
void advanced_content_cleanup(void);

/* Detection functions */
browser_type_t detect_browser_from_ua(const char *user_agent);
geographic_region_t detect_region_from_ip(const char *ip_addr);
time_period_t get_current_time_period(void);

/* Advanced content generation */
void generate_browser_specific_js(browser_type_t browser, 
                                 const adblock_seed_t *seeds,
                                 char *buffer, size_t buffer_size);

void generate_regional_headers(geographic_region_t region,
                              char *header_buffer, size_t buffer_size);

void generate_time_based_content(time_period_t period,
                                const adblock_seed_t *seeds,
                                char *buffer, size_t buffer_size);

/* HTTP/2 and modern web features */
void generate_http2_headers(char *header_buffer, size_t buffer_size);
void generate_modern_web_headers(char *header_buffer, size_t buffer_size);
void generate_pwa_manifest_response(char *buffer, size_t buffer_size);

/* CDN/Library responses */
void generate_cdn_library_response(const char *url_path,
                                  char *buffer, size_t buffer_size);

#endif /* ADVANCED_CONTENT_GENERATOR_H */
