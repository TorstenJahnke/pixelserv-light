/* browser_detection.h */
#ifndef BROWSER_DETECTION_H
#define BROWSER_DETECTION_H

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

/* Public functions */
browser_type_t detect_browser_from_ua(const char *user_agent);
void generate_regional_headers(geographic_region_t region, char *header_buffer, size_t buffer_size);
int is_cdn_library_request(const char *path);
void generate_cdn_library_response(const char *path, char *buffer, size_t buffer_size);

#endif /* BROWSER_DETECTION_H */
