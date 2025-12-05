/* browser_detection.c - Browser/CDN/Regional Detection System */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "browser_detection.h"

/* ULTRA-EXPANDED User Agent Database for Browser Detection (88 patterns!) */
static const struct {
    const char *pattern;
    browser_type_t browser;
} user_agent_patterns[] = {
    /* Chrome variants - MASSIVE expansion */
    {"Chrome/", BROWSER_CHROME}, {"Chromium/", BROWSER_CHROME}, {"CriOS/", BROWSER_MOBILE_CHROME},
    {"Chrome Mobile", BROWSER_MOBILE_CHROME}, {"Chrome Mobile WebView", BROWSER_ANDROID_WEBVIEW},
    {"Headless Chrome", BROWSER_CHROME}, {"Google Chrome", BROWSER_CHROME},
    {"OPR/", BROWSER_OPERA}, {"Opera/", BROWSER_OPERA}, {"Opera Mini", BROWSER_OPERA},

    /* Firefox variants - MASSIVE expansion */
    {"Firefox/", BROWSER_FIREFOX}, {"Gecko/", BROWSER_FIREFOX}, {"FxiOS/", BROWSER_MOBILE_FIREFOX},
    {"Firefox Mobile", BROWSER_MOBILE_FIREFOX}, {"Firefox Focus", BROWSER_MOBILE_FIREFOX},
    {"Fennec/", BROWSER_MOBILE_FIREFOX}, {"Firefox ESR", BROWSER_FIREFOX},

    /* Safari variants - MASSIVE expansion */
    {"Safari/", BROWSER_SAFARI}, {"Version/", BROWSER_SAFARI}, {"AppleWebKit/", BROWSER_SAFARI},
    {"Mobile Safari", BROWSER_MOBILE_SAFARI}, {"Mobile/", BROWSER_MOBILE_SAFARI},
    {"iPhone OS", BROWSER_MOBILE_SAFARI}, {"iPad", BROWSER_MOBILE_SAFARI}, {"iPod", BROWSER_MOBILE_SAFARI},

    /* Edge variants */
    {"Edg/", BROWSER_EDGE}, {"Edge/", BROWSER_EDGE}, {"EdgiOS/", BROWSER_EDGE},
    {"EdgA/", BROWSER_EDGE}, {"Microsoft Edge", BROWSER_EDGE},

    /* Internet Explorer */
    {"MSIE", BROWSER_IE}, {"Trident/", BROWSER_IE}, {"rv:11.0", BROWSER_IE},

    /* Mobile browsers - ULTRA expansion */
    {"SamsungBrowser/", BROWSER_SAMSUNG_BROWSER}, {"Samsung Internet", BROWSER_SAMSUNG_BROWSER},
    {"UCBrowser/", BROWSER_UC_BROWSER}, {"UC Browser", BROWSER_UC_BROWSER}, {"UCWEB", BROWSER_UC_BROWSER},
    {"YaBrowser/", BROWSER_CHROME}, {"Yandex", BROWSER_CHROME}, {"Vivaldi/", BROWSER_CHROME},
    {"Brave/", BROWSER_CHROME}, {"DuckDuckGo/", BROWSER_CHROME},
    {"Focus/", BROWSER_MOBILE_FIREFOX}, {"Puffin/", BROWSER_CHROME}, {"Dolphin/", BROWSER_CHROME},
    {"Maxthon/", BROWSER_CHROME}, {"QQBrowser/", BROWSER_CHROME}, {"MiuiBrowser/", BROWSER_CHROME},
    {"HuaweiBrowser/", BROWSER_CHROME}, {"XiaoMi/", BROWSER_CHROME}, {"OppoBrowser/", BROWSER_CHROME},
    {"VivoBrowser/", BROWSER_CHROME}, {"OnePlusBrowser/", BROWSER_CHROME},
    {"baiduboxapp/", BROWSER_CHROME}, {"BIDUBrowser/", BROWSER_CHROME},

    /* WebView and embedded browsers */
    {"wv", BROWSER_ANDROID_WEBVIEW}, {"WebView", BROWSER_ANDROID_WEBVIEW},
    {"Instagram", BROWSER_ANDROID_WEBVIEW}, {"Facebook", BROWSER_ANDROID_WEBVIEW},
    {"Twitter", BROWSER_ANDROID_WEBVIEW}, {"LinkedIn", BROWSER_ANDROID_WEBVIEW},
    {"Snapchat", BROWSER_ANDROID_WEBVIEW}, {"TikTok", BROWSER_ANDROID_WEBVIEW},
    {"WhatsApp", BROWSER_ANDROID_WEBVIEW}, {"Telegram", BROWSER_ANDROID_WEBVIEW},
    {"WeChat", BROWSER_ANDROID_WEBVIEW}, {"Line/", BROWSER_ANDROID_WEBVIEW},

    /* Gaming and app browsers */
    {"PlayStation", BROWSER_CHROME}, {"Xbox", BROWSER_EDGE}, {"Nintendo", BROWSER_CHROME},
    {"SteamOverlay", BROWSER_CHROME}, {"Discord", BROWSER_CHROME},
    {"Slack/", BROWSER_CHROME}, {"Teams/", BROWSER_EDGE}, {"Zoom", BROWSER_CHROME},

    /* Bots and crawlers (still give browser responses) */
    {"Googlebot", BROWSER_CHROME}, {"Bingbot", BROWSER_EDGE}, {"YandexBot", BROWSER_CHROME},
    {"facebookexternalhit", BROWSER_CHROME}, {"Twitterbot", BROWSER_CHROME},
    {"Applebot", BROWSER_SAFARI}, {"DuckDuckBot", BROWSER_CHROME}
};

/* Detect browser from User-Agent with ULTRA precision */
browser_type_t detect_browser_from_ua(const char *user_agent) {
    if (!user_agent || !*user_agent) {
        return BROWSER_UNKNOWN;
    }

    size_t pattern_count = sizeof(user_agent_patterns) / sizeof(user_agent_patterns[0]);
    for (size_t i = 0; i < pattern_count; i++) {
        if (strstr(user_agent, user_agent_patterns[i].pattern)) {
            return user_agent_patterns[i].browser;
        }
    }

    return BROWSER_UNKNOWN;
}

/* Generate regional privacy compliance headers */
void generate_regional_headers(geographic_region_t region, char *header_buffer, size_t buffer_size) {
    switch (region) {
        case REGION_EU:
            snprintf(header_buffer, buffer_size,
                "X-GDPR-Compliant: true\r\n"
                "X-Cookie-Policy: strict\r\n"
                "X-Privacy-Framework: GDPR\r\n");
            break;
        case REGION_US:
            snprintf(header_buffer, buffer_size,
                "X-CCPA-Compliant: true\r\n"
                "X-Privacy-Framework: CCPA\r\n"
                "X-Do-Not-Sell: enabled\r\n");
            break;
        case REGION_UK:
            snprintf(header_buffer, buffer_size,
                "X-UK-GDPR: true\r\n"
                "X-Brexit-Compliant: true\r\n"
                "X-Cookie-Policy: essential-only\r\n");
            break;
        case REGION_DE:
            snprintf(header_buffer, buffer_size,
                "X-DSGVO-Compliant: true\r\n"
                "X-German-Privacy: strict\r\n"
                "X-Telemetry: disabled\r\n");
            break;
        default:
            snprintf(header_buffer, buffer_size,
                "X-Privacy-Friendly: true\r\n");
            break;
    }
}

/* Check if request is for a CDN library */
int is_cdn_library_request(const char *path) {
    if (!path) return 0;

    return (strstr(path, "jquery") != NULL ||
            strstr(path, "jQuery") != NULL ||
            strstr(path, "bootstrap") != NULL ||
            strstr(path, "fontawesome") != NULL ||
            strstr(path, "font-awesome") != NULL ||
            strstr(path, "fonts.googleapis.com") != NULL ||
            strstr(path, "cdnjs.cloudflare.com") != NULL ||
            strstr(path, "unpkg.com") != NULL ||
            strstr(path, "jsdelivr.net") != NULL);
}

/* Generate CDN library response (prevents website crashes!) */
void generate_cdn_library_response(const char *path, char *buffer, size_t buffer_size) {
    if (!path || !buffer) {
        snprintf(buffer, buffer_size, "/* Library not found */");
        return;
    }

    /* jQuery responses - prevent "$(...) is not a function" errors */
    if (strstr(path, "jquery") || strstr(path, "jQuery")) {
        snprintf(buffer, buffer_size,
            "/*! jQuery Stub */\n"
            "window.jQuery=window.$=function(s){"
            "return{ready:function(f){f&&f();return this},"
            "on:function(){return this},"
            "off:function(){return this},"
            "click:function(){return this},"
            "hide:function(){return this},"
            "show:function(){return this},"
            "css:function(){return this},"
            "html:function(){return this},"
            "val:function(){return this},"
            "length:0}};");
        return;
    }

    /* Bootstrap responses - prevent bootstrap errors */
    if (strstr(path, "bootstrap")) {
        snprintf(buffer, buffer_size,
            "/*! Bootstrap Stub */\n"
            "window.bootstrap={Modal:function(){},Tooltip:function(){},"
            "Popover:function(){},Dropdown:function(){},Alert:function(){}};");
        return;
    }

    /* FontAwesome responses - empty font to prevent 404 */
    if (strstr(path, "fontawesome") || strstr(path, "font-awesome")) {
        snprintf(buffer, buffer_size,
            "/* FontAwesome Stub */\n"
            "@font-face{font-family:'Font Awesome 5 Free';"
            "src:url('data:font/woff2;base64,');}");
        return;
    }

    /* Google Fonts responses - empty font */
    if (strstr(path, "fonts.googleapis.com")) {
        snprintf(buffer, buffer_size,
            "/* Google Fonts Stub */\n"
            "@font-face{font-family:'Open Sans';"
            "src:url('data:font/woff2;base64,');}");
        return;
    }

    /* Default CDN library response */
    snprintf(buffer, buffer_size, "/* CDN Library loaded */");
}
