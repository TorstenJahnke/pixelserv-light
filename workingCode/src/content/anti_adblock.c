/* anti_adblock.c */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include "content/anti_adblock.h"
#include "content/extension_lookup.h"

/* CSP Policy strings for different content types */
const char* CSP_POLICIES[] = {
    [CSP_STRICT] = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'",
    [CSP_IMAGES] = "default-src 'none'; img-src *",
    [CSP_HTML] = "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'",
    [CSP_MEDIA] = "default-src 'none'; media-src *",
    [CSP_DOCUMENTS] = "default-src 'self'",
    [CSP_STYLESHEETS] = "default-src 'none'; style-src 'unsafe-inline'",
    [CSP_NONE] = NULL
};

/* Server names for rotation - MASSIVE EXPANSION for AdBlock prevention */
static const char* SERVER_NAMES[] = {
    "nginx/1.18.0", "nginx/1.20.2", "nginx/1.22.1", "nginx/1.24.0", "nginx/1.25.1", "nginx/1.25.2", "nginx/1.25.3",
    "Apache/2.4.52", "Apache/2.4.54", "Apache/2.4.56", "Apache/2.4.57", "Apache/2.4.58", "Apache/2.4.59", "Apache/2.4.60",
    "cloudflare", "cloudflare-nginx", "openresty/1.21.4.1", "openresty/1.21.4.2", "openresty/1.21.4.3", "openresty/1.23.0.1",
    "LiteSpeed", "LiteSpeed/6.1", "LiteSpeed/6.2", "Microsoft-IIS/10.0", "Microsoft-IIS/8.5", "Microsoft-IIS/8.0",
    "Caddy", "Caddy/2.7.6", "Caddy/2.7.5", "Traefik", "Traefik/3.0", "Traefik/2.10", "HAProxy", "HAProxy/2.8",
    "nginx", "Apache", "Microsoft-HTTPAPI/2.0", "Kestrel", "Express", "Node.js", "Gunicorn", "uWSGI",
    "Jetty", "Jetty/9.4", "Jetty/10.0", "Jetty/11.0", "Tomcat", "Tomcat/9.0", "Tomcat/10.1", "Undertow",
    "Varnish", "Varnish/7.4", "Varnish/7.3", "squid", "squid/5.7", "AmazonS3", "AmazonCloudFront",
    "Google Frontend", "Google", "gws", "sffe", "ESF", "BigIP", "F5 BIG-IP", "Citrix-NetScaler",
    "AkamaiGHost", "Akamai", "Fastly", "KeyCDN", "MaxCDN", "StackPath", "BunnyCDN", "JSDelivr",
    "GitHub.com", "GitLab", "Bitbucket", "DigitalOcean", "Linode", "Vultr", "Hetzner", "OVH",
    "Vercel", "Netlify", "Heroku", "Railway", "Render", "Fly.io", "Deno Deploy", "Workers",
    "php", "php/8.2", "php/8.1", "php/8.0", "php/7.4", "gunicorn/20.1.0", "Passenger/6.0",
    "IIS", "IIS/10", "IIS/8", "Lighttpd", "lighttpd/1.4", "Cherokee", "Monkey", "H2O", "Hiawatha",
    "Tengine", "Tengine/2.3", "OpenLiteSpeed", "Zeus", "Oracle-HTTP-Server", "IBM_HTTP_Server",
    "Sun-Java-System", "WebLogic", "WebSphere", "JBoss", "GlassFish", "WildFly", "Payara",
    "Cloudflare-Workers", "AWS-ALB", "AWS-ELB", "Azure-Front-Door", "Google-Cloud-Load-Balancer"
};
#define SERVER_NAMES_COUNT (sizeof(SERVER_NAMES) / sizeof(SERVER_NAMES[0]))

/* Cache status names for rotation - EXPANDED */
static const char* CACHE_STATUSES[] = {
    "HIT", "MISS", "BYPASS", "EXPIRED", "UPDATING", "STALE", "REVALIDATED", "DYNAMIC",
    "CACHE_HIT", "CACHE_MISS", "TCP_HIT", "TCP_MISS", "TCP_DENIED", "TCP_REFRESH_HIT",
    "UDP_HIT", "UDP_MISS", "UDP_DENIED", "ICP_HIT", "ICP_MISS", "SIBLING_HIT",
    "PARENT_HIT", "DEFAULT_PARENT", "SINGLE_PARENT", "FIRST_UP_PARENT", "NO_CACHE",
    "CONFIG_ERROR", "ABORTED", "TIMEOUT", "SWAPFAIL", "DENIED", "ALLOWED",
    "HIT-STALE", "MISS-FRESH", "HIT-FRESH", "MISS-STALE", "BYPASS-CACHE", "ORIGIN-HIT",
    "EDGE-HIT", "REGIONAL-HIT", "POP-HIT", "SHIELD-HIT", "PREFETCH-HIT", "WARMING",
    "PURGED", "REFRESH", "VALIDATED", "PARTIAL", "RANGE", "COMPRESSED", "DECOMPRESSED"
};
#define CACHE_STATUSES_COUNT (sizeof(CACHE_STATUSES) / sizeof(CACHE_STATUSES[0]))

/* Vary headers for rotation - MASSIVE EXPANSION */
static const char* VARY_HEADERS[] = {
    "Accept-Encoding", "User-Agent", "Accept-Encoding, User-Agent", "Origin", "Accept-Encoding, Origin", "Accept-Language",
    "Accept", "Accept-Charset", "Accept-Datetime", "Accept-Language, Accept-Encoding", "Authorization", "Cache-Control",
    "Connection", "Content-Language", "Content-Length", "Content-Type", "Cookie", "Date", "Expect", "Host",
    "If-Match", "If-Modified-Since", "If-None-Match", "If-Range", "If-Unmodified-Since", "Max-Forwards", "Pragma",
    "Proxy-Authorization", "Range", "Referer", "TE", "Upgrade", "Via", "Warning", "X-Requested-With",
    "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP", "X-Original-URL", "X-Rewrite-URL",
    "X-Forwarded-Server", "X-Forwarded-Port", "X-Scheme", "Front-End-Https", "X-Url-Scheme", "X-HTTP-Method-Override",
    "Accept-Encoding, Accept-Language", "User-Agent, Accept-Language", "Origin, Referer", "Cookie, User-Agent",
    "Authorization, User-Agent", "Accept, User-Agent", "Content-Type, Accept", "Range, User-Agent",
    "X-Requested-With, Origin", "Cache-Control, Pragma", "If-None-Match, If-Modified-Since", "Accept-Language, Cookie",
    "Upgrade-Insecure-Requests", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest",
    "Sec-CH-UA", "Sec-CH-UA-Mobile", "Sec-CH-UA-Platform", "DNT", "X-Do-Not-Track", "Save-Data",
    "Viewport-Width", "Width", "Device-Memory", "RTT", "Downlink", "ECT", "Early-Data",
    "CloudFront-Viewer-Country", "CloudFront-Is-Mobile-Viewer", "CloudFront-Is-Tablet-Viewer", "CF-IPCountry", "CF-Ray",
    "X-Edge-Request-ID", "X-Azure-Ref", "X-Cache-Key", "X-Served-By", "X-Timer", "X-Varnish"
};
#define VARY_HEADERS_COUNT (sizeof(VARY_HEADERS) / sizeof(VARY_HEADERS[0]))

/* CF-RAY locations - GLOBAL EXPANSION */
static const char* CF_LOCATIONS[] = {
    "FRA", "CDG", "AMS", "LHR", "DUB", "MAD", "MUC", "ZUR", "VIE", "PRG", "WAW", "BUD", "OTP", "SOF", "ATH",
    "LAX", "SFO", "SEA", "DFW", "ORD", "JFK", "IAD", "ATL", "MIA", "DEN", "PHX", "LAS", "SJC", "PDX", "MSP",
    "YYZ", "YVR", "YUL", "GRU", "SCL", "BOG", "LIM", "UIO", "CCS", "PTY", "SJO", "MEX", "MTY", "GDL",
    "NRT", "KIX", "ICN", "TPE", "HKG", "SIN", "KUL", "BKK", "CGK", "MNL", "SYD", "MEL", "BNE", "PER", "AKL",
    "BOM", "DEL", "BLR", "MAA", "HYD", "CCU", "CMB", "DAC", "KTM", "ISB", "KHI", "LHE", "TAS", "BAH", "DOH",
    "DXB", "AUH", "KWI", "RUH", "JED", "AMM", "BGW", "EVN", "TBS", "BAK", "ASB", "DUS", "TXL", "HAM", "STR",
    "CPH", "ARN", "OSL", "HEL", "TLL", "RIX", "VNO", "GDN", "KRK", "BTS", "LJU", "ZAG", "BEG", "SKP", "TIA",
    "CAI", "ALG", "TUN", "CMN", "CAS", "LOS", "ACC", "DKR", "NBO", "ADD", "DAR", "JNB", "CPT", "DUR", "PLZ",
    "LED", "SVO", "VKO", "KZN", "ROV", "UFA", "KUF", "SVX", "NOZ", "KEJ", "OVB", "KJA", "IKT", "YKS", "VVO",
    "PEK", "PVG", "CAN", "SZX", "CTU", "WUH", "XIY", "CGO", "TNA", "TSN", "NKG", "HGH", "FOC", "XMN", "KMG"
};
#define CF_LOCATIONS_COUNT (sizeof(CF_LOCATIONS) / sizeof(CF_LOCATIONS[0]))

/* Simple hash function for strings */
static uint32_t simple_hash(const char *str) {
    uint32_t hash = 5381;
    int c;
    
    if (!str) return hash;
    
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    
    return hash;
}

/* Initialize anti-adblock system */
void anti_adblock_init(void) {
    /* Seed random number generator */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    srand(tv.tv_usec);
}

/* Cleanup anti-adblock system */
void anti_adblock_cleanup(void) {
    /* Nothing to cleanup */
}

/* Generate randomization seeds (like PHP script) */
adblock_seed_t anti_adblock_generate_seeds(const char *request_uri, 
                                          const char *user_agent, 
                                          const char *remote_addr) {
    adblock_seed_t seeds;
    struct timeval tv;
    
    gettimeofday(&tv, NULL);
    
    /* Time-based seed */
    seeds.time_seed = simple_hash((char*)&tv.tv_sec) ^ tv.tv_usec;
    
    /* Request-based seed */
    uint32_t req_hash = simple_hash(request_uri ? request_uri : "");
    req_hash ^= simple_hash(user_agent ? user_agent : "");
    req_hash ^= simple_hash(remote_addr ? remote_addr : "");
    seeds.request_seed = req_hash;
    
    /* Content seed (combines time + request) */
    seeds.content_seed = seeds.time_seed ^ seeds.request_seed;
    
    /* Crypto seed (final hash) */
    seeds.crypto_seed = simple_hash((char*)&seeds.content_seed) & 0xFFFFFF;
    
    return seeds;
}

/* Generate dynamic headers for server mimicking */
void anti_adblock_generate_headers(const adblock_seed_t *seeds, 
                                  dynamic_headers_t *headers) {
    /* Server rotation */
    const char *server = SERVER_NAMES[seeds->crypto_seed % SERVER_NAMES_COUNT];
    strncpy(headers->server_header, server, sizeof(headers->server_header) - 1);
    headers->server_header[sizeof(headers->server_header) - 1] = '\0';
    
    /* CF-RAY generation (like PHP script) */
    const char *location = CF_LOCATIONS[seeds->crypto_seed % CF_LOCATIONS_COUNT];
    snprintf(headers->cf_ray, sizeof(headers->cf_ray), "%08x-%s", 
             seeds->content_seed & 0xFFFFFF, location);
    
    /* Cache status rotation */
    const char *cache_status = CACHE_STATUSES[seeds->crypto_seed % CACHE_STATUSES_COUNT];
    strncpy(headers->cache_status, cache_status, sizeof(headers->cache_status) - 1);
    headers->cache_status[sizeof(headers->cache_status) - 1] = '\0';
    
    /* Vary headers rotation */
    const char *vary = VARY_HEADERS[(seeds->crypto_seed >> 8) % VARY_HEADERS_COUNT];
    strncpy(headers->vary_header, vary, sizeof(headers->vary_header) - 1);
    headers->vary_header[sizeof(headers->vary_header) - 1] = '\0';
    
    /* Random ETag (33% chance like PHP script) */
    if ((seeds->crypto_seed % 3) == 0) {
        if (seeds->crypto_seed % 2) {
            snprintf(headers->etag, sizeof(headers->etag), "\"%08x\"", 
                     seeds->content_seed & 0xFFFF);
        } else {
            snprintf(headers->etag, sizeof(headers->etag), "W/\"%06x\"", 
                     (seeds->content_seed >> 16) & 0xFFF);
        }
        headers->has_etag = 1;
    } else {
        headers->has_etag = 0;
    }
}

/* Generate CORS headers (origin-adaptive like PHP script) */
void anti_adblock_generate_cors(const char *origin, cors_config_t *cors) {
    cors->has_origin = 0;
    cors->allow_credentials = 0;

    if (origin && *origin != '\0') {
        strncpy(cors->origin, origin, sizeof(cors->origin) - 1);
        cors->origin[sizeof(cors->origin) - 1] = '\0';
        cors->has_origin = 1;
        cors->allow_credentials = 1;  /* Like PHP script */
    } else {
        strcpy(cors->origin, "*");
        cors->has_origin = 1;
        cors->allow_credentials = 0;
    }
}

/* v2: Probabilistic CORS decision - mimics real server behavior
 * 70% chance to send CORS, 30% chance to send nothing
 * This creates unpredictable pattern that looks like real servers
 */
int anti_adblock_should_send_cors(const adblock_seed_t *seeds) {
    if (!seeds) return 0;
    return (seeds->crypto_seed % 100) < 70;
}

/* v2: Generate randomized CORS header (anti-fingerprinting)
 * Randomizes: whether to send CORS, wildcard vs specific origin, credentials
 */
void anti_adblock_generate_random_cors(const adblock_seed_t *seeds,
                                       const char *origin_header,
                                       char *cors_header_buffer,
                                       size_t buffer_size) {
    if (!seeds || !cors_header_buffer || buffer_size == 0) return;

    cors_header_buffer[0] = '\0';  /* Default: empty */

    /* Decision 1: Should we send CORS at all? */
    if (!anti_adblock_should_send_cors(seeds)) {
        return;  /* 30% of time: No CORS header */
    }

    /* Decision 2: Wildcard (*) or specific origin? */
    int use_wildcard = 0;

    if (!origin_header || *origin_header == '\0') {
        use_wildcard = 1;  /* No origin provided = wildcard */
    } else {
        /* Use request_seed bit pattern for decision: 50% wildcard, 50% specific */
        use_wildcard = (seeds->request_seed & 0x01);
    }

    /* Decision 3: Include credentials? (varies per request) */
    int allow_credentials = (seeds->content_seed & 0x02) ? 1 : 0;

    /* Build CORS header based on decisions */
    if (use_wildcard) {
        /* Simple wildcard (can't have credentials with wildcard) */
        snprintf(cors_header_buffer, buffer_size,
            "Access-Control-Allow-Origin: *\r\n"
            "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
            "Access-Control-Allow-Headers: Content-Type, Authorization\r\n");
    } else {
        /* Echo back specific origin */
        if (allow_credentials) {
            snprintf(cors_header_buffer, buffer_size,
                "Access-Control-Allow-Origin: %s\r\n"
                "Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE\r\n"
                "Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With\r\n"
                "Access-Control-Allow-Credentials: true\r\n"
                "Access-Control-Max-Age: 86400\r\n",
                origin_header);
        } else {
            snprintf(cors_header_buffer, buffer_size,
                "Access-Control-Allow-Origin: %s\r\n"
                "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                "Access-Control-Allow-Headers: Content-Type\r\n",
                origin_header);
        }
    }
}

/* Get CSP policy for content type */
const char* anti_adblock_get_csp_policy(csp_policy_type_t policy_type, 
                                       const adblock_seed_t *seeds) {
    if (policy_type >= 0 && (size_t)policy_type < (sizeof(CSP_POLICIES) / sizeof(CSP_POLICIES[0]))) {
        return CSP_POLICIES[policy_type];
    }
    return CSP_POLICIES[CSP_NONE];
}

/* Generate randomized JS content (AdBlock prevention) - MASSIVE EXPANSION */
void anti_adblock_generate_js_content(const adblock_seed_t *seeds, 
                                     char *buffer, size_t buffer_size) {
    /* JS variants - ULTRA EXPANDED for maximum AdBlock evasion */
    const char* js_variants[] = {
        "void 0;", "!0;", "!1;", "var _a=0;", "var _b=1;", "var _c=2;", "var _d=3;", "var _e=4;", "var _f=5;",
        "(function(){return 0})();", "(function(){return 1})();", "(function(){return false})();", "(function(){return true})();",
        "window._x||0;", "window._y||1;", "window._z||false;", "window._w||true;", "window._r||null;", "window._s||undefined;",
        "\"randomstr\";", "\"abcd1234\";", "\"xyz789\";", "\"test123\";", "\"data456\";", "\"info789\";", "\"content\";",
        "typeof window!==\"undefined\"&&window;", "typeof document!==\"undefined\"&&document;", "typeof navigator!==\"undefined\"&&navigator;",
        "document&&document.readyState;", "document&&document.documentElement;", "document&&document.body;", "document&&document.head;",
        "({}&&[]);", "([]&&{});", "({a:1}&&[1,2]);", "([1]&&{b:2});", "({x:true}&&[false]);",
        "Math.random();", "Math.floor(Math.random()*10);", "Math.ceil(Math.random()*100);", "Math.round(Math.PI);",
        "undefined;", "null;", "NaN;", "Infinity;", "-Infinity;", "0;", "1;", "-1;", "42;", "3.14159;",
        "({});", "[];", "{a:1};", "[1,2,3];", "{x:true,y:false};", "[null,undefined];", "{};", "Object.create(null);",
        "true;", "false;", "!true;", "!false;", "!!true;", "!!false;", "Boolean(1);", "Boolean(0);",
        "const c=0;", "const d=1;", "let e=2;", "var f=3;", "const PI=3.14;", "let name=\"test\";",
        "!function(){}();", "+function(){}();", "-function(){}();", "~function(){}();", "void function(){}();",
        "window.void;", "document.void;", "navigator.void;", "console.void;", "location.void;", "history.void;",
        "var a1;", "var a2;", "var a3;", "let b1;", "let b2;", "const c1=1;", "const c2=2;",
        "(function(){var x=1})();", "(function(){var y=2})();", "(function(){let z=3})();", "(function(){const w=4})();",
        "setTimeout(function(){},0);", "setTimeout(function(){},1);", "setTimeout(function(){},10);", "setTimeout(function(){},100);",
        "setInterval(function(){},1000);", "setInterval(function(){},2000);", "setInterval(function(){},5000);",
        "window[\"test\"]||0;", "window[\"data\"]||1;", "window[\"info\"]||false;", "window[\"value\"]||null;",
        "console&&console.log;", "console&&console.warn;", "console&&console.error;", "console&&console.info;",
        "JSON&&JSON.parse;", "JSON&&JSON.stringify;", "Array&&Array.isArray;", "Object&&Object.keys;",
        "String.prototype.charAt;", "Array.prototype.push;", "Object.prototype.toString;", "Function.prototype.call;",
        "Date.now();", "new Date().getTime();", "performance&&performance.now();", "+new Date();",
        "location&&location.href;", "location&&location.host;", "location&&location.pathname;", "location&&location.search;",
        "navigator&&navigator.userAgent;", "navigator&&navigator.platform;", "navigator&&navigator.language;",
        "screen&&screen.width;", "screen&&screen.height;", "screen&&screen.availWidth;", "screen&&screen.colorDepth;",
        "document&&document.cookie;", "document&&document.referrer;", "document&&document.title;", "document&&document.URL;",
        "window.devicePixelRatio||1;", "window.innerWidth||0;", "window.innerHeight||0;", "window.outerWidth||0;",
        "localStorage&&localStorage.length;", "sessionStorage&&sessionStorage.length;", "indexedDB&&indexedDB.cmp;",
        "WebSocket&&WebSocket.CONNECTING;", "XMLHttpRequest&&XMLHttpRequest.DONE;", "fetch&&fetch.name;",
        "Promise&&Promise.resolve();", "Promise&&Promise.reject();", "async function(){};", "function*(){};",
        "Symbol&&Symbol.iterator;", "Symbol&&Symbol.toStringTag;", "Proxy&&Proxy.revocable;", "Reflect&&Reflect.has;",
        "Map&&new Map();", "Set&&new Set();", "WeakMap&&new WeakMap();", "WeakSet&&new WeakSet();",
        "Int8Array&&new Int8Array();", "Uint8Array&&new Uint8Array();", "Float32Array&&new Float32Array();",
        "ArrayBuffer&&new ArrayBuffer(0);", "DataView&&DataView.prototype;", "SharedArrayBuffer&&SharedArrayBuffer.name;",
        "Worker&&Worker.prototype;", "ServiceWorker&&ServiceWorker.prototype;", "MessageChannel&&MessageChannel.prototype;",
        "document.createElement&&document.createElement('div');", "document.createTextNode&&document.createTextNode('');",
        "Element&&Element.prototype.setAttribute;", "Node&&Node.prototype.appendChild;", "Event&&Event.prototype.preventDefault;",
        "CustomEvent&&new CustomEvent('test');", "MutationObserver&&MutationObserver.prototype;", "IntersectionObserver&&IntersectionObserver.name;"
    };
    
    int variant_count = sizeof(js_variants) / sizeof(js_variants[0]);
    int selected = seeds->content_seed % variant_count;
    
    strncpy(buffer, js_variants[selected], buffer_size - 1);
    buffer[buffer_size - 1] = '\0';
}

/* Generate randomized CSS content (AdBlock prevention) - MASSIVE EXPANSION */
void anti_adblock_generate_css_content(const adblock_seed_t *seeds, 
                                      char *buffer, size_t buffer_size) {
    /* CSS variants - ULTRA EXPANDED for maximum AdBlock evasion */
    const char* css_variants[] = {
        "*{margin:0}", "*{padding:0}", "*{border:0}", "*{outline:0}", "*{font-size:100%}", "*{vertical-align:baseline}",
        "body{margin:0}", "body{padding:0}", "body{font-family:Arial}", "body{line-height:1}", "body{color:#000}", "body{background:#fff}",
        "html{margin:0}", "html{padding:0}", "html{font-size:16px}", "html{box-sizing:border-box}", "html{height:100%}",
        "div{display:block}", "div{margin:0}", "div{padding:0}", "div{border:none}", "div{background:transparent}",
        "span{display:inline}", "span{margin:0}", "span{padding:0}", "span{border:none}", "span{background:none}",
        "p{margin:0}", "p{padding:0}", "p{line-height:1.2}", "p{font-size:14px}", "p{color:inherit}",
        "a{text-decoration:none}", "a{color:inherit}", "a{border:none}", "a{outline:none}", "a{background:none}",
        "img{border:0}", "img{outline:0}", "img{max-width:100%}", "img{height:auto}", "img{display:block}",
        "h1{margin:0}", "h1{padding:0}", "h1{font-size:2em}", "h1{font-weight:bold}", "h1{line-height:1.2}",
        "h2{margin:0}", "h2{padding:0}", "h2{font-size:1.5em}", "h2{font-weight:bold}", "h2{line-height:1.3}",
        "h3{margin:0}", "h3{padding:0}", "h3{font-size:1.2em}", "h3{font-weight:bold}", "h3{line-height:1.4}",
        "ul{margin:0}", "ul{padding:0}", "ul{list-style:none}", "ul{display:block}", "ul{overflow:hidden}",
        "li{margin:0}", "li{padding:0}", "li{list-style:none}", "li{display:list-item}", "li{line-height:1.5}",
        "table{border-collapse:collapse}", "table{border-spacing:0}", "table{width:100%}", "table{margin:0}",
        "tr{margin:0}", "tr{padding:0}", "tr{border:none}", "tr{background:transparent}", "tr{vertical-align:top}",
        "td{margin:0}", "td{padding:0}", "td{border:none}", "td{vertical-align:top}", "td{text-align:left}",
        "th{margin:0}", "th{padding:0}", "th{border:none}", "th{font-weight:bold}", "th{text-align:left}",
        "form{margin:0}", "form{padding:0}", "form{border:none}", "form{display:block}", "form{background:none}",
        "input{margin:0}", "input{padding:0}", "input{border:1px solid #ccc}", "input{font-family:inherit}", "input{font-size:inherit}",
        "button{margin:0}", "button{padding:0}", "button{border:none}", "button{background:none}", "button{cursor:pointer}",
        "textarea{margin:0}", "textarea{padding:0}", "textarea{border:1px solid #ccc}", "textarea{font-family:inherit}",
        "select{margin:0}", "select{padding:0}", "select{border:1px solid #ccc}", "select{font-family:inherit}",
        ".a{display:block}", ".a{margin:0}", ".a{padding:0}", ".a{color:red}", ".a{background:blue}", ".a{width:100%}",
        ".b{display:inline}", ".b{margin:1px}", ".b{padding:1px}", ".b{color:blue}", ".b{background:red}",
        ".c{display:none}", ".c{visibility:hidden}", ".c{opacity:0}", ".c{position:absolute}", ".c{left:-9999px}",
        ".d{float:left}", ".d{float:right}", ".d{clear:both}", ".d{overflow:hidden}", ".d{zoom:1}",
        "#a{color:red}", "#a{background:blue}", "#a{margin:auto}", "#a{text-align:center}", "#a{position:relative}",
        "#b{color:blue}", "#b{background:red}", "#b{width:50%}", "#b{height:auto}", "#b{display:flex}",
        "#c{color:green}", "#c{background:yellow}", "#c{border:1px solid}", "#c{padding:10px}", "#c{margin:5px}",
        "@media(){}", "@media(max-width:768px){}", "@media(min-width:1024px){}", "@media screen{}", "@media print{}",
        "@media(orientation:portrait){}", "@media(orientation:landscape){}", "@media(device-width:320px){}",
        ":root{}", ":root{--color:red}", ":root{--size:16px}", ":root{--font:'Arial'}", ":root{--margin:0}",
        ":before{content:''}", ":after{content:''}", ":hover{color:red}", ":focus{outline:none}", ":active{color:blue}",
        ":first-child{margin-top:0}", ":last-child{margin-bottom:0}", ":nth-child(2n){background:#f0f0f0}",
        ".container{max-width:1200px}", ".wrapper{width:100%}", ".content{padding:20px}", ".header{height:60px}",
        ".footer{clear:both}", ".sidebar{width:25%}", ".main{width:75%}", ".nav{list-style:none}",
        ".btn{display:inline-block}", ".card{border:1px solid #ddd}", ".modal{display:none}", ".overlay{position:fixed}",
        ".grid{display:grid}", ".flex{display:flex}", ".inline{display:inline}", ".block{display:block}",
        ".hidden{display:none}", ".visible{visibility:visible}", ".transparent{opacity:0}", ".opaque{opacity:1}",
        ".left{float:left}", ".right{float:right}", ".center{text-align:center}", ".justify{text-align:justify}",
        ".bold{font-weight:bold}", ".italic{font-style:italic}", ".underline{text-decoration:underline}",
        ".uppercase{text-transform:uppercase}", ".lowercase{text-transform:lowercase}", ".capitalize{text-transform:capitalize}",
        ".rounded{border-radius:5px}", ".circle{border-radius:50%}", ".shadow{box-shadow:0 2px 4px rgba(0,0,0,0.1)}",
        ".gradient{background:linear-gradient(to bottom,#fff,#000)}", ".transition{transition:all 0.3s ease}",
        "/* */", " ", "  ", "\n", "\r\n", "\t", "    ", "/* comment */", "/* css */", "/* style */"
    };
    
    int variant_count = sizeof(css_variants) / sizeof(css_variants[0]);
    int selected = seeds->content_seed % variant_count;
    
    strncpy(buffer, css_variants[selected], buffer_size - 1);
    buffer[buffer_size - 1] = '\0';
}

/* Generate randomized JSON content - EXPANDED */
void anti_adblock_generate_json_content(const adblock_seed_t *seeds, 
                                       char *buffer, size_t buffer_size) {
    const char* json_variants[] = {
        "{}", "{\"s\":1}", "{\"s\":0}", "{\"result\":true}", "{\"result\":false}", "{\"data\":null}", "{\"data\":[]}",
        "{\"success\":1}", "{\"success\":0}", "{\"error\":0}", "{\"error\":null}", "{\"response\":{}}",
        "{\"items\":[]}", "{\"count\":0}", "{\"total\":0}", "{\"length\":0}", "{\"size\":0}",
        "{\"version\":\"1.0\"}", "{\"version\":\"2.0\"}", "{\"api\":\"v1\"}", "{\"status\":\"ok\"}", "{\"state\":\"ready\"}",
        "{\"id\":\"abc123\"}", "{\"id\":\"xyz789\"}", "{\"uid\":\"test\"}", "{\"key\":\"value\"}", "{\"name\":\"data\"}",
        "{\"value\":42}", "{\"value\":0}", "{\"value\":1}", "{\"number\":123}", "{\"amount\":0}",
        "{\"name\":\"resource\"}", "{\"name\":\"api\"}", "{\"title\":\"test\"}", "{\"label\":\"info\"}",
        "{\"type\":\"data\"}", "{\"type\":\"json\"}", "{\"type\":\"response\"}", "{\"format\":\"json\"}",
        "{\"config\":{}}", "{\"options\":{}}", "{\"settings\":{}}", "{\"params\":{}}", "{\"meta\":{}}",
        "{\"timestamp\":1234567890}", "{\"time\":0}", "{\"date\":null}", "{\"created\":null}",
        "{\"enabled\":true}", "{\"enabled\":false}", "{\"active\":true}", "{\"active\":false}",
        "{\"valid\":true}", "{\"valid\":false}", "{\"ok\":true}", "{\"ok\":false}",
        "{\"code\":200}", "{\"code\":0}", "{\"status_code\":200}", "{\"http_code\":200}",
        "{\"message\":\"\"}", "{\"message\":null}", "{\"text\":\"\"}", "{\"description\":\"\"}",
        "{\"url\":\"\"}", "{\"link\":\"\"}", "{\"href\":\"\"}", "{\"src\":\"\"}",
        "{\"width\":0}", "{\"height\":0}", "{\"x\":0}", "{\"y\":0}", "{\"left\":0}", "{\"top\":0}",
        "{\"min\":0}", "{\"max\":100}", "{\"start\":0}", "{\"end\":0}", "{\"first\":0}", "{\"last\":0}",
        "{\"page\":1}", "{\"limit\":10}", "{\"offset\":0}", "{\"per_page\":20}", "{\"current_page\":1}",
        "{\"has_more\":false}", "{\"is_last\":true}", "{\"is_first\":true}", "{\"has_next\":false}",
        "{\"loading\":false}", "{\"complete\":true}", "{\"finished\":true}", "{\"ready\":true}",
        "{\"empty\":true}", "{\"null\":null}", "{\"undefined\":null}", "{\"void\":null}",
        "{\"array\":[]}", "{\"object\":{}}", "{\"string\":\"\"}", "{\"number\":0}", "{\"boolean\":false}",
        "{\"items\":[1,2,3]}", "{\"data\":{\"a\":1}}", "{\"nested\":{\"b\":{\"c\":2}}}", "{\"deep\":{\"level\":{\"value\":3}}}"
    };
    
    int variant_count = sizeof(json_variants) / sizeof(json_variants[0]);
    int selected = seeds->content_seed % variant_count;
    
    strncpy(buffer, json_variants[selected], buffer_size - 1);
    buffer[buffer_size - 1] = '\0';
}

/* Generate randomized XML content - EXPANDED */
void anti_adblock_generate_xml_content(const adblock_seed_t *seeds, 
                                      char *buffer, size_t buffer_size) {
    const char* xml_variants[] = {
        "<?xml version=\"1.0\"?><root/>", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><data></data>",
        "<?xml version=\"1.0\"?><response><status>ok</status></response>", "<?xml version=\"1.0\"?><r></r>",
        "<?xml version=\"1.0\"?><items></items>", "<?xml version=\"1.0\"?><document><content/></document>",
        "<?xml version=\"1.0\"?><feed></feed>", "<?xml version=\"1.0\"?><config></config>",
        "<?xml version=\"1.0\"?><api><version>1.0</version></api>", "<?xml version=\"1.0\"?><result success=\"true\"/>",
        "<?xml version=\"1.0\"?><data><item/></data>", "<?xml version=\"1.0\"?><response code=\"200\"/>",
        "<?xml version=\"1.0\"?><status>ready</status>", "<?xml version=\"1.0\"?><info><name>test</name></info>",
        "<?xml version=\"1.0\"?><settings><option value=\"0\"/></settings>", "<?xml version=\"1.0\"?><empty/>",
        "<?xml version=\"1.0\"?><collection count=\"0\"/>", "<?xml version=\"1.0\"?><message type=\"info\"/>",
        "<?xml version=\"1.0\"?><metadata><created>null</created></metadata>", "<?xml version=\"1.0\"?><null></null>",
        "<?xml version=\"1.0\"?><page number=\"1\"/>", "<?xml version=\"1.0\"?><state active=\"false\"/>",
        "<?xml version=\"1.0\"?><cache hit=\"true\"/>", "<?xml version=\"1.0\"?><request id=\"123\"/>",
        "<?xml version=\"1.0\"?><content length=\"0\"/>", "<?xml version=\"1.0\"?><resource type=\"data\"/>",
        "<?xml version=\"1.0\"?><output format=\"xml\"/>", "<?xml version=\"1.0\"?><container><child/></container>",
        "<?xml version=\"1.0\"?><wrapper><element attr=\"value\"/></wrapper>", "<?xml version=\"1.0\"?><base/>",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><rss version=\"2.0\"><channel></channel></rss>",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><feed xmlns=\"http://www.w3.org/2005/Atom\"></feed>",
        "<?xml version=\"1.0\"?><sitemap xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"></sitemap>",
        "<?xml version=\"1.0\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"></urlset>",
        "<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"></soap:Envelope>",
        "<?xml version=\"1.0\"?><html xmlns=\"http://www.w3.org/1999/xhtml\"></html>",
        "<?xml version=\"1.0\"?><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"></rdf:RDF>",
        "<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\"></svg>",
        "<?xml version=\"1.0\"?><kml xmlns=\"http://www.opengis.net/kml/2.2\"></kml>",
        "<?xml version=\"1.0\"?><gpx version=\"1.1\" xmlns=\"http://www.topografix.com/GPX/1/1\"></gpx>"
    };
    
    int variant_count = sizeof(xml_variants) / sizeof(xml_variants[0]);
    int selected = seeds->content_seed % variant_count;
    
    strncpy(buffer, xml_variants[selected], buffer_size - 1);
    buffer[buffer_size - 1] = '\0';
}

/* Get randomized cache time */
int anti_adblock_get_cache_time(const adblock_seed_t *seeds, 
                               const char *extension) {
    int base_time = extension_get_cache_time(extension);
    
    /* Add random variance ±20% */
    int variance = (base_time * 20) / 100;
    int random_offset = (seeds->crypto_seed % (variance * 2)) - variance;
    
    return base_time + random_offset;
}

/* Variable delay for unpredictable timing (like PHP script) */
void anti_adblock_variable_delay(const adblock_seed_t *seeds) {
    /* Variable delay 1-50ms plus crypto randomness */
    int base_delay = 1000 + (seeds->crypto_seed % 49000);  /* 1-50ms in microseconds */
    int extra_delay = (seeds->time_seed % 30000);          /* 0-30ms extra */
    
    usleep(base_delay + extra_delay);
}
