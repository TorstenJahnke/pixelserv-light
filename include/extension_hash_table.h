/*
 * extension_hash_table.h - ULTRA-FAST Extension Hash-Table System
 * 
 * REGENERATED with correct FNV-1a hashes
 * Performance: O(log n) Binary Search (~8 comparisons for 265 entries)
 * Hash Algorithm: FNV-1a (case-insensitive)
 */

#ifndef EXTENSION_HASH_TABLE_H
#define EXTENSION_HASH_TABLE_H

#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

// CSP POLICY TYPE
#ifndef CSP_POLICY_TYPE_DEFINED
#define CSP_POLICY_TYPE_DEFINED
#define CSP_STRICT      0
#define CSP_IMAGES      1
#define CSP_HTML        2
#define CSP_MEDIA       3
#define CSP_DOCUMENTS   4
#define CSP_STYLESHEETS 5
#define CSP_NONE        6
typedef int csp_policy_type_t;
#endif

// TYPE DEFINITIONS
typedef enum {
    RESP_BINARY_GIF,
    RESP_BINARY_PNG,
    RESP_BINARY_JPG,
    RESP_BINARY_ICO,
    RESP_BINARY_SWF,
    RESP_SCRIPT_HTML,
    RESP_SCRIPT_JS,
    RESP_STYLE_CSS,
    RESP_DATA_JSON,
    RESP_DATA_XML,
    RESP_MEDIA_VIDEO,
    RESP_MEDIA_AUDIO,
    RESP_DOCUMENT_PDF,
    RESP_TEXT_PLAIN,
    RESP_DEFAULT
} response_type_t;

typedef struct {
    uint32_t hash;
    const char *content_type;
    response_type_t response_type;
    csp_policy_type_t csp_policy;
    const char *ext_name;
} extension_entry_t;

// FNV-1A HASH FUNCTION (case-insensitive)
static inline uint32_t fnv1a_hash(const char *data) {
    uint32_t hash = 2166136261U;
    while (*data) {
        hash ^= (uint32_t)(unsigned char)tolower(*data);
        hash *= 16777619U;
        data++;
    }
    return hash;
}

// HASH TABLE (273 entries, sorted by hash)
// Note: .ts (TypeScript) and .ts (MPEG-TS) had hash collision - using .m2ts for video
#define EXTENSION_COUNT 273

static const extension_entry_t extension_table[EXTENSION_COUNT] = {
    {0x00c704dd, "text/html; charset=utf-8", RESP_SCRIPT_HTML, CSP_STRICT, "cfml"},
    {0x01987941, "application/x-pip", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "requirements"},
    {0x01a0021b, "application/x-bson", RESP_DATA_JSON, CSP_STRICT, "bson"},
    {0x037448d8, "application/atom+xml", RESP_DATA_XML, CSP_STRICT, "atom"},
    {0x03812341, "application/javascript", RESP_SCRIPT_JS, CSP_STRICT, "cjs"},
    {0x045e9292, "text/x-c++", RESP_TEXT_PLAIN, CSP_STRICT, "cxx"},
    {0x05a8fb12, "audio/x-8svx", RESP_MEDIA_AUDIO, CSP_MEDIA, "8svx"},
    {0x078fda9c, "text/html; charset=utf-8", RESP_SCRIPT_HTML, CSP_HTML, "htm"},
    {0x07a54453, "font/woff2", RESP_BINARY_PNG, CSP_DOCUMENTS, "woff2"},
    {0x081fb565, "text/x-java", RESP_TEXT_PLAIN, CSP_STRICT, "java"},
    {0x083e3344, "text/x-license", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "license"},
    {0x08a59408, "text/html; charset=utf-8", RESP_SCRIPT_HTML, CSP_STRICT, "asmx"},
    {0x0a9038d0, "text/x-clojure", RESP_TEXT_PLAIN, CSP_STRICT, "clj"},
    {0x0d76a5a3, "text/html; charset=utf-8", RESP_SCRIPT_HTML, CSP_STRICT, "cfm"},
    {0x0e474901, "application/x-csh", RESP_DOCUMENT_PDF, CSP_STRICT, "csh"},
    {0x0ea5c8ba, "application/xhtml+xml", RESP_SCRIPT_HTML, CSP_HTML, "xhtml"},
    {0x0eb96753, "application/vnd.ms-works", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "wps"},
    {0x10fb5ecd, "text/x-lisp", RESP_TEXT_PLAIN, CSP_STRICT, "lisp"},
    {0x1222e0f3, "application/x-tcsh", RESP_DOCUMENT_PDF, CSP_STRICT, "tcsh"},
    {0x13e2bd39, "audio/wav", RESP_MEDIA_AUDIO, CSP_MEDIA, "wav"},
    {0x13ed4a95, "video/x-ms-wmv", RESP_MEDIA_VIDEO, CSP_MEDIA, "wmv"},
    {0x1472c0a0, "text/x-assembly", RESP_TEXT_PLAIN, CSP_STRICT, "asm"},
    {0x1691845d, "video/3gpp", RESP_MEDIA_VIDEO, CSP_MEDIA, "3gp"},
    {0x16b0e305, "text/html; charset=utf-8", RESP_SCRIPT_HTML, CSP_STRICT, "ashx"},
    {0x16ed0d2d, "text/html; charset=utf-8", RESP_SCRIPT_HTML, CSP_STRICT, "aspx"},
    {0x193f4a7a, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "xlsx"},
    {0x1947cb27, "audio/x-aiff", RESP_MEDIA_AUDIO, CSP_MEDIA, "aiff"},
    {0x1b2796f3, "audio/amr", RESP_MEDIA_AUDIO, CSP_MEDIA, "amr"},
    {0x1b76bbad, "text/html; charset=utf-8", RESP_SCRIPT_HTML, CSP_STRICT, "cfc"},
    {0x1c487b96, "application/font-sfnt", RESP_BINARY_PNG, CSP_DOCUMENTS, "sfnt"},
    {0x1c660145, "video/x-msvideo", RESP_MEDIA_VIDEO, CSP_MEDIA, "avi"},
    {0x1f29dbd6, "application/x-ant", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "ant"},
    {0x1f72d1f1, "video/x-ms-asf", RESP_MEDIA_VIDEO, CSP_MEDIA, "asf"},
    {0x216b57b8, "text/css", RESP_STYLE_CSS, CSP_STYLESHEETS, "less"},
    {0x2292ffab, "text/x-dockerfile", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "dockerfile"},
    {0x23b98862, "application/vnd.wordperfect", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "wpd"},
    {0x247e5071, "image/heif", RESP_BINARY_PNG, CSP_IMAGES, "heif"},
    {0x2491d065, "application/x-stuffitx", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "sitx"},
    {0x2738f2f8, "audio/x-adpcm", RESP_MEDIA_AUDIO, CSP_MEDIA, "adp"},
    {0x277e552a, "image/heic", RESP_BINARY_PNG, CSP_IMAGES, "heic"},
    {0x2e6f17f7, "image/x-sony-arw", RESP_BINARY_PNG, CSP_IMAGES, "arw"},
    {0x2fdc6133, "application/rss+xml", RESP_DATA_XML, CSP_STRICT, "rss"},
    {0x2feb3fd7, "application/vnd.openxmlformats-officedocument.wordprocessingml.document", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "docx"},
    {0x316f1cb0, "application/x-arj", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "arj"},
    {0x3172ee47, "text/html; charset=utf-8", RESP_SCRIPT_HTML, CSP_STRICT, "asp"},
    {0x32454316, "image/x-canon-cr2", RESP_BINARY_PNG, CSP_IMAGES, "cr2"},
    {0x3245d03c, "audio/aac", RESP_MEDIA_AUDIO, CSP_MEDIA, "aac"},
    {0x3259077d, "text/x-todo", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "todo"},
    {0x33725649, "application/json", RESP_DATA_JSON, CSP_STRICT, "jsonp"},
    {0x356ed285, "application/toml", RESP_DATA_JSON, CSP_STRICT, "toml"},
    {0x367196d1, "application/x-lzh", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "lzh"},
    {0x36a1a243, "application/json", RESP_DATA_JSON, CSP_STRICT, "json"},
    {0x37719864, "application/x-lzop", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "lzo"},
    {0x3799adae, "image/x-nikon-nef", RESP_BINARY_PNG, CSP_IMAGES, "nef"},
    {0x38390dbb, "text/x-ada", RESP_TEXT_PLAIN, CSP_STRICT, "ada"},
    {0x383d8ae9, "application/x-font-afm", RESP_BINARY_PNG, CSP_DOCUMENTS, "afm"},
    {0x3a6aadad, "application/vnd.android.package-archive", RESP_DOCUMENT_PDF, CSP_STRICT, "apk"},
    {0x3c4a5d28, "application/x-ace-compressed", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "ace"},
    {0x3f24efc0, "audio/x-alaw", RESP_MEDIA_AUDIO, CSP_MEDIA, "al"},
    {0x3f39a5e6, "audio/x-gsm", RESP_MEDIA_AUDIO, CSP_MEDIA, "gsm"},
    {0x3f515151, "text/x-log", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "log"},
    {0x3f520f5e, "application/x-shellscript", RESP_DOCUMENT_PDF, CSP_STRICT, "sh"},
    {0x4220774b, "text/x-go", RESP_TEXT_PLAIN, CSP_STRICT, "go"},
    {0x42521417, "application/x-sharedlib", RESP_DOCUMENT_PDF, CSP_STRICT, "so"},
    {0x4333083f, "text/x-authors", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "authors"},
    {0x44696553, "application/x-python-code", RESP_SCRIPT_HTML, CSP_STRICT, "pyc"},
    {0x44cfb64f, "application/rtf", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "rtf"},
    {0x454e4739, "text/html; charset=utf-8", RESP_SCRIPT_HTML, CSP_STRICT, "pl"},
    {0x462977f3, "text/x-csharp", RESP_TEXT_PLAIN, CSP_STRICT, "cs"},
    {0x46454e70, "application/typescript", RESP_SCRIPT_JS, CSP_STRICT, "ts"},  /* TypeScript - primary use */
    /* Note: video/mp2t (.ts) removed - hash collision with TypeScript, use .m2ts for MPEG-TS */
    {0x46ff17aa, "application/x-rar-compressed", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "rar"},
    {0x474fd226, "application/x-font-pcf", RESP_BINARY_PNG, CSP_DOCUMENTS, "pcf"},
    {0x49f34ddb, "application/ld+json", RESP_DATA_JSON, CSP_STRICT, "jsonld"},
    {0x4a07a0a7, "text/x-readme", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "readme"},
    {0x4b1a7548, "text/x-elixir", RESP_TEXT_PLAIN, CSP_STRICT, "ex"},
    {0x4b1cb3df, "video/x-dv", RESP_MEDIA_VIDEO, CSP_MEDIA, "dv"},
    {0x4bc7bc46, "text/x-news", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "news"},
    {0x4d522568, "application/x-snappy", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "sz"},
    {0x4dd8bed6, "application/x-rpm", RESP_DOCUMENT_PDF, CSP_STRICT, "rpm"},
    {0x4e335b17, "application/x-maven", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "pom"},
    {0x4e3acdac, "text/x-haskell", RESP_TEXT_PLAIN, CSP_STRICT, "hs"},
    {0x4e546592, "text/x-rust", RESP_TEXT_PLAIN, CSP_STRICT, "rs"},
    {0x4e7f3b60, "image/x-portable-pixmap", RESP_BINARY_PNG, CSP_IMAGES, "ppm"},
    {0x4f2bc4b5, "application/x-brotli", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "br"},
    {0x4f31d4e3, "application/x-lzip", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "lz"},
    {0x524927b2, "application/x-font-pfm", RESP_BINARY_PNG, CSP_DOCUMENTS, "pfm"},
    {0x54dbedd4, "text/x-copying", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "copying"},
    {0x55209534, "application/gzip", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "gz"},
    {0x55492c6b, "application/x-font-type1", RESP_BINARY_PNG, CSP_DOCUMENTS, "pfb"},
    {0x55e57564, "application/x-7z-compressed", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "7z"},
    {0x56299123, "text/x-c++", RESP_TEXT_PLAIN, CSP_STRICT, "cc"},
    {0x56492dfe, "application/x-font-type1", RESP_BINARY_PNG, CSP_DOCUMENTS, "pfa"},
    {0x57637e47, "application/x-xz", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "xz"},
    {0x5825171b, "audio/x-au", RESP_MEDIA_AUDIO, CSP_MEDIA, "au"},
    {0x584e6522, "text/html; charset=utf-8", RESP_SCRIPT_HTML, CSP_STRICT, "py"},
    {0x58884926, "application/x-elf", RESP_DOCUMENT_PDF, CSP_STRICT, "elf"},
    {0x58ca6a73, "font/woff", RESP_BINARY_PNG, CSP_DOCUMENTS, "woff"},
    {0x58d872f1, "application/x-lzma", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "lzma"},
    {0x5938b89e, "application/yaml", RESP_DATA_JSON, CSP_STRICT, "yaml"},
    {0x594f3ba8, "application/x-lha", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "lha"},
    {0x597b9e8b, "application/x-yarn", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "yarn"},
    {0x5b3d20ba, "text/x-kotlin", RESP_TEXT_PLAIN, CSP_STRICT, "kt"},
    {0x5b44b8af, "text/html; charset=utf-8", RESP_SCRIPT_HTML, CSP_STRICT, "php"},
    {0x5b7283e4, "application/vnd.ms-publisher", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "pub"},
    {0x5d9227e1, "text/x-lua", RESP_TEXT_PLAIN, CSP_STRICT, "lua"},
    {0x5e3f640a, "application/javascript", RESP_SCRIPT_JS, CSP_STRICT, "js"},
    {0x5e49696a, "image/tiff", RESP_BINARY_PNG, CSP_IMAGES, "tiff"},
    {0x5f2e1c7c, "text/x-ocaml", RESP_TEXT_PLAIN, CSP_STRICT, "ml"},
    {0x5f433734, "audio/x-ulaw", RESP_MEDIA_AUDIO, CSP_MEDIA, "ul"},
    {0x5f548055, "text/html; charset=utf-8", RESP_SCRIPT_HTML, CSP_STRICT, "rb"},
    {0x621cd814, "text/html; charset=utf-8", RESP_SCRIPT_HTML, CSP_STRICT, "do"},
    {0x625163ff, "application/x-stack", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "stack"},
    {0x636e7d9d, "application/x-mach-binary", RESP_DOCUMENT_PDF, CSP_STRICT, "dylib"},
    {0x6447bc41, "video/x-ms-wm", RESP_MEDIA_VIDEO, CSP_MEDIA, "wm"},
    {0x64560ffb, "text/x-pascal", RESP_TEXT_PLAIN, CSP_STRICT, "pas"},
    {0x6578a3d0, "image/vnd.adobe.photoshop", RESP_BINARY_PNG, CSP_IMAGES, "psd"},
    {0x662ad8c1, "image/gif", RESP_BINARY_GIF, CSP_IMAGES, "gif"},
    {0x667abd64, "audio/midi", RESP_MEDIA_AUDIO, CSP_MEDIA, "midi"},
    {0x66f24b81, "application/x-makefile", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "makefile"},
    {0x672e2914, "text/markdown", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "md"},
    {0x677f62bb, "application/vnd.ms-powerpoint", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "ppt"},
    {0x67a675d7, "application/x-executable", RESP_DOCUMENT_PDF, CSP_STRICT, "exe"},
    {0x6835c29c, "image/png", RESP_BINARY_PNG, CSP_IMAGES, "png"},
    {0x68a91acd, "application/cbor", RESP_DATA_JSON, CSP_STRICT, "cbor"},
    {0x693af82d, "text/x-c++hdr", RESP_TEXT_PLAIN, CSP_STRICT, "hh"},
    {0x694dc915, "application/pdf", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "pdf"},
    {0x6ad76064, "application/manifest+json", RESP_DATA_JSON, CSP_DOCUMENTS, "manifest"},
    {0x6be07ca8, "application/x-cmake", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "cmake"},
    {0x6cc1fab8, "image/bmp", RESP_BINARY_PNG, CSP_IMAGES, "bmp"},
    {0x6db2ee15, "application/yaml", RESP_DATA_JSON, CSP_STRICT, "yml"},
    {0x6e47152f, "image/x-portable-graymap", RESP_BINARY_PNG, CSP_IMAGES, "pgm"},
    {0x70b773a8, "application/x-ms-dos-executable", RESP_DOCUMENT_PDF, CSP_STRICT, "bat"},
    {0x7235d25a, "image/x-portable-anymap", RESP_BINARY_PNG, CSP_IMAGES, "pnm"},
    {0x7252546e, "image/x-portable-bitmap", RESP_BINARY_PNG, CSP_IMAGES, "pbm"},
    {0x7282eec0, "application/x-ruby", RESP_SCRIPT_HTML, CSP_STRICT, "rhtml"},
    {0x73c00bb1, "application/x-protobuf", RESP_DATA_JSON, CSP_STRICT, "proto"},
    {0x74a68a4e, "image/x-exr", RESP_BINARY_PNG, CSP_IMAGES, "exr"},
    {0x74b0be2f, "application/x-font-bdf", RESP_BINARY_PNG, CSP_DOCUMENTS, "bdf"},
    {0x788e8bb4, "application/x-environment", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "env"},
    {0x7890ca4b, "application/vnd.ms-fontobject", RESP_BINARY_PNG, CSP_DOCUMENTS, "eot"},
    {0x79179233, "audio/x-16sv", RESP_MEDIA_AUDIO, CSP_MEDIA, "16sv"},
    {0x7c978c5c, "application/x-erb", RESP_SCRIPT_HTML, CSP_STRICT, "erb"},
    {0x7ce1083e, "image/x-icon", RESP_BINARY_ICO, CSP_IMAGES, "ico"},
    {0x8052f79e, "application/vnd.ms-visio", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "vsd"},
    {0x829795ce, "text/x-erlang", RESP_TEXT_PLAIN, CSP_STRICT, "erl"},
    {0x8463e1a0, "text/x-install", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "install"},
    {0x85f3a527, "application/x-cargo", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "cargo"},
    {0x869722bd, "text/x-scala", RESP_TEXT_PLAIN, CSP_STRICT, "scala"},
    {0x8a35b313, "application/x-composer", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "composer"},
    {0x8d578943, "application/javascript", RESP_SCRIPT_JS, CSP_STRICT, "vue"},
    {0x8e2c7aa1, "application/javascript", RESP_SCRIPT_JS, CSP_STRICT, "coffee"},
    {0x913b2bfb, "application/x-npm", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "package"},
    {0x920f75d9, "text/x-changelog", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "changelog"},
    {0x9214ab35, "text/x-vhdl", RESP_TEXT_PLAIN, CSP_STRICT, "vhd"},
    {0x927c3c2b, "application/x-zoo", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "zoo"},
    {0x9c793831, "audio/mpeg", RESP_MEDIA_AUDIO, CSP_MEDIA, "mp3"},
    {0x9d09dd0e, "application/x-iso9660-image", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "iso"},
    {0x9d7939c4, "video/mp4", RESP_MEDIA_VIDEO, CSP_MEDIA, "mp4"},
    {0xa2e992d5, "text/x-ini", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "ini"},
    {0xa535a9ef, "text/plain", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "txt"},
    {0xa5f6cd4d, "application/wasm", RESP_DEFAULT, CSP_STRICT, "wasm"},
    {0xa719d698, "application/typescript", RESP_SCRIPT_JS, CSP_STRICT, "tsx"},
    {0xa7212b4c, "text/markdown", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "markdown"},
    {0xa7ce4d7e, "application/x-gradle", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "gradle"},
    {0xa7fd5617, "image/x-targa", RESP_BINARY_PNG, CSP_IMAGES, "tga"},
    {0xa8f7477c, "application/x-tar", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "tar"},
    {0xab3e0bff, "application/java-vm", RESP_DOCUMENT_PDF, CSP_STRICT, "class"},
    {0xab409a38, "application/vnd.oasis.opendocument.formula", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "odf"},
    {0xab8273b4, "application/zip", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "zip"},
    {0xabc1880a, "application/x-zstd", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "zst"},
    {0xac409bcb, "application/vnd.oasis.opendocument.graphics", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "odg"},
    {0xaef39ccf, "video/x-sgi-movie", RESP_MEDIA_VIDEO, CSP_MEDIA, "movie"},
    {0xaf40a084, "application/vnd.oasis.opendocument.database", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "odb"},
    {0xafad8963, "application/x-fish", RESP_DOCUMENT_PDF, CSP_STRICT, "fish"},
    {0xafc18e56, "application/x-zsh", RESP_DOCUMENT_PDF, CSP_STRICT, "zsh"},
    {0xaff149b2, "video/x-fli", RESP_MEDIA_VIDEO, CSP_MEDIA, "fli"},
    {0xb040a217, "application/vnd.oasis.opendocument.chart", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "odc"},
    {0xb0498f78, "application/manifest+json", RESP_DATA_JSON, CSP_DOCUMENTS, "webmanifest"},
    {0xb08878f9, "application/vnd.openxmlformats-officedocument.presentationml.presentation", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "pptx"},
    {0xb13260d8, "text/x-swift", RESP_TEXT_PLAIN, CSP_STRICT, "swift"},
    {0xb3159ff9, "audio/x-sbc", RESP_MEDIA_AUDIO, CSP_MEDIA, "sbc"},
    {0xb433b6a0, "audio/basic", RESP_MEDIA_AUDIO, CSP_MEDIA, "snd"},
    {0xb43404ff, "text/html; charset=utf-8", RESP_SCRIPT_HTML, CSP_HTML, "shtml"},
    {0xb5304e4f, "text/css", RESP_STYLE_CSS, CSP_STYLESHEETS, "stylus"},
    {0xb5b6c814, "application/x-cabal", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "cabal"},
    {0xb5f15324, "video/x-flc", RESP_MEDIA_VIDEO, CSP_MEDIA, "flc"},
    {0xb633b9c6, "application/x-font-snf", RESP_BINARY_PNG, CSP_DOCUMENTS, "snf"},
    {0xb72b38e9, "font/ttf", RESP_BINARY_PNG, CSP_DOCUMENTS, "ttf"},
    {0xb8facaed, "application/x-bzip2", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "bz2"},
    {0xb9eaa28b, "audio/flac", RESP_MEDIA_AUDIO, CSP_MEDIA, "flac"},
    {0xba2b3da2, "font/collection", RESP_BINARY_PNG, CSP_DOCUMENTS, "ttc"},
    {0xbb75a3f7, "text/css", RESP_STYLE_CSS, CSP_STYLESHEETS, "styl"},
    {0xbd3ce4f7, "video/ogg", RESP_MEDIA_VIDEO, CSP_MEDIA, "ogv"},
    {0xbd40b68e, "application/vnd.oasis.opendocument.text", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "odt"},
    {0xbd50172b, "application/x-msgpack", RESP_DATA_JSON, CSP_STRICT, "msgpack"},
    {0xbd727fa6, "application/vnd.ms-excel", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "xls"},
    {0xbe450f7f, "text/x-sql", RESP_TEXT_PLAIN, CSP_STRICT, "sql"},
    {0xbedf9323, "image/jpeg", RESP_BINARY_JPG, CSP_IMAGES, "jpeg"},
    {0xc040bb47, "application/vnd.oasis.opendocument.spreadsheet", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "ods"},
    {0xc0613b3e, "image/x-xcf", RESP_BINARY_PNG, CSP_IMAGES, "xcf"},
    {0xc09c031f, "video/x-mng", RESP_MEDIA_VIDEO, CSP_MEDIA, "mng"},
    {0xc140bcda, "application/vnd.oasis.opendocument.presentation", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "odp"},
    {0xc1597840, "application/x-deb", RESP_DOCUMENT_PDF, CSP_STRICT, "deb"},
    {0xc2f1679b, "video/x-flv", RESP_MEDIA_VIDEO, CSP_MEDIA, "flv"},
    {0xc2f43597, "text/css", RESP_STYLE_CSS, CSP_STYLESHEETS, "sass"},
    {0xc321d21f, "audio/mp4", RESP_MEDIA_AUDIO, CSP_MEDIA, "m4a"},
    {0xc38f3be5, "audio/midi", RESP_MEDIA_AUDIO, CSP_MEDIA, "mid"},
    {0xc415babc, "application/x-sbt", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "sbt"},
    {0xc4642eff, "text/html; charset=utf-8", RESP_SCRIPT_HTML, CSP_STRICT, "action"},
    {0xc50afb48, "image/tiff", RESP_BINARY_PNG, CSP_IMAGES, "tif"},
    {0xc630015f, "application/x-stuffit", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "sit"},
    {0xc66ac940, "image/x-adobe-dng", RESP_BINARY_PNG, CSP_IMAGES, "dng"},
    {0xc8499c6b, "application/x-shockwave-flash", RESP_BINARY_SWF, CSP_STRICT, "swf"},
    {0xca3cf96e, "audio/x-vorbis+ogg", RESP_MEDIA_AUDIO, CSP_MEDIA, "oga"},
    {0xca93c418, "audio/x-matroska", RESP_MEDIA_AUDIO, CSP_MEDIA, "mka"},
    {0xcb182a28, "font/otf", RESP_BINARY_PNG, CSP_DOCUMENTS, "otf"},
    {0xcc3cfc94, "audio/ogg", RESP_MEDIA_AUDIO, CSP_MEDIA, "ogg"},
    {0xcdedae92, "application/java-archive", RESP_DOCUMENT_PDF, CSP_STRICT, "jar"},
    {0xce875f5a, "audio/opus", RESP_MEDIA_AUDIO, CSP_MEDIA, "opus"},
    {0xcfcb1f76, "application/javascript", RESP_SCRIPT_JS, CSP_STRICT, "jsx"},
    {0xd021e696, "video/x-m4v", RESP_MEDIA_VIDEO, CSP_MEDIA, "m4v"},
    {0xd07d2aeb, "text/html; charset=utf-8", RESP_SCRIPT_HTML, CSP_HTML, "xht"},
    {0xd19e5c79, "video/quicktime", RESP_MEDIA_VIDEO, CSP_MEDIA, "mov"},
    {0xd1baeec9, "text/css", RESP_STYLE_CSS, CSP_STYLESHEETS, "scss"},
    {0xd2a304ca, "application/x-bundler", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "gemfile"},
    {0xd491953f, "application/javascript", RESP_SCRIPT_JS, CSP_STRICT, "mjs"},
    {0xd4c45633, "image/webp", RESP_BINARY_PNG, CSP_IMAGES, "webp"},
    {0xd500c706, "text/html; charset=utf-8", RESP_SCRIPT_HTML, CSP_STRICT, "fcgi"},
    {0xd775a7d0, "text/html; charset=utf-8", RESP_SCRIPT_HTML, CSP_HTML, "html"},
    {0xd793ca19, "image/avif", RESP_BINARY_PNG, CSP_IMAGES, "avif"},
    {0xd7cb2c0e, "text/html; charset=utf-8", RESP_SCRIPT_HTML, CSP_STRICT, "jsp"},
    {0xd84166d6, "application/x-font-speedo", RESP_BINARY_PNG, CSP_DOCUMENTS, "spd"},
    {0xd9799838, "application/vnd.ms-project", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "mpp"},
    {0xda5bde32, "image/x-dds", RESP_BINARY_PNG, CSP_IMAGES, "dds"},
    {0xda706eb6, "text/xml", RESP_DATA_XML, CSP_STRICT, "xml"},
    {0xdac75f30, "image/jpeg", RESP_BINARY_JPG, CSP_IMAGES, "jpg"},
    {0xdc4049d7, "text/x-config", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "conf"},
    {0xdfa2efb1, "application/json", RESP_DATA_JSON, CSP_STRICT, "map"},
    {0xe11826fa, "text/x-scheme", RESP_TEXT_PLAIN, CSP_STRICT, "scm"},
    {0xe193e84d, "video/x-matroska", RESP_MEDIA_VIDEO, CSP_MEDIA, "mkv"},
    {0xe2806228, "application/x-msi", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "msi"},
    {0xe30c2799, "text/x-fortran", RESP_TEXT_PLAIN, CSP_STRICT, "f"},
    {0xe3ab44c2, "application/vnd.ms-access", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "mdb"},
    {0xe40c292c, "application/x-archive", RESP_DOCUMENT_PDF, CSP_STRICT, "a"},
    {0xe60c2c52, "text/x-c", RESP_TEXT_PLAIN, CSP_STRICT, "c"},
    {0xe7478ea1, "image/svg+xml", RESP_BINARY_PNG, CSP_IMAGES, "svg"},
    {0xe80c2f78, "text/x-matlab", RESP_TEXT_PLAIN, CSP_STRICT, "m"},
    {0xe89c3f12, "application/vnd.visio", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "vsdx"},
    {0xea0c329e, "application/x-object", RESP_DOCUMENT_PDF, CSP_STRICT, "o"},
    {0xea68c355, "application/msword", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "doc"},
    {0xeb4794ed, "text/html; charset=utf-8", RESP_SCRIPT_HTML, CSP_STRICT, "svc"},
    {0xec8dcaff, "text/x-cobol", RESP_TEXT_PLAIN, CSP_STRICT, "cob"},
    {0xed0c3757, "text/x-chdr", RESP_TEXT_PLAIN, CSP_STRICT, "h"},
    {0xeec12d03, "application/x-haml", RESP_SCRIPT_HTML, CSP_STRICT, "haml"},
    {0xef778408, "text/x-dart", RESP_TEXT_PLAIN, CSP_STRICT, "dart"},
    {0xefc480b4, "video/webm", RESP_MEDIA_VIDEO, CSP_MEDIA, "webm"},
    {0xf18dd2de, "application/x-msdos-program", RESP_DOCUMENT_PDF, CSP_STRICT, "com"},
    {0xf30c40c9, "text/x-verilog", RESP_TEXT_PLAIN, CSP_STRICT, "v"},
    {0xf3471e80, "text/css", RESP_STYLE_CSS, CSP_STYLESHEETS, "css"},
    {0xf4743fb1, "application/vnd.ms-cab-compressed", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "cab"},
    {0xf498b70f, "text/x-c++hdr", RESP_TEXT_PLAIN, CSP_STRICT, "hpp"},
    {0xf4bd82be, "application/x-leiningen", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "project"},
    {0xf578be72, "text/html; charset=utf-8", RESP_SCRIPT_HTML, CSP_STRICT, "cgi"},
    {0xf60c4582, "text/x-assembly", RESP_TEXT_PLAIN, CSP_STRICT, "s"},
    {0xf66d5367, "application/x-dmg", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "dmg"},
    {0xf70c4715, "text/x-r", RESP_TEXT_PLAIN, CSP_STRICT, "r"},
    {0xf744e635, "image/x-canon-crw", RESP_BINARY_PNG, CSP_IMAGES, "crw"},
    {0xf847265f, "text/csv", RESP_TEXT_PLAIN, CSP_DOCUMENTS, "csv"},
    {0xfc4afe42, "text/x-c++", RESP_TEXT_PLAIN, CSP_STRICT, "cpp"},
    {0xfcac4b5f, "text/x-c++hdr", RESP_TEXT_PLAIN, CSP_STRICT, "hxx"},
    {0xfced2660, "audio/x-ms-wma", RESP_MEDIA_AUDIO, CSP_MEDIA, "wma"},
    {0xfeb6dbe1, "image/x-hdr", RESP_BINARY_PNG, CSP_IMAGES, "hdr"},
    {0xff0c53ad, "application/x-compress", RESP_DOCUMENT_PDF, CSP_DOCUMENTS, "Z"}
};

// BINARY SEARCH LOOKUP
static inline const extension_entry_t* lookup_extension(const char *ext) {
    if (!ext || *ext == '\0') return NULL;
    uint32_t target = fnv1a_hash(ext);
    int lo = 0, hi = EXTENSION_COUNT - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        uint32_t h = extension_table[mid].hash;
        if (h == target) return &extension_table[mid];
        if (h < target) lo = mid + 1;
        else hi = mid - 1;
    }
    return NULL;
}

#endif /* EXTENSION_HASH_TABLE_H */
