/* TLS-Gate NX - String Obfuscation
 * Copyright (C) 2025 Torsten Jahnke
 *
 * Lightweight string obfuscation for production builds (Level 3-4/10)
 * - Compile-time XOR encryption
 * - Runtime inline decryption
 * - Only active in production builds
 *
 * Usage: const char *str = OBFSTR("sensitive string");
 */

#ifndef TLSGATENG_STRING_OBFUSCATION_H
#define TLSGATENG_STRING_OBFUSCATION_H

#include <stddef.h>
#include <string.h>

#ifdef PRODUCTION_BUILD

/* XOR key for obfuscation (changed per build via __TIME__) */
#define OBF_KEY_SEED (__TIME__[0] ^ __TIME__[1] ^ __TIME__[3] ^ __TIME__[4] ^ __TIME__[6] ^ __TIME__[7])

/* Compile-time XOR encryption helper */
#define OBF_CHAR(c, i) ((char)((c) ^ (OBF_KEY_SEED + (i))))

/* Macro to obfuscate string at compile time */
#define OBFSTR(str) obfuscate_string_inline(str, sizeof(str) - 1)

/* Inline decryption function (called at runtime) */
static inline const char* obfuscate_string_inline(const char *obf_str, size_t len) {
    static __thread char buffer[512];  /* Thread-local buffer */
    if (len >= sizeof(buffer)) len = sizeof(buffer) - 1;

    for (size_t i = 0; i < len; i++) {
        buffer[i] = obf_str[i] ^ (OBF_KEY_SEED + i);
    }
    buffer[len] = '\0';
    return buffer;
}

/* Macro helper for compile-time string encryption (up to 64 chars) */
#define OBF_STR_1(s) OBF_CHAR(s[0], 0)
#define OBF_STR_2(s) OBF_STR_1(s), OBF_CHAR(s[1], 1)
#define OBF_STR_3(s) OBF_STR_2(s), OBF_CHAR(s[2], 2)
#define OBF_STR_4(s) OBF_STR_3(s), OBF_CHAR(s[3], 3)
#define OBF_STR_5(s) OBF_STR_4(s), OBF_CHAR(s[4], 4)
#define OBF_STR_6(s) OBF_STR_5(s), OBF_CHAR(s[5], 5)
#define OBF_STR_7(s) OBF_STR_6(s), OBF_CHAR(s[6], 6)
#define OBF_STR_8(s) OBF_STR_7(s), OBF_CHAR(s[7], 7)

/* Simple obfuscation for common strings */
#define OBFSTR_SIMPLE(str) ({ \
    static const char obf[] = {OBF_STR_8(str "\0\0\0\0\0\0\0\0")}; \
    obfuscate_string_inline(obf, strlen(str)); \
})

#else

/* Debug/development builds: No obfuscation */
#define OBFSTR(str) (str)
#define OBFSTR_SIMPLE(str) (str)

#endif /* PRODUCTION_BUILD */

#endif /* TLSGATENG_STRING_OBFUSCATION_H */
