AC_INIT([pixelserv-tls], [2.5.6], [])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CANONICAL_HOST
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])

AC_CHECK_LIB([dl], [dlopen], [], [])
AC_CHECK_LIB([rt], [clock_gettime], [], [])
AC_CHECK_LIB([pthread], [main], [],
	AC_MSG_ERROR([libpthread not found]))
AC_CHECK_LIB([crypto], [EVP_EncryptInit], [],
	AC_MSG_FAILURE([can't find openssl crypto lib]))
AC_CHECK_LIB([ssl], [SSL_CTX_new], [],
	AC_MSG_FAILURE([can't find openssl ssl lib]))

dnl =============================================================================
dnl Event Loop Backend Detection (io_uring > epoll > kqueue)
dnl =============================================================================

dnl Check for io_uring (Linux 5.1+, requires liburing)
AC_MSG_CHECKING([for io_uring support])
AC_CHECK_LIB([uring], [io_uring_queue_init],
    [
        AC_DEFINE([HAVE_IO_URING], [1], [Define if io_uring is available])
        LIBS="-luring $LIBS"
        have_io_uring=yes
        AC_MSG_RESULT([yes])
    ],
    [
        have_io_uring=no
        AC_MSG_RESULT([no - liburing not found])
    ])

dnl epoll is always available on Linux (checked at compile time in eventloop.c)
case "${host_os}" in
    linux*)
        have_epoll=yes
        ;;
    *)
        have_epoll=no
        ;;
esac

dnl kqueue is available on BSD/macOS (checked at compile time in eventloop.c)
case "${host_os}" in
    darwin* | freebsd* | openbsd* | netbsd*)
        have_kqueue=yes
        ;;
    *)
        have_kqueue=no
        ;;
esac

dnl Verify at least one event loop backend is available
if test "x$have_io_uring" != "xyes" && test "x$have_epoll" != "xyes" && test "x$have_kqueue" != "xyes"; then
    AC_MSG_ERROR([No event loop backend available! Requires io_uring, epoll (Linux), or kqueue (BSD/macOS)])
fi

dnl Check for OpenSSL version
AC_CHECK_DECL([TLS1_3_VERSION],
    [AC_DEFINE([HAVE_TLS1_3], [1], [Define if TLS 1.3 is supported])],
    [], [#include <openssl/ssl.h>])

dnl Check for SM2/SM3/SM4 support (Chinese GM/T Cryptography - Tongchou)
dnl SM4 is the block cipher
AC_MSG_CHECKING([for SM4 cipher support (Tongchou)])
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[
        #include <openssl/evp.h>
    ]], [[
        const EVP_CIPHER *c = EVP_sm4_cbc();
        return c ? 0 : 1;
    ]])],
    [
        AC_MSG_RESULT([yes])
        AC_DEFINE([HAVE_SM4], [1], [Define if OpenSSL has SM4 support])
        have_sm4=yes
    ],
    [
        AC_MSG_RESULT([no])
        have_sm4=no
    ])

dnl SM3 is the hash function
AC_MSG_CHECKING([for SM3 hash support (Tongchou)])
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[
        #include <openssl/evp.h>
    ]], [[
        const EVP_MD *md = EVP_sm3();
        return md ? 0 : 1;
    ]])],
    [
        AC_MSG_RESULT([yes])
        AC_DEFINE([HAVE_SM3], [1], [Define if OpenSSL has SM3 support])
        have_sm3=yes
    ],
    [
        AC_MSG_RESULT([no])
        have_sm3=no
    ])

dnl SM2 is the elliptic curve (requires OpenSSL 1.1.1+)
AC_MSG_CHECKING([for SM2 elliptic curve support (Tongchou)])
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[
        #include <openssl/ec.h>
        #include <openssl/obj_mac.h>
    ]], [[
        EC_KEY *key = EC_KEY_new_by_curve_name(NID_sm2);
        if (key) EC_KEY_free(key);
        return key ? 0 : 1;
    ]])],
    [
        AC_MSG_RESULT([yes])
        AC_DEFINE([HAVE_SM2], [1], [Define if OpenSSL has SM2 support])
        have_sm2=yes
    ],
    [
        AC_MSG_RESULT([no])
        have_sm2=no
    ])

dnl Combined Tongchou/GM support check
if test "x$have_sm2" = "xyes" && test "x$have_sm3" = "xyes" && test "x$have_sm4" = "xyes"; then
    AC_DEFINE([HAVE_TONGCHOU], [1], [Define if full SM2/SM3/SM4 Tongchou support is available])
    AC_MSG_NOTICE([Full Tongchou (SM2/SM3/SM4) cryptography support enabled])
else
    AC_MSG_NOTICE([Tongchou (SM2/SM3/SM4) support not available - OpenSSL was compiled without GM support])
fi

dnl Check for CHACHA20-POLY1305 support
AC_MSG_CHECKING([for CHACHA20-POLY1305 cipher support])
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[
        #include <openssl/evp.h>
    ]], [[
        const EVP_CIPHER *c = EVP_chacha20_poly1305();
        return c ? 0 : 1;
    ]])],
    [
        AC_MSG_RESULT([yes])
        AC_DEFINE([HAVE_CHACHA20_POLY1305], [1], [Define if OpenSSL has CHACHA20-POLY1305 support])
    ],
    [
        AC_MSG_RESULT([no])
    ])

AC_ARG_ENABLE([static], AS_HELP_STRING([--enable-static], [Build static binary]))
AS_IF([test "x$enable_static" = "xyes"], [
    EXTRA_LDFLAGS="-static"
])

AC_ARG_ENABLE([tongchou],
    AS_HELP_STRING([--disable-tongchou], [Disable Tongchou (SM2/SM3/SM4) cipher support even if available]),
    [enable_tongchou=$enableval],
    [enable_tongchou=yes])

if test "x$enable_tongchou" = "xno"; then
    AC_DEFINE([DISABLE_TONGCHOU], [1], [Disable Tongchou support even if available])
fi

dnl BSI TR-02102-2 strict mode - only BSI/NIS2 compliant ciphers
AC_ARG_ENABLE([bsi-strict],
    AS_HELP_STRING([--enable-bsi-strict], [Enable BSI TR-02102-2 strict mode (no legacy ciphers, no SHA-1)]),
    [enable_bsi_strict=$enableval],
    [enable_bsi_strict=no])

if test "x$enable_bsi_strict" = "xyes"; then
    AC_DEFINE([BSI_STRICT_MODE], [1], [Enable BSI TR-02102-2 strict cipher mode])
    AC_MSG_NOTICE([BSI TR-02102-2 strict mode enabled - legacy ciphers disabled])
fi

dnl Check for Brainpool curve support (BSI recommended)
AC_MSG_CHECKING([for Brainpool elliptic curve support (BSI)])
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[
        #include <openssl/ec.h>
        #include <openssl/obj_mac.h>
    ]], [[
        EC_KEY *key = EC_KEY_new_by_curve_name(NID_brainpoolP256r1);
        if (key) EC_KEY_free(key);
        return key ? 0 : 1;
    ]])],
    [
        AC_MSG_RESULT([yes])
        AC_DEFINE([HAVE_BRAINPOOL], [1], [Define if OpenSSL has Brainpool curve support])
        have_brainpool=yes
    ],
    [
        AC_MSG_RESULT([no])
        have_brainpool=no
    ])

dnl Check for X448 curve support
AC_MSG_CHECKING([for X448 curve support])
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[
        #include <openssl/evp.h>
    ]], [[
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X448, NULL);
        if (ctx) EVP_PKEY_CTX_free(ctx);
        return ctx ? 0 : 1;
    ]])],
    [
        AC_MSG_RESULT([yes])
        AC_DEFINE([HAVE_X448], [1], [Define if OpenSSL has X448 support])
        have_x448=yes
    ],
    [
        AC_MSG_RESULT([no])
        have_x448=no
    ])

case "${host_os}" in
    darwin*)
        EXTRA_LDFLAGS+=" -Wl,-dead_strip"
        ;;
    linux* | *)
        EXTRA_LDFLAGS+=" -Wl,--gc-sections -s"
        ;;
esac

AC_SUBST([EXTRA_LDFLAGS])

AC_CONFIG_FILES([
 Makefile
])
AC_OUTPUT

dnl Summary
AC_MSG_NOTICE([])
AC_MSG_NOTICE([pixelserv-tls configuration summary:])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([  Event loop backends (priority order):])
AC_MSG_NOTICE([    io_uring (Linux 5.1+): ${have_io_uring:-no}])
AC_MSG_NOTICE([    epoll (Linux):         ${have_epoll:-no}])
AC_MSG_NOTICE([    kqueue (BSD/macOS):    ${have_kqueue:-no}])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([  TLS 1.3 support:      ${have_tls13:-check header}])
AC_MSG_NOTICE([  CHACHA20-POLY1305:    ${have_chacha:-check result}])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([  BSI TR-02102-2 / NIS2 compliance:])
AC_MSG_NOTICE([    Brainpool curves:   ${have_brainpool:-no}])
AC_MSG_NOTICE([    X448 curve:         ${have_x448:-no}])
AC_MSG_NOTICE([    BSI strict mode:    ${enable_bsi_strict:-no}])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([  Tongchou (Chinese GM/T) support:])
AC_MSG_NOTICE([    SM2 (EC):           ${have_sm2:-no}])
AC_MSG_NOTICE([    SM3 (Hash):         ${have_sm3:-no}])
AC_MSG_NOTICE([    SM4 (Cipher):       ${have_sm4:-no}])
AC_MSG_NOTICE([])
