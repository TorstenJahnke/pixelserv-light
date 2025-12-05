AC_INIT([pixelserv-tls], [2.4.1], [])
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
AC_MSG_NOTICE([  TLS 1.3 support:      ${have_tls13:-check header}])
AC_MSG_NOTICE([  CHACHA20-POLY1305:    ${have_chacha:-check result}])
AC_MSG_NOTICE([  Tongchou SM2:         ${have_sm2:-no}])
AC_MSG_NOTICE([  Tongchou SM3:         ${have_sm3:-no}])
AC_MSG_NOTICE([  Tongchou SM4:         ${have_sm4:-no}])
AC_MSG_NOTICE([])
