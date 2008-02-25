# $Id$ -*- mode: autoconf -*-

AC_PREREQ(2.59)
AC_INIT(crypto-speedtest, 0.1)
AC_CONFIG_SRCDIR(src/speedtest_custom.cpp)
AC_CONFIG_AUX_DIR(acscripts)
AC_CANONICAL_HOST

AM_INIT_AUTOMAKE(foreign)
# AM_MAINTAINER_MODE

m4_include([m4/cryptopp.m4])
m4_include([m4/libmcrypt.m4])

# enable full optimization by configure switch
AC_ARG_ENABLE(optimize,
	AS_HELP_STRING([--enable-optimize],
		       [Build with full optimization @<:@default=no@:>@]),
        [ case "${enableval}" in
          yes)
                CFLAGS="$CFLAGS -O3";
                CXXFLAGS="$CXXFLAGS -O3";
          ;;
          no) ;;
          *) AC_MSG_ERROR(bad value ${enableval} for --enable-optimize) ;;
          esac ],
        [ optimize=false ])

# set debug info flag if no optimization flags are set.
if test "$CFLAGS" == ""; then
    CFLAGS="-g"
fi
if test "$CXXFLAGS" == ""; then
    CXXFLAGS="-g"
fi

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX

AC_LANG([C++])

# Check for libraries

# libgcrypt

AM_PATH_LIBGCRYPT([1.2.3])

AM_CONDITIONAL(HAVE_GCRYPT, test "$LIBGCRYPT_LIBS" != "")

if test "$LIBGCRYPT_LIBS" != ""; then
    AC_DEFINE(HAVE_LIBGCRYPT, 1)
fi

# libmcrypt

AM_PATH_LIBMCRYPT([2.5.7])

AM_CONDITIONAL(HAVE_MCRYPT, test "$LIBMCRYPT_LIBS" != "")

if test "$LIBMCRYPT_LIBS" != ""; then
    AC_DEFINE(HAVE_LIBMCRYPT, 1)
fi

# Botan

AC_PATH_GENERIC(botan, [1.6.0])

AM_CONDITIONAL(HAVE_BOTAN, test "$BOTAN_LIBS" != "")

if test "$BOTAN_LIBS" != ""; then
    AC_DEFINE(HAVE_BOTAN, 1)
fi

# Crypto++

AM_OPTIONS_CRYPTO
CHECK_CRYPTO(5.5)

AM_CONDITIONAL(HAVE_CRYPTOPP, test "$CRYPTO_PP_LIB_NAME" != "")

if test "$CRYPTO_PP_LIB_NAME" != ""; then
    AC_DEFINE(HAVE_CRYPTOPP, 1)
fi

# OpenSSL's crypto

PKG_CHECK_MODULES(OPENSSL, [libcrypto >= 0.9.8])

AM_CONDITIONAL(HAVE_OPENSSL, test "$OPENSSL_LIBS" != "")

if test "$OPENSSL_LIBS" != ""; then
    AC_DEFINE(HAVE_OPENSSL, 1)
fi

# Nettle

testflag_nettle=yes
AC_CHECK_HEADERS([nettle/aes.h])
AC_CHECK_LIB(nettle, [nettle_aes_encrypt], [], [testflag_nettle=no])

if test "$testflag_nettle" == "no"; then
    AC_MSG_NOTICE([
*** Could not find a suitable version of the nettle library! ***
*** Install the libnettle-dev package or use the source from http://www.lysator.liu.se/~nisse/nettle/ ***])
fi

AM_CONDITIONAL(HAVE_NETTLE, test "$testflag_nettle" == "yes")

# Beecrypt

testflag_beecrypt=yes
AC_CHECK_HEADERS([beecrypt/aes.h])
AC_CHECK_LIB(beecrypt, [aesSetup], [], [testflag_beecrypt=no])

if test "$testflag_beecrypt" == "no"; then
    AC_MSG_NOTICE([
*** Could not find a suitable version of the beecrypt library! ***
*** Install the libbeecrypt-dev package or use the source from http://beecrypt.sourceforge.net ***])
fi

AM_CONDITIONAL(HAVE_BEECRYPT, test "$testflag_beecrypt" == "yes")

# libtomcrypt

testflag_tomcrypt=yes
AC_CHECK_HEADERS([tomcrypt.h])
AC_CHECK_LIB(tomcrypt, [ecb_start], [], [testflag_tomcrypt=no])

if test "$testflag_tomcrypt" == "no"; then
    AC_MSG_NOTICE([
*** Could not find a suitable version of the libtomcrypt library! ***
*** Install the libtomcrypt-dev package or use the source from http://libtom.org ***])
fi

AM_CONDITIONAL(HAVE_TOMCRYPT, test "$testflag_tomcrypt" == "yes")

# Output Makefiles

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
