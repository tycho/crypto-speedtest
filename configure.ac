# $Id$ -*- mode: autoconf -*-

AC_PREREQ(2.59)
AC_INIT(crypto-speedtest, 0.1)
AC_CONFIG_SRCDIR(src/speedtest.cpp)
AC_CONFIG_AUX_DIR(acscripts)
AC_CANONICAL_HOST

AM_INIT_AUTOMAKE(foreign)
# AM_MAINTAINER_MODE

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

AM_PATH_LIBGCRYPT([1.4.0], [],
    AC_MSG_ERROR([
*** Could not find a suitable version of the libgcrypt library! ***
*** Install the libgcrypt-dev package or use the source from http://www.gnupg.org ***]))

AM_PATH_LIBMCRYPT([2.5.8], [],
    AC_MSG_ERROR([
*** Could not find a suitable version of the libmcrypt library! ***
*** Install the libmcrypt-dev package or use the source from http://mcrypt.sourceforge.net ***]))

AC_PATH_GENERIC(botan, [1.6.1], [],
    AC_MSG_ERROR([
*** Could not find a suitable version of the Botan library! ***
*** Install the libbotan-dev package or use the source from http://botan.randombit.net ***]))

m4_include(cryptopp.m4)
AM_OPTIONS_CRYPTO
CHECK_CRYPTO(5.5)

case "$CRYPTO_PP_STYLE" in
    gentoo_debian | installed | sources)
	;;
    *) AC_MSG_ERROR([
*** Could not find a suitable version of the Crypto++ library! ***
*** Install the libbotan-dev package or use the source from http://www.cryptopp.com ***])
	;;
esac

# Output Makefiles

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
