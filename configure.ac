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
                CFLAGS="$CFLAGS -O3 -DNDEBUG";
                CXXFLAGS="$CXXFLAGS -O3 -DNDEBUG";
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

# Checks for library functions.

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
