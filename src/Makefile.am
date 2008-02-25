# $Id$

TESTS = verify speedtest

noinst_PROGRAMS = verify speedtest

verify_SOURCES = verify.cpp

speedtest_SOURCES = speedtest.cpp

AM_CXXFLAGS = -W -Wall $(LIBGCRYPT_CFLAGS) $(LIBMCRYPT_CFLAGS) $(BOTAN_CFLAGS) $(CRYPTO_PP_CXXFLAGS)
LIBS = $(LIBGCRYPT_LIBS) $(LIBMCRYPT_LIBS) $(BOTAN_LIBS) $(CRYPTO_PP_LDFLAGS) -l$(CRYPTO_PP_LIB_NAME)
