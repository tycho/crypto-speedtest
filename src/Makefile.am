# $Id$

TESTS = verify speedtest

noinst_PROGRAMS = verify speedtest

verify_SOURCES = verify.cpp \
	rijndael.h rijndael.cpp \
	serpent-gladman.h serpent-gladman.cpp

speedtest_SOURCES = speedtest.cpp \
	rijndael.h rijndael.cpp \
	serpent-gladman.h serpent-gladman.cpp

AM_CXXFLAGS = -g -W -Wall -Wno-unused -momit-leaf-frame-pointer \
	$(LIBGCRYPT_CFLAGS) $(LIBMCRYPT_CFLAGS) \
	$(BOTAN_CFLAGS) $(CRYPTO_PP_CXXFLAGS) \
	$(OPENSSL_CFLAGS)

LDADD = $(LIBS) $(LIBGCRYPT_LIBS) $(LIBMCRYPT_LIBS) \
	$(BOTAN_LIBS) \
	$(CRYPTO_PP_LDFLAGS) -l$(CRYPTO_PP_LIB_NAME) \
	$(OPENSSL_LIBS)
