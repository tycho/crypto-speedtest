# $Id$

TESTS = verify

noinst_PROGRAMS = speedtest_custom verify

speedtest_custom_SOURCES = speedtest_custom.cpp \
	rijndael.cpp rijndael.h \
	serpent-gladman.cpp serpent-gladman.h \
	serpent.h serpent.cpp

verify_SOURCES = verify.cpp \
	rijndael.h rijndael.cpp \
	serpent-gladman.h serpent-gladman.cpp \
	serpent.h serpent.cpp

AM_CXXFLAGS = -g -W -Wall -Wno-unused -O3 -momit-leaf-frame-pointer

verify_CXXFLAGS =
verify_LDADD =

if HAVE_GCRYPT
verify_CXXFLAGS += $(LIBGCRYPT_CFLAGS)
verify_LDADD += $(LIBGCRYPT_LIBS)
endif

if HAVE_MCRYPT
verify_CXXFLAGS += $(LIBMCRYPT_CFLAGS)
verify_LDADD += $(LIBMCRYPT_LIBS)
endif

if HAVE_BOTAN
verify_CXXFLAGS += $(BOTAN_CFLAGS)
verify_LDADD += $(BOTAN_LIBS)
endif

if HAVE_CRYPTOPP
verify_CXXFLAGS += $(CRYPTO_PP_CXXFLAGS)
verify_LDADD += $(CRYPTO_PP_LDFLAGS) -l$(CRYPTO_PP_LIB_NAME)
endif

if HAVE_OPENSSL
verify_CXXFLAGS += $(OPENSSL_CFLAGS)
verify_LDADD += $(OPENSSL_LIBS)
endif

if HAVE_NETTLE
verify_LDADD += $(LIBS)
endif

if HAVE_BEECRYPT
verify_LDADD += $(LIBS)
endif

if HAVE_TOMCRYPT
verify_LDADD += $(LIBS)
endif

if HAVE_GCRYPT

noinst_PROGRAMS += speedtest_gcrypt

speedtest_gcrypt_SOURCES = speedtest_gcrypt.cpp

speedtest_gcrypt_CXXFLAGS = $(LIBGCRYPT_CFLAGS)
speedtest_gcrypt_LDADD = $(LIBGCRYPT_LIBS)

endif

if HAVE_MCRYPT

noinst_PROGRAMS += speedtest_mcrypt

speedtest_mcrypt_SOURCES = speedtest_mcrypt.cpp

speedtest_mcrypt_CXXFLAGS = $(LIBMCRYPT_CFLAGS)
speedtest_mcrypt_LDADD = $(LIBMCRYPT_LIBS)

endif

if HAVE_BOTAN

noinst_PROGRAMS += speedtest_botan

speedtest_botan_SOURCES = speedtest_botan.cpp

speedtest_botan_CXXFLAGS = $(BOTAN_CFLAGS)
speedtest_botan_LDADD = $(BOTAN_LIBS)

endif

if HAVE_CRYPTOPP

noinst_PROGRAMS += speedtest_cryptopp

speedtest_cryptopp_SOURCES = speedtest_cryptopp.cpp

speedtest_cryptopp_CXXFLAGS = $(CRYPTO_PP_CXXFLAGS)
speedtest_cryptopp_LDADD = $(CRYPTO_PP_LDFLAGS) -l$(CRYPTO_PP_LIB_NAME)

endif

if HAVE_OPENSSL

noinst_PROGRAMS += speedtest_openssl

speedtest_openssl_SOURCES = speedtest_openssl.cpp

speedtest_openssl_CXXFLAGS = $(OPENSSL_CFLAGS)
speedtest_openssl_LDADD = $(OPENSSL_LIBS)

endif

if HAVE_NETTLE

noinst_PROGRAMS += speedtest_nettle

speedtest_nettle_SOURCES = speedtest_nettle.cpp

speedtest_nettle_LDADD = $(LIBS)

endif

if HAVE_BEECRYPT

noinst_PROGRAMS += speedtest_beecrypt

speedtest_beecrypt_SOURCES = speedtest_beecrypt.cpp

speedtest_beecrypt_LDADD = $(LIBS)

endif

if HAVE_TOMCRYPT

noinst_PROGRAMS += speedtest_tomcrypt

speedtest_tomcrypt_SOURCES = speedtest_tomcrypt.cpp

speedtest_tomcrypt_LDADD = $(LIBS)

endif

