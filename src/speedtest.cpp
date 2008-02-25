// $Id$

#include <assert.h>
#include <stdint.h>
#include <sys/time.h>

#include <vector>
#include <map>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <numeric>
#include <cmath>

#include <gcrypt.h>

#include <mcrypt.h>

#include <botan/botan.h>
#include <botan/aes.h>
#include <botan/serpent.h>
#include <botan/twofish.h>
#include <botan/cast256.h>
#include <botan/gost.h>
#include <botan/xtea.h>
#include <botan/blowfish.h>
#include <botan/cast128.h>
#include <botan/des.h>

#include <crypto++/modes.h>
#include <crypto++/rijndael.h>
#include <crypto++/serpent.h>
#include <crypto++/twofish.h>
#include <crypto++/camellia.h>
#include <crypto++/cast.h>
#include <crypto++/gost.h>
#include <crypto++/tea.h>
#include <crypto++/blowfish.h>
#include <crypto++/des.h>

#define NCOMPAT
#include <openssl/aes.h>
#include <openssl/cast.h>
#include <openssl/blowfish.h>
#include <openssl/des.h>

#include "rijndael.h"

// *** Speedtest Parameters ***

// speed test different buffer sizes in this range
const unsigned int buffermin = 16;
const unsigned int buffermax = 16 * 65536;
const unsigned int repeatsize = 65536;
const unsigned int measureruns = 1;

/// Time is measured using gettimeofday()
inline double timestamp()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec * 0.000001;
}

// *** Global Buffers and Settings for the Speedtest Functions ***

char	enckey[32];	/// 256 bit encryption key
char	enciv[16];	/// 16 byte initialization vector if needed.

char	buffer[buffermax];	/// encryption buffer
unsigned int bufferlen;		/// currently tested buffer length

// *** Test Functions for libgcrypt ***

void test_libgcrypt_rijndael_ecb()
{
    gcry_cipher_hd_t encctx;
    gcry_cipher_open(&encctx, GCRY_CIPHER_RIJNDAEL256, GCRY_CIPHER_MODE_ECB, 0);
    gcry_cipher_setkey(encctx, (uint8_t*)enckey, 32);
    gcry_cipher_encrypt(encctx, buffer, bufferlen, buffer, bufferlen);
    gcry_cipher_close(encctx);

    gcry_cipher_hd_t decctx;
    gcry_cipher_open(&decctx, GCRY_CIPHER_RIJNDAEL256, GCRY_CIPHER_MODE_ECB, 0);
    gcry_cipher_setkey(decctx, (uint8_t*)enckey, 32);
    gcry_cipher_decrypt(decctx, buffer, bufferlen, buffer, bufferlen);
    gcry_cipher_close(decctx);
}

void test_libgcrypt_serpent_ecb()
{
    gcry_cipher_hd_t encctx;
    gcry_cipher_open(&encctx, GCRY_CIPHER_SERPENT256, GCRY_CIPHER_MODE_ECB, 0);
    gcry_cipher_setkey(encctx, (uint8_t*)enckey, 32);
    gcry_cipher_encrypt(encctx, buffer, bufferlen, buffer, bufferlen);
    gcry_cipher_close(encctx);

    gcry_cipher_hd_t decctx;
    gcry_cipher_open(&decctx, GCRY_CIPHER_SERPENT256, GCRY_CIPHER_MODE_ECB, 0);
    gcry_cipher_setkey(decctx, (uint8_t*)enckey, 32);
    gcry_cipher_decrypt(decctx, buffer, bufferlen, buffer, bufferlen);
    gcry_cipher_close(decctx);
}

void test_libgcrypt_camellia_ecb()
{
    gcry_cipher_hd_t encctx;
    gcry_cipher_open(&encctx, GCRY_CIPHER_CAMELLIA256, GCRY_CIPHER_MODE_ECB, 0);
    gcry_cipher_setkey(encctx, (uint8_t*)enckey, 32);
    gcry_cipher_encrypt(encctx, buffer, bufferlen, buffer, bufferlen);
    gcry_cipher_close(encctx);

    gcry_cipher_hd_t decctx;
    gcry_cipher_open(&decctx, GCRY_CIPHER_CAMELLIA256, GCRY_CIPHER_MODE_ECB, 0);
    gcry_cipher_setkey(decctx, (uint8_t*)enckey, 32);
    gcry_cipher_decrypt(decctx, buffer, bufferlen, buffer, bufferlen);
    gcry_cipher_close(decctx);
}

void test_libgcrypt_twofish_ecb()
{
    gcry_cipher_hd_t encctx;
    gcry_cipher_open(&encctx, GCRY_CIPHER_TWOFISH, GCRY_CIPHER_MODE_ECB, 0);
    gcry_cipher_setkey(encctx, (uint8_t*)enckey, 32);
    gcry_cipher_encrypt(encctx, buffer, bufferlen, buffer, bufferlen);
    gcry_cipher_close(encctx);

    gcry_cipher_hd_t decctx;
    gcry_cipher_open(&decctx, GCRY_CIPHER_TWOFISH, GCRY_CIPHER_MODE_ECB, 0);
    gcry_cipher_setkey(decctx, (uint8_t*)enckey, 32);
    gcry_cipher_decrypt(decctx, buffer, bufferlen, buffer, bufferlen);
    gcry_cipher_close(decctx);
}

void test_libgcrypt_blowfish_ecb()
{
    gcry_cipher_hd_t encctx;
    gcry_cipher_open(&encctx, GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_ECB, 0);
    gcry_cipher_setkey(encctx, (uint8_t*)enckey, 16);
    gcry_cipher_encrypt(encctx, buffer, bufferlen, buffer, bufferlen);
    gcry_cipher_close(encctx);

    gcry_cipher_hd_t decctx;
    gcry_cipher_open(&decctx, GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_ECB, 0);
    gcry_cipher_setkey(decctx, (uint8_t*)enckey, 16);
    gcry_cipher_decrypt(decctx, buffer, bufferlen, buffer, bufferlen);
    gcry_cipher_close(decctx);
}

void test_libgcrypt_cast5_ecb()
{
    gcry_cipher_hd_t encctx;
    gcry_cipher_open(&encctx, GCRY_CIPHER_CAST5, GCRY_CIPHER_MODE_ECB, 0);
    gcry_cipher_setkey(encctx, (uint8_t*)enckey, 16);
    gcry_cipher_encrypt(encctx, buffer, bufferlen, buffer, bufferlen);
    gcry_cipher_close(encctx);

    gcry_cipher_hd_t decctx;
    gcry_cipher_open(&decctx, GCRY_CIPHER_CAST5, GCRY_CIPHER_MODE_ECB, 0);
    gcry_cipher_setkey(decctx, (uint8_t*)enckey, 16);
    gcry_cipher_decrypt(decctx, buffer, bufferlen, buffer, bufferlen);
    gcry_cipher_close(decctx);
}

void test_libgcrypt_3des_ecb()
{
    gcry_cipher_hd_t encctx;
    gcry_cipher_open(&encctx, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_ECB, 0);
    gcry_cipher_setkey(encctx, (uint8_t*)enckey, 24);
    gcry_cipher_encrypt(encctx, buffer, bufferlen, buffer, bufferlen);
    gcry_cipher_close(encctx);

    gcry_cipher_hd_t decctx;
    gcry_cipher_open(&decctx, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_ECB, 0);
    gcry_cipher_setkey(decctx, (uint8_t*)enckey, 24);
    gcry_cipher_decrypt(decctx, buffer, bufferlen, buffer, bufferlen);
    gcry_cipher_close(decctx);
}

// *** Test Functions for libmcrypt ***

void test_libmcrypt_rijndael_ecb()
{
    // note: MCRYPT_RIJNDAEL_128 means blocksize 128 _not_ keysize 128 bits

    MCRYPT encctx = mcrypt_module_open(MCRYPT_RIJNDAEL_128, NULL, MCRYPT_ECB, NULL);
    mcrypt_generic_init(encctx, enckey, 32, NULL);
    mcrypt_generic(encctx, buffer, bufferlen);
    mcrypt_generic_end(encctx);

    MCRYPT decctx = mcrypt_module_open(MCRYPT_RIJNDAEL_128, NULL, MCRYPT_ECB, NULL);
    mcrypt_generic_init(decctx, enckey, 32, NULL);
    mdecrypt_generic(decctx, buffer, bufferlen);
    mcrypt_generic_end(decctx);
}

void test_libmcrypt_serpent_ecb()
{
    MCRYPT encctx = mcrypt_module_open(MCRYPT_SERPENT, NULL, MCRYPT_ECB, NULL);
    mcrypt_generic_init(encctx, enckey, 32, NULL);
    mcrypt_generic(encctx, buffer, bufferlen);
    mcrypt_generic_end(encctx);

    MCRYPT decctx = mcrypt_module_open(MCRYPT_SERPENT, NULL, MCRYPT_ECB, NULL);
    mcrypt_generic_init(decctx, enckey, 32, NULL);
    mdecrypt_generic(decctx, buffer, bufferlen);
    mcrypt_generic_end(decctx);
}

void test_libmcrypt_twofish_ecb()
{
    MCRYPT encctx = mcrypt_module_open(MCRYPT_TWOFISH, NULL, MCRYPT_ECB, NULL);
    mcrypt_generic_init(encctx, enckey, 32, NULL);
    mcrypt_generic(encctx, buffer, bufferlen);
    mcrypt_generic_end(encctx);

    MCRYPT decctx = mcrypt_module_open(MCRYPT_TWOFISH, NULL, MCRYPT_ECB, NULL);
    mcrypt_generic_init(decctx, enckey, 32, NULL);
    mdecrypt_generic(decctx, buffer, bufferlen);
    mcrypt_generic_end(decctx);
}

void test_libmcrypt_cast6_ecb()
{
    MCRYPT encctx = mcrypt_module_open(MCRYPT_CAST_256, NULL, MCRYPT_ECB, NULL);
    mcrypt_generic_init(encctx, enckey, 32, NULL);
    mcrypt_generic(encctx, buffer, bufferlen);
    mcrypt_generic_end(encctx);

    MCRYPT decctx = mcrypt_module_open(MCRYPT_CAST_256, NULL, MCRYPT_ECB, NULL);
    mcrypt_generic_init(decctx, enckey, 32, NULL);
    mdecrypt_generic(decctx, buffer, bufferlen);
    mcrypt_generic_end(decctx);
}

void test_libmcrypt_xtea_ecb()
{
    MCRYPT encctx = mcrypt_module_open(MCRYPT_XTEA, NULL, MCRYPT_ECB, NULL);
    mcrypt_generic_init(encctx, enckey, 16, NULL);
    mcrypt_generic(encctx, buffer, bufferlen);
    mcrypt_generic_end(encctx);

    MCRYPT decctx = mcrypt_module_open(MCRYPT_XTEA, NULL, MCRYPT_ECB, NULL);
    mcrypt_generic_init(decctx, enckey, 16, NULL);
    mdecrypt_generic(decctx, buffer, bufferlen);
    mcrypt_generic_end(decctx);
}

void test_libmcrypt_saferplus_ecb()
{
    MCRYPT encctx = mcrypt_module_open(MCRYPT_SAFERPLUS, NULL, MCRYPT_ECB, NULL);
    mcrypt_generic_init(encctx, enckey, 32, NULL);
    mcrypt_generic(encctx, buffer, bufferlen);
    mcrypt_generic_end(encctx);

    MCRYPT decctx = mcrypt_module_open(MCRYPT_SAFERPLUS, NULL, MCRYPT_ECB, NULL);
    mcrypt_generic_init(decctx, enckey, 32, NULL);
    mdecrypt_generic(decctx, buffer, bufferlen);
    mcrypt_generic_end(decctx);
}

void test_libmcrypt_loki97_ecb()
{
    MCRYPT encctx = mcrypt_module_open(MCRYPT_LOKI97, NULL, MCRYPT_ECB, NULL);
    mcrypt_generic_init(encctx, enckey, 32, NULL);
    mcrypt_generic(encctx, buffer, bufferlen);
    mcrypt_generic_end(encctx);

    MCRYPT decctx = mcrypt_module_open(MCRYPT_LOKI97, NULL, MCRYPT_ECB, NULL);
    mcrypt_generic_init(decctx, enckey, 32, NULL);
    mdecrypt_generic(decctx, buffer, bufferlen);
    mcrypt_generic_end(decctx);
}

void test_libmcrypt_blowfish_ecb()
{
    MCRYPT encctx = mcrypt_module_open(MCRYPT_BLOWFISH, NULL, MCRYPT_ECB, NULL);
    mcrypt_generic_init(encctx, enckey, 32, NULL);
    mcrypt_generic(encctx, buffer, bufferlen);
    mcrypt_generic_end(encctx);

    MCRYPT decctx = mcrypt_module_open(MCRYPT_BLOWFISH, NULL, MCRYPT_ECB, NULL);
    mcrypt_generic_init(decctx, enckey, 32, NULL);
    mdecrypt_generic(decctx, buffer, bufferlen);
    mcrypt_generic_end(decctx);
}

void test_libmcrypt_gost_ecb()
{
    MCRYPT encctx = mcrypt_module_open(MCRYPT_GOST, NULL, MCRYPT_ECB, NULL);
    mcrypt_generic_init(encctx, enckey, 32, NULL);
    mcrypt_generic(encctx, buffer, bufferlen);
    mcrypt_generic_end(encctx);

    MCRYPT decctx = mcrypt_module_open(MCRYPT_GOST, NULL, MCRYPT_ECB, NULL);
    mcrypt_generic_init(decctx, enckey, 32, NULL);
    mdecrypt_generic(decctx, buffer, bufferlen);
    mcrypt_generic_end(decctx);
}

void test_libmcrypt_cast5_ecb()
{
    MCRYPT encctx = mcrypt_module_open(MCRYPT_CAST_128, NULL, MCRYPT_ECB, NULL);
    mcrypt_generic_init(encctx, enckey, 16, NULL);
    mcrypt_generic(encctx, buffer, bufferlen);
    mcrypt_generic_end(encctx);

    MCRYPT decctx = mcrypt_module_open(MCRYPT_CAST_128, NULL, MCRYPT_ECB, NULL);
    mcrypt_generic_init(decctx, enckey, 16, NULL);
    mdecrypt_generic(decctx, buffer, bufferlen);
    mcrypt_generic_end(decctx);
}

void test_libmcrypt_3des_ecb()
{
    MCRYPT encctx = mcrypt_module_open(MCRYPT_3DES, NULL, MCRYPT_ECB, NULL);
    mcrypt_generic_init(encctx, enckey, 24, NULL);
    mcrypt_generic(encctx, buffer, bufferlen);
    mcrypt_generic_end(encctx);

    MCRYPT decctx = mcrypt_module_open(MCRYPT_3DES, NULL, MCRYPT_ECB, NULL);
    mcrypt_generic_init(decctx, enckey, 24, NULL);
    mdecrypt_generic(decctx, buffer, bufferlen);
    mcrypt_generic_end(decctx);
}

// *** Test Functions for Botan ***

void test_botan_rijndael_ecb()
{
    Botan::AES_256 encctx;
    encctx.set_key((Botan::byte*)enckey, 32);

    for(unsigned int p = 0; p < bufferlen; p += encctx.BLOCK_SIZE)
	encctx.encrypt((Botan::byte*)buffer + p);

    Botan::AES_256 decctx;
    decctx.set_key((Botan::byte*)enckey, 32);

    for(unsigned int p = 0; p < bufferlen; p += decctx.BLOCK_SIZE)
	decctx.decrypt((Botan::byte*)buffer + p);
}

void test_botan_serpent_ecb()
{
    Botan::Serpent encctx;
    encctx.set_key((Botan::byte*)enckey, 32);

    for(unsigned int p = 0; p < bufferlen; p += encctx.BLOCK_SIZE)
	encctx.encrypt((Botan::byte*)buffer + p);

    Botan::Serpent decctx;
    decctx.set_key((Botan::byte*)enckey, 32);

    for(unsigned int p = 0; p < bufferlen; p += decctx.BLOCK_SIZE)
	decctx.decrypt((Botan::byte*)buffer + p);
}

void test_botan_twofish_ecb()
{
    Botan::Twofish encctx;
    encctx.set_key((Botan::byte*)enckey, 32);

    for(unsigned int p = 0; p < bufferlen; p += encctx.BLOCK_SIZE)
	encctx.encrypt((Botan::byte*)buffer + p);

    Botan::Twofish decctx;
    decctx.set_key((Botan::byte*)enckey, 32);

    for(unsigned int p = 0; p < bufferlen; p += decctx.BLOCK_SIZE)
	decctx.decrypt((Botan::byte*)buffer + p);
}

void test_botan_cast6_ecb()
{
    Botan::CAST_256 encctx;
    encctx.set_key((Botan::byte*)enckey, 32);

    for(unsigned int p = 0; p < bufferlen; p += encctx.BLOCK_SIZE)
	encctx.encrypt((Botan::byte*)buffer + p);

    Botan::CAST_256 decctx;
    decctx.set_key((Botan::byte*)enckey, 32);

    for(unsigned int p = 0; p < bufferlen; p += decctx.BLOCK_SIZE)
	decctx.decrypt((Botan::byte*)buffer + p);
}

void test_botan_gost_ecb()
{
    Botan::GOST encctx;
    encctx.set_key((Botan::byte*)enckey, 32);

    for(unsigned int p = 0; p < bufferlen; p += encctx.BLOCK_SIZE)
	encctx.encrypt((Botan::byte*)buffer + p);

    Botan::GOST decctx;
    decctx.set_key((Botan::byte*)enckey, 32);

    for(unsigned int p = 0; p < bufferlen; p += decctx.BLOCK_SIZE)
	decctx.decrypt((Botan::byte*)buffer + p);
}

void test_botan_xtea_ecb()
{
    Botan::XTEA encctx;
    encctx.set_key((Botan::byte*)enckey, 16);

    for(unsigned int p = 0; p < bufferlen; p += encctx.BLOCK_SIZE)
	encctx.encrypt((Botan::byte*)buffer + p);

    Botan::XTEA decctx;
    decctx.set_key((Botan::byte*)enckey, 16);

    for(unsigned int p = 0; p < bufferlen; p += decctx.BLOCK_SIZE)
	decctx.decrypt((Botan::byte*)buffer + p);
}

void test_botan_blowfish_ecb()
{
    Botan::Blowfish encctx;
    encctx.set_key((Botan::byte*)enckey, 16);

    for(unsigned int p = 0; p < bufferlen; p += encctx.BLOCK_SIZE)
	encctx.encrypt((Botan::byte*)buffer + p);

    Botan::Blowfish decctx;
    decctx.set_key((Botan::byte*)enckey, 16);

    for(unsigned int p = 0; p < bufferlen; p += decctx.BLOCK_SIZE)
	decctx.decrypt((Botan::byte*)buffer + p);
}

void test_botan_cast5_ecb()
{
    Botan::CAST_128 encctx;
    encctx.set_key((Botan::byte*)enckey, 16);

    for(unsigned int p = 0; p < bufferlen; p += encctx.BLOCK_SIZE)
	encctx.encrypt((Botan::byte*)buffer + p);

    Botan::CAST_128 decctx;
    decctx.set_key((Botan::byte*)enckey, 16);

    for(unsigned int p = 0; p < bufferlen; p += decctx.BLOCK_SIZE)
	decctx.decrypt((Botan::byte*)buffer + p);
}

void test_botan_3des_ecb()
{
    Botan::TripleDES encctx;
    encctx.set_key((Botan::byte*)enckey, 16);

    for(unsigned int p = 0; p < bufferlen; p += encctx.BLOCK_SIZE)
	encctx.encrypt((Botan::byte*)buffer + p);

    Botan::TripleDES decctx;
    decctx.set_key((Botan::byte*)enckey, 16);

    for(unsigned int p = 0; p < bufferlen; p += decctx.BLOCK_SIZE)
	decctx.decrypt((Botan::byte*)buffer + p);
}

// *** Test Functions for Crypto++ ***

void test_cryptopp_rijndael_ecb()
{
    CryptoPP::ECB_Mode<CryptoPP::Rijndael>::Encryption encctx;
    encctx.SetKey((byte*)enckey, 32);
    encctx.ProcessData((byte*)buffer, (byte*)buffer, bufferlen);

    CryptoPP::ECB_Mode<CryptoPP::Rijndael>::Decryption decctx;
    decctx.SetKey((byte*)enckey, 32);
    decctx.ProcessData((byte*)buffer, (byte*)buffer, bufferlen);
}

void test_cryptopp_serpent_ecb()
{
    CryptoPP::ECB_Mode<CryptoPP::Serpent>::Encryption encctx;
    encctx.SetKey((byte*)enckey, 32);
    encctx.ProcessData((byte*)buffer, (byte*)buffer, bufferlen);

    CryptoPP::ECB_Mode<CryptoPP::Serpent>::Decryption decctx;
    decctx.SetKey((byte*)enckey, 32);
    decctx.ProcessData((byte*)buffer, (byte*)buffer, bufferlen);
}

void test_cryptopp_twofish_ecb()
{
    CryptoPP::ECB_Mode<CryptoPP::Twofish>::Encryption encctx;
    encctx.SetKey((byte*)enckey, 32);
    encctx.ProcessData((byte*)buffer, (byte*)buffer, bufferlen);

    CryptoPP::ECB_Mode<CryptoPP::Twofish>::Decryption decctx;
    decctx.SetKey((byte*)enckey, 32);
    decctx.ProcessData((byte*)buffer, (byte*)buffer, bufferlen);
}

void test_cryptopp_camellia_ecb()
{
    CryptoPP::ECB_Mode<CryptoPP::Camellia>::Encryption encctx;
    encctx.SetKey((byte*)enckey, 32);
    encctx.ProcessData((byte*)buffer, (byte*)buffer, bufferlen);

    CryptoPP::ECB_Mode<CryptoPP::Camellia>::Decryption decctx;
    decctx.SetKey((byte*)enckey, 32);
    decctx.ProcessData((byte*)buffer, (byte*)buffer, bufferlen);
}

void test_cryptopp_cast6_ecb()
{
    CryptoPP::ECB_Mode<CryptoPP::CAST256>::Encryption encctx;
    encctx.SetKey((byte*)enckey, 32);
    encctx.ProcessData((byte*)buffer, (byte*)buffer, bufferlen);

    CryptoPP::ECB_Mode<CryptoPP::CAST256>::Decryption decctx;
    decctx.SetKey((byte*)enckey, 32);
    decctx.ProcessData((byte*)buffer, (byte*)buffer, bufferlen);
}

void test_cryptopp_gost_ecb()
{
    CryptoPP::ECB_Mode<CryptoPP::GOST>::Encryption encctx;
    encctx.SetKey((byte*)enckey, 32);
    encctx.ProcessData((byte*)buffer, (byte*)buffer, bufferlen);

    CryptoPP::ECB_Mode<CryptoPP::GOST>::Decryption decctx;
    decctx.SetKey((byte*)enckey, 32);
    decctx.ProcessData((byte*)buffer, (byte*)buffer, bufferlen);
}

void test_cryptopp_xtea_ecb()
{
    CryptoPP::ECB_Mode<CryptoPP::XTEA>::Encryption encctx;
    encctx.SetKey((byte*)enckey, 16);
    encctx.ProcessData((byte*)buffer, (byte*)buffer, bufferlen);

    CryptoPP::ECB_Mode<CryptoPP::XTEA>::Decryption decctx;
    decctx.SetKey((byte*)enckey, 16);
    decctx.ProcessData((byte*)buffer, (byte*)buffer, bufferlen);
}

void test_cryptopp_blowfish_ecb()
{
    CryptoPP::ECB_Mode<CryptoPP::Blowfish>::Encryption encctx;
    encctx.SetKey((byte*)enckey, 16);
    encctx.ProcessData((byte*)buffer, (byte*)buffer, bufferlen);

    CryptoPP::ECB_Mode<CryptoPP::Blowfish>::Decryption decctx;
    decctx.SetKey((byte*)enckey, 16);
    decctx.ProcessData((byte*)buffer, (byte*)buffer, bufferlen);
}

void test_cryptopp_cast5_ecb()
{
    CryptoPP::ECB_Mode<CryptoPP::CAST128>::Encryption encctx;
    encctx.SetKey((byte*)enckey, 16);
    encctx.ProcessData((byte*)buffer, (byte*)buffer, bufferlen);

    CryptoPP::ECB_Mode<CryptoPP::CAST128>::Decryption decctx;
    decctx.SetKey((byte*)enckey, 16);
    decctx.ProcessData((byte*)buffer, (byte*)buffer, bufferlen);
}

void test_cryptopp_3des_ecb()
{
    CryptoPP::ECB_Mode<CryptoPP::DES_EDE3>::Encryption encctx;
    encctx.SetKey((byte*)enckey, 24);
    encctx.ProcessData((byte*)buffer, (byte*)buffer, bufferlen);

    CryptoPP::ECB_Mode<CryptoPP::DES_EDE3>::Decryption decctx;
    decctx.SetKey((byte*)enckey, 24);
    decctx.ProcessData((byte*)buffer, (byte*)buffer, bufferlen);
}

// *** Test Functions for OpenSSL ***

void test_openssl_rijndael_ecb()
{
    AES_KEY encctx;
    AES_set_encrypt_key((byte*)enckey, 256, &encctx);

    for(unsigned int p = 0; p < bufferlen; p += AES_BLOCK_SIZE)
	AES_encrypt((byte*)buffer + p, (byte*)buffer + p, &encctx);

    AES_KEY decctx;
    AES_set_decrypt_key((byte*)enckey, 256, &decctx);

    for(unsigned int p = 0; p < bufferlen; p += AES_BLOCK_SIZE)
	AES_decrypt((byte*)buffer + p, (byte*)buffer + p, &decctx);
}

void test_openssl_cast5_ecb()
{
    CAST_KEY encctx;
    CAST_set_key(&encctx, 16, (byte*)enckey);

    for(unsigned int p = 0; p < bufferlen; p += CAST_BLOCK)
	CAST_encrypt((CAST_LONG*)(buffer + p), &encctx);

    CAST_KEY decctx;
    CAST_set_key(&decctx, 16, (byte*)enckey);

    for(unsigned int p = 0; p < bufferlen; p += CAST_BLOCK)
	CAST_decrypt((CAST_LONG*)(buffer + p), &decctx);
}

void test_openssl_blowfish_ecb()
{
    BF_KEY encctx;
    BF_set_key(&encctx, 16, (byte*)enckey);

    for(unsigned int p = 0; p < bufferlen; p += BF_BLOCK)
	BF_encrypt((BF_LONG*)(buffer + p), &encctx);

    BF_KEY decctx;
    BF_set_key(&decctx, 16, (byte*)enckey);

    for(unsigned int p = 0; p < bufferlen; p += BF_BLOCK)
	BF_decrypt((BF_LONG*)(buffer + p), &decctx);
}

void test_openssl_3des_ecb()
{
    DES_key_schedule eks1, eks2, eks3;

    DES_set_key((DES_cblock*)(enckey +  0), &eks1);
    DES_set_key((DES_cblock*)(enckey +  8), &eks2);
    DES_set_key((DES_cblock*)(enckey + 16), &eks3);

    for(unsigned int p = 0; p < bufferlen; p += 8)
	DES_encrypt3((DES_LONG*)(buffer + p), &eks1, &eks2, &eks3);

    DES_key_schedule dks1, dks2, dks3;

    DES_set_key((DES_cblock*)(enckey +  0), &dks1);
    DES_set_key((DES_cblock*)(enckey +  8), &dks2);
    DES_set_key((DES_cblock*)(enckey + 16), &dks3);

    for(unsigned int p = 0; p < bufferlen; p += 8)
	DES_decrypt3((DES_LONG*)(buffer + p), &dks1, &dks2, &dks3);
}

// *** Test Functions for My Implementation ***

void test_my_rijndael_ecb()
{
    RijndaelEncryptECB encctx;
    encctx.set_key((byte*)enckey, 32);
    encctx.encrypt(buffer, buffer, bufferlen);

    RijndaelDecryptECB decctx;
    decctx.set_key((byte*)enckey, 32);
    decctx.decrypt(buffer, buffer, bufferlen);
}

// *** main() and run_test() ***

/**
 * This function will run a test routine multiple times with different buffer
 * sizes configured. It measures the time required to encrypt a number of
 * bytes. The average time and standard deviation are calculated and written to
 * a log file for gnuplot.
 */

template <void (*testfunc)()>
void run_test(const char* logfile)
{
    std::cout << "Speed testing for " << logfile << "\n";

    // Save the time required for each run.
    std::map<unsigned int, std::vector<double> > timelog;

    for(unsigned int fullrun = 0; fullrun < measureruns; ++fullrun)
    {
	for(unsigned int bufflen = buffermin; bufflen <= buffermax; bufflen *= 2)
	{
	    // because small time measurements are inaccurate, repeat very fast
	    // tests until the same amount of data is encrypted as in the large
	    // tests.
	    unsigned int repeat = repeatsize / bufflen;
	    if (repeat < 1) repeat = 1;

	    std::cout << "Test: bufflen " << bufflen << " repeat " << repeat << "\n";

	    bufferlen = bufflen;

	    // fill buffer
	    for(unsigned int i = 0; i < bufferlen; ++i)
		buffer[i] = (char)i;

	    double ts1 = timestamp();

	    for(unsigned int testrun = 0; testrun < repeat; ++testrun)
	    {
		testfunc();
	    }

	    double ts2 = timestamp();

	    // check buffer status after repeated en/decryption
	    for(unsigned int i = 0; i < bufferlen; ++i)
		assert(buffer[i] == (char)i);

	    timelog[bufferlen].push_back( (ts2 - ts1) / (double)repeat );
	}
    }

    // Calculate and output statistics.
    std::ofstream of (logfile);

    for(std::map<unsigned int, std::vector<double> >::const_iterator ti = timelog.begin();
	ti != timelog.end(); ++ti)
    {
	const std::vector<double>& timelist = ti->second;

	double average = std::accumulate(timelist.begin(), timelist.end(), 0.0) / timelist.size();

	double variance = 0.0;
	for(unsigned int i = 0; i < timelist.size(); ++i)
	    variance += (timelist[i] - average) * (timelist[i] - average);
	variance = variance / (timelist.size() - 1);

	double stddev = std::sqrt(variance);

	if (timelist.size() == 1) { // only one run -> no variance or stddev
	    variance = stddev = 0.0;
	}

	double vmin = *std::min_element(timelist.begin(), timelist.end());
	double vmax = *std::max_element(timelist.begin(), timelist.end());

	of << std::setprecision(16);
	of << ti->first << " " << average << " " << stddev << " " << vmin << " " << vmax << "\n";
    }
}

int main()
{
    // Initialize all cryptographic libaries

    gcry_check_version(GCRYPT_VERSION);

    Botan::LibraryInitializer init;

    // Create (somewhat) random encryption key and initialization vector

    srand(time(NULL));

    for(unsigned int i = 0; i < sizeof(enckey); ++i)
	enckey[i] = rand();

    for(unsigned int i = 0; i < sizeof(enciv); ++i)
	enciv[i] = rand();

    // Run speed tests

#if 1
    run_test<test_libgcrypt_rijndael_ecb>("gcrypt-rijndael-ecb.txt");
    run_test<test_libgcrypt_serpent_ecb>("gcrypt-serpent-ecb.txt");
    run_test<test_libgcrypt_twofish_ecb>("gcrypt-twofish-ecb.txt");
    run_test<test_libgcrypt_camellia_ecb>("gcrypt-camellia-ecb.txt");
    run_test<test_libgcrypt_blowfish_ecb>("gcrypt-blowfish-ecb.txt");
    run_test<test_libgcrypt_cast5_ecb>("gcrypt-cast5-ecb.txt");
    run_test<test_libgcrypt_3des_ecb>("gcrypt-3des-ecb.txt");
#endif

#if 1
    run_test<test_libmcrypt_rijndael_ecb>("mcrypt-rijndael-ecb.txt");
    run_test<test_libmcrypt_serpent_ecb>("mcrypt-serpent-ecb.txt");
    run_test<test_libmcrypt_twofish_ecb>("mcrypt-twofish-ecb.txt");
    run_test<test_libmcrypt_cast6_ecb>("mcrypt-cast6-ecb.txt");
    run_test<test_libmcrypt_xtea_ecb>("mcrypt-xtea-ecb.txt");
    run_test<test_libmcrypt_saferplus_ecb>("mcrypt-saferplus-ecb.txt");
    run_test<test_libmcrypt_loki97_ecb>("mcrypt-loki97-ecb.txt");
    run_test<test_libmcrypt_blowfish_ecb>("mcrypt-blowfish-ecb.txt");
    run_test<test_libmcrypt_gost_ecb>("mcrypt-gost-ecb.txt");
    run_test<test_libmcrypt_cast5_ecb>("mcrypt-cast5-ecb.txt");
    run_test<test_libmcrypt_3des_ecb>("mcrypt-3des-ecb.txt");
#endif

#if 1
    run_test<test_botan_rijndael_ecb>("botan-rijndael-ecb.txt");
    run_test<test_botan_serpent_ecb>("botan-serpent-ecb.txt");
    run_test<test_botan_twofish_ecb>("botan-twofish-ecb.txt");
    run_test<test_botan_cast6_ecb>("botan-cast6-ecb.txt");
    run_test<test_botan_gost_ecb>("botan-gost-ecb.txt");
    run_test<test_botan_xtea_ecb>("botan-xtea-ecb.txt");
    run_test<test_botan_blowfish_ecb>("botan-blowfish-ecb.txt");
    run_test<test_botan_cast5_ecb>("botan-cast5-ecb.txt");
    run_test<test_botan_3des_ecb>("botan-3des-ecb.txt");
#endif

#if 1
    run_test<test_cryptopp_rijndael_ecb>("cryptopp-rijndael-ecb.txt");
    run_test<test_cryptopp_serpent_ecb>("cryptopp-serpent-ecb.txt");
    run_test<test_cryptopp_twofish_ecb>("cryptopp-twofish-ecb.txt");
    run_test<test_cryptopp_cast6_ecb>("cryptopp-cast6-ecb.txt");
    run_test<test_cryptopp_camellia_ecb>("cryptopp-camellia-ecb.txt");
    run_test<test_cryptopp_gost_ecb>("cryptopp-gost-ecb.txt");
    run_test<test_cryptopp_xtea_ecb>("cryptopp-xtea-ecb.txt");
    run_test<test_cryptopp_blowfish_ecb>("cryptopp-blowfish-ecb.txt");
    run_test<test_cryptopp_cast5_ecb>("cryptopp-cast5-ecb.txt");
    run_test<test_cryptopp_3des_ecb>("cryptopp-3des-ecb.txt");
#endif

#if 1
    run_test<test_openssl_rijndael_ecb>("openssl-rijndael-ecb.txt");
    run_test<test_openssl_cast5_ecb>("openssl-cast5-ecb.txt");
    run_test<test_openssl_blowfish_ecb>("openssl-blowfish-ecb.txt");
    run_test<test_openssl_3des_ecb>("openssl-3des-ecb.txt");
#endif

    run_test<test_my_rijndael_ecb>("my-rijndael-ecb.txt");
}
