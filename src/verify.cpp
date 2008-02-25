// $Id$

#include <iostream>
#include <fstream>
#include <sys/time.h>
#include <assert.h>
#include <map>
#include <vector>
#include <numeric>
#include <math.h>

#include <gcrypt.h>

#include <mcrypt.h>

#include <botan/botan.h>
#include <botan/aes.h>
#include <botan/serpent.h>

#include <crypto++/modes.h>
#include <crypto++/rijndael.h>
#include <crypto++/serpent.h>

// *** Verfication Parameters ***

const unsigned int bufferlen = 8192;

// *** Global Buffers and Settings for the Verify Functions ***

char enckey[32];

// *** Tool Functions to Fill, Check and Compare Buffers ***

void fill_buffer(char *buffer, unsigned int bufferlen)
{
    for(unsigned int i = 0; i < bufferlen; ++i)
	buffer[i] = (char)i;
}

void compare_buffers(char *buffer1, char* buffer2, unsigned int bufferlen)
{
    for(unsigned int i = 0; i < bufferlen; ++i)
	assert(buffer1[i] == buffer2[i]);
}

void check_buffer(char *buffer, unsigned int bufferlen)
{
    for(unsigned int i = 0; i < bufferlen; ++i)
	assert(buffer[i] == (char)i);
}

// *** Verify Rijndael Implementations

void verify_rijndael()
{
    // libgcrypt

    char buffer_gcrypt[bufferlen];
    fill_buffer(buffer_gcrypt, bufferlen);

    {
	gcry_cipher_hd_t encctx;
	gcry_cipher_open(&encctx, GCRY_CIPHER_RIJNDAEL256, GCRY_CIPHER_MODE_ECB, 0);
	gcry_cipher_setkey(encctx, (uint8_t*)enckey, 32);
	gcry_cipher_encrypt(encctx, buffer_gcrypt, bufferlen, buffer_gcrypt, bufferlen);
	gcry_cipher_close(encctx);
    }

    // libmcrypt

    char buffer_mcrypt[bufferlen];
    fill_buffer(buffer_mcrypt, bufferlen);

    {
	MCRYPT encctx = mcrypt_module_open(MCRYPT_RIJNDAEL_128, NULL, MCRYPT_ECB, NULL);
	mcrypt_generic_init(encctx, enckey, 32, NULL);
	mcrypt_generic(encctx, buffer_mcrypt, bufferlen);
	mcrypt_generic_end(encctx);
    }

    // Botan

    char buffer_botan[bufferlen];
    fill_buffer(buffer_botan, bufferlen);

    {
	Botan::AES_256 encctx;
	encctx.set_key((Botan::byte*)enckey, 32);

	for(unsigned int p = 0; p < bufferlen; p += encctx.BLOCK_SIZE) {
	    encctx.encrypt((Botan::byte*)buffer_botan + p);
	}
    }

    // Crypto++

    char buffer_cryptopp[bufferlen];
    fill_buffer(buffer_cryptopp, bufferlen);

    {
	CryptoPP::ECB_Mode<CryptoPP::Rijndael>::Encryption encctx;
	encctx.SetKey((byte*)enckey, 32);

	encctx.ProcessData((byte*)buffer_cryptopp, (byte*)buffer_cryptopp, bufferlen);
    }

    // compare buffers

    compare_buffers(buffer_gcrypt, buffer_mcrypt, bufferlen);
    compare_buffers(buffer_gcrypt, buffer_botan, bufferlen);
    compare_buffers(buffer_gcrypt, buffer_cryptopp, bufferlen);

    // libgcrypt

    {
	gcry_cipher_hd_t decctx;
	gcry_cipher_open(&decctx, GCRY_CIPHER_RIJNDAEL256, GCRY_CIPHER_MODE_ECB, 0);
	gcry_cipher_setkey(decctx, (uint8_t*)enckey, 32);
	gcry_cipher_decrypt(decctx, buffer_gcrypt, bufferlen, buffer_gcrypt, bufferlen);
	gcry_cipher_close(decctx);
    }

    // libmcrypt

    {
	MCRYPT decctx = mcrypt_module_open(MCRYPT_RIJNDAEL_128, NULL, MCRYPT_ECB, NULL);
	mcrypt_generic_init(decctx, enckey, 32, NULL);
	mdecrypt_generic(decctx, buffer_mcrypt, bufferlen);
	mcrypt_generic_end(decctx);
    }

    // Botan

    {
	Botan::AES_256 decctx;
	decctx.set_key((Botan::byte*)enckey, 32);

	for(unsigned int p = 0; p < bufferlen; p += decctx.BLOCK_SIZE) {
	    decctx.decrypt((Botan::byte*)buffer_botan + p);
	}
    }

    // Crypto++

    {
	CryptoPP::ECB_Mode<CryptoPP::Rijndael>::Decryption decctx;
	decctx.SetKey((byte*)enckey, 32);

	decctx.ProcessData((byte*)buffer_cryptopp, (byte*)buffer_cryptopp, bufferlen);
    }

    // test buffers

    check_buffer(buffer_gcrypt, bufferlen);
    check_buffer(buffer_mcrypt, bufferlen);
    check_buffer(buffer_botan, bufferlen);
    check_buffer(buffer_cryptopp, bufferlen);
}

int main()
{
    // Initialize all cryptographic libaries

    gcry_check_version(GCRYPT_VERSION);

    Botan::LibraryInitializer init;

    // Create (somewhat) random encryption key

    srand(time(NULL));

    for(unsigned int i = 0; i < sizeof(enckey); ++i)
	enckey[i] = rand();

    // Verify cipher implementations

    verify_rijndael();

    return 0;
}
