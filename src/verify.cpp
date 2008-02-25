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
#include <botan/des.h>

#include <crypto++/modes.h>
#include <crypto++/rijndael.h>
#include <crypto++/serpent.h>
#include <crypto++/des.h>

#define NCOMPAT
#include <openssl/aes.h>
#include <openssl/des.h>

#include <nettle/aes.h>
#include <nettle/serpent.h>
#include <nettle/des.h>

#include <beecrypt/aes.h>

#include "rijndael.h"
#include "serpent-gladman.h"

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

void verify_rijndael_ecb()
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

	for(unsigned int p = 0; p < bufferlen; p += encctx.BLOCK_SIZE)
	    encctx.encrypt((Botan::byte*)buffer_botan + p);
    }

    // Crypto++

    char buffer_cryptopp[bufferlen];
    fill_buffer(buffer_cryptopp, bufferlen);

    {
	CryptoPP::ECB_Mode<CryptoPP::Rijndael>::Encryption encctx;
	encctx.SetKey((byte*)enckey, 32);

	encctx.ProcessData((byte*)buffer_cryptopp, (byte*)buffer_cryptopp, bufferlen);
    }

    // OpenSSL

    char buffer_openssl[bufferlen];
    fill_buffer(buffer_openssl, bufferlen);

    {
	AES_KEY aeskey;
	AES_set_encrypt_key((byte*)enckey, 256, &aeskey);

	for(unsigned int p = 0; p < bufferlen; p += AES_BLOCK_SIZE)
	    AES_encrypt((byte*)buffer_openssl + p, (byte*)buffer_openssl + p, &aeskey);
    }

    // Nettle

    char buffer_nettle[bufferlen];
    fill_buffer(buffer_nettle, bufferlen);

    {
	aes_ctx encctx;
	aes_set_encrypt_key(&encctx, 32, (byte*)enckey);
	aes_encrypt(&encctx, bufferlen, (uint8_t*)buffer_nettle, (uint8_t*)buffer_nettle);
    }

    // Beecrypt

    char buffer_beecrypt[bufferlen];
    fill_buffer(buffer_beecrypt, bufferlen);

    {
	aesParam encctx;
	aesSetup(&encctx, (byte*)enckey, 256, ENCRYPT);

	for(unsigned int p = 0; p < bufferlen; p += 16)
	    aesEncrypt(&encctx, (uint32_t*)(buffer_beecrypt + p), (uint32_t*)(buffer_beecrypt + p));
    }

    // My Implementation

    char buffer_my[bufferlen];
    fill_buffer(buffer_my, bufferlen);

    {
	RijndaelEncryptECB encctx;
	encctx.set_key((byte*)enckey, 32);
	encctx.encrypt(buffer_my, buffer_my, bufferlen);
    }

    // compare buffers

    compare_buffers(buffer_gcrypt, buffer_mcrypt, bufferlen);
    compare_buffers(buffer_gcrypt, buffer_botan, bufferlen);
    compare_buffers(buffer_gcrypt, buffer_cryptopp, bufferlen);
    compare_buffers(buffer_gcrypt, buffer_openssl, bufferlen);
    compare_buffers(buffer_gcrypt, buffer_nettle, bufferlen);
    compare_buffers(buffer_gcrypt, buffer_beecrypt, bufferlen);
    compare_buffers(buffer_gcrypt, buffer_my, bufferlen);

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

	for(unsigned int p = 0; p < bufferlen; p += decctx.BLOCK_SIZE)
	    decctx.decrypt((Botan::byte*)buffer_botan + p);
    }

    // Crypto++

    {
	CryptoPP::ECB_Mode<CryptoPP::Rijndael>::Decryption decctx;
	decctx.SetKey((byte*)enckey, 32);

	decctx.ProcessData((byte*)buffer_cryptopp, (byte*)buffer_cryptopp, bufferlen);
    }

    // OpenSSL

    {
	AES_KEY aeskey;
	AES_set_decrypt_key((byte*)enckey, 256, &aeskey);

	for(unsigned int p = 0; p < bufferlen; p += AES_BLOCK_SIZE)
	    AES_decrypt((byte*)buffer_openssl + p, (byte*)buffer_openssl + p, &aeskey);
    }

    // Nettle

    {
	aes_ctx decctx;
	aes_set_decrypt_key(&decctx, 32, (byte*)enckey);
	aes_decrypt(&decctx, bufferlen, (uint8_t*)buffer_nettle, (uint8_t*)buffer_nettle);
    }

    // Beecrypt

    {
	aesParam decctx;
	aesSetup(&decctx, (byte*)enckey, 256, DECRYPT);

	for(unsigned int p = 0; p < bufferlen; p += 16)
	    aesDecrypt(&decctx, (uint32_t*)(buffer_beecrypt + p), (uint32_t*)(buffer_beecrypt + p));
    }

    // My Implementation

    {
	RijndaelDecryptECB decctx;
	decctx.set_key((byte*)enckey, 32);
	decctx.decrypt(buffer_my, buffer_my, bufferlen);
    }

    // test buffers

    check_buffer(buffer_gcrypt, bufferlen);
    check_buffer(buffer_mcrypt, bufferlen);
    check_buffer(buffer_botan, bufferlen);
    check_buffer(buffer_cryptopp, bufferlen);
    check_buffer(buffer_openssl, bufferlen);
    check_buffer(buffer_nettle, bufferlen);
    check_buffer(buffer_beecrypt, bufferlen);
    check_buffer(buffer_my, bufferlen);
}

// *** Verify Serpent Implementations

void verify_serpent_ecb()
{
    // libgcrypt

    char buffer_gcrypt[bufferlen];
    fill_buffer(buffer_gcrypt, bufferlen);

    {
	gcry_cipher_hd_t encctx;
	gcry_cipher_open(&encctx, GCRY_CIPHER_SERPENT256, GCRY_CIPHER_MODE_ECB, 0);
	gcry_cipher_setkey(encctx, (uint8_t*)enckey, 32);
	gcry_cipher_encrypt(encctx, buffer_gcrypt, bufferlen, buffer_gcrypt, bufferlen);
	gcry_cipher_close(encctx);
    }

    // libmcrypt

    char buffer_mcrypt[bufferlen];
    fill_buffer(buffer_mcrypt, bufferlen);

    {
	MCRYPT encctx = mcrypt_module_open(MCRYPT_SERPENT, NULL, MCRYPT_ECB, NULL);
	mcrypt_generic_init(encctx, enckey, 32, NULL);
	mcrypt_generic(encctx, buffer_mcrypt, bufferlen);
	mcrypt_generic_end(encctx);
    }

    // Botan

    char buffer_botan[bufferlen];
    fill_buffer(buffer_botan, bufferlen);

    {
	Botan::Serpent encctx;
	encctx.set_key((Botan::byte*)enckey, 32);

	for(unsigned int p = 0; p < bufferlen; p += encctx.BLOCK_SIZE)
	    encctx.encrypt((Botan::byte*)buffer_botan + p);
    }

    // Crypto++

    char buffer_cryptopp[bufferlen];
    fill_buffer(buffer_cryptopp, bufferlen);

    {
	CryptoPP::ECB_Mode<CryptoPP::Serpent>::Encryption encctx;
	encctx.SetKey((byte*)enckey, 32);

	encctx.ProcessData((byte*)buffer_cryptopp, (byte*)buffer_cryptopp, bufferlen);
    }

   // Nettle

    char buffer_nettle[bufferlen];
    fill_buffer(buffer_nettle, bufferlen);

    {
	serpent_ctx encctx;
	serpent_set_key(&encctx, 32, (byte*)enckey);
	serpent_encrypt(&encctx, bufferlen, (uint8_t*)buffer_nettle, (uint8_t*)buffer_nettle);
    }

    // gladman implementation

    char buffer_gladman[bufferlen];
    fill_buffer(buffer_gladman, bufferlen);

    {
	SerpentGladman::EncryptECB encctx;

	encctx.set_key((uint8_t*)enckey, 256);
	encctx.encrypt(buffer_gladman, buffer_gladman, bufferlen);
    }

    // compare buffers

    compare_buffers(buffer_gcrypt, buffer_mcrypt, bufferlen);
    compare_buffers(buffer_gcrypt, buffer_botan, bufferlen);
    compare_buffers(buffer_gcrypt, buffer_cryptopp, bufferlen);
    // does not match! compare_buffers(buffer_gcrypt, buffer_nettle, bufferlen);
    compare_buffers(buffer_gcrypt, buffer_gladman, bufferlen);

    // libgcrypt

    {
	gcry_cipher_hd_t decctx;
	gcry_cipher_open(&decctx, GCRY_CIPHER_SERPENT256, GCRY_CIPHER_MODE_ECB, 0);
	gcry_cipher_setkey(decctx, (uint8_t*)enckey, 32);
	gcry_cipher_decrypt(decctx, buffer_gcrypt, bufferlen, buffer_gcrypt, bufferlen);
	gcry_cipher_close(decctx);
    }

    // libmcrypt

    {
	MCRYPT decctx = mcrypt_module_open(MCRYPT_SERPENT, NULL, MCRYPT_ECB, NULL);
	mcrypt_generic_init(decctx, enckey, 32, NULL);
	mdecrypt_generic(decctx, buffer_mcrypt, bufferlen);
	mcrypt_generic_end(decctx);
    }

    // Botan

    {
	Botan::Serpent decctx;
	decctx.set_key((Botan::byte*)enckey, 32);

	for(unsigned int p = 0; p < bufferlen; p += decctx.BLOCK_SIZE)
	    decctx.decrypt((Botan::byte*)buffer_botan + p);
    }

    // Crypto++

    {
	CryptoPP::ECB_Mode<CryptoPP::Serpent>::Decryption decctx;
	decctx.SetKey((byte*)enckey, 32);

	decctx.ProcessData((byte*)buffer_cryptopp, (byte*)buffer_cryptopp, bufferlen);
    }

    // Nettle

    {
	serpent_ctx decctx;
	serpent_set_key(&decctx, 32, (byte*)enckey);
	serpent_decrypt(&decctx, bufferlen, (uint8_t*)buffer_nettle, (uint8_t*)buffer_nettle);
    }

    // gladman implementation

    {
	SerpentGladman::DecryptECB decctx;

	decctx.set_key((uint8_t*)enckey, 256);
	decctx.decrypt(buffer_gladman, buffer_gladman, bufferlen);
    }

    // test buffers

    check_buffer(buffer_gcrypt, bufferlen);
    check_buffer(buffer_mcrypt, bufferlen);
    check_buffer(buffer_botan, bufferlen);
    check_buffer(buffer_cryptopp, bufferlen);
    check_buffer(buffer_nettle, bufferlen);
    check_buffer(buffer_gladman, bufferlen);
}

// *** Verify Triple DES Implementations

void verify_3des_ecb()
{
    // Nettle requires some parity fix of the key

    des_fix_parity(24, (byte*)enckey, (byte*)enckey);

    // libgcrypt

    char buffer_gcrypt[bufferlen];
    fill_buffer(buffer_gcrypt, bufferlen);

    {
	gcry_cipher_hd_t encctx;
	gcry_cipher_open(&encctx, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_ECB, 0);
	gcry_cipher_setkey(encctx, (uint8_t*)enckey, 24);
	gcry_cipher_encrypt(encctx, buffer_gcrypt, bufferlen, buffer_gcrypt, bufferlen);
	gcry_cipher_close(encctx);
    }

    // libmcrypt

    char buffer_mcrypt[bufferlen];
    fill_buffer(buffer_mcrypt, bufferlen);

    {
	MCRYPT encctx = mcrypt_module_open(MCRYPT_3DES, NULL, MCRYPT_ECB, NULL);
	mcrypt_generic_init(encctx, enckey, 24, NULL);
	mcrypt_generic(encctx, buffer_mcrypt, bufferlen);
	mcrypt_generic_end(encctx);
    }

    // Botan

    char buffer_botan[bufferlen];
    fill_buffer(buffer_botan, bufferlen);

    {
	Botan::TripleDES encctx;
	encctx.set_key((Botan::byte*)enckey, 24);

	for(unsigned int p = 0; p < bufferlen; p += encctx.BLOCK_SIZE)
	    encctx.encrypt((Botan::byte*)buffer_botan + p);
    }

    // Crypto++

    char buffer_cryptopp[bufferlen];
    fill_buffer(buffer_cryptopp, bufferlen);

    {
	CryptoPP::ECB_Mode<CryptoPP::DES_EDE3>::Encryption encctx;
	encctx.SetKey((byte*)enckey, 24);

	encctx.ProcessData((byte*)buffer_cryptopp, (byte*)buffer_cryptopp, bufferlen);
    }

    // OpenSSL

    char buffer_openssl[bufferlen];
    fill_buffer(buffer_openssl, bufferlen);

    {
	DES_key_schedule eks1, eks2, eks3;

	DES_set_key((DES_cblock*)(enckey +  0), &eks1);
	DES_set_key((DES_cblock*)(enckey +  8), &eks2);
	DES_set_key((DES_cblock*)(enckey + 16), &eks3);

	for(unsigned int p = 0; p < bufferlen; p += 8)
	    DES_encrypt3((DES_LONG*)(buffer_openssl + p), &eks1, &eks2, &eks3);
    }

   // Nettle

    char buffer_nettle[bufferlen];
    fill_buffer(buffer_nettle, bufferlen);

    {
	des3_ctx encctx;
	des3_set_key(&encctx, (byte*)enckey);
	des3_encrypt(&encctx, bufferlen, (byte*)buffer_nettle, (byte*)buffer_nettle);
    }

    // compare buffers

    compare_buffers(buffer_gcrypt, buffer_mcrypt, bufferlen);
    compare_buffers(buffer_gcrypt, buffer_botan, bufferlen);
    compare_buffers(buffer_gcrypt, buffer_cryptopp, bufferlen);
    compare_buffers(buffer_gcrypt, buffer_openssl, bufferlen);
    compare_buffers(buffer_gcrypt, buffer_nettle, bufferlen);

    // libgcrypt

    {
	gcry_cipher_hd_t decctx;
	gcry_cipher_open(&decctx, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_ECB, 0);
	gcry_cipher_setkey(decctx, (uint8_t*)enckey, 24);
	gcry_cipher_decrypt(decctx, buffer_gcrypt, bufferlen, buffer_gcrypt, bufferlen);
	gcry_cipher_close(decctx);
    }

    // libmcrypt

    {
	MCRYPT decctx = mcrypt_module_open(MCRYPT_3DES, NULL, MCRYPT_ECB, NULL);
	mcrypt_generic_init(decctx, enckey, 24, NULL);
	mdecrypt_generic(decctx, buffer_mcrypt, bufferlen);
	mcrypt_generic_end(decctx);
    }

    // Botan

    {
	Botan::TripleDES decctx;
	decctx.set_key((Botan::byte*)enckey, 24);

	for(unsigned int p = 0; p < bufferlen; p += decctx.BLOCK_SIZE)
	    decctx.decrypt((Botan::byte*)buffer_botan + p);
    }

    // Crypto++

    {
	CryptoPP::ECB_Mode<CryptoPP::DES_EDE3>::Decryption decctx;
	decctx.SetKey((byte*)enckey, 24);

	decctx.ProcessData((byte*)buffer_cryptopp, (byte*)buffer_cryptopp, bufferlen);
    }

    // OpenSSL

    {
	DES_key_schedule dks1, dks2, dks3;

	DES_set_key((DES_cblock*)(enckey +  0), &dks1);
	DES_set_key((DES_cblock*)(enckey +  8), &dks2);
	DES_set_key((DES_cblock*)(enckey + 16), &dks3);

	for(unsigned int p = 0; p < bufferlen; p += 8)
	    DES_decrypt3((DES_LONG*)(buffer_openssl + p), &dks1, &dks2, &dks3);
    }

    // Nettle

    {
	des3_ctx decctx;
	des3_set_key(&decctx, (byte*)enckey);
	des3_decrypt(&decctx, bufferlen, (byte*)buffer_nettle, (byte*)buffer_nettle);
    }

    // test buffers

    check_buffer(buffer_gcrypt, bufferlen);
    check_buffer(buffer_mcrypt, bufferlen);
    check_buffer(buffer_botan, bufferlen);
    check_buffer(buffer_cryptopp, bufferlen);
    check_buffer(buffer_openssl, bufferlen);
    check_buffer(buffer_nettle, bufferlen);
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

    verify_rijndael_ecb();
    verify_serpent_ecb();
    verify_3des_ecb();

    return 0;
}
