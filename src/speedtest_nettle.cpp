// $Id$

extern "C" {
#include <nettle/aes.h>
#include <nettle/serpent.h>
#include <nettle/twofish.h>
#include <nettle/cast128.h>
#include <nettle/blowfish.h>
#include <nettle/des.h>
}

#include "speedtest.h"

typedef uint8_t byte;

// *** Test Functions for Nettle ***

void test_nettle_rijndael_ecb()
{
    aes_ctx encctx;
    aes_set_encrypt_key(&encctx, 32, (byte*)enckey);
    aes_encrypt(&encctx, bufferlen, (byte*)buffer, (byte*)buffer);

    aes_ctx decctx;
    aes_set_decrypt_key(&decctx, 32, (byte*)enckey);
    aes_decrypt(&decctx, bufferlen, (byte*)buffer, (byte*)buffer);
}

void test_nettle_serpent_ecb()
{
    serpent_ctx encctx;
    serpent_set_key(&encctx, 32, (byte*)enckey);
    serpent_encrypt(&encctx, bufferlen, (byte*)buffer, (byte*)buffer);

    serpent_ctx decctx;
    serpent_set_key(&decctx, 32, (byte*)enckey);
    serpent_decrypt(&decctx, bufferlen, (byte*)buffer, (byte*)buffer);
}

void test_nettle_twofish_ecb()
{
    twofish_ctx encctx;
    twofish_set_key(&encctx, 32, (byte*)enckey);
    twofish_encrypt(&encctx, bufferlen, (byte*)buffer, (byte*)buffer);

    twofish_ctx decctx;
    twofish_set_key(&decctx, 32, (byte*)enckey);
    twofish_decrypt(&decctx, bufferlen, (byte*)buffer, (byte*)buffer);
}

void test_nettle_cast5_ecb()
{
    cast128_ctx encctx;
    cast128_set_key(&encctx, 32, (byte*)enckey);
    cast128_encrypt(&encctx, bufferlen, (byte*)buffer, (byte*)buffer);

    cast128_ctx decctx;
    cast128_set_key(&decctx, 32, (byte*)enckey);
    cast128_decrypt(&decctx, bufferlen, (byte*)buffer, (byte*)buffer);
}

void test_nettle_blowfish_ecb()
{
    blowfish_ctx encctx;
    blowfish_set_key(&encctx, 32, (byte*)enckey);
    blowfish_encrypt(&encctx, bufferlen, (byte*)buffer, (byte*)buffer);

    blowfish_ctx decctx;
    blowfish_set_key(&decctx, 32, (byte*)enckey);
    blowfish_decrypt(&decctx, bufferlen, (byte*)buffer, (byte*)buffer);
}

void test_nettle_3des_ecb()
{
    des3_ctx encctx;
    des3_set_key(&encctx, (byte*)enckey);
    des3_encrypt(&encctx, bufferlen, (byte*)buffer, (byte*)buffer);

    des3_ctx decctx;
    des3_set_key(&decctx, (byte*)enckey);
    des3_decrypt(&decctx, bufferlen, (byte*)buffer, (byte*)buffer);
}

// *** main() ***

int main()
{
    // Create (somewhat) random encryption key and initialization vector

    srand(time(NULL));

    for(unsigned int i = 0; i < sizeof(enckey); ++i)
	enckey[i] = rand();

    for(unsigned int i = 0; i < sizeof(enciv); ++i)
	enciv[i] = rand();

    // Nettle requires some parity fix of the key
    des_fix_parity(24, (byte*)enckey, (byte*)enckey);

    // Run speed tests

    run_test<test_nettle_rijndael_ecb>("nettle-rijndael-ecb.txt");
    run_test<test_nettle_serpent_ecb>("nettle-serpent-ecb.txt");
    run_test<test_nettle_twofish_ecb>("nettle-twofish-ecb.txt");
    run_test<test_nettle_blowfish_ecb>("nettle-blowfish-ecb.txt");
    run_test<test_nettle_cast5_ecb>("nettle-cast5-ecb.txt");
    run_test<test_nettle_3des_ecb>("nettle-3des-ecb.txt");
}
