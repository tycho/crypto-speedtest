// $Id$

#include <crypto++/modes.h>
#include <crypto++/rijndael.h>
#include <crypto++/serpent.h>
#include <crypto++/twofish.h>
#include <crypto++/cast.h>
#include <crypto++/gost.h>
#include <crypto++/tea.h>
#include <crypto++/blowfish.h>
#include <crypto++/des.h>

#include "speedtest.h"

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

// *** main() ***

int main()
{
    // Create (somewhat) random encryption key and initialization vector

    srand(time(NULL));

    for(unsigned int i = 0; i < sizeof(enckey); ++i)
	enckey[i] = rand();

    for(unsigned int i = 0; i < sizeof(enciv); ++i)
	enciv[i] = rand();

    // Run speed tests

    run_test<test_cryptopp_rijndael_ecb>("cryptopp-rijndael-ecb.txt");
    run_test<test_cryptopp_serpent_ecb>("cryptopp-serpent-ecb.txt");
    run_test<test_cryptopp_twofish_ecb>("cryptopp-twofish-ecb.txt");
    run_test<test_cryptopp_cast6_ecb>("cryptopp-cast6-ecb.txt");
    run_test<test_cryptopp_gost_ecb>("cryptopp-gost-ecb.txt");
    run_test<test_cryptopp_xtea_ecb>("cryptopp-xtea-ecb.txt");
    run_test<test_cryptopp_blowfish_ecb>("cryptopp-blowfish-ecb.txt");
    run_test<test_cryptopp_cast5_ecb>("cryptopp-cast5-ecb.txt");
    run_test<test_cryptopp_3des_ecb>("cryptopp-3des-ecb.txt");
}
