#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <cstdio>
#include <vector>



//https://stackoverflow.com/questions/71551116/openssl-3-diffie-hellman-key-exchange-c



void handleErrors() {
    ERR_print_errors_fp(stdout);
    abort();
}

void printdata(EVP_PKEY* key)
{
    size_t g_len;
    //get "g" parameter as unsigned char*
    EVP_PKEY_get_octet_string_param(key, "g", nullptr, 0, &g_len);
    unsigned char* g = (unsigned char*)OPENSSL_malloc(g_len);
    BIGNUM* g_bn = BN_new();
    EVP_PKEY_get_bn_param(key, "g", &g_bn);

    BN_bn2bin (g_bn, g);

    auto g_vec = std::vector<unsigned char>(g, g + g_len);

    //print hex bignum
     for (int i = 0; i < g_len; i++)
        printf("%02x", g[i]);

     printf("\n\n");
}

int main() {
    EVP_PKEY_CTX* pctx, * kctx;
    EVP_PKEY* key1 = NULL, * key2 = NULL, * peerkey = NULL;
    unsigned char* skey1 = NULL, * skey2 = NULL;
    size_t skeylen1, skeylen2;

    /* Create the context for parameter generation */
    if (NULL == (kctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL))) //OPPURE EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
        handleErrors();


    //OSSL_PARAM params[2];
    //const char* name = "dh_2048_256";
    //params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)name, 0);
    //params[1] = OSSL_PARAM_construct_end();

    //BIGNUM* g = BN_new();
    //BN_set_word(g, 2);  // replace 2 with your custom value for g
    //OSSL_PARAM paramsy[2];
    //params[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_DH_GENERATOR, &g, sizeof(g));
    //params[1] = OSSL_PARAM_construct_end();

    BIGNUM* prime = BN_new();
    BIGNUM* generator = BN_new();
    BIGNUM* sub = BN_new();

    // Set the values for prime and generator
    BN_hex2bn(&prime, "87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597");
    BN_hex2bn(&generator, "77732c9b73134d0b2e77506660edbd484ca7b18f21ef205407f4793a1a0ba12510dbc15077be463fff4fed4aac0bb555be3a6c1b0c6b47b1bc3773bf7e8c6f62901228f8c28cbb18a55ae31341000a650196f931c77a57f2ddf463e5e9ec144b777de62aaab8a8628ac376d282d6ed3864e67982428ebc831d14348f6f2f9193b5045af2767164e1dfc967c1fb3f2e55a4bd1bffe83b9c80d052b985d182ea0adb2a3b7313d3fe14c8484b1e052588b9b7d2bbd2df016199ecd06e1557cd0915b3353bbb64e0ec377fd028370df92b52c7891428cdc67eb6184b523d1db246c32f63078490f00ef8d647d148d47954515e2327cfef98c582664b4c0f6cc41659");
    BN_hex2bn(&sub, "8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3");


    // Create the OSSL_PARAM_BLD.
    OSSL_PARAM_BLD* paramBuild = OSSL_PARAM_BLD_new();
    if (!paramBuild) {
        // report the error
    }
    // Set the prime and generator.
    if (!OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_FFC_P, prime) ||
        !OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_FFC_G, generator) ||
        !OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_FFC_Q, sub)) {
        // report the error
    }
    // Convert to OSSL_PARAM.
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(paramBuild);
    if (!params) {
        // report the error
    }


    // Initialize the context.
    if (EVP_PKEY_fromdata_init(kctx) <= 0) {
        // report the error
    }
    // Create the domain parameter key.
    EVP_PKEY* domainParamKey = nullptr;
    if (EVP_PKEY_fromdata(kctx, &domainParamKey,
        EVP_PKEY_KEY_PARAMETERS, params) <= 0) {
        // report the error
    }

    printdata(domainParamKey);


    EVP_PKEY_CTX* keyGenerationCtx = EVP_PKEY_CTX_new_from_pkey(nullptr, domainParamKey, nullptr);
    if (!kctx) {
        // report the error
    }
    if (EVP_PKEY_keygen_init(keyGenerationCtx) <= 0) {
        // report the error
    }
    EVP_PKEY* keyPair = nullptr;
    if (EVP_PKEY_generate(keyGenerationCtx, &keyPair) <= 0) {
        handleErrors();
    }


    ///* Generate the key */
    //if (1 != EVP_PKEY_keygen_init(kctx))
    //    handleErrors();


    if (1 != EVP_PKEY_keygen(keyGenerationCtx, &key1))
        handleErrors();
    if (1 != EVP_PKEY_keygen(keyGenerationCtx, &key2))
        handleErrors();

    /* Derive the shared secret */
    if (0 == (kctx = EVP_PKEY_CTX_new(key1, NULL)))
        handleErrors();
    if (1 != EVP_PKEY_derive_init_ex(kctx, params))
        handleErrors();
    if (1 != EVP_PKEY_derive_set_peer(kctx, key2))
        handleErrors();

    /* Determine buffer length for shared secret */
    if (1 != EVP_PKEY_derive(kctx, NULL, &skeylen1))
        handleErrors();

    /* Create the buffer */
    if (NULL == (skey1 = (unsigned char*)OPENSSL_malloc(skeylen1)))
        handleErrors();

    /* Derive the shared secret */
    if (1 != (EVP_PKEY_derive(kctx, skey1, &skeylen1)))
        handleErrors();

    auto skey1_vec = std::vector<unsigned char>(skey1, skey1 + skeylen1);


        /* Derive the shared secret again to check that it is the same */
    if (0 == (kctx = EVP_PKEY_CTX_new(key2, NULL)))
        handleErrors();
    if (1 != EVP_PKEY_derive_init_ex(kctx, params))
        handleErrors();
    if (1 != EVP_PKEY_derive_set_peer(kctx, key1))
        handleErrors();

        /* Determine buffer length for shared secret */
    if (1 != EVP_PKEY_derive(kctx, NULL, &skeylen2))
        handleErrors();

        /* Create the buffer */
    if (NULL == (skey2 = (unsigned char*)OPENSSL_malloc(skeylen2)))
        handleErrors();

    /* Derive the shared secret */
    if (1 != (EVP_PKEY_derive(kctx, skey2, &skeylen2)))
        handleErrors();

    auto skey2_vec = std::vector<unsigned char>(skey2, skey2 + skeylen2);

        if (skey1_vec != skey2_vec)
            printf("Shared secrets are different\n");
        else
            printf("Shared secrets are the same\n");



        
    //size_t g_len;
    ////get "g" parameter as unsigned char*
    //EVP_PKEY_get_octet_string_param(key1, "g", nullptr, 0, &g_len);
    //unsigned char* g = (unsigned char*)OPENSSL_malloc(g_len);
    //BIGNUM* g_bn = BN_new();
    //EVP_PKEY_get_bn_param(key1, "g", &g_bn);

    //BN_bn2bin (g_bn, g);

    //auto g_vec = std::vector<unsigned char>(g, g + g_len);

    ////print hex bignum
    // for (int i = 0; i < g_len; i++)
    //    printf("%02x", g[i]);

    // printf("\n\n");

        printdata(key1);



    //create test prime and generator bignum

    // Create test prime and generator bignum
    //BIGNUM* prime = BN_new();
    //BIGNUM* generator = BN_new();

    //// Set the values for prime and generator
    //BN_hex2bn(&prime, "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF");
    //BN_hex2bn(&generator, "77b32c9b73134d0b2e77506660edbd484ca7b18f21ef205407f4793a1a0ba12510dbc15077be463fff4fed4aac0bb555be3a6c1b0c6b47b1bc3773bf7e8c6f62901228f8c28cbb18a55ae31341000a650196f931c77a57f2ddf463e5e9ec144b777de62aaab8a8628ac376d282d6ed3864e67982428ebc831d14348f6f2f9193b5045af2767164e1dfc967c1fb3f2e55a4bd1bffe83b9c80d052b985d182ea0adb2a3b7313d3fe14c8484b1e052588b9b7d2bbd2df016199ecd06e1557cd0915b3353bbb64e0ec377fd028370df92b52c7891428cdc67eb6184b523d1db246c32f63078490f00ef8d647d148d47954515e2327cfef98c582664b4c0f6cc41659");


    // // Create the OSSL_PARAM_BLD.
    // OSSL_PARAM_BLD* paramBuild = OSSL_PARAM_BLD_new();
    // if (!paramBuild) {
    //     // report the error
    // }
    // // Set the prime and generator.
    // if (!OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_FFC_P, prime) ||
    //     !OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_FFC_G, generator)) {
    //     // report the error
    // }
    // // Convert to OSSL_PARAM.
    // OSSL_PARAM* param = OSSL_PARAM_BLD_to_param(paramBuild);
    // if (!param) {
    //     // report the error
    // }



     ////set params to key1
     //if (1 != EVP_PKEY_set_params(key1, param))
     //    handleErrors();

     printdata(key1);



    /* Never use a derived secret directly. Typically it is passed
     * through some hash function to produce a key */



     /* Clean up */
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(peerkey);
    EVP_PKEY_free(key1);
    EVP_PKEY_free(key2);
    OPENSSL_free(skey1);

    return 0;
}