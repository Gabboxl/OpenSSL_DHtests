#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <cstdio>
#include <vector>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {
    EVP_PKEY_CTX* pctx, * kctx;
    EVP_PKEY* key1 = NULL, * key2 = NULL, * peerkey = NULL;
    unsigned char* skey1 = NULL, * skey2 = NULL;
    size_t skeylen1, skeylen2;

    /* Create the context for parameter generation */
    if (NULL == (kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL))) //OPPURE EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
        handleErrors();

    /* Generate the key */
    if (1 != EVP_PKEY_keygen_init(kctx))
        handleErrors();

    OSSL_PARAM params[2];
    const char* name = "dh_2048_256";
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)name, 0);
    params[1] = OSSL_PARAM_construct_end();


    if (1 != EVP_PKEY_CTX_set_params(kctx, params))
        handleErrors();


    if (1 != EVP_PKEY_keygen(kctx, &key1))
        handleErrors();
    if (1 != EVP_PKEY_keygen(kctx, &key2))
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