#include <Windows.h>
#include <stdio.h>

#include "pbkdf2_hmac.h"
#include "pbkdf2_hmac_test.h"

#define SHA1_BLOCK_SIZE 64

/******************************************************************************/
/* RFC 6070 test vectors https://tools.ietf.org/html/rfc6070                  */
/******************************************************************************/

unsigned char       derived_6070_1[20];
const char          pass_6070_1[]  = "password";
const char          salt_6070_1[]  = "salt";
unsigned            count_6070_1   = 1;
const unsigned char bytes_6070_1[] = {
    0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
    0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
    0x2f, 0xe0, 0x37, 0xa6
};

unsigned char       derived_6070_2[20];
const char          pass_6070_2[]  = "password";
const char          salt_6070_2[]  = "salt";
unsigned            count_6070_2   = 2;
const unsigned char bytes_6070_2[] = {
    0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c,
    0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0,
    0xd8, 0xde, 0x89, 0x57
};

unsigned char       derived_6070_3[20];
const char          pass_6070_3[]  = "password";
const char          salt_6070_3[]  = "salt";
unsigned            count_6070_3   = 4096;
const unsigned char bytes_6070_3[] = {
    0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a,
    0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0,
    0x65, 0xa4, 0x29, 0xc1
};

/* Skipping the fourth test vector because its iteration count is 16777216 which
 * is a tad large. */

unsigned char       derived_6070_5[25];
const char          pass_6070_5[]  = "passwordPASSWORDpassword";
const char          salt_6070_5[]  = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
unsigned            count_6070_5   = 4096;
const unsigned char bytes_6070_5[] = {
    0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b,
    0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a,
    0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70,
    0x38
};

unsigned char       derived_6070_6[16];
const char          pass_6070_6[]  = "pass\0word";
const char          salt_6070_6[]  = "sa\0lt";
unsigned            count_6070_6   = 4096;
const unsigned char bytes_6070_6[] = {
    0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x09, 0x9d,
    0xcc, 0x37, 0xd7, 0xf0, 0x34, 0x25, 0xe0, 0xc3,
};

/******************************************************************************/

#define TEST_VECTOR(name, n)                                        \
    result = pbkdf2_derive_bytes_hmac(                              \
        hash_sha1,                                                  \
        SHA1_BLOCK_SIZE,                                            \
        count_##n,                                                  \
        sizeof(pass_##n) - 1,                                       \
        pass_##n,                                                   \
        sizeof(salt_##n) - 1,                                       \
        salt_##n,                                                   \
        sizeof(derived_##n),                                        \
        derived_##n                                                 \
    );                                                              \
                                                                    \
    if(result != 0) {                                               \
        goto end_error;                                             \
    }                                                               \
                                                                    \
    if(memcmp(derived_##n, bytes_##n, sizeof(derived_##n) != 0)) {  \
        puts("FAILED  " name " test vector " # n);                  \
    } else {                                                        \
        puts("OK      " name " test vector " # n);                  \
    }

int pbkdf2_hmac_test_rfc6070()
{
    int        result    = 0;
    HCRYPTPROV provider  = NULL;
    HCRYPTHASH hash_sha1 = NULL;

    CryptAcquireContextA(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);

    if(provider == NULL) {
        result = -1;
        goto end_error;
    }

    CryptCreateHash(provider, CALG_SHA1, NULL, 0, &hash_sha1);

    if(hash_sha1 == NULL) {
        result = -1;
        goto end_error;
    }

    TEST_VECTOR("RFC 6070", 6070_1);
    TEST_VECTOR("RFC 6070", 6070_2);
    TEST_VECTOR("RFC 6070", 6070_3);
    TEST_VECTOR("RFC 6070", 6070_5);
    TEST_VECTOR("RFC 6070", 6070_6);

end_error:

    if(hash_sha1 != NULL) {
        CryptDestroyHash(hash_sha1);
    }

    if(provider != NULL) {
        CryptReleaseContext(provider, 0);
    }

    return result;
}
