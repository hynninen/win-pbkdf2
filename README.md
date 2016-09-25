# Files

| File | Description |
| --- | --- |
| `pbkdf2_hmac.c` | Contains the implementation for the PBKDF2-HMAC algorithm, as described in RFC 2898. |
| `pbkdf2_hmac.h` | Header file for the PBKDF2-HMAC algorithm. |
| `pbkdf2_hmac_test.c` | RFC 6070 test vectors. |
| `pbkdf2_hmac_test.h` | Header file for verifying against the RFC 6070 test vectors. |
| `main.c` | Main program that verifies the implementation against the RFC 6070 test vectors. |

# Usage example

```C
HCRYPTPROV provider    = NULL;
HCRYPTHASH hash_sha256 = NULL;
int        result      = 0;

char salt_data[] = "SALT";

CryptAcquireContext(provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
CryptCreateHash(provider, CALG_SHA_256, NULL, 0, &hash_sha256);

result = pbkdf2_derive_bytes_hmac(
    hash_sha256,            /* Initial hash           */
    64,                     /* Hash inner block size  */
    16384,                  /* Iteration count        */
    passwd_len,             /* Password length        */
    passwd_data,            /* Password bytes         */
    sizeof(salt_data) - 1,  /* Salt length            */
    (const BYTE*)salt_data, /* Salt data              */
    64,                     /* Length of output bytes */
    out_bytes               /* Output buffer          */
);

if(result != 0) {
    /* Failed to derive bytes. */
}

CryptDestroyHash(hash_sha256);
CryptReleaseContext(provider, 0);
```