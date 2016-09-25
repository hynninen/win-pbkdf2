#include <Windows.h>

#include "pbkdf2_hmac.h"

#define MAX_HASH_BUFFER_SIZE 640

/**
 * Internal function for XORing blocks of memory. The memory pointed to by the
 * @a dst argument is exclusive-or'd with the memory pointed to by @a dst.
 *
 * Both buffers @a dst and @a src must contain at least @a length bytes.
 */
static void memxor(BYTE *dst, const BYTE *src, DWORD length)
{
    while(length != 0) {
        dst[0] ^= src[0];
        dst++;
        src++;
        length--;
    }
}

/**
 * Internal function for initializing HMAC. Computes the inner padded key and
 * outer padded key (@a ipad and @a opad) for the specified password. Requires
 * an initialized hash in the @a hash_init parameter.
 *
 * @param hash_init An initialized hash that will be duplicated if necessary.
 *     The hash in this parameter is not modified.
 * @param passwd_len Length of the password in the @a passwd_data buffer, in
 *     bytes.
 * @param passwd_data Buffer containing the password.
 * @param hash_block_size Size of the internal block of the @a hash_init hash.
 * @param ipad Pointer to a buffer that receives the inner padded key. Must be
 *     at least @a hash_block_size bytes in size.
 * @param opad Pointer to a buffer that receives the outer padded key. Must be
 *     at least @a hash_block_size bytes in size.
 * @return Zero on success, nonzero on failure.
 */
static int hmac_init(HCRYPTHASH  hash_init,
                     DWORD       passwd_len,
                     const BYTE *passwd_data,
                     DWORD       hash_block_size,
                     BYTE       *ipad,
                     BYTE       *opad)
{
    BYTE buffer[MAX_HASH_BUFFER_SIZE] = { 0 };

    BOOL       r      = FALSE;
    int        result = 0;
    DWORD      length = 0;
    DWORD      i      = 0;
    HCRYPTHASH hash   = NULL;

    if(passwd_len > hash_block_size) {

        r = CryptDuplicateHash(hash_init, NULL, 0, &hash);

        if(r == FALSE || hash == NULL) {
            result = -1;
            goto end_error;
        }

        r = CryptHashData(hash, passwd_data, passwd_len, 0);
        
        if(r == FALSE) {
            result = -1;
            goto end_error;
        }

        length = MAX_HASH_BUFFER_SIZE;
        r = CryptGetHashParam(hash, HP_HASHVAL, buffer, &length, 0);

        if(r == FALSE) {
            result = -1;
            goto end_error;
        }

    } else {

        memcpy(buffer, passwd_data, passwd_len);
        length = passwd_len;

    }

    memset(opad, 0x5C, hash_block_size);
    memset(ipad, 0x36, hash_block_size);

    for(i = 0; i < hash_block_size; i++) {
        ipad[i] ^= buffer[i];
        opad[i] ^= buffer[i];
    }

end_error:

    if(hash != NULL) {
        CryptDestroyHash(hash);
        hash = NULL;
    }

    RtlSecureZeroMemory(buffer, MAX_HASH_BUFFER_SIZE);

    return result;
}

/**
 * Internal function for creating a HMAC hash.
 *
 * @param hash_init An initialized hash that will be duplicated.
 * @param ipad Previously initialized inner padded key.
 * @param block_size Size of the internal block of the @a hash_init hash.
 * @param out_hash Pointer to a variable that receives the created hash.
 * @return Zero on success, nonzero on failure.
 */
static int hmac_start(HCRYPTHASH  hash_init,
                      const BYTE *ipad,
                      DWORD       block_size,
                      HCRYPTHASH *out_hash)
{
    BOOL       r      = FALSE;
    int        result = 0;
    HCRYPTHASH hash   = NULL;

    if(hash_init == NULL) return -1;
    if(ipad == NULL)      return -1;
    if(block_size == 0)   return -1;
    if(out_hash == NULL)  return -1;

    r = CryptDuplicateHash(hash_init, NULL, 0, &hash);
    if(r == FALSE || hash == NULL) {
        result = -1;
        goto end_error;
    }

    r = CryptHashData(hash, ipad, block_size, 0);
    if(r == FALSE) {
        result = -1;
        goto end_error;
    }

    *out_hash = hash;

end_error:

    if(result != 0) {
        CryptDestroyHash(hash);
        *out_hash = NULL;
    }

    return result;
}

/**
 * Internal function for digesting HMAC data.
 */
static int hmac_process(HCRYPTHASH  hash,
                        DWORD       length,
                        const BYTE *data)
{
    BOOL r;

    if(hash == NULL) return -1;

    r = CryptHashData(hash, data, length, 0);

    return (r != FALSE) ? 0 : -1;
}

/**
 * Internal function for finishing a HMAC hash.
 *
 * @param hash_init An initialized hash that will be duplicated.
 * @param hash Pointer to the HMAC hash.
 * @param opad Previously initialized outer padded key.
 * @param block_size Size of the internal block of the @a hash_init hash.
 * @param out_data Pointer to a buffer that receives the HMAC hash.
 * @return Zero on success, nonzero on failure.
 */
static int hmac_end(HCRYPTHASH  hash_init,
                    HCRYPTHASH *hash,
                    const BYTE *opad,
                    DWORD       block_size,
                    BYTE       *out_data)
{
    DWORD length = 0;
    BOOL  r      = FALSE;
    int   result = 0;

    if(hash_init == NULL) return -1;
    if(hash == NULL)      return -1;
    if(*hash == NULL)     return -1;
    if(opad == NULL)      return -1;
    if(block_size == 0)   return -1;
    if(out_data == NULL)  return -1;

    length = MAX_HASH_BUFFER_SIZE;
    r = CryptGetHashParam(*hash, HP_HASHVAL, out_data, &length, 0);

    if(*hash != NULL) {
        CryptDestroyHash(*hash);
        *hash = NULL;
    }

    if(r == FALSE) {
        return -1;
    }

    r = CryptDuplicateHash(hash_init, NULL, 0, hash);

    if(r == FALSE || *hash == NULL) {
        result = -1;
        goto end_error;
    }

    r = CryptHashData(*hash, opad, block_size, 0);

    if(r == FALSE) {
        result = -1;
        goto end_error;
    }

    r = CryptHashData(*hash, out_data, length, 0);

    if(r == FALSE) {
        result = -1;
        goto end_error;
    }

    length = MAX_HASH_BUFFER_SIZE;
    r = CryptGetHashParam(*hash, HP_HASHVAL, out_data, &length, 0);

    if(hash != NULL) {
        CryptDestroyHash(*hash);
        *hash = NULL;
    }

    if(r == FALSE) {
        result = -1;
        goto end_error;
    }

end_error:

    return result;
}

static void encode_uint32(DWORD value,
                          BYTE  buffer[4])
{
    buffer[0] = (value >> 24) & 0xFF;
    buffer[1] = (value >> 16) & 0xFF;
    buffer[2] = (value >>  8) & 0xFF;
    buffer[3] = (value      ) & 0xFF;
}

int pbkdf2_derive_bytes_hmac(HCRYPTHASH  hash_init,
                             DWORD       hash_block_size,
                             DWORD       iter_count,
                             DWORD       passwd_len,
                             const BYTE *passwd_data,
                             DWORD       salt_len,
                             const BYTE *salt_data,
                             DWORD       out_len,
                             BYTE       *out_data)
{
    BYTE ipad[MAX_HASH_BUFFER_SIZE];
    BYTE opad[MAX_HASH_BUFFER_SIZE];

    BYTE xor_sum[MAX_HASH_BUFFER_SIZE];
    BYTE iter_hash[MAX_HASH_BUFFER_SIZE];
    BYTE block[MAX_HASH_BUFFER_SIZE];
    BYTE temp[4];

    BOOL       r           = FALSE;
    int        result      = 0;
    HCRYPTPROV provider    = NULL;
    HCRYPTHASH hash        = NULL;
    HCRYPTHASH hash_salt   = NULL;
    DWORD      hash_size   = 0;
    DWORD      length      = 0;
    DWORD      block_index = 1;

    /* Sanity check arguments. */

    if(hash_init == NULL)                      return -1;
    if(hash_block_size == 0)                   return -1;
    if(iter_count == 0)                        return -1;
    if(out_len == 0)                           return 0;
    if(out_data == NULL)                       return -1;
    if(hash_block_size > MAX_HASH_BUFFER_SIZE) return -1;

    /* Get the hash output size. */

    length = 4;
    r = CryptGetHashParam(hash_init, HP_HASHSIZE, &hash_size, &length, 0);

    if(r == FALSE || hash_size > MAX_HASH_BUFFER_SIZE) {
        return -1;
    }

    /* Initialize HMAC ipad & opad. */

    result = hmac_init(hash_init, passwd_len, passwd_data, hash_block_size, ipad, opad);

    if(result != 0) {
        goto end_error;
    }

    /* Generate hashes until no more bytes need to be filled.
     * Each block is the XOR-sum B = U_1 ^ U_2 ... U_{iter_count}.
     * Output the bytes B, then continue on to the next block. Blocks do not
     * depend on previous blocks, so this while-loop could be parallelized. */

    while(out_len != 0) {

        DWORD iter;

        /* First iteration: U_1 = HMAC(password, salt || block_index) */

        encode_uint32(block_index, temp);

        /* We can compute the hash as far as the salt and then duplicate it for
         * the later blocks. This will be especially advantageous if the salt is
         * long. */

        if(hash_salt == NULL) {

            hmac_start(hash_init, ipad, hash_block_size, &hash);
            hmac_process(hash, salt_len, salt_data);

            r = CryptDuplicateHash(hash, NULL, 0, &hash_salt);
            
        } else {

            r = CryptDuplicateHash(hash_salt, NULL, 0, &hash);

        }

        if(r == FALSE) {
            /* CryptDuplicateHash failed. */
            result = -1;
            goto end_error;
        }

        hmac_process(hash, sizeof(temp), temp);
        result = hmac_end(hash_init, &hash, opad, hash_block_size, block);

        if(result != 0) {
            /* Hashing error. */
            goto end_error;
        }

        memcpy(xor_sum, block, hash_size);

        /* The rest of the iterations:
         * U_i = HMAC(password, U_{i - 1}) */

        for(iter = 1; iter < iter_count; iter++) {

            hmac_start(hash_init, ipad, hash_block_size, &hash);
            hmac_process(hash, hash_size, block);
            result = hmac_end(hash_init, &hash, opad, hash_block_size, iter_hash);

            if(result != 0) {
                /* Hashing error. */
                goto end_error;
            }

            /* XOR with the sum. */
            memxor(xor_sum, iter_hash, hash_size);
            memcpy(block, iter_hash, hash_size);

        }

        if(out_len >= hash_size) {

            /* Advance to the next block. */

            memcpy(out_data, xor_sum, hash_size);

            out_data += hash_size;
            out_len  -= hash_size;

            block_index++;

        } else {

            /* This was the final block. */

            memcpy(out_data, xor_sum, out_len);
            break;

        }

    }

end_error:

    RtlSecureZeroMemory(ipad,      MAX_HASH_BUFFER_SIZE);
    RtlSecureZeroMemory(opad,      MAX_HASH_BUFFER_SIZE);
    RtlSecureZeroMemory(xor_sum,   MAX_HASH_BUFFER_SIZE);
    RtlSecureZeroMemory(iter_hash, MAX_HASH_BUFFER_SIZE);
    RtlSecureZeroMemory(block,     MAX_HASH_BUFFER_SIZE);

    if(hash != NULL) {
        CryptDestroyHash(hash);
    }

    if(hash_salt != NULL) {
        CryptDestroyHash(hash_salt);
    }

    return result;
}
