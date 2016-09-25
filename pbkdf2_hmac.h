#pragma once

#include <Windows.h>

/**
 * RFC 2898 PBKDF2 using HMAC as the pseudo-random number generator.
 *
 * Password-base key derivation function with HMAC. Based on the RFC 2898
 * specification https://tools.ietf.org/html/rfc2898
 *
 * Uses Windows CryptoAPI. The input parameter @a hash_init is used as a
 * reference hash and duplicated for the HMAC operations. The parameter hash
 * is not modified during operation. Since duplicating a hash requires no
 * knowledge of its provider or its algorithm, this enables a simpler interface.
 *
 * The @a out_data buffer contains valid key bytes only when the return value of
 * this function is zero.
 *
 * @param hash_init Initialized hash which is duplicated for the HMAC
 *     operations. For example, for PBKDF2-HMAC-SHA2-256, this parameter should
 *     just contain an empty SHA2-256 hash. The argument hash is not modified.
 * @param hash_block_size Size of the internal block that the @a hash_init
 *     hash uses, in bytes. For example, for SHA1 and SHA2-256 this value should
 *     be 64. Note that the internal block size is not necessarily the same as
 *     the hash output size.
 * @param iter_count Iteration count for the PBKDF2 algorithm, RFC 2898
 *     recommends this to be at least 1000 for SHA1.
 * @param passwd_len Length of the password in the @a passwd_data buffer.
 * @param passwd_data Pointer to the password data.
 * @param salt_len Length of the salt in the @a salt_data buffer. RFC 2898
 *     recommends a salt length of at least 64 bytes.
 * @param salt_data Pointer to the salt data.
 * @param out_len Amount of key bytes to be derived. The @a out_data buffer must
 *     be at least @a out_len bytes in size.
 * @param out_data Pointer to a buffer that receives the derived key bytes.
 * @return Zero on success, nonzero on failure.
 */
int pbkdf2_derive_bytes_hmac(HCRYPTHASH  hash_init,
                             DWORD       hash_block_size,
                             DWORD       iter_count,
                             DWORD       passwd_len,
                             const BYTE *passwd_data,
                             DWORD       salt_len,
                             const BYTE *salt_data,
                             DWORD       out_len,
                             BYTE       *out_data);
