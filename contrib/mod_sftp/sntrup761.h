#ifndef MOD_SFTP_SNTRUP761_H
#define MOD_SFTP_SNTRUP761_H

#include "mod_sftp.h"

typedef int8_t crypto_int8;
typedef uint8_t crypto_uint8;
typedef int16_t crypto_int16;
typedef uint16_t crypto_uint16;
typedef int32_t crypto_int32;
typedef uint32_t crypto_uint32;
typedef int64_t crypto_int64;
typedef uint64_t crypto_uint64;

#if defined(PR_USE_SODIUM)
/* Use Sodium's randombytes() implementation, if present. */
# include <sodium.h>
# else
/* Use OpenSSL for random bytes. */
#define randombytes(buf, buf_len) RAND_bytes((buf), (buf_len))
#endif /* PR_USE_SODIUM */

#if !defined(PR_USE_SODIUM)
static inline int crypto_hash_sha512(unsigned char *out,
    const unsigned char *in, unsigned long long inlen) {
  if (EVP_Digest(in, inlen, out, NULL, EVP_sha512(), NULL) == 0) {
    return -1;
  }
  return 0;
}
#endif /* PR_USE_SODIUM */

#define sntrup761_PUBLICKEYBYTES	1158
#define sntrup761_SECRETKEYBYTES	1763
#define sntrup761_CIPHERTEXTBYTES	1039
#define sntrup761_BYTES			32

int sntrup761_enc(unsigned char *cstr, unsigned char *k,
  const unsigned char *pk);
int sntrup761_dec(unsigned char *k, const unsigned char *cstr,
  const unsigned char *sk);
int sntrup761_keypair(unsigned char *pk, unsigned char *sk);

#endif /* MOD_SFTP_SNTRUP761_H */
