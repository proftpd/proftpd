/*
 * ProFTPD - mod_sftp key mgmt (keys)
 * Copyright (c) 2008-2025 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 */

#ifndef MOD_SFTP_KEYS_H
#define MOD_SFTP_KEYS_H

#include "mod_sftp.h"

enum sftp_key_type_e {
  SFTP_KEY_UNKNOWN = 0,
  SFTP_KEY_DSA,
  SFTP_KEY_RSA,
  SFTP_KEY_ECDSA_256,
  SFTP_KEY_ECDSA_384,
  SFTP_KEY_ECDSA_521,
  SFTP_KEY_ED25519,
  SFTP_KEY_ED448,
  SFTP_KEY_RSA_SHA256,
  SFTP_KEY_RSA_SHA512,

  /* OpenSSH security keys */
  SFTP_KEY_ECDSA_256_SK,
  SFTP_KEY_ED25519_SK
};

/* Details learned during verification of signed data, such as for
 * Security Keys (SK).
 */
struct sftp_verify_details {
  int is_security_key;
  const char *sk_application;
  uint32_t sk_counter;
  unsigned char sk_flags;
};

/* Returns a string of colon-separated lowercase hex characters, representing
 * the key "fingerprint" which has been run through the specified digest
 * algorithm.
 *
 * As per draft-ietf-secsh-fingerprint-00, only MD5 fingerprints are currently
 * supported.
 */
const char *sftp_keys_get_fingerprint(pool *p, unsigned char *key_data,
  uint32_t key_datalen, int digest_algo_id);
#define SFTP_KEYS_FP_DIGEST_MD5		1
#define SFTP_KEYS_FP_DIGEST_SHA1	2
#define SFTP_KEYS_FP_DIGEST_SHA256	3

const char *sftp_keys_get_fingerprint2(pool *p, unsigned char *key_data,
  uint32_t key_datalen, int digest_algo_id, int fmt_id);
#define SFTP_KEYS_FP_FMT_BASE64		1
#define SFTP_KEYS_FP_FMT_HEX		2
#define SFTP_KEYS_FP_FMT_HEX_COLONS	3

/* Retrieve the algorithm/encoding currently in effect for fingerprints. */
int sftp_keys_get_fingerprint_algo(pool *p, int *algo_id, const char **algo,
  int *fmt_id);

/* Security Key flags */
#define SFTP_KEYS_SK_USER_PRESENCE_REQUIRED	0x001
#define SFTP_KEYS_SK_USER_VERIFICATION_REQUIRED	0x004

void sftp_keys_free(void);
int sftp_keys_get_hostkey(pool *p, const char *);
const unsigned char *sftp_keys_get_hostkey_data(pool *, enum sftp_key_type_e,
  uint32_t *);
void sftp_keys_get_passphrases(void);
int sftp_keys_set_passphrase_provider(const char *);
const unsigned char *sftp_keys_sign_data(pool *, enum sftp_key_type_e,
  const unsigned char *, size_t, size_t *);
#ifdef PR_USE_OPENSSL_ECC
int sftp_keys_validate_ecdsa_params(const EC_GROUP *, const EC_POINT *);
#endif /* PR_USE_OPENSSL_ECC */
int sftp_keys_verify_pubkey_type(pool *, unsigned char *, uint32_t,
  enum sftp_key_type_e);
int sftp_keys_verify_signed_data(pool *, const char *,
  unsigned char *, uint32_t, unsigned char *, uint32_t,
  unsigned char *, size_t, struct sftp_verify_details *);
int sftp_keys_permit_key(pool *, const char *, const char *,
  struct sftp_verify_details *, pr_table_t *);

/* Sets minimum key sizes. */
int sftp_keys_set_key_limits(int rsa_min, int dsa_min, int ec_min);

/* Used for supporting the OpenSSH hostkey rotation mechanism. */
int sftp_keys_send_hostkeys(pool *p);
int sftp_keys_prove_hostkeys(pool *p, int want_reply, unsigned char *buf,
  uint32_t buflen);

int sftp_keys_clear_dsa_hostkey(void);
int sftp_keys_clear_ecdsa_hostkey(void);
int sftp_keys_clear_ed25519_hostkey(void);
int sftp_keys_clear_ed448_hostkey(void);
int sftp_keys_clear_rsa_hostkey(void);
int sftp_keys_have_dsa_hostkey(void);
int sftp_keys_have_ecdsa_hostkey(pool *, int **);
int sftp_keys_have_ed25519_hostkey(void);
int sftp_keys_have_ed448_hostkey(void);
int sftp_keys_have_rsa_hostkey(void);
#endif /* MOD_SFTP_KEYS_H */
