/*
 * ProFTPD - mod_sftp SSH cert mgmt (certs)
 * Copyright (c) 2026 TJ Saunders
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 */

#ifndef MOD_SFTP_CERTS_H
#define MOD_SFTP_CERTS_H

#include "mod_sftp.h"
#include "keys.h"

/* Per ... */
#define SFTP_SSH_CERT_TYPE_USER		1
#define SFTP_SSH_CERT_TYPE_HOST		2

struct sftp_cert {
  pool *cert_pool;

  const char *cert_algo;
  uint32_t cert_role;
  uint64_t serialno;
  const char *cert_id;
  unsigned char *nonce;
  uint32_t nonce_len;
  uint64_t valid_before_ts, valid_after_ts;
  array_header *principals;
  pr_table_t *critical_options;
  pr_table_t *extensions;

  /* Signature key */
  const char *signature_pubkey_algo;
  unsigned char *signature_pubkey_data;
  uint32_t signature_pubkey_datalen;
};

uint32_t sftp_certs_read_nonce(pool *p, unsigned char *cert_data,
  uint32_t cert_datalen, const char *cert_algo, unsigned char **nonce);
int sftp_certs_parse_cert(pool *p, unsigned char *cert_data,
  uint32_t cert_datalen, struct sftp_cert **cert);

/* Perform basic certificate validation, checking expiry, supported
 * options/extensions, signature validation, etc.
 */
int sftp_certs_validate_cert(pool *p, struct sftp_cert *cert,
  unsigned long cert_opts);

#endif /* MOD_SFTP_CERTS_H */
