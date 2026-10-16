/*
 * ProFTPD - mod_sftp public CA key store (including RFC4716 public key file
 *                                         format)
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

#ifndef MOD_SFTP_CASTORE_H
#define MOD_SFTP_CASTORE_H

#include "mod_sftp.h"

int sftp_castore_init(void);
int sftp_castore_free(void);

int sftp_castore_supports_store(const char *store_type,
  unsigned int store_ctype);
int sftp_castore_verify_host_cert(pool *p, const char *user,
  const char *host_fqdn, const char *host_user, unsigned char *cert_data,
  uint32_t cert_datalen, unsigned long cert_opts, pr_table_t *verify_notes);
int sftp_castore_verify_user_cert(pool *p, const char *user,
  unsigned char *cert_data, uint32_t cert_datalen, unsigned long cert_opts,
  pr_table_t *verify_notes);

#endif /* MOD_SFTP_CASTORE_H */
