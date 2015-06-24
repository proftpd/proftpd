/*
 * ProFTPD - mod_sftp user authentication (auth)
 * Copyright (c) 2008-2015 TJ Saunders
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

#include "mod_sftp.h"

#ifndef MOD_SFTP_AUTH_H
#define MOD_SFTP_AUTH_H

#include "packet.h"

#define SFTP_AUTH_FL_METH_PUBLICKEY	0x001
#define SFTP_AUTH_FL_METH_KBDINT	0x002
#define SFTP_AUTH_FL_METH_PASSWORD	0x004
#define SFTP_AUTH_FL_METH_HOSTBASED	0x008 

/* Structures which define a list of authentication methods; when each method
 * in a list has been satisfied, authentication succeeds.
 */
struct sftp_auth_method {
  unsigned int method_id;
  const char *method_name;

  /* For e.g. kbdint driver names. */
  const char *submethod_name;

  /* For use during authentication. */
  int succeeded, failed;
};

struct sftp_auth_chain {
  pool *pool;
  array_header *methods;
  int completed;
};

struct sftp_auth_chain *sftp_auth_chain_alloc(pool *);
int sftp_auth_chain_add_method(struct sftp_auth_chain *, unsigned int,
  const char *, const char *);

/* Parse given method name, e.g. "password" or "keyboard-interactive:pam",
 * into the ID for the method, and the submethod portion (if any).
 */
int sftp_auth_chain_parse_method(pool *p, const char *, unsigned int *,
  const char **, const char **);

/* Parse a chain of methods, e.g. "publickey+password", into its component
 * method names.  Returns the list of parsed method names, or NULL on error.
 */
array_header *sftp_auth_chain_parse_method_chain(pool *p, const char *);

char *sftp_auth_get_default_dir(void);
int sftp_auth_handle(struct ssh2_packet *);
int sftp_auth_init(void);

/* Handles 'hostbased' user authentication. */
int sftp_auth_hostbased(struct ssh2_packet *, cmd_rec *,
  const char *, const char *, const char *, unsigned char **, uint32_t *,
  int *);
int sftp_auth_hostbased_init(pool *);

/* Handles 'keyboard-interactive' user authentication. */
int sftp_auth_kbdint(struct ssh2_packet *, cmd_rec *,
  const char *, const char *, const char *, unsigned char **, uint32_t *,
  int *);
int sftp_auth_kbdint_init(pool *);

/* Handles 'password' user authentication. */
int sftp_auth_password(struct ssh2_packet *, cmd_rec *,
  const char *, const char *, const char *, unsigned char **, uint32_t *,
  int *);
int sftp_auth_password_init(pool *);

/* Handles 'publickey' user authentication. */
int sftp_auth_publickey(struct ssh2_packet *, cmd_rec *,
  const char *, const char *, const char *, unsigned char **, uint32_t *,
  int *);
int sftp_auth_publickey_init(pool *);

#endif
