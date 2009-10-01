/*
 * ProFTPD: mod_sql_passwd -- Various SQL password handlers
 * Copyright (c) 2009 TJ Saunders
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in
 * the source distribution.
 *
 * $Id: mod_sql_passwd.c,v 1.5 2009-10-01 15:25:34 castaglia Exp $
 */

#include "conf.h"
#include "privs.h"
#include "mod_sql.h"

#define MOD_SQL_PASSWD_VERSION		"mod_sql_passwd/0.0"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030302 
# error "ProFTPD 1.3.3rc2 or later required"
#endif

#if !defined(HAVE_OPENSSL) && !defined(PR_USE_OPENSSL)
# error "OpenSSL support required (--enable-openssl)"
#else
# include <openssl/evp.h>
#endif

module sql_passwd_module;

static int sql_passwd_engine = FALSE;

#define SQL_PASSWD_USE_BASE64		1
#define SQL_PASSWD_USE_HEX_LC		2
#define SQL_PASSWD_USE_HEX_UC		3
static unsigned int sql_passwd_encoding = SQL_PASSWD_USE_HEX_LC;

static char *sql_passwd_salt = NULL;
static size_t sql_passwd_salt_len = 0;
static unsigned int sql_passwd_salt_apprend = TRUE;

static modret_t *sql_passwd_auth(cmd_rec *cmd, const char *plaintext,
    const char *ciphertext, const char *digest) {
  EVP_MD_CTX md_ctxt;
  EVP_ENCODE_CTX base64_ctxt;
  const EVP_MD *md;

  /* According to RATS, the output buffer (buf) for EVP_EncodeBlock() needs to
   * be 4/3 the size of the input buffer (mdval).  Let's make it easy, and
   * use an output buffer that's twice the size of the input buffer.
   */
  unsigned char buf[EVP_MAX_MD_SIZE*2+1], mdval[EVP_MAX_MD_SIZE];
  unsigned int mdlen;

  char *copytext;               /* temporary copy of the ciphertext string */

  if (!sql_passwd_engine) {
    return PR_ERROR_INT(cmd, PR_AUTH_ERROR);
  }

  /* We need a copy of the ciphertext. */
  copytext = pstrdup(cmd->tmp_pool, ciphertext);

  OpenSSL_add_all_digests();

  md = EVP_get_digestbyname(digest);
  if (md == NULL) {
    sql_log(DEBUG_WARN, "no such digest '%s' supported", digest);
    return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
  }

  EVP_DigestInit(&md_ctxt, md);

  /* If a salt is configured, do we prepend the salt as a prefix (i.e. throw
   * it into the digest before the user-supplied password) or append it as a
   * suffix?
   */

  if (sql_passwd_salt_len > 0 &&
      sql_passwd_salt_append == FALSE) {
    /* If we have salt data, add it to the mix. */
    pr_log_debug(DEBUG9, MOD_SQL_PASSWD_VERSION
      ": adding %u bytes of salt data", sql_passwd_salt_len);
    EVP_DigestUpdate(&md_ctxt, (unsigned char *) sql_passwd_salt,
      sql_passwd_salt_len);
  }

  EVP_DigestUpdate(&md_ctxt, plaintext, strlen(plaintext));

  if (sql_passwd_salt_len > 0 &&
      sql_passwd_salt_append == TRUE) {
    /* If we have salt data, add it to the mix. */
    pr_log_debug(DEBUG9, MOD_SQL_PASSWD_VERSION
      ": adding %u bytes of salt data", sql_passwd_salt_len);
    EVP_DigestUpdate(&md_ctxt, (unsigned char *) sql_passwd_salt,
      sql_passwd_salt_len);
  }

  EVP_DigestFinal(&md_ctxt, mdval, &mdlen);

  memset(buf, '\0', sizeof(buf));

  switch (sql_passwd_encoding) {
    case SQL_PASSWD_USE_BASE64:
      EVP_EncodeInit(&base64_ctxt);
      EVP_EncodeBlock(buf, mdval, (int) mdlen);
      break;

    case SQL_PASSWD_USE_HEX_LC: {
      register unsigned int i;

      for (i = 0; i < mdlen; i++) {
        sprintf((char *) &(buf[i*2]), "%02x", mdval[i]);
      }

      break;
    }

    case SQL_PASSWD_USE_HEX_UC: {
      register unsigned int i;

      for (i = 0; i < mdlen; i++) {
        sprintf((char *) &(buf[i*2]), "%02X", mdval[i]);
      }

      break;
    }

    default:
      sql_log(DEBUG_WARN, "unsupported SQLPasswordEncoding configured");
      return PR_ERROR_INT(cmd, PR_AUTH_ERROR);
  }

  if (strcmp((char *) buf, copytext) == 0) {
    return PR_HANDLED(cmd);

  } else {
    pr_log_debug(DEBUG9, MOD_SQL_PASSWD_VERSION ": expected '%s', got '%s'",
      buf, copytext);
  }

  return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
}

static modret_t *sql_passwd_md5(cmd_rec *cmd, const char *plaintext,
    const char *ciphertext) {
  return sql_passwd_auth(cmd, plaintext, ciphertext, "md5");
}

static modret_t *sql_passwd_sha1(cmd_rec *cmd, const char *plaintext,
    const char *ciphertext) {
  return sql_passwd_auth(cmd, plaintext, ciphertext, "sha1");
}

/* Event handlers
 */

#if defined(PR_SHARED_MODULE)
static void sql_passwd_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_sql_passwd.c", (const char *) event_data) == 0) {
    sql_unregister_authtype("md5");
    sql_unregister_authtype("sha1");

    pr_event_unregister(&sql_passwd_module, NULL, NULL);
  }
}
#endif /* PR_SHARED_MODULE */

/* Configuration handlers
 */

/* usage: SQLPasswordEncoding "base64"|"hex"|"HEX" */
MODRET set_sqlpasswdencoding(cmd_rec *cmd) {
  unsigned int encoding;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (strcmp(cmd->argv[1], "base64") == 0) {
    encoding = SQL_PASSWD_USE_BASE64;

  } else if (strcmp(cmd->argv[1], "hex") == 0) {
    encoding = SQL_PASSWD_USE_HEX_LC;

  } else if (strcmp(cmd->argv[1], "HEX") == 0) {
    encoding = SQL_PASSWD_USE_HEX_UC;

  } else {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unsupported encoding '",
      cmd->argv[1], "' configured", NULL));
  }
 
  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[0]) = encoding;

  return PR_HANDLED(cmd);
}

/* usage: SQLPasswordEngine on|off */
MODRET set_sqlpasswdengine(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

/* usage: SQLPasswordSaltFile path|"none" ["prepend"|"append"] */
MODRET set_sqlpasswdsaltfile(cmd_rec *cmd) {
  if (cmd->argc < 2 ||
      cmd->argc > 3) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  (void) add_config_param_str(cmd->argv[0], 2, cmd->argv[1],
    cmd->argc == 3 ? cmd->argv[2] : "append");
  return PR_HANDLED(cmd);
}

/* Initialization routines
 */

static int sql_passwd_init(void) {

#if defined(PR_SHARED_MODULE)
  pr_event_register(&sql_passwd_module, "core.module-unload",
    sql_passwd_mod_unload_ev, NULL);
#endif /* PR_SHARED_MODULE */

  if (sql_register_authtype("md5", sql_passwd_md5) < 0) {
    pr_log_pri(PR_LOG_WARNING, MOD_SQL_PASSWD_VERSION
      ": unable to register 'md5' SQLAuthType handler: %s", strerror(errno));
  }

  pr_log_debug(DEBUG6, MOD_SQL_PASSWD_VERSION
    ": registered 'md5' SQLAuthType handler");

  if (sql_register_authtype("sha1", sql_passwd_sha1) < 0) {
    pr_log_pri(PR_LOG_WARNING, MOD_SQL_PASSWD_VERSION
      ": unable to register 'sha1' SQLAuthType handler: %s", strerror(errno));
  }

  pr_log_debug(DEBUG6, MOD_SQL_PASSWD_VERSION
    ": registered 'sha1' SQLAuthType handler");
  return 0;
}

static int sql_passwd_sess_init(void) {
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "SQLPasswordEngine", FALSE);
  if (c) {
    sql_passwd_engine = *((int *) c->argv[0]);
  }

  c = find_config(main_server->conf, CONF_PARAM, "SQLPasswordEncoding", FALSE);
  if (c) {
    sql_passwd_encoding = *((unsigned int *) c->argv[0]);
  }

  c = find_config(main_server->conf, CONF_PARAM, "SQLPasswordSaltFile", FALSE);
  if (c) {
    char *path;
    char *append;

    path = c->argv[0];
    append = c->argv[1];

    if (strcasecmp(path, "none") != 0) {
      int fd;

      PRIVS_ROOT
      fd = open(path, O_RDONLY);
      PRIVS_RELINQUISH

      if (fd >= 0) {
        char buf[512];
        ssize_t nread;
   
        nread = read(fd, buf, sizeof(buf));
        while (nread > 0) {
          pr_signals_handle();

          if (sql_passwd_salt == NULL) {

            /* If the very last byte in the buffer is a newline, trim it. */
            if (buf[nread-1] == '\n') {
              buf[nread-1] = '\0';
              nread--;
            }

            sql_passwd_salt_len = nread;
            sql_passwd_salt = palloc(session.pool, sql_passwd_salt_len);
            memcpy(sql_passwd_salt, buf, nread);

          } else {
            char *ptr, *tmp;

            /* Allocate a larger buffer for the salt. */
            ptr = tmp = palloc(session.pool, sql_passwd_salt_len + nread);
            memcpy(tmp, sql_passwd_salt, sql_passwd_salt_len);
            tmp += sql_passwd_salt_len;

            memcpy(tmp, buf, nread);
            sql_passwd_salt_len += nread;

            /* XXX Yes, this is a minor memory leak; we are overwriting the
             * previously allocated memory for the salt.  But it's per-session,
             * so it's not a great concern at this point.
             */
            sql_passwd_salt = ptr;
          }

          nread = read(fd, buf, sizeof(buf));
        }

        if (nread < 0) {
          pr_log_debug(DEBUG1, MOD_SQL_PASSWD_VERSION
            ": error reading salt data from SQLPasswordSaltFile '%s': %s",
            path, strerror(errno));
          sql_passwd_salt = NULL;
        }

        (void) close(fd);

        /* If the very last byte in the buffer is a newline, trim it.  This
         * is to deal with cases where the SaltFile may have been written
         * with an editor (e.g. vi) which automatically adds a trailing newline.
         */
        if (sql_passwd_salt[sql_passwd_salt_len-1] == '\n') {
          sql_passwd_salt[sql_passwd_salt_len-1] = '\0';
          sql_passwd_salt_len--;
        }

        /* Determine whether to use the obtained salt as a prefix or suffix. */ 
        if (strcasecmp(append, "prepend") == 0) {
          sql_passwd_salt_append = FALSE;

        } else {
          /* The default, for better/worse, is to append the salt as
           * a suffix.
           */
          sql_passwd_salt_append = TRUE;
        }

      } else {
        pr_log_debug(DEBUG1, MOD_SQL_PASSWD_VERSION
          ": unable to read SQLPasswordSaltFile '%s': %s", path,
          strerror(errno));
      }
    }
  }

  return 0;
}

/* Module API tables
 */

static conftable sql_passwd_conftab[] = {
  { "SQLPasswordEncoding",	set_sqlpasswdencoding,	NULL },
  { "SQLPasswordEngine",	set_sqlpasswdengine,	NULL },
  { "SQLPasswordSaltFile",	set_sqlpasswdsaltfile,	NULL },

  { NULL, NULL, NULL }
};

module sql_passwd_module = {

  /* Always NULL */
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "sql_passwd",

  /* Module configuration directive table */
  sql_passwd_conftab,

  /* Module command handler table */
  NULL,

  /* Module auth handler table */
  NULL,

  /* Module initialization */
  sql_passwd_init,

  /* Session initialization */
  sql_passwd_sess_init,

  /* Module version */
  MOD_SQL_PASSWD_VERSION
};

