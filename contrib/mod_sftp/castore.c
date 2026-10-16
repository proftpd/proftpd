/*
 * ProFTPD - mod_sftp CA key stores
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

#include "mod_sftp.h"
#include "certs.h"
#include "castore.h"
#include "rfc4716.h"

extern int ServerUseReverseDNS;

struct sftp_castore_store {
  struct sftp_castore_store *prev, *next;

  const char *store_type;
  sftp_castore_t *(*store_open)(pool *, int, const char *, const char *);
  unsigned int store_ctypes;
};

static pool *castore_pool = NULL;
static struct sftp_castore_store *castore_stores = NULL;
static unsigned int castore_nstores = 0;

static const char *trace_channel = "ssh2";

/* Iterate through any notes, normalizing any case-insensitive matches for
 * the supported RFC4716 headers.
 *
 * Actually, we cheat and leave the existing entries alone.  Instead, we
 * simply change the key comparator to a case-insensitive version.
 */

static int rfc4716_header_keycmp(const void *key1, size_t keysz1,
    const void *key2, size_t keysz2) {
  const char *k1, *k2;

  if (keysz1 != keysz2) {
    return keysz1 < keysz2 ? -1 : 1;
  }

  k1 = key1;
  k2 = key2;

  return strncmp(k1, k2, keysz1);
}

static void prepare_verify_notes(pr_table_t *notes) {
  int res;

  res = pr_table_ctl(notes, PR_TABLE_CTL_SET_KEY_CMP, rfc4716_header_keycmp);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1,
      "error setting case-insensitive comparator on notes: %s",
      strerror(errno));
  }
}

/* CA Store API internals */

static struct sftp_castore_store *castore_get_store(const char *store_type,
    unsigned int ctypes) {
  struct sftp_castore_store *store;

  for (store = castore_stores; store; store = store->next) {
    pr_signals_handle();

    if ((store->store_ctypes & ctypes) &&
        strcmp(store->store_type, store_type) == 0) {
      return store;
    }
  }

  errno = ENOENT;
  return NULL;
}

/* Main CA Store API */

int sftp_castore_register_store(const char *store_type,
    sftp_castore_t *(*store_open)(pool *, int, const char *, const char *),
    unsigned int store_ctypes) {
  struct sftp_castore_store *store;

  if (store_type == NULL ||
      store_open == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (castore_pool == NULL) {
    castore_pool = make_sub_pool(permanent_pool);
    pr_pool_tag(castore_pool, "SFTP CA Store Pool");
  }

  store = castore_get_store(store_type, store_ctypes);
  if (store != NULL) {
    errno = EEXIST;
    return -1;
  }

  store = pcalloc(castore_pool, sizeof(struct sftp_castore_store));
  store->store_type = pstrdup(castore_pool, store_type);
  store->store_open = store_open;
  store->store_ctypes = store_ctypes;

  store->next = castore_stores;
  castore_stores = store;
  castore_nstores++;

  return 0;
}

int sftp_castore_unregister_store(const char *store_type,
    unsigned int store_ctypes) {
  struct sftp_castore_store *store;

  if (store_type == NULL) {
    errno = EINVAL;
    return -1;
  }

  store = castore_get_store(store_type, store_ctypes);
  if (store == NULL) {
    errno = ENOENT;
    return -1;
  }

  if (store->prev != NULL) {
    store->prev->next = store->next;

  } else {
    castore_stores = store->next;
  }

  if (store->next != NULL) {
    store->next->prev = store->prev;
  }

  store->prev = store->next = NULL;
  castore_nstores--;

  return 0;
}

int sftp_castore_init(void) {
  /* Always support RFC4716 CAs, via files, by default. */
  sftp_rfc4716_init();

  return 0;
}

int sftp_castore_free(void) {
  sftp_rfc4716_free();

  return 0;
}

int sftp_castore_supports_store(const char *store_type,
    unsigned int store_ctype) {
  struct sftp_castore_store *store;

  store = castore_get_store(store_type, store_ctype);
  if (store != NULL) {
    return 0;
  }

  errno = ENOENT;
  return -1;
}

int sftp_castore_verify_host_cert(pool *p, const char *user,
    const char *host_fqdn, const char *host_user, unsigned char *cert_data,
    uint32_t cert_datalen, unsigned long cert_opts, pr_table_t *notes) {
  register unsigned int i;
  struct sftp_cert *cert = NULL;
  int matched_principal = FALSE, res = -1;
  config_rec *c;
  char *store_type = NULL;

  if (host_fqdn == NULL ||
      host_user == NULL ||
      cert_data == NULL ||
      cert_datalen == 0) {
    errno = EINVAL;
    return -1;
  }

  if (sftp_certs_parse_cert(p, cert_data, cert_datalen, &cert) < 0) {
    return -1;
  }

  if (sftp_certs_validate_cert(p, cert, cert_opts) < 0) {
    int xerrno = errno;

    destroy_pool(cert->cert_pool);
    errno = xerrno;
    return -1;
  }

  if (cert->cert_role != SFTP_SSH_CERT_TYPE_HOST) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "%s certificate is invalid, for it is not a host certificate",
      cert->cert_algo);
    destroy_pool(cert->cert_pool);
    errno = EPERM;
    return -1;
  }

  if (cert->critical_options != NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "%s host certificate is invalid, for it uses critical options",
      cert->cert_algo);
    destroy_pool(cert->cert_pool);
    errno = EPERM;
    return -1;
  }

  /* Verify the principals list contains the given name of the host. */
  if (cert->principals == NULL &&
      (cert_opts & SFTP_CERT_OPT_ALLOW_EMPTY_PRINCIPALS)) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "%s host certificate has empty principals, using AllowEmptyPrincipals "
      "to authenticate user '%s' from host '%s'", cert->cert_algo, user,
      host_fqdn);
    matched_principal = TRUE;

  } else {
    for (i = 0; i < cert->principals->nelts; i++) {
      const char *principal;

      principal = ((char **) cert->principals->elts)[i];

      pr_trace_msg(trace_channel, 25,
        "comparing host certificate principal '%s' against host '%s'",
        principal, host_fqdn);

      if (cert_opts & SFTP_CERT_OPT_ALLOW_MATCH_PRINCIPALS) {
        if (pr_fnmatch(principal, host_fqdn, 0) == 0) {
          matched_principal = TRUE;
        }

      } else {
        if (strcmp(principal, host_fqdn) == 0) {
          matched_principal = TRUE;
        }
      }

      if (matched_principal == TRUE) {
        break;
      }
    }
  }

  if (matched_principal == FALSE) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "%s certificate is invalid, for host '%s' is not a listed principal",
      cert->cert_algo, host_fqdn);
    destroy_pool(cert->cert_pool);
    errno = EPERM;
    return -1;
  }

  c = find_config(main_server->conf, CONF_PARAM, "SFTPAuthorizedHostCAKeys",
    FALSE);
  if (c == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "no SFTPAuthorizedHostCAKeys configured");
    destroy_pool(cert->cert_pool);
    errno = EPERM;
    return -1;
  }

  for (i = 0; i < c->argc; i++) {
    struct sftp_castore_store *scs;
    char *ptr;

    res = -1;
    pr_signals_handle();

    store_type = c->argv[i];

    pr_trace_msg(trace_channel, 2,
      "using SFTPAuthorizedHostCAKeys '%s' for certificate authentication for "
      "user '%s', host %s", store_type, user, host_fqdn);

    ptr = strchr(store_type, ':');
    if (ptr == NULL) {
      pr_trace_msg(trace_channel, 2,
        "skipping badly formatted SFTPAuthorizedHostCAKeys '%s'", store_type);
      continue;
    }

    *ptr = '\0';

    scs = castore_get_store(store_type, SFTP_SSH2_HOST_CA_KEY_STORE);
    if (scs != NULL) {
      sftp_castore_t *store;

      store = (scs->store_open)(p, SFTP_SSH2_HOST_CA_KEY_STORE, ptr + 1, user);
      if (store != NULL) {
        if (store->verify_host_cert_ca_key != NULL) {
          int xerrno;

          prepare_verify_notes(notes);
          res = (store->verify_host_cert_ca_key)(store, p, user, host_fqdn,
            host_user, cert->signature_pubkey_data,
            cert->signature_pubkey_datalen, notes);
          xerrno = errno;
          (store->store_close)(store);

          *ptr = ':';
          if (res == 0) {
            break;
          }

          pr_trace_msg(trace_channel, 3,
            "error verifying certificate for host '%s', user '%s' ('%s'): %s",
            host_fqdn, user, host_user, strerror(xerrno));
          if (xerrno == ENOENT) {
            pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
              "no matching CA found for host '%s' in '%s'", host_fqdn, ptr + 1);
          }

        } else {
          *ptr = ':';
          pr_trace_msg(trace_channel, 7,
            "error using SFTPAuthorizedHostCAKeys '%s': %s", store_type,
            strerror(ENOSYS));
        }

        continue;

      } else {
        *ptr = ':';
        pr_trace_msg(trace_channel, 7,
          "error opening SFTPAuthorizedHostCAKeys '%s': %s", store_type,
          strerror(errno));
      }
    }

    *ptr = ':';
  }

  if (res == 0) {
    const char *ca_fp;

    pr_trace_msg(trace_channel, 8,
      "verified host certificate for user '%s', host '%s'", user, host_fqdn);

    ca_fp = sftp_keys_get_fingerprint2(p, cert->signature_pubkey_data,
      cert->signature_pubkey_datalen, SFTP_KEYS_FP_DIGEST_SHA256,
      SFTP_KEYS_FP_FMT_BASE64);
    pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "Accepted %s host certicate ID '%s' (serial number %lu) signed by "
      "%s CA %s via %s", cert->cert_algo, cert->cert_id,
      (unsigned long) cert->serialno, cert->signature_pubkey_algo, ca_fp,
      store_type);

    destroy_pool(cert->cert_pool);
    return res;
  }

  destroy_pool(cert->cert_pool);
  errno = EACCES;
  return -1;
}

int sftp_castore_verify_user_cert(pool *p, const char *user,
    unsigned char *cert_data, uint32_t cert_datalen, unsigned long cert_opts,
    pr_table_t *notes) {
  register unsigned int i;
  struct sftp_cert *cert = NULL;
  int matched_principal = FALSE, res = -1;
  config_rec *c;
  char *store_type = NULL;

  if (cert_data == NULL ||
      cert_datalen == 0) {
    errno = EINVAL;
    return -1;
  }

  if (sftp_certs_parse_cert(p, cert_data, cert_datalen, &cert) < 0) {
    return -1;
  }

  if (sftp_certs_validate_cert(p, cert, cert_opts) < 0) {
    int xerrno = errno;

    destroy_pool(cert->cert_pool);
    errno = xerrno;
    return -1;
  }

  if (cert->cert_role != SFTP_SSH_CERT_TYPE_USER) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "%s certificate is invalid, for it is not a user certificate",
      cert->cert_algo);
    destroy_pool(cert->cert_pool);
    errno = EPERM;
    return -1;
  }

  /* Verify the principals list contains the given name of the user. */
  for (i = 0; i < cert->principals->nelts; i++) {
    const char *principal;

    principal = ((char **) cert->principals->elts)[i];

    pr_trace_msg(trace_channel, 25,
      "comparing user certificate principal '%s' against user '%s'", principal,
      user);

    if (cert_opts & SFTP_CERT_OPT_ALLOW_MATCH_PRINCIPALS) {
      if (pr_fnmatch(principal, user, 0) == 0) {
        matched_principal = TRUE;
      }

    } else {
      if (strcmp(principal, user) == 0) {
        matched_principal = TRUE;
      }
    }

    if (matched_principal == TRUE) {
      break;
    }
  }

  if (matched_principal == FALSE) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "%s certificate is invalid, for user '%s' is not a listed principal",
      cert->cert_algo, user);
    destroy_pool(cert->cert_pool);
    errno = EPERM;
    return -1;
  }

  c = find_config(main_server->conf, CONF_PARAM, "SFTPAuthorizedUserCAKeys",
    FALSE);
  if (c == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "no SFTPAuthorizedUserCAKeys configured");
    destroy_pool(cert->cert_pool);
    errno = EPERM;
    return -1;
  }

  for (i = 0; i < c->argc; i++) {
    struct sftp_castore_store *scs;
    const char *path, *sess_user;
    char *ptr;

    pr_signals_handle();

    res = -1;
    store_type = c->argv[i];

    ptr = strchr(store_type, ':');
    if (ptr == NULL) {
      pr_trace_msg(trace_channel, 2,
        "skipping badly formatted SFTPAuthorizedUserCAKeys '%s'", store_type);
      continue;
    }

    *ptr = '\0';
    path = ptr + 1;

    /* Check for any variables in the configured path.
     *
     * Note that path_subst_uservar() relies on the session.user variable
     * being set, hence why we cache/restore its value.
     */
    sess_user = session.user;
    session.user = user;
    path = path_subst_uservar(p, &path);
    session.user = sess_user;

    pr_trace_msg(trace_channel, 2,
      "using SFTPAuthorizedUserCAKeys '%s:%s' for certificate authentication "
      "for user '%s'", store_type, path, user);

    scs = castore_get_store(store_type, SFTP_SSH2_USER_CA_KEY_STORE);
    if (scs != NULL) {
      sftp_castore_t *store;

      store = (scs->store_open)(p, SFTP_SSH2_USER_CA_KEY_STORE, path, user);
      if (store != NULL) {
        if (store->verify_user_cert_ca_key != NULL) {
          int xerrno;

          prepare_verify_notes(notes);
          res = (store->verify_user_cert_ca_key)(store, p, user,
            cert->signature_pubkey_data, cert->signature_pubkey_datalen, notes);
          xerrno = errno;
          (store->store_close)(store);

          *ptr = ':';
          if (res == 0) {
            break;
          }

          pr_trace_msg(trace_channel, 3,
            "error verifying user certificate for user '%s': %s", user,
            strerror(xerrno));
          if (xerrno == ENOENT) {
            pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
              "no matching CA found for user '%s' in '%s'", user, path);
          }

        } else {
          *ptr = ':';
          pr_trace_msg(trace_channel, 7,
            "error using SFTPAuthorizedUserCAKeys '%s': %s", store_type,
            strerror(ENOSYS));
        }

        continue;

      } else {
        *ptr = ':';
        pr_trace_msg(trace_channel, 7,
          "error opening SFTPAuthorizedUserCAKeys '%s': %s", store_type,
          strerror(errno));
      }
    }

    *ptr = ':';
  }

  if (res == 0) {
    const char *ca_fp;

    pr_trace_msg(trace_channel, 8,
      "verified certificate for user '%s'", user);

    ca_fp = sftp_keys_get_fingerprint2(p, cert->signature_pubkey_data,
      cert->signature_pubkey_datalen, SFTP_KEYS_FP_DIGEST_SHA256,
      SFTP_KEYS_FP_FMT_BASE64);
    pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "Accepted %s user certicate ID '%s' (serial number %lu) signed by "
      "%s CA %s via %s", cert->cert_algo, cert->cert_id,
      (unsigned long) cert->serialno, cert->signature_pubkey_algo, ca_fp,
      store_type);

    destroy_pool(cert->cert_pool);
    return res;
  }

  destroy_pool(cert->cert_pool);
  errno = EACCES;
  return -1;
}
