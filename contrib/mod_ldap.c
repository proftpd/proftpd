/* mod_ldap - LDAP password lookup module for ProFTPD
 * Copyright (c) 1999, 2000-3, John Morrissey <jwm@horde.net>
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
 * Furthermore, John Morrissey gives permission to link this program with
 * OpenSSL, and distribute the resulting executable, without including the
 * source code for OpenSSL in the source distribution.
 */

/*
 * mod_ldap v2.8.11
 *
 * Thanks for patches go to (in alphabetical order):
 *
 * Peter Fabian (fabian at staff dot matavnet dot hu) - LDAPAuthBinds
 * Pierrick Hascoet (pierrick at alias dot fr) - OpenSSL password hash support
 * Florian Lohoff (flo at rfc822 dot org) - LDAPForceDefault[UG]ID code
 * Steve Luzynski (steve at uniteone dot net) - HomedirOnDemandPrefix support
 * Gaute Nessan (gaute at kpnqwest dot no) - OpenLDAP 2.0 fixes
 * Marcin Obara (gryzzli at wp-sa dot pl) - User/group caching code, Sun
 *                                          LDAP library portability fixes
 * Michael Schout (mschout at gkg dot net) - Full-path HomedirOnDemand and
 *                                           multiple-HomedirOnDemandSuffix
 *                                           support
 * Klaus Steinberger (klaus dot steinberger at physik dot uni-muenchen dot de)
 *                                         - LDAPForceHomedirOnDemand support
 * Andreas Strodl (andreas at strodl dot org) - multiple group support
 * Ross Thomas (ross at grinfinity dot com) - Non-AuthBinds auth fix
 * Ivo Timmermans (ivo at debian dot org) - TLS support
 * Bert Vermeulen (bert at be dot easynet dot net) - LDAPHomedirOnDemand,
 *                                                   LDAPDefaultAuthScheme
 *
 *
 * $Id: mod_ldap.c,v 1.29 2003-03-06 02:18:06 jwm Exp $
 * $Libraries: -lldap -llber$
 */

/* You can override the attribute names that mod_ldap uses here. */

/* User attributes */
#ifndef UID_ATTR
#define UID_ATTR            "uid"
#endif
#ifndef UIDNUMBER_ATTR
#define UIDNUMBER_ATTR      "uidNumber"
#endif
#ifndef GIDNUMBER_ATTR
#define GIDNUMBER_ATTR      "gidNumber"
#endif
#ifndef HOMEDIRECTORY_ATTR
#define HOMEDIRECTORY_ATTR  "homeDirectory"
#endif
#ifndef USERPASSWORD_ATTR
#define USERPASSWORD_ATTR   "userPassword"
#endif
#ifndef LOGINSHELL_ATTR
#define LOGINSHELL_ATTR     "loginShell"
#endif

/* Group attributes */
/* NOTE: gidNumber (above) is also a group attribute. */
#ifndef CN_ATTR
#define CN_ATTR             "cn"
#endif
#ifndef MEMBERUID_ATTR
#define MEMBERUID_ATTR      "memberUid"
#endif

/* Quota attributes */
#ifndef QUOTA_ATTR
#define QUOTA_ATTR          "ftpQuota"
#endif

/* Uncomment this to use LDAPv3 TLS. If enabled, we will try to enable
 * TLS after connecting to the LDAP server. If TLS cannot be enabled, the
 * LDAP connection will fail.
 */
/* #define USE_LDAPV3_TLS */

/* Uncomment this if you have OpenSSL and wish to verify non-crypt()
 * password hashes locally with OpenSSL. You'll also need to edit
 * ../Make.rules so the compiler will find OpenSSL's include files
 * (-I/path/to/include-dir) and link again OpenSSL's crypto library
 * (-L/path/to/lib-dir -lcrypto).
 */
/* #define HAVE_OPENSSL */

/*
 * If you have to edit anything below this line, it's a bug. Report it
 * at http://bugs.proftpd.org/.
 */

/* Default mode to use when creating home directory on demand. */
#define DEFAULT_HOMEDIR_MODE 0755

#include "conf.h"
#include "privs.h"

#ifdef HAVE_CRYPT_H
# include <crypt.h>
#endif

#include <errno.h>
#include <ctype.h>     /* isdigit()   */
#include <stdio.h>     /* snprintf()  */
#include <string.h>    /* various :-) */
#include <sys/types.h> /* seteuid()   */
#include <unistd.h>    /* seteuid()   */

#include <lber.h>
#include <ldap.h>

/* Sun fucks my shit right up. */
#ifndef LDAP_OPT_SUCCESS
# define LDAP_OPT_SUCCESS LDAP_SUCCESS
#endif

#ifdef HAVE_OPENSSL
# include <openssl/evp.h>
#endif

#define HASH_TABLE_SIZE 10

typedef union pr_idauth {
  uid_t uid;
  gid_t gid;
} pr_idauth_t;

typedef struct _idmap {
  struct _idmap *next, *prev;

  /* This is a union because different OSs may give different types/sizes to
   * UIDs and GIDs. This presents a far more portable way to deal with this
   * reality.
   */
  pr_idauth_t id;

  char *name;                  /* user or group name */
  unsigned short int negative; /* have we gotten a negative answer before? */
} pr_idmap_t;

static xaset_t *uid_table[HASH_TABLE_SIZE];
static xaset_t *gid_table[HASH_TABLE_SIZE];

/* Config entries */
static char *ldap_server, *ldap_dn, *ldap_dnpass,
            *ldap_auth_filter, *ldap_uid_filter,
            *ldap_group_gid_filter, *ldap_group_name_filter,
            *ldap_group_member_filter, *ldap_quota_filter,
            *ldap_auth_basedn, *ldap_uid_basedn, *ldap_gid_basedn,
            *ldap_quota_basedn,
            *ldap_defaultauthscheme, *ldap_authbind_dn,
            *ldap_hdod_prefix, **ldap_hdod_suffix;
static int ldap_doauth = 0, ldap_douid = 0, ldap_dogid = 0, ldap_doquota = 0,
           ldap_authbinds = 1, ldap_negcache = 1,
           ldap_querytimeout = 0, ldap_hdod = 0, ldap_hdod_prefix_nouname = 0,
           ldap_forcedefaultuid = 0, ldap_forcedefaultgid = 0,
           ldap_forcehdod = 0,
           ldap_search_scope = LDAP_SCOPE_SUBTREE;
static mode_t ldap_hdod_mode = DEFAULT_HOMEDIR_MODE;
static struct timeval ldap_querytimeout_tp;

/* We get these values from get_param_int(), which returns a long. On
 * systems with 4-byte longs (most 32-bit systems in existence), this limits
 * you to a maximum UID/GID of around 2 billion (half the limit of a true
 * 32-bit-UID-enabled system, which tops out at about 4 billion).
 */
static uid_t ldap_defaultuid = -1;
static gid_t ldap_defaultgid = -1;

#ifdef USE_LDAPV3_TLS
static int ldap_use_tls = 0;
#endif

static LDAP *ld;
static struct passwd *pw = NULL;
static struct group *gr = NULL;
array_header *cached_quota = NULL;


static int
pr_ldap_module_init(void)
{
  memset(uid_table, 0, sizeof(uid_table));
  memset(gid_table, 0, sizeof(gid_table));
  return 0;
}

static void
pr_ldap_set_sizelimit(int limit)
{
  /* I couldn't think of a better way to do this without having autoconf
   * jump through hoops to detect whether ldap_set_option() is present.
   * I think this works fairly well, though, as we're sure to need
   * LDAP_OPT_SIZELIMIT to use ldap_set_option in this case. :-)
   */
#ifdef LDAP_OPT_SIZELIMIT
  int ret;
  if ((ret = ldap_set_option(ld, LDAP_OPT_SIZELIMIT, (void *)&limit)) != LDAP_OPT_SUCCESS)
    log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_connect(): ldap_set_option() unable to set query size limit to %d entries: %s", limit, ldap_err2string(ret));
#else
  ld->ld_sizelimit = limit;
#endif
}

static int
pr_ldap_connect(void)
{
  int ret;
#ifdef USE_LDAPV3_TLS
  int version = LDAP_VERSION3;
#endif

  if ((ld = ldap_init(ldap_server, LDAP_PORT)) == NULL) {
    log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_connect(): ldap_init() to %s failed: %s", ldap_server, strerror(errno));
    return -1;
  }

#ifdef USE_LDAPV3_TLS
  if (ldap_use_tls) {
    if ((ret = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version)) != LDAP_OPT_SUCCESS) {
      log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_connect(): Setting LDAP version option failed: %s", ldap_err2string(ret));
      pr_ldap_unbind();
      return -1;
    }

    log_debug(DEBUG2, "mod_ldap: Starting TLS for this connection.");
    if ((ret = ldap_start_tls_s(ld, NULL, NULL)) != LDAP_SUCCESS) {
      log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_connect(): Starting TLS failed: %s", ldap_err2string(ret));
      pr_ldap_unbind();
      return -1;
    }
  }
#endif /* USE_LDAPV3_TLS */

  if ((ret = ldap_simple_bind_s(ld, ldap_dn, ldap_dnpass) != LDAP_SUCCESS)) {
    log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_connect(): ldap_simple_bind() as %s failed: %s", ldap_dn, ldap_err2string(ret));
    return -1;
  }

  pr_ldap_set_sizelimit(2);

  ldap_querytimeout_tp.tv_sec = (ldap_querytimeout > 0 ? ldap_querytimeout : 5);
  ldap_querytimeout_tp.tv_usec = 0;

  return 1;
}

static void
pr_ldap_unbind(void)
{
  int ret;

  if (! ld)
    return;

  if ((ret = ldap_unbind_s(ld)) != LDAP_SUCCESS)
    log_pri(LOG_NOTICE, "mod_ldap: pr_ldap_unbind(): ldap_unbind() failed: %s", ldap_err2string(ret));

  ld = NULL;
}

static void
pr_ldap_mkdir(char *dir, mode_t mode, uid_t uid, gid_t gid)
{
  int ret;
  mode_t old_umask;
  struct stat st;

  ret = pr_fsio_stat(dir, &st);

  /* If the directory already exists, just return. */
  if (ret == 0)
    return;
  else if (errno != ENOENT) {
    log_pri(PR_LOG_WARNING, "mod_ldap: pr_ldap_mkdir(): unable to create directory %s: pr_fsio_stat() failed: %s", dir, strerror(errno));
    return;
  }

  /* These permissions are absolute; we don't want them to be subject
   * to ProFTPD's Umask.
   */
  old_umask = umask(0);

  PRIVS_ROOT;
  if (pr_fsio_mkdir(dir, mode) != 0) {
    PRIVS_RELINQUISH;
    log_pri(PR_LOG_WARNING, "mod_ldap: pr_ldap_mkdir(): unable to create directory %s: %s", dir, strerror(errno));
    return;
  }
  if (pr_fsio_chmod(dir, mode) == -1) {
    PRIVS_RELINQUISH;
    log_pri(PR_LOG_WARNING, "mod_ldap: pr_ldap_chmod(): unable to chmod directory %s: %s", dir, strerror(errno));
    return;
  }
  if (pr_fsio_chown(dir, uid, gid) == -1) {
    PRIVS_RELINQUISH;
    log_pri(PR_LOG_WARNING, "mod_ldap: pr_ldap_mkdir(): unable to chown directory %s: %s", dir, strerror(errno));
    return;
  }
  PRIVS_RELINQUISH;

  umask(old_umask);
}

static int
pr_ldap_mkpath(pool *p, const char *path, mode_t mode)
{
  char *curpath, *currdir, *buf;
  struct stat st;

  /* If the full path already exists, just return without bothering to
   * stat() its individual components.
   */
  if (pr_fsio_stat(path, &st) != -1)
    return 0;

  buf = pstrdup(p, path);

  /* Move past the leading / in an absolute path. */
  if (buf && *buf == '/')
    ++buf;

  curpath = "";
  while (buf && *buf) {
    currdir = strsep(&buf, "/");
    curpath = pstrcat(p, curpath, "/", currdir, NULL);

    /* If buf is NULL, then we're creating the last part of the
     * directory (presumably, the user's home directory itself), so we
     * want to use the mode specified by the configuration and chown it
     * to the user's UID/GID.
     */
    if ((buf == NULL) || (*buf == '\0'))
      pr_ldap_mkdir(curpath, mode, session.login_uid, session.login_gid);
    else
      pr_ldap_mkdir(curpath, 0755, 0, 0);
  }

  return 0;
}

static void
create_homedir(pool *p, const char *homedir)
{
  int i;
  char *hdod_fulldir, *mode_pos, *suffix;
  mode_t mode;

  /* Make sure we were passed a valid directory to create. */
  if (!homedir || !*homedir)
    return;

  if (ldap_hdod)
    if (pr_ldap_mkpath(p, homedir, ldap_hdod_mode) != 0)
      return;

  /* Loop through the suffixes and create them. If the mode separator (":")
   * is found, we'll use that mode on the suffix directory; if not, default
   * to ldap_hdod_mode.
   */
  if (ldap_hdod_suffix) {
    for (i = 0; ldap_hdod_suffix[i] != NULL; ++i) {
      suffix = pstrdup(p, ldap_hdod_suffix[i]);
      if ((mode_pos = strrchr(suffix, ':')) != NULL &&
          *(mode_pos + 1) != '\0')
      {
        *mode_pos = '\0';
        mode_pos++;
        mode = strtol(mode_pos, (char **)NULL, 8);
      }
      else
        mode = ldap_hdod_mode;

      hdod_fulldir = pstrcat(p, homedir, "/", suffix, NULL);
      pr_ldap_mkdir(hdod_fulldir, mode, session.login_uid, session.login_gid);
    }
  }
}

static char *
pr_ldap_generate_filter(pool *p, char *template, const char *entity)
{
  char *filter, *pos;
  int num_escapes = 0, i = 0, j = 0;

  pos = template;
  while ((pos = strstr(pos + 2, "%v")) != NULL)
    ++num_escapes;

  /* -2 for the %v, +1 for the NULL */
  filter = pcalloc(p, strlen(template) - (num_escapes * 2) + (num_escapes * strlen(entity)) + 1);

  while (template[i] != '\0') {
    if (template[i] == '%' && template[i + 1] == 'v') {
      strcat(filter, entity);
      j += strlen(entity);
      i += 2;
    }
    else
      filter[j++] = template[i++];
  }

  return filter;
}

static struct passwd *
pr_ldap_user_lookup(pool *p,
                    char *filter_template, const char *replace,
                    char *basedn, char *ldap_attrs[],
                    char **user_dn)
{
  char *filter, **values, *dn;
  int i = 0, ret;
  LDAPMessage *result, *e;

  if (! basedn) {
    log_pri(PR_LOG_ERR, "mod_ldap: no LDAP base DN specified for auth/UID lookups, declining request.");
    return NULL;
  }

  /* If the LDAP connection has gone away or hasn't been established
   * yet, attempt to establish it now.
   */
  if (ld == NULL) {
    /* If we _still_ can't connect, give up and return NULL. */
    if (pr_ldap_connect() == -1)
      return NULL;
  }

  filter = pr_ldap_generate_filter(p, filter_template, replace);

  if ((ret = ldap_search_st(ld, basedn, ldap_search_scope, filter, ldap_attrs, 0, &ldap_querytimeout_tp, &result)) != LDAP_SUCCESS) {
    if (ret == LDAP_SERVER_DOWN) {
      log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_user_lookup(): LDAP server went away, trying to reconnect");

      if (pr_ldap_connect() == -1) {
        log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_user_lookup(): LDAP server went away, unable to reconnect");
        ld = NULL;
        return NULL;
      }

      log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_user_lookup(): Reconnect to LDAP server successful, resuming normal operations");
      if ((ret = ldap_search_st(ld, basedn, ldap_search_scope, filter, ldap_attrs, 0, &ldap_querytimeout_tp, &result)) != LDAP_SUCCESS) {
        log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_user_lookup(): ldap_search_st() failed: %s", ldap_err2string(ret));
        return NULL;
      }
    }
    else {
      log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_user_lookup(): ldap_search_st() failed: %s", ldap_err2string(ret));
      return NULL;
    }
  }

  if (ldap_count_entries(ld, result) > 1) {
    log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_user_lookup(): LDAP search returned multiple entries, aborting query");
    ldap_msgfree(result);
    return NULL;
  }

  if ((e = ldap_first_entry(ld, result)) == NULL) {
    ldap_msgfree(result);
    return NULL; /* No LDAP entries for this user */
  }

  if (! pw)
    pw = pcalloc(session.pool, sizeof(struct passwd));
  else
    memset(pw, '\0', sizeof(struct passwd));

  while (ldap_attrs[i] != NULL) {
    if ((values = ldap_get_values(ld, e, ldap_attrs[i])) == NULL) {
      /* Try to fill in default values if there's no value for certain attrs. */

      /* If we can't find the [ug]idNumber attrs, just fill the passwd
         struct in with default values from the config file. */
      if (strcasecmp(ldap_attrs[i], UIDNUMBER_ATTR) == 0) {
        if (ldap_defaultuid == -1) {
          log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_user_lookup(): no " UIDNUMBER_ATTR " attr for DN %s and LDAPDefaultUID was not specified!", (dn = ldap_get_dn(ld, e)));
          free(dn);
          return NULL;
        }

        pw->pw_uid = ldap_defaultuid;
        ++i;
        continue;
      }
      if (strcasecmp(ldap_attrs[i], GIDNUMBER_ATTR) == 0) {
        if (ldap_defaultgid == -1) {
          log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_user_lookup(): no " GIDNUMBER_ATTR " attr for DN %s and LDAPDefaultGID was not specified!", (dn = ldap_get_dn(ld, e)));
          free(dn);
          return NULL;
        }

        pw->pw_gid = ldap_defaultgid;
        ++i;
        continue;
      }

      if (strcasecmp(ldap_attrs[i], HOMEDIRECTORY_ATTR) == 0) {
        if (!ldap_hdod || !ldap_hdod_prefix || !*ldap_hdod_prefix) {
          log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_user_lookup(): no " HOMEDIRECTORY_ATTR " attr for DN %s and LDAPHomedirOnDemandPrefix was not enabled!", (dn = ldap_get_dn(ld, e)));
          free(dn);
          return NULL;
        }

        if (ldap_hdod_prefix_nouname)
          pw->pw_dir = pstrcat(session.pool, ldap_hdod_prefix, NULL);
        else {
          char **canon_username;
          if ((canon_username = ldap_get_values(ld, e, UID_ATTR)) == NULL) {
            log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_user_lookup(): couldn't get " UID_ATTR " attr for canonical username for %s", (dn = ldap_get_dn(ld, e)));
            free(dn);
            return NULL;
          }

          pw->pw_dir = pstrcat(session.pool, ldap_hdod_prefix, "/", canon_username[0], NULL);
          ldap_value_free(canon_username);
        }

        ++i;
        continue;
      }

      /* Don't worry if we don't have a loginShell attr. */
      if (strcasecmp(ldap_attrs[i], LOGINSHELL_ATTR) == 0) {
        /* Prevent a segfault if no loginShell attr && RequireValidShell on. */
        pw->pw_shell = pstrdup(session.pool, "");
        ++i;
        continue;
      }

      /* We only restart the while loop above if we can fill in alternate
       * values for certain attributes. If something odd has happened, we
       * fall through to here and will complain about not being able to find
       * the attr.
       */

      log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_user_lookup(): ldap_get_values() failed on attr %s for DN %s, ignoring request (perhaps this DN's entry does not have the attr?)", ldap_attrs[i], (dn = ldap_get_dn(ld, e)));
      free(dn);
      ldap_msgfree(result);
      return NULL;
    }

    /* Once we get here, we've already handled the "attribute defaults"
     * situation, so we can just fill in the struct as normal; the if
     * branches below for nonexistant attrs will just never be called.
     */

    if (strcasecmp(ldap_attrs[i], UID_ATTR) == 0)
      pw->pw_name = pstrdup(session.pool, values[0]);
    else if (strcasecmp(ldap_attrs[i], USERPASSWORD_ATTR) == 0)
      pw->pw_passwd = pstrdup(session.pool, values[0]);
    else if (strcasecmp(ldap_attrs[i], UIDNUMBER_ATTR) == 0) {
      if (ldap_forcedefaultuid && ldap_defaultuid != -1)
        pw->pw_uid = ldap_defaultuid;
      else
        pw->pw_uid = (uid_t) strtoul(values[0], (char **)NULL, 10);
    }
    else if (strcasecmp(ldap_attrs[i], GIDNUMBER_ATTR) == 0) {
      if (ldap_forcedefaultgid && ldap_defaultgid != -1)
        pw->pw_gid = ldap_defaultgid;
      else
        pw->pw_gid = (gid_t) strtoul(values[0], (char **)NULL, 10);
    }
    else if (strcasecmp(ldap_attrs[i], HOMEDIRECTORY_ATTR) == 0) {
      if (ldap_forcehdod) {
        if (!ldap_hdod || !ldap_hdod_prefix || !*ldap_hdod_prefix) {
          log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_user_lookup(): LDAPForceHomedirOnDemand is enabled, but LDAPHomedirOnDemand is not.");
          return NULL;
        }

        if (ldap_hdod_prefix_nouname)
          pw->pw_dir = pstrcat(session.pool, ldap_hdod_prefix, NULL);
        else {
          char **canon_username;
          if ((canon_username = ldap_get_values(ld, e, UID_ATTR)) == NULL) {
            log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_user_lookup(): couldn't get " UID_ATTR " attr for canonical username for %s", (dn = ldap_get_dn(ld, e)));
            free(dn);
            return NULL;
          }

          pw->pw_dir = pstrcat(session.pool, ldap_hdod_prefix, "/", canon_username[0], NULL);
          ldap_value_free(canon_username);
        }
      }
      else
        pw->pw_dir = pstrdup(session.pool, values[0]);
    }
    else if (strcasecmp(ldap_attrs[i], LOGINSHELL_ATTR) == 0)
      pw->pw_shell = pstrdup(session.pool, values[0]);
    else
      log_pri(PR_LOG_WARNING, "mod_ldap: pr_ldap_user_lookup(): ldap_get_values() loop found unknown attr %s", ldap_attrs[i]);

    ldap_value_free(values);
    ++i;
  }

  /* If we're doing auth binds, save the DN of this entry so we can
   * bind to the LDAP server as it later.
   */
  if (user_dn)
    *user_dn = ldap_get_dn(ld, e);

  ldap_msgfree(result);

  return pw;
}

static struct group *
pr_ldap_group_lookup(pool *p,
                     char *filter_template, const char *replace,
                     char *ldap_attrs[])
{
  char *filter, **values, *dn;
  int i = 0, j = 0, ret;
  LDAPMessage *result, *e;

  if (! ldap_gid_basedn) {
    log_pri(PR_LOG_ERR, "mod_ldap: no LDAP base DN specified for GID lookups");
    return NULL;
  }

  /* If the LDAP connection has gone away or hasn't been established
   * yet, attempt to establish it now.
   */
  if (ld == NULL) {
    /* If we _still_ can't connect, give up and return NULL. */
    if (pr_ldap_connect() == -1)
      return NULL;
  }

  filter = pr_ldap_generate_filter(p, filter_template, replace);

  if ((ret = ldap_search_st(ld, ldap_gid_basedn, ldap_search_scope, filter, ldap_attrs, 0, &ldap_querytimeout_tp, &result)) != LDAP_SUCCESS) {
    if (ret == LDAP_SERVER_DOWN) {
      log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_group_lookup(): LDAP server went away, trying to reconnect");

      if (pr_ldap_connect() != -1) {
        if ((ret = ldap_search_st(ld, ldap_gid_basedn, ldap_search_scope, filter, ldap_attrs, 0, &ldap_querytimeout_tp, &result)) != LDAP_SUCCESS) {
          log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_group_lookup(): ldap_search_st() failed: %s", ldap_err2string(ret));
          return NULL;
        }
      }
      else { /* Still can't connect */
        log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_group_lookup(): LDAP server went away, unable to reconnect");
        return NULL;
      }
    }
    else {
      log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_group_lookup(): ldap_search_st() failed: %s", ldap_err2string(ret));
      return NULL;
    }
  }

  if ((e = ldap_first_entry(ld, result)) == NULL) {
    ldap_msgfree(result);
    return NULL; /* No LDAP entries for this user */
  }

  if (! gr)
    gr = pcalloc(session.pool, sizeof(struct group));
  else
    memset(gr, '\0', sizeof(struct group));

  while (ldap_attrs[i] != NULL) {
    if ((values = ldap_get_values(ld, e, ldap_attrs[i])) == NULL) {
      if (strcasecmp(ldap_attrs[i], MEMBERUID_ATTR) == 0) {
        gr->gr_mem = palloc(session.pool, sizeof(char *));
        gr->gr_mem[0] = pstrdup(session.pool, "");
        gr->gr_mem[1] = NULL;

        ++i;
        continue;
      }

      ldap_msgfree(result);
      log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_group_lookup(): ldap_get_values() failed on attr %s for DN %s, ignoring request (perhaps that DN does not have that attr?)", ldap_attrs[i], (dn = ldap_get_dn(ld, e)));
      free(dn);
      return NULL;
    }

    if (strcasecmp(ldap_attrs[i], CN_ATTR) == 0)
      gr->gr_name = pstrdup(session.pool, values[0]);
    else if (strcasecmp(ldap_attrs[i], GIDNUMBER_ATTR) == 0)
      gr->gr_gid = strtoul(values[0], (char **)NULL, 10);
    else if (strcasecmp(ldap_attrs[i], MEMBERUID_ATTR) == 0) {
      gr->gr_mem = palloc(session.pool, sizeof(char *));

      while (values[j] != NULL)
        ++j;
      memcpy(gr->gr_mem, values, j + 1);
    }
    else
      log_pri(PR_LOG_WARNING, "mod_ldap: pr_ldap_group_lookup(): ldap_get_values() loop found unknown attr %s", ldap_attrs[i]);

    ldap_value_free(values);
    ++i;
  }

  ldap_msgfree(result);
  return gr;
}

static unsigned char
pr_ldap_quota_lookup(pool *p, char *filter_template, const char *replace,
                     char *basedn)
{
  char *filter, **values, *value, *token, *attrs[] = {QUOTA_ATTR, NULL},
       **elts;
  int ret;
  LDAPMessage *result, *e;

  if (! basedn) {
    log_pri(PR_LOG_ERR, "mod_ldap: no LDAP base DN specified for auth/UID lookups, declining request.");
    return FALSE;
  }

  /* If the LDAP connection has gone away or hasn't been established
   * yet, attempt to establish it now.
   */
  if (ld == NULL) {
    /* If we _still_ can't connect, give up and return NULL. */
    if (pr_ldap_connect() == -1)
      return FALSE;
  }

  filter = pr_ldap_generate_filter(p, filter_template, replace);

  if ((ret = ldap_search_st(ld, basedn, ldap_search_scope, filter, attrs, 0, &ldap_querytimeout_tp, &result)) != LDAP_SUCCESS) {
    if (ret == LDAP_SERVER_DOWN) {
      log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_quota_lookup(): LDAP server went away, trying to reconnect");

      if (pr_ldap_connect() == -1) {
        log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_quota_lookup(): LDAP server went away, unable to reconnect");
        ld = NULL;
        return FALSE;
      }

      log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_quota_lookup(): Reconnect to LDAP server successful, resuming normal operations");
      if ((ret = ldap_search_st(ld, basedn, ldap_search_scope, filter, attrs, 0, &ldap_querytimeout_tp, &result)) != LDAP_SUCCESS) {
        log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_quota_lookup(): ldap_search_st() failed: %s", ldap_err2string(ret));
        return FALSE;
      }
    }
    else {
      log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_quota_lookup(): ldap_search_st() failed: %s", ldap_err2string(ret));
      return FALSE;
    }
  }

  if (ldap_count_entries(ld, result) > 1) {
    log_pri(PR_LOG_ERR, "mod_ldap: pr_ldap_quota_lookup(): LDAP search returned multiple entries, aborting query");
    ldap_msgfree(result);
    return FALSE;
  }

  if ((e = ldap_first_entry(ld, result)) == NULL) {
    ldap_msgfree(result);
    return FALSE; /* No LDAP entries for this user. */
  }

  if ((values = ldap_get_values(ld, e, attrs[0])) == NULL) {
    ldap_msgfree(result);
    return FALSE; /* No quota attr for this user. */
  }

  if (cached_quota == NULL)
    cached_quota = make_array(p, 9, sizeof(char *));
  elts = (char **)cached_quota->elts;
  elts[0] = pstrdup(session.pool, replace);
  cached_quota->nelts = 1;

  value = values[0];
  while ((token = strsep(&value, ","))) {
    *((char **)push_array(cached_quota)) = pstrdup(session.pool, token);
  }

  ldap_value_free(values);
  ldap_msgfree(result);

  return TRUE;
}

static struct group *
pr_ldap_getgrnam(pool *p, const char *group_name)
{
  char *group_attrs[] = {CN_ATTR, GIDNUMBER_ATTR, MEMBERUID_ATTR, NULL};

  return pr_ldap_group_lookup(p, ldap_group_name_filter, group_name, group_attrs);
}

static struct group *
pr_ldap_getgrgid(pool *p, gid_t gid)
{
  char gidstr[PR_TUNABLE_BUFFER_SIZE] = {'\0'},
       *group_attrs[] = {CN_ATTR, GIDNUMBER_ATTR, MEMBERUID_ATTR, NULL};

  snprintf(gidstr, sizeof(gidstr), "%d", gid);

  return pr_ldap_group_lookup(p, ldap_group_gid_filter, (const char *)gidstr, group_attrs);
}

static struct passwd *
pr_ldap_getpwnam(pool *p, const char *username)
{
  char *name_attrs[] = {USERPASSWORD_ATTR, UID_ATTR, UIDNUMBER_ATTR,
                        GIDNUMBER_ATTR, HOMEDIRECTORY_ATTR, LOGINSHELL_ATTR,
                        NULL};

  /* pr_ldap_user_lookup() returns NULL if it doesn't find an entry or
   * encounters an error. If everything goes all right, it returns a
   * struct passwd, so we can just return its result directly.
   *
   * We also do some cute stuff here to work around lameness in LDAP servers
   * like Sun Directory Services (SDS) 1.x and 3.x. If you request an attr
   * that you don't have access to, SDS totally ignores any entries with
   * that attribute. Thank you, Sun; how very smart of you. So if we're
   * doing auth binds, we don't request the userPassword attr.
   */
  return pr_ldap_user_lookup(p, ldap_auth_filter, username,
                             pr_ldap_generate_filter(p, ldap_auth_basedn, username),
                             ldap_authbinds ? name_attrs + 1 : name_attrs,
                             ldap_authbinds ? &ldap_authbind_dn : NULL);
}

static struct passwd *
pr_ldap_getpwuid(pool *p, uid_t uid)
{
  char uidstr[PR_TUNABLE_BUFFER_SIZE] = {'\0'},
       *uid_attrs[] = {UID_ATTR, UIDNUMBER_ATTR, GIDNUMBER_ATTR,
                       HOMEDIRECTORY_ATTR, LOGINSHELL_ATTR, NULL};

  snprintf(uidstr, sizeof(uidstr), "%d", uid);

  /* pr_ldap_user_lookup() returns NULL if it doesn't find an entry or
   * encounters an error. If everything goes all right, it returns a
   * struct passwd, so we can just return its result directly.
   */
  return pr_ldap_user_lookup(p, ldap_uid_filter, (const char *)uidstr,
                             ldap_uid_basedn, uid_attrs,
                             ldap_authbinds ? &ldap_authbind_dn : NULL);
}

static int
_compare_uid(pr_idmap_t *m1, pr_idmap_t *m2)
{
  if (m1->id.uid < m2->id.uid)
    return -1;

  if (m1->id.uid > m2->id.uid)
    return 1;

  return 0;
}

static int
_compare_gid(pr_idmap_t *m1, pr_idmap_t *m2)
{
  if (m1->id.gid < m2->id.gid)
    return -1;

  if (m1->id.gid > m2->id.gid)
    return 1;

  return 0;
}

static int
_compare_id(xaset_t **table, pr_idauth_t id, pr_idauth_t idcomp)
{
  if (table == uid_table)
    return id.uid == idcomp.uid;
  else
    return id.gid == idcomp.gid;
}

static pr_idmap_t *
_auth_lookup_id(xaset_t **id_table, pr_idauth_t id)
{
  int hash = ((id_table == uid_table) ? id.uid : id.gid) % HASH_TABLE_SIZE;
  pr_idmap_t *m;

  if (! id_table[hash])
    id_table[hash] = xaset_create(permanent_pool, (id_table == uid_table) ?
                                  (XASET_COMPARE) _compare_uid :
                                  (XASET_COMPARE) _compare_gid);

  for (m = (pr_idmap_t *) id_table[hash]->xas_list; m; m = m->next) {
    if (_compare_id(id_table, m->id, id))
      break;
  }

  if (!m || !_compare_id(id_table, m->id, id)) {
    /* Isn't in the table */
    m = (pr_idmap_t *) pcalloc(id_table[hash]->mempool, sizeof(pr_idmap_t));

    if (id_table == uid_table)
      m->id.uid = id.uid;
    else
      m->id.gid = id.gid;

    xaset_insert_sort(id_table[hash], (xasetmember_t *) m, FALSE);
  }

  return m;
}

MODRET
handle_ldap_quota_lookup(cmd_rec *cmd)
{
  char **elts;
 
  if (cached_quota != NULL)
    elts = (char **)cached_quota->elts;

  if (cached_quota == NULL ||
      strcasecmp(elts[0], cmd->argv[0]) != 0)
  {
    if (pr_ldap_quota_lookup(cmd->tmp_pool, ldap_quota_filter,
                             cmd->argv[0], ldap_quota_basedn) == FALSE)
    {
      return DECLINED(cmd);
    }
  }

  return mod_create_data(cmd, cached_quota);
}

MODRET
handle_ldap_setpwent(cmd_rec *cmd)
{
  if (ldap_doauth || ldap_douid || ldap_dogid) {
    if (ld == NULL)
      (void) pr_ldap_connect();
    return HANDLED(cmd);
  }

  return DECLINED(cmd);
}

MODRET
handle_ldap_endpwent(cmd_rec *cmd)
{
  if (ldap_doauth || ldap_douid || ldap_dogid) {
    pr_ldap_unbind();
    pw = NULL;
    gr = NULL;
    return HANDLED(cmd);
  }

  return DECLINED(cmd);
}

MODRET
handle_ldap_getpwuid(cmd_rec *cmd)
{
  if (! ldap_douid)
    return DECLINED(cmd);

  if ((pw = pr_ldap_getpwuid(cmd->tmp_pool, (uid_t)cmd->argv[0])))
    return mod_create_data(cmd, pw);

  return DECLINED(cmd);
}

MODRET
handle_ldap_getpwnam(cmd_rec *cmd)
{
  if (! ldap_doauth)
    return DECLINED(cmd);

  if (pw && pw->pw_name && strcasecmp(pw->pw_name, cmd->argv[0]) == 0)
    return mod_create_data(cmd, pw);

  if ((pw = pr_ldap_getpwnam(cmd->tmp_pool, cmd->argv[0])))
    return mod_create_data(cmd, pw);

  return DECLINED(cmd);
}

MODRET
handle_ldap_getgrnam(cmd_rec *cmd)
{
  if (! ldap_dogid)
    return DECLINED(cmd);

  if (gr && strcasecmp(gr->gr_name, cmd->argv[0]) == 0)
    return mod_create_data(cmd, gr);

  if ((gr = pr_ldap_getgrnam(cmd->tmp_pool, cmd->argv[0])))
    return mod_create_data(cmd, gr);

  return DECLINED(cmd);
}

MODRET
handle_ldap_getgrgid(cmd_rec *cmd)
{
  if (! ldap_dogid)
    return DECLINED(cmd);

  if (gr && gr->gr_gid == (gid_t)cmd->argv[0])
    return mod_create_data(cmd, gr);

  if ((gr = pr_ldap_getgrgid(cmd->tmp_pool, (gid_t)cmd->argv[0])))
    return mod_create_data(cmd, gr);

  return DECLINED(cmd);
}

MODRET
handle_ldap_getgroups(cmd_rec *cmd)
{
  char *filter, **gidNumber, **cn,
       *w[] = {GIDNUMBER_ATTR, CN_ATTR, NULL};
  int ret;
  struct passwd *pw;
  struct group *gr;
  LDAPMessage *result = NULL, *e;
  array_header *gids   = (array_header *)cmd->argv[1],
               *groups = (array_header *)cmd->argv[2];

  if (! ldap_dogid)
    return DECLINED(cmd);

  if (!gids || !groups)
    return DECLINED(cmd);

  if ((pw = pr_ldap_getpwnam(cmd->tmp_pool, cmd->argv[0]))) {
    if ((gr = pr_ldap_getgrgid(cmd->tmp_pool, pw->pw_gid))) {
      *((gid_t *) push_array(gids))   = pw->pw_gid;
      *((char **) push_array(groups)) = pstrdup(session.pool, gr->gr_name);
    }
  }

  if (! ldap_gid_basedn) {
    log_pri(PR_LOG_ERR, "mod_ldap: no LDAP base DN specified for GID lookups");
    goto return_groups;
  }

  /* If the LDAP connection has gone away or hasn't been established
   * yet, attempt to establish it now.
   */
  if (ld == NULL) {
    /* If we _still_ can't connect, give up and decline. */
    if (pr_ldap_connect() == -1)
      goto return_groups;
  }

  filter = pr_ldap_generate_filter(cmd->tmp_pool, ldap_group_member_filter, cmd->argv[0]);

  pr_ldap_set_sizelimit(-1);
  if ((ret = ldap_search_st(ld, ldap_gid_basedn, ldap_search_scope, filter, w, 0, &ldap_querytimeout_tp, &result)) != LDAP_SUCCESS) {
    if (ret == LDAP_SERVER_DOWN) {
      log_pri(PR_LOG_ERR, "mod_ldap: ldap_handle_getgroups(): LDAP server went away, trying to reconnect");

      if (pr_ldap_connect() != -1) {
        if ((ret = ldap_search_st(ld, ldap_gid_basedn, ldap_search_scope, filter, w, 0, &ldap_querytimeout_tp, &result)) != LDAP_SUCCESS) {
          log_pri(PR_LOG_ERR, "mod_ldap: ldap_handle_getgroups(): ldap_search_st() failed: %s", ldap_err2string(ret));
          goto return_groups;
        }
      }
      else {
        log_pri(PR_LOG_ERR, "mod_ldap: ldap_handle_getgroups(): LDAP server went away, unable to reconnect");
        goto return_groups;
      }
    }
    else {
      log_pri(PR_LOG_ERR, "mod_ldap: ldap_handle_getgroups(): ldap_search_st() failed: %s", ldap_err2string(ret));
      goto return_groups;
    }
  }
  pr_ldap_set_sizelimit(2);

  if (ldap_count_entries(ld, result) == 0)
    goto return_groups;

  for (e = ldap_first_entry(ld, result); e; e = ldap_next_entry(ld, e)) {
    if (! (gidNumber = ldap_get_values(ld, e, w[0]))) {
      log_pri(PR_LOG_ERR, "mod_ldap: ldap_handle_getgroups(): ldap_get_values() on " GIDNUMBER_ATTR " attr failed, skipping current group: %s", ldap_err2string(ret));
      continue;
    }
    if (! (cn = ldap_get_values(ld, e, w[1]))) {
      log_pri(PR_LOG_ERR, "mod_ldap: ldap_handle_getgroups(): ldap_get_values() on " CN_ATTR " attr failed, skipping current group: %s", ldap_err2string(ret));
      continue;
    }

    if (strtoul(gidNumber[0], (char **)NULL, 10) != pw->pw_gid) {
      *((gid_t *) push_array(gids))   = strtoul(gidNumber[0], (char **)NULL, 10);
      *((char **) push_array(groups)) = pstrdup(session.pool, cn[0]);
    }

    ldap_value_free(gidNumber);
    ldap_value_free(cn);
  }

return_groups:
  if (result)
    ldap_msgfree(result);

  if (gids->nelts > 0)
    return mod_create_data(cmd, (void *)gids->nelts);
  return DECLINED(cmd);
}


/****************************
 * High-level auth handlers *
 ****************************/

/* cmd->argv[0] : user name
 * cmd->argv[1] : cleartext password
 */

MODRET
handle_ldap_is_auth(cmd_rec *cmd)
{
  const char *username = cmd->argv[0];
  char *pass_attrs[] = {USERPASSWORD_ATTR, HOMEDIRECTORY_ATTR, NULL};

  if (! ldap_doauth)
    return DECLINED(cmd);

  /* If anything here fails hard (IOW, we've found an LDAP entry for the
   * user, but they appear to have entered the wrong password), boot them.
   * Normally, I'd DECLINE here so other modules could have a shot, but if
   * we've found their LDAP entry, chances are that nothing else is going to
   * be able to auth them. If anyone has a reason that this shouldn't be
   * this way, then by all means, let me know.
   */

  /* If we don't have a cached entry, or if the cached entry isn't for this
   * user, fetch the entry.
   */
  if (!pw || (pw && pw->pw_name && strcasecmp(pw->pw_name, username) != 0))
    if ((pw = pr_ldap_user_lookup(cmd->tmp_pool, ldap_auth_filter, username,
                                  pr_ldap_generate_filter(cmd->tmp_pool, ldap_auth_basedn, username),
                                  pass_attrs, ldap_authbinds ? &ldap_authbind_dn : NULL)) == NULL)
      return DECLINED(cmd); /* Can't find the user in the LDAP directory. */

  if (!ldap_authbinds && !pw->pw_passwd)
    return ERROR_INT(cmd, PR_AUTH_NOPWD);

  /* FIXME: If we pass a "" or NULL "crypted password" argument to
   * auth_check, the mod_unixpw auth handler gets called before the mod_ldap
   * auth handler, so mod_unixpw will allow in any LDAP auth-bind user with
   * an incorrect password. Can we kludge around this by setting the
   * directive to not allow empty passwords? (its name escapes me right now)
   * For now, we'll kludge around this by passing "*", which mod_unixpw will
   * happily deny auth to.
   */
  if (auth_check(cmd->tmp_pool, ldap_authbinds ? "*" : pw->pw_passwd,
                 username, cmd->argv[1]))
  {
    return ERROR_INT(cmd, PR_AUTH_BADPWD);
  }

  create_homedir(cmd->tmp_pool, pw->pw_dir);
  return HANDLED(cmd);
}

/* cmd->argv[0] = hashed password,
 * cmd->argv[1] = user,
 * cmd->argv[2] = cleartext
 */

MODRET
handle_ldap_check(cmd_rec *cmd)
{
  char *pass, *cryptpass, *hash_method;
  int encname_len;
  LDAP *ld_auth;

#ifdef HAVE_OPENSSL
  EVP_MD_CTX EVP_Context;
  const EVP_MD *md;
  int md_len;
  unsigned char md_value[EVP_MAX_MD_SIZE];
  EVP_ENCODE_CTX EVP_Encode;
  char buff[EVP_MAX_KEY_LENGTH];
#endif /* HAVE_OPENSSL */

  if (! ldap_doauth)
    return DECLINED(cmd);

  cryptpass = cmd->argv[0];
  pass      = cmd->argv[2];


  if (ldap_authbinds) {
    /* Don't try to do auth binds with a NULL DN or password. */
    if ( (pass == NULL) || (strlen(pass) == 0) ||
         (ldap_authbind_dn == NULL) || (strlen(ldap_authbind_dn) == 0) )
      return DECLINED(cmd);

    if ((ld_auth = ldap_init(ldap_server, LDAP_PORT)) == NULL) {
      log_pri(PR_LOG_ERR, "mod_ldap: ldap_is_auth(): ldap_init() to %s failed", ldap_server);
      return DECLINED(cmd);
    }

    if (ldap_simple_bind_s(ld_auth, ldap_authbind_dn, cmd->argv[2]) != LDAP_SUCCESS) {
      ldap_unbind(ld_auth);
      return ERROR(cmd);
    }

    ldap_unbind(ld_auth);

    return HANDLED(cmd);
  }

  /* Get the length of "scheme" in the leading {scheme} so we can skip it
   * in the password comparison.
   */
  encname_len = strcspn(cryptpass + 1, "}");
  hash_method = pstrndup(cmd->tmp_pool, cryptpass + 1, encname_len);

  /* Check to see how the password is encrypted, and check accordingly. */

  if (encname_len == strlen(cryptpass + 1)) { /* No leading {scheme} */
    if (ldap_defaultauthscheme && (strcasecmp(ldap_defaultauthscheme, "clear") == 0)) {
      if (strcmp(pass, cryptpass) != 0)
        return ERROR(cmd);
    }
    else { /* else, assume crypt */
      if (strcmp(crypt(pass, cryptpass), cryptpass) != 0)
        return ERROR(cmd);
    }
  }
  else if (strncasecmp(hash_method, "crypt", strlen(hash_method)) == 0) { /* {crypt} */
    if (strcmp(crypt(pass, cryptpass + encname_len + 2), cryptpass + encname_len + 2) != 0)
      return ERROR(cmd);
  }
  else if (strncasecmp(hash_method, "clear", strlen(hash_method)) == 0) { /* {clear} */
    if (strcmp(pass, cryptpass + encname_len + 2) != 0)
      return ERROR(cmd);
  }
#ifdef HAVE_OPENSSL
  else { /* Try the cipher mode found */
    log_debug(DEBUG5, "mod_ldap: %s-encrypted password found, trying to auth.", hash_method);

    SSLeay_add_all_digests();

    /* This is a kludge. This is only a kludge. OpenLDAP likes {sha}
     * (at least, the OpenLDAP ldappasswd generates {sha}), but OpenSSL
     * likes {sha1} and does not understand {sha}. We translate
     * RMD160 -> RIPEMD160 here, too.
     */
    if (strncasecmp(hash_method, "SHA", 4) == 0)
        md = EVP_get_digestbyname("SHA1");
    else if (strncasecmp(hash_method, "RMD160", 7) == 0)
        md = EVP_get_digestbyname("RIPEMD160");
    else
        md = EVP_get_digestbyname(hash_method);

    if (! md) {
      log_debug(DEBUG5, "mod_ldap: %s not supported by OpenSSL, declining auth request", hash_method);
      return DECLINED(cmd); /* Some other module may support it. */
    }

    /* Make a digest of the user-supplied password. */
    EVP_DigestInit(&EVP_Context, md);
    EVP_DigestUpdate(&EVP_Context, pass, strlen(pass));
    EVP_DigestFinal(&EVP_Context, md_value, &md_len);

    /* Base64 Encoding */
    EVP_EncodeInit(&EVP_Encode);
    EVP_EncodeBlock(buff, md_value, md_len);

    if (strcmp(buff, cryptpass + encname_len + 2) != 0)
      return ERROR(cmd);
  }
#else /* HAVE_OPENSSL */
  else /* Can't find a supported {scheme} */
    return DECLINED(cmd);
#endif /* HAVE_OPENSSL */

  return HANDLED(cmd);
}

MODRET
handle_ldap_uid_name(cmd_rec *cmd)
{
  pr_idmap_t *m;
  pr_idauth_t id;

  if (! ldap_douid)
    return DECLINED(cmd);

  id.uid = (uid_t)cmd->argv[0];
  m = _auth_lookup_id(uid_table, id);

  if (! m->name) {
    if (ldap_negcache) /* If we're doing negative caching as per config... */
      if (m->negative) /* It wasn't in the LDAP db before, don't look again. */
        return DECLINED(cmd);

    /* Wasn't cached and we've haven't seen this one, so perform a lookup.
     * If we don't have a cached entry, or if the cached entry isn't for
     * this user, fetch the entry.
     */
    if (!pw || (pw && pw->pw_uid != id.uid)) {
      if (! (pw = pr_ldap_getpwuid(cmd->tmp_pool, id.uid))) {
        if (ldap_negcache)
          m->negative = 1;
        return DECLINED(cmd); /* Can't find the user in the LDAP directory. */
      }
    }

    m->name = pstrdup(permanent_pool, pw->pw_name);
  }

  return mod_create_data(cmd, m->name);
}

MODRET
handle_ldap_gid_name(cmd_rec *cmd)
{
  pr_idmap_t *m;
  pr_idauth_t id;

  if (! ldap_dogid)
    return DECLINED(cmd);

  id.gid = (gid_t)cmd->argv[0];
  m = _auth_lookup_id(gid_table, id);

  if (! m->name) {
    if (ldap_negcache) /* If we're doing negative caching as per config... */
      if (m->negative) /* It wasn't in the LDAP db before, don't look again. */
        return DECLINED(cmd);

    /* Wasn't cached and we've haven't seen this one, so perform a lookup.
     * If we don't have a cached entry, or if the cached entry isn't for
     * this group, fetch the entry.
     */
    if (!gr || (gr && gr->gr_gid != id.gid)) {
      if (! (gr = pr_ldap_getgrgid(cmd->tmp_pool, id.gid))) {
        if (ldap_negcache)
          m->negative = 1;
        return DECLINED(cmd); /* Can't find the user in the LDAP directory. */
      }
    }

    m->name = pstrdup(permanent_pool, gr->gr_name);
  }

  return mod_create_data(cmd, m->name);
}

MODRET
handle_ldap_name_uid(cmd_rec *cmd)
{
  if (! ldap_doauth)
    return DECLINED(cmd);

  if (pw && pw->pw_name && strcasecmp(pw->pw_name, cmd->argv[0]) == 0)
    return mod_create_data(cmd, (void *)pw->pw_uid);

  if ((pw = pr_ldap_getpwnam(cmd->tmp_pool, cmd->argv[0])))
    return mod_create_data(cmd, (void *)pw->pw_uid);

  return DECLINED(cmd);
}

MODRET
handle_ldap_name_gid(cmd_rec *cmd)
{
  if (! ldap_dogid)
    return DECLINED(cmd);

  if (gr && strcasecmp(gr->gr_name, cmd->argv[0]) == 0)
    return mod_create_data(cmd, (void *)gr->gr_gid);

  if ((gr = pr_ldap_getgrnam(cmd->tmp_pool, cmd->argv[0])))
    return mod_create_data(cmd, (void *)gr->gr_gid);

  return DECLINED(cmd);
}


/*****************************************
 * Config-file handlers/parsing routines *
 *****************************************/

MODRET
set_ldap_server(cmd_rec *cmd)
{
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str("LDAPServer", 1, cmd->argv[1]);
  return HANDLED(cmd);
}

MODRET
set_ldap_dninfo(cmd_rec *cmd)
{
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str("LDAPDNInfo", 2, cmd->argv[1], cmd->argv[2]);
  return HANDLED(cmd);
}

MODRET
set_ldap_authbinds(cmd_rec *cmd)
{
  int b;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((b = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "LDAPAuthBinds: expected a boolean value for first argument.");

  add_config_param("LDAPAuthBinds", 1, (void *)b);
  return HANDLED(cmd);
}

MODRET
set_ldap_querytimeout(cmd_rec *cmd)
{
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param("LDAPQueryTimeout", 1, atoi(cmd->argv[1]));
  return HANDLED(cmd);
}

MODRET
set_ldap_searchscope(cmd_rec *cmd)
{
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str("LDAPSearchScope", 1, cmd->argv[1]);
  return HANDLED(cmd);
}

MODRET
set_ldap_doauth(cmd_rec *cmd)
{
  int b;
  config_rec *c;

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((b = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "LDAPDoAuth: expected a boolean value for first argument.");

  if (b == 1) { CHECK_ARGS(cmd, 2); }
  else        { CHECK_ARGS(cmd, 1); }

  c = add_config_param("LDAPDoAuth", 3, (void *)b);
  c->argv[1] = pstrdup(c->pool, cmd->argv[2]);
  c->argv[2] = pstrdup(c->pool, cmd->argv[3]);

  return HANDLED(cmd);
}

MODRET
set_ldap_douid(cmd_rec *cmd)
{
  int b;
  config_rec *c;

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((b = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "LDAPDoUIDLookups: expected a boolean value for first argument.");

  if (b == 1) { CHECK_ARGS(cmd, 2); }
  else        { CHECK_ARGS(cmd, 1); }

  c = add_config_param("LDAPDoUIDLookups", 3, (void *)b);
  c->argv[1] = pstrdup(c->pool, cmd->argv[2]);
  c->argv[2] = pstrdup(c->pool, cmd->argv[3]);

  return HANDLED(cmd);
}

MODRET
set_ldap_dogid(cmd_rec *cmd)
{
  int b;
  config_rec *c;

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((b = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "LDAPDoGIDLookups: expected a boolean value for first argument.");

  if (b == 1) { CHECK_ARGS(cmd, 2); }
  else        { CHECK_ARGS(cmd, 1); }

  c = add_config_param("LDAPDoGIDLookups", cmd->argc - 1, (void *)b);
  if (cmd->argc > 2)
    c->argv[1] = pstrdup(c->pool, cmd->argv[2]);
  if (cmd->argc > 3)
    c->argv[2] = pstrdup(c->pool, cmd->argv[3]);
  if (cmd->argc > 4)
    c->argv[3] = pstrdup(c->pool, cmd->argv[4]);
  if (cmd->argc > 5)
    c->argv[4] = pstrdup(c->pool, cmd->argv[5]);

  return HANDLED(cmd);
}

MODRET
set_ldap_doquota(cmd_rec *cmd)
{
  int b;
  config_rec *c;

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((b = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "LDAPDoQuotaLookups: expected a boolean value for first argument.");

  if (b == 1) { CHECK_ARGS(cmd, 2); }
  else        { CHECK_ARGS(cmd, 1); }

  c = add_config_param("LDAPDoQuotaLookups", cmd->argc - 1, (void *)b);
  if (cmd->argc > 2)
    c->argv[1] = pstrdup(c->pool, cmd->argv[2]);
  if (cmd->argc > 3)
    c->argv[2] = pstrdup(c->pool, cmd->argv[3]);

  return HANDLED(cmd);
}

MODRET
set_ldap_defaultuid(cmd_rec *cmd)
{
  int i = 0;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  while (cmd->argv[1][i]) {
    if (! isdigit((int) cmd->argv[1][i]))
      CONF_ERROR(cmd, "LDAPDefaultUID: UID argument must be numeric!");
    ++i;
  }

  add_config_param("LDAPDefaultUID", 1, strtoul(cmd->argv[1], (char **)NULL, 10));
  return HANDLED(cmd);
}

MODRET
set_ldap_defaultgid(cmd_rec *cmd)
{
  int i = 0;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  while (cmd->argv[1][i]) {
    if (! isdigit((int) cmd->argv[1][i]))
      CONF_ERROR(cmd, "LDAPDefaultGID: GID argument must be numeric!");
    ++i;
  }

  add_config_param("LDAPDefaultGID", 1, strtoul(cmd->argv[1], (char **)NULL, 10));
  return HANDLED(cmd);
}

MODRET set_ldap_forcedefaultuid(cmd_rec *cmd)
{
  int b;

  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((b = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "LDAPForceDefaultUID: expected boolean argument for first argument.");

  add_config_param("LDAPForceDefaultUID", 1, (void *)b);
  return HANDLED(cmd);
}

MODRET set_ldap_forcedefaultgid(cmd_rec *cmd)
{
  int b;

  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((b = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "LDAPForceDefaultGID: expected boolean argument for first argument.");

  add_config_param("LDAPForceDefaultGID", 1, (void *)b);
  return HANDLED(cmd);
}

MODRET
set_ldap_negcache(cmd_rec *cmd)
{
  int b;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((b = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "LDAPNegativeCache: expected a boolean value for first argument.");

  add_config_param("LDAPNegativeCache", 1, (void *)b);
  return HANDLED(cmd);
}

MODRET
set_ldap_hdod(cmd_rec *cmd)
{
  int b;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((b = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "LDAPHomedirOnDemand: expected a boolean value for first argument.");

  c = add_config_param("LDAPHomedirOnDemand", 2, (void *)b);
  c->argv[1] = pstrdup(c->pool, cmd->argv[2]);

  return HANDLED(cmd);

}

MODRET set_ldap_forcehdod(cmd_rec *cmd)
{
  int b;

  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((b = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "LDAPForceHomeDirOnDemand: expected boolean argument for first argument.");

  add_config_param("LDAPForceHomeDirOnDemand", 1, (void *)b);
  return HANDLED(cmd);
}

MODRET
set_ldap_hdodprefix(cmd_rec *cmd)
{
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str("LDAPHomedirOnDemandPrefix", 1, cmd->argv[1]);
  return HANDLED(cmd);
}

MODRET
set_ldap_hdodprefixnouname(cmd_rec *cmd)
{
  int b;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((b = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "LDAPHomedirOnDemandPrefixNoUsername: expected a boolean value for first argument.");

  add_config_param("LDAPHomedirOnDemandPrefixNoUsername", 1, (void *)b);
  return HANDLED(cmd);
}

MODRET
set_ldap_hdodsuffix(cmd_rec *cmd)
{
  int i;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param_str("LDAPHomedirOnDemandSuffix", cmd->argc - 1, cmd->argv[1]);
  for (i = 1; i < cmd->argc - 1; ++i)
    c->argv[i] = pstrdup(c->pool, cmd->argv[1 + i]);

  return HANDLED(cmd);
}

MODRET
set_ldap_defaultauthscheme(cmd_rec *cmd)
{
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str("LDAPDefaultAuthScheme", 1, cmd->argv[1]);
  return HANDLED(cmd);
}

MODRET
set_ldap_usetls(cmd_rec *cmd)
{
#ifndef USE_LDAPV3_TLS
  CONF_ERROR(cmd, "LDAPUseTLS: You must edit mod_ldap.c and recompile with USE_LDAPV3_TLS enabled in order to use TLS.");
#else /* USE_LDAPV3_TLS */
  int b;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((b = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "LDAPUseTLS: expected a boolean value for first argument.");

  add_config_param("LDAPUseTLS", 1, (void *)b);
  return HANDLED(cmd);
#endif /* USE_LDAPV3_TLS */
}

static int
ldap_getconf(void)
{
  int i = 0;
  char *scope;
  config_rec *c;

  /* If ldap_server is NULL, ldap_init() will connect to your LDAP SDK's
   * default.
   */
  ldap_server = (char *)get_param_ptr(main_server->conf, "LDAPServer", FALSE);

  if ((c = find_config(main_server->conf, CONF_PARAM, "LDAPDNInfo", FALSE)) != NULL) {
    ldap_dn = pstrdup(session.pool, c->argv[0]);
    ldap_dnpass = pstrdup(session.pool, c->argv[1]);
  }

  if (get_param_int(main_server->conf, "LDAPAuthBinds", FALSE) == 0)
    ldap_authbinds = 0;

  ldap_querytimeout = get_param_int(main_server->conf, "LDAPQueryTimeout", FALSE);

  scope = get_param_ptr(main_server->conf, "LDAPSearchScope", FALSE);
  if (scope && *scope)
    if (strcasecmp(scope, "onelevel") == 0)
      ldap_search_scope = LDAP_SCOPE_ONELEVEL;

  if ((c = find_config(main_server->conf, CONF_PARAM, "LDAPDoAuth", FALSE)) != NULL) {
    if ( (int)c->argv[0] > 0) {
      ldap_doauth = 1;
      ldap_auth_basedn = pstrdup(session.pool, c->argv[1]);

      if (c->argv[2])
        ldap_auth_filter = pstrdup(session.pool, c->argv[2]);
      else
        ldap_auth_filter = "(&(" UID_ATTR "=%v)(objectclass=posixAccount))";
    }
  }

  if ((c = find_config(main_server->conf, CONF_PARAM, "LDAPDoUIDLookups", FALSE)) != NULL) {
    if ( (int)c->argv[0] > 0) {
      ldap_douid = 1;
      ldap_uid_basedn = pstrdup(session.pool, c->argv[1]);

      if (c->argv[2])
        ldap_uid_filter = pstrdup(session.pool, c->argv[2]);
      else
        ldap_uid_filter = "(&(" UIDNUMBER_ATTR "=%v)(objectclass=posixAccount))";
    }
  }

  if ((c = find_config(main_server->conf, CONF_PARAM, "LDAPDoGIDLookups", FALSE)) != NULL) {
    if ( (int)c->argv[0] > 0) {
      ldap_dogid = 1;
      ldap_gid_basedn = pstrdup(session.pool, c->argv[1]);

      if (c->argc > 2)
        ldap_group_name_filter = pstrdup(session.pool, c->argv[2]);
      else
        ldap_group_name_filter = "(&(" CN_ATTR " =%v)(objectclass=posixGroup))";

      if (c->argc > 3)
        ldap_group_gid_filter = pstrdup(session.pool, c->argv[3]);
      else
        ldap_group_gid_filter = "(&(" GIDNUMBER_ATTR "=%v)(objectclass=posixGroup))";

      if (c->argc > 4)
        ldap_group_member_filter = pstrdup(session.pool, c->argv[3]);
      else
        ldap_group_member_filter = "(&(" MEMBERUID_ATTR "=%v)(objectclass=posixGroup))";
    }
  }

  if ((c = find_config(main_server->conf, CONF_PARAM, "LDAPDoQuotaLookups", FALSE)) != NULL) {
    if ( (int)c->argv[0] > 0) {
      ldap_doquota = 1;
      ldap_quota_basedn = pstrdup(session.pool, c->argv[1]);

      if (c->argc > 2)
        ldap_quota_filter = pstrdup(session.pool, c->argv[2]);
      else
        ldap_quota_filter = "(&(" UIDNUMBER_ATTR "=%v)(objectclass=posixAccount))";
    }
  }

  ldap_defaultuid = get_param_int(main_server->conf, "LDAPDefaultUID", FALSE);
  ldap_defaultgid = get_param_int(main_server->conf, "LDAPDefaultGID", FALSE);

  if ((c = find_config(main_server->conf, CONF_PARAM, "LDAPForceDefaultUID", FALSE)) != NULL)
    if ( (int)c->argv[0] > 0)
      ldap_forcedefaultuid = 1;

  if ((c = find_config(main_server->conf, CONF_PARAM, "LDAPForceDefaultGID", FALSE)) != NULL)
    if ( (int)c->argv[0] > 0)
      ldap_forcedefaultgid = 1;

  if ((c = find_config(main_server->conf, CONF_PARAM, "LDAPForceHomeDirOnDemand", FALSE)) != NULL)
    if ( (int)c->argv[0] > 0)
      ldap_forcehdod = 1;

  if (get_param_int(main_server->conf, "LDAPNegativeCache", FALSE) > 0)
    ldap_negcache = 1;

  if ((c = find_config(main_server->conf, CONF_PARAM, "LDAPHomedirOnDemand", FALSE)) != NULL) {
    if ( (int)c->argv[0] > 0) {
      ldap_hdod = 1;

      /* Use strtol() instead of atoi() here becuase we need to pass an
       * octal mode to mkdir().
       */
      if (c->argv[1])
        ldap_hdod_mode = strtol(c->argv[1], (char **)NULL, 8);
    }
  }

  ldap_hdod_prefix = (char *)get_param_ptr(main_server->conf, "LDAPHomedirOnDemandPrefix", FALSE);
  if (get_param_int(main_server->conf, "LDAPHomedirOnDemandPrefixNoUsername", FALSE) == 1)
    ldap_hdod_prefix_nouname = 1;

  if ((c = find_config(main_server->conf, CONF_PARAM, "LDAPHomedirOnDemandSuffix", FALSE)) != NULL) {
    ldap_hdod_suffix = (char **) palloc(session.pool, ( (c->argc + 1) * sizeof(char *)) );
    for (i = 0; i < c->argc; ++i)
      ldap_hdod_suffix[i] = pstrdup(session.pool, c->argv[i]);
    ldap_hdod_suffix[i] = NULL;
  }

  /* If ldap_defaultauthscheme is NULL, ldap_check() will assume crypt. */
  ldap_defaultauthscheme = (char *)get_param_ptr(main_server->conf, "LDAPDefaultAuthScheme", FALSE);

#ifdef USE_LDAPV3_TLS
  ldap_use_tls = (int)get_param_int(main_server->conf, "LDAPUseTLS", FALSE);
#endif

  return 0;
}

static conftable ldap_config[] = {
  { "LDAPServer",                          set_ldap_server,            NULL },
  { "LDAPDNInfo",                          set_ldap_dninfo,            NULL },
  { "LDAPAuthBinds",                       set_ldap_authbinds,         NULL },
  { "LDAPQueryTimeout",                    set_ldap_querytimeout,      NULL },
  { "LDAPSearchScope",                     set_ldap_searchscope,       NULL },
  { "LDAPNegativeCache",                   set_ldap_negcache,          NULL },
  { "LDAPDoAuth",                          set_ldap_doauth,            NULL },
  { "LDAPDoUIDLookups",                    set_ldap_douid,             NULL },
  { "LDAPDoGIDLookups",                    set_ldap_dogid,             NULL },
  { "LDAPDoQuotaLookups",                  set_ldap_doquota,           NULL },
  { "LDAPDefaultUID",                      set_ldap_defaultuid,        NULL },
  { "LDAPDefaultGID",                      set_ldap_defaultgid,        NULL },
  { "LDAPForceDefaultUID",                 set_ldap_forcedefaultuid,   NULL },
  { "LDAPForceDefaultGID",                 set_ldap_forcedefaultgid,   NULL },
  { "LDAPHomedirOnDemand",                 set_ldap_hdod,              NULL },
  { "LDAPHomedirOnDemandPrefix",           set_ldap_hdodprefix,        NULL },
  { "LDAPHomedirOnDemandPrefixNoUsername", set_ldap_hdodprefixnouname, NULL },
  { "LDAPHomedirOnDemandSuffix",           set_ldap_hdodsuffix,        NULL },
  { "LDAPForceHomedirOnDemand",            set_ldap_forcehdod,         NULL },
  { "LDAPDefaultAuthScheme",               set_ldap_defaultauthscheme, NULL },
  { "LDAPUseTLS",                          set_ldap_usetls,            NULL },
  { NULL,                                  NULL,                       NULL }
};

static cmdtable ldap_cmdtab[] = {
  {CMD, "ldap_quota_lookup", G_NONE, handle_ldap_quota_lookup, FALSE, FALSE},
  {0, NULL}
};

static authtable ldap_auth[] = {
  { 0, "setpwent",  handle_ldap_setpwent  },
  { 0, "endpwent",  handle_ldap_endpwent  },
  { 0, "setgrent",  handle_ldap_setpwent  },
  { 0, "endgrent",  handle_ldap_endpwent  },
  { 0, "getpwnam",  handle_ldap_getpwnam  },
  { 0, "getpwuid",  handle_ldap_getpwuid  },
  { 0, "getgrnam",  handle_ldap_getgrnam  },
  { 0, "getgrgid",  handle_ldap_getgrgid  },
  { 0, "auth",      handle_ldap_is_auth   },
  { 0, "check",     handle_ldap_check     },
  { 0, "uid_name",  handle_ldap_uid_name  },
  { 0, "gid_name",  handle_ldap_gid_name  },
  { 0, "name_uid",  handle_ldap_name_uid  },
  { 0, "name_gid",  handle_ldap_name_gid  },
  { 0, "getgroups", handle_ldap_getgroups },
  { 0, NULL }
};

module ldap_module = {
  NULL, NULL,                       /* Always NULL */
  0x20,                             /* API Version 2.0 */
  "ldap",
  ldap_config,                      /* Configuration directive table */
  ldap_cmdtab,                      /* Command handlers */
  ldap_auth,                        /* Authentication handlers */
  pr_ldap_module_init, ldap_getconf /* Initialization functions */
};
