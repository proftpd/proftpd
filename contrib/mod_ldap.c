/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (C) 1999, MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
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
 */

/*
 * $Libraries: -lldap -llber$
 * ldap password lookup module for ProFTPD (mod_ldap v2.7.1)
 * Copyright (c) 1999-2000, John Morrissey <jwm@horde.net>
 *
 * Thanks for patches to:
 * Peter Fabian <fabian@staff.matavnet.hu> - LDAPAuthBinds
 * Pierrick Hascoet <pierrick@alias.fr> - OpenSSL password hash support
 * Bert Vermeulen <bert@be.easynet.net> - LDAPHomedirOnDemand,
 *                                        LDAPDefaultAuthScheme
 *
 * $Id: mod_ldap.c,v 1.10 2000-07-26 08:21:35 macgyver Exp $
 */

/* Default mode to use when creating home directory on demand. */
#define HOMEDIR_MODE 0755

/* Uncomment this if you have OpenSSL. You'll also need to edit ../Make.rules
   so the compiler will find OpenSSL's include files (-I/path/to/include-dir)
   and link again OpenSSL's crypto library (-L/path/to/lib-dir -lcrypto). */
/* #define HAVE_OPENSSL */

#include "conf.h"

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

#include <errno.h>
#include <lber.h>
#include <ldap.h>

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#endif

#include "privs.h"

#define HASH_TABLE_SIZE		10

typedef union idauth {
  uid_t uid;
  gid_t gid;
} idauth_t;

typedef struct _idmap {
  struct _idmap *next,*prev;

  /* This is a union because different OSs may give different types to UIDs
   * and GIDs.  This presents a far more portable way to deal with this
   * reality.
   */
  idauth_t id;

  unsigned short int negative;	/* have we gotten a negative answer before? */
  char *name;					/* user or group name */
} idmap_t;

static xaset_t *uid_table[HASH_TABLE_SIZE];
static xaset_t *gid_table[HASH_TABLE_SIZE];

/* Config entries */
static char *ldap_server,
			*ldap_dn, *ldap_dnpass,
			*ldap_auth_filter, *ldap_uid_filter, *ldap_gid_filter,
			*ldap_auth_prefix, *ldap_uid_prefix, *ldap_gid_prefix,
			*ldap_defaultauthscheme, *ldap_authbind_dn, *ldap_hdod_suffix;
static int ldap_doauth = 0, ldap_douid = 0, ldap_dogid = 0,
		   ldap_authbinds = 0, ldap_negcache = 0, ldap_querytimeout = 0,
           ldap_defaultuid = -1, ldap_defaultgid = -1,
		   ldap_hdod = 0, ldap_hdod_mode = HOMEDIR_MODE,
		   ldap_search_scope = LDAP_SCOPE_SUBTREE;
struct timeval ldap_querytimeout_tp;

static LDAP *ld, *ld_auth;



static void p_ldap_connect()
{
  if (ld != NULL) /* We're already connected, why connect again? */
	return;

  if ((ld = ldap_open(ldap_server, LDAP_PORT)) == NULL) {
	log_pri(LOG_ERR, "mod_ldap: p_ldap_connect(): ldap_open() to %s failed", ldap_server);
	return;
  }
  if (ldap_simple_bind_s(ld, ldap_dn, ldap_dnpass) != LDAP_SUCCESS) {
	log_pri(LOG_ERR, "mod_ldap: p_ldap_connect(): ldap_simple_bind() as %s failed", ldap_dn);
	return;
  }

  ldap_querytimeout_tp.tv_sec = (ldap_querytimeout ? ldap_querytimeout : 5);
  ldap_querytimeout_tp.tv_usec = 0;
}

static void p_ldap_unbind()
{
  if (ld != NULL) {
	if (ldap_unbind(ld) == -1)
	  log_pri(LOG_NOTICE, "mod_ldap: p_ldap_unbind(): ldap_unbind() failed");

	ld = NULL;
  }
}

static char *make_ldap_filter(pool *p, char *template, const char *entity)
{
    char *filter, *pos;
    int num_escapes = 0, i = 0, j = 0;

	pos = template;
	while ((pos = strstr(pos + 2, "%u")) != NULL)
		++num_escapes;

    /* -2 for the %u, +1 for the NULL */
    filter = pcalloc(p, strlen(template) - (num_escapes * 2) + (num_escapes * strlen(entity)) + 1);

	while (template[i] != '\0') {
		if (template[i] == '%' && template[i + 1] == 'u') {
			strcat(filter, entity);
			j += strlen(entity);
			i += 2;
		}
		else
			filter[j++] = template[i++];
	}

    return filter;
}

static struct passwd *ldap_user_lookup(char *filter, char *ldap_attrs[], char *prefix, pool *p)
{
  LDAPMessage *result, *e;
  char **values, *hdod_fulldir;
  unsigned short int i = 0;
  struct passwd *pw;
  struct stat st;

  /* If the LDAP connection has gone away or hasn't been established
     yet, attempt to establish it now. */
  if (ld == NULL) {
    p_ldap_connect();

    /* If we _still_ can't connect, give up and return NULL. */
    if (ld == NULL)
      return NULL;
  }

  if (! prefix) {
    log_pri(LOG_ERR, "mod_ldap: no LDAP prefix specified for auth/UID lookups");
    return NULL;
  }

  if (ldap_search_st(ld, prefix, ldap_search_scope, filter, ldap_attrs, 0, &ldap_querytimeout_tp, &result) == -1) {
    log_pri(LOG_ERR, "mod_ldap: ldap_user_lookup(): ldap_search_st() failed");
    return NULL;
  }

  if ((e = ldap_first_entry(ld, result)) == NULL) {
    ldap_msgfree(result);
    return NULL; /* No LDAP entries for this user */
  }

  pw = pcalloc(session.pool, sizeof(struct passwd));

  /* If we're doing auth binds, save the DN of this entry so we can
     bind to the LDAP server as it later. */
  if (ldap_authbinds && (! ldap_authbind_dn))
    ldap_authbind_dn = ldap_get_dn(ld, e);

  while (ldap_attrs[i] != NULL) {
    if ((values = ldap_get_values(ld, e, ldap_attrs[i])) == NULL) {

	  /* If we can't find the [ug]idNumber attrs, just fill the passwd
         struct in with default values from the config file. */
      if (strcasecmp(ldap_attrs[i], "uidNumber") == 0) {
        if (ldap_defaultuid != -1) {
          pw->pw_uid = ldap_defaultuid;
          ++i;
          continue;
        }
        else {
          log_pri(LOG_ERR, "mod_ldap: ldap_user_lookup(): no uidNumber attr for filter %s and ldap_defaultuid is undefined!", filter);
          return NULL;
        }
      }
      if (strcasecmp(ldap_attrs[i], "gidNumber") == 0) {
        if (ldap_defaultgid != -1) {
          pw->pw_gid = ldap_defaultgid;
          ++i;
          continue;
        }
        else {
          log_pri(LOG_ERR, "mod_ldap: ldap_user_lookup(): no gidNumber attr for filter %s and ldap_defaultgid is undefined!", filter);
          return NULL;
        }
      }

      /* We may not always have a loginShell entry. If it's not
         there, don't worry. */
      if (strcasecmp(ldap_attrs[i], "loginShell") == 0) {
        /* Prevent a segfault if no loginShell attr & RequireValidShell
           isn't in proftpd.conf. */
        pw->pw_shell = pstrdup(session.pool, "");
        ++i;
        continue;
      }

      /* We only restart the while loop above if we can fill in the
         [ug]id in question with a Default[UG]ID. If no [ug]idNumber
         attr was found and we don't have a Default[UG]ID configured,
         we will fall through to here and will complain about not being
         able to find the attr. */

      ldap_msgfree(result);
      log_pri(LOG_ERR, "mod_ldap: ldap_user_lookup(): ldap_get_values() failed for attr %s (filter: %s)", ldap_attrs[i], filter);
      return NULL;
    }

    /* Once we get here, we've already handled the default-[ug]idNumber
       situation, so we can just fill in the struct as normal; the if
       branches below for [ug]idNumber will never be called. */

    if (strcasecmp(ldap_attrs[i], "uid") == 0)
      pw->pw_name = pstrdup(session.pool, values[0]);
    else if (strcasecmp(ldap_attrs[i], "userPassword") == 0)
      pw->pw_passwd = pstrdup(session.pool, values[0]);
    else if (strcasecmp(ldap_attrs[i], "uidNumber") == 0)
      pw->pw_uid = (uid_t) atoi(values[0]);
    else if (strcasecmp(ldap_attrs[i], "gidNumber") == 0)
      pw->pw_gid = (gid_t) atoi(values[0]);
    else if (strcasecmp(ldap_attrs[i], "homeDirectory") == 0)
      pw->pw_dir = pstrdup(session.pool, values[0]);
    else if (strcasecmp(ldap_attrs[i], "loginShell") == 0)
      pw->pw_shell = pstrdup(session.pool, values[0]);
    else
      log_pri(LOG_WARNING, "mod_ldap: ldap_user_lookup(): ldap_get_values() loop found unknown attr %s", ldap_attrs[i]);

    ldap_value_free(values);
    ++i;
  }

  ldap_msgfree(result);

  if (ldap_hdod && pw->pw_dir) {
    if (stat(pw->pw_dir, &st) == -1 && errno == ENOENT) {
      if (mkdir(pw->pw_dir, ldap_hdod_mode) != 0) {
        log_pri(LOG_WARNING, "ldap_auth: ldap_user_lookup(): unable to create home directory %s: %s", pw->pw_dir, strerror(errno));
        return(NULL);
      }
    }

    if (ldap_hdod_suffix) {
      hdod_fulldir = pstrcat(p, pw->pw_dir, "/", ldap_hdod_suffix, NULL);
      if (stat(hdod_fulldir, &st) == -1 && errno == ENOENT) {
        if (mkdir(hdod_fulldir, ldap_hdod_mode) != 0) {
          log_pri(LOG_WARNING, "ldap_auth: ldap_user_lookup(): unable to create home directory suffix %s: %s", hdod_fulldir, strerror(errno));
          return(NULL);
        }
      }
    }
  }

  return pw;
}

static struct group *ldap_group_lookup(char *filter, char *ldap_attrs[])
{
  LDAPMessage *result, *e;
  char **values;
  unsigned short int i = 0, j = 0;
  int member_offset = 0, member_num = 0, member_len, members_len;
  struct group *gr;

  /* If the LDAP connection has gone away or hasn't been established
     yet, attempt to establish it now. */
  if (ld == NULL) {
    p_ldap_connect();

    /* If we _still_ can't connect, give up and return NULL. */
    if (ld == NULL)
      return NULL;
  }

  if (! ldap_gid_prefix) {
    log_pri(LOG_ERR, "mod_ldap: no LDAP prefix specified for GID lookups");
    return NULL;
  }

  if (ldap_search_st(ld, ldap_gid_prefix, ldap_search_scope, filter, ldap_attrs, 0, &ldap_querytimeout_tp, &result) == -1) {
    log_pri(LOG_ERR, "mod_ldap: ldap_group_lookup(): ldap_search_st() failed");
    return NULL;
  }

  if ((e = ldap_first_entry(ld, result)) == NULL) {
    ldap_msgfree(result);
    return NULL; /* No LDAP entries for this user */
  }

  gr = pcalloc(session.pool, sizeof(struct group));

  while (ldap_attrs[i] != NULL) {
    if ((values = ldap_get_values(ld, e, ldap_attrs[i])) == NULL) {
      if (strcasecmp(ldap_attrs[i], "memberUid") == 0) {
      	gr->gr_mem = palloc(session.pool, sizeof(char *));
      	gr->gr_mem[0] = pstrdup(session.pool, "");
      	gr->gr_mem[1] = NULL;

      	++i;
      	continue;
      }

      ldap_msgfree(result);
      log_pri(LOG_ERR, "mod_ldap: ldap_group_lookup(): ldap_get_values() failed for attr %s (filter: %s)", ldap_attrs[i], filter);
      return NULL;
    }

    if (strcasecmp(ldap_attrs[i], "cn") == 0)
      gr->gr_name = pstrdup(session.pool, values[0]);
    else if (strcasecmp(ldap_attrs[i], "gidNumber") == 0)
      gr->gr_gid = atoi(values[0]);
    else if (strcasecmp(ldap_attrs[i], "memberUid") == 0) {
      gr->gr_mem = palloc(session.pool, sizeof(char *));

      while (values[j] != NULL) {
        /* Take member1,member2,member3,... and put them, one at a time,
           into the array gr->gr_mem. */

        members_len = strlen(values[j]);
        while (member_offset < members_len)
        {
          member_len = strcspn(values[j] + member_offset, ",");
          gr->gr_mem[member_num] = pcalloc(session.pool, member_len + 1);
          strncpy(gr->gr_mem[member_num++], values[j] + member_offset, member_len);
          member_offset += member_len + 1;
        }

        gr->gr_mem[member_num] = NULL;
        ++j;
      }
    }
    else
      log_pri(LOG_WARNING, "mod_ldap: ldap_group_lookup(): ldap_get_values() loop found unknown attr %s", ldap_attrs[i]);

    ldap_value_free(values);
    ++i;
  }

  ldap_msgfree(result);
  return gr;
}

static struct group *p_ldap_getgrnam(cmd_rec *cmd, const char *name)
{
	char *filter, *group_attrs[] = {"cn", "gidNumber", "memberUid", NULL};

	filter = pstrcat(cmd->tmp_pool, "(&(cn=", name, ")(objectclass=posixGroup))", NULL);
	return(ldap_group_lookup(filter, group_attrs));
}

static struct group *p_ldap_getgrgid(cmd_rec *cmd, gid_t gid)
{
	char *filter, gidstr[BUFSIZ],
		 *group_attrs[] = {"cn", "gidNumber", "memberUid", NULL};

	snprintf(gidstr, sizeof(gidstr), "%d", gid);

    if (ldap_gid_filter && *ldap_gid_filter)
      filter = make_ldap_filter(cmd->tmp_pool, ldap_gid_filter, gidstr);
    else
      filter = pstrcat(cmd->tmp_pool, "(&(gidNumber=", gidstr, ")(objectclass=posixGroup))", NULL);

	return(ldap_group_lookup(filter, group_attrs));
}

static struct passwd *p_ldap_getpwnam(cmd_rec *cmd, const char *name)
{
  char *filter,
       *name_attrs[] = {"userPassword", "uid", "uidNumber", "gidNumber",
       					"homeDirectory", "loginShell", NULL};

  if (ldap_auth_filter && *ldap_auth_filter)
    filter = make_ldap_filter(cmd->tmp_pool, ldap_auth_filter, name);
  else
    filter = pstrcat(cmd->tmp_pool, "(&(uid=", name, ")(objectclass=posixAccount))", NULL);

  /* ldap_user_lookup() returns NULL if it doesn't find an entry or
     encounters an error. If everything goes all right, it returns a
     struct passwd, so we can just return its result directly.
     
     We also do some cute stuff here to work around lameness in LDAP servers
     like Sun Directory Services (SDS) 1.x and 3.x. If you request an attr
     that you don't have access to, SDS totally ignores any entries with
     that attribute. Thank you, Sun; how very smart of you. So if we're
     doing auth binds, we don't request the userPassword attr. */
  return ldap_user_lookup(filter, ldap_authbinds ? name_attrs + 1 : name_attrs, ldap_auth_prefix, cmd->tmp_pool);
}

static struct passwd *p_ldap_getpwuid(cmd_rec *cmd, uid_t uid)
{
  char *filter, uidstr[BUFSIZ],
       *uid_attrs[] = {"uid", "uidNumber", "gidNumber", "homeDirectory",
                       "loginShell", NULL};

  snprintf(uidstr, sizeof(uidstr), "%d", uid);

  if (ldap_uid_filter && *ldap_uid_filter)
    filter = make_ldap_filter(cmd->tmp_pool, ldap_uid_filter, uidstr);
  else
    filter = pstrcat(cmd->tmp_pool, "(&(uidNumber=", uidstr, ")(objectclass=posixAccount))", NULL);

  /* ldap_user_lookup() returns NULL if it doesn't find an entry or
     encounters an error. If everything goes all right, it returns a
     struct passwd, so we can just return its result directly. */
  return ldap_user_lookup(filter, uid_attrs, ldap_uid_prefix, cmd->tmp_pool);
}

inline static int _compare_uid(idmap_t *m1, idmap_t *m2)
{
  if(m1->id.uid < m2->id.uid)
    return -1;

  if(m1->id.uid > m2->id.uid)
    return 1;

  return 0;
}

inline static int _compare_gid(idmap_t *m1, idmap_t *m2)
{
  if(m1->id.gid < m2->id.gid)
    return -1;

  if(m1->id.gid > m2->id.gid)
    return 1;

  return 0;
}

inline static int _compare_id(xaset_t **table, idauth_t id, idauth_t idcomp)
{
  if(table == uid_table)
    return id.uid == idcomp.uid;
  else
    return id.gid == idcomp.gid;
}

static idmap_t *_auth_lookup_id(xaset_t **id_table, idauth_t id)
{
  int hash = ((id_table == uid_table) ? id.uid : id.gid) % HASH_TABLE_SIZE;
  idmap_t *m;
  
  if(!id_table[hash])
    id_table[hash] = xaset_create(permanent_pool, (id_table == uid_table) ?
				  (XASET_COMPARE)_compare_uid :
				  (XASET_COMPARE)_compare_gid);
  
  for(m = (idmap_t *) id_table[hash]->xas_list; m; m = m->next) {
    if(_compare_id(id_table, m->id, id))
      break;
  }
  
  if(!m || !_compare_id(id_table, m->id, id)) {
    /* Isn't in the table */
    m = (idmap_t *) pcalloc(id_table[hash]->mempool, sizeof(idmap_t));

    if(id_table == uid_table)
      m->id.uid = id.uid;
    else
      m->id.gid = id.gid;
    
    xaset_insert_sort(id_table[hash], (xasetmember_t *) m, FALSE);
  }
  
  return m;
}

MODRET ldap_setpwent(cmd_rec *cmd)
{
  if (ldap_doauth || ldap_douid || ldap_dogid)
    p_ldap_connect();
  else
    return DECLINED(cmd);

  return HANDLED(cmd);
}

MODRET ldap_endpwent(cmd_rec *cmd)
{
  if (ldap_doauth || ldap_douid || ldap_dogid)
    p_ldap_unbind();
  else
    return DECLINED(cmd);

  return HANDLED(cmd);
}

MODRET ldap_getpwuid(cmd_rec *cmd)
{
  struct passwd *pw;

  if (! ldap_douid)
    return DECLINED(cmd);

  if ((pw = p_ldap_getpwuid(cmd, (int)cmd->argv[0]))) {
    pw->pw_uid = (int)cmd->argv[0];
    return mod_create_data(cmd,pw);
  }
  else
    return DECLINED(cmd);
}

MODRET ldap_getpwnam(cmd_rec *cmd)
{
  struct passwd *pw;

  if (! ldap_doauth)
    return DECLINED(cmd);

  if ((pw = p_ldap_getpwnam(cmd, cmd->argv[0]))) {
    pw->pw_name = pstrdup(session.pool, cmd->argv[0]);
    return mod_create_data(cmd,pw);
  }
  else
    return DECLINED(cmd);
}

MODRET ldap_getgrnam(cmd_rec *cmd)
{
  struct group *gr;

  if (! ldap_dogid)
    return DECLINED(cmd);

  if ((gr = p_ldap_getgrnam(cmd, cmd->argv[0]))) {
    gr->gr_name = pstrdup(session.pool, cmd->argv[0]);
    return mod_create_data(cmd,gr);
  }
  else
    return DECLINED(cmd);
}

MODRET ldap_getgrgid(cmd_rec *cmd)
{
  struct group *gr;

  if (! ldap_dogid)
    return DECLINED(cmd);

  if ((gr = p_ldap_getgrgid(cmd, (int)cmd->argv[0]))) {
    gr->gr_gid = (int)cmd->argv[0];
    return mod_create_data(cmd,gr);
  }
  else
    return DECLINED(cmd);
}

/* high-level auth handlers
 */

/* cmd->argv[0] : user name
 * cmd->argv[1] : cleartext password
 */

MODRET ldap_is_auth(cmd_rec *cmd)
{
  const char *name;
  struct passwd *pw;
  char *filter, *pass_attrs[] = {"userPassword", NULL};

  if (! ldap_doauth)
    return DECLINED(cmd);

  name = cmd->argv[0];

  /* FIXME: If we pass "" to auth_check, the mod_unixpw auth handler gets
            called before the mod_ldap auth handler, so mod_unixpw will
            allow in any LDAP auth-bind user with an incorrect password.
            Can we kludge around this by setting the directive to not
            allow empty passwords? (its name escapes me right now)
            For now, we'll kludge around this by passing "*", which
            mod_unixpw will happily deny auth to. */
  /* If we're doing auth binds, cut right to the chase and auth them. */
  if (ldap_authbinds) {
    if (auth_check(cmd->tmp_pool, "*", cmd->argv[0], cmd->argv[1]))
/*      return ERROR_INT(cmd, AUTH_BADPWD);*/
      return DECLINED(cmd);

    return HANDLED(cmd);
  }

  filter = pstrcat(cmd->tmp_pool, "uid=", name, NULL);
  if ((pw = ldap_user_lookup(filter, pass_attrs, ldap_auth_prefix, cmd->tmp_pool)) == NULL)
    return DECLINED(cmd); /* Can't find the user in the LDAP db. */

  if (! pw->pw_passwd)
    return ERROR_INT(cmd, AUTH_NOPWD);

  if (auth_check(cmd->tmp_pool, pw->pw_passwd, cmd->argv[0], cmd->argv[1]))
    return ERROR_INT(cmd, AUTH_BADPWD);

  return HANDLED(cmd);
}

/*
 * cmd->argv[0] = hashed password,
 * cmd->argv[1] = user,
 * cmd->argv[2] = cleartext
 */

MODRET ldap_check(cmd_rec *cmd)
{
  char *pw, *cpw, *hash_method;
  int encname_len;

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

  cpw = cmd->argv[0];
  pw = cmd->argv[2];


  if (ldap_authbinds) {
    if ( (pw == NULL) || (strlen(pw) == 0) ||
         (ldap_authbind_dn == NULL) || ((ldap_authbind_dn) == 0) )
      return DECLINED(cmd);

    if ((ld_auth = ldap_open(ldap_server, LDAP_PORT)) == NULL) {
	  log_pri(LOG_ERR, "mod_ldap: ldap_is_auth(): ldap_open() to %s failed", ldap_server);
      return DECLINED(cmd);
    }

    if (ldap_simple_bind_s(ld_auth, ldap_authbind_dn, cmd->argv[2]) != LDAP_SUCCESS)
      return DECLINED(cmd);

    return HANDLED(cmd);
  }

  /* Get the length of "scheme" in the leading {scheme} so we can skip it
     in the password comparison. */
  encname_len = strcspn(cpw + 1, "}");
  hash_method = pstrndup(cmd->tmp_pool, cpw + 1, encname_len);

  /* Check to see how the password is encrypted, and check accordingly. */

  if (hash_method == NULL) { /* No leading {scheme} */
    if (ldap_defaultauthscheme && (strcasecmp(ldap_defaultauthscheme, "clear") == 0)) {
      if (strcmp(pw, cpw) != 0)
      return ERROR(cmd);
    }
    else { /* else, assume crypt */
      if (strcmp(crypt(pw,cpw), cpw) != 0)
      return ERROR(cmd);
    }
  }
  else if (strncasecmp(hash_method, "crypt", strlen(hash_method)) == 0) { /* {crypt} */
    if (strcmp(crypt(pw, cpw + encname_len + 2), cpw + encname_len + 2) != 0)
       return ERROR(cmd);
  }
  else if (strncasecmp(hash_method, "clear", strlen(hash_method)) == 0) { /* {clear} */
    if (strcmp(pw, cpw + encname_len + 2) != 0)
      return ERROR(cmd);
  }
#ifdef HAVE_OPENSSL
  else { /* Try the cipher mode found */
    log_debug(DEBUG5, "mod_ldap: %s-encrypted password found, trying to auth.", hash_method);

    SSLeay_add_all_digests();

    /* This is a kludge. This is only a kludge. OpenLDAP likes {sha}
       (at least, the OpenLDAP ldappasswd generates {sha}), but OpenSSL
       likes {sha1} and does not understand {sha}. We translate
       RMD160 -> RIPEMD160 here, too. */
    if (strncasecmp(hash_method, "SHA", 3) == 0)
        md = EVP_get_digestbyname("SHA1");
    else if (strncasecmp(hash_method, "RMD160", 6) == 0)
        md = EVP_get_digestbyname("RIPEMD160");
    else
        md = EVP_get_digestbyname(hash_method);

    if (! md) {
      log_debug(DEBUG5, "mod_ldap: %s not supported by OpenSSL, declining auth request", hash_method);
      return DECLINED(cmd); /* Some other module may support it. */
    }

    /* Make a digest of the user-supplied password. */
    EVP_DigestInit(&EVP_Context, md);
    EVP_DigestUpdate(&EVP_Context, pw, strlen(pw));
    EVP_DigestFinal(&EVP_Context, md_value, &md_len);

    /* Base64 Encoding */
    EVP_EncodeInit(&EVP_Encode);
    EVP_EncodeBlock(buff, md_value, md_len);

    if (strcmp(buff, cpw + encname_len + 2) != 0)
      return ERROR(cmd);
  }
#else /* HAVE_OPENSSL */
  else /* Can't find a supported {scheme} */
    return DECLINED(cmd);
#endif /* HAVE_OPENSSL */

  return HANDLED(cmd);
}

MODRET ldap_uid_name(cmd_rec *cmd)
{
  idmap_t *m;
  idauth_t id;
  struct passwd *pw;

  if (! ldap_douid)
    return DECLINED(cmd);

  id.uid = (uid_t)cmd->argv[0];
  m = _auth_lookup_id(uid_table, id);

  if(!m->name) {
    if (ldap_negcache) /* If we're doing negative caching as per config... */
      if (m->negative) /* It wasn't in the LDAP db before, don't look again. */
        return DECLINED(cmd);

    /* Wasn't cached and we've haven't seen this one, so perform a lookup. */
    pw = p_ldap_getpwuid(cmd, id.uid);

    if(pw)
      m->name = pstrdup(permanent_pool,pw->pw_name);
    else {
      if (ldap_negcache)
        m->negative = 1;
      return DECLINED(cmd);
    }
  }

  return mod_create_data(cmd,m->name);
}

MODRET ldap_gid_name(cmd_rec *cmd)
{
  idmap_t *m;
  idauth_t id;
  struct group *gr;

  if (! ldap_dogid)
    return DECLINED(cmd);

  id.gid = (gid_t)cmd->argv[0];
  m = _auth_lookup_id(gid_table, id);

  if(!m->name) {
    if (ldap_negcache) /* If we're doing negative caching as per config... */
      if (m->negative) /* It wasn't in the LDAP db before, don't look again. */
        return DECLINED(cmd);

    /* Wasn't cached and we've haven't seen this one, so perform a lookup. */
    gr = p_ldap_getgrgid(cmd, id.gid);

    if(gr)
      m->name = pstrdup(permanent_pool,gr->gr_name);
    else {
      if (ldap_negcache)
        m->negative = 1;
      return DECLINED(cmd);
    }
  }

  return mod_create_data(cmd,m->name);
}

MODRET ldap_name_uid(cmd_rec *cmd)
{
  struct passwd *pw;
  const char *name;

  if (! ldap_doauth)
    return DECLINED(cmd);

  name = cmd->argv[0];

  pw = p_ldap_getpwnam(cmd,name);

  if(pw)
    return mod_create_data(cmd,(void*)pw->pw_uid);
  return DECLINED(cmd);
}

MODRET ldap_name_gid(cmd_rec *cmd)
{
  struct group *gr;
  const char *name;

  if (! ldap_dogid)
    return DECLINED(cmd);

  name = cmd->argv[0];

  gr = p_ldap_getgrnam(cmd,name);

  if(gr)
    return mod_create_data(cmd,(void*)gr->gr_gid);
  return DECLINED(cmd);
}

static int p_ldap_init()
{
  memset(uid_table,0,sizeof(uid_table));
  memset(gid_table,0,sizeof(gid_table));
  return 0;
}

MODRET set_ldap_server(cmd_rec *cmd)
{
  config_rec *c;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param_str("LDAPServer",1,cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_ldap_dninfo(cmd_rec *cmd)
{
  config_rec *c;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param_str("LDAPDNInfo", 2, cmd->argv[1], cmd->argv[2]);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_ldap_authbinds(cmd_rec *cmd)
{
  int b;
  config_rec *c;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((b = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "LDAPAuthBinds: expected boolean argument.");

  c = add_config_param("LDAPAuthBinds", 1, (void *) b);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_ldap_querytimeout(cmd_rec *cmd)
{
  config_rec *c;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param("LDAPQueryTimeout", 1, atoi(cmd->argv[1]));
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_ldap_searchscope(cmd_rec *cmd)
{
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param_str("LDAPSearchScope", 1, cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;

  return(HANDLED(cmd));
}

MODRET set_ldap_searchfilter(cmd_rec *cmd)
{
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param_str("LDAPSearchFilter", 1, cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;

  return(HANDLED(cmd));
}

MODRET set_ldap_doauth(cmd_rec *cmd)
{
  int b;
  config_rec *c;

  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((b = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "LDAPDoAuth: expected boolean argument for first argument.");

  if (b == 1) { CHECK_ARGS(cmd,2); }
  else        { CHECK_ARGS(cmd,1); }

  c = add_config_param("LDAPDoAuth", 3, (void *) b);
  c->argv[1] = pstrdup(permanent_pool, cmd->argv[2]);
  c->argv[2] = pstrdup(permanent_pool, cmd->argv[3]);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_ldap_douid(cmd_rec *cmd)
{
  int b;
  config_rec *c;

  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((b = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "LDAPDoUIDLookups: expected boolean argument for first argument.");

  if (b == 1) { CHECK_ARGS(cmd, 2); }
  else        { CHECK_ARGS(cmd, 1); }

  c = add_config_param("LDAPDoUIDLookups", 3, (void *) b);
  c->argv[1] = pstrdup(permanent_pool, cmd->argv[2]);
  c->argv[2] = pstrdup(permanent_pool, cmd->argv[3]);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_ldap_dogid(cmd_rec *cmd)
{
  int b;
  config_rec *c;

  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((b = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "LDAPDoGIDLookups: expected boolean argument for first argument.");

  if (b == 1) { CHECK_ARGS(cmd,2); }
  else        { CHECK_ARGS(cmd,1); }

  c = add_config_param("LDAPDoGIDLookups", 3, (void *) b);
  c->argv[1] = pstrdup(permanent_pool, cmd->argv[2]);
  c->argv[2] = pstrdup(permanent_pool, cmd->argv[3]);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_ldap_defaultuid(cmd_rec *cmd)
{
  config_rec *c;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param("LDAPDefaultUID", 1, atoi(cmd->argv[1]));
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_ldap_defaultgid(cmd_rec *cmd)
{
  config_rec *c;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param("LDAPDefaultGID", 1, atoi(cmd->argv[1]));
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_ldap_negcache(cmd_rec *cmd)
{
  int b;
  config_rec *c;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((b = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "LDAPNegativeCache: expected boolean argument.");

  c = add_config_param("LDAPNegativeCache", 1, (void *) b);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_ldap_hdod(cmd_rec *cmd)
{
  int b;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((b = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "LDAPHomedirOnDemand: expected boolean argument.");

  c = add_config_param("LDAPHomedirOnDemand", 2, (void *) b);
  c->argv[1] = pstrdup(permanent_pool, cmd->argv[2]);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);

}

MODRET set_ldap_hdodsuffix(cmd_rec *cmd)
{
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param_str("LDAPHomedirOnDemandSuffix", 1, cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;

  return(HANDLED(cmd));
}

MODRET set_ldap_defaultauthscheme(cmd_rec *cmd)
{
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param_str("LDAPDefaultAuthScheme", 1, cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;

  return(HANDLED(cmd));
}

static int ldap_getconf(void)
{
  char *scope;
  config_rec *c;

  /* If ldap_server is NULL, ldap_open() will connect to localhost. */
  ldap_server = (char *)get_param_ptr(main_server->conf, "LDAPServer", FALSE);

  if ((c = find_config(CURRENT_CONF, CONF_PARAM, "LDAPDNInfo", FALSE)) != NULL) {
  	ldap_dn = pstrdup(session.pool, c->argv[0]);
  	ldap_dnpass = pstrdup(session.pool, c->argv[1]);
  }

  if (get_param_int(main_server->conf,"LDAPAuthBinds", FALSE) > 0)
    ldap_authbinds = 1;

  ldap_querytimeout = get_param_int(main_server->conf, "LDAPQueryTimeout", FALSE);

  scope = get_param_ptr(main_server->conf, "LDAPSearchScope", FALSE);
  if (scope && *scope)
    if (strcasecmp(scope, "onelevel") == 0)
      ldap_search_scope = LDAP_SCOPE_ONELEVEL;

  if ((c = find_config(CURRENT_CONF, CONF_PARAM, "LDAPDoAuth", FALSE)) != NULL) {
    if ( (int)c->argv[0] > 0) {
      ldap_doauth = 1;
      ldap_auth_prefix = pstrdup(session.pool, c->argv[1]);
      ldap_auth_filter = pstrdup(session.pool, c->argv[2]);
    }
  }

  if ((c = find_config(CURRENT_CONF, CONF_PARAM, "LDAPDoUIDLookups", FALSE)) != NULL) {
    if ( (int)c->argv[0] > 0) {
      ldap_douid = 1;
      ldap_uid_prefix = pstrdup(session.pool, c->argv[1]);
      ldap_uid_filter = pstrdup(session.pool, c->argv[2]);
    }
  }

  if ((c = find_config(CURRENT_CONF, CONF_PARAM, "LDAPDoGIDLookups", FALSE)) != NULL) {
    if ( (int)c->argv[0] > 0) {
      ldap_dogid = 1;
      ldap_gid_prefix = pstrdup(session.pool, c->argv[1]);
      ldap_gid_filter = pstrdup(session.pool, c->argv[2]);
    }
  }

  ldap_defaultuid = get_param_int(main_server->conf, "LDAPDefaultUID", FALSE);
  ldap_defaultgid = get_param_int(main_server->conf, "LDAPDefaultGID", FALSE);

  if (get_param_int(main_server->conf,"LDAPNegativeCache", FALSE) > 0)
    ldap_negcache = 1;

  if ((c = find_config(CURRENT_CONF, CONF_PARAM, "LDAPHomedirOnDemand", FALSE)) != NULL) {
    if ( (int)c->argv[0] > 0) {
      ldap_hdod = 1;

      /* Use strtol() instead of atoi() here becuase we need to pass an octal
         (base 8) mode to mkdir(). */
      if (c->argv[1])
        ldap_hdod_mode = strtol(c->argv[1], (char **)NULL, 8);
    }
  }

  ldap_hdod_suffix = (char *)get_param_ptr(main_server->conf, "LDAPHomedirOnDemandSuffix", FALSE);

  /* If ldap_defaultauthscheme is NULL, ldap_check() will assume crypt. */
  ldap_defaultauthscheme = (char *)get_param_ptr(main_server->conf, "LDAPDefaultAuthScheme", FALSE);

  return 0;
}

static conftable ldap_config[] = {
  { "LDAPServer",                set_ldap_server,                NULL },
  { "LDAPDNInfo",                set_ldap_dninfo,                NULL },
  { "LDAPAuthBinds",             set_ldap_authbinds,             NULL },
  { "LDAPQueryTimeout",          set_ldap_querytimeout,          NULL },
  { "LDAPSearchScope",           set_ldap_searchscope,           NULL },
  { "LDAPSearchFilter",          set_ldap_searchfilter,          NULL },
  { "LDAPNegativeCache",         set_ldap_negcache,              NULL },
  { "LDAPDoAuth",                set_ldap_doauth,                NULL },
  { "LDAPDoUIDLookups",          set_ldap_douid,                 NULL },
  { "LDAPDoGIDLookups",          set_ldap_dogid,                 NULL },
  { "LDAPDefaultUID",            set_ldap_defaultuid,            NULL },
  { "LDAPDefaultGID",            set_ldap_defaultgid,            NULL },
  { "LDAPHomedirOnDemand",       set_ldap_hdod,                  NULL },
  { "LDAPHomedirOnDemandSuffix", set_ldap_hdodsuffix,            NULL },
  { "LDAPDefaultAuthScheme",     set_ldap_defaultauthscheme,     NULL },
  { NULL,                        NULL,                           NULL }
};

static authtable ldap_auth[] = {
  { 0,  "setpwent",  ldap_setpwent  },
  { 0,  "endpwent",  ldap_endpwent  },
  { 0,  "setgrent",  ldap_setpwent  },
  { 0,  "endgrent",  ldap_endpwent  },
  { 0,  "getpwnam",  ldap_getpwnam  },
  { 0,  "getpwuid",  ldap_getpwuid  },
  { 0,  "getgrnam",  ldap_getgrnam  },
  { 0,  "getgrgid",  ldap_getgrgid  },
  { 0,  "auth",      ldap_is_auth   },
  { 0,  "check",     ldap_check     },
  { 0,  "uid_name",  ldap_uid_name  },
  { 0,  "gid_name",  ldap_gid_name  },
  { 0,  "name_uid",  ldap_name_uid  },
  { 0,  "name_gid",  ldap_name_gid  },
  { 0,  NULL }
};

module ldap_module = {
  NULL,NULL,                /* Always NULL */
  0x20,                     /* API Version 2.0 */
  "ldap",
  ldap_config,              /* Configuration directive table */
  NULL,                     /* No command handlers */
  ldap_auth,                /* Authentication handlers */
  p_ldap_init,ldap_getconf  /* Initialization functions */
};
