/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (C) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
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
 * ldap password lookup module for ProFTPD (mod_ldap v2.5.2)
 * Author: John Morrissey <jwm@horde.net>
 *
 * Thanks for patches to:
 * Peter Fabian <fabian@staff.matavnet.hu> - LDAPAuthBinds
 * Bert Vermeulen <bert@be.easynet.net> - LDAPHomedirOnDemand,
 *                                        LDAPDefaultAuthScheme
 *
 * $Id: mod_ldap.c,v 1.6 2000-02-26 21:34:39 macgyver Exp $
 */

#include "conf.h"

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

#include <lber.h>
#include <ldap.h>

#include "privs.h"

#define HASH_TABLE_SIZE		10

typedef struct _idmap {
  struct _idmap *next,*prev;

  unsigned short int negative;	/* have we gotten a negative answer before? */
  int id;						/* uid or gid */
  char *name;					/* user or group name */
} idmap_t;

static xaset_t *uid_table[HASH_TABLE_SIZE];
static xaset_t *gid_table[HASH_TABLE_SIZE];

/* Config entries */
static char *ldap_server,
			*ldap_dn, *ldap_dnpass,
			*ldap_auth_prefix, *ldap_uid_prefix, *ldap_gid_prefix,
			*ldap_defaultauthscheme, *ldap_authbind_dn;
static int ldap_doauth = 0, ldap_douid = 0, ldap_dogid = 0,
		   ldap_authbinds = 0, ldap_negcache = 0, ldap_querytimeout = 0,
           ldap_defaultuid = -1, ldap_defaultgid = -1,
		   ldap_homedirondemand = 0;

static LDAP *ld, *ld_auth;

/* Mode to use when creating home directory on demand. */
#define HOMEDIR_MODE 0755


static void p_ldap_connect()
{
  struct timeval tp;

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

  if (ldap_querytimeout) {
    tp.tv_sec = ldap_querytimeout;
    tp.tv_usec = 0;

    ldap_ufn_timeout(&tp);
  }
}

static void p_ldap_unbind()
{
  if (ld != NULL) {
	if (ldap_unbind(ld) == -1)
	  log_pri(LOG_NOTICE, "mod_ldap: p_ldap_unbind(): ldap_unbind() failed");

	ld = NULL;
  }
}

static struct passwd *ldap_user_lookup(char *filter, char *ldap_attrs[], char *prefix)
{
  LDAPMessage *result, *e;
  char **values;
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

  ldap_ufn_setprefix(ld, prefix);

  if (ldap_ufn_search_s(ld, filter, ldap_attrs, 0, &result) == -1) {
    log_pri(LOG_ERR, "mod_ldap: ldap_user_lookup(): ldap_ufn_search_s() failed");
    return NULL;
  }

  if ((e = ldap_first_entry(ld, result)) == NULL) {
    ldap_msgfree(result);
    return NULL; /* No LDAP entries for this user */
  }

  pw = pcalloc(session.pool, sizeof(struct passwd));

  /* If we're doing auth binds, save the DN of this entry so we can
     bind to the LDAP server as it later. */
  if (ldap_authbinds && (! ldap_authbind_dn)) {
    ldap_authbind_dn = ldap_get_dn(ld, e);
  }

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

      /* If we're doing authenticated binds, this record won't have a
         userPassword attr, so just skip this attr by continuing the loop. */
      if ( (strcasecmp(ldap_attrs[i], "userPassword") == 0) &&
           ldap_authbinds) {
        ++i;
        continue;
      }

      /* We may not always have an allowedServices entry. If it's not
         there, don't worry. */
      if (strcasecmp(ldap_attrs[i], "allowedServices") == 0) {
        ++i;
        continue;
      }

      /* We may not always have a loginShell entry. If it's not
         there, don't worry. */
      if (strcasecmp(ldap_attrs[i], "loginShell") == 0) {
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
    else if (strcasecmp(ldap_attrs[i], "allowedServices") == 0) {
      /* We'll look for the string FTP anywhere in this user's allowedServices
       attribute. If it's not there, we'll return NULL (and therefore deny
       them access). */

      if (strstr(values[0], "FTP") == NULL) {
        log_pri(LOG_ERR, "mod_ldap: user with filter %s denied (FTP not in allowedServices attr)", filter);
        ldap_value_free(values);
        ldap_msgfree(result);
        return NULL;
      }
    }
    else
      log_pri(LOG_WARNING, "mod_ldap: ldap_user_lookup(): ldap_get_values() loop found unknown attr %s", ldap_attrs[i]);

    ldap_value_free(values);
    ++i;
  }

  ldap_msgfree(result);

  if (ldap_homedirondemand && pw->pw_dir) {
    if (stat(pw->pw_dir, &st) == -1 && errno == ENOENT)
      if (mkdir(pw->pw_dir, HOMEDIR_MODE) != 0) {
        log_pri(LOG_WARNING, "ldap_auth: ldap_user_lookup(): unable to create home directory %s: %s", pw->pw_dir, strerror(errno));
        return(NULL);
      }
  }

  return pw;
}

static struct group *ldap_group_lookup(char *filter, char *ldap_attrs[])
{
  LDAPMessage *result, *e;
  char **values;
  unsigned short int i = 0;
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

  ldap_ufn_setprefix(ld, ldap_gid_prefix);

  if (ldap_ufn_search_s(ld, filter, ldap_attrs, 0, &result) == -1) {
    log_pri(LOG_ERR, "mod_ldap: ldap_group_lookup(): ldap_ufn_search_s() failed");
    return NULL;
  }

  if ((e = ldap_first_entry(ld, result)) == NULL) {
    ldap_msgfree(result);
    return NULL; /* No LDAP entries for this user */
  }

  gr = pcalloc(session.pool, sizeof(struct passwd));

  while (ldap_attrs[i] != NULL) {
    if ((values = ldap_get_values(ld, e, ldap_attrs[i])) == NULL) {
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

      /* Take member1,member2,member3,... and put them, one at a time,
         into the array gr->gr_mem. */

      members_len = strlen(values[0]);
      while (member_offset < members_len)
      {
        member_len = strcspn(values[0] + member_offset, ",");
        gr->gr_mem[member_num] = pcalloc(session.pool, member_len + 1);
        strncpy(gr->gr_mem[member_num++], values[0] + member_offset, member_len);
        member_offset += member_len + 1;
      }

      gr->gr_mem[member_num] = NULL;
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

	filter = pstrcat(cmd->tmp_pool, "cn=", name, NULL);
	return(ldap_group_lookup(filter, group_attrs));
}

static struct group *p_ldap_getgrgid(cmd_rec *cmd, gid_t gid)
{
	char *filter, gidstr[BUFSIZ],
		 *group_attrs[] = {"cn", "gidNumber", "memberUid", NULL};

	snprintf(gidstr, sizeof(gidstr), "%d", gid);
	filter = pstrcat(cmd->tmp_pool, "gidNumber=", gidstr, NULL);
	return(ldap_group_lookup(filter, group_attrs));
}

static struct passwd *p_ldap_getpwnam(cmd_rec *cmd, const char *name)
{
  struct passwd *pw;
  char *filter,
       *name_attrs[] = {"userPassword", "uidNumber", "gidNumber",
       					"homeDirectory", "loginShell", "allowedServices", NULL};

  filter = pstrcat(cmd->tmp_pool, "uid=", name, NULL);

  if ((pw = ldap_user_lookup(filter, name_attrs, ldap_auth_prefix)) != NULL) {
    pw->pw_name = pstrdup(session.pool, name);
    return pw; /* ldap_user_lookup() found an entry, so return it. */
  }

  /* ldap_user_lookup() didn't find it, or encountered an error. */
  return NULL;
}

static struct passwd *p_ldap_getpwuid(cmd_rec *cmd, uid_t uid)
{   
  struct passwd *pw;
  char *filter, uidstr[BUFSIZ],
       *uid_attrs[] = {"uid", "userPassword", "gidNumber", "homeDirectory",
                       "loginShell", NULL};

  snprintf(uidstr, sizeof(uidstr), "%d", uid);
  filter = pstrcat(cmd->tmp_pool, "uidNumber=", uidstr, NULL);

  if ((pw = ldap_user_lookup(filter, uid_attrs, ldap_uid_prefix)) != NULL) {
    pw->pw_uid = uid;
    return pw; /* ldap_user_lookup() found an entry, so return it. */
  }

  /* ldap_user_lookup() didn't find it, or encountered an error. */
  return NULL;
}

static int _compare_id(idmap_t *m1, idmap_t *m2)
{
  if(m1->id < m2->id)
    return -1;
  if(m1->id > m2->id)
    return 1;
  return 0;
}

static idmap_t *_auth_lookup_id(xaset_t **id_table, int id)
{
  int hash = id % HASH_TABLE_SIZE;
  idmap_t *m;

  if(!id_table[hash])
    id_table[hash] = xaset_create(permanent_pool,
                     (XASET_COMPARE)_compare_id);

  for(m = (idmap_t*)id_table[hash]->xas_list; m; m=m->next)
    if(m->id == id)
      break;

  if(!m || m->id != id) {
    /* Isn't in the table */
    m = (idmap_t*)pcalloc(id_table[hash]->mempool,sizeof(idmap_t));
    m->id = id;
    xaset_insert_sort(id_table[hash],(xasetmember_t*)m,FALSE);
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
  if ((pw = ldap_user_lookup(filter, pass_attrs, ldap_auth_prefix)) == NULL)
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
  static char *pw, *cpw;
  int encname_len;

  if (! ldap_doauth)
    return DECLINED(cmd);

  cpw = cmd->argv[0];
  pw = cmd->argv[2];

  if (ldap_authbinds) {
    if ( (pw == NULL) || (strlen(pw) == 0) ||
         (ldap_authbind_dn == NULL) || ((ldap_authbind_dn) == 0) )
      return DECLINED(cmd);

/*    ldap_authbind_dn = pstrcat(cmd->tmp_pool, "cn=", cmd->argv[1], ",", ldap_auth_prefix, NULL);*/

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

  /* Check to see how the password is encrypted, and check accordingly. */

  if (encname_len == strlen(cpw + 1)) { /* No leading {scheme} */
    if (ldap_defaultauthscheme && (strcmp(ldap_defaultauthscheme, "clear") == 0)) {
	  if (strcmp(pw, cpw) != 0)
	    return ERROR(cmd);
    }
    else { /* else, assume crypt */
	  if (strcmp(crypt(pw,cpw),cpw) != 0)
        return ERROR(cmd);
    }
  }

  else if (strncmp(cpw + 1, "crypt", encname_len) == 0) { /* {crypt} */
    if (strcmp(crypt(pw, cpw + encname_len + 2), cpw + encname_len + 2) != 0)
       return ERROR(cmd);
  }
  else if (strncmp(cpw + 1, "clear", encname_len) == 0) { /* {clear} */
    if (strcmp(pw, cpw + encname_len + 2) != 0)
      return ERROR(cmd);
  }
  else /* Can't find a supported {scheme} */
    return DECLINED(cmd);

  return HANDLED(cmd);
}

MODRET ldap_uid_name(cmd_rec *cmd)
{
  idmap_t *m;
  struct passwd *pw;
  uid_t uid;

  if (! ldap_douid)
    return DECLINED(cmd);

  uid = (uid_t)cmd->argv[0];
  m = _auth_lookup_id(uid_table,uid);

  if(!m->name) {
    if (ldap_negcache) /* If we're doing negative caching as per config... */
      if (m->negative) /* It wasn't in the LDAP db before, don't look again. */
        return DECLINED(cmd);

    /* Wasn't cached and we've haven't seen this one, so perform a lookup. */
    pw = p_ldap_getpwuid(cmd,uid);

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
  struct group *gr;
  gid_t gid;

  if (! ldap_dogid)
    return DECLINED(cmd);

  gid = (gid_t)cmd->argv[0];

  m = _auth_lookup_id(gid_table,gid);

  if(!m->name) {
    if (ldap_negcache) /* If we're doing negative caching as per config... */
      if (m->negative) /* It wasn't in the LDAP db before, don't look again. */
        return DECLINED(cmd);

    /* Wasn't cached and we've haven't seen this one, so perform a lookup. */
    gr = p_ldap_getgrgid(cmd,gid);

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

MODRET set_ldap_doauth(cmd_rec *cmd)
{
  int b;
  config_rec *c;

  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((b = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "LDAPDoAuth: expected boolean argument for first argument.");

  if (b == 1) { CHECK_ARGS(cmd,2); }
  else        { CHECK_ARGS(cmd,1); }

  c = add_config_param("LDAPDoAuth", 2, (void *) b, NULL);
  c->argv[1] = pstrdup(permanent_pool, cmd->argv[2]);
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

  c = add_config_param("LDAPDoUIDLookups", 2, (void *) b, NULL);
  c->argv[1] = pstrdup(permanent_pool, cmd->argv[2]);
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

  c = add_config_param("LDAPDoGIDLookups", 2, (void *) b, NULL);
  c->argv[1] = pstrdup(permanent_pool, cmd->argv[2]);
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

MODRET set_ldap_homedirondemand(cmd_rec *cmd)
{
  int b;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((b = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "LDAPHomedirOnDemand: expected boolean argument.");

  add_config_param("LDAPHomedirOnDemand", 1, (void *) b);
  return HANDLED(cmd);
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
  char *conf_timeout;
  config_rec *c;

  /* If ldap_server is NULL, ldap_open() will connect to localhost. */
  ldap_server = (char *)get_param_ptr(main_server->conf, "LDAPServer", FALSE);

  if ((c = find_config(CURRENT_CONF, CONF_PARAM, "LDAPDNInfo", FALSE)) != NULL) {
  	ldap_dn = pstrdup(session.pool, c->argv[0]);
  	ldap_dnpass = pstrdup(session.pool, c->argv[1]);
  }

  if (get_param_int(main_server->conf,"LDAPAuthBinds", FALSE) > 0)
    ldap_authbinds = 1;

  if (get_param_int(main_server->conf, "LDAPQueryTimeout", FALSE) > 0)
    ldap_querytimeout = 1;

  if ((c = find_config(CURRENT_CONF, CONF_PARAM, "LDAPDoAuth", FALSE)) != NULL) {
    if ( (int)c->argv[0] > 0) {
      ldap_doauth = 1;
      ldap_auth_prefix = pstrdup(session.pool, c->argv[1]);
    }
  }

  if ((c = find_config(CURRENT_CONF, CONF_PARAM, "LDAPDoUIDLookups", FALSE)) != NULL) {
    if ( (int)c->argv[0] > 0) {
      ldap_douid = 1;
      ldap_uid_prefix = pstrdup(session.pool, c->argv[1]);
    }
  }

  if ((c = find_config(CURRENT_CONF, CONF_PARAM, "LDAPDoGIDLookups", FALSE)) != NULL) {
    if ( (int)c->argv[0] > 0) {
      ldap_dogid = 1;
      ldap_gid_prefix = pstrdup(session.pool, c->argv[1]);
    }
  }

  ldap_defaultuid = get_param_int(main_server->conf, "LDAPDefaultUID", FALSE);
  ldap_defaultgid = get_param_int(main_server->conf, "LDAPDefaultGID", FALSE);

  if (get_param_int(main_server->conf,"LDAPNegativeCache",FALSE) > 0)
    ldap_negcache = 1;

  if (get_param_int(main_server->conf, "LDAPHomedirOnDemand", FALSE) > 0)
    ldap_homedirondemand = 1;

  /* If ldap_defaultauthscheme is NULL, ldap_check() will assume crypt. */
  ldap_defaultauthscheme = (char *)get_param_ptr(main_server->conf, "LDAPDefaultAuthScheme", FALSE);

/*  log_pri(LOG_ERR, "mod_ldap: ldap_getconf: doauth: %d, douser: %d, dogid: %d, authbase: %s, uidbase: %s, gidbase: %s, defaultuid: %d, defaultgid %d, querytimeout %d, homedirondemand: %d, defaultauthscheme: %s, authbinds: %d", ldap_doauth, ldap_douid, ldap_dogid, ldap_auth_prefix, ldap_uid_prefix, ldap_gid_prefix, ldap_defaultuid, ldap_defaultgid, ldap_querytimeout, ldap_homedirondemand, ldap_defaultauthscheme, ldap_authbinds);*/

  return 0;
}

static conftable ldap_config[] = {
  { "LDAPServer",            set_ldap_server,            NULL },
  { "LDAPDNInfo",            set_ldap_dninfo,            NULL },
  { "LDAPAuthBinds",         set_ldap_authbinds,         NULL },
  { "LDAPQueryTimeout",      set_ldap_querytimeout,      NULL },
  { "LDAPNegativeCache",     set_ldap_negcache,          NULL },
  { "LDAPDoAuth",            set_ldap_doauth,            NULL },
  { "LDAPDoUIDLookups",      set_ldap_douid,             NULL },
  { "LDAPDoGIDLookups",      set_ldap_dogid,             NULL },
  { "LDAPDefaultUID",        set_ldap_defaultuid,        NULL },
  { "LDAPDefaultGID",        set_ldap_defaultgid,        NULL },
  { "LDAPHomedirOnDemand",   set_ldap_homedirondemand,   NULL },
  { "LDAPDefaultAuthScheme", set_ldap_defaultauthscheme, NULL },
  { NULL,                    NULL,                       NULL }
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
