/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
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
 * ldap password lookup module for ProFTPD
 * $Id: mod_ldap.c,v 1.1 1999-10-10 10:01:02 macgyver Exp $
 */

#include "conf.h"

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

#include <lber.h>
#include <ldap.h>

#include "privs.h"

static const char *grpfname="/etc/group";

#ifdef HAVE__PW_STAYOPEN
extern int _pw_stayopen;
#endif

#define HASH_TABLE_SIZE		10

typedef struct _idmap {
  struct _idmap *next,*prev;

  unsigned short int negative;	/* have we gotten a negative answer before? */
  int id;						/* uid or gid */
  char *name;					/* user or group name */
} idmap_t;

static xaset_t *uid_table[HASH_TABLE_SIZE];
static xaset_t *gid_table[HASH_TABLE_SIZE];

static FILE *grpf = NULL;

#ifdef NEED_PERSISTENT_PASSWD
static int persistent = 1;
#else
static int persistent = 0;
#endif

static int persistent_group = 0;

#define PERSISTENT_GROUP	(persistent || persistent_group)

#undef GROUP
#define	GROUP		grpfname

/* Config entries */
char *ldap_server, *ldap_prefix, *ldap_dn, *ldap_dnpass;
int ldap_negcache;

static LDAP *ld;
static char *name_attrs[] = {"userPassword", "uidNumber", "gidNumber", "homeDirectory", "loginShell", NULL};
static char *uid_attrs[] = {"uid", "userPassword", "gidNumber", "homeDirectory", "loginShell", NULL};
static char *pass_attrs[] = {"userPassword", NULL};

static void p_setpwent()
{
  /* FUTURE: secondary ldap server? */

  if ((ld = ldap_open(ldap_server, LDAP_PORT)) == NULL) {
    log_pri(LOG_ERR, "ldap_auth: p_setpwent(): ldap_open() to %s failed", ldap_server);
    return;
  }
  if (ldap_simple_bind(ld, ldap_dn, ldap_dnpass) == -1) {
    log_pri(LOG_ERR, "ldap_auth: p_setpwent(): ldap_simple_bind() as %s failed", ldap_dn);
    return;
  }
}

static void p_endpwent()
{
  if (ld != NULL)
    if (ldap_unbind(ld) == -1)
      log_pri(LOG_NOTICE, "ldap_auth: p_endpwent(): ldap_unbind() failed");
}

static void p_setgrent()
{
  if(grpf)
    rewind(grpf);
  else
    grpf = fopen(GROUP,"r");
}

static void p_endgrent()
{   
  if(grpf) {
    fclose(grpf);
    grpf = NULL;
  }
}

static struct group *p_getgrent()
{   
  struct group *gr;
   
  if(!grpf)
    p_setgrent();

  if(!grpf)
    return NULL;

  gr = fgetgrent(grpf);  
 
  return gr;
}

static struct passwd *p_getpwnam(cmd_rec *cmd, const char *name)
{  
  struct passwd *pw;
  BerElement *ber;
  LDAPMessage *result, *e;
  char *filter, **values;
  unsigned short int i;

  pw = palloc(session.pool, sizeof(struct passwd));
  pw->pw_name = pstrdup(session.pool, name);

  /* If the LDAP connection has gone away or hasn't been established
     yet, attempt to establish it now. */
  if (ld == NULL)
	p_setpwent();

  /* If we _still_ can't connect, give up and return NULL. */
  if (ld == NULL)
    return NULL;

  ldap_ufn_setprefix(ld, ldap_prefix);
  filter = pstrcat(cmd->tmp_pool, "uid=", name, NULL);

  if (ldap_ufn_search_s(ld, filter, name_attrs, 0, &result) == -1) {
    log_pri(LOG_ERR, "ldap_auth: p_getpwnam(): ldap_ufn_search_s() failed");
    return NULL;
  }

  if ((e = ldap_first_entry(ld, result)) == NULL) {
    ldap_msgfree(result);
    return NULL; /* No LDAP entries for this user */
  }

  for (i = 0; i <= sizeof(name_attrs) / sizeof(*name_attrs) - 2; ++i) {
    if ((values = ldap_get_values(ld, e, name_attrs[i])) == NULL) {
      ldap_msgfree(result);
      log_pri(LOG_ERR, "ldap_auth: p_getpwnam(): ldap_get_values() failed for attr %s", name_attrs[i]);
      return NULL;
    }

    if (strcasecmp(name_attrs[i], "userPassword") == 0)
      pw->pw_passwd = pstrdup(session.pool, values[0]);
    else if (strcasecmp(name_attrs[i], "uidNumber") == 0)
      pw->pw_uid = (uid_t) atoi(values[0]);
    else if (strcasecmp(name_attrs[i], "gidNumber") == 0)
      pw->pw_gid = (gid_t) atoi(values[0]);
    else if (strcasecmp(name_attrs[i], "homeDirectory") == 0)
      pw->pw_dir = pstrdup(session.pool, values[0]);
    else if (strcasecmp(name_attrs[i], "loginShell") == 0)
      pw->pw_shell = pstrdup(session.pool, values[0]);
    else
      log_pri(LOG_WARNING, "ldap_auth: p_getpwnam(): ldap_get_values() loop found unknown attr %s", name_attrs[i]);

    ldap_value_free(values);
  }

  ldap_msgfree(result);

  return pw;
}

static struct passwd *p_getpwuid(cmd_rec *cmd, uid_t uid)
{   
  struct passwd *pw;

  BerElement *ber;
  LDAPMessage *result, *e;
  char *filter, **values, uidstr[BUFSIZ]; 
  unsigned short int i;

  pw = palloc(session.pool, sizeof(struct passwd));
  pw->pw_uid = uid;

  p_setpwent();

  /* If the LDAP connection has gone away, attempt to reestablish it. */
  if (ld == NULL)
	p_setpwent();

  /* If we _still_ can't connect, give up and return NULL. */
  if (ld == NULL)
    return NULL;

  ldap_ufn_setprefix(ld, ldap_prefix);

  snprintf(uidstr, sizeof(uidstr), "%d", uid);
  filter = pstrcat(session.pool, "uidNumber=", uidstr, NULL);

  if (ldap_ufn_search_s(ld, filter, uid_attrs, 0, &result) == -1) {
    log_pri(LOG_ERR, "ldap_auth: p_getpwuid(): ldap_ufn_search_s() failed");
    return NULL;
  }

  if ((e = ldap_first_entry(ld, result)) == NULL) {
    ldap_msgfree(result);
    return NULL; /* No LDAP entries found for this user. */
  }

  for (i = 0; i <= sizeof(uid_attrs) / sizeof(*uid_attrs) - 2; ++i) {
    if ((values = ldap_get_values(ld, e, uid_attrs[i])) == NULL) {
      ldap_msgfree(result);
      log_pri(LOG_ERR, "ldap_auth: p_getpwuid(): ldap_get_values() failed for attr %s", uid_attrs[i]);
      return NULL;
    }

    if (strcasecmp(uid_attrs[i], "userPassword") == 0)
      pw->pw_passwd = pstrdup(session.pool, values[0]);
    else if (strcasecmp(uid_attrs[i], "uid") == 0)
      pw->pw_uid = (uid_t) atoi(values[0]);
    else if (strcasecmp(uid_attrs[i], "gid") == 0)
      pw->pw_gid = (gid_t) atoi(values[0]);
    else if (strcasecmp(uid_attrs[i], "homeDir") == 0)
      pw->pw_dir = pstrdup(session.pool, values[0]);
    else if (strcasecmp(uid_attrs[i], "shell") == 0)
      pw->pw_shell = pstrdup(session.pool, values[0]);
    else
      log_pri(LOG_WARNING, "ldap_auth: p_getpwuid(): ldap_get_values() loop found unknown attr %s", uid_attrs[i]);

    ldap_value_free(values);
  }

  ldap_msgfree(result);

  return pw;
}

static struct group *p_getgrnam(const char *name)
{ 
  struct group *gr;

  p_setgrent();
  while((gr = p_getgrent()) != NULL)
    if(!strcmp(name,gr->gr_name))
      break;
 
  return gr;
}

static struct group *p_getgrgid(gid_t gid)
{ 
  struct group *gr;

  p_setgrent();
  while((gr = p_getgrent()) != NULL)
    if(gr->gr_gid == gid)
      break;
 
  return gr;
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

MODRET pw_setpwent(cmd_rec *cmd)
{
  p_setpwent();
  return HANDLED(cmd);
}

MODRET pw_endpwent(cmd_rec *cmd)
{
  p_endpwent();
  return HANDLED(cmd);
}

MODRET pw_setgrent(cmd_rec *cmd)
{
  if(PERSISTENT_GROUP)
    p_setgrent();
  else
    setgrent();

  return HANDLED(cmd);
}

MODRET pw_endgrent(cmd_rec *cmd)
{
  if(PERSISTENT_GROUP)
    p_endgrent();
  else
    endgrent();

  return HANDLED(cmd);
}

MODRET pw_getgrent(cmd_rec *cmd)
{
  struct group *gr;

  if(PERSISTENT_GROUP)
    gr = p_getgrent();
  else
    gr = getgrent();

  if(gr)
    return mod_create_data(cmd,gr);
  else
    return DECLINED(cmd);
}

MODRET pw_getpwuid(cmd_rec *cmd)
{
  struct passwd *pw;
  uid_t uid;

  uid = (uid_t)cmd->argv[0];
  pw = p_getpwuid(cmd,uid);

  if(pw)
    return mod_create_data(cmd,pw);
  else
    return DECLINED(cmd);
}

MODRET pw_getpwnam(cmd_rec *cmd)
{
  struct passwd *pw;
  const char *name;

  name = cmd->argv[0];
  pw = p_getpwnam(cmd,name);

  if(pw)
    return mod_create_data(cmd,pw);
  else
    return DECLINED(cmd);
}

MODRET pw_getgrnam(cmd_rec *cmd)
{
  struct group *gr;
  const char *name;

  name = cmd->argv[0];
  if(PERSISTENT_GROUP)
    gr = p_getgrnam(name);
  else
    gr = getgrnam(name);

  if(gr)
    return mod_create_data(cmd,gr);
  else
    return DECLINED(cmd);
}

MODRET pw_getgrgid(cmd_rec *cmd)
{
  struct group *gr;
  gid_t gid;

  gid = (gid_t)cmd->argv[0];
  if(PERSISTENT_GROUP)
    gr = p_getgrgid(gid);
  else
    gr = getgrgid(gid);

  if(gr)
    return mod_create_data(cmd,gr);
  else
    return DECLINED(cmd);
}

/* high-level auth handlers
 */

/* cmd->argv[0] : user name
 * cmd->argv[1] : cleartext password
 */

MODRET pw_auth(cmd_rec *cmd)
{
  time_t now;
  char *cpw;
  time_t lstchg = -1,max = -1,inact = -1,disable = -11;
  const char *name;

  BerElement *ber;
  LDAPMessage *result, *e;
  char *filter, **values;

  name = cmd->argv[0];
  time(&now);


  /* If the LDAP connection has gone away, attempt to reestablish it. */
  if (ld == NULL)
	p_setpwent();

  /* If we _still_ can't connect, give up and return NULL. */
  if (ld == NULL)
    return NULL;

  ldap_ufn_setprefix(ld, ldap_prefix);
  filter = pstrcat(cmd->tmp_pool, "uid=", name, NULL);

  if (ldap_ufn_search_s(ld, filter, pass_attrs, 0, &result) == -1) {
    log_pri(LOG_ERR, "ldap_auth: pw_auth(): ldap_ufn_search_s() failed");
    return NULL;
  }

  if ((e = ldap_first_entry(ld, result)) == NULL) {
    ldap_msgfree(result);
    return NULL; /* No LDAP entries found for this user. */
  }

  if ((values = ldap_get_values(ld, e, "userPassword")) == NULL) {
    ldap_msgfree(result);
    log_pri(LOG_ERR, "ldap_auth: pw_auth(): ldap_get_values() failed");
    return NULL;
  }

  cpw = pstrdup(cmd->tmp_pool, values[0]);
  ldap_value_free(values);
  ldap_msgfree(result);


  if(!cpw)
    return ERROR_INT(cmd,AUTH_NOPWD);

  if(auth_check(cmd->tmp_pool,cpw,cmd->argv[0],cmd->argv[1]))
    return ERROR_INT(cmd,AUTH_BADPWD);

  if(lstchg > (time_t)0 && max > (time_t)0 &&
     inact > (time_t)0)
    if(now > lstchg + max + inact)
      return ERROR_INT(cmd,AUTH_AGEPWD);

  if(disable > (time_t)0 && now > disable)
    return ERROR_INT(cmd,AUTH_DISABLEDPWD);

  return HANDLED(cmd);
}

/*
 * cmd->argv[0] = hashed password,
 * cmd->argv[1] = user,
 * cmd->argv[2] = cleartext
 */

MODRET pw_check(cmd_rec *cmd)
{
  static char *pw,*cpw;
  int encname_len;

  cpw = cmd->argv[0];
  pw = cmd->argv[2];

  /* Check to see how the password is encrypted. */

  encname_len = strcspn(cpw + 1, "}");
  if (strncmp(cpw + 1, "crypt", encname_len) == 0) { /* It's crypt()ed */
    if(strcmp(crypt(pw,cpw + encname_len + 2),cpw + encname_len + 2) != 0)
      return DECLINED(cmd);
  }
  else {
    log_pri(LOG_ERR, "ldap_auth: pw_check(): can't determine encryption scheme from '%s'", cpw);
    return DECLINED(cmd);
  }

  return HANDLED(cmd);
}

MODRET pw_uid_name(cmd_rec *cmd)
{
  idmap_t *m;
  struct passwd *pw;
  uid_t uid;

  uid = (uid_t)cmd->argv[0];
  m = _auth_lookup_id(uid_table,uid);

  if(!m->name) {
    if (ldap_negcache) /* If we're doing negative caching as per config... */
      if (m->negative) /* It wasn't in the LDAP db before, don't look again. */
        return DECLINED(cmd);

    /* wasn't cached and we've haven't seen this one, so perform a lookup */
    pw = p_getpwuid(cmd,uid);

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

MODRET pw_gid_name(cmd_rec *cmd)
{
  idmap_t *m;
  struct group *gr;
  gid_t gid;

  gid = (gid_t)cmd->argv[0];

  m = _auth_lookup_id(gid_table,gid);

  if(!m->name) {
    if(PERSISTENT_GROUP)
      gr = p_getgrgid(gid);
    else
      gr = getgrgid(gid);

    if(gr)
      m->name = pstrdup(permanent_pool,gr->gr_name);
    else {
      char buf[10];

      snprintf(buf, sizeof(buf), "%lu",(ULONG)gid);
      m->name = pstrdup(permanent_pool,buf);
    }
  }

  return mod_create_data(cmd,m->name);
}

MODRET pw_name_uid(cmd_rec *cmd)
{
  struct passwd *pw;
  const char *name;

  name = cmd->argv[0];

  pw = p_getpwnam(cmd,name);

  if(pw)
    return mod_create_data(cmd,(void*)pw->pw_uid);
  return DECLINED(cmd);
}

MODRET pw_name_gid(cmd_rec *cmd)
{
  struct group *gr;

  const char *name;

  name = cmd->argv[0];

  if(PERSISTENT_GROUP)
    gr = p_getgrnam(name);
  else
    gr = getgrnam(name);

  if(gr)
    return mod_create_data(cmd,(void*)gr->gr_gid);
  return DECLINED(cmd);
}

MODRET set_persistentpasswd(cmd_rec *cmd)
{
  int b;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT);

  b = get_boolean(cmd,1);
  if(b != -1)
    persistent = b;

  return HANDLED(cmd);
}

MODRET set_authuserfile(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str("AuthUserFile",1,cmd->argv[1]);
  return HANDLED(cmd);
}

MODRET set_authgroupfile(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str("AuthGroupFile",1,cmd->argv[1]);
  return HANDLED(cmd);
}

static int ldappw_init()
{
  memset(uid_table,0,sizeof(uid_table));
  memset(gid_table,0,sizeof(gid_table));

#ifdef HAVE__PW_STAYOPEN
  _pw_stayopen = 1;
#endif

  return 0;
}

MODRET set_ldapserver(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str("LDAPServer",1,cmd->argv[1]);
  return HANDLED(cmd);
}

MODRET set_ldapprefix(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str("LDAPPrefix",1,cmd->argv[1]);
  return HANDLED(cmd);
}

MODRET set_ldapdn(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str("LDAPDN",1,cmd->argv[1]);
  return HANDLED(cmd);
}

MODRET set_ldapdnpass(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str("LDAPDNPass",1,cmd->argv[1]);
  return HANDLED(cmd);
}

MODRET set_ldapnegcache(cmd_rec *cmd)
{
  int b;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((b = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "LDAPNegativeCache: expected boolean argument.");

  add_config_param("LDAPNegativeCache", 1, (void *) b);
  return HANDLED(cmd);
}

static int ldap_child()
{
  const char *file;

  file = (const char*)get_param_ptr(main_server->conf,"AuthGroupFile",FALSE);
  if(file) {
    endgrent();
    persistent_group = 1;
    grpfname = file;
    p_endgrent();
    p_setgrent();
  }

  /* If ldap_server is NULL, ldap_open() will connect to localhost. */
  ldap_server = (char*)get_param_ptr(main_server->conf,"LDAPServer",FALSE);

  ldap_prefix = (char*)get_param_ptr(main_server->conf,"LDAPPrefix",FALSE);
  ldap_dn = (char*)get_param_ptr(main_server->conf,"LDAPDN",FALSE);
  ldap_dnpass = (char*)get_param_ptr(main_server->conf,"LDAPDNPass",FALSE);

  ldap_negcache = get_param_int(main_server->conf,"LDAPNegativeCache",FALSE);
  if (ldap_negcache == -1)
    ldap_negcache = 0; /* Don't do negative caching by default. */

  return 0;
}

static conftable ldap_config[] = {
  { "PersistentPasswd",		set_persistentpasswd,	NULL },
  { "AuthGroupFile",		set_authgroupfile,		NULL },
  { "LDAPServer",           set_ldapserver,         NULL },
  { "LDAPPrefix",           set_ldapprefix,         NULL },
  { "LDAPDN",               set_ldapdn,             NULL },
  { "LDAPDNPass",           set_ldapdnpass,         NULL },
  { "LDAPNegativeCache",    set_ldapnegcache,       NULL },
  { NULL,					NULL,					NULL }
};

static authtable ldap_auth[] = {
  { 0,  "setpwent",	pw_setpwent	},
  { 0,  "endpwent",	pw_endpwent	},
  { 0,  "setgrent", pw_setgrent	},
  { 0,  "endgrent",	pw_endgrent	},
  { 0,  "getgrent",	pw_getgrent	},
  { 0,  "getpwnam",	pw_getpwnam	},
  { 0,	"getpwuid",	pw_getpwuid	},
  { 0,  "getgrnam", pw_getgrnam },
  { 0,  "getgrgid", pw_getgrgid },
  { 0,  "auth",     pw_auth		},
  { 0,  "check",	pw_check	},
  { 0,  "uid_name",	pw_uid_name	},
  { 0,  "gid_name",	pw_gid_name	},
  { 0,  "name_uid",	pw_name_uid	},
  { 0,  "name_gid",	pw_name_gid	},
  { 0,  NULL }
};

module ldap_module = {
  NULL,NULL,				/* Always NULL */
  0x20,						/* API Version 2.0 */
  "ldap",
  ldap_config,				/* Configuration directive table */
  NULL,						/* No command handlers */
  ldap_auth,				/* Authentication handlers */
  ldappw_init,ldap_child	/* Initialization functions */
};
