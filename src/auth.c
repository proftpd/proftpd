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
 *
 * As a special exemption, Public Flood Software/MacGyver aka Habeeb J. Dihu
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

/* Authentication front-end for ProFTPD
 * $Id: auth.c,v 1.12 2002-06-23 18:58:46 jwm Exp $
 */

#include "conf.h"

static cmd_rec *_make_cmd(pool *cp, int argc, ...)
{
  va_list args;
  cmd_rec *c;
  int     i;

  c = pcalloc(cp,sizeof(cmd_rec));

  c->argc = argc;
  c->symtable_index = -1;

  if(argc) {
    c->argv = pcalloc(cp,sizeof(void*)*argc);

    va_start(args,argc);

    for(i = 0; i < argc; i++)
      c->argv[i] = (void*)va_arg(args,char*);

    va_end(args);
  }

  return c;
}

static modret_t *_dispatch_auth(cmd_rec *cmd, char *match)
{
  authtable *m;
  modret_t *mr = NULL;

  m = mod_find_auth_symbol(match,&cmd->symtable_index,NULL);
  while(m) {
    log_debug(DEBUG6, "dispatching auth request \"%s\" to module mod_%s",
      match, m->m->name);
    mr = call_module_auth(m->m,m->handler,cmd);
    if(MODRET_ISHANDLED(mr) || MODRET_ISERROR(mr))
      break;

    m = mod_find_auth_symbol(match,&cmd->symtable_index,m);
  }
    
  return mr; 
}

void auth_setpwent(pool *p)
{
  cmd_rec *c;
  modret_t *mr;

  c = _make_cmd(p,0);
  mr = _dispatch_auth(c,"setpwent");

  if(c->tmp_pool) {
    destroy_pool(c->tmp_pool);
    c->tmp_pool = NULL;
  }
  return;  
}

void auth_endpwent(pool *p)
{
  cmd_rec *c;
  modret_t *mr;

  c = _make_cmd(p,0);
  mr = _dispatch_auth(c,"endpwent");

  if(c->tmp_pool) {
    destroy_pool(c->tmp_pool);
    c->tmp_pool = NULL;
  }
  return;  
}

void auth_setgrent(pool *p)
{
  cmd_rec *c;
  modret_t *mr;

  c = _make_cmd(p,0);
  mr = _dispatch_auth(c,"setgrent");

  if(c->tmp_pool) {
    destroy_pool(c->tmp_pool);
    c->tmp_pool = NULL;
  }
  return;  
}

void auth_endgrent(pool *p)
{
  cmd_rec *c;
  modret_t *mr;

  c = _make_cmd(p,0);
  mr = _dispatch_auth(c,"endgrent");

  if(c->tmp_pool) {
    destroy_pool(c->tmp_pool);
    c->tmp_pool = NULL;
  }
  return;  
}

struct passwd *auth_getpwent(pool *p)
{
  cmd_rec *c;
  modret_t *mr;
  struct passwd *ret = NULL;

  c = _make_cmd(p,0);
  mr = _dispatch_auth(c,"getpwent");

  if(MODRET_ISHANDLED(mr) && MODRET_HASDATA(mr))
    ret = mr->data;

  if(c->tmp_pool) {
    destroy_pool(c->tmp_pool);
    c->tmp_pool = NULL;
  }

  /* sanity check */
  if (ret == NULL)
    return NULL;

  /* make sure the UID and GID are not -1 */
  if (ret->pw_uid == (uid_t) -1) {
    log_pri(LOG_ERR, "error: UID of -1 not allowed");
    return NULL;
  }

  if (ret->pw_gid == (gid_t) -1) {
    log_pri(LOG_ERR, "error: GID of -1 not allowed");
    return NULL;
  }

  return ret;
}

struct group *auth_getgrent(pool *p)
{
  cmd_rec *c;
  modret_t *mr;
  struct group *ret = NULL;

  c = _make_cmd(p,0);
  mr = _dispatch_auth(c,"getgrent");

  if(MODRET_ISHANDLED(mr) && MODRET_HASDATA(mr))
    ret = mr->data;

  if(c->tmp_pool) {
    destroy_pool(c->tmp_pool);
    c->tmp_pool = NULL;
  }

  /* sanity check */
  if (ret == NULL)
    return NULL;

  /* make sure the GID is not -1 */
  if (ret->gr_gid == (gid_t) -1) {
    log_pri(LOG_ERR, "error: GID of -1 not allowed");
    return NULL;
  }

  return ret;
}

struct passwd *auth_getpwnam(pool *p, const char *name)
{
  cmd_rec *c;
  modret_t *mr;
  struct passwd *ret = NULL;

  c = _make_cmd(p,1,name);
  mr = _dispatch_auth(c,"getpwnam");

  if(MODRET_ISHANDLED(mr) && MODRET_HASDATA(mr))
    ret = mr->data;

  if(c->tmp_pool) {
    destroy_pool(c->tmp_pool);
    c->tmp_pool = NULL;
  }

  /* sanity check */
  if (ret == NULL) {
    log_pri(LOG_NOTICE, "no such user '%s'", name);
    return NULL;
  }

  /* make sure the UID and GID are not -1 */
  if (ret->pw_uid == (uid_t) -1) {
    log_pri(LOG_ERR, "error: UID of -1 not allowed");
    return NULL;
  }

  if (ret->pw_gid == (gid_t) -1) {
    log_pri(LOG_ERR, "error: GID of -1 not allowed");
    return NULL;
  }

  return ret;
}

struct passwd *auth_getpwuid(pool *p, uid_t uid)
{
  cmd_rec *c;
  modret_t *mr;
  struct passwd *ret = NULL;

  c = _make_cmd(p,1,(void*)uid);
  mr = _dispatch_auth(c,"getpwuid");

  if(MODRET_ISHANDLED(mr) && MODRET_HASDATA(mr))
    ret = mr->data;

  if(c->tmp_pool) {
    destroy_pool(c->tmp_pool);
    c->tmp_pool = NULL;
  }

  /* sanity check */
  if (ret == NULL) {
    log_pri(LOG_NOTICE, "no such UID '%lu'", (unsigned long)uid);
    return NULL;
  }

  /* make sure the UID and GID are not -1 */
  if (ret->pw_uid == (uid_t) -1) {
    log_pri(LOG_ERR, "error: UID of -1 not allowed");
    return NULL;
  }

  if (ret->pw_gid == (gid_t) -1) {
    log_pri(LOG_ERR, "error: GID of -1 not allowed");
    return NULL;
  }

  return ret;
}

struct group *auth_getgrnam(pool *p, const char *name)
{
  cmd_rec *c;
  modret_t *mr;
  struct group *ret = NULL;

  c = _make_cmd(p,1,name);
  mr = _dispatch_auth(c,"getgrnam");

  if(MODRET_ISHANDLED(mr) && MODRET_HASDATA(mr))
    ret = mr->data;

  if(c->tmp_pool) {
    destroy_pool(c->tmp_pool);
    c->tmp_pool = NULL;
  }

  /* sanity check */
  if (ret == NULL) {
    log_pri(LOG_NOTICE, "no such group '%s'", name);
    return NULL;
  }

  /* make sure the GID is not -1 */
  if (ret->gr_gid == (gid_t) -1) {
    log_pri(LOG_ERR, "error: GID of -1 not allowed");
    return NULL;
  }

  return ret;
}

struct group *auth_getgrgid(pool *p, gid_t gid)
{
  cmd_rec *c;
  modret_t *mr;
  struct group *ret = NULL;

  c = _make_cmd(p,1,(void*)gid);
  mr = _dispatch_auth(c,"getgrgid");

  if(MODRET_ISHANDLED(mr) && MODRET_HASDATA(mr))
    ret = mr->data;

  if(c->tmp_pool) {
    destroy_pool(c->tmp_pool);
    c->tmp_pool = NULL;
  }

  /* sanity check */
  if (ret == NULL) {
    log_pri(LOG_NOTICE, "no such GID '%lu'", (unsigned long)gid);
    return NULL;
  }

  /* make sure the GID is not -1 */
  if (ret->gr_gid == (gid_t) -1) {
    log_pri(LOG_ERR, "error: GID of -1 not allowed");
    return NULL;
  }

  return ret;
}

int auth_authenticate(pool *p, const char *name, const char *pw)
{
  cmd_rec *c;
  modret_t *mr;
  int ret = AUTH_NOPWD;

  c = _make_cmd(p,2,name,pw);
  mr = _dispatch_auth(c,"auth");

  if(MODRET_ISHANDLED(mr))
    ret = 0;
  else if(MODRET_ISERROR(mr))
    ret = MODRET_ERROR(mr);

  if(c->tmp_pool) {
    destroy_pool(c->tmp_pool);
    c->tmp_pool = NULL;
  }

  return ret;
}

int auth_check(pool *p, const char *cpw, const char *name, const char *pw)
{
  cmd_rec *c;
  modret_t *mr;
  int ret = AUTH_BADPWD;

  c = _make_cmd(p,3,cpw,name,pw);
  mr = _dispatch_auth(c,"check");

  if(MODRET_ISHANDLED(mr))
    ret = 0;

  if(c->tmp_pool) {
    destroy_pool(c->tmp_pool);
    c->tmp_pool = NULL;
  }

  return ret;
}

const char *auth_uid_name(pool *p, uid_t uid)
{
  cmd_rec *c;
  modret_t *mr;
  static char namebuf[64];
  char *ret = "ERROR";

  memset(namebuf,'\0',sizeof(namebuf));
  c = _make_cmd(p,1,(void*)uid);
  mr = _dispatch_auth(c,"uid_name");

  if(MODRET_ISHANDLED(mr) && MODRET_HASDATA(mr)) {
    ret = mr->data;
    sstrncpy(namebuf,ret,sizeof(namebuf));
    ret = namebuf;
  }

  if(c->tmp_pool) {
    destroy_pool(c->tmp_pool);
    c->tmp_pool = NULL;
  }

  return ret;
}

const char *auth_gid_name(pool *p, gid_t gid)
{
  cmd_rec *c;
  modret_t *mr;
  static char namebuf[64];
  char *ret = "ERROR";

  memset(namebuf,'\0',sizeof(namebuf));
  c = _make_cmd(p,1,(void*)gid);
  mr = _dispatch_auth(c,"gid_name");

  if(MODRET_ISHANDLED(mr) && MODRET_HASDATA(mr)) {
    ret = mr->data;
    sstrncpy(namebuf,ret,sizeof(namebuf));
    ret = namebuf;
  }

  if(c->tmp_pool) {
    destroy_pool(c->tmp_pool);
    c->tmp_pool = NULL;
  }

  return ret;
}

uid_t auth_name_uid(pool *p, const char *name)
{
  cmd_rec *c;
  modret_t *mr;
  uid_t ret = -1;

  c = _make_cmd(p,1,name);
  mr = _dispatch_auth(c,"name_uid");

  if (MODRET_ISHANDLED(mr))
    ret = (uid_t) mr->data;
  else
    errno = EINVAL;

  if(c->tmp_pool) {
    destroy_pool(c->tmp_pool);
    c->tmp_pool = NULL;
  }

  return ret;
}

gid_t auth_name_gid(pool *p, const char *name)
{
  cmd_rec *c;
  modret_t *mr;
  gid_t ret = -1;

  c = _make_cmd(p,1,name);
  mr = _dispatch_auth(c,"name_gid");

  if (MODRET_ISHANDLED(mr))
    ret = (gid_t) mr->data;
  else
    errno = EINVAL;

  if(c->tmp_pool) {
    destroy_pool(c->tmp_pool);
    c->tmp_pool = NULL;
  }

  return ret;
}

int auth_getgroups(pool *p, const char *name, array_header **group_ids,
               array_header **group_names) {

  cmd_rec *cmd = NULL;
  modret_t *mr = NULL;
  int res = -1;
  
  /* allocate memory for the array_headers of GIDs and group names
   */
    if (group_ids)
    *group_ids = make_array(permanent_pool, 2, sizeof(gid_t));
  
  if (group_names)
    *group_names = make_array(permanent_pool, 2, sizeof(char *));
  
  cmd = _make_cmd(p, 3, name, group_ids ? *group_ids : NULL,
    group_names ? *group_names : NULL);

  mr = _dispatch_auth(cmd, "getgroups");

  if (MODRET_ISHANDLED(mr) && MODRET_HASDATA(mr)) {
    res = (int) mr->data;

    /* NOTE: the number of groups returned should, barring error,
     * always be at least 1, as per getgroups(2) behavior.  This one
     * ID is present because it is the primary group membership set in
     * struct passwd, from /etc/passwd.  This will need to be documented
     * for the benefit of auth_getgroup() implementors.
     * -tj, 2001-10-12
         */
  }
 
  if (cmd->tmp_pool) {
    destroy_pool(cmd->tmp_pool);
    cmd->tmp_pool = NULL;
  }

  return res;
}

int set_groups(pool *p, gid_t primary_gid, array_header *suppl_gids) {
#ifndef HAVE_SETGROUPS
  return 0;
#else /* HAVE_SETGROUPS */
  gid_t *process_gids = NULL, *group_ids = NULL;
  size_t ngids = 0;
  int i = 0, res = 0;

  /* sanity check */
  if (!suppl_gids)
    return 0;

  ngids = suppl_gids->nelts;
  group_ids = suppl_gids->elts;
  process_gids = palloc(p, sizeof(gid_t) * (ngids + 1));

  /* From FreeBSD: /usr/src/lib/libc/gen/getgrouplist.c
   *
   * When installing primary group, duplicate it;
   * the first element of groups is the effective gid
   * and will be overwritten when a setgid file is executed.
   */
  process_gids[0] = primary_gid;

  for (i = 0; i < ngids; i++)
    process_gids[i + 1] = group_ids[i];

  /* set the supplemental groups...
   */
  if ((res = setgroups(ngids + 1, process_gids)) < 0)
    return res;

  /* ...and if that worked OK, set the primary GID of the process
   */
  if ((res = setgid(primary_gid)) < 0)
    return res;

  return res;
#endif /* HAVE_SETGROUPS */
}

