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

/* Authentication front-end for ProFTPD
 * $Id: auth.c,v 1.3 2000-07-07 00:26:24 macgyver Exp $
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

  if(MODRET_ISHANDLED(mr) && MODRET_HASDATA(mr))
    ret = (uid_t)mr->data;

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

  if(MODRET_ISHANDLED(mr) && MODRET_HASDATA(mr))
    ret = (gid_t)mr->data;

  if(c->tmp_pool) {
    destroy_pool(c->tmp_pool);
    c->tmp_pool = NULL;
  }

  return ret;
}
