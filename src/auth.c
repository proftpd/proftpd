/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001, 2002, 2003 The ProFTPD Project team
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
 * $Id: auth.c,v 1.29 2003-04-23 06:53:23 castaglia Exp $
 */

#include "conf.h"

static cmd_rec *make_cmd(pool *cp, int argc, ...) {
  va_list args;
  cmd_rec *c;
  int     i;

  c = pcalloc(cp, sizeof(cmd_rec));

  c->argc = argc;
  c->stash_index = -1;

  if (argc) {
    c->argv = pcalloc(cp, sizeof(void *) * argc);

    va_start(args, argc);

    for (i = 0; i < argc; i++)
      c->argv[i] = (void *) va_arg(args, char *);

    va_end(args);
  }

  return c;
}

static modret_t *dispatch_auth(cmd_rec *cmd, char *match) {
  authtable *authtab = NULL;
  modret_t *mr = NULL;

  authtab = pr_stash_get_symbol(PR_SYM_AUTH, match, NULL,
    &cmd->stash_index);

  while (authtab) {
    log_debug(DEBUG6, "dispatching auth request \"%s\" to module mod_%s",
      match, authtab->m->name);

    mr = call_module_auth(authtab->m, authtab->handler, cmd);

    if (MODRET_ISHANDLED(mr) || MODRET_ISERROR(mr))
      break;

    authtab = pr_stash_get_symbol(PR_SYM_AUTH, match, authtab,
      &cmd->stash_index);
  }

  return mr;
}

void auth_setpwent(pool *p) {
  cmd_rec *cmd = NULL;
  modret_t *mr = NULL;

  cmd = make_cmd(p, 0);
  mr = dispatch_auth(cmd, "setpwent");

  if (cmd->tmp_pool) {
    destroy_pool(cmd->tmp_pool);
    cmd->tmp_pool = NULL;
  }

  return;
}

void auth_endpwent(pool *p) {
  cmd_rec *cmd = NULL;
  modret_t *mr = NULL;

  cmd = make_cmd(p, 0);
  mr = dispatch_auth(cmd, "endpwent");

  if (cmd->tmp_pool) {
    destroy_pool(cmd->tmp_pool);
    cmd->tmp_pool = NULL;
  }

  return;
}

void auth_setgrent(pool *p) {
  cmd_rec *cmd = NULL;
  modret_t *mr = NULL;

  cmd = make_cmd(p, 0);
  mr = dispatch_auth(cmd, "setgrent");

  if (cmd->tmp_pool) {
    destroy_pool(cmd->tmp_pool);
    cmd->tmp_pool = NULL;
  }

  return;
}

void auth_endgrent(pool *p) {
  cmd_rec *cmd = NULL;
  modret_t *mr = NULL;

  cmd = make_cmd(p, 0);
  mr = dispatch_auth(cmd, "endgrent");

  if (cmd->tmp_pool) {
    destroy_pool(cmd->tmp_pool);
    cmd->tmp_pool = NULL;
  }

  return;
}

struct passwd *auth_getpwent(pool *p) {
  cmd_rec *cmd = NULL;
  modret_t *mr = NULL;
  struct passwd *res = NULL;

  cmd = make_cmd(p, 0);
  mr = dispatch_auth(cmd, "getpwent");

  if (MODRET_ISHANDLED(mr) && MODRET_HASDATA(mr))
    res = mr->data;

  if (cmd->tmp_pool) {
    destroy_pool(cmd->tmp_pool);
    cmd->tmp_pool = NULL;
  }

  /* Sanity check */
  if (res == NULL)
    return NULL;

  /* Make sure the UID and GID are not -1 */
  if (res->pw_uid == (uid_t) -1) {
    log_pri(PR_LOG_ERR, "error: UID of -1 not allowed");
    return NULL;
  }

  if (res->pw_gid == (gid_t) -1) {
    log_pri(PR_LOG_ERR, "error: GID of -1 not allowed");
    return NULL;
  }

  return res;
}

struct group *auth_getgrent(pool *p) {
  cmd_rec *cmd = NULL;
  modret_t *mr = NULL;
  struct group *res = NULL;

  cmd = make_cmd(p, 0);
  mr = dispatch_auth(cmd, "getgrent");

  if (MODRET_ISHANDLED(mr) && MODRET_HASDATA(mr))
    res = mr->data;

  if (cmd->tmp_pool) {
    destroy_pool(cmd->tmp_pool);
    cmd->tmp_pool = NULL;
  }

  /* Sanity check */
  if (res == NULL)
    return NULL;

  /* Make sure the GID is not -1 */
  if (res->gr_gid == (gid_t) -1) {
    log_pri(PR_LOG_ERR, "error: GID of -1 not allowed");
    return NULL;
  }

  return res;
}

struct passwd *auth_getpwnam(pool *p, const char *name) {
  cmd_rec *cmd = NULL;
  modret_t *mr = NULL;
  struct passwd *res = NULL;

  cmd = make_cmd(p, 1, name);
  mr = dispatch_auth(cmd, "getpwnam");

  if (MODRET_ISHANDLED(mr) && MODRET_HASDATA(mr))
    res = mr->data;

  if (cmd->tmp_pool) {
    destroy_pool(cmd->tmp_pool);
    cmd->tmp_pool = NULL;
  }

  /* Sanity check */
  if (res == NULL) {
    log_pri(PR_LOG_NOTICE, "no such user '%s'", name);
    return NULL;
  }

  /* Make sure the UID and GID are not -1 */
  if (res->pw_uid == (uid_t) -1) {
    log_pri(PR_LOG_ERR, "error: UID of -1 not allowed");
    return NULL;
  }

  if (res->pw_gid == (gid_t) -1) {
    log_pri(PR_LOG_ERR, "error: GID of -1 not allowed");
    return NULL;
  }

  return res;
}

struct passwd *auth_getpwuid(pool *p, uid_t uid) {
  cmd_rec *cmd = NULL;
  modret_t *mr = NULL;
  struct passwd *res = NULL;

  cmd = make_cmd(p, 1, (void *) uid);
  mr = dispatch_auth(cmd, "getpwuid");

  if (MODRET_ISHANDLED(mr) && MODRET_HASDATA(mr))
    res = mr->data;

  if (cmd->tmp_pool) {
    destroy_pool(cmd->tmp_pool);
    cmd->tmp_pool = NULL;
  }

  /* Sanity check */
  if (res == NULL) {
    log_pri(PR_LOG_NOTICE, "no such UID '%lu'", (unsigned long)uid);
    return NULL;
  }

  /* Make sure the UID and GID are not -1 */
  if (res->pw_uid == (uid_t) -1) {
    log_pri(PR_LOG_ERR, "error: UID of -1 not allowed");
    return NULL;
  }

  if (res->pw_gid == (gid_t) -1) {
    log_pri(PR_LOG_ERR, "error: GID of -1 not allowed");
    return NULL;
  }

  return res;
}

struct group *auth_getgrnam(pool *p, const char *name) {
  cmd_rec *cmd = NULL;
  modret_t *mr = NULL;
  struct group *res = NULL;

  cmd = make_cmd(p, 1, name);
  mr = dispatch_auth(cmd, "getgrnam");

  if (MODRET_ISHANDLED(mr) && MODRET_HASDATA(mr))
    res = mr->data;

  if (cmd->tmp_pool) {
    destroy_pool(cmd->tmp_pool);
    cmd->tmp_pool = NULL;
  }

  /* Sanity check */
  if (res == NULL) {
    log_pri(PR_LOG_NOTICE, "no such group '%s'", name);
    return NULL;
  }

  /* Make sure the GID is not -1 */
  if (res->gr_gid == (gid_t) -1) {
    log_pri(PR_LOG_ERR, "error: GID of -1 not allowed");
    return NULL;
  }

  return res;
}

struct group *auth_getgrgid(pool *p, gid_t gid) {
  cmd_rec *cmd = NULL;
  modret_t *mr = NULL;
  struct group *res = NULL;

  cmd = make_cmd(p, 1, (void *) gid);
  mr = dispatch_auth(cmd, "getgrgid");

  if (MODRET_ISHANDLED(mr) && MODRET_HASDATA(mr))
    res = mr->data;

  if (cmd->tmp_pool) {
    destroy_pool(cmd->tmp_pool);
    cmd->tmp_pool = NULL;
  }

  /* Sanity check */
  if (res == NULL) {
    log_pri(PR_LOG_NOTICE, "no such GID '%lu'", (unsigned long)gid);
    return NULL;
  }

  /* Make sure the GID is not -1 */
  if (res->gr_gid == (gid_t) -1) {
    log_pri(PR_LOG_ERR, "error: GID of -1 not allowed");
    return NULL;
  }

  return res;
}

int auth_authenticate(pool *p, const char *name, const char *pw) {
  cmd_rec *cmd = NULL;
  modret_t *mr = NULL;
  int res = PR_AUTH_NOPWD;

  cmd = make_cmd(p, 2, name, pw);
  mr = dispatch_auth(cmd, "auth");

  if (MODRET_ISHANDLED(mr))
    res = MODRET_HASDATA(mr) ? PR_AUTH_RFC2228_OK : PR_AUTH_OK;

  else if (MODRET_ISERROR(mr))
    res = MODRET_ERROR(mr);

  if (cmd->tmp_pool) {
    destroy_pool(cmd->tmp_pool);
    cmd->tmp_pool = NULL;
  }

  return res;
}

int auth_check(pool *p, const char *cpw, const char *name, const char *pw) {
  cmd_rec *cmd = NULL;
  modret_t *mr = NULL;
  int res = PR_AUTH_BADPWD;

  cmd = make_cmd(p, 3, cpw, name, pw);
  mr = dispatch_auth(cmd, "check");

  if (MODRET_ISHANDLED(mr))
    res = MODRET_HASDATA(mr) ? PR_AUTH_RFC2228_OK : PR_AUTH_OK;

  if (cmd->tmp_pool) {
    destroy_pool(cmd->tmp_pool);
    cmd->tmp_pool = NULL;
  }

  return res;
}

const char *auth_uid_name(pool *p, uid_t uid) {
  cmd_rec *cmd = NULL;
  modret_t *mr = NULL;
  static char namebuf[64];
  char *res = "(?)";

  memset(namebuf, '\0', sizeof(namebuf));

  cmd = make_cmd(p, 1, (void *) uid);
  mr = dispatch_auth(cmd, "uid_name");

  if (MODRET_ISHANDLED(mr) && MODRET_HASDATA(mr)) {
    res = mr->data;
    sstrncpy(namebuf, res, sizeof(namebuf));
    res = namebuf;
  }

  if (cmd->tmp_pool) {
    destroy_pool(cmd->tmp_pool);
    cmd->tmp_pool = NULL;
  }

  return res;
}

const char *auth_gid_name(pool *p, gid_t gid) {
  cmd_rec *cmd = NULL;
  modret_t *mr = NULL;
  static char namebuf[64];
  char *res = "(?)";

  memset(namebuf, '\0', sizeof(namebuf));

  cmd = make_cmd(p, 1, (void *) gid);
  mr = dispatch_auth(cmd, "gid_name");

  if (MODRET_ISHANDLED(mr) && MODRET_HASDATA(mr)) {
    res = mr->data;
    sstrncpy(namebuf, res, sizeof(namebuf));
    res = namebuf;
  }

  if (cmd->tmp_pool) {
    destroy_pool(cmd->tmp_pool);
    cmd->tmp_pool = NULL;
  }

  return res;
}

uid_t auth_name_uid(pool *p, const char *name) {
  cmd_rec *cmd = NULL;
  modret_t *mr = NULL;
  uid_t res = -1;

  cmd = make_cmd(p, 1, name);
  mr = dispatch_auth(cmd, "name_uid");

  if (MODRET_ISHANDLED(mr))
    res = (uid_t) mr->data;
  else
    errno = EINVAL;

  if (cmd->tmp_pool) {
    destroy_pool(cmd->tmp_pool);
    cmd->tmp_pool = NULL;
  }

  return res;
}

gid_t auth_name_gid(pool *p, const char *name) {
  cmd_rec *cmd = NULL;
  modret_t *mr = NULL;
  gid_t res = -1;

  cmd = make_cmd(p, 1, name);
  mr = dispatch_auth(cmd, "name_gid");

  if (MODRET_ISHANDLED(mr))
    res = (gid_t) mr->data;
  else
    errno = EINVAL;

  if (cmd->tmp_pool) {
    destroy_pool(cmd->tmp_pool);
    cmd->tmp_pool = NULL;
  }

  return res;
}

int auth_getgroups(pool *p, const char *name, array_header **group_ids,
               array_header **group_names) {

  cmd_rec *cmd = NULL;
  modret_t *mr = NULL;
  int res = -1;

  /* Allocate memory for the array_headers of GIDs and group names. */
  if (group_ids)
    *group_ids = make_array(permanent_pool, 2, sizeof(gid_t));

  if (group_names)
    *group_names = make_array(permanent_pool, 2, sizeof(char *));

  cmd = make_cmd(p, 3, name, group_ids ? *group_ids : NULL,
    group_names ? *group_names : NULL);

  mr = dispatch_auth(cmd, "getgroups");

  if (MODRET_ISHANDLED(mr) && MODRET_HASDATA(mr)) {
    res = (int) mr->data;

    /* Note: the number of groups returned should, barring error,
     * always be at least 1, as per getgroups(2) behavior.  This one
     * ID is present because it is the primary group membership set in
     * struct passwd, from /etc/passwd.  This will need to be documented
     * for the benefit of auth_getgroup() implementors.
     */
  }

  if (cmd->tmp_pool) {
    destroy_pool(cmd->tmp_pool);
    cmd->tmp_pool = NULL;
  }

  return res;
}

int set_groups(pool *p, gid_t primary_gid, array_header *suppl_gids) {
  int res = 0;
  pool *tmp_pool = NULL;

#ifdef HAVE_SETGROUPS
  register unsigned int i = 0;
  gid_t *gids = NULL, *proc_gids = NULL;
  size_t ngids = 0, nproc_gids = 0;

  /* sanity check */
  if (!p || !suppl_gids)
    return 0;

  tmp_pool = make_sub_pool(p);

  /* Check for a NULL supplemental group ID list. */
  if (suppl_gids) {
    ngids = suppl_gids->nelts;
    gids = suppl_gids->elts;

    if (ngids && gids) {
      proc_gids = pcalloc(tmp_pool, sizeof(gid_t) * (ngids));

      /* Note: the list of supplemental GIDs may contain duplicates.  Sort
       * through the list and keep only the unique IDs - this should help avoid
       * running into the NGROUPS limit when possible.  This algorithm may slow
       * things down some; optimize it if/when possible.
       */
      proc_gids[nproc_gids++] = gids[0];
    }
  }

  for (i = 1; i < ngids; i++) {
    register unsigned int j = 0;
    unsigned char skip_gid = FALSE;

    /* This duplicate ID search only needs to be done after the first GID
     * in the given list is examined, as the first GID cannot be a duplicate.
     */
    for (j = 0; j < nproc_gids; j++) {
      if (proc_gids[j] == gids[i]) {
        skip_gid = TRUE;
        break;
      }
    }

    if (!skip_gid)
      proc_gids[nproc_gids++] = gids[i];
  }

  /* Set the supplemental groups. */
  if ((res = setgroups(nproc_gids, proc_gids)) < 0) {
    destroy_pool(tmp_pool);
    return res;
  }
#endif /* !HAVE_SETGROUPS */

#ifndef PR_DEVEL_COREDUMP
  /* Set the primary GID of the process.
   */
  if ((res = setgid(primary_gid)) < 0) {
    if (tmp_pool)
      destroy_pool(tmp_pool);
    return res;
  }
#endif /* PR_DEVEL_COREDUMP */

  if (tmp_pool)
    destroy_pool(tmp_pool);

  return res;
}

