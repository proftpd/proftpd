/*
 * ProFTPD: mod_copy -- a module supporting copying of files on the server
 *                      without transferring the data to the client and back
 *
 * Copyright (c) 2009-2010 TJ Saunders
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
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * This is mod_copy, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 *
 * $Id: mod_copy.c,v 1.1 2010-03-10 19:20:43 castaglia Exp $
 */

#include "conf.h"

#define MOD_COPY_VERSION	"mod_copy/0.2"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030301
# error "ProFTPD 1.3.3rc1 or later required"
#endif

/* These are copied largely from src/mkhome.c */

static int create_dir(const char *dir) {
  struct stat st;
  int res = -1;

  pr_fs_clear_cache();
  res = pr_fsio_stat(dir, &st);

  if (res < 0 &&
      errno != ENOENT) {
    pr_log_pri(PR_LOG_WARNING, MOD_COPY_VERSION ": error checking '%s': %s",
      dir, strerror(errno));
    return -1;
  }

  /* The directory already exists. */
  if (res == 0) {
    pr_log_debug(DEBUG3, MOD_COPY_VERSION ": '%s' already exists", dir);
    return 0;
  }

  if (pr_fsio_mkdir(dir, 0777) < 0) {
    pr_log_pri(PR_LOG_WARNING, MOD_COPY_VERSION ": error creating '%s': %s",
      dir, strerror(errno));
    return -1;
  }

  pr_log_debug(DEBUG6, MOD_COPY_VERSION ": directory '%s' created", dir);
  return 0;
}

static int create_path(pool *p, const char *path) {
  struct stat st;
  char *curr_path, *dup_path; 
 
  pr_fs_clear_cache();
 
  if (pr_fsio_stat(path, &st) == 0)
    return 0;
 
  dup_path = pstrdup(p, path);
  curr_path = session.cwd;
 
  while (dup_path &&
         *dup_path) {
    char *curr_dir;

    pr_signals_handle();

    curr_dir = strsep(&dup_path, "/");
    curr_path = pdircat(p, curr_path, curr_dir, NULL);

    if (create_dir(curr_path) < 0) {
      return -1;
    }
  }

  return 0;
}

static int copy_symlink(pool *p, const char *src_path, const char *dst_path) {
  char *link_path = pcalloc(p, PR_TUNABLE_BUFFER_SIZE);
  int len;

  len = pr_fsio_readlink(src_path, link_path, PR_TUNABLE_BUFFER_SIZE-1);
  if (len < 0) {
    pr_log_pri(PR_LOG_WARNING, MOD_COPY_VERSION ": error reading link '%s': %s",
      src_path, strerror(errno));
    return -1;
  }
  link_path[len] = '\0';

  if (pr_fsio_symlink(link_path, dst_path) < 0) {
    pr_log_pri(PR_LOG_WARNING, MOD_COPY_VERSION
      ": error symlinking '%s' to '%s': %s", link_path, dst_path,
      strerror(errno));
    return -1;
  }

  return 0;
}

static int copy_dir(pool *p, const char *src_dir, const char *dst_dir) {
  DIR *dh = NULL;
  struct dirent *dent = NULL;
  int res = 0;

  dh = opendir(src_dir);
  if (dh == NULL) {
    pr_log_pri(PR_LOG_WARNING, MOD_COPY_VERSION
      ": error reading directory '%s': %s", src_dir, strerror(errno));
    return -1;
  }

  while ((dent = readdir(dh)) != NULL) {
    struct stat st;
    char *src_path, *dst_path;

    pr_signals_handle();

    /* Skip "." and ".." */
    if (strcmp(dent->d_name, ".") == 0 ||
        strcmp(dent->d_name, "..") == 0) {
      continue;
    }

    src_path = pdircat(p, src_dir, dent->d_name, NULL);
    dst_path = pdircat(p, dst_dir, dent->d_name, NULL);

    if (pr_fsio_lstat(src_path, &st) < 0) {
      pr_log_debug(DEBUG3, MOD_COPY_VERSION
        ": unable to stat '%s' (%s), skipping", src_path, strerror(errno));
      continue;
    }

    /* Is this path to a directory? */
    if (S_ISDIR(st.st_mode)) {
      create_path(p, dst_path);
      if (copy_dir(p, src_path, dst_path) < 0) {
        res = -1;
        break;
      }
      continue;

    /* Is this path to a regular file? */
    } else if (S_ISREG(st.st_mode)) {
      if (pr_fs_copy_file(src_path, dst_path) < 0) {
        res = -1;
        break;
      }
      continue;

    /* Is this path a symlink? */
    } else if (S_ISLNK(st.st_mode)) {
      if (copy_symlink(p, src_path, dst_path) < 0) {
        res = -1;
        break;
      }
      continue;

    /* All other file types are skipped */
    } else {
      pr_log_debug(DEBUG3, MOD_COPY_VERSION ": skipping supported file '%s'",
        src_path);
      continue;
    }
  }

  closedir(dh);
  return res;
}

static int copy_paths(pool *p, const char *from, const char *to) {
  struct stat st;
  int res;
  xaset_t *set;

  set = get_dir_ctxt(p, (char *) to);
  res = pr_filter_allow_path(set, to);
  switch (res) {
    case 0:
      break;

    case PR_FILTER_ERR_FAILS_ALLOW_FILTER:
      pr_log_debug(DEBUG7, MOD_COPY_VERSION
        ": path '%s' denied by PathAllowFilter", to);
      errno = EPERM;
      return -1;

    case PR_FILTER_ERR_FAILS_DENY_FILTER:
      pr_log_debug(DEBUG7, MOD_COPY_VERSION
        ": path '%s' denied by PathDenyFilter", to);
      errno = EPERM;
      return -1;
  }

  /* Check whether from is a file, a directory, a symlink, or something
   * unsupported.
   */
  res = pr_fsio_lstat(from, &st);
  if (res < 0) {
    pr_log_debug(DEBUG7, MOD_COPY_VERSION ": error checking '%s': %s", from,
      strerror(errno));
    return -1;
  }
   
  if (S_ISREG(st.st_mode)) { 
    char *abs_path;

    pr_fs_clear_cache();
    res = pr_fsio_stat(to, &st);
    if (res == 0) {
      unsigned char *allow_overwrite;

      allow_overwrite = get_param_ptr(CURRENT_CONF, "AllowOverwrite", FALSE);
      if (allow_overwrite == NULL ||
          *allow_overwrite == FALSE) {
        pr_log_debug(DEBUG6,
          MOD_COPY_VERSION ": AllowOverwrite permission denied for '%s'", to);
        errno = EACCES;
        return -1;
      }
    }

    res = pr_fs_copy_file(from, to);
    if (res < 0) {
      pr_log_debug(DEBUG7, MOD_COPY_VERSION
        ": error copying file '%s' to '%s': %s", from, to, strerror(errno));
      return -1;
    }

    pr_fs_clear_cache();
    pr_fsio_stat(to, &st);

    /* Write a TransferLog entry as well. */
    abs_path = dir_abs_path(p, to, TRUE);

    if (session.sf_flags & SF_ANON) {
      xferlog_write(0, session.c->remote_name, st.st_size, abs_path,
        (session.sf_flags & SF_ASCII ? 'a' : 'b'), 'd', 'a',
        session.anon_user, 'c');

    } else {
      xferlog_write(0, session.c->remote_name, st.st_size, abs_path,
        (session.sf_flags & SF_ASCII ? 'a' : 'b'), 'd', 'r',
        session.user, 'c');
    }

  } else if (S_ISDIR(st.st_mode)) {
    create_path(p, to);
    res = copy_dir(p, from, to);
    if (res < 0) {
      pr_log_debug(DEBUG7, MOD_COPY_VERSION
        ": error copying directory '%s' to '%s': %s", from, to,
        strerror(errno));
      return -1;
    }

  } else if (S_ISLNK(st.st_mode)) {
    pr_fs_clear_cache();
    res = pr_fsio_stat(to, &st);
    if (res == 0) {
      unsigned char *allow_overwrite;

      allow_overwrite = get_param_ptr(CURRENT_CONF, "AllowOverwrite", FALSE);
      if (allow_overwrite == NULL ||
          *allow_overwrite == FALSE) {
        pr_log_debug(DEBUG6, MOD_COPY_VERSION
          ": AllowOverwrite permission denied for '%s'", to);
        errno = EACCES;
        return -1;
      }
    }

    res = copy_symlink(p, from, to);
    if (res < 0) {
      pr_log_debug(DEBUG7, MOD_COPY_VERSION
        ": error copying symlink '%s' to '%s': %s", from, to,
        strerror(errno));
      return -1;
    }

  } else {
    pr_log_debug(DEBUG7, MOD_COPY_VERSION
      ": unsupported file type for '%s'", from);
    errno = EINVAL;
    return -1;
  }

  return 0;
}

/* Command handlers
 */

MODRET copy_copy(cmd_rec *cmd) {
  if (cmd->argc < 2) {
    return PR_DECLINED(cmd);
  }

  if (strcasecmp(cmd->argv[1], "COPY") == 0) {
    char *cmd_name, *from, *to;
    unsigned char *authenticated;

    if (cmd->argc != 4) {
      return PR_DECLINED(cmd);
    }

    authenticated = get_param_ptr(cmd->server->conf, "authenticated", FALSE);
    if (authenticated == NULL ||
        *authenticated == FALSE) {
      pr_response_add_err(R_530, _("Please login with USER and PASS"));
      return PR_ERROR(cmd);
    }

    /* XXX What about paths which contain spaces? */
    from = pr_fs_decode_path(cmd->tmp_pool, cmd->argv[2]);
    from = dir_canonical_path(cmd->tmp_pool, from);

    to = pr_fs_decode_path(cmd->tmp_pool, cmd->argv[3]);
    to = dir_canonical_path(cmd->tmp_pool, to);

    cmd_name = cmd->argv[0];
    cmd->argv[0] = "SITE_COPY";
    if (!dir_check(cmd->tmp_pool, cmd, G_WRITE, to, NULL)) {
      cmd->argv[0] = cmd_name;
      pr_response_add_err(R_550, "%s: %s", cmd->argv[3], strerror(EPERM));
      return PR_ERROR(cmd);
    }
    cmd->argv[0] = cmd_name;

    if (copy_paths(cmd->tmp_pool, from, to) < 0) {
      int xerrno = errno;

      pr_response_add_err(R_550, "%s: %s", cmd->argv[1], strerror(xerrno));

      errno = xerrno;
      return PR_ERROR(cmd);
    }

    pr_response_add(R_200, _("SITE %s command successful"), cmd->argv[1]);
    return PR_HANDLED(cmd);
  }

  if (strcasecmp(cmd->argv[1], "HELP") == 0) {
    pr_response_add(R_214, _("CPFR <sp> pathname"));
    pr_response_add(R_214, _("CPTO <sp> pathname"));
  }

  return PR_DECLINED(cmd);
}

MODRET copy_cpfr(cmd_rec *cmd) {
  register unsigned int i;
  int res;
  char *path = "";

  if (strcasecmp(cmd->argv[1], "CPFR") != 0) {
    return PR_DECLINED(cmd);
  }

  CHECK_CMD_MIN_ARGS(cmd, 3);

  /* Construct the target file name by concatenating all the parameters after
   * the "SITE CPFR", separating them with spaces.
   */
  for (i = 2; i <= cmd->argc-1; i++) {
    path = pstrcat(cmd->tmp_pool, path, *path ? " " : "",
      pr_fs_decode_path(cmd->tmp_pool, cmd->argv[i]), NULL);
  }

  res = pr_filter_allow_path(CURRENT_CONF, path);
  switch (res) {
    case 0:
      break;

    case PR_FILTER_ERR_FAILS_ALLOW_FILTER:
      pr_log_debug(DEBUG2, MOD_COPY_VERSION
        ": 'CPFR %s' denied by PathAllowFilter", path);
      pr_response_add_err(R_550, _("%s: Forbidden filename"), path);
      return PR_ERROR(cmd);

    case PR_FILTER_ERR_FAILS_DENY_FILTER:
      pr_log_debug(DEBUG2, MOD_COPY_VERSION
        ": 'CPFR %s' denied by PathDenyFilter", path);
      pr_response_add_err(R_550, _("%s: Forbidden filename"), path);
      return PR_ERROR(cmd);
  }

  /* Allow renaming a symlink, even a dangling one. */
  path = dir_canonical_path(cmd->tmp_pool, path);

  if (!path ||
      !dir_check_canon(cmd->tmp_pool, cmd, cmd->group, path, NULL) ||
      !exists(path)) {
    pr_response_add_err(R_550, "%s: %s", path, strerror(errno));
    return PR_ERROR(cmd);
  }

  pr_table_add(session.notes, "mod_copy.cpfr-path",
    pstrdup(session.pool, path), 0);

  pr_response_add(R_350, _("File or directory exists, ready for destination "
    "name"));
  return PR_HANDLED(cmd);
}

MODRET copy_cpto(cmd_rec *cmd) {
  register unsigned int i;
  char *from, *to = "";

  if (strcasecmp(cmd->argv[1], "CPTO") != 0) {
    return PR_DECLINED(cmd);
  }

  CHECK_CMD_MIN_ARGS(cmd, 3);

  from = pr_table_get(session.notes, "mod_copy.cpfr-path", NULL);
  if (from == NULL) {
    pr_response_add_err(R_503, _("Bad sequence of commands"));
    return PR_ERROR(cmd);
  }

  /* Construct the target file name by concatenating all the parameters after
   * the "SITE CPTO", separating them with spaces.
   */
  for (i = 2; i <= cmd->argc-1; i++) {
    to = pstrcat(cmd->tmp_pool, to, *to ? " " : "",
      pr_fs_decode_path(cmd->tmp_pool, cmd->argv[i]), NULL);
  }

  if (copy_paths(cmd->tmp_pool, from, to) < 0) {
    int xerrno = errno;

    pr_response_add_err(R_550, "%s: %s", cmd->argv[1], strerror(xerrno));

    errno = xerrno;
    return PR_ERROR(cmd);
  }

  pr_table_remove(session.notes, "mod_copy.cpfr-path", NULL);

  pr_response_add(R_250, _("Copy successful"));
  return PR_HANDLED(cmd);
}

/* Initialization functions
 */

static int copy_sess_init(void) {
  /* Advertise support for the SITE command */
  pr_feat_add("SITE COPY");

  return 0;
}

/* Module API tables
 */

static cmdtable copy_cmdtab[] = {
  { CMD, C_SITE, G_WRITE,	copy_copy,	FALSE,	FALSE, CL_MISC },
  { CMD, C_SITE, G_DIRS,	copy_cpfr,	FALSE,	FALSE, CL_MISC },
  { CMD, C_SITE, G_WRITE,	copy_cpto,	FALSE,	FALSE, CL_MISC },
  { 0, NULL }
};

module copy_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "copy",

  /* Module configuration handler table */
  NULL,

  /* Module command handler table */
  copy_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  NULL,

  /* Session initialization function */
  copy_sess_init,

  /* Module version */
  MOD_COPY_VERSION
};
