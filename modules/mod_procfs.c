/*
 * ProFTPD: mod_procfs -- a module for hiding the /proc filesystem
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
 *
 * This is mod_procfs contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 *
 * -----DO NOT CHANGE THE LINES BELOW-----
 */

#include "conf.h"
#include "privs.h"

#if !defined(HAVE_MNTENT_H)
/* Older ProFTPD versions did not check for the <mntent.h> header, so we
 * will use heuristics to guess whether it is present.  Some platforms,
 * such as Mac OSX, do not have this header.
 *
 * If/when I get access to BSD platforms, I can add heuristics to handle them
 * appropriately in the future.
 */
# if defined(__GLIBC__)
#   define HAVE_MNTENT_H 1
# elif defined(LINUX)
#   define HAVE_MNTENT_H 1
# endif /* LINUX */
#endif /* HAVE_MNTENT_H */

#if defined(HAVE_MNTENT_H)
# include <mntent.h>
#endif /* HAVE_MNTENT_H */

#if PROFTPD_VERSION_NUMBER < 0x0001030602
# error "ProFTPD 1.3.6rc2 or later required"
#endif

#define MOD_PROCFS_VERSION	"mod_procfs/0.4"

module procfs_module;

static int procfs_engine = FALSE;
static int procfs_logfd = -1;
static pool *procfs_pool = NULL;

static const char *trace_channel = "procfs";

struct procfs_mount {
  const char *path;
  size_t path_len;
  const char *type;
};

static array_header *procfs_mounts = NULL;

static int get_procfs_mounts(pool *p) {
#if defined(HAVE_MNTENT_H)
  FILE *mountf = NULL;
  struct mntent *mnt = NULL;

  mountf = setmntent("/etc/mtab", "r");
  if (mountf == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 1, "unable to read /etc/mtab: %s",
      strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  mnt = getmntent(mountf);
  while (mnt != NULL) {
    struct procfs_mount *mount = NULL;
    size_t path_len = 0;

    pr_signals_handle();

    if (strcmp(mnt->mnt_type, "proc") == 0) {
      pr_log_debug(DEBUG0, MOD_PROCFS_VERSION
        ": discovered procfs mounted at '%s'", mnt->mnt_dir);
      mount = palloc(p, sizeof(struct procfs_mount));
      mount->type = pstrdup(p, "procfs");

    } else if (strcmp(mnt->mnt_type, "sysfs") == 0) {
      pr_log_debug(DEBUG0, MOD_PROCFS_VERSION
        ": discovered sysfs mounted at '%s'", mnt->mnt_dir);
      mount = palloc(p, sizeof(struct procfs_mount));
      mount->type = pstrdup(p, "sysfs");
    }

    if (mount != NULL) {
      /* If the mount point path does not end with a trailing slash, add it.
       * We use this property when checking paths that reference this mount
       * point.
       */
      path_len = strlen(mnt->mnt_dir);
      if (mnt->mnt_dir[path_len-1] != '/') {
        mount->path = pstrcat(p, mnt->mnt_dir, "/", NULL);
        mount->path_len = path_len + 1;

      } else {
        mount->path = pstrdup(p, mnt->mnt_dir);
        mount->path_len = path_len;
      }

      if (procfs_mounts == NULL) {
        procfs_mounts = make_array(p, 0, sizeof(struct procfs_mount *));
      }

      *((struct procfs_mount **) push_array(procfs_mounts)) = mount;
    }

    mnt = getmntent(mountf);
  }

  if (endmntent(mountf) != 1) {
    pr_trace_msg(trace_channel, 1, "error closing /etc/mtab: %s",
      strerror(errno));
  }

#else
  struct stat st;

  /* Check for the presence of the /proc filesystem on this host.  If it
   * is not present, then we need do nothing else.
   */
  if (lstat("/proc/", &st) == 0) {
    pr_log_debug(DEBUG10, MOD_PROCFS_VERSION ": found /proc/ filesystem");

    if (S_ISDIR(st.st_mode)) {
      struct procfs_mount *mount;

      mount = palloc(p, sizeof(struct procfs_mount));
      mount->path = pstrdup(p, "/proc/");
      mount->path_len = 6;

      procfs_mounts = make_array(p, 0, sizeof(struct procfs_mount *));
      *((struct procfs_mount **) push_array(procfs_mounts)) = mount;

    } else {
      pr_log_debug(DEBUG10, MOD_PROCFS_VERSION ": /proc/ is not a directory");
    }
  }
#endif /* HAVE_MNTENT_H */

  if (procfs_mounts != NULL) {
    /* Automatically enable ProcfsEngine on in such cases. */
    procfs_engine = TRUE;

  } else {
    pr_log_debug(DEBUG5, MOD_PROCFS_VERSION
      ": did not find /proc filesystem: %s", strerror(errno));
  }

  return 0;
}

static int is_blocked_path(pool *p, const char *path) {
  register unsigned int i;
  int res = FALSE;
  char *abs_path;
  size_t abs_pathlen;
  struct procfs_mount **mounts;

  abs_path = dir_abs_path(p, path, FALSE);
  abs_pathlen = strlen(abs_path);

  mounts = procfs_mounts->elts;
  for (i = 0; i < procfs_mounts->nelts; i++) {
    struct procfs_mount *mount;

    pr_signals_handle();

    mount = mounts[i];

    pr_trace_msg(trace_channel, 19,
      "checking path '%s' against %s mount '%s'", abs_path, mount->type,
      mount->path);

    if (abs_pathlen >= mount->path_len &&
        strncmp(abs_path, mount->path, mount->path_len) == 0) {
      res = TRUE;

    } else if (abs_pathlen == (mount->path_len - 1) &&
               strncmp(abs_path, mount->path, mount->path_len - 1) == 0) {
      res = TRUE;
    }

    if (res == TRUE) {
      break;
    }
  }

  return res;
}

/* Configuration handlers
 */

/* usage: ProcfsEngine on|off */
MODRET set_procfsengine(cmd_rec *cmd) {
  int engine = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1); 
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  return PR_HANDLED(cmd);
}

/* usage: ProcfsLog path|"none" */ 
MODRET set_procfslog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1); 
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
 
  if (pr_fs_valid_path(cmd->argv[1]) < 0) {
    CONF_ERROR(cmd, "must be an absolute path");
  }
 
  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

static const char *get_cmd_resp_code(cmd_rec *cmd) {
  const char *resp_code = R_550;

  if (pr_cmd_cmp(cmd, PR_CMD_LIST_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_NLST_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_STAT_ID) == 0) {
    resp_code = R_450;
  }

  return resp_code;
}

static modret_t *handle_path(cmd_rec *cmd, const char *cmd_name,
    const char *path) {
  pr_trace_msg(trace_channel, 19, "checking path '%s' for %s", path, cmd_name);

  if (is_blocked_path(cmd->tmp_pool, path) == TRUE) {
    const char *proto, *resp_code;

    proto = pr_session_get_protocol(0);

    (void) pr_log_writefile(procfs_logfd, MOD_PROCFS_VERSION,
      "%s %s denied by mod_procfs for user '%s', client IP %s, protocol %s",
      cmd_name, path, session.user,
      pr_netaddr_get_ipstr(session.c->remote_addr), proto);
    pr_log_pri(PR_LOG_NOTICE, "%s %s denied by mod_procfs", cmd_name, path);

    /* The response code to use depends on the command. */
    resp_code = get_cmd_resp_code(cmd);
    pr_response_add_err(resp_code, _("%s: %s"), path, strerror(ENOENT));

    pr_cmd_set_errno(cmd, ENOENT);
    errno = ENOENT;
    return PR_ERROR(cmd);
  }

  return PR_DECLINED(cmd);
}

/* Command handlers
 */

MODRET procfs_pre_mfmt(cmd_rec *cmd) {
  const char *path, *ptr;

  if (procfs_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  if (cmd->argc < 3) {
    return PR_DECLINED(cmd);
  }

  /* The path can contain spaces.  Thus we need to use cmd->arg, not cmd->argv,
   * to find the path.  But cmd->arg contains the facts as well.  Thus we
   * find the FIRST space in cmd->arg; the path is everything past that space.
   */
  ptr = strchr(cmd->arg, ' ');
  if (ptr == NULL) {
    return PR_DECLINED(cmd);
  }

  path = ptr + 1;
  return handle_path(cmd, cmd->argv[0], path);
}

MODRET procfs_pre_path(cmd_rec *cmd) {
  const char *path;

  if (procfs_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  if (cmd->argc < 2) {
    return PR_DECLINED(cmd);
  }

  /* TODO: Add similar decoding, handling of spaces as done by mod_core. */

  path = cmd->arg;
  return handle_path(cmd, cmd->argv[0], path);
}

MODRET procfs_pre_site(cmd_rec *cmd) {
  char *cmd_name, *path;

  if (procfs_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  if (cmd->argc < 3) {
    return PR_DECLINED(cmd);
  }

  /* These are the SITE commands we know about:
   *
   *  SITE CHGRP <group> <path>
   *  SITE CHMOD <mode> <path>
   *
   *  SITE MKDIR <path> (mod_site_misc)
   *  SITE RMDIR <path> (mod_site_misc)
   *  SITE SYMLINK <from> <to> (mod_site_misc)
   *  SITE UTIME <timestamp> <path> (mod_site_misc)
   *
   *  SITE CPFR <path> (mod_copy)
   *  SITE CPTO <path> (mod_copy)
   *  SITE COPY <from> <to> (mod_copy)
   */

  if (strcmp(cmd->argv[1], "CHGRP") == 0 ||
      strcmp(cmd->argv[1], "CHMOD") == 0 ||
      strcmp(cmd->argv[1], "UTIME") == 0) {
    register unsigned int i;
    char *arg = "";

    if (cmd->argc < 4) {
      return PR_DECLINED(cmd);
    }

    /* Construct the path by concatenating all of the parameter after the
     * operational data, separating them with spaces.
     */

    for (i = 3; i < cmd->argc; i++) {
      arg = pstrcat(cmd->tmp_pool, arg, *arg ? " " : "", cmd->argv[i], NULL);
    }

    cmd_name = pstrcat(cmd->tmp_pool, cmd->argv[0], " ", cmd->argv[1], NULL);
    path = arg;
    return handle_path(cmd, cmd_name, path);

  } else if (strcmp(cmd->argv[1], "CPFR") == 0 ||
             strcmp(cmd->argv[1], "CPTO") == 0 ||
             strcmp(cmd->argv[1], "MKDIR") == 0 ||
             strcmp(cmd->argv[1], "RMDIR") == 0) {

    cmd_name = pstrcat(cmd->tmp_pool, cmd->argv[0], " ", cmd->argv[1], NULL);
    path = cmd->argv[2];
    return handle_path(cmd, cmd_name, path);

  } else if (strcmp(cmd->argv[1], "COPY") == 0 ||
             strcmp(cmd->argv[1], "SYMLINK") == 0) {
    char *from, *to;
    modret_t *mr;

    if (cmd->argc < 4) {
      return PR_DECLINED(cmd);
    }

    cmd_name = pstrcat(cmd->tmp_pool, cmd->argv[0], " ", cmd->argv[1], NULL);
    from = cmd->argv[2];
    to = cmd->argv[3];

    mr = handle_path(cmd, cmd_name, from);
    if (MODRET_ISERROR(mr)) {
      return mr;
    }

    return handle_path(cmd, cmd_name, to);

  } else {
    pr_trace_msg(trace_channel, 7,
      "unknown/unsupported SITE '%s' command, ignoring", (char *) cmd->argv[1]);
  }

  return PR_DECLINED(cmd);
}

MODRET procfs_sftp_pre_path(cmd_rec *cmd) {
  const char *path, *proto;

  if (procfs_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);
  if (strcmp(proto, "sftp") != 0) {
    return PR_DECLINED(cmd);
  }

  path = cmd->argv[1];
  return handle_path(cmd, cmd->argv[0], path);
}

MODRET procfs_sftp_pre_hardlink(cmd_rec *cmd) {
  const char *src_path, *dst_path, *proto;
  char *ptr;
  modret_t *mr;

  if (procfs_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);
  if (strcmp(proto, "sftp") != 0) {
    return PR_DECLINED(cmd);
  }

  /* Unfortunately, mod_sftp currently does NOT break the two paths into
   * the cmd->argv array; it only populates cmd->arg.
   *
   * In the future, if/when mod_sftp behavior changes, we can look at the
   * cmd->argc to determine which style is being used by mod_sftp.
   */
  ptr = strchr(cmd->arg, ' ');
  if (ptr == NULL) {
    return PR_DECLINED(cmd);
  }

  src_path = pstrndup(cmd->tmp_pool, cmd->arg, ptr - cmd->arg);
  dst_path = pstrdup(cmd->tmp_pool, ptr + 1);

  mr = handle_path(cmd, cmd->argv[0], src_path);
  if (MODRET_ISERROR(mr)) {
    return mr;
  }

  return handle_path(cmd, cmd->argv[0], dst_path);
}

MODRET procfs_sftp_pre_symlink(cmd_rec *cmd) {
  const char *src_path, *dst_path, *proto;
  char *ptr;
  modret_t *mr;

  if (procfs_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);
  if (strcmp(proto, "sftp") != 0) {
    return PR_DECLINED(cmd);
  }

  /* Unfortunately, mod_sftp currently does NOT break the two paths into
   * the cmd->argv array; it only populates cmd->arg.
   *
   * In the future, if/when mod_sftp behavior changes, we can look at the
   * cmd->argc to determine which style is being used by mod_sftp.
   */
  ptr = strchr(cmd->arg, '\t');
  if (ptr == NULL) {
    return PR_DECLINED(cmd);
  }

  src_path = pstrndup(cmd->tmp_pool, cmd->arg, ptr - cmd->arg);
  dst_path = pstrdup(cmd->tmp_pool, ptr + 1);

  mr = handle_path(cmd, cmd->argv[0], src_path);
  if (MODRET_ISERROR(mr)) {
    return mr;
  }

  return handle_path(cmd, cmd->argv[0], dst_path);
}

MODRET procfs_post_pass(cmd_rec *cmd) {
  config_rec *c;

  if (procfs_mounts == NULL) {
    procfs_engine = FALSE;
    return PR_DECLINED(cmd);
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProcfsEngine", FALSE);
  if (c != NULL) {
    procfs_engine = *((int *) c->argv[0]);
  }

  if (procfs_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  /* Check whether we are chrooted.  If so, then we need not do anything. */
  if (session.chroot_path != NULL) {
    if (strcmp(session.chroot_path, "/") != 0) {
      pr_trace_msg(trace_channel, 3,
        "session is chrooted to '%s', disabling mod_procfs",
        session.chroot_path);
      procfs_engine = FALSE;
    }
  }

  return PR_DECLINED(cmd);
}

/* Event Listeners
 */

#if defined(PR_SHARED_MODULE)
static void procfs_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_procfs.c", (const char *) event_data) != 0) {
    return;
  }

  pr_event_unregister(&procfs_module, NULL, NULL);

  (void) close(procfs_logfd);
  procfs_logfd = -1;

  if (procfs_pool != NULL) {
    destroy_pool(procfs_pool);
    procfs_pool = NULL;
    procfs_mounts = NULL;
  }

  procfs_engine = FALSE;
}
#endif /* PR_SHARED_MODULE */

static void procfs_restart_ev(const void *event_data, void *user_data) {
  (void) close(procfs_logfd);
  procfs_logfd = -1;

  if (procfs_pool != NULL) {
    destroy_pool(procfs_pool);
  }

  procfs_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(procfs_pool, MOD_PROCFS_VERSION);
}

static void procfs_shutdown_ev(const void *event_data, void *user_data) {
  (void) close(procfs_logfd);
  procfs_logfd = -1;

  if (procfs_pool != NULL) {
    destroy_pool(procfs_pool);
    procfs_pool = NULL;
    procfs_mounts = NULL;
  }
}

/* Initialization functions
 */

static int procfs_init(void) {
  if (procfs_pool != NULL) {
    destroy_pool(procfs_pool);
  }

  procfs_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(procfs_pool, MOD_PROCFS_VERSION);

#if defined(PR_SHARED_MODULE)
  pr_event_register(&procfs_module, "core.module-unload", procfs_mod_unload_ev,
    NULL);
#endif /* PR_SHARED_MODULE */
  pr_event_register(&procfs_module, "core.restart", procfs_restart_ev, NULL);
  pr_event_register(&procfs_module, "core.shutdown", procfs_shutdown_ev, NULL);

  if (get_procfs_mounts(procfs_pool) < 0) {
    pr_trace_msg(trace_channel, 1, "unable to discover procfs mounts: %s",
      strerror(errno));
  }

  return 0;
}

static int procfs_sess_init(void) {
  config_rec *c;
  const char *path;
  int res, xerrno;

  c = find_config(main_server->conf, CONF_PARAM, "ProcfsLog", FALSE);
  if (c == NULL) {
    return 0;
  }

  path = c->argv[0];
  if (strcasecmp(path, "none") == 0) {
    return 0;
  }

  PRIVS_ROOT
  res = pr_log_openfile(path, &procfs_logfd, 0660);
  xerrno = errno;
  PRIVS_RELINQUISH

  switch (res) {
    case 0:
      break;

    case -1:
      pr_log_debug(DEBUG1, MOD_PROCFS_VERSION
        ": unable to open ProcfsLog '%s': %s", path, strerror(xerrno));
      break;

    case PR_LOG_SYMLINK:
      pr_log_debug(DEBUG1, MOD_PROCFS_VERSION
        ": unable to open ProcfsLog '%s': %s", path, "is a symlink");
      break;

    case PR_LOG_WRITABLE_DIR:
      pr_log_debug(DEBUG1, MOD_PROCFS_VERSION
        ": unable to open ProcfsLog '%s': %s", path,
        "parent directory is world-writable");
      break;
  }

  return 0;
}

/* Module API tables
 */

static conftable procfs_conftab[] = {
  { "ProcfsEngine",	set_procfsengine,	NULL },
  { "ProcfsLog",	set_procfslog,		NULL },
  { NULL }
};

static cmdtable procfs_cmdtab[] = {

  /* FTP */
  { PRE_CMD,		C_APPE,	G_NONE,	procfs_pre_path,	FALSE, FALSE },
  { PRE_CMD,		C_CWD,	G_NONE,	procfs_pre_path,	FALSE, FALSE },
  { PRE_CMD,		C_XCWD,	G_NONE,	procfs_pre_path,	FALSE, FALSE },
  { PRE_CMD,		C_DELE,	G_NONE,	procfs_pre_path,	FALSE, FALSE },
  { PRE_CMD,		C_LIST,	G_NONE,	procfs_pre_path,	FALSE, FALSE },
  { PRE_CMD,		C_MDTM,	G_NONE,	procfs_pre_path,	FALSE, FALSE },
  { PRE_CMD,		C_MFF,	G_NONE,	procfs_pre_mfmt,	FALSE, FALSE },
  { PRE_CMD,		C_MFMT,	G_NONE,	procfs_pre_mfmt,	FALSE, FALSE },
  { PRE_CMD,		C_MKD,	G_NONE,	procfs_pre_path,	FALSE, FALSE },
  { PRE_CMD,		C_XMKD,	G_NONE,	procfs_pre_path,	FALSE, FALSE },
  { PRE_CMD,		C_MLSD,	G_NONE,	procfs_pre_path,	FALSE, FALSE },
  { PRE_CMD,		C_MLST,	G_NONE,	procfs_pre_path,	FALSE, FALSE },
  { PRE_CMD,		C_NLST,	G_NONE,	procfs_pre_path,	FALSE, FALSE },
  { PRE_CMD,		C_RETR,	G_NONE,	procfs_pre_path,	FALSE, FALSE },
  { PRE_CMD,		C_RMD,	G_NONE,	procfs_pre_path,	FALSE, FALSE },
  { PRE_CMD,		C_XRMD,	G_NONE,	procfs_pre_path,	FALSE, FALSE },
  { PRE_CMD,		C_RNFR,	G_NONE,	procfs_pre_path,	FALSE, FALSE },
  { PRE_CMD,		C_RNTO,	G_NONE,	procfs_pre_path,	FALSE, FALSE },
  { PRE_CMD,		C_SITE,	G_NONE,	procfs_pre_site,	FALSE, FALSE },
  { PRE_CMD,		C_SIZE,	G_NONE,	procfs_pre_path,	FALSE, FALSE },
  { PRE_CMD,		C_STAT,	G_NONE,	procfs_pre_path,	FALSE, FALSE },
  { PRE_CMD,		C_STOR,	G_NONE,	procfs_pre_path,	FALSE, FALSE },

  /* mod_digest FTP commands */
  { PRE_CMD,	"HASH",		G_NONE,	procfs_pre_path,	FALSE, FALSE },
  { PRE_CMD,	"MD5",		G_NONE,	procfs_pre_path,	FALSE, FALSE },
  { PRE_CMD,	"XCRC",		G_NONE,	procfs_pre_path,	FALSE, FALSE },
  { PRE_CMD,	"XMD5",		G_NONE,	procfs_pre_path,	FALSE, FALSE },
  { PRE_CMD,	"XSHA",		G_NONE,	procfs_pre_path,	FALSE, FALSE },
  { PRE_CMD,	"XSHA1",	G_NONE,	procfs_pre_path,	FALSE, FALSE },
  { PRE_CMD,	"XSHA256",	G_NONE,	procfs_pre_path,	FALSE, FALSE },
  { PRE_CMD,	"XSHA512",	G_NONE,	procfs_pre_path,	FALSE, FALSE },

  /* SFTP */
  { PRE_CMD, "HARDLINK",	G_NONE, procfs_sftp_pre_hardlink, FALSE, FALSE },
  { PRE_CMD, "LINK",		G_NONE, procfs_sftp_pre_hardlink, FALSE, FALSE },
  { PRE_CMD, "LSTAT",		G_NONE, procfs_sftp_pre_path, FALSE, FALSE },
  { PRE_CMD, "OPENDIR",		G_NONE, procfs_sftp_pre_path, FALSE, FALSE },
  { PRE_CMD, "READLINK",	G_NONE, procfs_sftp_pre_path, FALSE, FALSE },
  { PRE_CMD, "REALPATH",	G_NONE, procfs_sftp_pre_path, FALSE, FALSE },
  { PRE_CMD, "SETSTAT",		G_NONE, procfs_sftp_pre_path, FALSE, FALSE },
  { PRE_CMD, "SYMLINK",		G_NONE, procfs_sftp_pre_symlink, FALSE, FALSE },

  { POST_CMD,		C_PASS, G_NONE, procfs_post_pass,	FALSE, FALSE },
  { 0, NULL }
};

module procfs_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "procfs",

  /* Module configuration handler table */
  procfs_conftab,

  /* Module command handler table */
  procfs_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  procfs_init,

  /* Session initialization function */
  procfs_sess_init,

  /* Module version */
  MOD_PROCFS_VERSION
};
