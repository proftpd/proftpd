/*
 * ProFTPD - mod_sftp user authentication
 * Copyright (c) 2008-2009 TJ Saunders
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
 * $Id: auth.c,v 1.10 2009-04-24 16:48:13 castaglia Exp $
 */

#include "mod_sftp.h"
#include "ssh2.h"
#include "packet.h"
#include "msg.h"
#include "disconnect.h"
#include "interop.h"
#include "auth.h"
#include "crypto.h"
#include "cipher.h"
#include "mac.h"
#include "compress.h"
#include "session.h"
#include "keys.h"
#include "keystore.h"
#include "kbdint.h"
#include "utf8.h"

/* This value of 6 is the same default as OpenSSH's MaxAuthTries. */
static unsigned int auth_attempts_max = 6;
static unsigned int auth_attempts = 0;

static pool *auth_pool = NULL;
static char *auth_default_dir = NULL;
static const char *auth_avail_meths = NULL;
static const char *auth_remaining_meths = NULL;
static unsigned int auth_meths_enabled = 0;

static int auth_sent_userauth_success = FALSE;

static const char *auth_user = NULL;
static const char *auth_service = NULL;

static const char *trace_channel = "ssh2";

static struct passwd *dup_passwd(pool *p, struct passwd *pw) {
  struct passwd *res = NULL;

  res = pcalloc(p, sizeof(struct passwd));
  res->pw_name = pstrdup(p, pw->pw_name);
  res->pw_uid = pw->pw_uid;
  res->pw_gid = pw->pw_gid;
  res->pw_gecos = pstrdup(p, pw->pw_gecos);
  res->pw_dir = pstrdup(p, pw->pw_dir);
  res->pw_shell = pstrdup(p, pw->pw_shell);

  return res;
}

static void ensure_open_passwd(pool *p) {
  pr_auth_setpwent(p);
  pr_auth_setgrent(p);

  pr_auth_getpwent(p);
  pr_auth_getgrent(p);
}

static char *get_default_chdir(pool *p) {
  config_rec *c;
  char *path = NULL;

  c = find_config(main_server->conf, CONF_PARAM, "DefaultChdir", FALSE);
  while (c) {
    int res;

    pr_signals_handle();

    if (c->argc < 2) {
      path = c->argv[0];
      break;
    }

    res = pr_expr_eval_group_and(((char **) c->argv) + 1);
    if (res) {
      path = c->argv[0];
      break;
    }

    c = find_config_next(c, c->next, CONF_PARAM, "DefaultChdir", FALSE);
  }

  if (path &&
      *path != '/' &&
      *path != '~') {
    path = pdircat(p, session.cwd, path, NULL);
  }

  if (path) {
    path = path_subst_uservar(p, &path);
  }

  return path;
}

static char *get_default_root(pool *p) {
  config_rec *c;
  char *path = NULL;

  c = find_config(main_server->conf, CONF_PARAM, "DefaultRoot", FALSE);
  while (c) {
    int res;

    pr_signals_handle();

    if (c->argc < 2) {
      path = c->argv[0];
      break;
    }

    res = pr_expr_eval_group_and(((char **) c->argv) + 1);
    if (res) {
      path = c->argv[0];
      break;
    }

    c = find_config_next(c, c->next, CONF_PARAM, "DefaultRoot", FALSE);
  }

  if (path) {
    path = path_subst_uservar(p, &path);

    if (strcmp(path, "/") == 0) {
      path = NULL;

    } else {
      char *real_path;
      int xerrno = 0;

      PRIVS_USER
      real_path = dir_realpath(p, path);
      if (real_path == NULL) {
        xerrno = errno;
      }
      PRIVS_RELINQUISH

      if (real_path) {
        path = real_path;

      } else {
        int res;
        char interp_path[PR_TUNABLE_PATH_MAX + 1];

        memset(interp_path, '\0', sizeof(interp_path));
        res = pr_fs_interpolate(path, interp_path, sizeof(interp_path) - 1);

        pr_log_pri(PR_LOG_NOTICE,
          "notice: unable to use %s (resolved to '%s'): %s", path, interp_path,
          strerror(xerrno));
      }
    }
  }

  return path;
}

static void set_userauth_methods(void) {
  config_rec *c;

  if (auth_meths_enabled > 0) {
    /* No need to do the lookup if we've already done it. */
    return;
  }

  auth_avail_meths = auth_remaining_meths = NULL;
  auth_meths_enabled = 0;

  c = find_config(main_server->conf, CONF_PARAM, "SFTPAuthMethods", FALSE);
  if (c) {
    auth_avail_meths = auth_remaining_meths = c->argv[0];
    auth_meths_enabled = *((unsigned int *) c->argv[1]);

  } else {
    c = find_config(main_server->conf, CONF_PARAM, "SFTPAuthorizedUserKeys",
      FALSE);
    if (c) {
      auth_avail_meths = "publickey";
      auth_meths_enabled |= SFTP_AUTH_FL_METH_PUBLICKEY;

    } else {
      pr_trace_msg(trace_channel, 9, "no SFTPAuthorizedUserKeys configured, "
        "not offering 'publickey' authentication");
    }

    c = find_config(main_server->conf, CONF_PARAM, "SFTPAuthorizedHostKeys",
      FALSE);
    if (c) {
      if (auth_avail_meths) {
        auth_avail_meths = pstrcat(auth_pool, auth_avail_meths, ",hostbased",
          NULL);

      } else {
        auth_avail_meths = "hostbased";
      }

      auth_meths_enabled |= SFTP_AUTH_FL_METH_HOSTBASED;

    } else {
      pr_trace_msg(trace_channel, 9, "no SFTPAuthorizedHostKeys configured, "
        "not offering 'hostbased' authentication");
    }

    if (sftp_kbdint_have_drivers() > 0) {
      if (auth_avail_meths) {
        auth_avail_meths = pstrcat(auth_pool, auth_avail_meths,
          ",keyboard-interactive", NULL);

      } else {
        auth_avail_meths = "keyboard-interactive";
      }

      auth_meths_enabled |= SFTP_AUTH_FL_METH_KBDINT;

    } else {
      pr_trace_msg(trace_channel, 9, "no kbdint drivers present, not "
        "offering 'keyboard-interactive' authentication");
    }

    /* The 'password' method is always available. */
    if (auth_avail_meths) {
      auth_avail_meths = pstrcat(auth_pool, auth_avail_meths, ",password",
        NULL);

    } else {
      auth_avail_meths = "password";
    }

    auth_meths_enabled |= SFTP_AUTH_FL_METH_PASSWORD;

    auth_remaining_meths = pstrdup(auth_pool, auth_avail_meths);
  }
}

static int setup_env(pool *p, char *user) {
  struct passwd *pw;
  config_rec *c;
  int login_acl, i, res, show_symlinks = FALSE;
  struct stat st;
  char *default_chdir, *default_root, *home_dir;
  const char *sess_ttyname = NULL;
  cmd_rec *cmd;

  pw = pr_auth_getpwnam(p, user);

  pw = dup_passwd(p, pw);

  if (pw->pw_uid == PR_ROOT_UID) {
    c = find_config(main_server->conf, CONF_PARAM, "RootLogin", FALSE);
    if (c) {
      if (*((int *) c->argv[0]) == TRUE) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "root login attempted, denied by RootLogin configuration");
        pr_log_auth(PR_LOG_CRIT, "SECURITY VIOLATION: Root login attempted.");
        return -1;
      }
    }
  }

  res = pr_auth_is_valid_shell(main_server->conf, pw->pw_shell);
  if (res == FALSE) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "authentication for user '%s' failed: Invalid shell", user);
    pr_log_auth(PR_LOG_NOTICE, "USER %s (Login failed): Invalid shell: '%s'",
      user, pw->pw_shell);
    return -1;
  }

  res = pr_auth_banned_by_ftpusers(main_server->conf, pw->pw_name);
  if (res == TRUE) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "authentication for user '%s' failed: User in " PR_FTPUSERS_PATH, user);
    pr_log_auth(PR_LOG_NOTICE, "USER %s (Login failed): User in "
      PR_FTPUSERS_PATH, pw->pw_name);
    return -1;
  }

  session.user = pstrdup(p, pw->pw_name);
  session.group = pstrdup(p, pr_auth_gid2name(p, pw->pw_gid));

  session.login_uid = pw->pw_uid;
  session.login_gid = pw->pw_gid;

  pw->pw_dir = pr_auth_get_home(p, pw->pw_dir);
  pw->pw_dir = path_subst_uservar(p, &pw->pw_dir);

  if (session.gids == NULL &&
      session.groups == NULL) {
    res = pr_auth_getgroups(p, pw->pw_name, &session.gids, &session.groups);
    if (res < 1) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "no supplemental groups found for user '%s'", pw->pw_name);
    }
  }

  login_acl = login_check_limits(main_server->conf, FALSE, TRUE, &i);
  if (!login_acl) {
    pr_log_auth(PR_LOG_NOTICE, "USER %s (Login failed): Limit configuration "
      "denies login", user);
    return -1;
  }

  PRIVS_USER
  home_dir = dir_realpath(p, pw->pw_dir);
  PRIVS_RELINQUISH

  if (home_dir) {
    sstrncpy(session.cwd, home_dir, sizeof(session.cwd));

  } else {
    sstrncpy(session.cwd, pw->pw_dir, sizeof(session.cwd));
  }

  c = find_config(main_server->conf, CONF_PARAM, "CreateHome", FALSE);
  if (c) {
    if (*((unsigned char *) c->argv[0]) == TRUE) {
      if (create_home(p, session.cwd, user, pw->pw_uid, pw->pw_gid) < 0) {
        return -1;
      }
    }
  }

  default_chdir = get_default_chdir(p);

  /* Make sure any <Limit LOGIN> sections still allow access. */
  login_acl = login_check_limits(main_server->conf, FALSE, TRUE, &i);
  if (!login_acl) {
    pr_log_auth(PR_LOG_NOTICE, "USER %s: Limit configuration denies login",
      user);
    return -1;
  }

  resolve_deferred_dirs(main_server);
  fixup_dirs(main_server, CF_DEFER);

  session.wtmp_log = TRUE;

  c = find_config(main_server->conf, CONF_PARAM, "WtmpLog", FALSE);
  if (c &&
      *((unsigned char *) c->argv[0]) == FALSE) {
    session.wtmp_log = FALSE;
  }

  PRIVS_ROOT

  if (session.wtmp_log) {
    sess_ttyname = pr_session_get_ttyname(p);

    log_wtmp(sess_ttyname, session.user, session.c->remote_name,
      session.c->remote_addr);
  }

#ifdef PR_USE_LASTLOG
  c = find_config(main_server->conf, CONF_PARAM, "UseLastlog", FALSE);
  if (c &&
      *((unsigned char *) c->argv[0]) == TRUE) {
    if (sess_ttyname == NULL) {
      sess_ttyname = pr_session_get_ttyname(p);
    }

    log_lastlog(pw->pw_uid, session.user, sess_ttyname,
      session.c->remote_addr);
  }
#endif /* PR_USE_LASTLOG */

/* XXX TransferLog? */

  res = set_groups(p, pw->pw_gid, session.gids);
  PRIVS_RELINQUISH

  if (res < 0) {
    pr_log_pri(PR_LOG_ERR, "unable to set process groups: %s", strerror(errno));
  }

  default_root = get_default_root(session.pool);
  if (default_root) {
    ensure_open_passwd(p);

    if (pr_auth_chroot(default_root) < 0) {
      pr_log_pri(PR_LOG_ERR, "unable to set DefaultRoot directory '%s'",
        default_root);
      return -1;
    }

    if (strncmp(session.cwd, default_root, strlen(default_root)) == 0) {
      char *new_cwd;

      new_cwd = &session.cwd[strlen(default_root)];

      if (*new_cwd == '/') {
        new_cwd++;
      }
      session.cwd[0] = '/';

      sstrncpy(&session.cwd[1], new_cwd, sizeof(session.cwd));
    }
  }

  pr_signals_block();
  PRIVS_ROOT
  PRIVS_SETUP(pw->pw_uid, pw->pw_gid)
  pr_signals_unblock();

  /* Should we give up root privs completely here? */
  PRIVS_REVOKE
  session.disable_id_switching = TRUE;

#ifdef HAVE_GETEUID
  if (getegid() != pw->pw_gid ||
      geteuid() != pw->pw_uid) {
    pr_log_pri(PR_LOG_ERR, "process effective IDs do not match expected IDs");
    return -1;
  }
#endif

  if (pw->pw_dir == NULL ||
      strcmp(pw->pw_dir, "") == 0) {
    pr_log_pri(PR_LOG_ERR, "Home directory for user '%s' is NULL/empty",
      session.user);
    return -1;
  }

  c = find_config(main_server->conf, CONF_PARAM, "ShowSymlinks", FALSE);
  if (c) {
    if (*((unsigned char *) c->argv[0]) == TRUE) {
      show_symlinks = TRUE;
    }
  }

  if (pr_fsio_chdir_canon(session.cwd, !show_symlinks) == -1) {
    if (session.chroot_path != NULL ||
        default_root != NULL) {

      pr_log_debug(DEBUG2, "unable to chdir to %s (%s), defaulting to chroot "
        "directory %s", session.cwd, strerror(errno),
        (session.chroot_path ? session.chroot_path : default_root));

      if (pr_fsio_chdir_canon("/", !show_symlinks) == -1) {
        pr_log_pri(PR_LOG_ERR, "%s chdir(\"/\"): %s", session.user,
          strerror(errno));
        return -1;
      }

    } else if (default_chdir) {
      pr_log_debug(DEBUG2, "unable to chdir to %s (%s), defaulting to home "
        "directory %s", session.cwd, strerror(errno), pw->pw_dir);

      if (pr_fsio_chdir_canon(pw->pw_dir, !show_symlinks) == -1) {
        pr_log_pri(PR_LOG_ERR, "%s chdir(\"%s\"): %s", session.user,
          session.cwd, strerror(errno));
        return -1;
      }

    } else {
      pr_log_pri(PR_LOG_ERR, "%s chdir(\"%s\"): %s", session.user, session.cwd,
        strerror(errno));
      return -1;
    }
  }

  sstrncpy(session.cwd, pr_fs_getcwd(), sizeof(session.cwd));
  sstrncpy(session.vwd, pr_fs_getvwd(), sizeof(session.vwd));

  /* Make sure directory config pointers are set correctly */
  cmd = pr_cmd_alloc(p, 1, C_PASS);
  cmd->arg = "";
  dir_check_full(p, cmd, G_NONE, session.cwd, NULL);

  session.proc_prefix = pstrdup(session.pool, session.c->remote_name);
  session.sf_flags = 0;

  pr_log_auth(PR_LOG_NOTICE, "USER %s: Login successful", user);

  if (pw->pw_uid == PR_ROOT_UID) {
    pr_log_auth(PR_LOG_WARNING, "ROOT SFTP login successful");
  }

  if (pr_fsio_stat(session.cwd, &st) != -1) {
    build_dyn_config(p, session.cwd, &st, TRUE);
  }

  pr_scoreboard_update_entry(session.pid,
    PR_SCORE_USER, session.user,
    PR_SCORE_CWD, session.cwd,
    NULL);

  session_set_idle();

  pr_timer_remove(PR_TIMER_LOGIN, ANY_MODULE);

  auth_default_dir = pstrdup(session.pool, pr_fs_getvwd());

  session.user = pstrdup(session.pool, session.user);

  if (session.group) {
    session.group = pstrdup(session.pool, session.group);
  }

  session.groups = copy_array_str(session.pool, session.groups);

  pr_resolve_fs_map();
  return 0;
}

static int send_userauth_banner(void) {
  struct ssh2_packet *pkt;
  char *buf, *ptr, *mesg = "", *path;
  char data[PR_TUNABLE_BUFFER_SIZE];
  uint32_t buflen, bufsz;
  int res;
  config_rec *c;
  pr_fh_t *fh;
  pool *sub_pool;

  c = find_config(main_server->conf, CONF_PARAM, "SFTPDisplayBanner", FALSE);
  if (c == NULL) {
    return 0;
  }
  path = c->argv[0];

  if (!sftp_interop_supports_feature(SFTP_SSH2_FEAT_USERAUTH_BANNER)) {
    pr_trace_msg(trace_channel, 3, "unable to send SFTPDisplayBanner '%s': "
      "USERAUTH_BANNER supported by client", path);
    return 0;
  }

  fh = pr_fsio_open_canon(path, O_RDONLY);
  if (fh == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error opening SFTPDisplayBanner '%s': %s", path, strerror(errno));
    return 0;
  }

  sub_pool = make_sub_pool(auth_pool);
  pr_pool_tag(sub_pool, "SSH2 auth banner pool");

  while (pr_fsio_gets(data, sizeof(data), fh) != NULL) {
    size_t datalen;

    pr_signals_handle();

    data[sizeof(data)-1] = '\0';
    datalen = strlen(data);

    while (datalen &&
           (data[datalen-1] == '\r' ||
            data[datalen-1] == '\n')) {
      data[datalen-1] = '\0';
      datalen--;
    }

    /* XXX Add handling of Variables, etc here. */

    /* We have to separate lines using CRLF, as per RFC 4252 Section 5.4. */
    mesg = pstrcat(sub_pool, mesg, *mesg ? "\r\n" : "", data, NULL);
  }

  pkt = sftp_ssh2_packet_create(auth_pool);

  buflen = bufsz = strlen(mesg) + 32;
  ptr = buf = palloc(pkt->pool, bufsz);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_USER_AUTH_BANNER);
  sftp_msg_write_string(&buf, &buflen, mesg);
  sftp_msg_write_string(&buf, &buflen, "");

  pkt->payload = ptr;
  pkt->payload_len = (bufsz - buflen);

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "sending userauth banner");

  res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt);
  if (res < 0) {
    destroy_pool(sub_pool);
    destroy_pool(pkt->pool);
    return -1;
  }

  destroy_pool(sub_pool);
  destroy_pool(pkt->pool);
  return 0;
}

static int send_userauth_failure(char *failed_meth) {
  struct ssh2_packet *pkt;
  char *buf, *ptr, *meths;
  uint32_t buflen, bufsz = 1024;
  int res;

  pkt = sftp_ssh2_packet_create(auth_pool);

  if (failed_meth) {
    meths = pstrdup(pkt->pool, auth_remaining_meths);
    meths = sreplace(pkt->pool, meths, failed_meth, "", NULL);

    if (*meths == ',') {
      meths++;
    }

    if (meths[strlen(meths)-1] == ',') {
      meths[strlen(meths)-1] = '\0';
    }

    if (strstr(meths, ",,") != NULL) {
      meths = sreplace(pkt->pool, meths, ",,", ",", NULL);
    }

    if (strcmp(failed_meth, "publickey") == 0) {
      auth_meths_enabled &= ~SFTP_AUTH_FL_METH_PUBLICKEY;

    } else if (strcmp(failed_meth, "hostbased") == 0) {
      auth_meths_enabled &= ~SFTP_AUTH_FL_METH_HOSTBASED;

    } else if (strcmp(failed_meth, "password") == 0) {
      auth_meths_enabled &= ~SFTP_AUTH_FL_METH_PASSWORD;

    } else if (strcmp(failed_meth, "keyboard-interactive") == 0) {
      auth_meths_enabled &= ~SFTP_AUTH_FL_METH_KBDINT;
    }

    if (strlen(meths) == 0) {
      /* If there are no more auth methods available, we have to disconnect. */
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "no more auth methods available, disconnecting");
      SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
        NULL);
    }

    auth_remaining_meths = pstrdup(auth_pool, meths);

  } else {
    meths = pstrdup(pkt->pool, auth_avail_meths);
  }

  buflen = bufsz;
  ptr = buf = palloc(pkt->pool, bufsz);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_USER_AUTH_FAILURE);
  sftp_msg_write_string(&buf, &buflen, meths);
  sftp_msg_write_bool(&buf, &buflen, FALSE);

  pkt->payload = ptr;
  pkt->payload_len = (bufsz - buflen);

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "sending userauth failure; remaining userauth methods: %s", meths);

  res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt);
  if (res < 0) {
    destroy_pool(pkt->pool);
    return -1;
  }

  return 0;
}

static int send_userauth_success(void) {
  struct ssh2_packet *pkt;
  char *buf, *ptr;
  uint32_t buflen, bufsz = 1024;
  int res;

  if (auth_sent_userauth_success) {
    return 0;
  }

  pkt = sftp_ssh2_packet_create(auth_pool);

  buflen = bufsz;
  ptr = buf = palloc(pkt->pool, bufsz);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_USER_AUTH_SUCCESS);

  pkt->payload = ptr;
  pkt->payload_len = (bufsz - buflen);

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "sending userauth success");

  res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt);
  if (res < 0) {
    destroy_pool(pkt->pool);
    return -1;
  }

  auth_sent_userauth_success = TRUE;

  /* We call the compression init routines here as well, in case the
   * client selected "delayed" compression.
   */
  sftp_compress_init_read(SFTP_COMPRESS_FL_AUTHENTICATED);
  sftp_compress_init_write(SFTP_COMPRESS_FL_AUTHENTICATED);

  return 0;
}

static int send_userauth_methods(void) {
  struct ssh2_packet *pkt;
  char *buf, *ptr;
  uint32_t buflen, bufsz = 1024;
  int res;

  pkt = sftp_ssh2_packet_create(auth_pool);

  buflen = bufsz;
  ptr = buf = palloc(pkt->pool, bufsz);

  /* We send the remaining auth methods, not the avail auth methods, since
   * the list of remaining auth methods may have changed (i.e. because of
   * of failed auth attempts).
   */

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "sending acceptable userauth methods: %s", auth_remaining_meths);
  
  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_USER_AUTH_FAILURE);
  sftp_msg_write_string(&buf, &buflen, auth_remaining_meths);
  sftp_msg_write_bool(&buf, &buflen, FALSE);

  pkt->payload = ptr;
  pkt->payload_len = (bufsz - buflen);

  res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt);
  if (res < 0) {
    destroy_pool(pkt->pool);
    return -1;
  }

  return 0;
}

/* Return -1 on error, 0 to continue, and 1 if the authentication succeeded. */
static int handle_userauth_req(struct ssh2_packet *pkt, char **service) {
  char *buf, *orig_user, *user, *method;
  uint32_t buflen;
  cmd_rec *cmd, *cmd2, *cmd3;
  int res, send_userauth_fail = FALSE;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  orig_user = sftp_msg_read_string(pkt->pool, &buf, &buflen);

  cmd2 = pr_cmd_alloc(pkt->pool, 2, pstrdup(pkt->pool, C_USER), orig_user);
  cmd2->arg = orig_user;

  cmd3 = pr_cmd_alloc(pkt->pool, 1, pstrdup(pkt->pool, C_PASS));
  cmd3->arg = "(hidden)";

  /* Dispatch these as a PRE_CMDs, so that mod_delay's tactics can be used
   * to ameliorate any timing-based attacks.
   */
  pr_cmd_dispatch_phase(cmd2, PRE_CMD, 0);
  if (strcmp(orig_user, cmd2->arg) == 0) {
    user = orig_user;

  } else {
    user = cmd2->arg;
  }

  pr_cmd_dispatch_phase(cmd3, PRE_CMD, 0);

  if (auth_user) {
    /* Check to see if the client has requested a different user name in
     * this USERAUTH_REQUEST.  As per Section 5 of RFC4252, if the user
     * name changes, we can disconnect the client.
     */
    if (strcmp(orig_user, auth_user) != 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "client used different user name '%s' in USERAUTH_REQUEST (was '%s'), "
        "disconnecting", orig_user, auth_user);

      pr_cmd_dispatch_phase(cmd2, POST_CMD_ERR, 0);
      pr_cmd_dispatch_phase(cmd2, LOG_CMD_ERR, 0);

      pr_cmd_dispatch_phase(cmd3, POST_CMD_ERR, 0);
      pr_cmd_dispatch_phase(cmd3, LOG_CMD_ERR, 0);

      return -1;
    }

  } else {
    auth_user = pstrdup(auth_pool, orig_user);
  }

  *service = sftp_msg_read_string(pkt->pool, &buf, &buflen);
  if (auth_service) {
    /* Check to see if the client has requested a different service name in
     * this USERAUTH_REQUEST.  As per Section 5 of RFC4252, if the service
     * name changes, we can disconnect the client.
     */
    if (strcmp(*service, auth_service) != 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "client used different service name '%s' in USERAUTH_REQUEST (was "
        "'%s'), disconnecting", *service, auth_service);

      pr_cmd_dispatch_phase(cmd2, POST_CMD_ERR, 0);
      pr_cmd_dispatch_phase(cmd2, LOG_CMD_ERR, 0);

      pr_cmd_dispatch_phase(cmd3, POST_CMD_ERR, 0);
      pr_cmd_dispatch_phase(cmd3, LOG_CMD_ERR, 0);

      return -1;
    }

  } else {
    auth_service = pstrdup(auth_pool, *service);
  }

  method = sftp_msg_read_string(pkt->pool, &buf, &buflen);

  pr_trace_msg(trace_channel, 10, "auth requested for user '%s', service '%s', "
    "using method '%s'", user, *service, method);

  (void) pr_table_remove(session.notes, "mod_auth.orig-user", NULL);
  if (pr_table_add_dup(session.notes, "mod_auth.orig-user", user, 0) < 0) {
    pr_log_debug(DEBUG3, "error stashing 'mod_auth.orig-user' in "
      "session.notes: %s", strerror(errno));
  }

  cmd = pr_cmd_alloc(pkt->pool, 1, pstrdup(pkt->pool, "USERAUTH_REQUEST"));
  cmd->arg = pstrcat(pkt->pool, user, " ", method, NULL);

  if (auth_attempts > auth_attempts_max) {
    pr_log_auth(PR_LOG_NOTICE,
      "Maximum login attempts (%u) exceeded, connection refused",
      auth_attempts_max);
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "Maximum login attempts (%u) exceeded, refusing connection for user '%s'",
      auth_attempts_max, user);
    pr_event_generate("mod_auth.max-login-attempts", session.c);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_BY_APPLICATION, NULL);
  }

  set_userauth_methods();

  if (strcmp(method, "none") == 0) {
    /* If the client requested the "none" auth method at this point, then
     * the list of authentication methods supported by the server is being
     * queried.
     */
    if (send_userauth_methods() < 0) {
      pr_cmd_dispatch_phase(cmd, POST_CMD_ERR, 0);
      pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);

      pr_cmd_dispatch_phase(cmd2, POST_CMD_ERR, 0);
      pr_cmd_dispatch_phase(cmd2, LOG_CMD_ERR, 0);

      pr_cmd_dispatch_phase(cmd3, POST_CMD_ERR, 0);
      pr_cmd_dispatch_phase(cmd3, LOG_CMD_ERR, 0);

      return -1;
    }

    pr_cmd_dispatch_phase(cmd, POST_CMD, 0);
    pr_cmd_dispatch_phase(cmd, LOG_CMD, 0);

    return 0;

  } else if (strcmp(method, "publickey") == 0) {
    if (auth_meths_enabled & SFTP_AUTH_FL_METH_PUBLICKEY) {
      res = sftp_auth_publickey(pkt, orig_user, user, *service, &buf, &buflen,
        &send_userauth_fail);

    } else {
      pr_trace_msg(trace_channel, 10, "auth method '%s' not enabled", method);
      auth_attempts++;

      if (send_userauth_methods() < 0) {
        pr_cmd_dispatch_phase(cmd, POST_CMD_ERR, 0);
        pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);

        pr_cmd_dispatch_phase(cmd2, POST_CMD_ERR, 0);
        pr_cmd_dispatch_phase(cmd2, LOG_CMD_ERR, 0);

        pr_cmd_dispatch_phase(cmd3, POST_CMD_ERR, 0);
        pr_cmd_dispatch_phase(cmd3, LOG_CMD_ERR, 0);

        return -1;
      }

      pr_cmd_dispatch_phase(cmd, POST_CMD, 0);
      pr_cmd_dispatch_phase(cmd, LOG_CMD, 0);

      return 0;
    }

  } else if (strcmp(method, "keyboard-interactive") == 0) {
    if (auth_meths_enabled & SFTP_AUTH_FL_METH_KBDINT) {
      res = sftp_auth_kbdint(pkt, orig_user, user, *service, &buf, &buflen,
        &send_userauth_fail);

    } else {
      pr_trace_msg(trace_channel, 10, "auth method '%s' not enabled", method);
      auth_attempts++;

      if (send_userauth_methods() < 0) {
        pr_cmd_dispatch_phase(cmd, POST_CMD_ERR, 0);
        pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);

        pr_cmd_dispatch_phase(cmd2, POST_CMD_ERR, 0);
        pr_cmd_dispatch_phase(cmd2, LOG_CMD_ERR, 0);

        pr_cmd_dispatch_phase(cmd3, POST_CMD_ERR, 0);
        pr_cmd_dispatch_phase(cmd3, LOG_CMD_ERR, 0);

        return -1;
      }

      pr_cmd_dispatch_phase(cmd, POST_CMD, 0);
      pr_cmd_dispatch_phase(cmd, LOG_CMD, 0);

      return 0;
    }

  } else if (strcmp(method, "password") == 0) {
    if (auth_meths_enabled & SFTP_AUTH_FL_METH_PASSWORD) {
      res = sftp_auth_password(pkt, orig_user, user, *service, &buf, &buflen,
        &send_userauth_fail);

    } else {
      pr_trace_msg(trace_channel, 10, "auth method '%s' not enabled", method);
      auth_attempts++;

      if (send_userauth_methods() < 0) {
        pr_cmd_dispatch_phase(cmd, POST_CMD_ERR, 0);
        pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);

        pr_cmd_dispatch_phase(cmd2, POST_CMD_ERR, 0);
        pr_cmd_dispatch_phase(cmd2, LOG_CMD_ERR, 0);

        pr_cmd_dispatch_phase(cmd3, POST_CMD_ERR, 0);
        pr_cmd_dispatch_phase(cmd3, LOG_CMD_ERR, 0);

        return -1;
      }

      pr_cmd_dispatch_phase(cmd, POST_CMD, 0);
      pr_cmd_dispatch_phase(cmd, LOG_CMD, 0);

      return 0;
    }

  } else if (strcmp(method, "hostbased") == 0) {
    if (auth_meths_enabled & SFTP_AUTH_FL_METH_HOSTBASED) {
      res = sftp_auth_hostbased(pkt, orig_user, user, *service, &buf, &buflen,
        &send_userauth_fail);

    } else {
      pr_trace_msg(trace_channel, 10, "auth method '%s' not enabled", method);
      auth_attempts++;

      if (send_userauth_methods() < 0) {
        pr_cmd_dispatch_phase(cmd, POST_CMD_ERR, 0);
        pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);

        pr_cmd_dispatch_phase(cmd2, POST_CMD_ERR, 0);
        pr_cmd_dispatch_phase(cmd2, LOG_CMD_ERR, 0);

        pr_cmd_dispatch_phase(cmd3, POST_CMD_ERR, 0);
        pr_cmd_dispatch_phase(cmd3, LOG_CMD_ERR, 0);

        return -1;
      }

      pr_cmd_dispatch_phase(cmd, POST_CMD, 0);
      pr_cmd_dispatch_phase(cmd, LOG_CMD, 0);

      return 0;
    }

  } else {
    auth_attempts++;

    pr_cmd_dispatch_phase(cmd, POST_CMD_ERR, 0);
    pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);

    pr_cmd_dispatch_phase(cmd2, POST_CMD_ERR, 0);
    pr_cmd_dispatch_phase(cmd2, LOG_CMD_ERR, 0);

    pr_cmd_dispatch_phase(cmd3, POST_CMD_ERR, 0);
    pr_cmd_dispatch_phase(cmd3, LOG_CMD_ERR, 0);

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "unsupported authentication method '%s' requested", method);
    return -1;
  }

  if (res <= 0) {
    int xerrno = errno;

    auth_attempts++;

    pr_cmd_dispatch_phase(cmd, res == 0 ? POST_CMD : POST_CMD_ERR, 0);
    pr_cmd_dispatch_phase(cmd, res == 0 ? LOG_CMD : LOG_CMD_ERR, 0);

    if (send_userauth_fail) {
      errno = xerrno;

      if (send_userauth_failure(errno != EPERM ? NULL : method) < 0) {
        return -1;
      }
    }

    return res;
  }

  if (setup_env(pkt->pool, user) < 0) {
    auth_attempts++;

    pr_cmd_dispatch_phase(cmd, POST_CMD_ERR, 0);
    pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);

    pr_cmd_dispatch_phase(cmd2, POST_CMD_ERR, 0);
    pr_cmd_dispatch_phase(cmd2, LOG_CMD_ERR, 0);

    pr_cmd_dispatch_phase(cmd3, POST_CMD_ERR, 0);
    pr_cmd_dispatch_phase(cmd3, LOG_CMD_ERR, 0);

    if (send_userauth_failure(NULL) < 0) {
      return -1;
    }

    return 0;
  }

  if (send_userauth_success() < 0) {
    pr_cmd_dispatch_phase(cmd, POST_CMD_ERR, 0);
    pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);

    pr_cmd_dispatch_phase(cmd2, POST_CMD_ERR, 0);
    pr_cmd_dispatch_phase(cmd2, LOG_CMD_ERR, 0);

    pr_cmd_dispatch_phase(cmd3, POST_CMD_ERR, 0);
    pr_cmd_dispatch_phase(cmd3, LOG_CMD_ERR, 0);

    return -1;
  }

  if (session.auth_mech) {
    pr_log_debug(DEBUG2, "user '%s' authenticated by %s", user,
      session.auth_mech);
  }

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "user '%s' authenticated via '%s' method", user, method);

  pr_cmd_dispatch_phase(cmd, POST_CMD, 0);
  pr_cmd_dispatch_phase(cmd, LOG_CMD, 0);

  pr_cmd_dispatch_phase(cmd2, POST_CMD, 0);
  pr_cmd_dispatch_phase(cmd2, LOG_CMD, 0);

  pr_cmd_dispatch_phase(cmd3, POST_CMD, 0);
  pr_cmd_dispatch_phase(cmd3, LOG_CMD, PR_CMD_DISPATCH_FL_CLEAR_RESPONSE);

  return 1;
}

char *sftp_auth_get_default_dir(void) {
  return auth_default_dir;
}

int sftp_auth_handle(struct ssh2_packet *pkt) {
  char *service = NULL;
  int res;

  /* The send_userauth_banner() function makes sure that the banner
   * is not sent multiple times.
   */
  if (send_userauth_banner() < 0) {
    return -1;
  }

  res = handle_userauth_req(pkt, &service);
  if (res < 0) {
    destroy_pool(pkt->pool);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_PROTOCOL_ERROR, NULL);
  }

  destroy_pool(pkt->pool);
  return res;
}

int sftp_auth_init(void) {

  /* There's no point in trying to handle the case where a client will
   * want/attempt to authenticate again, as a different user.
   *
   * The issue is that if a client successfully authenticates, and the
   * authenticated session is chrooted, a subsequent attempt to authenticate
   * will occur in a chrooted process, and that will likely lead to all
   * sorts of brokenness.
   */

  if (auth_pool == NULL) {
    unsigned int *max_logins;

    auth_pool = make_sub_pool(sftp_pool);
    pr_pool_tag(auth_pool, "SSH2 Auth Pool");

    max_logins = get_param_ptr(main_server->conf, "MaxLoginAttempts", FALSE);
    if (max_logins) {
      auth_attempts_max = *max_logins;
    }
  }

  return 0;
}
