/*
 * ProFTPD: mod_redis -- a module for managing Redis data
 * Copyright (c) 2017 The ProFTPD Project
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
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * -----DO NOT EDIT BELOW THIS LINE-----
 * $Libraries: -lhiredis$
 */

#include "conf.h"
#include "privs.h"

#define MOD_REDIS_VERSION		"mod_redis/0.1"

#if PROFTPD_VERSION_NUMBER < 0x0001030603
# error "ProFTPD 1.3.6rc3 or later required"
#endif

#include <hiredis/hiredis.h>

extern xaset_t *server_list;

module redis_module;

#define REDIS_DEFAULT_PORT		6379

static int redis_logfd = -1;
static pool *redis_pool = NULL;

static void redis_exit_ev(const void *, void *);
static int redis_sess_init(void);

/* Configuration handlers
 */

/* usage: RedisEngine on|off */
MODRET set_redisengine(cmd_rec *cmd) {
  int engine = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  return PR_HANDLED(cmd);
}

/* usage: RedisLog path|"none" */
MODRET set_redislog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (strcasecmp(cmd->argv[1], "none") != 0 &&
      pr_fs_valid_path(cmd->argv[1]) < 0) {
    CONF_ERROR(cmd, "must be an absolute path");
  }

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: RedisServer host[:port] ... */
/* NOTE: Need to handle IPv6 addresses here, eventually. */
MODRET set_redisserver(cmd_rec *cmd) {
  config_rec *c;
  char *server, *ptr;
  int ctx, port;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  server = pstrdup(cmd->tmp_pool, cmd->argv[1]);
  ptr = strrchr(server, ':');
  if (ptr == NULL) {
    port = REDIS_DEFAULT_PORT;

  } else {
    *ptr = '\0';
    port = atoi(ptr + 1);
  }

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  c->argv[0] = pstrdup(c->pool, server);
  c->argv[1] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[1]) = port;

  ctx = (cmd->config && cmd->config->config_type != CONF_PARAM ?
    cmd->config->config_type : cmd->server->config_type ?
    cmd->server->config_type : CONF_ROOT);

  if (ctx == CONF_ROOT) {
    /* If we're the "server config" context, set the server now.  This
     * would let mod_redis talk to those servers for e.g. ftpdctl actions.
     */
    redis_set_server(server, port);
  }

  return PR_HANDLED(cmd);
}

/* usage: RedisTimeouts conn-timeout io-timeout */
MODRET set_redistimeouts(cmd_rec *cmd) {
  config_rec *c;
  unsigned long connect_millis, io_millis;
  char *ptr = NULL;

  CHECK_ARGS(cmd, 2);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  connect_millis = strtoul(cmd->argv[1], &ptr, 10);
  if (ptr && *ptr) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
      "badly formatted connect timeout value: ", cmd->argv[1], NULL));
  }

  ptr = NULL;
  io_millis = strtoul(cmd->argv[2], &ptr, 10);
  if (ptr && *ptr) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
      "badly formatted IO timeout value: ", cmd->argv[2], NULL));
  }

#if 0
  /* XXX If we're the "server config" context, set the timeouts now.
   * This would let mod_redis talk to those servers for e.g. ftpdctl
   * actions.
   */
  redis_set_timeouts(conn_timeout, io_timeout);
#endif

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  c->argv[0] = palloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = connect_millis;
  c->argv[1] = palloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[1]) = io_millis;

  return PR_HANDLED(cmd);
}

/* Event handlers
 */

static void redis_exit_ev(const void *event_data, void *user_data) {
  redis_clear();
}

static void redis_restart_ev(const void *event_data, void *user_data) {
  destroy_pool(redis_pool);
  redis_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(redis_pool, MOD_REDIS_VERSION);
}

static void redis_sess_reinit_ev(const void *event_data, void *user_data) {
  int res;

  /* A HOST command changed the main_server pointer, reinitialize ourselves. */

  pr_event_unregister(&redis_module, "core.exit", redis_exit_ev);
  pr_event_unregister(&redis_module, "core.session-reinit",
    redis_sess_reinit_ev);

  (void) close(redis_logfd);
  redis_logfd = -1;

  /* XXX Restore other Redis settings? */
  /* reset RedisTimeouts */

  res = redis_sess_init();
  if (res < 0) {
    pr_session_disconnect(&redis_module,
      PR_SESS_DISCONNECT_SESSION_INIT_FAILED, NULL);
  }
}

/* Initialization functions
 */

static int redis_module_init(void) {
  redis_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(redis_pool, MOD_REDIS_VERSION);

  redis_init();
  pr_event_register(&redis_module, "core.restart", redis_restart_ev, NULL);

  pr_log_debug(DEBUG2, MOD_REDIS_VERSION ": using hiredis-%d.%d.%d",
    HIREDIS_MAJOR, HIREDIS_MINOR, HIREDIS_PATCH);
  return 0;
}

static int redis_sess_init(void) {
  config_rec *c;

  pr_event_register(&redis_module, "core.session-reinit",
    redis_sess_reinit_ev, NULL);

  c = find_config(main_server->conf, CONF_PARAM, "RedisEngine", FALSE);
  if (c != NULL) {
    int engine;

    engine = *((int *) c->argv[0]);
    if (engine == FALSE) {
      return 0;
    }
  }

  pr_event_register(&redis_module, "core.exit", redis_exit_ev, NULL);

  c = find_config(main_server->conf, CONF_PARAM, "RedisLog", FALSE);
  if (c != NULL) {
    const char *path;

    path = c->argv[0];
    if (strcasecmp(path, "none") != 0) {
      int res, xerrno;

      pr_signals_block();
      PRIVS_ROOT
      res = pr_log_openfile(path, &redis_logfd, PR_LOG_SYSTEM_MODE);
      xerrno = errno;
      PRIVS_RELINQUISH
      pr_signals_unblock();

      switch (res) {
        case 0:
          break;

        case -1:
          pr_log_pri(PR_LOG_NOTICE, MOD_REDIS_VERSION
            ": notice: unable to open RedisLog '%s': %s", path,
            strerror(xerrno));
          break;

        case PR_LOG_WRITABLE_DIR:
          pr_log_pri(PR_LOG_WARNING, MOD_REDIS_VERSION
            ": notice: unable to use RedisLog '%s': parent directory is "
              "world-writable", path);
          break;

        case PR_LOG_SYMLINK:
          pr_log_pri(PR_LOG_WARNING, MOD_REDIS_VERSION
            ": notice: unable to use RedisLog '%s': cannot log to a symlink",
            path);
          break;
      }
    }
  }

  c = find_config(main_server->conf, CONF_PARAM, "RedisServer", FALSE);
  if (c != NULL) {
    const char *server;
    int port;

    server = c->argv[0];
    port = *((int *) c->argv[1]);
    redis_set_server(server, port);
  }

  c = find_config(main_server->conf, CONF_PARAM, "RedisTimeouts", FALSE);
  if (c) {
    unsigned long connect_millis, io_millis;

    connect_millis = *((unsigned long *) c->argv[0]);
    io_millis = *((unsigned long *) c->argv[1]);

    if (redis_set_timeouts(connect_millis, io_millis) < 0) {
      (void) pr_log_writefile(redis_logfd, MOD_REDIS_VERSION,
        "error setting Redis timeouts: %s", strerror(errno));
    }
  }

  return 0;
}

/* Module API tables
 */

static conftable redis_conftab[] = {
  { "RedisEngine",		set_redisengine,	NULL },
  { "RedisLog",			set_redislog,		NULL },
  { "RedisServer",		set_redisserver,	NULL },
  { "RedisTimeouts",		set_redistimeouts,	NULL },
 
  { NULL }
};

module redis_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "redis",

  /* Module configuration handler table */
  redis_conftab,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  redis_module_init,

  /* Session initialization function */
  redis_sess_init,

  /* Module version */
  MOD_REDIS_VERSION
};
