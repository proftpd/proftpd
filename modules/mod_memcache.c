/*
 * ProFTPD: mod_memcache -- a module for managing memcache data
 *
 * Copyright (c) 2010 The ProFTPD Project
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
 * $Libraries: -lmemcached$
 * $Id: mod_memcache.c,v 1.2 2010-03-14 00:47:31 castaglia Exp $
 */

#include "conf.h"
#include "privs.h"
#include <libmemcached/memcached.h>

#define MOD_MEMCACHE_VERSION		"mod_memcache/0.1"

#if PROFTPD_VERSION_NUMBER < 0x0001030401
# error "ProFTPD 1.3.4rc1 or later required"
#endif

extern xaset_t *server_list;

module memcache_module;

static int memcache_logfd = -1;

/* Configuration handlers
 */

/* usage: MemcacheEngine on|off */
MODRET set_memcacheengine(cmd_rec *cmd) {
  int b = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  b = get_boolean(cmd, 1);
  if (b == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = b;

  return PR_HANDLED(cmd);
}

/* usage: MemcacheLog path|"none" */
MODRET set_memcachelog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (strcasecmp(cmd->argv[1], "none") != 0 &&
      pr_fs_valid_path(cmd->argv[1]) < 0) {
    CONF_ERROR(cmd, "must be an absolute path");
  }

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: MemcacheServers host1[:port1] ... */
MODRET set_memcacheservers(cmd_rec *cmd) {
  register unsigned int i;
  config_rec *c;
  char *str = "";
  memcached_server_st *memcache_servers;

  if (cmd->argc-1 < 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);
  for (i = 1; i < cmd->argc; i++) {
    str = pstrcat(cmd->tmp_pool, str, *str ? ", " : "", cmd->argv[i], NULL);
  }

  memcache_servers = memcached_servers_parse(str);
  if (memcache_servers == NULL) {
    CONF_ERROR(cmd, "unable to parse server parameters");
  }

  c->argv[0] = memcache_servers;
  return PR_HANDLED(cmd);
}

/* Event handlers
 */

static void memcache_restart_ev(const void *event_data, void *user_data) {
  server_rec *s;

  for (s = (server_rec *) server_list->xas_list; s; s = s->next) {
    config_rec *c;

    c = find_config(s->conf, CONF_PARAM, "MemcacheServers", FALSE);
    if (c) {
      memcached_server_st *memcache_servers;

      memcache_servers = c->argv[0];
      memcached_server_list_free(memcache_servers);
    }
  }
}

/* Initialization functions
 */

static int memcache_init(void) {
  pr_event_register(&memcache_module, "core.restart", memcache_restart_ev,
    NULL);
  return 0;
}

static int memcache_sess_init(void) {
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "MemcacheLog", FALSE);
  if (c) {
    const char *path;

    path = c->argv[0];
    if (strcasecmp(path, "none") != 0) {
      int res;

      pr_signals_block();
      PRIVS_ROOT
      res = pr_log_openfile(path, &memcache_logfd, 0600);
      PRIVS_RELINQUISH
      pr_signals_unblock();

      switch (res) {
        case 0:
          memcache_set_logfd(memcache_logfd);
          break;

        case -1:
          pr_log_pri(PR_LOG_NOTICE, MOD_MEMCACHE_VERSION
            ": notice: unable to open MemcacheLog '%s': %s", path,
            strerror(errno));

        case PR_LOG_WRITABLE_DIR:
          pr_log_pri(PR_LOG_NOTICE, MOD_MEMCACHE_VERSION
            ": notice: unable to use MemcacheLog '%s': parent directory is "
              "world-writeable", path);

        case PR_LOG_SYMLINK:
          pr_log_pri(PR_LOG_NOTICE, MOD_MEMCACHE_VERSION
            ": notice: unable to use MemcacheLog '%s': cannot log to a symlink",
            path);
      }
    }
  }

  c = find_config(main_server->conf, CONF_PARAM, "MemcacheEngine", FALSE);
  if (c) {
    int engine;

    engine = *((int *) c->argv[0]);
    if (engine == FALSE) {
      /* Explicitly disable memcache support for this session */
      memcache_set_servers(NULL);
    }

    return 0;
  }

  c = find_config(main_server->conf, CONF_PARAM, "MemcacheServers", FALSE);
  if (c) {
    memcached_server_st *memcache_servers;

    memcache_servers = c->argv[0]; 
    memcache_set_servers(memcache_servers);
  }

  return 0;
}

/* Module API tables
 */

static conftable memcache_conftab[] = {
  { "MemcacheEngine",	set_memcacheengine,	NULL },
  { "MemcacheLog",	set_memcachelog,	NULL },
  { "MemcacheServers",	set_memcacheservers,	NULL },

  { NULL }
};

module memcache_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "memcache",

  /* Module configuration handler table */
  memcache_conftab,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  memcache_init,

  /* Session initialization function */
  memcache_sess_init,

  /* Module version */
  MOD_MEMCACHE_VERSION
};
