/*
 * ProFTPD: mod_ctrls_admin -- a module implementing admin control handlers
 *
 * Copyright (c) 2000-2003 TJ Saunders
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
 * This is mod_controls, contrib software for proftpd 1.2 and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 *
 * $Id: mod_ctrls_admin.c,v 1.4 2003-11-12 19:14:23 castaglia Exp $
 */

#include "conf.h"
#include "privs.h"
#include "mod_ctrls.h"

#define MOD_CTRLS_ADMIN_VERSION		"mod_ctrls_admin/0.9.2"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001020902
# error "ProFTPD 1.2.9rc2 or later required"
#endif

/* Values for the stop flags */
#define CTRL_STOP_DEFAULT     (1 << 0)
#define CTRL_STOP_CLEAN       (1 << 1)
#define CTRL_STOP_FULL        (1 << 2)
#define CTRL_STOP_GRACEFUL    (1 << 3)

/* from src/dirtree.c */
extern xaset_t *server_list;

module ctrls_admin_module;
static ctrls_acttab_t ctrls_admin_acttab[];

/* Pool for this module's use */
static pool *ctrls_admin_pool = NULL;

/* For debugging, both config and memory */
static pr_ctrls_t *ctrls_debug_ctrl = NULL;

/* Support routines
 */

static void ctrls_admin_printf(const char *fmt, ...) {
  char buf[PR_TUNABLE_BUFFER_SIZE] = {'\0'};
  va_list msg;

  va_start(msg, fmt);
  vsnprintf(buf, sizeof(buf), fmt, msg);
  va_end(msg);

  buf[sizeof(buf)-1] = '\0';

  pr_ctrls_add_response(ctrls_debug_ctrl, "%s", buf);
}

#if 0
/* Will be used when scheduled shutdowns are supported.. */
static unsigned char isnumeric(char *str) {
  while (str && isspace((int) *str))
    str++;

  if (!str || !*str)
    return FALSE;

  for (; str && *str; str++) {
    if (!isdigit((int) *str))
      return TRUE;
  }

  return 1;
}
#endif

static int respcmp(const void *a, const void *b) {
  return strcmp(*((char **) a), *((char **) b));
}

/* Controls handlers
 */

static int ctrls_handle_debug(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {

  /* Check the debug ACL */
  if (!ctrls_check_acl(ctrl, ctrls_admin_acttab, "debug")) {

    /* Access denied */
    pr_ctrls_add_response(ctrl, "access denied");
    return -1;
  }

  /* Sanity check */
  if (reqargc == 0 || reqargv == NULL) {
    pr_ctrls_add_response(ctrl, "debug: missing required parameters");
    return -1;
  }

  /* Handle 'debug level' requests */
  if (strcmp(reqargv[0], "level") == 0) {
    int level = 0;

    if (reqargc != 2) {
      pr_ctrls_add_response(ctrl, "debug: missing required parameters");
      return -1;
    }

    if ((level = atoi(reqargv[1])) < 0) {
      pr_ctrls_add_response(ctrl, "debug level must not be negative");
      return -1; 
    }
  
    pr_log_setdebuglevel(level);
    ctrls_log(MOD_CTRLS_ADMIN_VERSION, "debug: level set to %d", level);
    pr_ctrls_add_response(ctrl, "debug level set to %d", level);

  /* Handle 'debug config' requests */
  } else if (strcmp(reqargv[0], "config") == 0) {

    ctrls_debug_ctrl = ctrl;
    pr_conf_debug_config(ctrls_admin_printf, main_server->conf, NULL);

    pr_ctrls_add_response(ctrl, "%s", "");
    pr_ctrls_add_response(ctrl, "config dumped");

  /* Handle 'debug memory' requests */
  } else if (strcmp(reqargv[0], "memory") == 0) {

    ctrls_debug_ctrl = ctrl;
    pr_pool_debug_memory(ctrls_admin_printf);

    pr_ctrls_add_response(ctrl, "memory dumped");

  } else {
    pr_ctrls_add_response(ctrl, "unknown debug action: '%s'", reqargv[0]);
    return -1;
  }

  return 0;
}

/* From src/modules.c */
extern conftable *m_conftable;
extern unsigned int n_conftabs;

static int ctrls_handle_get(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {
  int res = 0;

  /* Sanity check */
  if (reqargc == 0 || reqargv == NULL) {
    pr_ctrls_add_response(ctrl, "get: missing required parameters");
    return -1;
  }

  /* Handle 'get config' requests */
  if (strcmp(reqargv[0], "config") == 0) {
    if (reqargc >= 2) {
      register int i = 0;

      for (i = 1; i < reqargc; i++) {
        config_rec *c = NULL;

        /* NOTE: there are some directives that are not stored as config_recs,
         * but rather as static variables or as members of other structs.
         * Handle these exceptions as well?  These include ServerName,
         * ServerType, ServerAdmin, etc.  How to handle configs that should
         * be retrievable, but are Boolean values instead of strings.  Hmmm.
         */

        if ((c = find_config(main_server->conf, CONF_PARAM, reqargv[i],
            FALSE)) != NULL) {

#if 0
          /* Not yet supported */
          if (c->flags & CF_GCTRL)
            pr_ctrls_add_response(ctrl, "%s: %s", reqargv[i],
              (char *) c->argv[0]);
          else
#endif
            pr_ctrls_add_response(ctrl, "%s: not retrievable", reqargv[i]);

        } else
          pr_ctrls_add_response(ctrl, "%s: directive not found", reqargv[i]);
      }

    } else {
      pr_ctrls_add_response(ctrl, "%s: missing parameters", reqargv[0]);
      res = -1;
    }

  } else if (strcmp(reqargv[0], "directives") == 0) {

    if (reqargc == 1) {
      register unsigned int i = 0;

      /* Create a list of all known configuration directives. */
      for (i = 0; i < n_conftabs; i++) {
        conftable conftab = m_conftable[i];

        if (!conftab.directive)
          continue;

        pr_ctrls_add_response(ctrl, "%s (mod_%s.c)", conftab.directive,
          conftab.m->name);

        /* Be nice, and sort the directives lexicographically */
        qsort(ctrl->ctrls_cb_resps->elts, ctrl->ctrls_cb_resps->nelts,
          sizeof(char *), respcmp);
      }

    } else {
      pr_ctrls_add_response(ctrl, "%s: wrong number of parameters", reqargv[0]);
      res = -1;
    }

  } else {
    pr_ctrls_add_response(ctrl, "unknown get type requested: '%s'", reqargv[0]);
    res = -1;
  }

  return res;
}

static int ctrls_handle_restart(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {

  /* Check the restart ACL */
  if (!ctrls_check_acl(ctrl, ctrls_admin_acttab, "restart")) {

    /* Access denied */
    pr_ctrls_add_response(ctrl, "access denied");
    return -1;
  }

  /* Be pedantic */
  if (reqargc != 0) {
    pr_ctrls_add_response(ctrl, "bad number of arguments");
    return -1;
  }

  PRIVS_ROOT
  raise(SIGHUP);
  PRIVS_RELINQUISH

  pr_ctrls_add_response(ctrl, "restarted server");
  return 0;
}

static int ctrls_handle_set(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {

  /* Sanity check */
  if (reqargc == 0 || reqargv == NULL) {
    pr_ctrls_add_response(ctrl, "set: missing required parameters");
    return -1;
  }

  pr_ctrls_add_response(ctrl, "set action currently unsupported");
  return 0;
}

static int ctrls_handle_shutdown(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {
  register unsigned int i = 0;
  int respargc = 0;
  char **respargv = NULL;

  /* Check the shutdown ACL */
  if (!ctrls_check_acl(ctrl, ctrls_admin_acttab, "shutdown")) {

    /* Access denied */
    pr_ctrls_add_response(ctrl, "access denied");
    return -1;
  }

  /* Sanity check */
  if (reqargc != 0 || reqargv != NULL) {
    pr_ctrls_add_response(ctrl, "wrong number of parameters");
    return -1;
  }

  /* Add a response */
  pr_ctrls_add_response(ctrl, "shutting down");

  /* This is one of the rare cases where the control handler needs to
   * flush the responses out to the client manually, rather than waiting
   * for the normal controls cycle to handle it, as this handler is
   * not going to exit the function normally.
   */

  respargc = ctrl->ctrls_cb_resps->nelts;
  respargv = ctrl->ctrls_cb_resps->elts;

  /* Manually tweak the return value, for the benefit of the client */
  ctrl->ctrls_cb_retval = 0;

  if (pr_ctrls_flush_response(ctrl) < 0)
    ctrls_log(MOD_CTRLS_ADMIN_VERSION,
      "shutdown: error flushing response: %s", strerror(errno));

  /* For logging/accounting purposes */
  ctrls_log(MOD_CTRLS_ADMIN_VERSION,
    "shutdown: flushed to %s/%s client: return value: 0",
    ctrl->ctrls_cl->cl_user, ctrl->ctrls_cl->cl_group);

  for (i = 0; i < respargc; i++)
    ctrls_log(MOD_CTRLS_ADMIN_VERSION,
      "shutdown: flushed to %s/%s client: '%s'",
      ctrl->ctrls_cl->cl_user, ctrl->ctrls_cl->cl_group, respargv[i]);

  /* For this control action to handle a 'graceful' option (see Bug#2034),
   * we'll need some core changes.  Specifically, there needs to be an API
   * for accessing the pidrec list maintained in src/main.c.
   *
   * I'm thinking that a separate src/child.c, pr_child_t object, and
   * pr_child_add()/pr_child_get()/pr_child_del() API would suffice.
   *
   * In addition, we'd need a way to tell the daemon to not accept
   * any more connections.  Similar to a shutmsg file in a way, but this
   * can be done internally, since this function executes within the
   * context of the daemon process.  Actually...we don't need to do
   * anything.  As long as this function doesn't return (or get interrupted),
   * the daemon process (us) will never return accepting clients.
   *
   * So, we just need to loop through the children, waiting for them all
   * end.  How long do we wait?
   */

  /* Shutdown by raising SIGTERM.  Easy. */
  raise(SIGTERM);

  return 0;
}

static int admin_start_addr(pr_ctrls_t *ctrl, pr_netaddr_t *addr,
    unsigned int port) {
  pr_ipbind_t *ipbind = NULL;
  int res = 0;

  /* Fetch the ipbind associated with this address/port. */
  ipbind = pr_ipbind_find(addr, port, FALSE);
  if (ipbind == NULL) {
    pr_ctrls_add_response(ctrl,
      "start: no server associated with %s#%u", pr_netaddr_get_ipstr(addr),
      port);
    return -1;
  }

  /* If this ipbind is already active, abort now. */
  if (ipbind->ib_isactive) {
    pr_ctrls_add_response(ctrl, "start: %s#%u already started",
      pr_netaddr_get_ipstr(addr), port);
    return 0;
  }

  /* Determine whether this server_rec needs a listening connection
   * created.  A ServerType of SERVER_STANDALONE combined with a
   * SocketBindTight means each server_rec will have its own listen
   * connection; any other combination means that all the server_recs
   * share the same listen connection.
   */
  if (ipbind->ib_server->ServerPort && !ipbind->ib_server->listen) {
    ipbind->ib_server->listen =
      pr_inet_create_connection(ipbind->ib_server->pool, server_list, -1,
      (SocketBindTight ? ipbind->ib_server->addr : NULL),
      ipbind->ib_server->ServerPort, FALSE);
  }

  ctrls_log(MOD_CTRLS_ADMIN_VERSION, "start: attempting to start %s#%u",
    pr_netaddr_get_ipstr(addr), port);

  PR_OPEN_IPBIND(ipbind->ib_server->addr, ipbind->ib_server->ServerPort,
    ipbind->ib_server->listen, FALSE, FALSE, TRUE);

  if (res < 0)
    pr_ctrls_add_response(ctrl, "start: no server listening on %s#%u",
      pr_netaddr_get_ipstr(addr), port);
  else
    pr_ctrls_add_response(ctrl, "start: %s#%u started",
      pr_netaddr_get_ipstr(addr), port);

  PR_ADD_IPBINDS(ipbind->ib_server);

  return 0;
}

static int ctrls_handle_start(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {
  register unsigned int i = 0;

  /* Handle scheduled starts of virtual servers in the future, and
   * cancellations of scheduled starts.
   */

  /* Check the start ACL */
  if (!ctrls_check_acl(ctrl, ctrls_admin_acttab, "start")) {

    /* Access denied */
    pr_ctrls_add_response(ctrl, "access denied");
    return -1;
  }

  /* Sanity check */
  if (reqargc < 1 || reqargv == NULL) {
    pr_ctrls_add_response(ctrl, "start: missing required parameters");
    return -1;
  }

  for (i = 0; i < reqargc; i++) { 
    unsigned int server_port = 21;
    char *server_str = reqargv[i], *tmp = NULL;
    pr_netaddr_t *server_addr = NULL;
    array_header *addrs = NULL;

    tmp = strchr(server_str, '#');
    if (tmp != NULL) {
      server_port = atoi(tmp + 1);
      *tmp = '\0';
    }

    if ((server_addr = pr_netaddr_get_addr(ctrl->ctrls_tmp_pool,
        server_str, &addrs)) == NULL) {
      pr_ctrls_add_response(ctrl, "start: unable to resolve address for '%s'",
        server_str);
      return -1;
    }

    if (admin_start_addr(ctrl, server_addr, server_port) < 0)
      return -1;

    if (addrs) {
      register unsigned int j;
      pr_netaddr_t **elts = addrs->elts;

      for (j = 0; j < addrs->nelts; j++)
        if (admin_start_addr(ctrl, elts[j], server_port) < 0)
          return -1;
    }
  }

  return 0;
}

static int admin_status_addr(pr_ctrls_t *ctrl, pr_netaddr_t *addr,
    unsigned int port) {
  pr_ipbind_t *ipbind = NULL;

  ctrls_log(MOD_CTRLS_ADMIN_VERSION, "status: checking %s#%u",
    pr_netaddr_get_ipstr(addr), port);

  /* Fetch the ipbind associated with this address/port. */
  ipbind = pr_ipbind_find(addr, port, FALSE);
  if (ipbind == NULL) {
    pr_ctrls_add_response(ctrl,
      "status: no server associated with %s#%u", pr_netaddr_get_ipstr(addr),
      port);
    return -1;
  }

  pr_ctrls_add_response(ctrl, "status: %s#%u %s", pr_netaddr_get_ipstr(addr),
    port, ipbind->ib_isactive ? "RUNNING" : "STOPPED");

  return 0;
}

static int ctrls_handle_status(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {
  register unsigned int i = 0;

  /* Check the status ACL. */
  if (!ctrls_check_acl(ctrl, ctrls_admin_acttab, "status")) {

    /* Access denied. */
    pr_ctrls_add_response(ctrl, "access denied");
    return -1;
  }

  /* Sanity check */ 
  if (reqargc < 1 || reqargv == NULL) {
    pr_ctrls_add_response(ctrl, "status: missing required parameters");
    return -1;
  }

  for (i = 0; i < reqargc; i++) {
    unsigned int server_port = 21;
    char *server_str = reqargv[i], *tmp = NULL;
    pr_netaddr_t *server_addr = NULL;
    array_header *addrs = NULL;

    /* Check for an argument of "all" */
    if (strcasecmp(server_str, "all") == 0) {
      pr_ipbind_t *ipbind = NULL;

      ctrls_log(MOD_CTRLS_ADMIN_VERSION, "status: checking all servers");

      while ((ipbind = pr_ipbind_get(ipbind)) != NULL) {
        const char *ipbind_str = pr_netaddr_get_ipstr(ipbind->ib_addr); 

        pr_ctrls_add_response(ctrl, "status: %s#%u %s", ipbind_str,
          ipbind->ib_port, ipbind->ib_isactive ? "RUNNING" : "STOPPED");
      }

      return 0;
    }

    tmp = strchr(server_str, '#');
    if (tmp != NULL) {
      server_port = atoi(tmp + 1);
      *tmp = '\0';
    }

    server_addr = pr_netaddr_get_addr(ctrl->ctrls_tmp_pool, server_str, &addrs);

    if (!server_addr) {
      pr_ctrls_add_response(ctrl, "status: no such server: %s#%u",
        server_str, server_port);
      continue;
    }

    if (admin_status_addr(ctrl, server_addr, server_port) < 0)
      continue;

    if (addrs) {
      register unsigned int j;
      pr_netaddr_t **elts = addrs->elts;

      for (j = 0; j < addrs->nelts; j++)
        admin_status_addr(ctrl, elts[j], server_port);
    }
  }

  return 0;
}

static int admin_stop_addr(pr_ctrls_t *ctrl, pr_netaddr_t *addr,
    unsigned int port) {

  ctrls_log(MOD_CTRLS_ADMIN_VERSION, "stop: stopping %s:%u",
    pr_netaddr_get_ipstr(addr), port);

  if (pr_ipbind_close(addr, port, FALSE) < 0) {
    if (errno == ENOENT)
      pr_ctrls_add_response(ctrl, "stop: no such server: %s:%u",
        pr_netaddr_get_ipstr(addr), port);
    else
      pr_ctrls_add_response(ctrl, "stop: %s:%u already stopped",
        pr_netaddr_get_ipstr(addr), port);

  } else
    pr_ctrls_add_response(ctrl, "stop: %s:%u stopped",
      pr_netaddr_get_ipstr(addr), port);

  return 0;
}

static int ctrls_handle_stop(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {
  register unsigned int i = 0;

  /* Handle scheduled stops of virtual servers in the future, and
   * cancellations of scheduled stops.
   */

  /* Check the stop ACL */
  if (!ctrls_check_acl(ctrl, ctrls_admin_acttab, "stop")) {

    /* Access denied */
    pr_ctrls_add_response(ctrl, "access denied");
    return -1;
  }

  /* Sanity check */
  if (reqargc < 1 || reqargv == NULL) {
    pr_ctrls_add_response(ctrl, "stop: missing required parameters");
    return -1;
  }

  for (i = 0; i < reqargc; i++) {
    unsigned int server_port = 21;
    char *server_str = reqargv[i], *tmp = NULL;
    pr_netaddr_t *server_addr = NULL;
    array_header *addrs = NULL;

    /* Check for an argument of "all" */
    if (strcasecmp(server_str, "all") == 0) {
      pr_ipbind_close(NULL, 0, FALSE);
      pr_ctrls_add_response(ctrl, "stop: all servers stopped");
      return 0; 
    }

    tmp = strchr(server_str, '#');
    if (tmp != NULL) {
      server_port = atoi(tmp + 1);
      *tmp = '\0';
    }

    server_addr = pr_netaddr_get_addr(ctrl->ctrls_tmp_pool, server_str, &addrs);

    if (!server_addr) {
      pr_ctrls_add_response(ctrl, "stop: no such server: %s#%u",
        server_str, server_port);
      continue;
    }

    admin_stop_addr(ctrl, server_addr, server_port);

    if (addrs) {
      register unsigned int j;
      pr_netaddr_t **elts = addrs->elts;

      for (j = 0; j < addrs->nelts; j++)
        admin_stop_addr(ctrl, elts[j], server_port);
    }
  }

  return 0;
}

/* Configuration handlers
 */

/* usage: AdminControlsACLs actions|all allow|deny user|group list */
MODRET set_adminctrlsacls(cmd_rec *cmd) {
  char *bad_action = NULL, **actions = NULL;

  CHECK_ARGS(cmd, 4);
  CHECK_CONF(cmd, CONF_ROOT);

  /* We can cheat here, and use the ctrls_parse_acl() routine to
   * separate the given string...
   */
  actions = ctrls_parse_acl(cmd->tmp_pool, cmd->argv[1]);

  /* Check the second parameter to make sure it is "allow" or "deny" */
  if (strcmp(cmd->argv[2], "allow") != 0 &&
      strcmp(cmd->argv[2], "deny") != 0)
    CONF_ERROR(cmd, "second parameter must be 'allow' or 'deny'");

  /* Check the third parameter to make sure it is "user" or "group" */
  if (strcmp(cmd->argv[3], "user") != 0 &&
      strcmp(cmd->argv[3], "group") != 0)
    CONF_ERROR(cmd, "third parameter must be 'user' or 'group'");

  if ((bad_action = ctrls_set_module_acls(ctrls_admin_acttab,
      ctrls_admin_pool, actions, cmd->argv[2], cmd->argv[3],
      cmd->argv[4])) != NULL)
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown action: '",
      bad_action, "'", NULL));

  return HANDLED(cmd);
}

/* usage: AdminControlsEngine on|off|actions */
MODRET set_adminctrlsengine(cmd_rec *cmd) {
  int bool = -1;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if ((bool = get_boolean(cmd, 1)) != -1) {
    /* If bool is TRUE, there's no need to do anything.  If FALSE,
     * then unregister all the controls of this module.
     */
    if (!bool) {
      register unsigned int i = 0;

      for (i = 0; ctrls_admin_acttab[i].act_action; i++) {
        pr_ctrls_unregister(&ctrls_admin_module,
          ctrls_admin_acttab[i].act_action);
        destroy_pool(ctrls_admin_acttab[i].act_acl->acl_pool);
      }
    }

  } else {
    char *bad_action = NULL;

    /* Parse the given string of actions into a char **.  Then iterate
     * through the acttab, checking to see if a given control is _not_ in
     * the list.  If not in the list, unregister that control.
     */

    /* We can cheat here, and use the ctrls_parse_acl() routine to
     * separate the given string...
     */
    char **actions = ctrls_parse_acl(cmd->tmp_pool, cmd->argv[1]);

    if ((bad_action = ctrls_unregister_module_actions(ctrls_admin_acttab,
        actions, &ctrls_admin_module)) != NULL)   
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown action: '",
          bad_action, "'", NULL));
  }

  return HANDLED(cmd);
}

/* Event handlers
 */

static void ctrls_admin_restart_ev(const void *event_data, void *user_data) {

  if (ctrls_admin_pool)
    destroy_pool(ctrls_admin_pool);

  /* Allocate the pool for this module's use */
  ctrls_admin_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(ctrls_admin_pool, MOD_CTRLS_ADMIN_VERSION);

  return;
}

/* Initialization routines
 */

static int ctrls_admin_init(void) {
  register unsigned int i = 0;

  /* Allocate the pool for this module's use */
  ctrls_admin_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(ctrls_admin_pool, MOD_CTRLS_ADMIN_VERSION);

  /* Register the control handlers */
  for (i = 0; ctrls_admin_acttab[i].act_action; i++) {

    /* Allocate and initialize the ACL for this control. */
    ctrls_admin_acttab[i].act_acl = pcalloc(ctrls_admin_pool,
      sizeof(ctrls_acl_t));
    ctrls_init_acl(ctrls_admin_acttab[i].act_acl);

    if (pr_ctrls_register(&ctrls_admin_module,
        ctrls_admin_acttab[i].act_action, ctrls_admin_acttab[i].act_desc,
        ctrls_admin_acttab[i].act_cb) < 0)
     pr_log_pri(PR_LOG_INFO, MOD_CTRLS_ADMIN_VERSION
        ": error registering '%s' control: %s",
        ctrls_admin_acttab[i].act_action, strerror(errno));
  }

  pr_event_register(&ctrls_admin_module, "core.restart",
    ctrls_admin_restart_ev, NULL);

  return 0;
}

static ctrls_acttab_t ctrls_admin_acttab[] = {
  { "debug",    "perform debugging operations",	NULL,
    ctrls_handle_debug },
  { "get",      "",	NULL,
    ctrls_handle_get },
  { "restart",  "restart the daemon (similar to using HUP)",	NULL,
    ctrls_handle_restart },
  { "set",      "",	NULL,
    ctrls_handle_set },
  { "shutdown", "shutdown the daemon",	NULL,
    ctrls_handle_shutdown },
  { "start",	"enable a stopped virtual server",	NULL,
    ctrls_handle_start },
  { "status",	"display status of servers",		NULL,
    ctrls_handle_status },
  { "stop",     "disable an individual virtual server",	NULL,
    ctrls_handle_stop },
  { NULL, NULL,	NULL, NULL }
};

/* Module API tables
 */

static conftable ctrls_admin_conftab[] = {
  { "AdminControlsACLs",    	set_adminctrlsacls, 		NULL },
  { "AdminControlsEngine",	set_adminctrlsengine,		NULL },
  { NULL }
};

module ctrls_admin_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "ctrls_admin",

  /* Module configuration handler table */
  ctrls_admin_conftab,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  ctrls_admin_init,

  /* Session initialization function */
  NULL
};
