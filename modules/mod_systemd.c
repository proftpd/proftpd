/*
 * ProFTPD: mod_systemd -- provides systemd "socket activation" support
 * Copyright (c) 2025 TJ Saunders
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
 * This is mod_systemd, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "conf.h"
#include "privs.h"

#define MOD_SYSTEMD_VERSION	"mod_systemd/0.1"

/* Make sure the version of ProFTPD is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030A01
# error "ProFTPD 1.3.10rc1 or later required"
#endif

extern char ServerType;

module systemd_module;

static int systemd_engine = TRUE;
static int started_up = FALSE;

static const char *trace_channel = "systemd";

/* See the example implementation in the sd_notify(3) man page:
 *   https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html
 */
static void notify_systemd(const char *text) {
  const char *socket_path = NULL;
  struct sockaddr_un sock;
  int fd = -1, res;
  size_t text_len;

  socket_path = getenv("NOTIFY_SOCKET");
  if (socket_path == NULL ||
      strlen(socket_path) == 0) {
    pr_trace_msg(trace_channel, 9,
      "empty/missing NOTIFY_SOCKET environment variable, ignoring");
    return;
  }

  /* Only Unix domain sockets supported, either abstract or with concrete
   * paths.
   */
  if (socket_path[0] != '/' &&
      socket_path[0] != '@') {
    pr_trace_msg(trace_channel, 9,
      "ignoring non-Unix domain NOTIFY_SOCKET path '%s'", socket_path);
    return;
  }

  if (socket_path[0] == '/') {
    struct stat st;

    res = stat(socket_path, &st);
    if (res < 0) {
      pr_trace_msg(trace_channel, 3,
        "error checking Unix domain NOTIFY_SOCKET path '%s': %s", socket_path,
        strerror(errno));
      return;
    }
  }

  memset(&sock, 0, sizeof(sock));
  sock.sun_family = AF_UNIX;
  sstrncpy(sock.sun_path, socket_path, sizeof(sock.sun_path));

  /* Make sure we handle abstract socket paths. */
  if (sock.sun_path[0] == '@') {
    sock.sun_path[0] = '\0';
  }

  fd = socket(PF_UNIX, SOCK_DGRAM, 0);
  if (fd < 0) {
    pr_trace_msg(trace_channel, 3,
      "error creating Unix domain datagram socket: %s",
      strerror(errno));
    return;
  }

  res = connect(fd, (struct sockaddr *) &sock, sizeof(sock));
  if (res < 0) {
    pr_trace_msg(trace_channel, 3,
      "error connecting Unix domain datagram socket to '%s': %s",
      socket_path, strerror(errno));
    (void) close(fd);
    return;
  }

  text_len = strlen(text);
  res = write(fd, text, text_len);
  if (res < 0) {
    pr_trace_msg(trace_channel, 3,
      "error writing to Unix domain datagram socket '%s': %s",
      socket_path, strerror(errno));
    (void) close(fd);
    return;
  }

  if ((size_t) res != text_len) {
    /* A short write occurred unexpectedly. */
    pr_trace_msg(trace_channel, 3,
      "only wrote %d bytes of %lu message to Unix domain datagram socket '%s'",
      res, (unsigned long) text_len, socket_path);
    (void) close(fd);
    return;
  }

  pr_trace_msg(trace_channel, 9, "Unix domain socket '%s' notified: %s",
    socket_path, text);
  (void) close(fd);
}

/* Configuration handlers
 */

/* usage: SystemdEngine on|off */
MODRET set_systemdengine(cmd_rec *cmd) {
  int engine;
  config_rec *c;

  CHECK_CONF(cmd, CONF_ROOT);
  CHECK_ARGS(cmd, 1);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  return PR_HANDLED(cmd);
}

/* Event listeners
 */

#if defined(PR_SHARED_MODULE)
static void systemd_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_systemd.c", (const char *) event_data) != 0) {
    return;
  }

  pr_event_unregister(&systemd_module, NULL, NULL);
  systemd_engine = TRUE;
  started_up = FALSE;
}
#endif /* PR_SHARED_MODULE */

static void systemd_postparse_ev(const void *event_data, void *user_data) {
  config_rec *c;
  char main_pid[1024];

  c = find_config(main_server->conf, CONF_PARAM, "SystemdEngine", FALSE);
  if (c != NULL) {
    systemd_engine = *((int *) c->argv[0]);
  }

  if (systemd_engine == FALSE) {
    return;
  }

  if (ServerType != SERVER_STANDALONE) {
    return;
  }

  /* Note that this event is generated prior to writing out the PidFile,
   * at least on initial startup.  And that means that systemd won't be
   * able to read the PidFile, and thus won't know the "main PID", without
   * which, it gets fussy.
   *
   * To work around this, we notify systemd directly of the main PID.
   */
  memset(main_pid, '\0', sizeof(main_pid));
  pr_snprintf(main_pid, sizeof(main_pid)-1, "MAINPID=%lu",
    (unsigned long) getpid());
  notify_systemd(main_pid);

  notify_systemd("READY=1");
}

static void systemd_restart_ev(const void *event_data, void *user_data) {
  if (systemd_engine == FALSE) {
    return;
  }

  if (ServerType != SERVER_STANDALONE) {
    return;
  }

  notify_systemd("RELOADING=1");
}

static void systemd_shutdown_ev(const void *event_data, void *user_data) {
  if (systemd_engine == FALSE) {
    return;
  }

  if (ServerType != SERVER_STANDALONE) {
    return;
  }

  if (started_up == TRUE) {
    notify_systemd("STOPPING=1");
    started_up = FALSE;
  }
}

static void systemd_startup_ev(const void *event_data, void *user_data) {
  if (systemd_engine == FALSE) {
    return;
  }

  if (ServerType != SERVER_STANDALONE) {
    return;
  }

  /* Set a flag to indicate that the process did, in fact, start up.
   *
   * Why is this necessary?  During a syntax check, this startup event
   * will not happen, but the shutdown event will.  We want to notify
   * systemd when we are shutting down, but only if we started up in the
   * first place and not, for example, after doing just a syntax check.
   */
  started_up = TRUE;
}

/* Initialization routines
 */

static int systemd_init(void) {
#if defined(PR_SHARED_MODULE)
  pr_event_register(&systemd_module, "core.module-unload",
    systemd_mod_unload_ev, NULL);
#endif /* PR_SHARED_MODULE */
  pr_event_register(&systemd_module, "core.postparse", systemd_postparse_ev,
    NULL);
  pr_event_register(&systemd_module, "core.restart", systemd_restart_ev,
    NULL);
  pr_event_register(&systemd_module, "core.shutdown", systemd_shutdown_ev,
    NULL);
  pr_event_register(&systemd_module, "core.startup", systemd_startup_ev,
    NULL);

  return 0;
}

/* Module API tables
 */

static conftable systemd_conftab[] = {
  { "SystemdEngine",	set_systemdengine,	NULL },
  { NULL }
};

module systemd_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "systemd",

  /* Module configuration handler table */
  systemd_conftab,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  systemd_init,

  /* Session initialization function */
  NULL,

  /* Module version */
  MOD_SYSTEMD_VERSION
};
