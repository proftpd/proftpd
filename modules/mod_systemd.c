/*
 * ProFTPD: mod_systemd -- provides systemd "socket activation" support
 * Copyright (c) 2025-2026 TJ Saunders
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
 * This is mod_systemd, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "conf.h"
#include "privs.h"

#define MOD_SYSTEMD_VERSION	"mod_systemd/0.3"

/* Make sure the version of ProFTPD is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030A01
# error "ProFTPD 1.3.10rc1 or later required"
#endif

extern char ServerType;

module systemd_module;

static int systemd_engine = TRUE;
static pid_t init_pid = 0;
static int syntax_check = FALSE;

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
  syntax_check = FALSE;
}
#endif /* PR_SHARED_MODULE */

static void systemd_postparse_ev(const void *event_data, void *user_data) {
  config_rec *c;

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

  /* If we have not already started up (via "core.startup" event), then
   * we are the initial process, prior to any possible daemonization.
   * Remember our current PID then, for comparison later, as a way of
   * determining whether we daemonized or not (Issue #2412).
   *
   * And if we happen to be reloading the module, storing our current PID
   * here will have no effect, but will not cause problems.
   */
  init_pid = getpid();
}

static void get_current_time(struct timespec *ts) {
  struct timeval tv;
#if defined(HAVE_CLOCK_GETTIME) && \
    defined(HAVE_CLOCK_MONOTONIC)
  if (clock_gettime(CLOCK_MONOTONIC, ts) == 0) {
    return;
  }
#endif /* HAVE_CLOCK_GETTIME and HAVE_CLOCK_MONOTONIC */

  gettimeofday(&tv, NULL);
  ts->tv_sec = tv.tv_sec;
  ts->tv_nsec = (long) tv.tv_usec * 1000;
}

static void systemd_restart_ev(const void *event_data, void *user_data) {
  struct timespec now;
  char text[1024];

  if (systemd_engine == FALSE) {
    return;
  }

  if (ServerType != SERVER_STANDALONE) {
    return;
  }

  get_current_time(&now);

  memset(text, '\0', sizeof(text));
  pr_snprintf(text, sizeof(text)-1, "RELOADING=1\nMONOTONIC_USEC=%llu",
    ((uint64_t) now.tv_sec * 1000000ULL) +
    ((uint64_t) now.tv_nsec / 1000ULL));
  notify_systemd(text);
}

static void systemd_restarted_ev(const void *event_data, void *user_data) {
  if (systemd_engine == FALSE) {
    return;
  }

  if (ServerType != SERVER_STANDALONE) {
    return;
  }

  notify_systemd("READY=1");
}

static void systemd_shutdown_ev(const void *event_data, void *user_data) {
  if (systemd_engine == FALSE) {
    return;
  }

  if (ServerType != SERVER_STANDALONE) {
    return;
  }

  if (syntax_check == FALSE) {
    notify_systemd("STOPPING=1");
  }

  syntax_check = FALSE;
}

static void systemd_startup_ev(const void *event_data, void *user_data) {
  char main_pid[1024];

  if (systemd_engine == FALSE) {
    return;
  }

  if (ServerType != SERVER_STANDALONE) {
    return;
  }

  /* If this event has been generated, then we are definitely NOT in a
   * syntax check only scenario.
   */
  syntax_check = FALSE;

  if (init_pid != getpid()) {
    int res;

    /* If we have daemonized, we need to wait for our parent process to
     * exit, so that the cgroup to which we belong is just us (see Issue #2412).
     */
    PRIVS_ROOT
    res = kill(init_pid, 0);
    PRIVS_RELINQUISH

    if (res == 0) {
      pr_trace_msg(trace_channel, 9,
        "due to daemonization, waiting for initial PID %lu to exit",
        (unsigned long) init_pid);

      while (res == 0) {
        pr_timer_usleep(250 * 1000);

        PRIVS_ROOT
        res = kill(init_pid, 0);
        PRIVS_RELINQUISH
      }
    }

    pr_trace_msg(trace_channel, 9, "initial PID %lu has exited",
      (unsigned long) init_pid);
    init_pid = 0;
  }

  memset(main_pid, '\0', sizeof(main_pid));
  pr_snprintf(main_pid, sizeof(main_pid)-1, "MAINPID=%lu\nREADY=1",
    (unsigned long) getpid());
  notify_systemd(main_pid);
}

static void systemd_syntax_check_ev(const void *event_data, void *user_data) {
  if (systemd_engine == FALSE) {
    return;
  }

  if (ServerType != SERVER_STANDALONE) {
    return;
  }

  pr_trace_msg(trace_channel, 19, "handling syntax check");
  syntax_check = TRUE;
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
  pr_event_register(&systemd_module, "core.restarted", systemd_restarted_ev,
    NULL);
  pr_event_register(&systemd_module, "core.shutdown", systemd_shutdown_ev,
    NULL);
  pr_event_register(&systemd_module, "core.startup", systemd_startup_ev,
    NULL);
  pr_event_register(&systemd_module, "core.syntax-check",
    systemd_syntax_check_ev, NULL);

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
