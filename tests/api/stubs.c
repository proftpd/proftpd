/*
 * ProFTPD - FTP server API testsuite
 * Copyright (c) 2008-2015 The ProFTPD Project team
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
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

#include "tests.h"

/* Stubs */

session_t session;

char ServerType = SERVER_STANDALONE;
int ServerUseReverseDNS = 1;
server_rec *main_server = NULL;
pid_t mpid = 1;
module *static_modules[] = { NULL };
module *loaded_modules = NULL;
xaset_t *server_list = NULL;

int tests_stubs_set_main_server(server_rec *s) {
  main_server = s;
  return 0;
}

char *dir_realpath(pool *p, const char *path) {
  return NULL;
}

int pr_cmd_dispatch(cmd_rec *cmd) {
  return 0;
}

int pr_cmd_read(cmd_rec **cmd) {
  *cmd = NULL;
  return 0;
}

int pr_config_get_server_xfer_bufsz(int direction) {
  int bufsz = -1;

  switch (direction) {
    case PR_NETIO_IO_RD:
      bufsz = PR_TUNABLE_DEFAULT_RCVBUFSZ;
      break;

    case PR_NETIO_IO_WR:
      bufsz = PR_TUNABLE_DEFAULT_SNDBUFSZ;
      break;

    default:
      errno = EINVAL;
      return -1;
  }

  return bufsz;
}

int pr_ctrls_unregister(module *m, const char *action) {
  return 0;
}

struct tm *pr_localtime(pool *p, const time_t *t) {
  return localtime(t);
}

void pr_log_debug(int level, const char *fmt, ...) {
  if (getenv("TEST_VERBOSE") != NULL) {
    va_list msg;

    fprintf(stderr, "DEBUG%d: ", level);

    va_start(msg, fmt);
    vfprintf(stderr, fmt, msg);
    va_end(msg);

    fprintf(stderr, "\n");
  }
}

int pr_log_event_generate(unsigned int log_type, int log_fd, int log_level,
    const char *log_msg, size_t log_msglen) {
  errno = ENOSYS;
  return -1;
}

int pr_log_event_listening(unsigned int log_type) {
  return FALSE;
}

void pr_log_pri(int prio, const char *fmt, ...) {
  if (getenv("TEST_VERBOSE") != NULL) {
    va_list msg;

    fprintf(stderr, "PRI%d: ", prio);

    va_start(msg, fmt);
    vfprintf(stderr, fmt, msg);
    va_end(msg);

    fprintf(stderr, "\n");
  }
}

int pr_log_openfile(const char *log_file, int *log_fd, mode_t log_mode) {
  *log_fd = STDERR_FILENO;
  return 0;
}

int pr_proctitle_get(char *buf, size_t buflen) {
  errno = ENOSYS;
  return -1;
}

void pr_proctitle_set(const char *fmt, ...) {
}

void pr_proctitle_set_str(const char *str) {
}

void pr_session_disconnect(module *m, int reason_code, const char *details) {
}

int pr_session_set_idle(void) {
  return 0;
}

void pr_signals_handle(void) {
}

void pr_signals_block(void) {
}

void pr_signals_unblock(void) {
}

int pr_timeval2millis(struct timeval *tv, uint64_t *millis) {
  if (tv == NULL ||
      millis == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Make sure to use 64-bit multiplication to avoid overflow errors,
   * as much as we can.
   */
  *millis = (tv->tv_sec * (uint64_t) 1000) + (tv->tv_usec / (uint64_t) 1000);
  return 0;
}

int pr_gettimeofday_millis(uint64_t *millis) {
  struct timeval tv;

  if (millis == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (gettimeofday(&tv, NULL) < 0) {
    return -1;
  }

  if (pr_timeval2millis(&tv, millis) < 0) {
    return -1;
  }

  return 0;
}

void run_schedule(void) {
}
