/*
 * ProFTPD: mod_exec_mqueue -- a module for sending messages via IPC
 * Copyright (c) 2018 Joshua Megerman
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
 * This is mod_exec_mqueue, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "conf.h"
#include "privs.h"
#include "mod_exec.h"

#include <sys/ipc.h>
#include <sys/msg.h>

#define MOD_EXEC_MQUEUE_VERSION	"mod_exec_mqueue/0.9.0"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030402
# error "ProFTPD 1.3.4rc2 or later required"
#endif

module exec_mqueue_module;
extern xaset_t *server_list;

static int exec_mqueue_logfd = -1;
static char *exec_mqueue_logname = NULL;
static const char *trace_channel = "exec";

static int exec_mqueue_timeout_triggered = FALSE;

/* Message defaults */
#define DEFAULT_MSGTYPE 1L
#define MAX_MESSAGE_SIZE (1024 - sizeof(long))

/* This corresponds to a struct msgbuf from <sys/msg.h> */
typedef struct EventMessage {
  long mtype;
  char buf[MAX_MESSAGE_SIZE];
} EventMessage;


/* End msg stuff */

/* Prototypes */
static int exec_mqueue_log(const char *, ...)
#ifdef __GNUC__
      __attribute__ ((format (printf, 1, 2)));
#else
      ;
#endif
static int exec_mqueue_sess_init(void);

/* Support routines
 */

static int exec_mqueue_closelog(void) {
  /* sanity check */
  if (exec_mqueue_logfd != -1) {
    close(exec_mqueue_logfd);
    exec_mqueue_logfd = -1;
    exec_mqueue_logname = NULL;
  }

  return 0;
}

static int exec_mqueue_log(const char *fmt, ...) {
  va_list msg;
  int res;

  if (!exec_mqueue_logname)
    return 0;

  va_start(msg, fmt);
  res = pr_log_vwritefile(exec_mqueue_logfd, MOD_EXEC_MQUEUE_VERSION, fmt, msg);
  va_end(msg);
  
  return res;
}

static int exec_mqueue_openlog(void) {
  int res = 0;

  /* Sanity check */
  exec_mqueue_logname = (char *) get_param_ptr(main_server->conf, "ExecLog", FALSE);
  if (exec_mqueue_logname == NULL)
    return 0;

  /* Check for "none". */
  if (strncasecmp(exec_mqueue_logname, "none", 5) == 0) {
    exec_mqueue_logname = NULL;
    return 0;
  }

  pr_signals_block();
  PRIVS_ROOT
  res = pr_log_openfile(exec_mqueue_logname, &exec_mqueue_logfd, PR_LOG_SYSTEM_MODE);
  PRIVS_RELINQUISH
  pr_signals_unblock();

  return res;
}

static int exec_mqueue_timeout_cb(CALLBACK_FRAME) {
  exec_mqueue_timeout_triggered = TRUE;
  pr_trace_msg(trace_channel, 8, "msgsnd timed out");

  return 0;
}

/* Send messages via IPC instead of executing commands to get around chroot(2)
 * limitations.
 */
static int exec_mqueue_smessage(cmd_rec *cmd, config_rec *c, int flags) {
  int status, i, j, mqid, xerrno, timerno;
  int exec_mqueue_timeout = 0, format = 0;
  EventMessage msgbuf;
  char buf[MAX_MESSAGE_SIZE], *p, *endptr = NULL;
  int c_remain = MAX_MESSAGE_SIZE-1;
  void *ptr;

  ptr = get_param_ptr(main_server->conf, "ExecMqueueKey", FALSE);
  if (ptr == NULL) {
    exec_mqueue_log("no message queue key specified");
    return EINVAL;
  }
  if ((mqid = msgget(*((key_t *)ptr), IPC_CREAT | 0660)) == -1) {
    xerrno = errno;
    exec_mqueue_log("couldn't get message queue: %s", strerror(xerrno));
    return xerrno;
  }

  msgbuf.mtype = 0;
  *msgbuf.buf = *buf = 0;

  p = (char *)(c->argv[2]) + 7; // after 'mqueue:'
  if (*p != '\0') {
    errno = 0;
    i = strtoul(p, &endptr, 0);
    xerrno = errno;
    if ((*endptr == '\0') && !xerrno && (i > 0)) {
      msgbuf.mtype = i;
      exec_mqueue_log("message type %d specified in command", i);
    }
  }
  if (msgbuf.mtype == 0) {
    ptr = get_param_ptr(CURRENT_CONF, "ExecMqueueType", FALSE);
    if (ptr == NULL) {
      exec_mqueue_log("warning: no message type specified - defaulting to %ld", DEFAULT_MSGTYPE);
      msgbuf.mtype = DEFAULT_MSGTYPE;
    } else {
      msgbuf.mtype = *((long *)ptr);
    }
  }

  /* Determine the message format (and potentially maximum size) */
  ptr = get_param_ptr(main_server->conf, "ExecMqueueFormat", FALSE);
  if (ptr && (*((int *)ptr) == 1)) {
    /* "ncftpd" format */
    format = 1;
    c_remain = 999;
  }

  /* Perform any required substitution on the command arguments. */
  pool *tmp_pool = cmd ? cmd->tmp_pool : make_sub_pool(session.pool);
  for (i = 3; i < c->argc; i++) {
    pr_signals_handle();
    if (!c->argv[i])
      break;
    c->argv[i] = (void *) exec_subst_var(tmp_pool, c->argv[i], cmd);
    p = (char *) c->argv[i];
    j = strlen(p);
    if ((j+1) > c_remain) {
      exec_mqueue_log("error: message is too big");
      return(EMSGSIZE);
    } else {
      strncat(buf, p, c_remain);
      c_remain -= j;
      strncat(buf, "\n", c_remain--);
    }
  }
  if (cmd == NULL) {
    destroy_pool(tmp_pool);
  }

  /* finish generating the message */
  if (format == 1) {
    sprintf(msgbuf.buf, "STR\n%3d\n", (int)strlen(buf));
  }
  strncat(msgbuf.buf, buf, MAX_MESSAGE_SIZE-strlen(msgbuf.buf)-1);
  
  ptr = get_param_ptr(main_server->conf, "ExecMqueueTimeout", FALSE);
  if (ptr) {
    exec_mqueue_timeout = *((int *)ptr);
  }

  exec_mqueue_timeout_triggered = FALSE;
  if (exec_mqueue_timeout) {
    timerno = pr_timer_add(exec_mqueue_timeout, -1, &exec_mqueue_module, exec_mqueue_timeout_cb, "msgsnd");
    if (timerno <= 0) {
      xerrno = errno;
      pr_trace_msg(trace_channel, 8, "error adding timer: %s", strerror(xerrno));
      return xerrno;
    }
  }

  status = msgsnd(mqid, &msgbuf, strlen(msgbuf.buf)+1, 0);
  xerrno = errno;
  pr_trace_msg(trace_channel, 10, "msgsnd returned: %s", strerror(xerrno));
  if (exec_mqueue_timeout) {
    pr_timer_remove(timerno, &exec_mqueue_module);
  }
  if (status == -1) {
    status = xerrno;
    if (exec_mqueue_timeout_triggered) {
      exec_mqueue_log("message timed out: %s", strerror(status));
    } else {
      exec_mqueue_log("couldn't send message: %s", strerror(status));
    }
  } else {
  }

  return status;
}

/* usage: ExecMqueueKey <queue id> */
MODRET set_execmqueuekey(cmd_rec *cmd) {
  int xerrno;
  config_rec *c;
  long mqkey = 0;
  char *endptr = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  errno = 0;
  mqkey = strtol(cmd->argv[1], &endptr, 0);
  xerrno = errno;

  if (*endptr != '\0') {
    CONF_ERROR(cmd, "requires a numeric argument");
  }

  if ((xerrno == ERANGE) || (mqkey > INT_MAX) || (mqkey < INT_MIN)) {
    CONF_ERROR(cmd, "the value given is outside the legal range");
  }

  if (!mqkey) {
    CONF_ERROR(cmd, "the value given must be non-zero");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(key_t));
  *((key_t *) c->argv[0]) = (key_t)mqkey;

  return PR_HANDLED(cmd);
}

/* usage: ExecMqueueType <message type> */
MODRET set_execmqueuetype(cmd_rec *cmd) {
  int xerrno;
  config_rec *c;
  long msgtype = 0;
  char *endptr = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|
    CONF_DIR);

  errno = 0;
  msgtype = strtoul(cmd->argv[1], &endptr, 0);
  xerrno = errno;

  if (*endptr != '\0') {
    CONF_ERROR(cmd, "requires a numeric argument");
  }

  if ((xerrno == ERANGE) || (msgtype > UINT_MAX)) {
    CONF_ERROR(cmd, "the value given is outside the legal range");
  }

  if (!msgtype) {
    CONF_ERROR(cmd, "the value given must be greater than zero");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(long));
  *((long *) c->argv[0]) = (long)msgtype;
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* usage: ExecMqueueFormat <message type> */
MODRET set_execmqueueformat(cmd_rec *cmd) {
  config_rec *c;
  int format = 0;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (!strcmp(cmd->argv[1], "ncftpd")) {
    format = 1;
  } else if (strcmp(cmd->argv[1], "raw")) {
    CONF_ERROR(cmd, "invalid format - the supported formats are 'raw' and 'ncftpd'");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = (int)format;

  return PR_HANDLED(cmd);
}

/* usage: ExecMqueueTimeout <seconds> */
MODRET set_execmqueuetimeout(cmd_rec *cmd) {
  int timeout = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (pr_str_get_duration(cmd->argv[1], &timeout) < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error parsing timeout value '",
      cmd->argv[1], "': ", strerror(errno), NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = timeout;

  return PR_HANDLED(cmd);
}

/* usage: ExecMqueueCleanup on|off */
MODRET set_execmqueuecleanup(cmd_rec *cmd) {
  int cleanup = -1;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  cleanup = get_boolean(cmd, 1);
  if (cleanup == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = cleanup;

  return PR_HANDLED(cmd);
}

/* Event handlers
 */

#if defined(PR_SHARED_MODULE)
static void exec_mqueue_mod_unload_ev(const void *event_data, void *user_data) {
  if (strncmp("mod_exec_mqueue.c", (const char *) event_data, 11) == 0) {

    pr_event_unregister(&exec_mqueue_module, NULL, NULL);

    exec_mqueue_closelog();
  }
}
#endif /* PR_SHARED_MODULE */

static void exec_mqueue_postparse_ev(const void *event_data, void *user_data) {
  exec_mqueue_openlog();
}

static void exec_mqueue_shutdown_ev(const void *event_data, void *user_data) {
  void *ptr;
  int mqid;
  server_rec *s;

  for (s = (server_rec *) server_list->xas_list; s; s = s->next) {
    ptr = get_param_ptr(s->conf, "ExecMqueueCleanup", FALSE);
    if (ptr && !(*((int *)ptr))) // Don't cleanup this server
      continue;

    ptr = get_param_ptr(s->conf, "ExecMqueueKey", FALSE);
    if (ptr) {
      mqid = msgget(*((key_t *)ptr), 0);
      if (mqid != -1) {
        msgctl(mqid, IPC_RMID, NULL);
        pr_trace_msg(trace_channel, 5, "removed queue %x", *((key_t *)ptr));
      }
    }
  }

}
static void exec_mqueue_restart_ev(const void *event_data, void *user_data) {

  /* Bounce the log file descriptor. */
  exec_mqueue_closelog();
  exec_mqueue_openlog();

  return;
}

static void exec_mqueue_sess_reinit_ev(const void *event_data, void *user_data) {

  /* A HOST command changed the main_server pointer, reinitialize ourselves. */

  pr_event_unregister(&exec_mqueue_module, "core.session-reinit", exec_mqueue_sess_reinit_ev);

  exec_mqueue_closelog();

  exec_mqueue_sess_init();
}

/* Initialization routines
 */

static int exec_mqueue_sess_init(void) {

  pr_event_register(&exec_mqueue_module, "core.session-reinit", exec_mqueue_sess_reinit_ev,
    NULL);

  if (!exec_engine) {
    return 0;
  }

  exec_mqueue_closelog();
  exec_mqueue_openlog();

  return 0;
}

static int exec_mqueue_init(void) {
  /* Register event handlers. */
#if defined(PR_SHARED_MODULE)
  pr_event_register(&exec_mqueue_module, "core.module-unload", exec_mqueue_mod_unload_ev,
    NULL);
#endif /* PR_SHARED_MODULE */
  pr_event_register(&exec_mqueue_module, "core.postparse", exec_mqueue_postparse_ev, NULL);
  pr_event_register(&exec_mqueue_module, "core.restart", exec_mqueue_restart_ev, NULL);
  pr_event_register(&exec_mqueue_module, "core.shutdown", exec_mqueue_shutdown_ev, NULL);

  /* Register the mqueue backend */
  exec_register_backend("mqueue:", exec_mqueue_smessage);

  return 0;
}

/* Module API tables
 */

static conftable exec_mqueue_conftab[] = {
  { "ExecMqueueKey",		set_execmqueuekey,	NULL },
  { "ExecMqueueType",		set_execmqueuetype,	NULL },
  { "ExecMqueueFormat",		set_execmqueueformat,	NULL },
  { "ExecMqueueTimeout",	set_execmqueuetimeout,	NULL },
  { "ExecMqueueCleanup",	set_execmqueuecleanup,	NULL },
  { NULL }
};

module exec_mqueue_module = {

  /* Always NULL */
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "exec_mqueue",

  /* Configuration handler table */
  exec_mqueue_conftab,

  /* Command handler table */
  NULL,

  /* Authentication handler table */
  NULL,

  /* Module initialization */
  exec_mqueue_init,

  /* Session initialization */
  exec_mqueue_sess_init,

  /* Module version */
  MOD_EXEC_MQUEUE_VERSION
};
