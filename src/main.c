/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001, 2002 The ProFTPD Project team
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
 * As a special exemption, Public Flood Software/MacGyver aka Habeeb J. Dihu
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

/*
 * House initialization and main program loop
 * $Id: main.c,v 1.139 2002-12-07 22:02:51 jwm Exp $
 */

#include "conf.h"

#include <signal.h>
#include <sys/resource.h>

#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif

#ifdef HAVE_LIBUTIL_H
# include <libutil.h>
#endif /* HAVE_LIBUTIL_H */

#if PF_ARGV_TYPE == PF_ARGV_PSTAT
# ifdef HAVE_SYS_PSTAT_H
#  include <sys/pstat.h>
# else
#  undef PF_ARGV_TYPE
#  define PF_ARGV_TYPE PF_ARGV_WRITEABLE
# endif /* HAVE_SYS_PSTAT_H */
#endif /* PF_ARGV_PSTAT */

#if PF_ARGV_TYPE == PF_ARGV_PSSTRINGS
# ifndef HAVE_SYS_EXEC_H
#  undef PF_ARGV_TYPE
#  define PF_ARGV_TYPE PF_ARGV_WRITEABLE
# else
#  include <machine/vmparam.h>
#  include <sys/exec.h>
# endif /* HAVE_SYS_EXEC_H */
#endif /* PF_ARGV_PSSTRINGS */

#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

#ifdef HAVE_REGEXP_H
# include <regexp.h>
#endif /* HAVE_REGEXP_H */

#include "privs.h"

int (*cmd_auth_chk)(cmd_rec *);

/* From mod_core.c
 */
extern int core_display_file(const char *numeric, const char *fn, const char *fs);

struct rehash {
  struct rehash *next;

  void *data;
  void (*rehash)(void*);
};

unsigned long max_connects = 0UL;
unsigned int max_connect_interval = 1;

typedef struct _pidrec {
  struct _pidrec *next,*prev;

  pool *pool;
  pid_t pid;
  time_t when;

  int sempipe;				/* semaphore pipe fd (parent) */
  unsigned char dead;
} pidrec_t;

/* From src/dirtree.c */
extern xaset_t *server_list;

session_t session;

/* Is this daemon operating in standalone mode? */
static unsigned char is_standalone = FALSE;

/* Is this process the master standalone daemon process? */
static unsigned char is_master = TRUE;

pid_t mpid = 0;				/* Master pid */
struct rehash *rehash_list = NULL;	/* Pre-rehash callbacks */

uid_t daemon_uid;
gid_t daemon_gid;
array_header *daemon_gids;

static time_t shut = 0, deny = 0, disc = 0;
static char shutmsg[81] = {'\0'};

static xaset_t *child_list = NULL;
static unsigned char have_dead_child = FALSE;
static unsigned long child_listlen = 0;

response_t *resp_list = NULL,*resp_err_list = NULL;
static pool *resp_pool = NULL;
static char sbuf[1024] = {'\0'};
static char _ml_numeric[4] = {'\0'};
static char **Argv = NULL;
static char *LastArgv = NULL;
static char *PidPath = PID_FILE_PATH;

/* from dirtree.c */
extern array_header *server_defines;

static int nodaemon = 0;
static int shutdownp = 0;

/* Signal handling */
static RETSIGTYPE sig_disconnect(int);
static RETSIGTYPE sig_debug(int);

volatile unsigned int recvd_signal_flags = 0;

/* Used to capture an "unknown" signal value that causes termination. */
static int term_signo = 0;

/* Signal processing functions */
static void handle_abort(void);
static void handle_chld(void);
static void handle_xcpu(void);
static void handle_terminate(void);
static void handle_terminate_other(void);
static void finish_terminate(void);

#ifdef DEBUG_CORE
static int abort_core = 0;
#endif /* DEBUG_CORE */

static char *config_filename = CONFIG_FILE_PATH;

/* Add child semaphore fds into the rfd for selecting */
static int semaphore_fds(fd_set *rfd, int max_fd) {
  pidrec_t *p;

  if (child_list)
    for (p = (pidrec_t *) child_list->xas_list; p; p = p->next) {
      if (p->sempipe != -1) {
	FD_SET(p->sempipe,rfd);
	if (p->sempipe > max_fd)
	  max_fd = p->sempipe;
      }
    }

  return max_fd;
}

static void init_set_proc_title(int argc, char *argv[], char *envp[]) {
#ifdef HAVE___PROGNAME
  extern char *__progname, *__progname_full;
#endif /* HAVE___PROGNAME */
  extern char **environ;

  register int i, envpsize;
  char **p;

  /* Move the environment so setproctitle can use the space.
   */
  for (i = envpsize = 0; envp[i] != NULL; i++)
    envpsize += strlen(envp[i]) + 1;

  if ((p = (char **)malloc((i + 1) * sizeof(char *))) != NULL) {
    environ = p;

    for (i = 0; envp[i] != NULL; i++)
      if ((environ[i] = malloc(strlen(envp[i]) + 1)) != NULL)
        strcpy(environ[i], envp[i]);

    environ[i] = NULL;
  }

  Argv = argv;

  for (i = 0; i < argc; i++)
    if (!i || (LastArgv + 1 == argv[i]))
      LastArgv = argv[i] + strlen(argv[i]);

  for (i = 0; envp[i] != NULL; i++)
    if ((LastArgv + 1) == envp[i])
      LastArgv = envp[i] + strlen(envp[i]);

#ifdef HAVE___PROGNAME
  /* Set the __progname and __progname_full variables so glibc and company
   * don't go nuts.
   */
  __progname      = strdup("proftpd");
  __progname_full = strdup(argv[0]);
#endif /* HAVE___PROGNAME */
}

static void set_proc_title(const char *fmt, ...) {
  va_list msg;
  static char statbuf[BUFSIZ];

#ifndef HAVE_SETPROCTITLE
#if PF_ARGV_TYPE == PF_ARGV_PSTAT
   union pstun pst;
#endif /* PF_ARGV_PSTAT */
  char *p;
  int i,maxlen = (LastArgv - Argv[0]) - 2;
#endif /* HAVE_SETPROCTITLE */

  va_start(msg,fmt);

  memset(statbuf, 0, sizeof(statbuf));

#ifdef HAVE_SETPROCTITLE
# if __FreeBSD__ >= 4 && !defined(FREEBSD4_0) && !defined(FREEBSD4_1)
  /* FreeBSD's setproctitle() automatically prepends the process name. */
  vsnprintf(statbuf, sizeof(statbuf), fmt, msg);

# else /* FREEBSD4 */
  /* Manually append the process name for non-FreeBSD platforms. */
  snprintf(statbuf, sizeof(statbuf), "%s", "proftpd: ");
  vsnprintf(statbuf + strlen(statbuf), sizeof(statbuf) - strlen(statbuf),
    fmt, msg);

# endif /* FREEBSD4 */
  setproctitle("%s", statbuf);

#else /* HAVE_SETPROCTITLE */
  /* Manually append the process name for non-setproctitle() platforms. */
  snprintf(statbuf, sizeof(statbuf), "%s", "proftpd: ");
  vsnprintf(statbuf + strlen(statbuf), sizeof(statbuf) - strlen(statbuf),
    fmt, msg);

#endif /* HAVE_SETPROCTITLE */

  va_end(msg);

#ifdef HAVE_SETPROCTITLE
  return;
#else
  i = strlen(statbuf);

#if PF_ARGV_TYPE == PF_ARGV_NEW
  /* We can just replace argv[] arguments.  Nice and easy.
   */
  Argv[0] = statbuf;
  Argv[1] = NULL;
#endif /* PF_ARGV_NEW */

#if PF_ARGV_TYPE == PF_ARGV_WRITEABLE
  /* We can overwrite individual argv[] arguments.  Semi-nice.
   */
  snprintf(Argv[0], maxlen, "%s", statbuf);
  p = &Argv[0][i];

  while(p < LastArgv)
    *p++ = '\0';
  Argv[1] = NULL;
#endif /* PF_ARGV_WRITEABLE */

#if PF_ARGV_TYPE == PF_ARGV_PSTAT
  pst.pst_command = statbuf;
  pstat(PSTAT_SETCMD, pst, i, 0, 0);
#endif /* PF_ARGV_PSTAT */

#if PF_ARGV_TYPE == PF_ARGV_PSSTRINGS
  PS_STRINGS->ps_nargvstr = 1;
  PS_STRINGS->ps_argvstr = statbuf;
#endif /* PF_ARGV_PSSTRINGS */

#endif /* HAVE_SETPROCTITLE */
}

void session_set_idle(void) {

  pr_scoreboard_update_entry(getpid(),
    PR_SCORE_BEGIN_IDLE, time(NULL),
    PR_SCORE_CMD, "%s", "(idle)", NULL,
    NULL);

  set_proc_title("%s - %s: IDLE", session.user, session.proc_prefix);
}

static void send_response_list(response_t **head)
{
  int ml = 0;
  char *last_numeric = NULL;
  response_t *t;

  for (t = *head; t; t=t->next) {
    if (ml) {
      /* look for end of multiline */
      if (!t->next || (t->num && strcmp(t->num, last_numeric) != 0)) {
        pr_netio_printf(session.c->outstrm, "%s %s\r\n", last_numeric, t->msg);
        ml = 0;

      } else {
	if (MultilineRFC2228)
	  pr_netio_printf(session.c->outstrm, "%s-%s\r\n", last_numeric,
            t->msg);
	else
	  pr_netio_printf(session.c->outstrm, " %s\r\n" ,t->msg);
      }

    } else {
      /* look for start of multiline */
      if (t->next && (!t->next->num || strcmp(t->num, t->next->num) == 0)) {
        pr_netio_printf(session.c->outstrm, "%s-%s\r\n", t->num, t->msg);
        ml = 1;
        last_numeric = t->num;

      } else
        pr_netio_printf(session.c->outstrm, "%s %s\r\n", t->num, t->msg);
    }
  }

  *head = NULL;
}

void add_response_err(const char *numeric, const char *fmt, ...)
{
  va_list msg;
  response_t *t,**head;

  va_start(msg,fmt);
  vsnprintf(sbuf, sizeof(sbuf), fmt, msg);
  va_end(msg);

  sbuf[sizeof(sbuf) - 1] = '\0';

  t = (response_t*) pcalloc(resp_pool, sizeof(response_t));
  t->num = (numeric ? pstrdup(resp_pool, numeric) : NULL);
  t->msg = pstrdup(resp_pool, sbuf);

  for(head = &resp_err_list; *head && (!numeric || !(*head)->num ||
      strcmp((*head)->num,numeric) <= 0); head = &(*head)->next) ;

  t->next = *head;
  *head = t;
}

void add_response(const char *numeric, const char *fmt, ...) {
  va_list msg;
  response_t *t,**head;

  va_start(msg,fmt);
  vsnprintf(sbuf, sizeof(sbuf), fmt, msg);
  va_end(msg);

  sbuf[sizeof(sbuf) - 1] = '\0';

  t = (response_t*) pcalloc(resp_pool, sizeof(response_t));
  t->num = (numeric ? pstrdup(resp_pool, numeric) : NULL);
  t->msg = pstrdup(resp_pool, sbuf);

  for(head = &resp_list; *head && (!numeric || !(*head)->num ||
      strcmp((*head)->num,numeric) <= 0); head = &(*head)->next) ;

  t->next = *head;
  *head = t;
}

void send_response_raw(const char *fmt, ...) {
  va_list msg;

  va_start(msg,fmt);
  vsnprintf(sbuf, sizeof(sbuf), fmt, msg);
  va_end(msg);

  sbuf[sizeof(sbuf) - 1] = '\0';
  pr_netio_printf(session.c->outstrm, "%s\r\n", sbuf);
}

void send_response_async(const char *resp_numeric, const char *fmt, ...) {
  char buf[1024] = {'\0'};
  va_list msg;
  int maxlen;

  sstrncpy(buf, resp_numeric, sizeof(buf));
  sstrcat(buf, " ", sizeof(buf));

  maxlen = sizeof(buf) - strlen(buf) - 1;

  va_start(msg, fmt);
  vsnprintf(buf + strlen(buf), maxlen, fmt, msg);
  va_end(msg);

  buf[sizeof(buf) - 1] = '\0';
  sstrcat(buf, "\r\n", sizeof(buf));

  pr_netio_write_async(session.c->outstrm, buf, strlen(buf));
}

void send_response(const char *resp_numeric, const char *fmt, ...) {
  va_list msg;

  va_start(msg,fmt);
  vsnprintf(sbuf, sizeof(sbuf), fmt, msg);
  va_end(msg);

  sbuf[sizeof(sbuf) - 1] = '\0';
  pr_netio_printf(session.c->outstrm, "%s %s\r\n", resp_numeric, sbuf);
}

void send_response_ml_start(const char *resp_numeric, const char *fmt, ...) {
  va_list msg;

  va_start(msg,fmt);
  vsnprintf(sbuf, sizeof(sbuf), fmt, msg);
  va_end(msg);

  sbuf[sizeof(sbuf) - 1] = '\0';
  sstrncpy(_ml_numeric, resp_numeric, sizeof(_ml_numeric));
  pr_netio_printf(session.c->outstrm, "%s-%s\r\n", _ml_numeric, sbuf);
}

void send_response_ml(const char *fmt, ...) {
  va_list msg;

  va_start(msg,fmt);
  vsnprintf(sbuf, sizeof(sbuf), fmt, msg);
  va_end(msg);

  sbuf[sizeof(sbuf) - 1] = '\0';

  pr_netio_printf(session.c->outstrm, " %s\r\n", sbuf);
}

void send_response_ml_end(const char *fmt, ...) {
  va_list msg;

  va_start(msg,fmt);
  vsnprintf(sbuf, sizeof(sbuf), fmt, msg);
  va_end(msg);

  sbuf[sizeof(sbuf) - 1] = '\0';

  pr_netio_printf(session.c->outstrm, "%s %s\r\n", _ml_numeric, sbuf);
}

void set_auth_check(int (*chk)(cmd_rec*)) {
  cmd_auth_chk = chk;
}

static void end_login_noexit(void) {

  /* Clear the scoreboard entry. */
  if (ServerType == SERVER_STANDALONE) {

    /* For standalone daemons, we only clear the scoreboard slot if we are
     * an exiting child process.
     */
    if (!is_master && pr_scoreboard_del_entry(TRUE) < 0)
      log_pri(PR_LOG_NOTICE, "error deleting scoreboard entry: %s",
        strerror(errno));

  } else if (ServerType == SERVER_INETD) {
    /* For inetd-spawned daemons, we always clear the scoreboard slot. */
    if (pr_scoreboard_del_entry(TRUE) < 0)
      log_pri(PR_LOG_NOTICE, "error deleting scoreboard entry: %s",
        strerror(errno));
  }

  /* Run all the exit handlers */
  run_exit_handlers();

  /* If session.user is set, we have a valid login */
  if (session.user) {
#if (defined(BSD) && (BSD >= 199103))
    snprintf(sbuf, sizeof(sbuf), "ftp%ld",(long)getpid());
#else
    snprintf(sbuf, sizeof(sbuf), "ftpd%d",(int)getpid());
#endif
    sbuf[sizeof(sbuf) - 1] = '\0';

    if (session.wtmp_log)
      log_wtmp(sbuf,"",
        (session.c && session.c->remote_name ? session.c->remote_name : ""),
        (session.c && session.c->remote_ipaddr ? session.c->remote_ipaddr : NULL));
  }

  /* These are necessary in order that cleanups associated with these pools
   * (and their subpools) are properly run.
   */
  if (session.d)
    inet_close(session.pool, session.d);

  if (session.c)
    inet_close(session.pool, session.c);
}

/* Finish any cleaning up, mark utmp as closed and exit
 * without flushing buffers
 */

void end_login(int exitcode) {
  end_login_noexit();
  destroy_pool(permanent_pool);
  _exit(exitcode);
}

void session_exit(int pri, void *lv, int exitval, void *dummy) {
  char *log = (char *) lv;

  log_pri(pri, "%s", log);

  if (is_standalone && is_master) {
    log_pri(PR_LOG_NOTICE, "ProFTPD " PROFTPD_VERSION_TEXT
      " standalone mode SHUTDOWN");

    PRIVS_ROOT
    pr_delete_scoreboard();
    if (!nodaemon)
      unlink(PidPath);
    PRIVS_RELINQUISH
  }

  end_login(exitval);
}

static void shutdown_exit(void *d1, void *d2, void *d3, void *d4) {
  if (check_shutmsg(&shut, &deny, &disc, shutmsg, sizeof(shutmsg)) == 1) {
    char *user;
    time_t now;
    char *msg;
    char *serveraddress = main_server->ServerAddress;
    config_rec *c = NULL;
    unsigned char *authenticated = get_param_ptr(main_server->conf,
      "authenticated", FALSE);

    if ((c = find_config(main_server->conf, CONF_PARAM, "MasqueradeAddress",
        FALSE)) != NULL) {

      p_in_addr_t *masq_addr = (p_in_addr_t *) c->argv[0];
      serveraddress = pstrdup(main_server->pool, inet_ntoa(*masq_addr));
    }

    time(&now);
    if (authenticated && *authenticated == TRUE)
      user = get_param_ptr(main_server->conf, C_USER, FALSE);
    else
      user = "NONE";

    msg = sreplace(permanent_pool, shutmsg,
                   "%s", pstrdup(permanent_pool, fmt_time(shut)),
                   "%r", pstrdup(permanent_pool, fmt_time(deny)),
                   "%d", pstrdup(permanent_pool, fmt_time(disc)),
		   "%C", (session.cwd[0] ? session.cwd : "(none)"),
		   "%L", serveraddress,
		   "%R", (session.c && session.c->remote_name ?
                         session.c->remote_name : "(unknown)"),
		   "%T", pstrdup(permanent_pool,fmt_time(now)),
		   "%U", user,
		   "%V", main_server->ServerName,
                   NULL );

    send_response_async(R_421,"FTP server shutting down - %s",msg);

    session_exit(PR_LOG_NOTICE, msg, 0, NULL);
  }

  signal(SIGUSR1,sig_disconnect);
}

static int get_command_class(const char *name) {
  cmdtable *c = mod_find_cmd_symbol((char*)name, NULL, NULL);

  while(c && c->cmd_type != CMD)
    c = mod_find_cmd_symbol((char*)name, NULL, c);

  return (c ? c->class : 0);
}

static int _dispatch(cmd_rec *cmd, int cmd_type, int validate, char *match)
{
  char *argstr = NULL;
  cmdtable *c;
  modret_t *mr;
  int success = 0;
  int send_error = 0;
  static int match_index_cache = -1;
  static char *last_match = NULL;
  int *index_cache;

  send_error = (cmd_type == PRE_CMD || cmd_type == CMD ||
    cmd_type == POST_CMD_ERR);

  if (!match) {
    match = cmd->argv[0];
    index_cache = &cmd->symtable_index;
  } else {
    if (last_match != match) {
      match_index_cache = -1;
      last_match = match;
    }

    index_cache = &match_index_cache;
  }

  c = mod_find_cmd_symbol(match,index_cache,NULL);
  while(c && !success) {
    if (c->cmd_type == cmd_type) {
      if (c->group)
        cmd->group = pstrdup(cmd->pool,c->group);

      if (c->requires_auth && cmd_auth_chk && !cmd_auth_chk(cmd))
        return -1;

      cmd->tmp_pool = make_sub_pool(cmd->pool);

      argstr = make_arg_str(cmd->tmp_pool, cmd->argc, cmd->argv);

      if (cmd_type == CMD) {

        /* The client has successfully authenticated.. */
        if (session.user) {
          pr_scoreboard_update_entry(getpid(),
            PR_SCORE_CMD, "%s", argstr, NULL,
            NULL);
          set_proc_title("%s - %s: %s", session.user, session.proc_prefix,
            argstr);

        /* ...else the client has not yet authenticated */
        } else
          set_proc_title("%s:%d: %s", session.c->remote_ipaddr ?
            inet_ntoa(*session.c->remote_ipaddr) : "?",
            session.c->remote_port ? session.c->remote_port : 0, argstr);
      }

      log_debug(DEBUG4, "dispatching %s command '%s' to mod_%s",
        (cmd_type == PRE_CMD ? "PRE_CMD" :
         cmd_type == CMD ? "CMD" :
         cmd_type == POST_CMD ? "POST_CMD" :
         cmd_type == POST_CMD_ERR ? "POST_CMD_ERR" :
         cmd_type == LOG_CMD ? "LOG_CMD" :
         cmd_type == LOG_CMD_ERR ? "LOG_CMD_ERR" :
         "(unknown)"),
        argstr, c->m->name);

      cmd->class |= c->class;

      /* KLUDGE: disable umask() for not G_WRITE operations.  Config/
       * Directory walking code will be completely redesigned in 1.3,
       * this is only necessary for perfomance reasons in 1.1/1.2
       */

      if (!c->group || strcmp(c->group,G_WRITE) != 0)
        kludge_disable_umask();
      mr = call_module_cmd(c->m,c->handler,cmd);
      kludge_enable_umask();

      if (MODRET_ISHANDLED(mr))
        success = 1;
      else if (MODRET_ISERROR(mr)) {
        if (cmd_type == POST_CMD || cmd_type == LOG_CMD ||
                                   cmd_type == LOG_CMD_ERR) {
          if (MODRET_ERRMSG(mr))
            log_pri(PR_LOG_NOTICE, "%s", MODRET_ERRMSG(mr));

        } else if (send_error) {
          if (MODRET_ERRNUM(mr) && MODRET_ERRMSG(mr))
            add_response_err(MODRET_ERRNUM(mr),"%s",MODRET_ERRMSG(mr));
          else if (MODRET_ERRMSG(mr))
            send_response_raw("%s",MODRET_ERRMSG(mr));
        }

        success = -1;
      }

      if (session.user && !(session.sf_flags & SF_XFER) && cmd_type == CMD)
        session_set_idle();

      destroy_pool(cmd->tmp_pool);
    }

    if (!success)
      c = mod_find_cmd_symbol(match,index_cache,c);
  }

  if (!c && !success && validate) {
    add_response_err(R_500, "%s not understood.", cmd->argv[0]);
    success = -1;
  }

  return success;
}

static void dispatch_cmd(cmd_rec *cmd) {
  char *cp = NULL;
  int success = 0;

  cmd->server = main_server;
  resp_list = resp_err_list = NULL;
  resp_pool = cmd->pool;

  for (cp = cmd->argv[0]; *cp; cp++)
    *cp = toupper(*cp);

  if (!cmd->class)
    cmd->class = get_command_class(cmd->argv[0]);

  /* debug_print_dispatch(cmd); */

  /* First, dispatch to wildcard PRE_CMD handlers. */
  success = _dispatch(cmd, PRE_CMD, FALSE, C_ANY);

  if (!success)	/* run other pre_cmd */
    success = _dispatch(cmd, PRE_CMD, FALSE, NULL);

  if (success < 0) {

    /* Dispatch to POST_CMD_ERR handlers as well. */

    _dispatch(cmd, POST_CMD_ERR, FALSE, C_ANY);
    _dispatch(cmd, POST_CMD_ERR, FALSE, NULL);

    _dispatch(cmd, LOG_CMD_ERR, FALSE, C_ANY);
    _dispatch(cmd, LOG_CMD_ERR, FALSE, NULL);

    send_response_list(&resp_err_list);
    return;
  }

  success = _dispatch(cmd, CMD, FALSE, C_ANY);

  if (!success)
    success = _dispatch(cmd, CMD, TRUE, NULL);

  if (success == 1) {
    success = _dispatch(cmd, POST_CMD, FALSE, C_ANY);
    if (!success)
      success = _dispatch(cmd, POST_CMD, FALSE, NULL);

    _dispatch(cmd, LOG_CMD, FALSE, C_ANY);
    _dispatch(cmd, LOG_CMD, FALSE, NULL);

    send_response_list(&resp_list);

  } else if (success < 0) {

    /* Allow for non-logging command handlers to be run if CMD fails. */

    success = _dispatch(cmd, POST_CMD_ERR, FALSE, C_ANY);
    if (!success)
      success = _dispatch(cmd, POST_CMD_ERR, FALSE, NULL);

    _dispatch(cmd, LOG_CMD_ERR, FALSE, C_ANY);
    _dispatch(cmd, LOG_CMD_ERR, FALSE, NULL);

    send_response_list(&resp_err_list);
  }
}

static cmd_rec *make_ftp_cmd(pool *p, char *buf) {
  char *cp = buf, *wrd;
  cmd_rec *newcmd;
  pool *newpool;
  array_header *tarr;

  /* Be pedantic (and RFC-compliant) by not allowing leading whitespace
   * in an issued FTP command.  Will this cause troubles with many clients?
   */
  if (isspace((int) buf[0]))
    return NULL;

  /* Nothing there...bail out.
   */
  if ((wrd = get_word(&cp)) == NULL)
    return NULL;

  newpool = make_sub_pool(p);
  newcmd = (cmd_rec *) pcalloc(newpool,sizeof(cmd_rec));
  newcmd->pool = newpool;
  newcmd->symtable_index = -1;

  tarr = make_array(newpool, 2, sizeof(char *));

  *((char **) push_array(tarr)) = pstrdup(newpool, wrd);
  newcmd->argc++;
  newcmd->arg = pstrdup(newpool, cp);

  while((wrd = get_word(&cp)) != NULL) {
    *((char **) push_array(tarr)) = pstrdup(newpool, wrd);
    newcmd->argc++;
  }

  *((char **) push_array(tarr)) = NULL;

  newcmd->argv = (char **) tarr->elts;

  return newcmd;
}

static int idle_timeout_cb(CALLBACK_FRAME) {
  /* We don't want to quit in the middle of a transfer */
  if (session.sf_flags & SF_XFER) {

    /* Restart the timer. */
    return 1;
  }

  send_response_async(R_421,"Idle Timeout (%d seconds): closing control "
    "connection.", TimeoutIdle);

  session_exit(PR_LOG_INFO, "FTP session idle timeout, disconnected.", 0, NULL);

  remove_timer(TIMER_LOGIN, ANY_MODULE);
  remove_timer(TIMER_NOXFER, ANY_MODULE);
  return 0;
}

static void cmd_loop(server_rec *server, conn_t *c) {
  static long cmd_buf_size = -1;
  config_rec *id = NULL;
  char buf[1024] = {'\0'};
  char *cp;
  char *display, *serveraddress = server->ServerAddress;
  config_rec *masq_c = NULL;
  int i;

  set_proc_title("connected: %s (%s:%d)",
                 c->remote_name   ? c->remote_name               : "?",
                 c->remote_ipaddr ? inet_ntoa(*c->remote_ipaddr) : "?",
                 c->remote_port   ? c->remote_port               : 0);

  /* Setup the main idle timer */
  if (TimeoutIdle)
    add_timer(TimeoutIdle, TIMER_IDLE, NULL, idle_timeout_cb);

  if ((masq_c = find_config(server->conf, CONF_PARAM, "MasqueradeAddress",
      FALSE)) != NULL) {
    p_in_addr_t *masq_addr = (p_in_addr_t *) masq_c->argv[0];
    serveraddress = pstrdup(server->pool, inet_ntoa(*masq_addr));
  }

  if ((display = get_param_ptr(server->conf, "DisplayConnect", FALSE)) != NULL)
    core_display_file(R_220, display, NULL);

  if ((id = find_config(server->conf, CONF_PARAM, "ServerIdent",
      FALSE)) == NULL || *((unsigned char *) id->argv[0]) == FALSE) {
    unsigned char *defer_welcome = get_param_ptr(main_server->conf,
      "DeferWelcome", FALSE);

    if (id && id->argc > 1)
      send_response(R_220, "%s", (char *) id->argv[1]);

    else if (defer_welcome && *defer_welcome == TRUE)
      send_response(R_220, "ProFTPD " PROFTPD_VERSION_TEXT " Server ready.");

    else
      send_response(R_220, "ProFTPD " PROFTPD_VERSION_TEXT " Server (%s) [%s]",
           server->ServerName,serveraddress);

  } else
    send_response(R_220, "%s FTP server ready.", serveraddress);

  /* Make sure we can receive OOB data */
  inet_setasync(session.pool, session.c);

  log_pri(PR_LOG_INFO, "FTP session opened.");

  while (TRUE) {
    pr_handle_signals();

    if (pr_netio_telnet_gets(buf, sizeof(buf)-1, session.c->instrm,
        session.c->outstrm) == NULL) {

      if (PR_NETIO_ERRNO(session.c->instrm) == EINTR)
        /* Simple interrupted syscall */
	continue;

      /* Otherwise, EOF */
      log_pri(PR_LOG_INFO, "FTP session closed.");
      end_login(0);
    }

    /* Data received, reset idle timer */
    if (TimeoutIdle)
      reset_timer(TIMER_IDLE, NULL);

    if (cmd_buf_size == -1) {
      long *buf_size = get_param_ptr(main_server->conf,
        "CommandBufferSize", FALSE);

      if (buf_size == NULL || *buf_size <= 0)
        cmd_buf_size = 512;

      else if (*buf_size + 1 > sizeof(buf)) {
	log_pri(PR_LOG_WARNING, "Invalid CommandBufferSize size given. "
          "Resetting to 512.");
	cmd_buf_size = 512;
      }
    }

    buf[cmd_buf_size - 1] = '\0';
    i = strlen(buf);

    if (i && (buf[i-1] == '\n' || buf[i-1] == '\r')) {
      buf[i-1] = '\0'; i--;
      if (i && (buf[i-1] == '\n' || buf[i-1] =='\r'))
        buf[i-1] = '\0';
    }

    cp = buf;
    if (*cp == '\r') cp++;

    if (*cp) {
      cmd_rec *cmd;

      cmd = make_ftp_cmd(permanent_pool, cp);
      if (cmd) {
        dispatch_cmd(cmd);
        destroy_pool(cmd->pool);

      } else
	send_response(R_500, "Invalid command: try being more creative.");
    }

    /* release any working memory allocated in inet */
    clear_inet_pool();
  }
}

void register_rehash(void *data, void (*fp)(void*)) {
  struct rehash *r = (struct rehash*)pcalloc(permanent_pool,
		  				sizeof(struct rehash));

  r->data = data;
  r->rehash = fp;
  r->next = rehash_list;
  rehash_list = r;
}

static void core_rehash_cb(void *d1, void *d2, void *d3, void *d4) {
  struct rehash *rh = NULL;

  if (is_master && mpid) {
    int max_fd;
    fd_set child_fds;

    log_pri(PR_LOG_NOTICE, "received SIGHUP -- master server rehashing "
      "configuration file");

    /* Make sure none of our children haven't completed start up */
    FD_ZERO(&child_fds);
    max_fd = -1;

    if ((max_fd = semaphore_fds(&child_fds, max_fd)) > -1) {
      log_pri(PR_LOG_NOTICE, "waiting for child processes to complete "
        "initialization");

      while (max_fd != -1) {
	int i;
	pidrec_t *cp;
	
	i = select(max_fd + 1, &child_fds, NULL, NULL, NULL);

	if (i > 0)
	  for (cp = (pidrec_t *) child_list->xas_list; cp; cp = cp->next)
	    if (cp->sempipe != -1 && FD_ISSET(cp->sempipe, &child_fds)) {
	      close(cp->sempipe);
	      cp->sempipe = -1;
	    }

	FD_ZERO(&child_fds);
        max_fd = -1;
	max_fd = semaphore_fds(&child_fds, max_fd);
      }
    }

    pr_free_bindings();

    /* Run through the list of registered rehash callbacks. */
    for (rh = rehash_list; rh; rh = rh->next)
      rh->rehash(rh->data);

    init_log();
    init_config();
    init_conf_stacks();

    PRIVS_ROOT
    if (parse_config_file(config_filename) == -1) {
      PRIVS_RELINQUISH
      log_pri(PR_LOG_ERR, "Fatal: unable to read configuration file '%s'.",
        config_filename);
      end_login(1);
    }
    PRIVS_RELINQUISH
    free_conf_stacks();

    /* Set the (possibly new) resource limits. */
    set_daemon_rlimits();

    fixup_servers();

    /* Recreate the listen connection.  Can an inetd-spawned server accept
     * and process HUP?
     */
    pr_init_bindings();

  } else

    /* Child process -- cannot rehash, log error */
    log_pri(PR_LOG_ERR, "received SIGHUP, cannot rehash child process");
}

static int _dup_low_fd(int fd)
{
  int i,need_close[3] = {-1, -1, -1};

  for(i = 0; i < 3; i++)
    if (fd == i) {
      fd = dup(fd);
      need_close[i] = 1;
    }

  for(i = 0; i < 3; i++)
    if (need_close[i] > -1)
      close(i);

  return fd;
}

static void set_server_privs(void) {
  uid_t server_uid, current_euid = geteuid();
  gid_t server_gid, current_egid = getegid();
  unsigned char switch_server_id = FALSE;

  uid_t *uid = get_param_ptr(main_server->conf, "UserID", FALSE);
  gid_t *gid =  get_param_ptr(main_server->conf, "GroupID", FALSE);

  if (uid) {
    server_uid = *uid;
    switch_server_id = TRUE;

  } else
    server_uid = current_euid;

  if (gid) {
    server_gid = *gid;
    switch_server_id = TRUE;

  } else
    server_gid = current_egid;

  if (switch_server_id) {
    PRIVS_ROOT

    /* Note: will it be necessary to double check this switch, as is done
     * in elsewhere in this file?
     */
    PRIVS_SETUP(server_uid, server_gid);
  }
}

static void fork_server(int fd, conn_t *l, unsigned char nofork) {
  server_rec *s = NULL, *s_saved = NULL, *serv = NULL;
  conn_t *conn = NULL;
  unsigned char *ident_lookups = NULL;
  int i, rev;
  int sempipe[2] = { -1, -1 };

#ifndef DEBUG_NOFORK
  pid_t pid;
  sigset_t sigset;
  pool *pidrec_pool = NULL, *set_pool = NULL;

  if (!nofork) {
    pidrec_t *cpid;

    /* A race condition exists on heavily loaded servers where the parent
     * catches SIGHUP and attempts to close/re-open the main listening
     * socket(s), however the children haven't finished closing them
     * (EADDRINUSE).  We use a semaphore pipe here to flag the parent once
     * the child has closed all former listening sockets.
     */

    if (pipe(sempipe) == -1) {
      log_pri(PR_LOG_ERR, "pipe(): %s", strerror(errno));
      close(fd);
      return;
    }

    /* Need to make sure the child (writer) end of the pipe isn't
     * < 2 (stdio,stdout,stderr) as this will cause problems later.
     */

    if (sempipe[1] < 3)
      sempipe[1] = _dup_low_fd(sempipe[1]);

    /* We block SIGCHLD to prevent a race condition if the child
     * dies before we can record it's pid.  Also block SIGTERM to
     * prevent sig_terminate() from examining the child list
     */

    sigemptyset(&sigset);
    sigaddset(&sigset,SIGTERM);
    sigaddset(&sigset,SIGCHLD);
    sigaddset(&sigset,SIGUSR1);
    sigaddset(&sigset,SIGUSR2);

    sigprocmask(SIG_BLOCK,&sigset,NULL);

    switch ((pid = fork())) {
    case 0: /* child */

      /* No longer the master process. */
      is_master = FALSE;
      sigprocmask(SIG_UNBLOCK,&sigset,NULL);

      /* No longer need the read side of the semaphore pipe. */
      close(sempipe[0]);
      break;

    case -1:
      sigprocmask(SIG_UNBLOCK, &sigset, NULL);
      log_pri(PR_LOG_ERR, "fork(): %s", strerror(errno));

      /* The parent doesn't need the socket open. */
      close(fd);
      close(sempipe[0]);
      close(sempipe[1]);

      return;

    default: /* parent */
      /* The parent doesn't need the socket open */
      close(fd);

      if (!child_list) {

        /* allocate a subpool from permanent_pool for the set
         */
        set_pool = make_sub_pool(permanent_pool);
        child_list = xaset_create(set_pool, NULL);
        child_list->mempool = set_pool;

        /* now, make a subpool for the pidrec_t to be allocated
         */
        pidrec_pool = make_sub_pool(set_pool);

      } else {

        /* allocate a subpool for the pidrec_t to be allocated
         */
        pidrec_pool = make_sub_pool(child_list->mempool);
      }

      cpid = (pidrec_t *) pcalloc(pidrec_pool, sizeof(pidrec_t));
      cpid->pid = pid;
      time(&cpid->when);
      cpid->sempipe = sempipe[0];
      cpid->pool = pidrec_pool;
      xaset_insert(child_list,(xasetmember_t*)cpid);
      child_listlen++;

      close(sempipe[1]);

      /* Unblock the signals now as sig_child() will catch
       * an "immediate" death and remove the pid from the children list
       */
      sigprocmask(SIG_UNBLOCK,&sigset,NULL);
      return;
    }
  }

  /* There would appear to be no useful purpose behind setting the process
   * group of the newly forked child.  In daemon/inetd mode, we should have no
   * controlling tty and either have the process group of the parent or of
   * inetd.  In non-daemon mode (-n), doing this may cause SIGTTOU to be
   * raised on output to the terminal (stderr logging).
   *
   * #ifdef HAVE_SETPGID
   *   setpgid(0,getpid());
   * #else
   * # ifdef SETPGRP_VOID
   *   setpgrp();
   * # else
   *   setpgrp(0,getpid());
   * # endif
   * #endif
   *
   */

  /* Reseed pseudo-randoms */
  srand(time(NULL));

#endif /* DEBUG_NOFORK */

  /* Child is running here */
  signal(SIGUSR1,sig_disconnect);
  signal(SIGUSR2,sig_debug);
  signal(SIGCHLD,SIG_DFL);
  signal(SIGHUP,SIG_IGN);

  /* From this point on, syslog stays open. We close it first so that the
   * logger will pick up our new PID.
   *
   * We have to delay calling log_opensyslog() until after inet_openrw()
   * is called, otherwise the potential exists for the syslog FD to
   * be overwritten and the user to see logging information.
   *
   * This isn't that big of a deal because the logging functions will
   * just open it dynamically if they need to.
   */
  log_closesyslog();

  /* Specifically DO NOT perform reverse DNS at this point, to alleviate
   * the race condition mentioned above.  Instead we do it after closing
   * all former listening sockets.
   */
  conn = inet_openrw(permanent_pool, l, NULL, PR_NETIO_STRM_CTRL, fd,
    STDIN_FILENO, STDOUT_FILENO, FALSE);

  /* Now do the permanent syslog open
   */
  block_signals();
  PRIVS_ROOT

  log_opensyslog(NULL);

  PRIVS_RELINQUISH
  unblock_signals();

  if (!conn) {
    log_pri(PR_LOG_ERR, "Fatal: unable to open incoming connection: %s",
      strerror(errno));
    exit(1);
  }

  inet_set_proto_options(permanent_pool,conn, 1, 1, 0, 0);

  /* Find the server for this connection. */
  serv = pr_ipbind_get_server(conn->local_ipaddr, conn->local_port);

#ifndef PR_HACK_DISABLE_VHOST_MEM_FREE
  /* To conserve memory, free all other servers and associated
   * configurations
   */
  s = main_server;
  while (s) {
    s_saved = s->next;
    if (s != serv) {
      if (s->listen && s->listen != l) {
	/* If our former listen socket was stdin or stdout (0 or 1),
         * inet_close() will attempt to close it, and in the process
         * close our read/write sockets for this connection.
         */
        if (s->listen->listen_fd == conn->rfd ||
           s->listen->listen_fd == conn->wfd)
          s->listen->listen_fd = -1;
        else
          inet_close(s->pool,s->listen);
      }

      if (s->listen) {
        if (s->listen->listen_fd == conn->rfd ||
           s->listen->listen_fd == conn->wfd)
             s->listen->listen_fd = -1;
      }

      xaset_remove(server_list,(xasetmember_t*)s);
      destroy_pool(s->pool);
    }
    s = s_saved;
  }
#endif

  main_server = serv;

  session.pool = permanent_pool;
  session.c = conn;
  session.data_port = conn->remote_port - 1;
  session.sf_flags = 0;
  session.sp_flags = 0;

  /* Close the write side of the semaphore pipe to tell the parent
   * we are all grown up and have finished housekeeping (closing
   * former listen sockets).
   */
  close(sempipe[1]);

  /* Now perform reverse dns */
  if (ServerUseReverseDNS) {
    rev = inet_reverse_dns(permanent_pool, ServerUseReverseDNS);
    inet_resolve_ip(permanent_pool, conn);
    inet_reverse_dns(permanent_pool, rev);
  }

  /* Check and see if we are shutdown */
  if (shutdownp) {
    time_t now;

    time(&now);
    if (!deny || deny <= now) {
      config_rec *c = NULL;
      char *reason = NULL;
      char *serveraddress = main_server->ServerAddress;

      if ((c = find_config(main_server->conf, CONF_PARAM, "MasqueradeAddress",
        FALSE)) != NULL) {

        p_in_addr_t *masq_addr = (p_in_addr_t *) c->argv[0];
        serveraddress = pstrdup(main_server->pool, inet_ntoa(*masq_addr));
      }

      reason = sreplace(permanent_pool, shutmsg,
                   "%s", pstrdup(permanent_pool, fmt_time(shut)),
                   "%r", pstrdup(permanent_pool, fmt_time(deny)),
                   "%d", pstrdup(permanent_pool, fmt_time(disc)),
		   "%C", (session.cwd[0] ? session.cwd : "(none)"),
		   "%L", serveraddress,
		   "%R", (session.c && session.c->remote_name ?
                         session.c->remote_name : "(unknown)"),
		   "%T", pstrdup(permanent_pool, fmt_time(now)),
		   "%U", "NONE",
		   "%V", main_server->ServerName,
                   NULL );

      log_auth(PR_LOG_NOTICE, "connection refused (%s) from %s [%s]",
               reason, session.c->remote_name,
               inet_ntoa(*session.c->remote_ipaddr));

      send_response(R_500,
		    "FTP server shut down (%s) -- please try again later.",
		    reason);
      exit(0);
    }
  }

  /* If no server is configured to handle the addr the user is
   * connected to, drop them.
   */
  if (!serv) {
    send_response(R_500,
		  "Sorry, no server available to handle request on %s.",
		  inet_getname(conn->pool, conn->local_ipaddr));
    exit(0);
  }

  if (serv->listen) {
    if (serv->listen->listen_fd == conn->rfd ||
        serv->listen->listen_fd == conn->wfd)
          serv->listen->listen_fd = -1;

    destroy_pool(serv->listen->pool);
    serv->listen = NULL;
  }

  /* Check config tree for <Limit LOGIN> directives */
  if (!login_check_limits(serv->conf, TRUE, FALSE, &i)) {
    log_pri(PR_LOG_NOTICE, "Connection from %s [%s] denied.",
            session.c->remote_name, inet_ntoa(*session.c->remote_ipaddr));
    exit(0);
  }

  /* Use the ident protocol (RFC1413) to try to get remote ident_user
   */

  if ((ident_lookups = get_param_ptr(main_server->conf, "IdentLookups",
     FALSE)) == NULL || *ident_lookups == TRUE) {
    session.ident_lookups = TRUE;
    session.ident_user = get_ident(session.pool, conn);

  } else {
    session.ident_lookups = FALSE;
    session.ident_user = "UNKNOWN";
  }

  /* Set the ID/privs for the User/Group in this server */
  set_server_privs();

  /* Find class. */
  {
    unsigned char *class_engine = get_param_ptr(main_server->conf,
      "Classes", FALSE);

    if (class_engine && *class_engine == TRUE) {
      if ((session.class = (class_t *) find_class(conn->remote_ipaddr,
          conn->remote_name)) != NULL)
        log_debug(DEBUG2, "FTP session requested from class '%s'",
          session.class->name);
      else
        log_debug(DEBUG2, "FTP session requested from unknown class");
    }
  }

  /* Inform all the modules that we are now a child */
  log_debug(DEBUG7, "performing module session initializations");

  pr_init_session_modules();

  log_debug(DEBUG4,"connected - local  : %s:%d",
                    inet_ntoa(*session.c->local_ipaddr),
                    session.c->local_port);
  log_debug(DEBUG4,"connected - remote : %s:%d",
                    inet_ntoa(*session.c->remote_ipaddr),
                    session.c->remote_port);

  /* set the per-child resource limits */
  set_session_rlimits();

  cmd_loop(serv,conn);
}

static void disc_children(void) {
  sigset_t sigset;
  pidrec_t *cp;

  if (disc && disc <= time(NULL) && child_list) {
    sigemptyset(&sigset);
    sigaddset(&sigset,SIGTERM);
    sigaddset(&sigset,SIGCHLD);
    sigaddset(&sigset,SIGUSR1);
    sigaddset(&sigset,SIGUSR2);

    sigprocmask(SIG_BLOCK,&sigset,NULL);

    PRIVS_ROOT
    for(cp = (pidrec_t*) child_list->xas_list; cp; cp=cp->next)
      kill(cp->pid,SIGUSR1);
    PRIVS_RELINQUISH

    sigprocmask(SIG_UNBLOCK,&sigset,NULL);
  }
}

static void server_loop(void) {
  fd_set listen_fds;
  conn_t *listen;
  int fd, max_fd;
  int i,err_count = 0;
  unsigned long nconnects = 0UL;
  time_t last_error;
  struct timeval tv;
  static int running = 0;

  set_proc_title("(accepting connections)");

  time(&last_error);

  while (TRUE) {
    run_schedule();

    FD_ZERO(&listen_fds);
    max_fd = 0;
    max_fd = pr_ipbind_listen(&listen_fds);

    /* Monitor children pipes */
    max_fd = semaphore_fds(&listen_fds, max_fd);

    /* Check for ftp shutdown message file */
    switch (check_shutmsg(&shut, &deny, &disc, shutmsg, sizeof(shutmsg))) {
    case 1: if (!shutdownp) disc_children(); shutdownp = 1; break;
    case 0: shutdownp = 0; deny = disc = (time_t)0; break;
    }

    if (shutdownp) {
      tv.tv_sec = 5L;
      tv.tv_usec = 0L;

    } else {

      tv.tv_sec = PR_TUNABLE_SELECT_TIMEOUT;
      tv.tv_usec = 0L;
    }

    /* If running (a flag signaling whether proftpd is just starting up)
     * AND shutdownp (a flag signalling the present of /etc/shutmsg) are
     * true, then log an error stating this -- but don't stop the server.
     */
    if (shutdownp && !running) {

      /* Check the value of the deny time_t struct w/ the current time.
       * If the deny time has passed, log that all incoming connections
       * will be refused.  If not, note the date at which they will be
       * refused in the future.
       */
      time_t now = time(NULL);

      if (difftime(deny, now) < 0.0) {
        log_pri(PR_LOG_ERR, SHUTMSG_PATH " present: all incoming connections "
          "will be refused.");

      } else {
        log_pri(PR_LOG_ERR, SHUTMSG_PATH " present: incoming connections "
          "will be denied starting %s", CHOP(ctime(&deny)));
      }
    }

    running = 1;

    i = select(max_fd + 1, &listen_fds, NULL, NULL, &tv);

    if (i == -1 && errno == EINTR) {
      pr_handle_signals();
      continue;
    }

    if (have_dead_child) {
      sigset_t sigset;
      pidrec_t *cp,*cpnext;

      sigemptyset(&sigset);
      sigaddset(&sigset,SIGCHLD);
      sigaddset(&sigset,SIGTERM);
      block_alarms();
      sigprocmask(SIG_BLOCK,&sigset,NULL);

      have_dead_child = FALSE;
      if (child_list) {
        for(cp = (pidrec_t*) child_list->xas_list; cp; cp=cpnext) {
          cpnext = cp->next;

          /* if the pidrec_t is marked "dead", remove it from the set,
           * and recover its resources
           */
          if (cp->dead) {
	    if (cp->sempipe != -1)
	      close(cp->sempipe);
            xaset_remove(child_list, (xasetmember_t *) cp);
            destroy_pool(cp->pool);
          }
        }
      }

      /* Don't need the pool anymore */
      if (!child_list->xas_list) {
        destroy_pool(child_list->mempool);
        child_list = NULL;
      }

      sigprocmask(SIG_UNBLOCK,&sigset,NULL);
      unblock_alarms();
    }

    if (i == -1) {
      time_t this_error;

      time(&this_error);

      if ((this_error - last_error) <= 5 && err_count++ > 10) {
        log_pri(PR_LOG_ERR, "Fatal: select() failing repeatedly, shutting "
          "down.");
        exit(1);

      } else if ((this_error - last_error) > 5) {
        last_error = this_error;
        err_count = 0;
      }

      log_pri(PR_LOG_NOTICE, "select() failed in server_loop(): %s",
              strerror(errno));
    }

    if (i == 0)
      continue;

    /* Reset the connection counter.  Take into account this current
     * connection, which does not (yet) have an entry in the child list.
     */
    nconnects = 1UL;

    /* See if child semaphore pipes have signaled */
    if (child_list) {
      pidrec_t *cp = NULL;
      time_t now = time(NULL);

      for (cp = (pidrec_t *) child_list->xas_list; cp; cp = cp->next) {
	if (cp->sempipe != -1 && FD_ISSET(cp->sempipe, &listen_fds)) {
	  close(cp->sempipe);
	  cp->sempipe = -1;
	}

        /* While we're looking, tally up the number of children forked in
         * the past interval.
         */
        if (cp->when >= (now - (unsigned long) max_connect_interval))
          nconnects++;
      }
    }

    pr_handle_signals();

    /* Accept the connection. */
    listen = pr_ipbind_accept_conn(&listen_fds, &fd);

    /* Fork off servers to handle each connection our job is to get back to
     * answering connections asap, so leave the work of determining which
     * server the connection is for to our child.
     */

    if (listen) {

      /* Check for exceeded MaxInstances. */
      if (ServerMaxInstances && (child_listlen >= ServerMaxInstances)) {
        log_pri(PR_LOG_WARNING,
          "MaxInstances (%d) reached, new connection denied",
          ServerMaxInstances);
        close(fd);

      /* Check for exceeded MaxConnectionRate. */
      } else if (max_connects && (nconnects > max_connects)) {
        log_pri(PR_LOG_WARNING,
          "MaxConnectionRate (%lu/%u secs) reached, new connection denied",
          max_connects, max_connect_interval);
        close(fd);

      /* Fork off a child to handle the connection. */
      } else
        fork_server(fd, listen, FALSE);
    }
  }
}

/* This function is to handle the dispatching of actions based on
 * signals received by the signal handlers, to avoid signal handler-based
 * race conditions.
 */

void pr_handle_signals(void) {

  while (recvd_signal_flags) {

    if (recvd_signal_flags & RECEIVED_SIG_ALRM) {
      recvd_signal_flags &= ~RECEIVED_SIG_ALRM;
      handle_alarm();
    }

    if (recvd_signal_flags & RECEIVED_SIG_CHLD) {
      recvd_signal_flags &= ~RECEIVED_SIG_CHLD;
      handle_chld();
    }

    if (recvd_signal_flags & RECEIVED_SIG_DEBUG) {
      recvd_signal_flags &= ~RECEIVED_SIG_DEBUG;
      debug_walk_pools();
    }

    if (recvd_signal_flags & RECEIVED_SIG_SEGV) {
      recvd_signal_flags &= ~RECEIVED_SIG_SEGV;
      handle_terminate_other();
    }

    if (recvd_signal_flags & RECEIVED_SIG_TERMINATE) {
      recvd_signal_flags &= ~RECEIVED_SIG_TERMINATE;
      handle_terminate();
    }

    if (recvd_signal_flags & RECEIVED_SIG_TERM_OTHER) {
      recvd_signal_flags &= ~RECEIVED_SIG_TERM_OTHER;
      handle_terminate_other();
    }

    if (recvd_signal_flags & RECEIVED_SIG_XCPU) {
      recvd_signal_flags &= ~RECEIVED_SIG_XCPU;
      handle_xcpu();
    }

    if (recvd_signal_flags & RECEIVED_SIG_ABORT) {
      recvd_signal_flags &= RECEIVED_SIG_ABORT;
      handle_abort();
    }

    if (recvd_signal_flags & RECEIVED_SIG_REHASH) {

      /* NOTE: should this be done here, rather than using a schedule? */
      schedule(core_rehash_cb, 0, NULL, NULL, NULL, NULL);

      recvd_signal_flags &= ~RECEIVED_SIG_REHASH;
    }

    if (recvd_signal_flags & RECEIVED_SIG_EXIT) {
      session_exit(PR_LOG_NOTICE, "Parent process requested shutdown", 0, NULL);
      recvd_signal_flags &= ~RECEIVED_SIG_EXIT;
    }

    if (recvd_signal_flags & RECEIVED_SIG_SHUTDOWN) {

      /* NOTE: should this be done here, rather than using a schedule? */
      schedule(shutdown_exit, 0, NULL, NULL, NULL, NULL);

      recvd_signal_flags &= ~RECEIVED_SIG_SHUTDOWN;
    }
  }
}

/* sig_rehash occurs in the master daemon when manually "kill -HUP"
 * in order to re-read configuration files, and is sent to all
 * children by the master.
 */
static RETSIGTYPE sig_rehash(int signo) {
  recvd_signal_flags |= RECEIVED_SIG_REHASH;
  signal(SIGHUP, sig_rehash);
}

/* sig_debug outputs some basic debugging info
 */
static RETSIGTYPE sig_debug(int signo) {
  recvd_signal_flags |= RECEIVED_SIG_DEBUG;
  signal(SIGHUP, sig_debug);
}

/* sig_disconnect is called in children when the parent daemon
 * detects that shutmsg has been created and ftp sessions should
 * be destroyed.  If a file transfer is underway, the process simply
 * dies, otherwise a function is scheduled to attempt to display
 * the shutdown reason.
 */
static RETSIGTYPE sig_disconnect(int signo) {

  /* If this is an anonymous session, or a transfer is in progress,
   * perform the exit a little later...
   */
  if ((session.sf_flags & SF_ANON) ||
      (session.sf_flags & SF_XFER))
    recvd_signal_flags |= RECEIVED_SIG_EXIT;
  else
    recvd_signal_flags |= RECEIVED_SIG_SHUTDOWN;

  signal(SIGUSR1, SIG_IGN);
}

static RETSIGTYPE sig_child(int signo) {
  recvd_signal_flags |= RECEIVED_SIG_CHLD;

  /* We make an exception here to the synchronous processing that is done
   * for other signals; SIGCHLD is handled asynchronously.  This is made
   * necessary by two things.
   *
   * First, we need to support non-POSIX systems.  Under POSIX, once a
   * signal handler has been configured for a given signal, that becomes
   * that signal's disposition, until explicitly changed later.  Non-POSIX
   * systems, on the other hand, will restore the default disposition of
   * a signal after a custom signal handler has been configured.  Thus,
   * to properly support non-POSIX systems, a call to signal(2) is necessary
   * as one of the last steps in our signal handlers.
   *
   * Second, SVR4 systems differ specifically in their semantics of signal(2)
   * and SIGCHLD.  These systems will check for any unhandled SIGCHLD
   * signals, waiting to be reaped via wait(2) or waitpid(2), whenever
   * the disposition of SIGCHLD is changed.  This means that if our process
   * handles SIGCHLD, but does not call wait(2) or waitpid(2), and then
   * calls signal(2), another SIGCHLD is generated; this loop repeats,
   * until the process runs out of stack space and terminates.
   *
   * Thus, in order to cover this interaction, we'll need to call handle_chld()
   * here, asynchronously.  handle_chld() does the work of reaping dead
   * child processes, and does not seem to call any non-reentrant functions,
   * so it should be safe.
   */

  handle_chld();
  signal(SIGCHLD, sig_child);
}

#ifdef DEBUG_CORE
static char *_prepare_core(void)
{
  static char dir[256];

  snprintf(dir, sizeof(dir), "%s/proftpd-core-%ld", CORE_DIR, getpid());

  if (mkdir(dir, 0700) != -1)
    chdir(dir);

  return dir;
}
#endif /* DEBUG_CORE */

static RETSIGTYPE sig_abort(int signo) {
  recvd_signal_flags |= RECEIVED_SIG_ABORT;
  signal(SIGABRT, SIG_DFL);
}

static void handle_abort(void) {

#ifdef DEBUG_CORE
  if (abort_core)
    log_pri(PR_LOG_NOTICE,
	    "ProFTPD received SIGABRT signal, generating core file in %s",
	    _prepare_core());
  else
#endif /* DEBUG_CORE */
    log_pri(PR_LOG_NOTICE, "ProFTPD received SIGABRT signal, no core dump.");

  end_login_noexit();
  abort();
}

#ifdef DEBUG_CORE
static void _internal_abort(void) {
  if (abort_core) {
    log_pri(PR_LOG_NOTICE, "core file dumped to %s", _prepare_core());
    signal(SIGABRT,SIG_DFL);
    end_login_noexit();
    abort();
  }
}
#endif /* DEBUG_CORE */

static RETSIGTYPE sig_terminate(int signo) {

  if (signo == SIGSEGV) {
    recvd_signal_flags |= RECEIVED_SIG_ABORT;

    /* Make sure the scoreboard slot is properly cleared. */
    pr_scoreboard_del_entry(FALSE);

    /* This is probably not the safest thing to be doing, but since the
     * process is terminating anyway, why not?  It helps when knowing/logging
     * that a segfault happened...
     */
    log_pri(PR_LOG_NOTICE, "ProFTPD terminating (signal 11)");

    /* Restore the default signal handler. */
    signal(SIGSEGV, SIG_DFL);

  } else if (signo == SIGTERM)
    recvd_signal_flags |= RECEIVED_SIG_TERMINATE;

  else if (signo == SIGXCPU)
    recvd_signal_flags |= RECEIVED_SIG_XCPU;

  else
    recvd_signal_flags |= RECEIVED_SIG_TERM_OTHER;

  /* Capture the signal number for later display purposes. */
  term_signo = signo;
}

static void handle_chld(void) {
  sigset_t sigset;
  pid_t child_pid;
  pidrec_t *child = NULL, *child_next = NULL;

  sigemptyset(&sigset);
  sigaddset(&sigset, SIGTERM);
  sigaddset(&sigset, SIGCHLD);

  block_alarms();
  sigprocmask(SIG_BLOCK, &sigset, NULL);

  /* Block SIGTERM in here, so we don't create havoc with the
   * child list while modifying it.
   */
  while ((child_pid = waitpid(-1, NULL, WNOHANG)) > 0) {
    if (child_list) {
      for (child = (pidrec_t *) child_list->xas_list; child;
          child = child_next) {
        child_next = child->next;

        if (child->pid == child_pid) {
          child_listlen--;
          have_dead_child = TRUE;
          child->dead = TRUE;
        }
      }
    }
  }

  sigprocmask(SIG_UNBLOCK, &sigset, NULL);
  unblock_alarms();
}

static void handle_xcpu(void) {
  log_pri(PR_LOG_NOTICE, "ProFTPD CPU limit exceeded (signal %d)", SIGXCPU);
  finish_terminate();
}

static void handle_terminate_other(void) {
  log_pri(PR_LOG_ERR, "ProFTPD terminating (signal %d)", term_signo);
  finish_terminate();
}

static void handle_terminate(void) {
  pidrec_t *pid = NULL;

  /* Do not log if we are a child that has been terminated. */
  if (is_master) {

    /* Send a SIGTERM to all our children */
    if (child_list) {
      PRIVS_ROOT
      for (pid = (pidrec_t *) child_list->xas_list; pid; pid = pid->next)
        kill(pid->pid, SIGTERM);
      PRIVS_RELINQUISH
    }

    log_pri(PR_LOG_NOTICE, "ProFTPD killed (signal %d)", term_signo);
  }

  finish_terminate();
}

static void finish_terminate(void) {

  if (is_master && mpid == getpid()) {
    PRIVS_ROOT

    /* Do not need the pidfile any longer. */
    if (is_standalone && !nodaemon)
      unlink(PidPath);

    /* Run any exit handlers registered in the master process here, so that
     * they may have the benefit of root privs.  More than likely these
     * exit handlers were registered by modules' module initialization
     * functions, which also occur under root priv conditions. (If an
     * exit handler is registered after the fork(), it won't be run here --
     * that registration occurs in a different process space.
     */
    run_exit_handlers();

    /* Remove the registered exit handlers now, so that the ensuing
     * end_login() call (outside the root privs condition) does not call
     * the exit handlers for the master process again.
     */
    remove_exit_handlers();

    PRIVS_RELINQUISH

    if (is_standalone) {
      log_pri(PR_LOG_NOTICE, "ProFTPD " PROFTPD_VERSION_TEXT
        " standalone mode SHUTDOWN");

      /* Clean up the scoreboard */
      PRIVS_ROOT
      pr_delete_scoreboard();
      PRIVS_RELINQUISH
    }
  }

#ifdef DEBUG_CORE
  _internal_abort();
#endif /* DEBUG_CORE */

  end_login(1);
}

static void install_signal_handlers(void) {
  sigset_t sigset;

  /* Should the master server (only applicable in standalone mode)
   * kill off children if we receive a signal that causes termination?
   * hmmmm... Maybe this needs to be rethought, but I've done it in
   * such a way as to only kill off our children if we receive a SIGTERM,
   * meaning that the admin wants us dead (and prolly our kids too).
   */

  /* The sub-pool for the child list is created the first time we fork
   * off a child.  To conserve memory, the pool and list is destroyed
   * when our last child dies (to prevent the list from eating more and
   * more memory on long uptimes)
   */

  sigemptyset(&sigset);
  sigaddset(&sigset,SIGCHLD);
  sigaddset(&sigset,SIGINT);
  sigaddset(&sigset,SIGQUIT);
  sigaddset(&sigset,SIGILL);
  sigaddset(&sigset,SIGABRT);
  sigaddset(&sigset,SIGFPE);
  sigaddset(&sigset,SIGSEGV);
  sigaddset(&sigset,SIGALRM);
  sigaddset(&sigset,SIGTERM);
#ifdef SIGSTKFLT
  sigaddset(&sigset,SIGSTKFLT);
#endif
#ifdef SIGIO
  sigaddset(&sigset,SIGIO);
#endif
#ifdef SIGBUS
  sigaddset(&sigset,SIGBUS);
#endif
  sigaddset(&sigset,SIGHUP);
  sigaddset(&sigset,SIGUSR2);

  signal(SIGCHLD,sig_child);
  signal(SIGHUP,sig_rehash);
  signal(SIGUSR2,sig_debug);

#ifndef DEBUG_NOSIG
  signal(SIGINT,sig_terminate);
  signal(SIGQUIT,sig_terminate);
  signal(SIGILL,sig_terminate);
  signal(SIGABRT,sig_abort);
  signal(SIGFPE,sig_terminate);
  signal(SIGSEGV,sig_terminate);
  signal(SIGTERM,sig_terminate);
  signal(SIGXCPU,sig_terminate);
#ifdef SIGSTKFLT
  signal(SIGSTKFLT,sig_terminate);
#endif /* SIGSTKFLT */
#ifdef SIGIO
  signal(SIGIO,sig_terminate);
#endif
#ifdef SIGBUS
  signal(SIGBUS,sig_terminate);
#endif /* SIGBUS */
#endif /* DEBUG_NOSIG */

#ifdef SIGIO
  signal(SIGIO,SIG_IGN);
#endif
  signal(SIGURG,SIG_IGN);

  /* In case our parent left signals blocked (as happens under some
   * poor inetd implementations)
   */
  sigprocmask(SIG_UNBLOCK,&sigset,NULL);
}

void set_daemon_rlimits(void) {
  config_rec *c = NULL;
  struct rlimit rlim;

  if (getrlimit(RLIMIT_CORE, &rlim) == -1)
    log_pri(PR_LOG_ERR, "error: getrlimit(RLIMIT_CORE): %s", strerror(errno));
  else {
#ifdef DEBUG_CORE
    if (abort_core)
      rlim.rlim_cur = rlim.rlim_max = RLIM_INFINITY;
    else
#endif /* DEBUG_CORE */
      rlim.rlim_cur = rlim.rlim_max = 0;

    PRIVS_ROOT
    if (setrlimit(RLIMIT_CORE, &rlim) == -1) {
      PRIVS_RELINQUISH
      log_pri(PR_LOG_ERR, "error: setrlimit(RLIMIT_CORE): %s", strerror(errno));
      return;
    }
    PRIVS_RELINQUISH
  }

  /* Now check for the configurable resource limits */
  c = find_config(main_server->conf, CONF_PARAM, "RLimitCPU", FALSE);

#ifdef RLIMIT_CPU
  while (c) {
    /* Does this limit apply to the daemon? */
    if (c->argv[1] == NULL || !strcmp(c->argv[1], "daemon")) {
      struct rlimit *cpu_rlimit = (struct rlimit *) c->argv[0];

      PRIVS_ROOT
      if (setrlimit(RLIMIT_CPU, cpu_rlimit) == -1) {
        PRIVS_RELINQUISH
        log_pri(PR_LOG_ERR, "error: setrlimit(RLIMIT_CPU): %s",
          strerror(errno));
        return;
      }
      PRIVS_RELINQUISH

      log_debug(DEBUG2, "set RLimitCPU for daemon");
    }

    c = find_config_next(c, c->next, CONF_PARAM, "RLimitCPU", FALSE);
  }
#endif /* defined RLIMIT_CPU */

  c = find_config(main_server->conf, CONF_PARAM, "RLimitMemory", FALSE);

#if defined(RLIMIT_AS) || defined(RLIMIT_DATA) || defined(RLIMIT_VMEM)
  while (c) {
    /* Does this limit apply to the daemon? */
    if (c->argv[1] == NULL || !strcmp(c->argv[1], "daemon")) {
      struct rlimit *memory_rlimit = (struct rlimit *) c->argv[0];

      PRIVS_ROOT
#  if defined(RLIMIT_AS)
      if (setrlimit(RLIMIT_AS, memory_rlimit) == -1) {
        PRIVS_RELINQUISH
        log_pri(PR_LOG_ERR, "error: setrlimit(RLIMIT_AS): %s", strerror(errno));
        return;
      }
#  elif defined(RLIMIT_DATA)
      if (setrlimit(RLIMIT_DATA, memory_rlimit) == -1) {
        PRIVS_RELINQUISH
        log_pri(PR_LOG_ERR, "error: setrlimit(RLIMIT_DATA): %s",
          strerror(errno));
        return;
      }
#  elif defined(RLIMIT_VMEM)
      if (setrlimit(RLIMIT_VMEM, memory_rlimit) == -1) {
        PRIVS_RELINQUISH
        log_pri(PR_LOG_ERR, "error: setrlimit(RLIMIT_VMEM): %s",
          strerror(errno));
        return;
      }
#  endif
      PRIVS_RELINQUISH

      log_debug(DEBUG2, "set RLimitMemory for daemon");
    }

    c = find_config_next(c, c->next, CONF_PARAM, "RLimitMemory", FALSE);
  }
#endif /* no RLIMIT_AS || RLIMIT_DATA || RLIMIT_VMEM */

  c = find_config(main_server->conf, CONF_PARAM, "RLimitOpenFiles", FALSE);

#if defined(RLIMIT_NOFILE) || defined(RLIMIT_OFILE)
  while (c) {
    /* Does this limit apply to the daemon? */
    if (c->argv[1] == NULL || !strcmp(c->argv[1], "daemon")) {
      struct rlimit *nofile_rlimit = (struct rlimit *) c->argv[0];

      PRIVS_ROOT
#  if defined(RLIMIT_NOFILE)
      if (setrlimit(RLIMIT_NOFILE, nofile_rlimit) == -1) {
        PRIVS_RELINQUISH
        log_pri(PR_LOG_ERR, "error: setrlimit(RLIMIT_NOFILE): %s",
          strerror(errno));
        return;
      }
#  elif defined(RLIMIT_OFILE)
      if (setrlimit(RLIMIT_OFILE, nofile_rlimit) == -1) {
        PRIVS_RELINQUISH
        log_pri(PR_LOG_ERR, "error: setrlimit(RLIMIT_OFILE): %s",
          strerror(errno));
        return;
      }
#  endif
      PRIVS_RELINQUISH

      log_debug(DEBUG2, "set RLimitOpenFiles for daemon");
    }

    c = find_config_next(c, c->next, CONF_PARAM, "RLimitOpenFiles", FALSE);
  }
#endif /* defined RLIMIT_NOFILE or defined RLIMIT_OFILE */
}

void set_session_rlimits(void) {
  config_rec *c = NULL;

  /* now check for the configurable rlimits */
  c = find_config(main_server->conf, CONF_PARAM, "RLimitCPU", FALSE);

#ifdef RLIMIT_CPU
  while (c) {
    /* Does this limit apply to the session? */
    if (c->argv[1] == NULL || !strcmp(c->argv[1], "session")) {
      struct rlimit *cpu_rlimit = (struct rlimit *) c->argv[0];

      PRIVS_ROOT
      if (setrlimit(RLIMIT_CPU, cpu_rlimit) == -1) {
        PRIVS_RELINQUISH
        log_pri(PR_LOG_ERR, "error: setrlimit(RLIMIT_CPU): %s",
          strerror(errno));
        return;
      }
      PRIVS_RELINQUISH

      log_debug(DEBUG2, "set RLimitCPU for session");
    }

    c = find_config_next(c, c->next, CONF_PARAM, "RLimitCPU", FALSE);
  }
#endif /* defined RLIMIT_CPU */

  c = find_config(main_server->conf, CONF_PARAM, "RLimitMemory", FALSE);

#if defined(RLIMIT_AS) || defined(RLIMIT_DATA) || defined(RLIMIT_VMEM)
  while (c) {
    /* Does this limit apply to the session? */
    if (c->argv[1] == NULL || !strcmp(c->argv[1], "session")) {
      struct rlimit *memory_rlimit = (struct rlimit *) c->argv[0];

      PRIVS_ROOT
#  if defined(RLIMIT_AS)
      if (setrlimit(RLIMIT_AS, memory_rlimit) == -1) {
        PRIVS_RELINQUISH
        log_pri(PR_LOG_ERR, "error: setrlimit(RLIMIT_AS): %s", strerror(errno));
        return;
      }
#  elif defined(RLIMIT_DATA)
      if (setrlimit(RLIMIT_DATA, memory_rlimit) == -1) {
        PRIVS_RELINQUISH
        log_pri(PR_LOG_ERR, "error: setrlimit(RLIMIT_DATA): %s",
          strerror(errno));
        return;
      }
#  elif defined(RLIMIT_VMEM)
      if (setrlimit(RLIMIT_VMEM, memory_rlimit) == -1) {
        PRIVS_RELINQUISH
        log_pri(PR_LOG_ERR, "error: setrlimit(RLIMIT_VMEM): %s",
          strerror(errno));
        return;
      }
#  endif
      PRIVS_RELINQUISH

      log_debug(DEBUG2, "set RLimitMemory for session");
    }

    c = find_config_next(c, c->next, CONF_PARAM, "RLimitMemory", FALSE);
  }
#endif /* no RLIMIT_AS || RLIMIT_DATA || RLIMIT_VMEM */

  c = find_config(main_server->conf, CONF_PARAM, "RLimitOpenFiles", FALSE);

#if defined(RLIMIT_NOFILE) || defined(RLIMIT_OFILE)
  while (c) {
    /* Does this limit apply to the session? */
    if (c->argv[1] == NULL || !strcmp(c->argv[1], "session")) {
      struct rlimit *nofile_rlimit = (struct rlimit *) c->argv[0];

      PRIVS_ROOT
#  if defined(RLIMIT_NOFILE)
      if (setrlimit(RLIMIT_NOFILE, nofile_rlimit) == -1) {
        PRIVS_RELINQUISH
        log_pri(PR_LOG_ERR, "error: setrlimit(RLIMIT_NOFILE): %s",
          strerror(errno));
        return;
      }
#  elif defined(RLIMIT_OFILE)
      if (setrlimit(RLIMIT_OFILE, nofile_rlimit) == -1) {
        PRIVS_RELINQUISH
        log_pri(PR_LOG_ERR, "error: setrlimit(RLIMIT_OFILE): %s",
          strerror(errno));
        return;
      }
#  endif /* defined RLIMIT_OFILE */
      PRIVS_RELINQUISH

      log_debug(DEBUG2, "set RLimitOpenFiles for session");
    }

    c = find_config_next(c, c->next, CONF_PARAM, "RLimitOpenFiles", FALSE);
  }
#endif /* defined RLIMIT_NOFILE or defined RLIMIT_OFILE */
}

static void write_pid(void) {
  FILE *pidf = NULL;

  PidPath = get_param_ptr(main_server->conf, "PidFile", FALSE);
  if (!PidPath || !*PidPath)
    PidPath = PID_FILE_PATH;

  PRIVS_ROOT
  if ((pidf = fopen(PidPath, "w")) == NULL) {
    PRIVS_RELINQUISH
    perror(PidPath);
    exit(1);
  }
  PRIVS_RELINQUISH

  fprintf(pidf, "%lu\n", (unsigned long) getpid());
  fclose(pidf);
  pidf = NULL;
}

static void daemonize(void) {
#ifndef HAVE_SETSID
  int ttyfd;
#endif

  /* Fork off and have parent exit.
   */
  switch (fork()) {
    case -1: perror("fork"); exit(1);
    case 0: break;
    default: exit(0);
  }

#ifdef HAVE_SETSID
  /* setsid() is the preferred way to disassociate from the
   * controlling terminal
   */
  setsid();
#else
  /* Open /dev/tty to access our controlling tty (if any) */
  if ( (ttyfd = open("/dev/tty",O_RDWR)) != -1)
  {
    if (ioctl(ttyfd,TIOCNOTTY,NULL) == -1) {
      perror("ioctl"); exit(1);
    }

    close(ttyfd);
  }
#endif /* HAVE_SETSID */

  /* Close the three big boys */
  close(fileno(stdin));
  close(fileno(stdout));
  close(fileno(stderr));

  /* Portable way to prevent re-acquiring a tty in the future */

#ifdef HAVE_SETPGID
  setpgid(0,getpid());
#else
# ifdef SETPGRP_VOID
  setpgrp();
# else
  setpgrp(0,getpid());
# endif
#endif

  pr_fsio_chdir("/", 0);
}

static void inetd_main(void) {
  int res = 0;

  /* Make sure the scoreboard file exists. */
  PRIVS_ROOT
  if ((res = pr_open_scoreboard(O_RDWR, NULL)) < 0) {
    PRIVS_RELINQUISH

    switch (res) {
      case -1:
        log_pri(PR_LOG_ERR, "error: unable to open scoreboard: %s",
          strerror(errno));
        return;

      case PR_SCORE_ERR_BAD_MAGIC:
        log_pri(PR_LOG_ERR, "error: scoreboard is corrupted or old");
        return;

      case PR_SCORE_ERR_OLDER_VERSION:
        log_pri(PR_LOG_ERR, "error: scoreboard is too old");
        return;

      case PR_SCORE_ERR_NEWER_VERSION:
        log_pri(PR_LOG_ERR, "error: scoreboard is too new");
        return;
    }
  }
  PRIVS_RELINQUISH
  pr_close_scoreboard();

  pr_init_bindings();

  /* Check our shutdown status */
  if (check_shutmsg(&shut, &deny, &disc, shutmsg, sizeof(shutmsg)) == 1)
    shutdownp = 1;

  /* Finally, call right into fork_server() to start servicing the
   * connection immediately
   */
  fork_server(STDIN_FILENO, main_server->listen, TRUE);
}

static void standalone_main(void) {
  int res = 0;

  is_standalone = TRUE;

  if (nodaemon) {
    log_stderr(TRUE);
    close(fileno(stdin));
    close(fileno(stdout));

  } else {
    log_stderr(FALSE);
    daemonize();
  }

  mpid = getpid();

  PRIVS_ROOT
  pr_delete_scoreboard();
  if ((res = pr_open_scoreboard(O_RDWR, NULL)) < 0) {
    PRIVS_RELINQUISH

    switch (res) {
      case -1:
        log_pri(PR_LOG_ERR, "error: unable to open scoreboard: %s",
          strerror(errno));
        return;

      case PR_SCORE_ERR_BAD_MAGIC:
        log_pri(PR_LOG_ERR, "error: scoreboard is corrupted or old");
        return;

      case PR_SCORE_ERR_OLDER_VERSION:
        log_pri(PR_LOG_ERR, "error: scoreboard is too old");
        return;

      case PR_SCORE_ERR_NEWER_VERSION:
        log_pri(PR_LOG_ERR, "error: scoreboard is too new");
        return;
    }
  }
  PRIVS_RELINQUISH
  pr_close_scoreboard();

  pr_init_bindings();

  log_pri(PR_LOG_NOTICE, "ProFTPD %s (built %s) standalone mode STARTUP",
    PROFTPD_VERSION_TEXT " " PR_STATUS, BUILD_STAMP);

  write_pid();
  server_loop();
}

extern char *optarg;
extern int optind,opterr,optopt;

#ifdef HAVE_GETOPT_LONG
static struct option opts[] = {
  { "nodaemon",	  0, NULL, 'n' },
  { "debug",	  1, NULL, 'd' },
  { "define",	  1, NULL, 'D' },
  { "config",	  1, NULL, 'c' },
  { "persistent", 1, NULL, 'p' },
  { "list",       0, NULL, 'l' },
  { "version",    0, NULL, 'v' },
  { "version-status",0,NULL,1 },
  { "configtest", 0, NULL, 't' },
#ifdef DEBUG_CORE
  { "core",     0, NULL, 'o' },
#endif /* DEBUG_CORE */
  { "help",	0, NULL, 'h' },
  { NULL,	0, NULL,  0  }
};
#endif /* HAVE_GETOPT_LONG */

static struct option_help {
  char *long_opt,*short_opt,*desc;
} opts_help[] = {
  { "--help", "-h",
    "Display proftpd usage"},
  { "--nodaemon", "-n",
    "Disable background daemon mode (all output goes to tty, instead of syslog)" },
  { "--debug", "-d [level]",
    "Set debugging level (0-9, 9 = most debugging)" },
  { "--define", "-D [definition]",
    "Set arbitrary IfDefine definition" },
  { "--config", "-c [config-file]",
    "Specify alternate configuration file" },
  { "--persistent", "-p [0|1]",
    "Enable/disable default persistent passwd support" },
  { "--list", "-l",
    "List all compiled-in modules" },
  { "--configtest", "-t",
    "Test the syntax of the specified config" },
#ifdef DEBUG_CORE
  { "--core","-o","enable core dump for profiling/debugging on serious errors"},
#endif /* DEBUG_CORE */
  { "--version", "-v",
    "Print version number and exit" },
  { "--version-status","-vv",
    "Print extended version information and exit" },
  { NULL, NULL, NULL }
};

static void show_usage(int exit_code) {
  struct option_help *h;

  printf("usage: proftpd [options]\n");
  for(h = opts_help; h->long_opt; h++) {
#ifdef HAVE_GETOPT_LONG
    printf(" %s, %s\n ", h->long_opt, h->short_opt);
#else /* HAVE_GETOPT_LONG */
    printf(" %s\n", h->short_opt);
#endif /* HAVE_GETOPT_LONG */
    printf("    %s\n", h->desc);
  }

  exit(exit_code);
}

int main(int argc, char *argv[], char **envp) {
  int socketp, optc;
  mode_t *main_umask = NULL;
  int check_config_syntax = 0;
  int show_version = 0;
  struct sockaddr peer;
  const char *cmdopts = "D:nd:c:p:lhtv"

#ifdef DEBUG_CORE
    "o"
#endif /* DEBUG_CORE */
    ;

#ifdef DEBUG_MEMORY
  int logfd;
  extern int EF_PROTECT_BELOW;
  extern int EF_PROTECT_FREE;
  extern int EF_ALIGNMENT;

  EF_PROTECT_BELOW = 1;/* */
  EF_PROTECT_FREE = 1; /* */
  EF_ALIGNMENT = 0; /* */

  /* Redirect stderr to somewhere appropriate.
   * Ideally, this would be syslog, but alas...
   */
  if ((logfd = open(RUN_DIR "/proftpd-memory.log",
		   O_WRONLY | O_CREAT | O_APPEND, 0644))< 0) {
	log_pri(PR_LOG_ERR, "Error opening error logfile: %s", strerror(errno));
	exit(1);
  }

  close(fileno(stderr));
  if (dup2(logfd, fileno(stderr)) == -1) {
	log_pri(PR_LOG_ERR, "Error converting standard error to a logfile: %s",
					strerror(errno));
	exit(1);
  }
  close(logfd);
#endif /* DEBUG_MEMORY */

#ifdef HAVE_SET_AUTH_PARAMETERS
  (void) set_auth_parameters(argc, argv);
#endif

#ifdef HAVE_TZSET
  /* Preserve timezone information in jailed environments.
   */
  tzset();
#endif

  memset(&session, 0, sizeof(session));

  /* Initialize stuff for set_proc_title.
   */
  init_set_proc_title(argc, argv, envp);

  /* Seed rand */
  srand(time(NULL));

  /* getpeername() fails if the fd isn't a socket */
  socketp = sizeof(peer);
  if (getpeername(fileno(stdin),&peer,&socketp) != -1) {
    log_stderr(FALSE);
    socketp = TRUE;
  } else
    socketp = FALSE;

  /* Open the syslog */
  log_opensyslog(NULL);

  /* Initialize the memory subsystem here */
  pr_init_pools();

  /* Command line options supported:
   *
   * -D parameter       set run-time configuration parameter
   * --define parameter
   * -c path            set the configuration path
   * --config path
   * -d n               set the debug level
   * --debug n
   * -n                 standalone server does not daemonize, all logging
   * --nodaemon         redirected to stderr
   * -o                 enable gracefule coredumps, dropping things into
   * --core                       CORE_DIR
   * -t                 syntax check of the configuration file
   * --configtest
   * -v                 report version number
   * --version
   */

  opterr = 0;
  while((optc =
#ifdef HAVE_GETOPT_LONG
	 getopt_long(argc, argv, cmdopts, opts, NULL)
#else /* HAVE_GETOPT_LONG */
	 getopt(argc, argv, cmdopts)
#endif /* HAVE_GETOPT_LONG */
	 ) != -1) {
    switch (optc) {
    case 'D':
      if (!optarg) {
        log_pri(PR_LOG_ERR, "Fatal: -D requires definition argument");
        exit(1);
      }

      /* if this is the first time through, allocate an array_header
       * for these command-line definitions
       */
      if (!server_defines)
        server_defines = make_array(permanent_pool, 0, sizeof(char *));

      *((char **) push_array(server_defines)) = pstrdup(permanent_pool, optarg);
      break;
    case 'n':
      nodaemon++;
      break;
    case 'd':
      if (!optarg) {
        log_pri(PR_LOG_ERR, "Fatal: -d requires debugging level argument.");
        exit(1);
      }
      log_setdebuglevel(atoi(optarg));
      break;
    case 'c':
      if (!optarg) {
        log_pri(PR_LOG_ERR,"Fatal: -c requires configuration path argument.");
        exit(1);
      }
      config_filename = strdup(optarg);
      break;

    case 'l':
      list_modules();
      exit(0);
      break;

    case 't':
      check_config_syntax = 1;
      printf("Checking syntax of configuration file\n");
      fflush(stdout);
      break;

    case 'p':
    {

      /* From mod_unixpw.c */
      extern unsigned char unixpw_persistent;

      if (!optarg ||
          ((unixpw_persistent = atoi(optarg)) != 1 && unixpw_persistent != 0)) {
        log_pri(PR_LOG_ERR, "Fatal: -p requires boolean (0|1) argument.");
        exit(1);
      }

      break;
    }
#ifdef DEBUG_CORE
    case 'o':
      abort_core = 1;
      break;
#endif /* DEBUG_CORE */
    case 'v':
      show_version++;
      break;
    case 1:
      show_version = 2;
      break;
    case 'h':
      show_usage(0);
    case '?':
      log_pri(PR_LOG_ERR, "unknown option: %c", (char)optopt);
      show_usage(1);
    }
  }

  if (show_version) {
    if (show_version == 1)
      log_pri(PR_LOG_NOTICE, "ProFTPD Version " PROFTPD_VERSION_TEXT);

    else {
      log_pri(PR_LOG_NOTICE, "         Version: %s",
        PROFTPD_VERSION_TEXT " " PR_STATUS);
      log_pri(PR_LOG_NOTICE, "Scoreboard Version: %08x", PR_SCOREBOARD_VERSION);
      log_pri(PR_LOG_NOTICE, "     Build Stamp: %s", BUILD_STAMP);
    }

    exit(0);
  }

  /* Initialize sub-systems */
  pr_init_pools();
  pr_init_regexp();
  init_log();
  init_inet();
  pr_init_netio();
  pr_init_fs();
  pr_free_bindings();
  init_config();
  pr_preparse_init_modules();

  init_conf_stacks();
  if (parse_config_file(config_filename) == -1) {
    log_pri(PR_LOG_ERR, "Fatal: unable to read configuration file '%s'",
      config_filename);
    exit(1);
  }

  free_conf_stacks();
  fixup_servers();

  pr_postparse_init_modules();
  pr_remove_postparse_inits();

  /* We're only doing a syntax check of the configuration file.
   */
  if (check_config_syntax) {
    printf("Syntax check complete.\n");
    end_login(0);
  }

  /* After configuration is complete, make sure that passwd, group
   * aren't held open (unnecessary fds for master daemon)
   */
  endpwent();
  endgrent();

  /* Security */
  {
    uid_t *uid = (uid_t *) get_param_ptr(main_server->conf, "UserID", FALSE);
    gid_t *gid = (gid_t *) get_param_ptr(main_server->conf, "GroupID", FALSE);

    if (uid)
      daemon_uid = *uid;
    else
      daemon_uid = 0;

    if (gid)
      daemon_gid = *gid;
    else
      daemon_gid = 0;
  }

  if (daemon_uid) {
    /* allocate space for daemon supplemental groups
     */
    daemon_gids = make_array(permanent_pool, 2, sizeof(gid_t));

    if (auth_getgroups(permanent_pool, (const char *) get_param_ptr(
        main_server->conf, "UserName", FALSE), &daemon_gids, NULL) < 0)
      log_debug(DEBUG2, "unable to retrieve daemon supplemental groups");

    if (set_groups(permanent_pool, daemon_gid, daemon_gids) < 0)
      log_pri(PR_LOG_ERR, "unable to set daemon groups: %s",
        strerror(errno));
  }

   if ((main_umask = (mode_t *) get_param_ptr(main_server->conf, "Umask",
       FALSE)) == NULL)
     umask((mode_t) 0022);
   else
     umask(*main_umask);

  /* Give up root and save our uid/gid for later use (if supported)
   * If we aren't currently root, PRIVS_SETUP will get rid of setuid
   * granted root and prevent further uid switching from being attempted.
   */

  PRIVS_SETUP(daemon_uid, daemon_gid)

  /* Test to make sure that our uid/gid is correct.  Try to do this in
   * a portable fashion *gah!*
   */

  if (geteuid() != daemon_uid) {
    log_pri(PR_LOG_ERR, "unable to set uid to %lu, current uid: %lu",
		    (unsigned long)daemon_uid,(unsigned long)geteuid());
    exit(1);
  }

  if (getegid() != daemon_gid) {
    log_pri(PR_LOG_ERR, "unable to set gid to %lu, current gid: %lu",
		    (unsigned long)daemon_gid,(unsigned long)getegid());
    exit(1);
  }

  /* Install a signal handlers/abort handler */
  install_signal_handlers();
  set_daemon_rlimits();

  switch (ServerType) {
    case SERVER_STANDALONE:
      standalone_main();

    case SERVER_INETD:
      inetd_main();
  }

  return 0;
}
