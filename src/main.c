/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
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
 */

/*
 * House initialization and main program loop
 * $Id: main.c,v 1.15 1999-09-16 17:20:51 macgyver Exp $
 */

/*
 * History Log:
 *
 * 9/21/97 current: 0.99.0pl6, next: 0.99.0pl7
 *   Removed the -o (--core) option, because some kernels won't
 *   produce a core dump after the euid/egid have changed.  If
 *   anyone knows a way around this, please let me know.
 * 4/28/97 current: 0.99.0pl1, next: 0.99.0pl2
 *   Added checking for <Limit LOGIN> in fork_server(), in order
 *   to disconnect any connections which can never be authorized.
 * 4/24/97 current: 0.99.0pl1, next: 0.99.0pl2
 *   Removed include/proftpd_conf.h; unnecessary header file
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

#include "privs.h"

struct rehash {
  struct rehash *next;

  void *data;
  void (*rehash)(void*);
};

typedef struct _pidrec {
  struct _pidrec *next,*prev;

  pid_t pid;
  int dead;
} pidrec_t;

typedef struct _binding {
  struct _binding *next;

  server_rec *server;			/* server to handle request */
  p_in_addr_t ipaddr;			/* ip address "bound" to */
  int        port;
  conn_t     *listen;			/* listen connection (if separate) */
  char       isdefault;			/* if default connection */
  char       islocalhost;		/* if handles localhost */
} binding_t;

void addl_bindings(server_rec*);

extern xaset_t *servers;

session_t session;
int master = TRUE;			/* Master daemon in standalone mode */
int standalone = 0;			/* If in standalone mode */
pid_t mpid = 0;				/* Master pid */
int rehash = 0;				/* Performing rehash? */
struct rehash *rehash_list = NULL;	/* Pre-rehash callbacks */
binding_t *bind_list = NULL;
pool *bind_pool = NULL;

time_t shut = (time_t)0,deny = (time_t)0, disc = (time_t)0;
char shutmsg[81] = "";

xaset_t *children = NULL;
static int child_count = 0,child_flag = 0;

response_t *resp_list = NULL,*resp_err_list = NULL;
static pool *resp_pool = NULL;
static int (*main_check_auth)(cmd_rec*) = NULL;
static char sbuf[1024];
static char _ml_numeric[4];
static char **Environment = NULL;
static char **Argv = NULL;
static char *LastArgv = NULL;

static int shutdownp = 0;
static int abort_core = 0;
static RETSIGTYPE sig_disconnect(int);
static RETSIGTYPE sig_debug(int);

char *config_filename = CONFIG_FILE_PATH;

#if 0
void test_fs()
{
  glob_t pglob;
  char buf[1024];
  char **cp;
  int fd;
  fsdir_t *f;
  size_t l;

  bzero(&pglob,sizeof(pglob));

  chdir("/");
  fs_setcwd("/");
  if(fs_chdir("~flood/test",TRUE) == -1)
    perror("fs_chdir [tmp]");

  fs_chdir("test.tar/foo",1);

  printf("cwd: %s\n",fs_getcwd());
  printf("vwd: %s\n",fs_getvwd());

  f = fs_open("TESTFILE",O_RDONLY,&fd);
  if(!f) {
    perror("fs_open");
    exit(1);
  }

  fs_lseek(f,fd,-1024,SEEK_END);
  while((l = fs_read(f,fd,buf,sizeof(buf)-1)) > 0) {
    buf[l] = '\0';
    printf("%s",buf);
  }

  fs_close(f,fd);
  exit(0);

  if(fs_glob("*",GLOB_PERIOD,0,&pglob) == -1)
    perror("fs_glob");
  else {
    cp = pglob.gl_pathv;
    while(pglob.gl_pathc--) {
      printf("matched: %s\n",*cp);
      cp++;
    }
  }

  exit(0);
}
#endif

int add_binding(server_rec *server, p_in_addr_t *ipaddr, conn_t *listen,
                char isdefault, char islocalhost)
{
  binding_t *b;

  for(b = bind_list; b; b=b->next)
    if(b->ipaddr.s_addr == ipaddr->s_addr &&
       b->port == server->ServerPort) {
      /* binding already exists for this IP */
      log_pri(LOG_NOTICE,"cannot bind %s:%d to server '%s', already bound to '%s'.",
              inet_ntoa(*ipaddr),server->ServerPort,
              server->ServerName,b->server->ServerName);
      return -1;
    }

  if(!bind_pool)
    bind_pool = make_sub_pool(permanent_pool);

  b = palloc(bind_pool,sizeof(binding_t));
  b->server = server;
  b->port = server->ServerPort;
  b->ipaddr = *ipaddr;
  b->listen = listen;
  b->isdefault = isdefault;
  b->islocalhost = islocalhost;

  b->next = bind_list;
  bind_list = b;

  return 0;
}

server_rec *find_binding(p_in_addr_t *ipaddr, int port)
{
  binding_t *b,*local_b = NULL,*default_b = NULL;

  for(b = bind_list; b; b=b->next) {
    if(b->ipaddr.s_addr == ipaddr->s_addr && (!b->port || b->port == port))
      return b->server;

    if(b->islocalhost)
      local_b = b;
    if(b->isdefault)
      default_b = b;
  }

  /* Not found in binding list, so see if it's the loopback address */
  if(local_b) {
    p_in_addr_t loopback,loopmask,tmp;

#ifdef HAVE_INET_ATON
    inet_aton(LOOPBACK_NET,&loopback);
    inet_aton(LOOPBACK_MASK,&loopmask);
#else
    loopback.s_addr = inet_addr(LOOPBACK_NET);
    loopmask.s_addr = inet_addr(LOOPBACK_MASK);
#endif
    loopback.s_addr = ntohl(loopback.s_addr);
    loopmask.s_addr = ntohl(loopmask.s_addr);
    tmp.s_addr = ntohl(ipaddr->s_addr);

    if((tmp.s_addr & loopmask.s_addr) == loopback.s_addr &&
       (!local_b->port || port == local_b->port))
      return local_b->server;
  }

  /* otherwise, use the default server, if set */
  if(default_b)
    return default_b->server;

  return NULL;
}

conn_t *accept_binding(fd_set *rfd, int *lfd)
{
  binding_t *b;
  int fd;

  for(b = bind_list; b; b=b->next) {
    if(b->listen && FD_ISSET(b->listen->listen_fd,rfd) &&
       b->listen->mode == CM_LISTEN) {
      if((fd = inet_accept_nowait(b->listen->pool,b->listen)) == -1) {
	/* Handle errors gracefully.  If we're here, then b->listen contains
	 * either error information, or we just got caught in a blocking
	 * condition. - MacGyver
	 */
	if(b->listen->mode == CM_ERROR) {
	  log_pri(LOG_ERR, "Error: unable to accept an incoming connection (%s)",
		  strerror(b->listen->xerrno));
	  b->listen->xerrno = 0;
	  b->listen->mode = CM_LISTEN;
	  return NULL;
	}
      }
      
      *lfd = fd;
      return b->listen;
    }
  }

  return NULL;
}

void listen_binding(fd_set *rfd)
{
  binding_t *b;

  FD_ZERO(rfd);
  for(b = bind_list; b; b=b->next) {
    if(b->listen) {
      if(b->listen->mode == CM_NONE)
        inet_listen(b->listen->pool,b->listen,tcpBackLog);

      if(b->listen->mode == CM_ACCEPT)
        inet_resetlisten(b->listen->pool,b->listen);
      if(b->listen->mode == CM_LISTEN)
        FD_SET(b->listen->listen_fd,rfd);
    }
  }
}

static void init_set_proc_title(int argc, char *argv[], char *envp[])
{
#ifdef HAVE___PROGNAME
  extern char *__progname, *__progname_full;
#endif /* HAVE___PROGNAME */
  int i;
  
  Argv = argv;
  
  for(i = 0; i < argc; i++) {
    if(!i || (LastArgv + 1 == argv[i]))
      LastArgv = argv[i] + strlen(argv[i]);
  }
  
  for(i = 0; envp[i] != NULL; i++) {
    if((LastArgv + 1) == envp[i])
      LastArgv = envp[i] + strlen(envp[i]);
  }
  
#ifdef HAVE___PROGNAME
  /* Set the __progname and __progname_full variables so glibc and company don't
   * go nuts. - MacGyver
   */
  __progname = strdup("proftpd");
  __progname_full = strdup(argv[0]);
#endif /* HAVE___PROGNAME */
  
#if 0
  /* Save argument/environment globals for use by set_proc_title */

  Argv = argv;
  while(*envp)
    envp++;

  LastArgv = envp[-1] + strlen(envp[-1]);
#endif
}    

void set_proc_title(char *fmt,...)
{
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
  vsnprintf(statbuf, sizeof(statbuf), fmt, msg);

#ifdef HAVE_SETPROCTITLE
  setproctitle(statbuf);
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
  
void main_set_idle()
{
  time_t now;

  time(&now);

  log_add_run(mpid,&now,session.user,
              main_server->ipaddr,(unsigned short)main_server->ServerPort,
              0,0,"proftpd: %s - %s: IDLE",
              session.user,session.proc_prefix);
  set_proc_title("proftpd: %s - %s: IDLE",
              session.user,session.proc_prefix);
}

static void send_response_list(response_t **head)
{
  int ml = 0;
  char *last_numeric = NULL;
  response_t *t;

  for(t = *head; t; t=t->next) {
    if(ml) {
      /* look for end of multiline */
      if(!t->next || (t->num && strcmp(t->num,last_numeric) != 0)) {
        io_printf(session.c->outf,"%s %s\r\n",last_numeric,t->msg);
        ml = 0;
      } else {
	if(MultilineRFC2228)
	  io_printf(session.c->outf,"%s-%s\r\n",last_numeric,t->msg);
	else
	  io_printf(session.c->outf," %s\r\n",t->msg);
      }
    } else {
      /* look for start of multiline */
      if(t->next && (!t->next->num || strcmp(t->num,t->next->num) == 0)) {
        io_printf(session.c->outf,"%s-%s\r\n",t->num,t->msg);
        ml = 1;
        last_numeric = t->num;
      } else
        io_printf(session.c->outf,"%s %s\r\n",t->num,t->msg);
    }
  }

  *head = NULL;
}

void add_response_err(const char *numeric, const char *fmt, ...)
{
  va_list msg;
  response_t *t,**head;

  va_start(msg,fmt);
  vsnprintf(sbuf,sizeof(sbuf),fmt,msg);
  va_end(msg);

  sbuf[1023] = '\0';
  
  t = (response_t*)pcalloc(resp_pool,sizeof(response_t));
  t->num = (numeric ? pstrdup(resp_pool,numeric) : NULL);
  t->msg = pstrdup(resp_pool,sbuf);

  for(head = &resp_err_list; *head && (!numeric || !(*head)->num ||
      strcmp((*head)->num,numeric) <= 0); head = &(*head)->next) ;

  t->next = *head;
  *head = t;
}

void add_response(const char *numeric, const char *fmt, ...)
{
  va_list msg;
  response_t *t,**head;

  va_start(msg,fmt);
  vsnprintf(sbuf,sizeof(sbuf),fmt,msg);
  va_end(msg);

  sbuf[1023] = '\0';
  
  t = (response_t*)pcalloc(resp_pool,sizeof(response_t));
  t->num = (numeric ? pstrdup(resp_pool,numeric) : NULL);
  t->msg = pstrdup(resp_pool,sbuf);

  for(head = &resp_list; *head && (!numeric || !(*head)->num ||
      strcmp((*head)->num,numeric) <= 0); head = &(*head)->next) ;

  t->next = *head;
  *head = t;
}

void send_response_raw(const char *fmt, ...)
{
  va_list msg;

  va_start(msg,fmt);
  vsnprintf(sbuf,sizeof(sbuf),fmt,msg);
  va_end(msg);

  sbuf[1023] = '\0';
  io_printf(session.c->outf,"%s\r\n",sbuf);
}

void send_response_async(const char *resp_numeric, const char *fmt, ...)
{
  char buf[1023],*cp = buf;
  va_list msg;
  int maxlen;

  maxlen = sizeof(buf) - strlen(resp_numeric) - 1;

  strncpy(cp,resp_numeric,maxlen);
  cp += strlen(resp_numeric);
  *cp++ = ' ';

  va_start(msg,fmt);
  vsnprintf(cp,maxlen,fmt,msg);
  va_end(msg);

  buf[1022] = '\0';
  cp = buf + strlen(buf);
  *cp++ = '\r'; *cp++ = '\n'; *cp++ = '\0';

  io_write_async(session.c->outf,buf,strlen(buf));
}

void send_response(const char *resp_numeric, const char *fmt, ...)
{
  va_list msg;

  va_start(msg,fmt);
  vsnprintf(sbuf,sizeof(sbuf),fmt,msg);
  va_end(msg);

  sbuf[1023] = '\0';
  io_printf(session.c->outf,"%s %s\r\n",resp_numeric,sbuf);
}

void send_response_ml_start(const char *resp_numeric, const char *fmt, ...)
{
  va_list msg;

  va_start(msg,fmt);
  vsnprintf(sbuf,sizeof(sbuf),fmt,msg);
  va_end(msg);

  sbuf[1023] = '\0';
  strncpy(_ml_numeric,resp_numeric,3); _ml_numeric[3] = '\0';

  io_printf(session.c->outf,"%s-%s\r\n",_ml_numeric,sbuf);
}

void send_response_ml(const char *fmt, ...)
{
  va_list msg;

  va_start(msg,fmt);
  vsnprintf(sbuf,sizeof(sbuf),fmt,msg);
  va_end(msg);

  sbuf[1023] = '\0';

  io_printf(session.c->outf," %s\r\n",sbuf);
}

void send_response_ml_end(const char *fmt, ...)
{
  va_list msg;
 
  va_start(msg,fmt);
  vsnprintf(sbuf,sizeof(sbuf),fmt,msg);
  va_end(msg);

  sbuf[1023] = '\0';

  io_printf(session.c->outf,"%s %s\r\n",_ml_numeric,sbuf);
}

void set_auth_check(int (*ck)(cmd_rec*))
{
  main_check_auth = ck;
}

void end_login_noexit()
{
  /* Run all the exit handlers */
  run_exit_handlers();

  /* If session.user is set, we have a valid login */
  if(session.user) {
#if (defined(BSD) && (BSD >= 199103))
    snprintf(sbuf, sizeof(sbuf), "ftp%ld",(long)getpid());
#else
    snprintf(sbuf, sizeof(sbuf), "ftpd%d",(int)getpid());
#endif
    if(session.wtmp_log)
      log_wtmp(sbuf,"",
        (session.c && session.c->remote_name ? session.c->remote_name : ""),
        (session.c && session.c->remote_ipaddr ? session.c->remote_ipaddr : NULL));
    log_add_run(mpid,NULL,NULL,NULL,0,0,0,NULL);
    log_close_run();
  }
}

/* Finish any cleaning up, mark utmp as closed and exit
 * without flushing buffers
 */

void end_login(int exitcode)
{
  end_login_noexit();
  _exit(exitcode);
}

void main_exit(void *pv, void *lv, void *ev, void *dummy)
{
  int pri = (int)pv;
  char *log = (char*)lv;
  int exitcode = (int)ev;

  log_pri(pri,log);
  if(standalone && master)
    log_pri(LOG_NOTICE,"ProFTPD %s standalone mode SHUTDOWN",VERSION);
  end_login(exitcode);
}

void shutdown_exit(void *d1, void *d2, void *d3, void *d4)
{
  char *msg;

  if(check_shutmsg(&shut,&deny,&disc,shutmsg,sizeof(shutmsg)) == 1) {
    char *user;
    time_t now;

    time(&now);
    if(get_param_int(main_server->conf,"authenticated",FALSE) == 1)
      user = get_param_ptr(main_server->conf,"USER",FALSE);
    else
      user = "NONE";

    msg = sreplace(permanent_pool,shutmsg,
                   "%s",pstrdup(permanent_pool,fmt_time(shut)),
                   "%r",pstrdup(permanent_pool,fmt_time(deny)),
                   "%d",pstrdup(permanent_pool,fmt_time(disc)),
		   "%C",(session.cwd[0] ? session.cwd : "(none)"),
		   "%L",main_server->ServerAddress,
		   "%R",(session.c && session.c->remote_name ?
                         session.c->remote_name : "(unknown)"),
		   "%T",pstrdup(permanent_pool,fmt_time(now)),
		   "%U",user,
		   "%V",main_server->ServerName,
                   NULL );

    send_response_async(R_421,"FTP server shutting down - %s",msg);

    main_exit((void*)LOG_NOTICE,msg,(void*)0,NULL);
  }

  signal(SIGUSR1,sig_disconnect);
}

static int _dispatch(cmd_rec *cmd, int cmd_type, int validate, char *match)
{
  char *argstr;
  cmdtable *c;
  modret_t *mr;
  int success = 0;
  int send_error = 0;
  static int match_index_cache = -1;
  static char *last_match = NULL;
  int *index_cache;

  send_error = (cmd_type == CMD || cmd_type == PRE_CMD);

  if(!match) {
    match = cmd->argv[0];
    index_cache = &cmd->symtable_index;
  } else {
    if(last_match != match) {
      match_index_cache = -1;
      last_match = match;
    }

    index_cache = &match_index_cache;
  }

  c = mod_find_cmd_symbol(match,index_cache,NULL);
  while(c && !success) {
    if(c->cmd_type == cmd_type) {
      if(c->group)
        cmd->group = pstrdup(cmd->pool,c->group);

      if(c->requires_auth && main_check_auth && !main_check_auth(cmd))
        return -1;

#if 0
      if(!c->interrupt_xfer && (session.flags & SF_XFER)) {
        if(send_error)
          add_response_err(R_451,"Cannot accept command, transfer is in progress.");
        success = -1;
        break;
      }
#endif

      cmd->tmp_pool = make_named_sub_pool(cmd->pool,"temp - dispatch pool");

      argstr = make_arg_str(cmd->tmp_pool,cmd->argc,cmd->argv);

      if(session.user && (session.flags & SF_XFER) == 0 &&
         cmd_type == CMD) {
        log_add_run(mpid,NULL,session.user,NULL,0,0,0,"proftpd: %s - %s: %s",
                    session.user,session.proc_prefix,
                    make_arg_str(cmd->tmp_pool,cmd->argc,cmd->argv));
        set_proc_title("proftpd: %s - %s: %s",
                       session.user,session.proc_prefix,
                       argstr);
      }

      /* Hack to hide passwords */

      if(send_error) {
        if(!strcasecmp(cmd->argv[0],"PASS"))
          log_debug(DEBUG4,"received: PASS (hidden)");
        else
          log_debug(DEBUG4,"received: %s",argstr);
      }

      cmd->class |= c->class;

      /* KLUDGE: disable umask() for not G_WRITE operations.  Config/
       * Directory walking code will be completely redesigned in 1.3,
       * this is only necessary for perfomance reasons in 1.1/1.2
       */

      if(!c->group || strcmp(c->group,G_WRITE) != 0)
        kludge_disable_umask();
      mr = call_module_cmd(c->m,c->handler,cmd);
      kludge_enable_umask();

      if(MODRET_ISHANDLED(mr))
        success = 1;
      else if(MODRET_ISERROR(mr)) {
        if(cmd_type == POST_CMD || cmd_type == LOG_CMD || 
                                   cmd_type == LOG_CMD_ERR) {
          if(MODRET_ERRMSG(mr))
            log_pri(LOG_NOTICE,"%s",MODRET_ERRMSG(mr));
        } else if(send_error) {
          if(MODRET_ERRNUM(mr) && MODRET_ERRMSG(mr))
            add_response_err(MODRET_ERRNUM(mr),MODRET_ERRMSG(mr));
          else if(MODRET_ERRMSG(mr))
            send_response_raw(MODRET_ERRMSG(mr));
        }

        success = -1;
      }

      if(session.user && (session.flags & SF_XFER) == 0 && cmd_type == CMD)
        main_set_idle();

      destroy_pool(cmd->tmp_pool);
    }

    if(!success)
      c = mod_find_cmd_symbol(match,index_cache,c);
  }

  if(!c && !success && validate) {
    add_response_err("500", "%s not understood.", cmd->argv[0]);
    success = -1;
  }

  return success;
}

static void dispatch_cmd(cmd_rec *cmd)
{
  char *cp;
  int success = 0;

  cmd->server = main_server;
  resp_list = resp_err_list = NULL;
  resp_pool = cmd->pool;

  for(cp = cmd->argv[0]; *cp; cp++)
    *cp = toupper(*cp);

  /* debug_print_dispatch(cmd); */

  /* first dispatch PRE_CMD with wildcard */
  success = _dispatch(cmd,PRE_CMD,FALSE,"*");

  if(!success)	/* run other pre_cmd */
    success = _dispatch(cmd,PRE_CMD,FALSE,NULL);

  if(success < 0) {
    send_response_list(&resp_err_list);
    return;
  }

  success = _dispatch(cmd,CMD,FALSE,"*");
  if(!success)
    success = _dispatch(cmd,CMD,TRUE,NULL);

  if(success == 1) {
    success = _dispatch(cmd,POST_CMD,FALSE,"*");
    if(!success)
      success = _dispatch(cmd,POST_CMD,FALSE,NULL);

    _dispatch(cmd,LOG_CMD,FALSE,"*");
    _dispatch(cmd,LOG_CMD,FALSE,NULL);

    send_response_list(&resp_list);
  } else if(success < 0) {
    _dispatch(cmd,LOG_CMD_ERR,FALSE,"*");
    _dispatch(cmd,LOG_CMD_ERR,FALSE,NULL);

    send_response_list(&resp_err_list);
  }
}

cmd_rec *make_cmd(pool *p, char *buf)
{
  char *cp = buf, *wrd;
  cmd_rec *newcmd;
  pool *newpool;
  array_header *tarr;

  newpool = make_sub_pool(p);
  newcmd = (cmd_rec*)pcalloc(newpool,sizeof(cmd_rec));
  newcmd->pool = newpool;
  newcmd->symtable_index = -1;
  tarr = make_array(newpool,2,sizeof(char*));

  if((wrd = get_word(&cp)) != NULL) {
    *((char**)push_array(tarr)) = pstrdup(newpool,wrd);
    newcmd->argc++;
    newcmd->arg = pstrdup(newpool,cp);
 
    while((wrd = get_word(&cp)) != NULL) {
      *((char**)push_array(tarr)) = pstrdup(newpool,wrd);
      newcmd->argc++;
    }
  }

  *((char**)push_array(tarr)) = NULL;

  newcmd->argv = (char**)tarr->elts;

  return newcmd;
}

static int _idle_timeout(CALLBACK_FRAME)
{
  /* we don't want to quit in the middle of a transfer */
  if(session.flags & SF_XFER)
    return 1;				/* auto-restart the timer */

  send_response_async(R_421,"Idle Timeout (%d seconds): closing control connection.", 
                      TimeoutIdle);

  main_exit((void*)LOG_NOTICE,
		  "FTP session idle timeout, disconnected.",
		  (void*)0,NULL);

  remove_timer(TIMER_LOGIN,ANY_MODULE);
  remove_timer(TIMER_NOXFER,ANY_MODULE);
  return 0;
}

void cmd_loop(server_rec *server, conn_t *c)
{
  static int CmdBufSize = -1;
  config_rec *id;
  char buf[1024];
  char *cp;
  char *display;
  int i;

  /* Setup the main idle timer */
  if(TimeoutIdle)
    add_timer(TimeoutIdle,TIMER_IDLE,NULL,_idle_timeout);

  display = (char*)get_param_ptr(server->conf,"DisplayConnect",FALSE);
  if(display) {
      core_display_file(R_220,display);
  }

  if((id = find_config(server->conf,CONF_PARAM,"ServerIdent",FALSE)) == NULL ||
		  !id->argv[0]) {
    if(id && id->argc > 1)
      send_response("220","%s",(char*)id->argv[1]);
    else if(get_param_int(server->conf,"DeferWelcome",FALSE) == 1)
      send_response("220", "ProFTPD " VERSION " Server ready.");
    else
      send_response("220", "ProFTPD " VERSION " Server (%s) [%s]",
           server->ServerName,server->ServerAddress);
  }
  else
  {
    send_response("220", "%s FTP server ready.", server->ServerAddress);
  }

  /* make sure we can receive OOB data */
  inet_setasync(session.pool,session.c);

  while(1) {
    if(io_telnet_gets(buf,sizeof(buf)-1,session.c->inf,session.c->outf) == NULL) {
      if(session.c->inf->xerrno == EINTR)
	continue;		/* Simple interrupted syscall */
      
      /* Otherwise, EOF */
      log_pri(LOG_NOTICE,"FTP session closed.");
      end_login(0);
    }

    /* Data received, reset idle timer */
    if(TimeoutIdle)
      reset_timer(TIMER_IDLE,NULL);

    if(CmdBufSize == -1) {
      if((CmdBufSize = get_param_int(main_server->conf,
				     "CommandBufferSize", FALSE)) <= 0) {
	CmdBufSize = 512;
      } else if(CmdBufSize + 1 > sizeof(buf)) {
	log_pri(LOG_WARNING,
		"Invalid CommandBufferSize size given.  Resetting to 512.");
	CmdBufSize = 512;
      }
    }
    
    buf[CmdBufSize - 1] = '\0';
    i = strlen(buf);

    if(i && (buf[i-1] == '\n' || buf[i-1] == '\n')) {
      buf[i-1] = '\0'; i--;
      if(i && (buf[i-1] == '\n' || buf[i-1] =='\r'))
        buf[i-1] = '\0';
    }

    cp = buf;
    if(*cp == '\r') cp++;

    if(*cp) {
      cmd_rec *cmd;

      cmd = make_cmd(permanent_pool,cp);
      if(cmd) {
        dispatch_cmd(cmd);
        destroy_pool(cmd->pool);
      }
    }
  }
}

static void _server_conn_cleanup(void *connp)
{
  *((conn_t**)connp) = NULL;
}

void register_rehash(void *data, void (*fp)(void*))
{
  struct rehash *r = (struct rehash*)pcalloc(permanent_pool,
		  				sizeof(struct rehash));

  r->data = data;
  r->rehash = fp;
  r->next = rehash_list;
  rehash_list = r;
}

void main_rehash(void *d1,void *d2,void *d3,void *d4)
{
  struct rehash *rh;
  server_rec *s,*snext,*old_main;
  xaset_t *old_servers;
  int isdefault;

  rehash++;

  old_servers = servers;
  old_main = main_server;

  if(master && mpid) {
    log_pri(LOG_NOTICE,"received SIGHUP -- master server rehashing configuration file.");

    for(rh = rehash_list; rh; rh=rh->next)
      rh->rehash(rh->data);
    
    init_config();
    init_conf_stacks();

    PRIVS_ROOT
    if(parse_config_file(config_filename) == -1) {
      PRIVS_RELINQUISH
      log_pri(LOG_ERR,"Fatal: unable to read configuration file '%s'.",
              config_filename);
      end_login(1);
    }
    PRIVS_RELINQUISH
    free_conf_stacks();

    fixup_servers();

    /* Free old configuration completely */

    for(s = (server_rec*)old_servers->xas_list; s; s=snext) {
      snext = s->next;
      destroy_pool(s->pool);
    }

    destroy_pool(old_servers->mempool);

    /* Destroy the old bind list */
    if(bind_pool) {
      destroy_pool(bind_pool);
      bind_pool = NULL;
    }
    bind_list = NULL;

    /* Recreate the listen connection */

    if(main_server->ServerPort)
      main_server->listen =
        inet_create_connection(main_server->pool,servers,-1,
                               (SocketBindTight ? main_server->ipaddr : NULL),
  		   	       main_server->ServerPort,FALSE);
    else
      main_server->listen = NULL;

    isdefault = get_param_int(main_server->conf,"DefaultServer",FALSE);
    if(isdefault != 1)
      isdefault = 0;

    if(main_server->ServerPort || isdefault) {
      add_binding(main_server,main_server->ipaddr,main_server->listen,
                  isdefault,1);
      addl_bindings(main_server);
    }

    for(s = main_server->next; s; s=s->next) {
      if(s->ServerPort != main_server->ServerPort || SocketBindTight ||
         !main_server->listen) {

        isdefault = get_param_int(s->conf,"DefaultServer",FALSE);
        if(isdefault != 1)
          isdefault = 0;

        if(s->ServerPort) {
          s->listen = inet_create_connection(
                        s->pool,servers,-1,
                        (SocketBindTight ? s->ipaddr : NULL),
                        s->ServerPort, FALSE);
          add_binding(s,s->ipaddr,s->listen,isdefault,0);
          addl_bindings(s);
        } else if(isdefault) {
          s->listen = NULL;
          add_binding(s,s->ipaddr,s->listen,isdefault,0);
          addl_bindings(s);
        } else
          s->listen = NULL;
      } else {
        isdefault = get_param_int(s->conf,"DefaultServer",FALSE);
        if(isdefault != 1)
          isdefault = 0;

        s->listen = main_server->listen;
        register_cleanup(s->listen->pool,&s->listen,
                         _server_conn_cleanup,
                         _server_conn_cleanup);
        add_binding(s,s->ipaddr,NULL,isdefault,0);
        addl_bindings(s);
      }
    }
  } else
    /* Child process -- cannot rehash, log error */
    log_pri(LOG_ERR,"received SIGHUP, cannot rehash child process");
}

void fork_server(int fd,conn_t *l,int nofork)
{
  server_rec *s,*serv = NULL;
  conn_t *conn;
  pid_t pid;
  sigset_t sigset;
  pool *p;
  int i;

#ifndef DEBUG_NOFORK
  if(!nofork) {
    pidrec_t *cpid;

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

    switch((pid = fork())) {
    case 0: /* child */
      master = FALSE;		/* We aren't the master anymore */
      sigprocmask(SIG_UNBLOCK,&sigset,NULL);
      break;
    case -1:
      sigprocmask(SIG_UNBLOCK,&sigset,NULL);
      log_pri(LOG_ERR,"fork(): %s",strerror(errno));
      return;
    default: /* parent */
      /* The parent doesn't need the socket open */
      close(fd);

      if(!children) {
        p = make_sub_pool(permanent_pool);
        children = xaset_create(p,NULL);
      } else
        p = children->mempool;

      cpid = (pidrec_t*)pcalloc(p,sizeof(pidrec_t));
      cpid->pid = pid;
      xaset_insert(children,(xasetmember_t*)cpid);
      child_count++;

      /* Unblock the signals now as sig_child() will catch
       * an "immediate" death and remove the pid from the children list
       */
      sigprocmask(SIG_UNBLOCK,&sigset,NULL);
      return;
    }
  }
#ifdef HAVE_SETPGID
  setpgid(0,getpid());
#else
# ifdef SETPGRP_VOID
  setpgrp();
# else
   setpgrp(0,getpid());
# endif
#endif

#endif /* DEBUG_NOFORK */


  /* Child is running here */
  signal(SIGUSR1,sig_disconnect);
  signal(SIGUSR2,sig_debug);
  signal(SIGCHLD,SIG_DFL);
  signal(SIGHUP,SIG_IGN);

  /* From this point on, syslog stays open */
  /* We close it first so that the logger will pick up our
   * new pid.
   */

  block_signals();
  PRIVS_ROOT

  log_closesyslog();
  log_opensyslog(NULL);

  PRIVS_RELINQUISH
  unblock_signals();

  /* It's safe to call inet_openrw now (it might block),
   * because the parent is off answering new connections
   */

  conn = inet_openrw(permanent_pool,l,NULL,fd,
                     STDIN_FILENO,STDOUT_FILENO,TRUE);

  if(!conn) {
    log_pri(LOG_ERR,"Fatal: unable to open incoming connection: %s",
                   strerror(errno));
    exit(1);
  }

  inet_set_proto_options(permanent_pool,conn,1,1,0,0);

  serv = find_binding(conn->local_ipaddr,conn->local_port);

  /* If no server is configured to specifically handle the destination
   * address, search for the first server with DefaultServer set.
   */

#if 0
  if(!serv) {
    for(s = main_server; s; s=s->next)
      if(s->listen == l && 
         get_param_int(s->conf,"DefaultServer",FALSE) == 1) {
        serv = s;
        break;
      }
  }
#endif

  /* To conserve memory, free all other servers and associated
   * configurations
   */
  for(s = main_server; s; s=s->next)
    if(s != serv) {
      if(s->listen && s->listen != l) {
	/* If our former listen socket was stdin or stdout (0 or 1),
         * inet_close() will attempt to close it, and in the process
         * close our read/write sockets for this connection.
         */
        if(s->listen->listen_fd == conn->rfd ||
           s->listen->listen_fd == conn->wfd)
          s->listen->listen_fd = -1;
        else
          inet_close(s->pool,s->listen);
      }

      if(s->listen) {
        if(s->listen->listen_fd == conn->rfd ||
           s->listen->listen_fd == conn->wfd)
             s->listen->listen_fd = -1;
      }

      xaset_remove(servers,(xasetmember_t*)s);
      destroy_pool(s->pool);
    }

  main_server = serv;
    
  session.pool = permanent_pool;
  session.c = conn;
  session.data_port = conn->remote_port - 1;

  /* Check and see if we are shutdown */
  if(shutdownp) {
    time_t now;

    time(&now);
    if(!deny || deny <= now) {
      char *reason =
          sreplace(permanent_pool,shutmsg,
                   "%s",pstrdup(permanent_pool,fmt_time(shut)),
                   "%r",pstrdup(permanent_pool,fmt_time(deny)),
                   "%d",pstrdup(permanent_pool,fmt_time(disc)),
		   "%C",(session.cwd[0] ? session.cwd : "(none)"),
		   "%L",main_server->ServerAddress,
		   "%R",(session.c && session.c->remote_name ?
                         session.c->remote_name : "(unknown)"),
		   "%T",pstrdup(permanent_pool,fmt_time(now)),
		   "%U","NONE",
		   "%V",main_server->ServerName,
                   NULL );

      log_auth(LOG_NOTICE,"connection refused (%s) from %s [%s]",
               reason,session.c->remote_name,
               inet_ntoa(*session.c->remote_ipaddr));

      printf("500 FTP server shut down (%s) -- please try again later.\r\n",
             reason); 
      fflush(stdout);
      exit(0);
    }
  }

  /* If no server is configured to handle the addr the user is
   * connected to, drop them.
   */

  if(!serv) {
    printf("500 Sorry, no server available to handle request on %s.\r\n",
           inet_getname(conn->pool,conn->local_ipaddr));
    fflush(stdout);
    exit(0);
  }

  if(serv->listen) {
    if(serv->listen->listen_fd == conn->rfd ||
        serv->listen->listen_fd == conn->wfd)
          serv->listen->listen_fd = -1;

    destroy_pool(serv->listen->pool);
    serv->listen = NULL;
  }

  /* Check config tree for <Limit LOGIN> directives */
  if(!login_check_limits(serv->conf,TRUE,FALSE,&i)) {
    log_pri(LOG_NOTICE,"Connection from %s [%s] denied.",
            session.c->remote_name,inet_ntoa(*session.c->remote_ipaddr));
    exit(0);
  }

  log_debug(DEBUG4,"connected - local  : %s:%d",
                    inet_ntoa(*session.c->local_ipaddr),
                    session.c->local_port);
  log_debug(DEBUG4,"connected - remote : %s:%d",
  		    inet_ntoa(*session.c->remote_ipaddr),
  		    session.c->remote_port);

  /* Use the ident protocol (RFC1413) to try to get remote ident_user
   */

  if(get_param_int(main_server->conf,"IdentLookups",FALSE) != 0)
    session.ident_user = get_ident(session.pool,conn);
  else
    session.ident_user = "UNKNOWN";

  /* Inform all the modules that we are now a child */
  init_child_modules();

  /* xfer_set_data_port(conn->local_ipaddr,conn->local_port-1); */
  cmd_loop(serv,conn);
}

void disc_children()
{
  sigset_t sigset;
  pidrec_t *cp;

  if(disc && disc <= time(NULL) && children) {
    sigemptyset(&sigset);
    sigaddset(&sigset,SIGTERM);
    sigaddset(&sigset,SIGCHLD);
    sigaddset(&sigset,SIGUSR1);
    sigaddset(&sigset,SIGUSR2);

    sigprocmask(SIG_BLOCK,&sigset,NULL);

    PRIVS_ROOT
    for(cp = (pidrec_t*)children->xas_list; cp; cp=cp->next)
      kill(cp->pid,SIGUSR1);
    PRIVS_RELINQUISH

    sigprocmask(SIG_UNBLOCK,&sigset,NULL);
  }
}

void server_loop()
{
  fd_set rfd;
  conn_t *listen;
  int fd;
  int i,err_count = 0;
  time_t last_error;
  struct timeval tv;

  set_proc_title("proftpd (accepting connections)");

  time(&last_error);

  while(1) {
    run_schedule();

    listen_binding(&rfd);

    /* Check for ftp shutdown message file */
    switch(check_shutmsg(&shut,&deny,&disc,shutmsg,sizeof(shutmsg))) {
    case 1: if(!shutdownp) disc_children(); shutdownp = 1; break;
    case 0: shutdownp = 0; deny = disc = (time_t)0; break;
    }

    if(shutdownp) {
      tv.tv_usec = 0L;
      tv.tv_sec = 5L;
    } else {
      tv.tv_usec = 0L;
      tv.tv_sec = 30L;
    }

    i = select(NFDBITS,&rfd,NULL,NULL,&tv);

    if(child_flag) {
      sigset_t sigset;
      pidrec_t *cp,*cpnext;

      sigemptyset(&sigset);
      sigaddset(&sigset,SIGCHLD);
      sigaddset(&sigset,SIGTERM);
      block_alarms();
      sigprocmask(SIG_BLOCK,&sigset,NULL);

      child_flag = 0;
      if(children) {
        for(cp = (pidrec_t*)children->xas_list; cp; cp=cpnext) {
          cpnext = cp->next;
          if(cp->dead)
            xaset_remove(children,(xasetmember_t*)cp);
        }
      }
      /* Don't need the pool anymore */
      if(!children->xas_list) {
        destroy_pool(children->mempool);
        children = NULL;
      }

      sigprocmask(SIG_UNBLOCK,&sigset,NULL);
      unblock_alarms();
    }

    if(i == -1) {
      time_t this_error;

      if(errno == EINTR)
        continue;

      time(&this_error);
      if((this_error - last_error) <= 5 && err_count++ > 10) {
        log_pri(LOG_ERR,"Fatal: select() failing repeatedly, shutting down.");
        exit(1);
      } else if((this_error - last_error) > 5) {
        last_error = this_error;
        err_count = 0;
      }

      log_pri(LOG_NOTICE,"select() failed in server_loop(): %s",
              strerror(errno));
    }

    if(i == 0)
      continue;

    /* fork off servers to handle each connection
     * our job is to get back to answering connections asap,
     * so leave the work of determining which server the connection
     * is for to our child.
     */

    listen = accept_binding(&rfd, &fd);
    if(listen) {
      if(ServerMaxInstances && child_count >= ServerMaxInstances) {
        log_pri(LOG_WARNING,"MaxInstances (%d) reached, new connection denied.",ServerMaxInstances);
        close(fd);
      } else
        fork_server(fd,listen,FALSE);
    }
  }
}

/* sig_rehash occurs in the master daemon when manually "kill -HUP"
 * in order to re-read configuration files, and is sent to all
 * children by the master.
 */

static RETSIGTYPE sig_rehash(int sig)
{
  schedule(main_rehash,0,NULL,NULL,NULL,NULL);

  signal(SIGHUP,sig_rehash);
}

/* sig_debug outputs some basic debugging info
 */

static RETSIGTYPE sig_debug(int sig)
{
  debug_walk_pools();
}

/* sig_disconnect is called in children when the parent daemon
 * detects that shutmsg has been created and ftp sessions should
 * be destroyed.  If a file transfer is underway, the process simply
 * dies, otherwise a function is scheduled to attempt to display
 * the shutdown reason.
 */

static RETSIGTYPE sig_disconnect(int sig)
{
  if((session.flags & SF_ANON) || (session.flags & SF_XFER))
    schedule(main_exit,0,(void*)LOG_NOTICE,
             "Parent process requested shutdown",
             (void*)0,NULL);
  else
    schedule(shutdown_exit,0,NULL,NULL,NULL,NULL);

  signal(SIGUSR1,SIG_IGN);
}

static RETSIGTYPE sig_child(int sig)
{
  sigset_t sigset;
  pid_t cpid;
  pidrec_t *cp,*cpnext;

  sigemptyset(&sigset);
  sigaddset(&sigset,SIGTERM);

  block_alarms();
  sigprocmask(SIG_BLOCK,&sigset,NULL);

  /* block SIGTERM in here, so we don't create screw with the
   * child list while modifying it.
   */

  while((cpid = waitpid(-1,NULL,WNOHANG)) > 0) {
    child_count--; child_flag = 1;
    if(children) {
      for(cp = (pidrec_t*)children->xas_list; cp; cp=cpnext) {
        cpnext = cp->next;
        if(cp->pid == cpid) {
          child_flag++;
          cp->dead = 1;
        }
      }
    }
  }

  sigprocmask(SIG_UNBLOCK,&sigset,NULL);
  unblock_alarms();
  signal(SIGCHLD,sig_child);
}

static RETSIGTYPE sig_abort(int sig)
{
#if 0
  if(abort_core)
    log_pri(LOG_NOTICE,"ProFTPD received SIGABRT signal, generating core file in %s",_prepare_core());
  else
#endif
    log_pri(LOG_NOTICE,"ProFTPD received SIGABRT signal, no core dump.");
  
  signal(SIGABRT,SIG_DFL);
  end_login_noexit();
  abort();
}  

static void _internal_abort()
{
  if(abort_core) {
#if 0
    log_pri(LOG_NOTICE,"core file dumped to %s",_prepare_core());
#endif
    signal(SIGABRT,SIG_DFL);
    end_login_noexit();
    abort();
  }
}

static RETSIGTYPE sig_terminate(int sig)
{
  pidrec_t *pid;

  if(sig == SIGTERM) {
    /* Don't log if we are a child that has been terminated */
    if(master) {
      /* Send a SIGKILL to all our children */
      if(children) {
        PRIVS_ROOT
        for(pid = (pidrec_t*)children->xas_list; pid; pid=pid->next)
          kill(pid->pid,SIGTERM);
        PRIVS_RELINQUISH
      }

      log_pri(LOG_NOTICE,"ProFTPD killed (signal %d)",sig);
    }
  } else
    log_pri(LOG_ERR,"ProFTPD terminating (signal %d)",sig);

  if(master && mpid == getpid()) {
    PRIVS_ROOT
    log_close_run();
    log_rm_run();
    PRIVS_RELINQUISH
    if(standalone)
      log_pri(LOG_NOTICE,"ProFTPD %s standalone mode SHUTDOWN",VERSION);
  }

  _internal_abort();  
  end_login(1);
}

static void install_signal_handlers()
{
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
  sigaddset(&sigset,SIGIO);
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
#ifdef SIGSTKFLT
  signal(SIGSTKFLT,sig_terminate);
#endif /* SIGSTKFLT */
  signal(SIGIO,sig_terminate);
#ifdef SIGBUS
  signal(SIGBUS,sig_terminate);
#endif /* SIGBUS */
#endif /* DEBUG_NOSIG */

  signal(SIGIO,SIG_IGN);
  signal(SIGURG,SIG_IGN);

  /* In case our parent left signals blocked (as happens under some
   * poor inetd implementations)
   */
  sigprocmask(SIG_UNBLOCK,&sigset,NULL);
}

static void set_rlimits()
{
  struct rlimit rlim;

  if(getrlimit(RLIMIT_CORE,&rlim) == -1)
    log_pri(LOG_ERR,"getrlimit(): %s",strerror(errno));
  else {
    if(abort_core)
      rlim.rlim_cur = rlim.rlim_max = RLIM_INFINITY;
    else
      rlim.rlim_cur = rlim.rlim_max = 0;

    PRIVS_ROOT
    if(setrlimit(RLIMIT_CORE,&rlim) == -1) {
      PRIVS_RELINQUISH
      log_pri(LOG_ERR,"setrlimit(): %s",strerror(errno));
      return;
    }
    PRIVS_RELINQUISH
  }
}

void start_daemon()
{
#ifndef HAVE_SETSID
  int ttyfd;
#endif

  /* Fork off and have parent exit */
  switch(fork()) {
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
  if( (ttyfd = open("/dev/tty",O_RDWR)) != -1)
  {
    if(ioctl(ttyfd,TIOCNOTTY,NULL) == -1) {
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

  fs_chdir("/",0);
}

void addl_bindings(server_rec *s)
{
  config_rec *c;
  conn_t *listen;
  p_in_addr_t *ipaddr;

  c = find_config(s->conf,CONF_PARAM,"Bind",FALSE);
  while(c) {
    listen = NULL;

    /* If SocketBindTight is set, we create an additional listen
     * connection for each binding.
     */

    ipaddr = inet_getaddr(s->pool,c->argv[0]);
    if(!ipaddr) {
      log_pri(LOG_NOTICE,"unable to determine IP address of `%s'.",
              c->argv[0]);

      continue;
    }

    if(SocketBindTight && s->ServerPort) {
      listen = inet_create_connection(s->pool,servers,-1,
               ipaddr,s->ServerPort,FALSE);
      add_binding(s,ipaddr,listen,0,0);
    } else
      add_binding(s,ipaddr,s->listen,0,0);

    c = find_config_next(c,c->next,CONF_PARAM,"Bind",FALSE);
  }
}

void inetd_main()
{
  server_rec *s;
  int isdefault;

  PRIVS_ROOT
  log_open_run(0,FALSE,TRUE);
  log_close_run();
  PRIVS_RELINQUISH

  main_server->listen = 
    inet_create_connection(main_server->pool,servers,STDIN_FILENO,
                           NULL,INPORT_ANY,FALSE);

  /* Fill in all the important connection info */
  if(inet_get_conn_info(main_server->listen,STDIN_FILENO) == -1) {
    log_pri(LOG_ERR,"Fatal: %s",strerror(errno));
    if(errno == ENOTSOCK)
      log_pri(LOG_ERR,"(Running from command line? "
                      "Use `ServerType standalone' in config file!)");
    exit(1);
  }

  isdefault = get_param_int(main_server->conf,"DefaultServer",FALSE);
  if(isdefault != 1)
    isdefault = 0;

  add_binding(main_server,main_server->ipaddr,main_server->listen,
                isdefault,1);
  addl_bindings(main_server);

  /* Now attach the faked connection to all virtual servers */
  for(s = main_server->next; s; s=s->next) {
      /* Because this server is sharing the connection with the
       * main server, we need a cleanup handler to remove
       * the server's reference when the original connection's
       * pool is destroyed.
       */
      s->listen = main_server->listen;
      register_cleanup(s->listen->pool,&s->listen,
                       _server_conn_cleanup,
                       _server_conn_cleanup);
      

      isdefault = get_param_int(s->conf,"DefaultServer",FALSE);
      if(isdefault != 1)
        isdefault = 0;

      add_binding(s,s->ipaddr,s->listen,isdefault,0);
      addl_bindings(s);
  }

  /* Check our shutdown status */
  if(check_shutmsg(&shut,&deny,&disc,shutmsg,sizeof(shutmsg)) == 1)
    shutdownp = 1;

  /* Finally, call right into fork_server() to start servicing the
   * connection immediately
   */
  fork_server(STDIN_FILENO,main_server->listen,TRUE);
}

void standalone_main(int nodaemon)
{
  server_rec *s;
  int isdefault;

  standalone = 1;
  if(nodaemon) {
    log_stderr(TRUE);
    close(fileno(stdin));
    close(fileno(stdout));
  }
  else {
    log_stderr(FALSE);
    start_daemon();
  }

  mpid = getpid();

  PRIVS_ROOT
  log_open_run(mpid,TRUE,TRUE);
  log_close_run();
  PRIVS_RELINQUISH

  /* If a port is set to 0, the address/port is not bound at all */

  if(main_server->ServerPort)
    main_server->listen =
      inet_create_connection(main_server->pool,servers,-1,
                             (SocketBindTight ? main_server->ipaddr :  NULL),
                             main_server->ServerPort,FALSE);
  else
    main_server->listen = NULL;

  isdefault = get_param_int(main_server->conf,"DefaultServer",FALSE);
  if(isdefault != 1)
    isdefault = 0;

  if(main_server->ServerPort || isdefault) {
    add_binding(main_server,main_server->ipaddr,main_server->listen,
                isdefault,1);

    addl_bindings(main_server);
  }

  for(s = main_server->next; s; s=s->next)
    if(s->ServerPort != main_server->ServerPort || SocketBindTight ||
       !main_server->listen) {

      isdefault = get_param_int(s->conf,"DefaultServer",FALSE);
      if(isdefault != 1)
        isdefault = 0;

      if(s->ServerPort) {

        s->listen = inet_create_connection(
                      s->pool,servers,-1,
	  	      (SocketBindTight ? s->ipaddr : NULL),
                      s->ServerPort,FALSE);        
        add_binding(s,s->ipaddr,s->listen,isdefault,0);
        addl_bindings(s);
      } else if(isdefault) {
        s->listen = NULL;
        add_binding(s,s->ipaddr,s->listen,isdefault,0);
        addl_bindings(s);
      } else
        s->listen = NULL;
    } else {
      /* Because this server is sharing the connection with the
       * main server, we need a cleanup handler to remove
       * the server's reference when the original connection's
       * pool is destroyed.
       */
      isdefault = get_param_int(s->conf,"DefaultServer",FALSE);
      if(isdefault != 1)
        isdefault = 0;
       
      s->listen = main_server->listen;
      register_cleanup(s->listen->pool,&s->listen,
                       _server_conn_cleanup,
                       _server_conn_cleanup);
      add_binding(s,s->ipaddr,NULL,isdefault,0);
      addl_bindings(s);
    }

  log_pri(LOG_NOTICE,"ProFTPD %s standalone mode STARTUP",VERSION);
  server_loop();
}

extern char *optarg;
extern int optind,opterr,optopt;

struct option opts[] = {
  { "nodaemon",	0, NULL, 'n' },
  { "debug",	1, NULL, 'd' },
  { "config",	1, NULL, 'c' },
  { "persistent",1,NULL, 'p' },
  { "list",     0, NULL, 'l' },
  { "version",  0, NULL, 'v' },
/*
  { "core",     0, NULL, 'o' },
*/
  { "help",	0, NULL, 'h' },
  { NULL,	0, NULL,  0  }
};

struct option_help {
  char *long_opt,*short_opt,*desc;
} opts_help[] = {
  { "--help","-h","display proftpd usage"},
  { "--nodaemon","-n","disable background daemon mode (all output goes to tty, instead of syslog)" },
  { "--debug","-d [level]","set debugging level (0-5, 5 == most debugging)" },
  { "--config","-c [config-file]","specify alternate configuration file" },
  { "--persistent","-p [0|1]","enable/disable default persistent passwd support" },
  { "--list","-l","list all compiled-in modules" },
/*
  { "--core","-o","enable core dump for profiling/debugging on serious errors"},
*/
  { "--version","-v","print version number and exit" },
  { NULL,NULL,NULL }
};


void show_usage(int exit_code)
{
  struct option_help *h;

  printf("usage: proftpd [options]\n");
  for(h = opts_help; h->long_opt; h++) {
    printf("  %s,%s\n",h->long_opt,h->short_opt);
    printf("    %s\n",h->desc);
  }
  exit(exit_code);
}

int main(int argc, char **argv, char **envp)
{
  int daemon_uid,daemon_gid,socketp;
  int _umask = 0,nodaemon = 0,c;
  struct sockaddr peer;
  
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
  if((logfd = open("/tmp/proftpd.log", O_WRONLY | O_CREAT | O_APPEND,0644))< 0) {
	log_pri(LOG_ERR, "Error opening error logfile: %s", strerror(errno));
	exit(1);
  }

  close(fileno(stderr));
  if(dup2(logfd, fileno(stderr)) == -1) {
	log_pri(LOG_ERR, "Error converting standard error to a logfile: %s",
					strerror(errno));
	exit(1);
  }
  close(logfd);
#endif /* DEBUG_MEMORY */

#ifdef HAVE_SET_AUTH_PARAMETERS
  (void) set_auth_parameters(argc, argv);
#endif

  bzero(&session,sizeof(session));

  /* Initialize stuff for set_proc_title.
   */
  init_set_proc_title(argc, argv, envp);

  /* getpeername() fails if the fd isn't a socket */
  socketp = sizeof(peer);
  if(getpeername(fileno(stdin),&peer,&socketp) != -1) {
    log_stderr(FALSE);
    socketp = TRUE;
  } else
    socketp = FALSE;

  /* Open the syslog */
  log_opensyslog(NULL);

  /* Command line options supported:
   * -n,--nodaemon	standalone server doesn't background itself,
   *                    all logging dumped to stderr
   *
   * -d n,--debug n	set debug level
   *
   * -c, --config path  set the configuration path
   *
   * -v, --version      report version number
   */

  opterr = 0;
  while((c = getopt_long(argc,argv,"nd:c:p:lhv",opts,NULL)) != -1) {
    switch(c) {
    case 'n': 
      nodaemon++; break;
    case 'd': 
      if(!optarg) {
        log_pri(LOG_ERR,"Fatal: -d requires debugging level argument.");
        exit(1);
      }
      log_setdebuglevel(atoi(optarg));
      break;
    case 'c':
      if(!optarg) {
        log_pri(LOG_ERR,"Fatal: -c requires configuration path argument.");
        exit(1);
      }
      config_filename = strdup(optarg);
      break;
    case 'l':
      list_modules();
      exit(0);
    case 'p':
    {
      extern int persistent;

      if(!optarg || ((persistent = atoi(optarg)) != 1 && persistent != 0)) {
        log_pri(LOG_ERR,"Fatal: -p requires boolean (0|1) argument.");
        exit(1);
      }

      break;
    }
    /*
    case 'o':
      abort_core++;
      break;
    */
    case 'v':
      log_pri(LOG_NOTICE,"ProFTPD Version " VERSION);
      exit(0);
    case 'h':
      show_usage(0);
    case '?':
      log_pri(LOG_ERR,"Unknown option: %c",(char)optopt);
      show_usage(1);
    }
  }
 
  /* Initialize sub-systems */
  init_alloc();
  init_log();
  init_inet();
  init_io();
  init_fs();
  init_config();
  init_modules();

  init_conf_stacks();
  if(parse_config_file(config_filename) == -1) {
    log_pri(LOG_ERR,"Fatal: unable to read configuration file '%s'.",
            config_filename);
    exit(1);
  }

  free_conf_stacks();

  fixup_servers();

  /* After configuration is complete, make sure that passwd, group
   * aren't held open (unnecessary fds for master daemon)
   */

  endpwent();
  endgrent();

  /* Security */
  daemon_uid = get_param_int(main_server->conf,"User",FALSE);
  if(daemon_uid == -1)
    daemon_uid = 0;
  daemon_gid = get_param_int(main_server->conf,"Group",FALSE);
  if(daemon_gid == -1)
    daemon_gid = 0;

  if(daemon_uid)
    initgroups((const char*)get_param_ptr(main_server->conf,"UserName",
                  FALSE),daemon_gid);
  
   if((_umask = get_param_int(main_server->conf,"Umask",FALSE)) == -1)
    _umask = 0022;

  umask(_umask);

  /* Give up root and save our uid/gid for later use (if supported)
   * If we aren't currently root, PRIVS_SETUP will get rid of setuid
   * granted root and prevent further uid switching from being attempted.
   */

  PRIVS_SETUP(daemon_uid,daemon_gid)

  /* Install a signal handlers/abort handler */
  install_signal_handlers();
  set_rlimits();

  switch(ServerType) {
  case SERVER_STANDALONE: standalone_main(nodaemon);
  case SERVER_INETD:      inetd_main();
  }

  return 0;
}

#ifdef DEBUG_MEMORY
#undef strncpy
char *my_strncpy(to, from, num, file, function, line, args)
{
  fprintf(stderr, "%s:%d:%s - strncpy(%s)\n", file, line, function, args);
  fflush(stderr);
  fsync(fileno(stderr));

  return strncpy(to, from, num);
}
#endif /* DEBUG_MEMORY */
