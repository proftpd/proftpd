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
 * Flexible logging module for proftpd
 * $Id: mod_log.c,v 1.6 1999-09-17 04:14:15 macgyver Exp $
 */

#include "conf.h"

#include "privs.h"

extern response_t *resp_list,*resp_err_list;

#define LOGBUF_SIZE		1025

typedef struct logformat_struc	logformat_t;
typedef struct logfile_struc 	logfile_t;

struct logformat_struc {
  logformat_t		*next,*prev;

  char			*lf_nickname;
  unsigned char		*lf_format;
};

struct logfile_struc {
  logfile_t		*next,*prev;

  int			lf_fd;
  int			lf_classes;
  char			*lf_filename;
  logformat_t		*lf_format;
  config_rec		*lf_conf;	/* pointer to the "owning" configuration */
};
  
#define META_START		0xff
#define META_ARG_END		0xfe
#define META_ARG		1
#define META_BYTES_SENT		2
#define META_FILENAME		3
#define META_ENV_VAR		4
#define META_REMOTE_HOST	5
#define META_REMOTE_IP		6
#define META_IDENT_USER		7
#define META_SERVER_PORT	8
#define META_PID		9
#define META_TIME		10
#define META_SECONDS		11
#define META_COMMAND		12
#define META_SERVERNAME		13
#define META_USER		14
#define META_RESPONSE_CODE	15

static pool			*log_pool;
static logformat_t		*formats = NULL;
static xaset_t			*format_set = NULL;
static logfile_t		*logs = NULL;
static xaset_t			*log_set = NULL;

/* format string args:
   %b			- bytes sent for request
   %f			- filename
   %{FOOBAR}e		- contents of environment variable FOOBAR
   %h			- remote host
   %a			- remote IP-address
   %l			- remote logname (from identd)
   %p			- Port of server serving request
   %P			- Process ID of child serving request
   %r			- Full request (command)
   %t			- Time
   %{format}t		- formatted time (strftime(3) format)
   %T			- Time taken to serve request, in seconds
   %s			- Reponse code (status)
   %u			- Local user
   %v			- Servername of server serving request
*/

static
void add_meta(unsigned char **s, unsigned char meta, int args, ...)
{
  int arglen;
  char *arg;

  **s = META_START;
  (*s) = (*s) + 1;
  **s = meta;
  (*s) = (*s) + 1;

  if(args) {
    va_list ap;
    va_start(ap,args);

    while(args--) {
      arglen = va_arg(ap,int);
      arg = va_arg(ap,char*);

      bcopy(arg,*s,arglen);
      (*s) = (*s) + arglen;
      **s = META_ARG_END;
      (*s) = (*s) + 1;
    }

    va_end(ap);
  }
}

static
char *preparse_arg(char **s)
{
  char *ret = (*s) + 1;

  (*s) = (*s) + 1;
  while(**s && **s != '}')
    (*s) = (*s) + 1;

  **s = 0;
  (*s) = (*s) + 1;
  return ret;
}

static
void logformat(char *nickname, char *fmts)
{
  char *tmp,*arg;
  unsigned char format[1024],*outs;
  logformat_t *lf;

  outs = format;
  for(tmp = fmts; *tmp; ) {
    if(*tmp == '%') {
      arg = NULL;
      tmp++;
      for(;;) {
        switch(*tmp) {
        case '{':
          arg = preparse_arg(&tmp);
          continue;
        case 'b':
          add_meta(&outs,META_BYTES_SENT,0);
          break;
        case 'f':
          add_meta(&outs,META_FILENAME,0);
          break;
        case 'e':
          if(arg) {
            add_meta(&outs,META_ENV_VAR,0);
            add_meta(&outs,META_ARG,1,(int)strlen(arg),arg);
          }
          break;
        case 'h':
          add_meta(&outs,META_REMOTE_HOST,0);
          break;
        case 'a':
          add_meta(&outs,META_REMOTE_IP,0);
          break;
        case 'l':
          add_meta(&outs,META_IDENT_USER,0);
          break;
        case 'p': 
          add_meta(&outs,META_SERVER_PORT,0);
          break;
        case 'P':
          add_meta(&outs,META_PID,0);
          break;
        case 't':
          add_meta(&outs,META_TIME,0);
          if(arg)
            add_meta(&outs,META_ARG,1,(int)strlen(arg),arg);
          break;
        case 'T':
          add_meta(&outs,META_SECONDS,0);
          break;
        case 'u':
          add_meta(&outs,META_USER,0);
          break;
        case 'r':
          add_meta(&outs,META_COMMAND,0);
          break;
        case 'v':
          add_meta(&outs,META_SERVERNAME,0);
          break;
        case 's':
          add_meta(&outs,META_RESPONSE_CODE,0);
          break;
        case '%':
          *outs++ = '%';
          break;
        }
	tmp++;
	break;
      }
    } else
      *outs++ = *tmp++;
  }

  *outs++ = 0;

  lf = (logformat_t*)pcalloc(log_pool,sizeof(logformat_t));
  lf->lf_nickname = pstrdup(log_pool,nickname);
  lf->lf_format = palloc(log_pool,outs - format);
  bcopy(format,lf->lf_format,outs-format);

  if(!format_set)
    format_set = xaset_create(log_pool,NULL);

  xaset_insert_end(format_set,(xasetmember_t*)lf);
  formats = (logformat_t*)format_set->xas_list;
}

/* Syntax: LogFormat nickname "format string"
 */

MODRET add_logformat(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,2);
  CHECK_CONF(cmd,CONF_ROOT);

  logformat(cmd->argv[1],cmd->argv[2]);
  return HANDLED(cmd);
}

static int _parse_classes(char *s)
{
  int classes = 0;
  char *nextp = NULL;

  do {

    if((nextp = strchr(s,',')))
      *nextp++ = '\0';

    if(!nextp) {
      if((nextp = strchr(s,'|')))
        *nextp++ = '\0';
    }

    if(!strcasecmp(s,"NONE"))
      { classes = CL_NONE; break; }
    if(!strcasecmp(s,"ALL"))
      { classes = CL_ALL; break; }
    else if(!strcasecmp(s,"AUTH"))
      classes |= CL_AUTH;
    else if(!strcasecmp(s,"INFO"))
      classes |= CL_INFO;
    else if(!strcasecmp(s,"DIRS"))
      classes |= CL_DIRS;
    else if(!strcasecmp(s,"READ"))
      classes |= CL_READ;
    else if(!strcasecmp(s,"WRITE"))
      classes |= CL_WRITE;
    else if(!strcasecmp(s,"MISC"))
      classes |= CL_MISC;
  } while((s = nextp));

  return classes;
}

/* Syntax: ExtendedLog <log-filename> [<cmd-classes> [<format-nickname>]]
 */

MODRET add_extendedlog(cmd_rec *cmd)
{
  config_rec *c;
  int argc;
  char **argv;

  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);

  argc = cmd->argc;
  argv = cmd->argv;

  if(argc < 2)
    CONF_ERROR(cmd,"Syntax: ExtendedLog <log-filename> [<command-classes> [<format-nickname>]]");

  c = add_config_param("ExtendedLog",3,NULL,NULL,NULL);

  if(cmd->argv[1][0] != '/')
    c->argv[0] = dir_canonical_path(log_pool,cmd->argv[1]);
  else
    c->argv[0] = pstrdup(log_pool,cmd->argv[1]);

  if(argc > 2)
    c->argv[1] = pstrdup(log_pool,cmd->argv[2]);
  if(argc > 3)
    c->argv[2] = pstrdup(log_pool,cmd->argv[3]);

  c->argc = argc-1;
  return HANDLED(cmd);
}

/* Syntax: SystemLog <filename> */

MODRET set_systemlog(cmd_rec *cmd)
{
  char *syslogfn;
  int ret;
  
  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT);

  log_closesyslog();

  syslogfn = cmd->argv[1];

  if(strcasecmp(syslogfn,"NONE") == 0) {
    log_discard();
    return HANDLED(cmd);
  }

  if(*syslogfn != '/') 
    syslogfn = dir_canonical_path(cmd->tmp_pool,syslogfn);

  block_signals();
  PRIVS_ROOT

    if((ret = log_opensyslog(syslogfn)) < 0) {
      int xerrno = errno;
      
      PRIVS_RELINQUISH
      unblock_signals();
      
      if(ret == -2) {
	CONF_ERROR(cmd, "you are attempting to log to a world writeable directory");
      } else {
	CONF_ERROR(cmd,pstrcat(cmd->tmp_pool,"unable to redirect logging to '",
			       syslogfn,"': ",strerror(xerrno),NULL));
      }
    }
  
  PRIVS_RELINQUISH
  unblock_signals();

  return HANDLED(cmd);
}

#ifdef HAVE_GMTOFF
static
struct tm *_get_gmtoff(int *tz)
{
  time_t tt = time(NULL);
  struct tm *t;

  t = localtime(&tt);
  *tz = (int)(t->tm_gmtoff / 60)
  return t;
}
#else
static
struct tm *_get_gmtoff(int *tz)
{
  time_t tt = time(NULL);
  struct tm gmt;
  struct tm *t;
  int days,hours,minutes;

  gmt = *gmtime(&tt);
  t = localtime(&tt);

  days = t->tm_yday - gmt.tm_yday;
  hours = ((days < -1 ? 24 : 1 < days ? -24 : days * 24)
          + t->tm_hour - gmt.tm_hour);
  minutes = hours * 60 + t->tm_min - gmt.tm_min;
  *tz = minutes;
  return t;
}
#endif /* HAVE_GMTOFF */

static
char *get_next_meta(pool *p, cmd_rec *cmd, unsigned char **f)
{
  unsigned char *m;
  char arg[256],*argp = NULL;

  m = (*f) + 1;
  switch(*m) {
  case META_ARG:
    m++; argp = arg;
    while(*m != META_ARG_END)
      *argp++ = (char)*m++;

    *argp = 0; argp = arg;
    m++;
    break;

  case META_BYTES_SENT:
    argp = arg;
    if(session.xfer.p)
      snprintf(argp, sizeof(arg), "%lu",session.xfer.total_bytes);
    else
      strncpy(argp,"-",sizeof(arg));
    m++; break;

  case META_FILENAME:
    argp = arg;
    if(session.xfer.p && session.xfer.path) {
      char *fullpath;
      fullpath = dir_abs_path(p,session.xfer.path,TRUE);
      strncpy(argp,fullpath,sizeof(arg));
      arg[sizeof(arg)-1] = '\0';
    } else
      strncpy(argp,"-",sizeof(arg));
    m++; break;

  case META_ENV_VAR:
    argp = arg; m++;
    if(*m == META_START && *(m+1) == META_ARG) {
      char *env;

      env = getenv(get_next_meta(p,cmd,&m));
      strncpy(argp,env,sizeof(arg));
      arg[sizeof(arg)-1] = '\0';
    }
    break;

  case META_REMOTE_HOST:
    argp = arg;
    strncpy(argp,session.c->remote_name,sizeof(arg));
    arg[sizeof(arg)-1] = '\0';
    m++; break;

  case META_REMOTE_IP:
    argp = arg;
    strncpy(argp,inet_ntoa(*session.c->remote_ipaddr),sizeof(arg));
    arg[sizeof(arg)-1] = '\0';
    m++; break;

  case META_IDENT_USER:
    argp = arg;
    strncpy(argp,session.ident_user,sizeof(arg));
    arg[sizeof(arg)-1] = '\0';
    m++; break;

  case META_SERVER_PORT:
    argp = arg;
    snprintf(argp, sizeof(arg), "%d",cmd->server->ServerPort);
    m++; break;

  case META_PID:
    argp = arg;
    snprintf(argp, sizeof(arg), "%u",(unsigned int)getpid());
    m++; break;

  case META_TIME:
    {
      char *time_fmt = "[%d/%b/%Y:%H:%M:%S ";
      struct tm t;
      int internal_fmt = 1;
      int timz;
      char sign;

      argp = arg; m++;

      if(*m == META_START && *(m+1) == META_ARG) {
        time_fmt = get_next_meta(p,cmd,&m);
        internal_fmt = 0;
      }
      t = *_get_gmtoff(&timz);
      sign = (timz < 0 ? '-' : '+');
      if(timz < 0)
        timz = -timz;

      strftime(argp,80,time_fmt,&t);
      if(internal_fmt)
        snprintf(argp + strlen(argp), sizeof(arg) - strlen(argp),
                "%c%.2d%.2d]", sign, timz/60, timz%60);

    }
    break;

  case META_SECONDS:
    argp = arg;
    if(session.xfer.p) {
      struct timeval end_time;

      gettimeofday(&end_time,NULL);
      end_time.tv_sec -= session.xfer.start_time.tv_sec;
      if(end_time.tv_usec >= session.xfer.start_time.tv_usec)
        end_time.tv_usec -= session.xfer.start_time.tv_usec;
      else {
        end_time.tv_usec = 1000000L - (session.xfer.start_time.tv_usec -
                           end_time.tv_usec);
        end_time.tv_sec--;
      }

      snprintf(argp, sizeof(arg), "%lu",(unsigned long)end_time.tv_sec);
    } else
      strncpy(argp,"-",sizeof(arg));

    m++; break;

  case META_COMMAND:
    argp = arg;

    if(!strcasecmp(cmd->argv[0],"PASS") && session.hide_password)
      strncpy(argp,"PASS (hidden)",sizeof(arg));
    else
      strncpy(argp,get_full_cmd(cmd),sizeof(arg));
    arg[sizeof(arg)-1] = '\0';
    m++; break;

  case META_SERVERNAME:
    argp = arg;

    strncpy(argp,cmd->server->ServerName,sizeof(arg));
    arg[sizeof(arg)-1] = '\0';
    m++; break;

  case META_USER:
    argp = arg;

    if(!session.user) {
      char *u;

      u = get_param_ptr(cmd->server->conf,"UserName",FALSE);
      if(!u)
        u = "root";
    
      strncpy(argp,u,sizeof(arg));
    } else
      strncpy(argp,session.user,sizeof(arg));

    arg[sizeof(arg)-1] = '\0';
    m++; break;

  case META_RESPONSE_CODE:
    {
      response_t *r;

      argp = arg;
      r = (resp_list ? resp_list : resp_err_list);

      for(; r && !r->num; r=r->next) ;
      if(r && r->num)
        strncpy(argp,r->num,sizeof(arg));
      else
        strncpy(argp,"-",sizeof(arg));
    }
    m++; break;
  }

  *f = m;
  if(argp)
    return pstrdup(p,argp);
  else
    return NULL;
}

static
void do_log(cmd_rec *cmd, logfile_t *lf)
{
  unsigned char *f;
  size_t size = LOGBUF_SIZE-2;
  char logbuf[LOGBUF_SIZE];
  logformat_t *fmt;
  char *s,*bp;

  fmt = lf->lf_format;
  f = fmt->lf_format;
  bp = logbuf;

  while(*f && size) {
    if(*f == META_START) {
      s = get_next_meta(cmd->tmp_pool,cmd,&f);
      if(s) {
        size_t tmp;

        tmp = strlen(s);
        if(tmp > size)
          tmp = size;

        bcopy(s,bp,tmp);
        size -= tmp;
        bp += tmp;
      }
    } else {
      *bp++ = (char)*f++;
      size--;
    }
  }

  *bp++ = '\n';
  *bp = '\0';

  write(lf->lf_fd,logbuf,strlen(logbuf));
}

MODRET log_command(cmd_rec *cmd)
{
  logfile_t *lf;
  /* If not in anon mode, only handle logs for main servers */

  for(lf = logs; lf; lf=lf->next)
    if(lf->lf_fd != -1 && (cmd->class & lf->lf_classes)) {
      if(!session.anon_config && lf->lf_conf && lf->lf_conf->config_type == CONF_ANON)
        continue;
      do_log(cmd,lf);
    }

  return DECLINED(cmd);
}

/* log_rehash is called whenever the master server rehashes it's
 * config (in response to SIGHUP).
 */

static
void log_rehash(void *d)
{
  destroy_pool(log_pool);

  formats = NULL;
  format_set = NULL;
  logs = NULL;
  log_set = NULL;

  log_pool = make_sub_pool(permanent_pool);
  logformat("","%h %l %u %t \"%r\" %s %b");
}
  
static 
int log_init()
{
  log_pool = make_sub_pool(permanent_pool);
  /* add the "default" extendedlog format */
  logformat("","%h %l %u %t \"%r\" %s %b");
  register_rehash(NULL,log_rehash);
  return 0;
}

static
void get_extendedlogs()
{
  config_rec *c;
  char *logfname;
  int logclasses = CL_ALL;
  logformat_t *logfmt;
  char *logfmt_s = NULL;
  logfile_t *logf;

  c = find_config(main_server->conf,CONF_PARAM,"ExtendedLog",TRUE);

  while(c) {
    logfname = c->argv[0];

    if(c->argc > 1) {
      logclasses = _parse_classes(c->argv[1]);
      if(c->argc > 2)
        logfmt_s = c->argv[2];
    }

    if(logfmt_s) {
      /* search for the format-nickname */
      for(logfmt = formats; logfmt; logfmt=logfmt->next)
        if(!strcmp(logfmt->lf_nickname,logfmt_s))
          break;

      if(!logfmt) {
        log_pri(LOG_NOTICE,"format-nickname '%s' is not defined.",
                           logfmt_s);
        goto loop_extendedlogs;
      }
    } else
      logfmt = formats;

    logf = (logfile_t*)pcalloc(permanent_pool,sizeof(logfile_t));
    logf->lf_fd = -1;
    logf->lf_classes = logclasses;
    logf->lf_filename = pstrdup(permanent_pool,logfname);
    logf->lf_format = logfmt;
    logf->lf_conf = c->parent;
    if(!log_set)
      log_set = xaset_create(permanent_pool,NULL);

    xaset_insert(log_set,(xasetmember_t*)logf);
    logs = (logfile_t*)log_set->xas_list;

loop_extendedlogs:
    c = find_config_next(c,c->next,CONF_PARAM,"ExtendedLog",TRUE);
  }
}

MODRET log_auth_complete(cmd_rec *cmd)
{
  logfile_t *lf;

  /* authentication is complete, if we aren't in anon-mode, close
   * all extendedlogs opened inside <Anonymous> blocks.
   */
  if(!session.anon_config) {
    for(lf = logs; lf; lf=lf->next)
      if(lf->lf_fd != -1 && lf->lf_conf && lf->lf_conf->config_type == CONF_ANON) {
        close(lf->lf_fd);
        lf->lf_fd = -1;
      }
  } else {
    /* close all logs which were opened inside a _different_ anonymous
     * context.
     */
    for(lf = logs; lf; lf=lf->next)
      if(lf->lf_fd != -1 && lf->lf_conf && lf->lf_conf != session.anon_config) {
        close(lf->lf_fd);
        lf->lf_fd = -1;
      }

    /* if any extendedlogs set inside our context match an outer log,
     * close the outer (this allows overriding inside <Anonymous>).
     */
    for(lf = logs; lf; lf=lf->next)
      if(lf->lf_conf && lf->lf_conf == session.anon_config) {
        /* this should "override" any lower-level extendedlog with the
         * same filename.
         */
        logfile_t *lf2;

        for(lf2 = logs; lf2; lf2=lf2->next) {
          if(lf2->lf_fd != -1 && !lf2->lf_conf &&
             !strcmp(lf2->lf_filename,lf->lf_filename)) {
            close(lf2->lf_fd);
            lf2->lf_fd = -1;
          }
        }
       
        /* go ahead and close the log if it's CL_NONE */

        if(lf->lf_fd != -1 && lf->lf_classes == CL_NONE) {
          close(lf->lf_fd);
          lf->lf_fd = -1;
        }
      }
  }
  return DECLINED(cmd);
}

static
int log_child_init()
{
  /* open all log files */
  logfile_t *lf;
  int xerrno;

  get_extendedlogs();

  for(lf = logs; lf; lf=lf->next)
    if(lf->lf_fd == -1) {
      block_signals();
      PRIVS_ROOT

      lf->lf_fd = 
         open(lf->lf_filename,O_CREAT|O_APPEND|O_WRONLY,0644);
      xerrno = errno;

      PRIVS_RELINQUISH
      unblock_signals();

      if(lf->lf_fd == -1)
        log_pri(LOG_NOTICE,"unable to open ExtendedLog '%s': %s",
                lf->lf_filename,strerror(errno));
    }

  return 0;
}


static conftable log_config[] = {
  { "LogFormat",	add_logformat,				NULL },
  { "ExtendedLog",	add_extendedlog,			NULL },
  { "SystemLog",	set_systemlog,				NULL },
  { NULL,		NULL,					NULL }
};

cmdtable log_commands[] = {
  { LOG_CMD,	"*",	G_NONE,		log_command,	FALSE, FALSE },
  { LOG_CMD_ERR,"*",	G_NONE,		log_command,	FALSE, FALSE },
  { POST_CMD,	"PASS",	G_NONE,		log_auth_complete,FALSE,FALSE },
  { 0, NULL }
};

module log_module = {
  NULL,NULL,			/* Always NULL */
  0x20,				/* API version */
  "log",			/* Module name */
  log_config,
  log_commands,
  NULL,
  log_init,log_child_init
};
