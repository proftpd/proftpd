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
 * Core FTPD module
 * $Id
 *
 * 11/5/98	Habeeb J. Dihu aka MacGyver (macgyver@tos.net): added
 * 			wu-ftpd style CDPath support.
 */

#include "conf.h"

#include "privs.h"

#include <ctype.h>

#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

/* This is declared static to this module because it's not needed,
 * except for the HELP command.
 */

static struct {
  char *cmd;
  char *syntax;
  int implemented;
} _help[] = {
  { C_USER, "<sp> username",			TRUE },
  { C_PASS, "<sp> password",			TRUE },
  { C_ACCT, "is not implemented",		FALSE },
  { C_CWD,  "<sp> pathname",			TRUE },
  { C_XCWD, "<sp> pathname",			TRUE },
  { C_CDUP, "(up one directory)",		TRUE },
  { C_XCUP, "(up one directory)",		TRUE },
  { C_SMNT, "is not implemented",		FALSE },
  { C_QUIT, "(close control connection)",	TRUE },
  { C_REIN, "is not implemented",		FALSE },
  { C_PORT, "<sp> h1,h2,h3,h4,p1,p2",		TRUE },
  { C_PASV, "(returns address/port)",		TRUE },
  { C_TYPE, "<sp> type-code (A or I)",		TRUE },
  { C_STRU, "is not implemented",		FALSE },
  { C_MODE, "is not implemented (always S)",	FALSE },
  { C_RETR, "<sp> pathname",			TRUE },
  { C_STOR, "<sp> pathname",			TRUE },
  { C_STOU, "is not implemented",		FALSE },
  { C_APPE, "<sp> pathname",			TRUE },
  { C_ALLO, "is not implemented",		FALSE },
  { C_REST, "<sp> byte-count",			TRUE },
  { C_RNFR, "<sp> pathname",			TRUE },
  { C_RNTO, "<sp> pathname",			TRUE },
  { C_ABOR, "(abort current operation)",	TRUE },
  { C_DELE, "<sp> pathname",			TRUE },
  { C_MDTM, "<sp> pathname",			TRUE },
  { C_RMD,  "<sp> pathname",			TRUE },
  { C_XRMD, "<sp> pathname",			TRUE },
  { C_MKD,  "<sp> pathname",			TRUE },
  { C_XMKD, "<sp> pathname",			TRUE },
  { C_PWD,  "(returns current working directory)", TRUE },
  { C_XPWD, "(returns current working directory)", TRUE },
  { C_SIZE, "<sp> pathname",			TRUE },
  { C_LIST, "[<sp> pathname]",			TRUE },
  { C_NLST, "[<sp> (pathname)]",		TRUE },
  { C_SITE, "is not implemented",		TRUE },
  { C_SYST, "(returns system type)",		TRUE },
  { C_STAT, "[<sp> pathname]",			TRUE },
  { C_HELP, "[<sp> command]",			TRUE },
  { C_NOOP, "(no operation)",			TRUE },
  { NULL,   NULL,          			FALSE }
};

extern module site_module;
extern xaset_t *servers;

/* from mod_site */
extern modret_t *site_dispatch(cmd_rec*);

MODRET set_servername(cmd_rec *cmd)
{
  server_rec *s = cmd->server;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL);

  s->ServerName = pstrdup(s->pool,cmd->argv[1]);
  return HANDLED(cmd);
}

MODRET set_servertype(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT);

  if(!strcasecmp(cmd->argv[1],"inetd"))
    ServerType = SERVER_INETD;
  else if(!strcasecmp(cmd->argv[1],"standalone"))
    ServerType = SERVER_STANDALONE;
  else
    CONF_ERROR(cmd,"type must be either 'inetd' or 'standalone'.");
  return HANDLED(cmd);
}

MODRET add_transferlog(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);

  add_config_param_str("TransferLog",1,(void*)cmd->argv[1]);

  return HANDLED(cmd);
}

MODRET set_wtmplog(cmd_rec *cmd)
{
  int b;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);

  if(strcasecmp(cmd->argv[1],"NONE") == 0)
    b = 0;
  else
    b = get_boolean(cmd,1);

  if(b != -1)
    add_config_param("WtmpLog",1,(void*)b);

  return HANDLED(cmd);
}

MODRET add_bind(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL);

  add_config_param_str("Bind",1,(void*)cmd->argv[1]);

  return HANDLED(cmd);
}

MODRET set_serveradmin(cmd_rec *cmd)
{
  server_rec *s = cmd->server;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL);

  s->ServerAdmin = pstrdup(s->pool,cmd->argv[1]);

  return HANDLED(cmd);
}

MODRET set_usereversedns(cmd_rec *cmd)
{
  int b;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT);

  if((b = get_boolean(cmd,1)) == -1)
    CONF_ERROR(cmd,"expected boolean argument.");

  ServerUseReverseDNS = b;

  return HANDLED(cmd);
}

MODRET set_scoreboardpath(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT);

  log_run_setpath(cmd->argv[1]);

  return HANDLED(cmd);
}

MODRET set_serverport(cmd_rec *cmd)
{
  server_rec *s = cmd->server;
  int port;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL);

  port = atoi(cmd->argv[1]);
  if(port < 0 || port > 65535)
    CONF_ERROR(cmd,"value must be between 0 and 65535");

  s->ServerPort = port;
  return HANDLED(cmd);
}

MODRET set_deferwelcome(cmd_rec *cmd)
{
  int b;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if((b = get_boolean(cmd,1)) == -1)
    CONF_ERROR(cmd,"expected boolean argument.");

  add_config_param("DeferWelcome",1,(void*)b);

  return HANDLED(cmd);
}

MODRET set_serverident(cmd_rec *cmd)
{
  int b;
  config_rec *c;
  
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if(cmd->argc < 2 || cmd->argc > 3)
    CONF_ERROR(cmd,"invalid number of arguments");
  
  if((b = get_boolean(cmd,1)) == -1)
    CONF_ERROR(cmd,"expected boolean argument.");

  if(b && cmd->argc == 3) {
    c = add_config_param("ServerIdent",2,(void*)!b,NULL);
    c->argv[1] = pstrdup(permanent_pool,cmd->argv[2]);
  } else
    add_config_param("ServerIdent",1,(void*)!b);

  return HANDLED(cmd);
}

MODRET set_defaultserver(cmd_rec *cmd)
{
  int b;
  server_rec *s;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL);

  if((b = get_boolean(cmd,1)) == -1)
    CONF_ERROR(cmd,"expected boolean argument.");

  if(!b)
    return HANDLED(cmd);

  /* DefaultServer is not allowed if already set somewhere */
  for(s = (server_rec*)servers->xas_list; s; s=s->next)
    if(find_config(s->conf,CONF_PARAM,"DefaultServer",FALSE)) {
      CONF_ERROR(cmd,"DefaultServer has already been set.");
    }

  add_config_param("DefaultServer",1,(void*)b);
  return HANDLED(cmd);
}

MODRET set_maxinstances(cmd_rec *cmd)
{
  int max;
  char *endp;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT);

  if(!strcasecmp(cmd->argv[1],"none"))
    max = 0;
  else {
    max = (int)strtol(cmd->argv[1],&endp,10);

    if((endp && *endp) || max < 1)
      CONF_ERROR(cmd,"argument must be 'none' or a number greater than 0.");
  }

  ServerMaxInstances = max;
  return HANDLED(cmd);
}

MODRET _set_timeout(int *v, cmd_rec *cmd)
{
  int timeout;
  char *endp;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT);

  timeout = (int)strtol(cmd->argv[1],&endp,10);

  if((endp && *endp) || timeout < 0 || timeout > 65535)
    CONF_ERROR(cmd,"timeout values must be between 0 and 65535");

  *v = timeout;
  return HANDLED(cmd);
}

MODRET set_maxclients(cmd_rec *cmd)
{
  int max;
  char *endp;
  config_rec *c;

  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);

  if(cmd->argc < 2 || cmd->argc > 3)
    CONF_ERROR(cmd,"invalid number of arguments");

  if(!strcasecmp(cmd->argv[1],"none"))
    max = -1;
  else {
    max = (int)strtol(cmd->argv[1],&endp,10);

    if((endp && *endp) || max < 1)
      CONF_ERROR(cmd,"argument must be 'none' or a number greater than 0.");
  }

  if(cmd->argc == 3) {
    c = add_config_param("MaxClients",2,(void*)max,NULL);
    c->argv[1] = pstrdup(permanent_pool,cmd->argv[2]);   
  } else
    add_config_param("MaxClients",1,(void*)max);

  return HANDLED(cmd);
}

MODRET set_maxhostclients(cmd_rec *cmd)
{
  int max;
  char *endp;
  config_rec *c;

  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);

  if(cmd->argc < 2 || cmd->argc > 3)
    CONF_ERROR(cmd,"invalid number of arguments");

  if(!strcasecmp(cmd->argv[1],"none"))
    max = -1;
  else {
    max = (int)strtol(cmd->argv[1],&endp,10);

    if((endp && *endp) || max < 1)
      CONF_ERROR(cmd,"argument must be 'none' or a number greater than 0.");
  }

  if(cmd->argc == 3) {
    c = add_config_param("MaxClientsPerHost",2,(void*)max,NULL);
    c->argv[1] = pstrdup(c->pool,cmd->argv[2]);   
  } else
    add_config_param("MaxClientsPerHost",1,(void*)max);

  return HANDLED(cmd);
}

MODRET set_maxloginattempts(cmd_rec *cmd)
{
  int max;
  char *endp;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if(!strcasecmp(cmd->argv[1],"none"))
    max = 0;
  else {
    max = (int)strtol(cmd->argv[1],&endp,10);

    if((endp && *endp) || max < 1)
      CONF_ERROR(cmd,"argument must be 'none' or a number greater than 0.");
  }

  add_config_param("MaxLoginAttempts",1,(void*)max);
  return HANDLED(cmd);
}

MODRET set_useftpusers(cmd_rec *cmd)
{
  config_rec *c;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);

  c = add_config_param("UseFtpUsers",1,(void*)get_boolean(cmd,1));

  c->flags |= CF_MERGEDOWN;
  return HANDLED(cmd);
}

MODRET set_timeoutlogin(cmd_rec *cmd)
{
  return _set_timeout(&TimeoutLogin,cmd);
}

MODRET set_timeoutidle(cmd_rec *cmd)
{
  return _set_timeout(&TimeoutIdle,cmd);
}

MODRET set_timeoutnoxfer(cmd_rec *cmd)
{
  return _set_timeout(&TimeoutNoXfer,cmd);
}

MODRET set_timeoutstalled(cmd_rec *cmd)
{
  return _set_timeout(&TimeoutStalled,cmd);
}

MODRET set_socketbindtight(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT);

  SocketBindTight = get_boolean(cmd,1);
  return HANDLED(cmd);  
}

MODRET set_multilinerfc2228(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT);

  MultilineRFC2228 = get_boolean(cmd,1);
  return HANDLED(cmd);
}

MODRET set_identlookups(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param("IdentLookups",1,get_boolean(cmd,1));
  return HANDLED(cmd);
}

MODRET set_tcpbacklog(cmd_rec *cmd)
{
  int backlog;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT);

  backlog = atoi(cmd->argv[1]);

  if(backlog < 1 || backlog > 255)
    CONF_ERROR(cmd,"parameter must be a number between 1 and 255.");

  tcpBackLog = backlog;
  return HANDLED(cmd);
}

MODRET set_tcpreceivewindow(cmd_rec *cmd)
{
  int rwin;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL);

  rwin = atoi(cmd->argv[1]);

  if(rwin < 1024)
    CONF_ERROR(cmd,"parameter must be number equal to or greater than 1024.");

  cmd->server->tcp_rwin = rwin;
  cmd->server->tcp_rwin_override = 1;
  return HANDLED(cmd);
}

MODRET set_tcpsendwindow(cmd_rec *cmd)
{
  int swin;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL);

  swin = atoi(cmd->argv[1]);

  if(swin < 1024)
    CONF_ERROR(cmd,"parameter must be number equal to or greater than 1024.");

  cmd->server->tcp_swin = swin;
  cmd->server->tcp_swin_override = 1;
  return HANDLED(cmd);
}

MODRET set_user(cmd_rec *cmd)
{
  struct passwd *pw = NULL;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);

  /* 1.1.7, no longer force user/group lookup inside <Anonymous>
   * it's now defered until authentication occurs.
   */

  if(!cmd->config || cmd->config->config_type != CONF_ANON) {
    if((pw = auth_getpwnam(cmd->tmp_pool,cmd->argv[1])) == NULL) {
      auth_endpwent(cmd->tmp_pool);
      CONF_ERROR(cmd,pstrcat(cmd->tmp_pool,"Unknown user '",
                             cmd->argv[1],"'.",NULL));
    }
  }

  /* The extra cast is required to avoid compiler warning */

  if(pw) {
    add_config_param("User",1,(void*)((int)pw->pw_uid));
    /* We don't need extra fds sitting around open */
    auth_endpwent(cmd->tmp_pool);
  }

  add_config_param_str("UserName",1,(void*)cmd->argv[1]);
  return HANDLED(cmd);
}

MODRET set_group(cmd_rec *cmd)
{
  struct group *grp = NULL;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);

  if(!cmd->config || cmd->config->config_type != CONF_ANON) {
    if((grp = auth_getgrnam(cmd->tmp_pool,cmd->argv[1])) == NULL) {
      auth_endgrent(cmd->tmp_pool);
      CONF_ERROR(cmd,pstrcat(cmd->tmp_pool,"Unknown group '",
                             cmd->argv[1],"'.",NULL));
    }
  }

  /* The extra cast is needed to avoid compiler warning */

  if(grp) {
    add_config_param("Group",1,(void*)((int)grp->gr_gid));
    auth_endgrent(cmd->tmp_pool);
  }
  add_config_param_str("GroupName",1,(void*)cmd->argv[1]);

  return HANDLED(cmd);
}

MODRET add_userpassword(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,2);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);

  add_config_param_str("UserPassword",2,cmd->argv[1],cmd->argv[2]);
  return HANDLED(cmd);
}

MODRET add_grouppassword(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,2);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);

  add_config_param_str("GroupPassword",2,cmd->argv[1],cmd->argv[2]);
  return HANDLED(cmd);
}

MODRET set_accessgrantmsg(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);

  add_config_param_str("AccessGrantMsg",1,cmd->argv[1]);
  return HANDLED(cmd);
}

MODRET set_umask(cmd_rec *cmd)
{
  config_rec *c;
  char *endp;
  int _umask;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_DIR|CONF_ANON|CONF_GLOBAL);

  _umask = strtol(cmd->argv[1],&endp,8);

  if(endp && *endp)
    CONF_ERROR(cmd,pstrcat(cmd->tmp_pool,"'",cmd->argv[1],"' is not "
                           "a valid umask.",NULL));

  c = add_config_param("Umask",1,(void*)_umask);
  c->flags |= CF_MERGEDOWN;
  return HANDLED(cmd);
}

MODRET set_requirevalidshell(cmd_rec *cmd)
{
  config_rec *c;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);

  c = add_config_param("RequireValidShell",1,get_boolean(cmd,1));
  c->flags |= CF_MERGEDOWN;
  return HANDLED(cmd);
}

MODRET set_syslogfacility(cmd_rec *cmd)
{
  int i;
  struct {
    char *name;
    int facility;
  } factable[] = {
  { "AUTH",		LOG_AUTHPRIV		},
  { "AUTHPRIV",		LOG_AUTHPRIV		},
#ifdef HAVE_LOG_FTP
  { "FTP",		LOG_FTP			},
#endif
#ifdef HAVE_LOG_CRON
  { "CRON",		LOG_CRON		},
#endif  
  { "DAEMON",		LOG_DAEMON		},
  { "KERN",		LOG_KERN		},
  { "LOCAL0",		LOG_LOCAL0		},
  { "LOCAL1",		LOG_LOCAL1		},
  { "LOCAL2",		LOG_LOCAL2		},
  { "LOCAL3",		LOG_LOCAL3		},
  { "LOCAL4",		LOG_LOCAL4		},
  { "LOCAL5",		LOG_LOCAL5		},
  { "LOCAL6",		LOG_LOCAL6		},
  { "LOCAL7",		LOG_LOCAL7		},
  { "LPR",		LOG_LPR			},
  { "MAIL",		LOG_MAIL		},
  { "NEWS",		LOG_NEWS		},
  { "USER",		LOG_USER		},
  { "UUCP",		LOG_UUCP		},
  { NULL,		0			} };

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT);

  for(i = 0; factable[i].name; i++) {
    if(!strcasecmp(cmd->argv[1],factable[i].name)) {
      log_closesyslog();
      log_setfacility(factable[i].facility);

      block_signals();
      PRIVS_ROOT
      log_opensyslog(NULL);
      PRIVS_RELINQUISH
      unblock_signals();

      return HANDLED(cmd);
    }
  }

  CONF_ERROR(cmd,"argument must be a valid syslog facility");
}

MODRET set_showsymlinks(cmd_rec *cmd)
{
  config_rec *c;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);

  c = add_config_param("ShowSymlinks",1,get_boolean(cmd,1));
  c->flags |= CF_MERGEDOWN;
  return HANDLED(cmd);
}

MODRET set_pathallowfilter(cmd_rec *cmd)
#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
{
  regex_t *preg;
  config_rec *c;
  int ret;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);

  log_debug(DEBUG4,"Compiling allow regex '%s'",cmd->argv[1]);
  preg = calloc(1,sizeof(regex_t));
  log_debug(DEBUG4,"Allocated allow regex at location %p", preg);

  if((ret = regcomp(preg,cmd->argv[1],REG_EXTENDED|REG_NOSUB)) != 0) {
    char errmsg[200];

    regerror(ret, preg, errmsg, 200);
    regfree(preg);

    CONF_ERROR(cmd,pstrcat(cmd->tmp_pool,"'",cmd->argv[1],
               "' failed regex compilation: ",errmsg));
  }

  c = add_config_param("PathAllowFilter",1,preg);
  c->flags |= CF_MERGEDOWN;
  return HANDLED(cmd);
}
#else /* no regular expression support at the moment */
{
  CONF_ERROR(cmd,"The PathAllowFilter directive cannot be used on this system, "
                 "as you do not have POSIX compliant regex support.");
}
#endif

MODRET set_pathdenyfilter(cmd_rec *cmd)
#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
{
  regex_t *preg;
  config_rec *c;
  int ret;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);

  log_debug(DEBUG4,"Compiling deny regex '%s'",cmd->argv[1]);
  preg = calloc(1,sizeof(regex_t));
  log_debug(DEBUG4,"Allocated deny regex at location %p", preg);

  if((ret = regcomp(preg,cmd->argv[1],REG_EXTENDED|REG_NOSUB)) != 0) {
    char errmsg[200];

    regerror(ret, preg, errmsg, 200);
    regfree(preg);

    CONF_ERROR(cmd,pstrcat(cmd->tmp_pool,"'",cmd->argv[1],
               "' failed regex compilation: ",errmsg));
  }

  c = add_config_param("PathDenyFilter",1,preg);
  c->flags |= CF_MERGEDOWN;
  return HANDLED(cmd);
}
#else /* no regular expression support at the moment */
{
  CONF_ERROR(cmd,"The PathDenyFilter directive cannot be used on this system, "
                 "as you do not have POSIX compliant regex support.");
}
#endif

MODRET set_allowforeignaddress(cmd_rec *cmd)
{
  int b;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);

  if((b = get_boolean(cmd,1)) == -1)
    CONF_ERROR(cmd,"expected boolean argument.");

  add_config_param("AllowForeignAddress",1,(void*)b);

  return HANDLED(cmd);
}

MODRET add_cdpath(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);

  add_config_param_str("CDPath",1,(void*)cmd->argv[1]);

  return HANDLED(cmd);
}

MODRET add_directory(cmd_rec *cmd)
{
  config_rec *c;
  char *dir,*rootdir = NULL;
  int flags = 0;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);

  dir = cmd->argv[1];

  if(*dir != '/' && *dir != '~' && 
     (!cmd->config || cmd->config->config_type != CONF_ANON))
    CONF_ERROR(cmd,"relative pathname not allowed in non-anonymous blocks.");

  /* If in anonymous mode, and path is relative, just cat anon root
   * and relative path
   *
   * NOTE [Flood,9/97]: This is no longer necessary, because we don't
   * interpolate anonymous dirs at run-time.
   *
   */
  if(cmd->config && cmd->config->config_type == CONF_ANON &&
     *dir != '/' && *dir != '~') {
    if(strcmp(dir,"*") != 0)
      dir = pdircat(cmd->tmp_pool,"/",dir,NULL);
    rootdir = cmd->config->name;
  }
  else {
    /* if the directory begins with ~, two possibilities:
     * ~username/... : resolve to absolute path for ~username
     * ~/... : intended to be defered until authenciation, where
     *         ~ will be replaced w/ user's home dir
     */

    if(*dir == '~' && (!*(dir+1) || *(dir+1) == '/'))
      flags |= CF_DEFER;
    else {
      dir = dir_best_path(cmd->tmp_pool,dir);

      if(!dir)
        CONF_ERROR(cmd,pstrcat(cmd->tmp_pool,cmd->argv[1],": ",
                       strerror(errno),NULL));
    }
  }

  c = start_sub_config(dir);
  c->argc = 2;
  c->argv = pcalloc(c->pool,3*sizeof(void*));
  if(rootdir)
    c->argv[1] = pstrdup(permanent_pool,rootdir);

  c->config_type = CONF_DIR;
  c->flags |= flags;
  return HANDLED(cmd);
}

MODRET set_allowretrieverestart(cmd_rec *cmd)
{
  config_rec *c;
  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_DIR|CONF_ANON|CONF_GLOBAL);

  c = add_config_param("AllowRetrieveRestart",1,
                       (void*)get_boolean(cmd,1));
  c->flags |= CF_MERGEDOWN;
  return HANDLED(cmd);
}

MODRET set_allowstorerestart(cmd_rec *cmd)
{
  config_rec *c;
  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_DIR|CONF_ANON|CONF_GLOBAL);

  c = add_config_param("AllowStoreRestart",1,
                       (void*)get_boolean(cmd,1));
  c->flags |= CF_MERGEDOWN;
  return HANDLED(cmd);
}

MODRET add_hidenoaccess(cmd_rec *cmd)
{
  config_rec *c;
  CHECK_ARGS(cmd,0);
  CHECK_CONF(cmd,CONF_DIR|CONF_ANON);

  c = add_config_param("HideNoAccess",1,(void*)1);
  c->flags |= CF_MERGEDOWN;
  return HANDLED(cmd);
}

MODRET add_anonymousgroup(cmd_rec *cmd)
{
  config_rec *c;
  int argc;
  char **argv;
  array_header *acl;

  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if(cmd->argc < 2)
    CONF_ERROR(cmd,"syntax: AnonymousGroup <group-expression>");

  argv = cmd->argv;
  argc = cmd->argc - 1;

  acl = parse_group_expression(cmd->tmp_pool,&argc,argv);

  c = add_config_param("AnonymousGroup",0);
  c->argc = argc;
  c->argv = pcalloc(c->pool,(argc+1) * sizeof(char*));
  argv = (char**)c->argv;

  if(argc && acl)
    while(argc--) {
      *argv++ = pstrdup(permanent_pool,*((char**)acl->elts));
      acl->elts = ((char**)acl->elts) + 1;
    }

  *argv = NULL;
  return HANDLED(cmd);
}

MODRET add_hideuser(cmd_rec *cmd)
{
  config_rec *c;
  struct passwd *pw;
  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_DIR|CONF_ANON);

  pw = auth_getpwnam(cmd->tmp_pool,cmd->argv[1]);
  if(!pw)
    CONF_ERROR(cmd,pstrcat(cmd->tmp_pool,"'",cmd->argv[1],"' is not "
                   "a valid user.",NULL));

  c = add_config_param("HideUser",1,(void*)((int)pw->pw_uid));
  c->flags |= CF_MERGEDOWN;
  return HANDLED(cmd);
}

MODRET add_hidegroup(cmd_rec *cmd)
{
  config_rec *c;
  struct group *gr;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_DIR|CONF_ANON);

  gr = auth_getgrnam(cmd->tmp_pool,cmd->argv[1]);
  if(!gr)
    CONF_ERROR(cmd,pstrcat(cmd->tmp_pool,"'",cmd->argv[1],"' is not "
                   "a valid group.",NULL));

  c = add_config_param("HideGroup",1,(void*)((int)gr->gr_gid));
  c->flags |= CF_MERGEDOWN;
  return HANDLED(cmd);
}

MODRET add_groupowner(cmd_rec *cmd)
{
  config_rec *c;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ANON|CONF_DIR|CONF_DYNDIR);

  c = add_config_param_str("GroupOwner",1,cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;
  return HANDLED(cmd);
}

MODRET set_allowoverwrite(cmd_rec *cmd)
{
  config_rec *c;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_DIR|CONF_GLOBAL);

  c = add_config_param("AllowOverwrite",1,(void*)get_boolean(cmd,1));
  c->flags |= CF_MERGEDOWN;
  return HANDLED(cmd);
}

MODRET end_directory(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,0);
  CHECK_CONF(cmd,CONF_DIR);

  end_sub_config();
  return HANDLED(cmd);
}

MODRET add_anonymous(cmd_rec *cmd)
{
  config_rec *c;
  char *dir;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  dir = cmd->argv[1];

  if(*dir != '/' && *dir != '~')
    CONF_ERROR(cmd,pstrcat(cmd->tmp_pool,"(",dir,") absolute pathname "
               "required.",NULL));

  if(strchr(dir,'*'))
    CONF_ERROR(cmd,pstrcat(cmd->tmp_pool,"(",dir,") wildcards not allowed "
               "in pathname."));

  if(!strcmp(dir,"/"))
    CONF_ERROR(cmd,"'/' not permitted for anonymous root directory.");

  if(*(dir+strlen(dir)-1) != '/')
    dir = pstrcat(cmd->tmp_pool,dir,"/",NULL);

  if(!dir)
    CONF_ERROR(cmd,pstrcat(cmd->tmp_pool,cmd->argv[1],": ",
               strerror(errno),NULL));

  c = start_sub_config(dir);

  c->config_type = CONF_ANON;
  return HANDLED(cmd);
}

MODRET set_anonrequirepassword(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ANON);

  add_config_param("AnonRequirePassword",1,
                   (void*)get_boolean(cmd,1));
  return HANDLED(cmd);
}

MODRET end_anonymous(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,0);
  CHECK_CONF(cmd,CONF_ANON);

  end_sub_config();
  return HANDLED(cmd);
}

MODRET add_global(cmd_rec *cmd)
{
  config_rec *c;

  CHECK_ARGS(cmd,0);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL);

  c = start_sub_config("Global");
  c->config_type = CONF_GLOBAL;

  return HANDLED(cmd);
}

MODRET end_global(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,0);
  CHECK_CONF(cmd,CONF_GLOBAL);

  end_sub_config();
  return HANDLED(cmd);
}

MODRET add_limit(cmd_rec *cmd)
{
  config_rec *c;
  int cargc;
  char **argv,**cargv;

  if(cmd->argc < 2)
    CONF_ERROR(cmd,"directive requires one or more FTP commands.");
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_DIR|CONF_ANON|CONF_DYNDIR|CONF_GLOBAL);

  c = start_sub_config("Limit");
  c->config_type = CONF_LIMIT;
  cargc = cmd->argc-1;
  cargv = cmd->argv+1;

  c->argc = cmd->argc-1;
  c->argv = pcalloc(c->pool,cmd->argc*sizeof(void*));
  argv = (char**)c->argv;

  while(cargc--)
    *argv++ = pstrdup(permanent_pool,*cargv++);

  *argv = NULL;

  return HANDLED(cmd);
}

MODRET add_order(cmd_rec *cmd)
{
  int order = -1,argc = cmd->argc;
  char *arg = "",**argv = cmd->argv+1;

  CHECK_CONF(cmd,CONF_LIMIT);

  while(--argc && *argv)
    arg = pstrcat(cmd->tmp_pool,arg,*argv++,NULL);

  if(!strcasecmp(arg,"allow,deny"))
    order = ORDER_ALLOWDENY;
  else if(!strcasecmp(arg,"deny,allow"))
    order = ORDER_DENYALLOW;
  else
    CONF_ERROR(cmd,pstrcat(cmd->tmp_pool,"'",arg,"': invalid argument",NULL));

  add_config_param("Order",1,(void*)order);
  return HANDLED(cmd);
}

MODRET _add_allow_deny_user(cmd_rec *cmd, char *name)
{
  config_rec *c;
  char **argv;
  int argc;
  array_header *acl = NULL;

  CHECK_CONF(cmd,CONF_LIMIT);

  if(cmd->argc < 2)
    CONF_ERROR(cmd,pstrcat(cmd->tmp_pool,"syntax: ",name,
               " <user-expression>",NULL));

  argv = cmd->argv;
  argc = cmd->argc-1;

  acl = parse_user_expression(cmd->tmp_pool,&argc,argv);

  c = add_config_param(name,0);

  c->argc = argc;
  c->argv = pcalloc(c->pool,(argc+1) * sizeof(char*));
  argv = (char**)c->argv;
  while(argc--) {
    *argv++ = pstrdup(permanent_pool,*((char**)acl->elts));
    acl->elts = ((char**)acl->elts) + 1;
  }

  *argv = NULL;
  return HANDLED(cmd);
}

MODRET _add_allow_deny_group(cmd_rec *cmd, char *name)
{
  config_rec *c;
  char **argv;
  int argc;
  array_header *acl = NULL;

  CHECK_CONF(cmd,CONF_LIMIT);

  if(cmd->argc < 2)
    CONF_ERROR(cmd,pstrcat(cmd->tmp_pool,"syntax: ",name,
               " <group-expression>",NULL));

  argv = cmd->argv;
  argc = cmd->argc-1;

  acl = parse_group_expression(cmd->tmp_pool,&argc,argv);

  c = add_config_param(name,0);

  c->argc = argc;
  c->argv = pcalloc(c->pool,(argc+1) * sizeof(char*));
  argv = (char**)c->argv;
  while(argc--) {
    *argv++ = pstrdup(permanent_pool,*((char**)acl->elts));
    acl->elts = ((char**)acl->elts) + 1;
  }

  *argv = NULL;
  return HANDLED(cmd);
}

MODRET add_allowgroup(cmd_rec *cmd)
{
  return _add_allow_deny_group(cmd,"AllowGroup");
}

MODRET add_denygroup(cmd_rec *cmd)
{
  return _add_allow_deny_group(cmd,"DenyGroup");
}

MODRET add_allowuser(cmd_rec *cmd)
{
  return _add_allow_deny_user(cmd,"AllowUser");
}

MODRET add_denyuser(cmd_rec *cmd)
{
  return _add_allow_deny_user(cmd,"DenyUser");
}

MODRET _add_allow_deny(cmd_rec *cmd, char *name)
{
  int argc;
  char *s,*ent,**argv;
  array_header *acl;
  config_rec *c;

  CHECK_CONF(cmd,CONF_LIMIT);

  /* Syntax: allow [from] [all|none]|host|network[,...] */
  acl = make_array(cmd->tmp_pool,cmd->argc,sizeof(char*));
  argc = cmd->argc-1; argv = cmd->argv;

  /* Skip optional "from" keyword */
  while(argc && *(argv+1)) {
    if(!strcasecmp("from",*(argv+1))) {
      argv++; argc--; continue;
    } else if(!strcasecmp("all",*(argv+1))) {
      *((char**)push_array(acl)) = "ALL";
      argc = 0;
    } else if(!strcasecmp("none",*(argv+1))) {
      *((char**)push_array(acl)) = "NONE";
      argc = 0;
    }
    break;
  }

  while(argc-- && *(++argv)) {
    s = pstrdup(cmd->tmp_pool,*argv);

    /* parse the string into coma-delimited entries */
    while((ent = get_token(&s,",")) != NULL)
      if(*ent) {
        if(!strcasecmp(ent,"all") || !strcasecmp(ent,"none")) {
          acl->nelts = 0; argc = 0; break;
        }

        *((char**)push_array(acl)) = ent;
      }
  }

  if(!acl->nelts)
    CONF_ERROR(cmd,pstrcat(cmd->tmp_pool,"syntax: ",name,
                   " [from] [all|none]|host|network[,...]",NULL));

  c = add_config_param(name,0);

  c->argc = acl->nelts;
  c->argv = pcalloc(c->pool,(c->argc+1) * sizeof(char*));
  argv = (char**)c->argv;
  while(acl->nelts--) {
    *argv++ = pstrdup(permanent_pool,*((char**)acl->elts));
    acl->elts = ((char**)acl->elts) + 1;
  }

  *argv = NULL;
  return HANDLED(cmd);
}

MODRET add_allow(cmd_rec *cmd)
{
  return _add_allow_deny(cmd,"Allow");
}

MODRET add_deny(cmd_rec *cmd)
{
  return _add_allow_deny(cmd,"Deny");
}

MODRET set_denyall(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,0);
  CHECK_CONF(cmd,CONF_LIMIT|CONF_ANON);

  add_config_param("DenyAll",1,(void*)1);
  return HANDLED(cmd);
}

MODRET set_allowall(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,0);
  CHECK_CONF(cmd,CONF_LIMIT|CONF_ANON);

  add_config_param("AllowAll",1,(void*)1);
  return HANDLED(cmd);
}

MODRET end_limit(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,0);
  CHECK_CONF(cmd,CONF_LIMIT);

  end_sub_config();
  return HANDLED(cmd);
}

MODRET set_ignorehidden(cmd_rec *cmd)
{
  config_rec *c;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_LIMIT);

  c = add_config_param("IgnoreHidden",1,(void*)get_boolean(cmd,1));
  return HANDLED(cmd);
}

MODRET add_useralias(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,2);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);

  add_config_param_str("UserAlias",2,(void*)cmd->argv[1],(void*)cmd->argv[2]);

  return HANDLED(cmd);
}

MODRET set_displaylogin(cmd_rec *cmd)
{
  config_rec *c;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);

  c = add_config_param_str("DisplayLogin",1,(void*)cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;
  return HANDLED(cmd);
}

MODRET set_displayconnect(cmd_rec *cmd)
{
  config_rec *c;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param_str("DisplayConnect",1,(void*)cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;
  return HANDLED(cmd);
}

MODRET set_displayfirstchdir(cmd_rec *cmd)
{
  config_rec *c;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_DIR|CONF_GLOBAL);

  c = add_config_param_str("DisplayFirstChdir",1,(void*)cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;
  return HANDLED(cmd);
}

MODRET set_authaliasonly(cmd_rec *cmd)
{
  int b;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);

  if((b = get_boolean(cmd,1)) == -1)
    CONF_ERROR(cmd,"expected boolean argument.");

  add_config_param("AuthAliasOnly",1,(void*)b);

  return HANDLED(cmd);
}

MODRET add_virtualhost(cmd_rec *cmd)
{
  server_rec *s;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT);

  if(cmd->server != main_server)
    CONF_ERROR(cmd,"directive cannot be nested.");

  s = start_new_server(cmd->argv[1]);
  if(!s)
    CONF_ERROR(cmd,"unable to create virtual server configuration.");

  s->ServerPort = main_server->ServerPort;
  return HANDLED(cmd);
}

MODRET end_virtualhost(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,0);

  if(cmd->server == main_server)
    CONF_ERROR(cmd,"must be matched with <VirtualServer> directive.");

  end_new_server();
  return HANDLED(cmd);
}

/* Display a file via a given response numeric.  File is displayed
 * in normal RFC959 multline mode, unless MultilineRFC2228 is set.
 * Returns: -1 on error
 *          0 if file display
 */

int core_display_file(const char *numeric, const char *fn)
{
  fsdir_t *fp;
  char buf[1024];
  int len,max,fd;
  unsigned long fs_size = 0;
  pool *p;
  xaset_t *s;
  char *outs,*mg_time,mg_size[12],mg_max[12] = "unlimited";
  char mg_cur[12];
  short first = 1;

#if defined(HAVE_SYS_STATVFS_H) || defined(HAVE_SYS_VFS_H)
  fs_size = get_fs_size((char*)fn);
#endif

  if((fp = fs_open_canon(fn,O_RDONLY,&fd)) == NULL)
    return -1;

  p = make_sub_pool(permanent_pool);

  s = (session.anon_config ? session.anon_config->subset : main_server->conf);

  mg_time = fmt_time(time(NULL));
  sprintf(mg_size,"%lu",fs_size);
  max = get_param_int(s,"MaxClients",FALSE);
  sprintf(mg_cur,"%d",(int)get_param_int(main_server->conf,
          "CURRENT-CLIENTS",FALSE)+1);

  if(max != -1)
    sprintf(mg_max,"%d",max);

  while(fs_gets(buf,sizeof(buf),fp,fd) != NULL) {
    buf[1023] = '\0';

    len = strlen(buf);

    while(len && (buf[len-1] == '\r' || buf[len-1] == '\n')) {
      buf[len-1] = '\0';
      len--;
    }

    outs = sreplace(p,buf,
             "%T",mg_time,
             "%F",mg_size,
	     "%C",(session.cwd[0] ? session.cwd : "(none)"),
	     "%R",(session.c && session.c->remote_name ?
		   session.c->remote_name : "(unknown)"),
	     "%L",main_server->ServerFQDN,
             "%u",session.ident_user,
	     "%U",(char*)get_param_ptr(main_server->conf,"USER",FALSE),
	     "%M",mg_max,
             "%N",mg_cur,
	     "%E",main_server->ServerAdmin,
	     "%V",main_server->ServerName,
             NULL);

    if(first) {
      send_response_raw("%s-%s",numeric,outs);
      first=0;
    } else {
      if(MultilineRFC2228)
        send_response_raw("%s-%s",numeric,outs);
      else
        send_response_raw(" %s",outs);
      }
  }

  fs_close(fp,fd);
  return 0;
}

MODRET cmd_quit(cmd_rec *cmd)
{
  send_response(R_221,"Goodbye.");
  log_pri(LOG_NOTICE,"FTP session closed.");
  end_login(0);
  return HANDLED(cmd);			/* Avoid compiler warning */
}

/* per RFC959, directory responses for MKD and PWD should be
 * "dir_name" (w/ quote).  For directories that CONTAIN quotes,
 * the add'l quotes must be duplicated.
 */

static char *quote_dir(cmd_rec *cmd, char *dir)
{
  return sreplace(cmd->tmp_pool,dir,"\"","\"\"",NULL);
}

MODRET cmd_pwd(cmd_rec *cmd)
{
  if(cmd->argc != 1) {
    add_response_err(R_500,"'%s' not understood.",get_full_cmd(cmd));
    return ERROR(cmd);
  }

  
  add_response(R_257,"\"%s\" is current directory.",
                quote_dir(cmd,session.vwd));
  return HANDLED(cmd);
}

MODRET cmd_pasv(cmd_rec *cmd)
{
  union {
    p_in_addr_t addr;
    unsigned char u[4];
  } addr;

  union {
    unsigned short port;
    unsigned char u[2];
  } port;

  if(cmd->argc != 1) {
    add_response_err(R_500,"'%s' not understood.",get_full_cmd(cmd));
    return ERROR(cmd);
  }

  /* If we already have a passive listen data connection open,
   * kill it.
   */

  if(session.d) {
    inet_close(session.d->pool,session.d);
    session.d = NULL;
  }

  session.d = inet_create_connection(session.pool,NULL,-1,
		session.c->local_ipaddr,INPORT_ANY,FALSE);

  if(!session.d)
     return ERROR_MSG(cmd,R_425,
                     "Unable to build data connection: Internal error.");

  inet_setblock(session.pool,session.d);
  inet_listen(session.pool,session.d,1);

  session.d->inf = io_open(session.pool,session.d->listen_fd,IO_READ);

  /* Now tell the client our address/port */
  session.data_port = session.d->local_port;
  session.flags |= SF_PASSIVE;

  addr.addr = *session.d->local_ipaddr;
  port.port = htons(session.data_port);


  log_debug(DEBUG1,"Entering Passive Mode (%u,%u,%u,%u,%u,%u)",
		(int)addr.u[0],(int)addr.u[1],(int)addr.u[2],
		(int)addr.u[3],(int)port.u[0],(int)port.u[1]);

  add_response(R_227, "Entering Passive Mode (%u,%u,%u,%u,%u,%u)",
                (int)addr.u[0],(int)addr.u[1],(int)addr.u[2],
                (int)addr.u[3],(int)port.u[0],(int)port.u[1]);

  return HANDLED(cmd);
}

MODRET cmd_port(cmd_rec *cmd)
{
  union {
    p_in_addr_t addr;
    unsigned char u[4];
  } addr;

  union {
    unsigned short port;
    unsigned char u[2];
  } port;

  char *a,*endp,*arg;
  int i,cnt = 0;
  int allow_foreign_addr = 0;

  if(cmd->argc != 2) {
    add_response_err(R_500,"'%s' not understood.",get_full_cmd(cmd));
    return ERROR(cmd);
  }

  /* Format is h1,h2,h3,h4,p1,p2 (ASCII in network order) */
  a = pstrdup(cmd->tmp_pool,cmd->argv[1]);

  while(a && *a && cnt < 6) {
    arg = strsep(&a,",");

    if(!arg && a && *a) {
      arg = a;
      a = NULL;
    } else if(!arg)
      break;

    i = strtol(arg,&endp,10);
    if(*endp || i < 0 || i > 255)
      break;

    if(cnt < 4)
      addr.u[cnt++] = (unsigned char)i;
    else
      port.u[cnt++ - 4] = (unsigned char)i;
  }

  if(cnt != 6 || (a && *a))
    return ERROR_MSG(cmd,R_501,"Illegal PORT command.");

  /* Make sure that the address specified matches the address
   * that the control connection is coming from.
   */

  allow_foreign_addr = get_param_int(TOPLEVEL_CONF,"AllowForeignAddress",FALSE);

  if(allow_foreign_addr != 1) {
    if(addr.addr.s_addr != session.c->remote_ipaddr->s_addr ||
       !port.port) {
      log_pri(LOG_WARNING,"refused PORT %s from %s (address mismatch)",
    			  cmd->arg,session.c->remote_name);
      return ERROR_MSG(cmd,R_500,"Illegal PORT command.");
    }
  }

  /* Additionally, make sure that the port number used is a "high
   * numbered" port, to avoid bounce attacks
   */

  if(ntohs(port.port) < 1024) {
    log_pri(LOG_WARNING,"refused PORT %s from %s (bounce attack)",
                        cmd->arg,session.c->remote_name);
    return ERROR_MSG(cmd,R_500,"Illegal PORT command.");
  }

  memcpy(&session.data_addr, &addr.addr, sizeof(session.data_addr));
  session.data_port = ntohs(port.port);
  session.flags &= (SF_ALL^SF_PASSIVE);

  /* If we already have a data connection open, kill it.
   */

  if(session.d) {
    inet_close(session.d->pool,session.d);
    session.d = NULL;
  }

  add_response(R_200,"PORT command successful.");
  return HANDLED(cmd);
}

MODRET cmd_help(cmd_rec *cmd)
{
  int i,c = 0;
  char buf[9];

  if(cmd->argc == 1) {
    /* Print help for all commands */
    char *outa[8];
    char *outs = "";

    bzero(outa,sizeof(outa));

    add_response(R_214,
      "The following commands are recognized (* =>'s unimplemented).");
    for(i = 0; _help[i].cmd; i++) {

      if(_help[i].implemented)
        outa[c++] = _help[i].cmd;
      else
        outa[c++] = pstrcat(cmd->tmp_pool,_help[i].cmd,"*",NULL);

      /* 8 rows */
      if(((i+1) % 8 == 0) || !_help[i+1].cmd) {
        int j;

        for(j = 0; j < 8; j++) {
          if(outa[j]) {
            sprintf(buf,"%-8s",outa[j]);
            outs = pstrcat(cmd->tmp_pool,outs,buf,NULL);
          } else
            break;
        }

        if(*outs)
          add_response(R_214,"%s",outs);
        outs = "";
        c = 0;
        bzero(outa,sizeof(outa));
      }
    }

    add_response(R_214,"Direct comments to %s.",
                         (cmd->server->ServerAdmin ? cmd->server->ServerAdmin :
                          "ftp-admin"));
  } else {
    char *cp;

    for(cp = cmd->argv[1]; *cp; cp++)
      *cp = toupper(*cp);

    if(!strcmp(cmd->argv[1],"SITE"))
      return call_module(&site_module,site_dispatch,cmd);

    for(i = 0; _help[i].cmd; i++)
      if(!strcasecmp(cmd->argv[1],_help[i].cmd)) {
        add_response(R_214,"Syntax: %s %s",cmd->argv[1],_help[i].syntax);
        return HANDLED(cmd);
      }

    add_response_err(R_502,"Unknown command '%s'.",cmd->argv[1]);
    return ERROR(cmd);
  }

  return HANDLED(cmd);
}

MODRET cmd_syst(cmd_rec *cmd)
{
  add_response(R_215,"UNIX Type: L8");
  return HANDLED(cmd);
}

int core_chmod(cmd_rec *cmd, char *dir, mode_t mode)
{
  if(!dir_check(cmd->tmp_pool,"SITE_CHMOD","WRITE",dir,NULL))
    return -1;

  return fs_chmod(dir,mode);
}

MODRET _chdir(cmd_rec *cmd,char *ndir)
{
  char *display = NULL;
  char *dir,*odir,*cdir;
  config_rec *cdpath;
  int showsymlinks;
  
  odir = ndir;
  showsymlinks = get_param_int(TOPLEVEL_CONF,"ShowSymlinks",FALSE);

  if(showsymlinks == -1)
    showsymlinks = 1;

  if(showsymlinks) {
    dir = dir_realpath(cmd->tmp_pool,ndir);

    if(!dir || !dir_check_full(cmd->tmp_pool,cmd->argv[0],cmd->group,dir,NULL) ||
        fs_chdir(dir,0) == -1) {
      for(cdpath = find_config(main_server->conf,CONF_PARAM,"CDPath",TRUE);
	  cdpath != NULL; cdpath =
	    find_config_next(cdpath,cdpath->next,CONF_PARAM,"CDPath",TRUE)) {
	cdir = (char *) malloc(strlen(cdpath->argv[0]) + strlen(ndir) + 2);
	sprintf(cdir,"%s%s%s",cdpath->argv[0],
		((char *)cdpath->argv[0])[strlen(cdpath->argv[0]) - 1] == '/' ? "" : "/",
		ndir);
	dir = dir_realpath(cmd->tmp_pool,cdir);
	free(cdir);
	if(dir &&
	   dir_check_full(cmd->tmp_pool,cmd->argv[0],cmd->group,dir,NULL) &&
	   fs_chdir(dir,0) != -1) {
	  break;
	}
      }
      if(!cdpath) {
	add_response_err(R_550,"%s: %s",odir,strerror(errno));
	return ERROR(cmd);
      }
    }
  } else {
    /* virtualize the chdir */
    ndir = dir_virtual_chdir(cmd->tmp_pool,ndir);
    dir = dir_realpath(cmd->tmp_pool,ndir);

    if(!dir || !dir_check_full(cmd->tmp_pool,cmd->argv[0],cmd->group,dir,NULL) ||
        fs_chdir_canon(ndir,1) == -1) {

      for(cdpath = find_config(main_server->conf,CONF_PARAM,"CDPath",TRUE);
	  cdpath != NULL; cdpath =
	    find_config_next(cdpath,cdpath->next,CONF_PARAM,"CDPath",TRUE)) {
	cdir = (char *) malloc(strlen(cdpath->argv[0]) + strlen(ndir) + 2);
	sprintf(cdir,"%s%s%s",cdpath->argv[0],
		((char *)cdpath->argv[0])[strlen(cdpath->argv[0]) - 1] == '/' ? "" : "/",
		ndir);
	ndir = dir_virtual_chdir(cmd->tmp_pool,cdir);
	dir = dir_realpath(cmd->tmp_pool,ndir);
	free(cdir);
	if(dir &&
	   dir_check_full(cmd->tmp_pool,cmd->argv[0],cmd->group,dir,NULL) &&
	   fs_chdir_canon(ndir,1) != -1) {
	  break;
	}
      }
      if(!cdpath) {
	add_response_err(R_550,"%s: %s",odir,strerror(errno));
	return ERROR(cmd);
      }
    }
  }

  strncpy(session.cwd,fs_getcwd(),sizeof(session.cwd));
  strncpy(session.vwd,fs_getvwd(),sizeof(session.vwd));
  log_run_cwd(session.cwd);

  if(session.dir_config)
    display = (char*)get_param_ptr(session.dir_config->subset,
                                   "DisplayFirstChdir",FALSE);
  if(!display && session.anon_config)
    display = (char*)get_param_ptr(session.anon_config->subset,
                                   "DisplayFirstChdir",FALSE);
  if(!display)
    display = (char*)get_param_ptr(cmd->server->conf,
                                   "DisplayFirstChdir",FALSE);

  if(display) {
    config_rec *c;
    time_t last;
    struct stat sbuf;

    c = find_config(cmd->server->conf,CONF_USERDATA,session.cwd,FALSE);

    if(!c) {
      time(&last);
      c = add_config_set(&cmd->server->conf,session.cwd);
      c->config_type = CONF_USERDATA;
      c->argc = 1;
      c->argv = pcalloc(c->pool,sizeof(void**) * 2);
      c->argv[0] = (void*)last;
      last = (time_t)0L;
    } else {
      last = (time_t)c->argv[0];
      c->argv[0] = (void*)time(NULL);
    }

    if(fs_stat(display,&sbuf) != -1 && !S_ISDIR(sbuf.st_mode) &&
       sbuf.st_mtime > last)
      core_display_file(R_250,display);
  }

  add_response(R_250,"CWD command successful.");
  return HANDLED(cmd);
}

MODRET cmd_rmd(cmd_rec *cmd)
{
  char *dir;
#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  regex_t *preg;
#endif

  if(cmd->argc < 2) {
    add_response_err(R_500,"'%s' is an unknown command.",get_full_cmd(cmd));
    return ERROR(cmd);
  }

#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  preg = (regex_t*)get_param_ptr(TOPLEVEL_CONF,"PathAllowFilter",FALSE);

  if(preg && regexec(preg,cmd->arg,0,NULL,0) != 0) {
    add_response_err(R_550,"%s: Forbidden filename",cmd->arg);
    return ERROR(cmd);
  }

  preg = (regex_t*)get_param_ptr(TOPLEVEL_CONF,"PathDenyFilter",FALSE);
  
  if(preg && regexec(preg,cmd->arg,0,NULL,0) == 0) {
    add_response_err(R_550,"%s: Forbidden filename",cmd->arg);
    return ERROR(cmd);
  }
#endif

  dir = dir_realpath(cmd->tmp_pool,cmd->arg);

  if(!dir || !dir_check(cmd->tmp_pool,cmd->argv[0],cmd->group,dir,NULL) ||
     rmdir(dir) == -1) {
    add_response_err(R_550,"%s: %s",cmd->arg,strerror(errno));
    return ERROR(cmd);
  } else
    add_response(R_250,"%s command successful.",cmd->argv[0]);

  return HANDLED(cmd);
}

MODRET cmd_mkd(cmd_rec *cmd)
{
  char *dir;
#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  regex_t *preg;
#endif

  if(cmd->argc < 2) {
    add_response_err(R_500,"'%s' is an unknown command.",get_full_cmd(cmd));
    return ERROR(cmd);
  }

  if(strchr(cmd->arg,'*')) {
    add_response_err(R_550,"%s: Invalid directory name", cmd->argv[1]);
    return ERROR(cmd);
  }

#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
    preg = (regex_t*)get_param_ptr(TOPLEVEL_CONF,"PathAllowFilter",FALSE);

    if(preg && regexec(preg,cmd->arg,0,NULL,0) != 0) {
      add_response_err(R_550,"%s: Forbidden filename",cmd->arg);
      return ERROR(cmd);
    }

    preg = (regex_t*)get_param_ptr(TOPLEVEL_CONF,"PathDenyFilter",FALSE);

    if(preg && regexec(preg,cmd->arg,0,NULL,0) == 0) {
      add_response_err(R_550,"%s: Forbidden filename",cmd->arg);
      return ERROR(cmd);
    }
#endif

  dir = dir_canonical_path(cmd->tmp_pool,cmd->arg);

  if(!dir || !dir_check_canon(cmd->tmp_pool,cmd->argv[0],cmd->group,dir,NULL) ||
     mkdir(dir,0777) == -1) {
    add_response_err(R_550,"%s: %s",cmd->argv[1],strerror(errno));
    return ERROR(cmd);
  } else {
    if(session.fsgid) {
      struct stat sbuf;

      fs_stat(dir,&sbuf);
      if(chown(dir,(uid_t)-1,(gid_t)session.fsgid) == -1)
        log_pri(LOG_WARNING,"chown() failed: %s",strerror(errno));
      else
        chmod(dir,sbuf.st_mode);
    }
    add_response(R_257,"\"%s\" - directory successfully created.",
                  quote_dir(cmd,dir));
  }
    
  return HANDLED(cmd);
}

MODRET cmd_cwd(cmd_rec *cmd)
{
  
  if(cmd->argc < 2) {
    add_response_err(R_500,"'%s' is an unknown command.",get_full_cmd(cmd));
    return ERROR(cmd);
  }

  return _chdir(cmd,cmd->arg);
}

MODRET cmd_cdup(cmd_rec *cmd)
{
  if(cmd->argc != 1) {
    add_response_err(R_500,"'%s' is an unknown command.",get_full_cmd(cmd));
    return ERROR(cmd);
  }

  return _chdir(cmd,"..");
}

/* Returns the modification time of a file.  This is not in RFC959,
 * but supposedly will be in the future.  Command/response:
 * - MDTM <sp> path-name <crlf>
 * - 213 <sp> YYYYMMDDHHMMSS <crlf>
 *
 * We return the time as GMT, not localtime.  WU-ftpd returns localtime,
 * which seems like a Bad Thing<tm> to me.  However, my reasoning might
 * not be correct.
 */

MODRET cmd_mdtm(cmd_rec *cmd)
{
  char *path;
  char buf[16];
  struct tm *tm;
  struct stat sbuf;
  
  if(cmd->argc < 2) {
    add_response_err(R_500,"'%s' is an unknown command.",get_full_cmd(cmd));
    return ERROR(cmd);
  }

  path = dir_realpath(cmd->tmp_pool,cmd->arg);

  if(!path || !dir_check(cmd->tmp_pool,cmd->argv[0],cmd->group,path,NULL) ||
     fs_stat(path,&sbuf) == -1) {
    add_response_err(R_550,"%s: %s",cmd->argv[1],strerror(errno));
    return ERROR(cmd);
  } else {
    if(!S_ISREG(sbuf.st_mode)) {
      add_response_err(R_550,"%s: not a plain file.",cmd->argv[1]);
      return ERROR(cmd);
    } else {
      tm = gmtime(&sbuf.st_mtime);
      if(tm)
        sprintf(buf,"%04d%02d%02d%02d%02d%02d",
                tm->tm_year+1900,tm->tm_mon+1,tm->tm_mday,
                tm->tm_hour,tm->tm_min,tm->tm_sec);
      else
        sprintf(buf,"00000000000000");        
      add_response(R_213,"%s",buf);
    }
  }

  return HANDLED(cmd);
}

MODRET cmd_size(cmd_rec *cmd)
{
  char *path;
  struct stat sbuf;
  unsigned long st_size;

  if(cmd->argc < 2) {
    add_response_err(R_500,"'%s' is an unknown command.",get_full_cmd(cmd));
    return ERROR(cmd);
  }

  path = dir_realpath(cmd->tmp_pool,cmd->arg);

  if(!path || !dir_check(cmd->tmp_pool,cmd->argv[0],cmd->group,path,NULL) ||
      fs_stat(path,&sbuf) == -1) {
    add_response_err(R_550,"%s: %s",cmd->arg,strerror(errno));
    return ERROR(cmd);
  } else {
    if(!S_ISREG(sbuf.st_mode)) {
      add_response_err(R_550,"%s: not a regular file.",cmd->arg);
      return ERROR(cmd);
    } else {
      st_size = sbuf.st_size;
#if 0
      /* This code disabled in 1.1.6pl2, it allowed a possible DoS when sizeing
       * large files in ascii mode.
       */
      if(session.flags & (SF_ASCII|SF_ASCII_OVERRIDE)) {
        int fd,cnt;
	char buf[4096];

        if((fp = fs_open(path,O_RDONLY,&fd)) != NULL) {
          st_size = 0;
          while((cnt = fs_read(fp,fd,buf,sizeof(buf))) > 0) {
            st_size += cnt;
            while(cnt--)
              if(buf[cnt] == '\n') st_size++;
          }
          
          fs_close(fp,fd);
        }
      }
#endif
      add_response(R_213,"%lu",st_size);
    }
  }

  return HANDLED(cmd);
}

MODRET cmd_dele(cmd_rec *cmd)
{
  char *path;
#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  regex_t *preg;
#endif

  if(cmd->argc < 2) {
    add_response_err(R_500,"'%s' is an unknown command.",get_full_cmd(cmd));
    return ERROR(cmd);
  }

#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  preg = (regex_t*)get_param_ptr(TOPLEVEL_CONF,"PathAllowFilter",FALSE);

  if(preg && regexec(preg,cmd->arg,0,NULL,0) != 0) {
    add_response_err(R_550,"%s: Forbidden filename",cmd->arg);
    return ERROR(cmd);
  }

  preg = (regex_t*)get_param_ptr(TOPLEVEL_CONF,"PathDenyFilter",FALSE);

  if(preg && regexec(preg,cmd->arg,0,NULL,0) == 0) {
    add_response_err(R_550,"%s: Forbidden filename",cmd->arg);
    return ERROR(cmd);
  }
#endif

  path = dir_realpath(cmd->tmp_pool,cmd->arg);
  if(!path || !dir_check(cmd->tmp_pool,cmd->argv[0],cmd->group,path,NULL) ||
     fs_unlink(path) == -1) {
    add_response_err(R_550,"%s: %s",cmd->arg,strerror(errno));
    return ERROR(cmd);
  }

  add_response(R_250,"%s command successful.",cmd->argv[0]);
  return HANDLED(cmd);
}

MODRET cmd_rnto(cmd_rec *cmd)
{
  char *path;
#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  regex_t *preg;
#endif

  if(cmd->argc < 2) {
    add_response_err(R_500,"'%s' is an unknown command.",get_full_cmd(cmd));
    return ERROR(cmd);
  }

  if(!session.xfer.path) {
    if(session.xfer.p) {
      destroy_pool(session.xfer.p);
      bzero(&session.xfer,sizeof(session.xfer));
    }

    add_response_err(R_503,"Bad sequence of commands.");
    return ERROR(cmd);
  }

#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  preg = (regex_t*)get_param_ptr(TOPLEVEL_CONF,"PathAllowFilter",FALSE);

  if(preg && regexec(preg,cmd->arg,0,NULL,0) != 0) {
    add_response_err(R_550,"%s: Forbidden filename",cmd->arg);
    return ERROR(cmd);
  }

  preg = (regex_t*)get_param_ptr(TOPLEVEL_CONF,"PathDenyFilter",FALSE);

  if(preg && regexec(preg,cmd->arg,0,NULL,0) == 0) {
    add_response_err(R_550,"%s: Forbidden filename",cmd->arg);
    return ERROR(cmd);
  }
#endif

  path = dir_canonical_path(cmd->tmp_pool,cmd->arg);

  if(!path || !dir_check_canon(cmd->tmp_pool,cmd->argv[0],cmd->group,path,NULL) 
     || rename(session.xfer.path,path) == -1) {
    add_response_err(R_550,"rename: %s",strerror(errno));
    destroy_pool(session.xfer.p);
    bzero(&session.xfer,sizeof(session.xfer));
    return ERROR(cmd);
  }

  add_response(R_200,"rename successful.");
  destroy_pool(session.xfer.p);
  bzero(&session.xfer,sizeof(session.xfer));
  return HANDLED(cmd);
}

MODRET cmd_rnfr(cmd_rec *cmd)
{
  char *path;
#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  regex_t *preg;
#endif

  if(cmd->argc < 2) {
    add_response_err(R_500,"'%s' is an unknown command.",get_full_cmd(cmd));
    return ERROR(cmd);
  }

#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  preg = (regex_t*)get_param_ptr(TOPLEVEL_CONF,"PathAllowFilter",FALSE);

  if(preg && regexec(preg,cmd->arg,0,NULL,0) != 0) {
    add_response_err(R_550,"%s: Forbidden filename",cmd->arg);
    return ERROR(cmd);
  }

  preg = (regex_t*)get_param_ptr(TOPLEVEL_CONF,"PathDenyFilter",FALSE);

  if(preg && regexec(preg,cmd->arg,0,NULL,0) == 0) {
    add_response_err(R_550,"%s: Forbidden filename",cmd->arg);
    return ERROR(cmd);
  }
#endif

  path = dir_realpath(cmd->tmp_pool,cmd->arg);

  if(!path || !dir_check(cmd->tmp_pool,cmd->argv[0],cmd->group,path,NULL) ||
     !exists(path)) {
    add_response_err(R_550,"%s: %s",cmd->argv[1],strerror(errno));
    return ERROR(cmd);
  }

  /* We store the path in session.xfer.path */
  if(session.xfer.p) {
    destroy_pool(session.xfer.p);
    bzero(&session.xfer,sizeof(session.xfer));
  }

  session.xfer.p = make_sub_pool(session.pool);
  session.xfer.path = pstrdup(session.xfer.p,path);
  add_response(R_350,"File or directory exists, ready for destination name.");

  return HANDLED(cmd);
}

MODRET cmd_site(cmd_rec *cmd)
{
  char *cp;

  cmd->argc--;
  cmd->argv++;

  if(cmd->argc)
    for(cp = cmd->argv[0]; *cp; cp++)
      *cp = toupper(*cp);

  return call_module(&site_module,site_dispatch,cmd);
}

MODRET cmd_noop(cmd_rec *cmd)
{
  add_response(R_200,"NOOP command successful.");
  return HANDLED(cmd);
}

/* Configuration directive table */

conftable core_conftable[] = {
  { "ServerName",		set_servername, 		NULL },
  { "ServerIdent",		set_serverident,		NULL },
  { "ServerType",		set_servertype,			NULL },
  { "ServerAdmin",		set_serveradmin,		NULL },
  { "UseReverseDNS",		set_usereversedns,		NULL },
  { "ScoreboardPath",		set_scoreboardpath,		NULL },
  { "TransferLog",		add_transferlog,		NULL },
  { "WtmpLog",			set_wtmplog,			NULL },
  { "Bind",			add_bind,			NULL },
  { "Port",			set_serverport, 		NULL },
  { "SocketBindTight",		set_socketbindtight,		NULL },
  { "IdentLookups",		set_identlookups,		NULL },
  { "tcpBackLog",		set_tcpbacklog,			NULL },
  { "tcpReceiveWindow",		set_tcpreceivewindow,		NULL },
  { "tcpSendWindow",		set_tcpsendwindow,		NULL },
  { "DeferWelcome",		set_deferwelcome,		NULL },
  { "DefaultServer",		set_defaultserver,		NULL },
  { "MultilineRFC2228",		set_multilinerfc2228,		NULL },
  { "User",			set_user,			NULL },
  { "Group",			set_group, 			NULL },
  { "UserPassword",		add_userpassword,		NULL },
  { "GroupPassword",		add_grouppassword,		NULL },
  { "Umask",			set_umask,			NULL },
  { "MaxLoginAttempts",		set_maxloginattempts,		NULL },
  { "MaxClients",		set_maxclients,			NULL },
  { "MaxClientsPerHost",	set_maxhostclients,		NULL },
  { "MaxInstances",		set_maxinstances,		NULL },
  { "RequireValidShell",	set_requirevalidshell,		NULL },
  { "ShowSymlinks",		set_showsymlinks,		NULL },
  { "SyslogFacility",		set_syslogfacility,		NULL },
  { "TimeoutLogin",		set_timeoutlogin,		NULL },
  { "TimeoutIdle",		set_timeoutidle,		NULL },
  { "TimeoutNoTransfer",	set_timeoutnoxfer,		NULL },
  { "TimeoutStalled",		set_timeoutstalled,		NULL },
  { "UseFtpUsers",		set_useftpusers,		NULL },
  { "AccessGrantMsg",		set_accessgrantmsg,		NULL },
  { "AnonymousGroup",		add_anonymousgroup,		NULL },
  { "<VirtualHost>",		add_virtualhost,		NULL },
  { "</VirtualHost>",		end_virtualhost,		NULL },
  { "<Directory>",		add_directory,			NULL },
  { "CDPath",			add_cdpath,			NULL },
  { "HideNoAccess",		add_hidenoaccess,		NULL },
  { "HideUser",			add_hideuser,			NULL },
  { "HideGroup",		add_hidegroup,			NULL },
  { "GroupOwner",		add_groupowner,			NULL },
  { "AllowOverwrite",		set_allowoverwrite,		NULL },
  { "DisplayFirstChdir",	set_displayfirstchdir,		NULL },
  { "AuthAliasOnly",		set_authaliasonly,		NULL },
  { "AllowRetrieveRestart",	set_allowretrieverestart,	NULL },
  { "AllowStoreRestart",	set_allowstorerestart,		NULL },
  { "</Directory>",		end_directory,			NULL },
  { "<Limit>",			add_limit,			NULL },
  { "IgnoreHidden",		set_ignorehidden,		NULL },
  { "Order",			add_order,			NULL },
  { "Allow",			add_allow,			NULL },
  { "Deny",			add_deny,			NULL },
  { "AllowGroup",		add_allowgroup,			NULL },
  { "DenyGroup",		add_denygroup,			NULL },
  { "AllowUser",		add_allowuser,			NULL },
  { "DenyUser",			add_denyuser,			NULL },
  { "AllowAll",			set_allowall,			NULL },
  { "DenyAll",			set_denyall,			NULL },
  { "</Limit>", 		end_limit, 			NULL },
  { "DisplayLogin",		set_displaylogin,		NULL },
  { "DisplayConnect",	set_displayconnect,		NULL },
  { "<Anonymous>",		add_anonymous,			NULL },
  { "UserAlias",		add_useralias, 			NULL },
  { "AnonRequirePassword",	set_anonrequirepassword,	NULL },
  { "PathAllowFilter",		set_pathallowfilter,		NULL },
  { "PathDenyFilter",		set_pathdenyfilter,		NULL },
  { "AllowForeignAddress",	set_allowforeignaddress,	NULL },
  { "</Anonymous>",		end_anonymous,			NULL },
  { "<Global>",			add_global,			NULL },
  { "</Global>",		end_global,			NULL },
  { NULL, NULL, NULL }
};

cmdtable core_commands[] = {
  { CMD, C_HELP, G_NONE,  cmd_help,	FALSE,	FALSE, CL_INFO },
  { CMD, C_PORT, G_NONE,  cmd_port,	TRUE,	FALSE, CL_MISC },
  { CMD, C_PASV, G_NONE,  cmd_pasv,	TRUE,	FALSE, CL_MISC },
  { CMD, C_SYST, G_NONE,  cmd_syst,	TRUE,	FALSE, CL_INFO },
  { CMD, C_PWD,	 G_NONE,  cmd_pwd,	TRUE,	FALSE, CL_INFO|CL_DIRS },
  { CMD, C_XPWD, G_NONE,  cmd_pwd,	TRUE,	FALSE, CL_INFO|CL_DIRS },
  { CMD, C_CWD,	 G_DIRS,  cmd_cwd,	TRUE,	FALSE, CL_DIRS },
  { CMD, C_XCWD, G_DIRS,  cmd_cwd,	TRUE,	FALSE, CL_DIRS },
  { CMD, C_MKD,	 G_WRITE, cmd_mkd,	TRUE,	FALSE, CL_DIRS|CL_WRITE },
  { CMD, C_XMKD, G_WRITE, cmd_mkd,	TRUE,	FALSE, CL_DIRS|CL_WRITE },
  { CMD, C_RMD,	 G_WRITE, cmd_rmd,	TRUE,	FALSE, CL_DIRS|CL_WRITE },
  { CMD, C_XRMD, G_WRITE, cmd_rmd,	TRUE,	FALSE, CL_DIRS|CL_WRITE },
  { CMD, C_CDUP, G_DIRS,  cmd_cdup,	TRUE,	FALSE, CL_DIRS },
  { CMD, C_XCUP, G_DIRS,  cmd_cdup,	TRUE,	FALSE, CL_DIRS },
  { CMD, C_SITE, G_NONE,  cmd_site,	TRUE,	FALSE, CL_MISC },
  { CMD, C_DELE, G_WRITE, cmd_dele,	TRUE,	FALSE, CL_WRITE },
  { CMD, C_MDTM, G_DIRS,  cmd_mdtm,	TRUE,	FALSE, CL_INFO },
  { CMD, C_RNFR, G_DIRS,  cmd_rnfr,	TRUE,	FALSE, CL_MISC },
  { CMD, C_RNTO, G_WRITE, cmd_rnto,	TRUE,	FALSE, CL_MISC },
  { CMD, C_SIZE, G_READ,  cmd_size,	TRUE,	FALSE, CL_INFO },
  { CMD, C_QUIT, G_NONE,  cmd_quit,	FALSE,	TRUE,  CL_INFO },
  { CMD, C_NOOP, G_NONE,  cmd_noop,	FALSE,	TRUE,  CL_MISC },
  { 0, NULL }
};

/* Module interface */

module core_module = {
  NULL,NULL,			/* always NULL */
  0x20,				/* API Version 2.0 */
  "core",
  core_conftable,
  core_commands,
  NULL,
  NULL,NULL			/* No initialization needed */
};
