/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
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
 * "SITE" commands module for ProFTPD
 * $Id: mod_site.c,v 1.18 2002-09-06 01:06:12 castaglia Exp $
 */

#include "conf.h"
#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

/* From mod_core.c */
extern int core_chmod(cmd_rec *cmd, char *dir, mode_t mode);
extern int core_chgrp(cmd_rec *cmd, char *dir, uid_t uid, gid_t gid);

static struct {
  char *cmd;
  char *syntax;
  int implemented;
} _help[] = {
  { "HELP",	"[<sp> site-command]",			TRUE },
  { "CHGRP",	"<sp> group <sp> pathname",		TRUE },
  { "CHMOD",	"<sp> mode <sp> pathname",		TRUE },
  { NULL,	NULL,					FALSE }
};

static char *_get_full_cmd(cmd_rec *cmd)
{
  char *res = "";
  int i;

  for(i = 0; i < cmd->argc; i++)
    res = pstrcat(cmd->tmp_pool,res,cmd->argv[i]," ",NULL);

  while(res[strlen(res)-1] == ' ')
    res[strlen(res)-1] = '\0';

  return res;
}

MODRET site_chgrp(cmd_rec *cmd) {
  gid_t gid;
  char *path = NULL;

#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  regex_t *preg;
#endif

  if (cmd->argc != 3) {
    add_response_err(R_500,"'SITE %s' not understood.", _get_full_cmd(cmd));
    return NULL;
  }

#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  preg = (regex_t *) get_param_ptr(TOPLEVEL_CONF, "PathAllowFilter", FALSE);

  if (preg && regexec(preg, cmd->argv[2], 0, NULL, 0) != 0) {
    log_debug(DEBUG2, "'%s %s' denied by PathAllowFilter", cmd->argv[0],
      cmd->arg);
    add_response_err(R_550, "%s: Forbidden filename", cmd->argv[2]);
    return ERROR(cmd);
  }

  preg = (regex_t *) get_param_ptr(TOPLEVEL_CONF, "PathDenyFilter", FALSE);

  if (preg && regexec(preg, cmd->argv[2], 0, NULL, 0) == 0) {
    log_debug(DEBUG2, "'%s %s' denied by PathDenyFilter", cmd->argv[0],
      cmd->arg);
    add_response_err(R_550, "%s: Forbidden filename", cmd->argv[2]);
    return ERROR(cmd);
  }
#endif

  path = dir_realpath(cmd->tmp_pool, cmd->argv[2]);

  if (!path) {
    add_response_err(R_550, "%s: %s", cmd->argv[2], strerror(errno));
    return ERROR(cmd);
  }

  /* Map the given group argument, if a string, to a GID.  If already a
   * number, pass through as is.
   */
  if (sscanf(cmd->argv[1], "%u", &gid) != 1) {
    if ((gid = auth_name_gid(cmd->tmp_pool, cmd->argv[1])) == -1) {
      add_response_err(R_550, "%s: %s", cmd->argv[2], strerror(EINVAL));
      return ERROR(cmd);
    }
  }

  if (core_chgrp(cmd, path, (uid_t) -1, gid) == -1) {
    add_response_err(R_550, "%s: %s", cmd->argv[2], strerror(errno));
    return ERROR(cmd);

  } else
    add_response(R_200, "SITE %s command successful.", cmd->argv[0]);

  return HANDLED(cmd);
}

MODRET site_chmod(cmd_rec *cmd) {
  mode_t mode = 0;
  char *dir,*endp,*tmp;
#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  regex_t *preg;
#endif

  if(cmd->argc != 3) {
    add_response_err(R_500,"'SITE %s' not understood.",_get_full_cmd(cmd));
    return NULL;
  }

#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  preg = (regex_t*)get_param_ptr(TOPLEVEL_CONF,"PathAllowFilter",FALSE);

  if(preg && regexec(preg,cmd->argv[2],0,NULL,0) != 0) {
    log_debug(DEBUG2, "'%s %s %s' denied by PathAllowFilter", cmd->argv[0],
      cmd->argv[1], cmd->argv[2]);
    add_response_err(R_550,"%s: Forbidden filename",cmd->argv[2]);
    return ERROR(cmd);
  }

  preg = (regex_t*)get_param_ptr(TOPLEVEL_CONF,"PathDenyFilter",FALSE);

  if(preg && regexec(preg,cmd->argv[2],0,NULL,0) == 0) {
    log_debug(DEBUG2, "'%s %s %s' denied by PathDenyFilter", cmd->argv[0],
      cmd->argv[1], cmd->argv[2]);
    add_response_err(R_550,"%s: Forbidden filename",cmd->argv[2]);
    return ERROR(cmd);
  }
#endif

  dir = dir_realpath(cmd->tmp_pool,cmd->argv[2]);

  if(!dir) {
    add_response_err(R_550,"%s: %s",cmd->argv[2],strerror(errno));
    return ERROR(cmd);
  }

  /* If the first character isn't '0', prepend it and attempt conversion.
   * This will fail if the chmod is a symbolic, but takes care of the
   * case where an octal number is sent without the leading '0'.
   */

  if(cmd->argv[1][0] != '0')
    tmp = pstrcat(cmd->tmp_pool,"0",cmd->argv[1],NULL);
  else
    tmp = cmd->argv[1];

  mode = strtol(tmp,&endp,0);
  if(endp && *endp) {
    /* It's not an absolute number, try symbolic */
    char *cp = cmd->argv[1];
    int mask = 0,mode_op = 0,curmode = 0,curumask = umask(0);
    int invalid = 0; 
    char *who,*how,*what,*tmp;
    struct stat sbuf;

    umask(curumask);
    mode = 0; 

    if(stat(dir,&sbuf) != -1)
      curmode = sbuf.st_mode;

    while(1) {
      who = pstrdup(cmd->tmp_pool,cp);
      if((tmp = strpbrk(who,"+-=")) != NULL) {
        how = pstrdup(cmd->tmp_pool,tmp);
        if(*how != '=')
          mode = curmode;

        *tmp = '\0';
      } else {
        invalid++;
        break;
      }

      if((tmp = strpbrk(how,"rwxXstugo")) != NULL) {
        what = pstrdup(cmd->tmp_pool,tmp);
        *tmp = '\0';
      } else {
        invalid++;
        break;
      }

      cp = what;
      while(cp) {
        switch(*who) {
        case 'u':
          mask = 0077;
          break;
        case 'g':
          mask = 0707;
          break;
        case 'o':
          mask = 0770;
          break;
        case 'a':
          mask = 0000;
          break;
        case '\0':
          mask = curumask;
          break;
        default:
          invalid++;
          break;
        }

        if(invalid) break;

        switch(*how) {
        case '+':
        case '-':
        case '=':
          break;
        default:
          invalid++;
        }

        if(invalid) break;

        switch(*cp) {
        case 'r':
          mode_op |= (S_IRUSR|S_IRGRP|S_IROTH);
          break;
        case 'w':
          mode_op |= (S_IWUSR|S_IWGRP|S_IWOTH);
          break;
        case 'x':
          mode_op |= (S_IXUSR|S_IXGRP|S_IXOTH);
          break;
        /* 'X' not implemented */
        case 's':
	  /* setuid */
          mode_op |= S_ISUID;
          break;
        case 't':
          /* sticky */
          mode_op |= S_ISVTX;
          break;
        case 'o':
          mode_op |= curmode & S_IRWXO;
          mode_op |= (curmode & S_IRWXO) << 3;
          mode_op |= (curmode & S_IRWXO) << 6;
          break;
        case 'g':
          mode_op |= (curmode & S_IRWXG) >> 3;
          mode_op |= curmode & S_IRWXG;
          mode_op |= (curmode & S_IRWXG) << 3;
          break;
        case 'u':
          mode_op |= (curmode & S_IRWXO) >> 6;
          mode_op |= (curmode & S_IRWXO) >> 3;
          mode_op |= curmode & S_IRWXU;
          break;
        case '\0':
          /* Apply the mode and move on */
          switch(*how) {
          case '+':
          case '=':
            mode |= (mode_op & ~mask);
            break;
          case '-':
            mode &= ~(mode_op & ~mask);
            break;
          }

          mode_op = 0;
          if(*who && *(who+1)) {
            who++;
            cp = what;
            continue;
          } else
            cp = NULL;
          break;
        default:
          invalid++;
        }

        if(invalid) break;
        if(cp) cp++;
      }
      break;
    }

    if(invalid) {
      add_response_err(R_550,"'%s': invalid mode.",cmd->argv[1]);
      return ERROR(cmd);
    }
  }

  if(core_chmod(cmd,dir,mode) == -1) {
    add_response_err(R_550,"%s: %s",cmd->argv[2],strerror(errno));
    return ERROR(cmd);
  } else
    add_response(R_200,"SITE %s command successful.",cmd->argv[0]);

  return HANDLED(cmd);
}

MODRET site_help(cmd_rec *cmd)
{
  int i,c = 0;
  char buf[9] = {'\0'};

  if(cmd->argc == 1 || (cmd->argc == 2 && !strcasecmp(cmd->argv[1],"SITE"))) {
    char *outa[8];
    char *outs = "";

    memset(outa, '\0', sizeof(outa));

    add_response(R_214,
    "The following SITE commands are recognized (* =>'s unimplemented).");
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
            snprintf(buf, sizeof(buf), "%-8s",outa[j]);
            outs = pstrcat(cmd->tmp_pool,outs,buf,NULL);
          } else
            break;
        }	

        if(*outs)
          add_response(R_214,"%s",outs);
        outs = "";
        c = 0;

        memset(outa, '\0', sizeof(outa));
      }
    }

    add_response(R_214,"Direct comments to %s.",
                         (cmd->server->ServerAdmin ? cmd->server->ServerAdmin :
                          "ftp-admin"));
  } else {
    char *cp;

    for(cp = cmd->argv[1]; *cp; cp++)
      *cp = toupper(*cp);

    for(i = 0; _help[i].cmd; i++)
      if(!strcasecmp(cmd->argv[1], _help[i].cmd)) {
        add_response(R_214, "Syntax: SITE %s %s", cmd->argv[1],
		     _help[i].syntax);
        return HANDLED(cmd);
      }

    add_response_err(R_502, "Unknown command 'SITE %s'.", cmd->arg);
    return ERROR(cmd);
  }

  return HANDLED(cmd);
}

/* The site_commands table is local only, and not registered with our
 * module.
 */

static cmdtable site_commands[] = {
  { CMD, "HELP",	G_NONE,		site_help,	FALSE, FALSE },
  { CMD, "CHGRP",	G_NONE,		site_chgrp,	FALSE, FALSE },
  { CMD, "CHMOD",	G_NONE,		site_chmod,	FALSE, FALSE },
  { 0, NULL }
};

modret_t *site_dispatch(cmd_rec *cmd)
{
  int i;

  if (!cmd->argc) {
    add_response_err(R_500,"'SITE' requires argument.");
    return ERROR(cmd);
  }

  for(i = 0; site_commands[i].command; i++)
    if(!strcmp(cmd->argv[0],site_commands[i].command))
      return site_commands[i].handler(cmd);

  add_response_err(R_500,"'SITE %s' not understood.",cmd->argv[0]);
  return ERROR(cmd);
}

/* Configuration directives table */

static conftable site_conftab[] = {
  { NULL, 		NULL,			NULL }
};

/* Module interface */

module site_module = {
  NULL,NULL,			/* Always NULL */
  0x20,				/* API Version 1.0 */
  "site",
  site_conftab,
  NULL,
  NULL,
  NULL,
  NULL
};
