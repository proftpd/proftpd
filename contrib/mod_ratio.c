/*
 * ProFTPD: mod_ratio -- Support upload/download ratios.
 * Time-stamp: <1998-09-10 13:21:41 root>
 * Copyright (c) 1998 Johnie Ingram.
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

/* This is mod_ratio 1.0, contrib software for proftpd 1.1.6 and above.
   For more information contact Johnie Ingram <johnie@netgod.net>.

   To install, copy this file into modules/ and do:

      ./configure --with-modules=mod_ratio

   This module is inactive unless configured, which can be done with
   an Anonymous, Directory, or VirtualHost block in proftpd.conf, or
   with a .ftpaccess file.  (Ratios must be turned on elsewhere for a
   directive in .ftpaccess to take effect.)

   The ratio directives take four numbers: file ratio, initial file
   credit, byte ratio, and initial byte credit.  Setting either ratio
   to 0 disables that check.
      
   The directives are HostRatio (matches FQDN -- wildcards are allowed
   in this one), AnonRatio (matches password entered in an anon login,
   usually an email address), UserRatio (accepts "*" for 'any user'),
   and GroupRatio.  Matches are looked for in that order.

   Some examples:

     Ratios on                                    # enable module
     UserRatio ftp 0 0 0 0
     HostRatio master.debian.org 0 0 0 0          # leech access (default)
     GroupRatio proftpd 100 10 5 100000           # 100:1 files, 10 file cred
                                                    5:1 bytes, 100k byte cred
     AnonRatio billg@microsoft.com 1 0 1 0        # 1:1 ratio, no credits
     UserRatio * 5 5 5 50000                      # special default case

   Setting "Ratios on" without configuring anything else will enable
   leech mode: it logs activity and sends status messages to the ftp
   client, but doesn't restrict traffic.

   Ratio module activity is recorded to syslog at DEBUG0; it usually
   shows up in /var/log/debug, like this:

     localhost: -1/82788 +0/0 5/5 4/17212: /art/nudes/young CWD carla

   This example is for someone who (1) has downloaded 1 file of 82k,
   (2) has uploaded nothing, (3) has a ratio of 5:1 files and 5:1
   bytes, (4) has 4 files and 17k credit remaining, and (5) is now
   changing directory to /art/nudes/young/carla.  The initial credit,
   not shown, was 5 files and 100k (UserRatio * 5 5 5 100000).

   Similar information is available with the XRATIO ftp command, which
   returns debugging info like this:

     200 localhost: -(1 82788) +(0 0) [5+5 5+100000] 4F 17212B

   Note that if this module is turned on globally, any user can create
   a personal ratio area with a .ftpaccess file.  One way to prevent
   this is with: PathDenyFilter "\.ftpaccess$"

   If you have ideas on how to improve this module, please contact
   Johnie Ingram <johnie@netgod.net>.

*/

#include "conf.h"

static struct {
  int ratios;

  unsigned int bytes;
  unsigned int b_credit;
  unsigned int files;
  unsigned int f_credit;

  size_t b_stor;
  size_t b_retr;
  unsigned int f_stor;
  unsigned int f_retr;

} ratio;


#define RATIO_SHOW (ratio.ratios > 0)
#define FILE_ENFORCE (RATIO_SHOW && ratio.files)
#define BYTE_ENFORCE (RATIO_SHOW && ratio.bytes)
#define RATIO_ENFORCE (RATIO_SHOW && (ratio.bytes + ratio.files))
#define FILES_ALLOWED (int)((ratio.files * ratio.f_stor) + ratio.f_credit - ratio.f_retr)
#define BYTES_ALLOWED (int)((ratio.bytes * ratio.b_stor) + ratio.b_credit - ratio.b_retr)
#define RATIO_SHORT "%s: -%i/%i +%i/%i %i/%i %i/%i%s%s", \
	    session.c->remote_name, ratio.f_retr, ratio.b_retr, ratio.f_stor, \
	    ratio.b_stor, ratio.files, ratio.bytes, FILES_ALLOWED, BYTES_ALLOWED, \
	    (FILE_ENFORCE && FILES_ALLOWED < 1) ? " [F]" : "", \
	    (BYTE_ENFORCE && BYTES_ALLOWED < 1) ? " [B]" : ""
#define RATIO_LONG "%s: -(%i %i) +(%i %i) [%i+%i %i+%i] %iF %iB%s%s", \
	    session.c->remote_name, ratio.f_retr, ratio.b_retr, ratio.f_stor, \
	    ratio.b_stor, ratio.files, ratio.f_credit, ratio.bytes, \
	    ratio.b_credit, FILES_ALLOWED, BYTES_ALLOWED, \
	    (FILE_ENFORCE && FILES_ALLOWED < 1) ? " [FILE LIMIT]" : "", \
	    (BYTE_ENFORCE && BYTES_ALLOWED < 1) ? " [BYTE LIMIT]" : ""

static void
log_ratio(cmd_rec *cmd)
{
  char sbuf[1023];
  sprintf (sbuf, RATIO_SHORT);
  log_debug(DEBUG0, "%s: %s %s %s",
	    sbuf, session.cwd, cmd->argv[0], cmd->arg);
}

static void
add_ratio_response (cmd_rec *cmd)
{
  char sbuf1[128];
  char sbuf2[128];
  char sbuf3[128];
  sbuf1[0] = sbuf2[0] = sbuf3[0] = 0;
  sprintf(sbuf1,
	  "Sent: %i (%iB)  Got: %i (%iB)",
	  ratio.f_retr, ratio.b_retr, ratio.f_stor, ratio.b_stor);
  if (FILE_ENFORCE)
    sprintf(sbuf2,"  [%i:1F] CR: %iF", ratio.files, FILES_ALLOWED);
  if (BYTE_ENFORCE)
    sprintf(sbuf3,"  [%i:1B] CR: %iB", ratio.bytes, BYTES_ALLOWED);
  if (! RATIO_ENFORCE)
    add_response(R_DUP, "%s  [10,000,000:1]  CR: LEECH", sbuf1);
  else
    add_response(R_DUP, "%s%s%s", sbuf1, sbuf2, sbuf3);
}

static void
set_ratios(char *a, char *b, char *c, char *d)
{
  ratio.files = ratio.f_credit = ratio.bytes = ratio.b_credit = 0;
  if (a) ratio.files = atoi(a);
  if (b) ratio.f_credit = atoi(b);
  if (c) ratio.bytes = atoi(c);
  if (d) ratio.b_credit = atoi(d);
}

MODRET calculate_ratios(cmd_rec *cmd)
{
  config_rec *cfg;
  char buf[1024];
  char *mask;
  ratio.ratios = get_param_int(CURRENT_CONF,"Ratios",FALSE);
  if (!ratio.ratios || !cmd || !cmd->server || !cmd->server->conf)
    return DECLINED(cmd);

  cfg = find_config(cmd->server->conf,CONF_PARAM, "HostRatio",TRUE);
  while(cfg) {
    mask = buf;
    if(*(char *)cfg->argv[0] == '.') {
      *mask++ = '*';
      strncpy(mask,cfg->argv[0],sizeof(buf)-2);
    }
    else if(*(char *)(cfg->argv[0] + (strlen(cfg->argv[0]) -1)) == '.') {
      strncpy(mask,cfg->argv[0],sizeof(buf)-2);
        buf[1023] = '\0';
        strcpy(&buf[strlen(buf)-1],"*");
    } else
      strncpy(mask,cfg->argv[0],sizeof(buf)-1);
    buf[1023] = '\0';
    if(!fnmatch(buf,session.c->remote_name,FNM_NOESCAPE) ||
       !fnmatch(buf,inet_ntoa(*session.c->remote_ipaddr),FNM_NOESCAPE)) {
      set_ratios (cfg->argv[1], cfg->argv[2], cfg->argv[3], cfg->argv[4]);
      return DECLINED(cmd);
    }
    cfg = find_config_next(cfg,cfg->next,CONF_PARAM,"HostRatio",FALSE);
  }
  cfg = find_config(cmd->server->conf,CONF_PARAM, "AnonRatio",TRUE);
  while(cfg) {
    if(session.anon_user && !strcmp(cfg->argv[0],session.anon_user)) {
      set_ratios (cfg->argv[1], cfg->argv[2], cfg->argv[3], cfg->argv[4]);
      return DECLINED(cmd);
    }
    cfg = find_config_next(cfg,cfg->next,CONF_PARAM,"AnonRatio",FALSE);
  }
  cfg = find_config(cmd->server->conf,CONF_PARAM, "UserRatio",TRUE);
  while(cfg) {
    if(* (char *) cfg->argv[0] == '*'
       || !strcmp(cfg->argv[0],session.user)) {
      set_ratios (cfg->argv[1], cfg->argv[2], cfg->argv[3], cfg->argv[4]);
      return DECLINED(cmd);
    }
    cfg = find_config_next(cfg,cfg->next,CONF_PARAM,"UserRatio",FALSE);
  }
  cfg = find_config(cmd->server->conf,CONF_PARAM, "GroupRatio",TRUE);
  while(cfg) {
    if(!strcmp(cfg->argv[0],session.group)) {
      set_ratios (cfg->argv[1], cfg->argv[2], cfg->argv[3], cfg->argv[4]);
      return DECLINED(cmd);
    }
    cfg = find_config_next(cfg,cfg->next,CONF_PARAM,"GroupRatio",FALSE);
  }
  return DECLINED(cmd);
}

MODRET cmd_xratio(cmd_rec *cmd)
{
  add_response(R_200, RATIO_LONG);
  return HANDLED(cmd);
}

MODRET pre_cmd(cmd_rec *cmd)
{
  return calculate_ratios(cmd);
}

MODRET pre_cmd_log(cmd_rec *cmd)
{
  calculate_ratios(cmd);
  if (! RATIO_SHOW)
    return DECLINED(cmd);
  log_ratio(cmd);
  return DECLINED(cmd);
}

MODRET post_cmd(cmd_rec *cmd)
{
  if (! RATIO_SHOW)
    return DECLINED(cmd);
  add_ratio_response(cmd);
  return DECLINED(cmd);
}

MODRET post_cmd_log(cmd_rec *cmd)
{
  if (! RATIO_SHOW)
    return DECLINED(cmd);
  add_ratio_response(cmd);
  log_ratio(cmd);
  return DECLINED(cmd);
}

MODRET pre_cmd_retr(cmd_rec *cmd)
{
  char *path;
  int fsize = 0;
  struct stat sbuf;

  calculate_ratios(cmd);
  if (! RATIO_SHOW)
    return DECLINED(cmd);
  log_ratio(cmd);
  if (! RATIO_ENFORCE)
    return DECLINED(cmd);
  if (FILE_ENFORCE && FILES_ALLOWED < 1)
    {
      add_response_err(R_550, "%s: File Ratio: [%i:1F]  Sent: %i  Got: %i",
		       cmd->arg, ratio.files, ratio.f_retr, ratio.f_stor);
      add_response_err(R_550,
	      "Too few files uploaded to earn file -- please upload more.");
      return ERROR(cmd);
    }
  path = dir_realpath(cmd->tmp_pool,cmd->arg);
  if(path && dir_check(cmd->tmp_pool,cmd->argv[0],cmd->group,path,NULL) &&
     fs_stat(path,&sbuf) > -1)
    fsize = sbuf.st_size;
  if (BYTE_ENFORCE && (BYTES_ALLOWED - fsize) <= -1)
    {
      add_response_err(R_550, "%s: Byte Ratio: [%i:1B]  Sent: %i  Got: %i",
		       cmd->arg, ratio.bytes, ratio.b_retr, ratio.b_stor);
      add_response_err(R_550,
		       "Too few bytes uploaded to earn file (%iB) -- please upload more.",
		       fsize);
      return ERROR(cmd);
    }
  return DECLINED(cmd);
}

MODRET post_cmd_retr(cmd_rec *cmd)
{
  ratio.f_retr++;
  ratio.b_retr += session.xfer.total_bytes;
  if (! RATIO_SHOW)
    return DECLINED(cmd);
  add_ratio_response(cmd);
  return DECLINED(cmd);
}

MODRET post_cmd_stor(cmd_rec *cmd)
{
  ratio.f_stor++;
  ratio.b_stor += session.xfer.total_bytes;
  if (! RATIO_SHOW)
    return DECLINED(cmd);
  add_ratio_response(cmd);
  log_ratio(cmd);
  return DECLINED(cmd);
}

MODRET log_cmd_pass(cmd_rec *cmd)
{
  log_pri(LOG_NOTICE, "FTP session opened: %s/%s %s[%s] %s",
	    session.user, session.group,
	    session.c->remote_name, inet_ntoa(*session.c->remote_ipaddr),
	    session.anon_user ? session.anon_user : "");
  return DECLINED(cmd);
}

MODRET _add_ratiocmd(cmd_rec *cmd, char *directive)
{
 config_rec *c;
 CHECK_ARGS(cmd,5);
 CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_DIR|CONF_DYNDIR|CONF_GLOBAL);
 c = add_config_param_str(directive,5,
                         (void*)cmd->argv[1],(void*)cmd->argv[2],
                         (void*)cmd->argv[3],(void*)cmd->argv[4],
                         (void*)cmd->argv[5]);
 c->flags |= CF_MERGEDOWN;
 return HANDLED(cmd);
}

MODRET add_userratio(cmd_rec *cmd)
{
  return _add_ratiocmd(cmd, "UserRatio");
}

MODRET add_groupratio(cmd_rec *cmd)
{
  return _add_ratiocmd(cmd, "GroupRatio");
}

MODRET add_anonratio(cmd_rec *cmd)
{
  return _add_ratiocmd(cmd, "AnonRatio");
}

MODRET add_hostratio(cmd_rec *cmd)
{
  return _add_ratiocmd(cmd, "HostRatio");
}

MODRET add_ratios(cmd_rec *cmd)
{
  int b;
  config_rec *c;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_DIR|CONF_GLOBAL);
  b = get_boolean(cmd,1);
  if(b == -1)
    CONF_ERROR(cmd, "requires a boolean value");
  c = add_config_param("Ratios",1,(void*)b);
  c->flags |= CF_MERGEDOWN;
  return HANDLED(cmd);
}

conftable ratio_config[] = {
  { "Ratios",	        add_ratios,                    },
  { "UserRatio",	add_userratio,                 },
  { "GroupRatio",	add_groupratio,                },
  { "AnonRatio",	add_anonratio,                 },
  { "HostRatio",	add_hostratio,                 },
  { NULL }
};

static int ratio_child_init()
{
  memset (&ratio, 0, sizeof (ratio));
  return 0;
}

cmdtable ratio_commands[] = {
  { LOG_CMD,  C_PASS,	G_NONE, log_cmd_pass, 	FALSE, FALSE },

  { PRE_CMD,  C_CWD,	G_NONE, pre_cmd_log, 	FALSE, FALSE },
  { PRE_CMD,  C_STOR,	G_NONE, pre_cmd, 	FALSE, FALSE },
  { PRE_CMD,  C_APPE,	G_NONE, pre_cmd,	FALSE, FALSE },
  { PRE_CMD,  C_PORT,	G_NONE, pre_cmd, 	FALSE, FALSE },
  { PRE_CMD,  C_LIST,	G_NONE, pre_cmd, 	FALSE, FALSE },
  { PRE_CMD,  C_NLST,	G_NONE, pre_cmd, 	FALSE, FALSE },

  { POST_CMD, C_LIST,	G_NONE, post_cmd_log, 	FALSE, FALSE },
  { POST_CMD, C_NLST,	G_NONE, post_cmd_log, 	FALSE, FALSE },
  { POST_CMD, C_NOOP,	G_NONE, post_cmd, 	FALSE, FALSE },
  { POST_CMD, C_CWD,	G_NONE, post_cmd, 	FALSE, FALSE },

  { PRE_CMD,  C_RETR,   G_NONE, pre_cmd_retr,	FALSE, FALSE },
  { POST_CMD, C_RETR,   G_NONE, post_cmd_retr,	FALSE, FALSE },
  { POST_CMD, C_STOR,	G_NONE, post_cmd_stor,	FALSE, FALSE },
  { POST_CMD, C_APPE,   G_NONE, post_cmd_stor,  FALSE, FALSE },

  { CMD,      "XRATIO",	G_NONE, cmd_xratio, 	FALSE, FALSE },
  { 0,	      NULL }
};

module ratio_module = {
  NULL,NULL,			/* Always NULL */
  0x20,				/* API Version 2.0 */
  "ratio",
  ratio_config,	        	/* No configuration table */
  ratio_commands,		/* Our command table is for local use only */
  NULL,				/* No authentication handlers */
  NULL, 			/* Initialization function */
  ratio_child_init		/* Post-fork "child mode" init */
};

