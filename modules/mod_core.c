/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001, 2002, 2003 The ProFTPD Project team
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

/* Core FTPD module
 * $Id: mod_core.c,v 1.160 2003-03-09 02:24:05 castaglia Exp $
 */

#include "conf.h"
#include "privs.h"

#include <ctype.h>
#include <sys/resource.h>

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
  { C_TYPE, "<sp> type-code (A, I, L 7, L 8)",	TRUE },
  { C_STRU, "is not implemented (always F)",	TRUE },
  { C_MODE, "is not implemented (always S)",	TRUE },
  { C_RETR, "<sp> pathname",			TRUE },
  { C_STOR, "<sp> pathname",			TRUE },
  { C_STOU, "(store unique filename)",		TRUE },
  { C_APPE, "<sp> pathname",			TRUE },
  { C_ALLO, "is not implemented (ignored)",	FALSE },
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
  { C_SITE, "<sp> string",			TRUE },
  { C_SYST, "(returns system type)",		TRUE },
  { C_STAT, "[<sp> pathname]",			TRUE },
  { C_HELP, "[<sp> command]",			TRUE },
  { C_NOOP, "(no operation)",			TRUE },
  { C_FEAT, "(returns feature list)",		TRUE },
  { C_OPTS, "<sp> command [<sp> options]",	TRUE },
  { C_ADAT, "<sp> mechanism-name",		FALSE },
  { C_AUTH, "<sp> base64-data",			FALSE },
  { C_CCC,  "(clears protection level)",	FALSE },
  { C_CONF, "<sp> base64-data",			FALSE },
  { C_ENC,  "<sp> base64-data",			FALSE },
  { C_MIC,  "<sp> base64-data",			FALSE },
  { C_PBSZ, "<sp> protection buffer size",	FALSE },
  { C_PROT, "<sp> protection code",		FALSE },
  { NULL,   NULL,          			FALSE }
};

extern module site_module;
extern xaset_t *server_list;

/* from src/main.c */
extern unsigned long max_connects;
extern unsigned int max_connect_interval;

/* from mod_site */
extern modret_t *site_dispatch(cmd_rec*);

/* from dirtree.c */
extern array_header *server_defines;

/* for bytes-retrieving directives */
#define PR_BYTES_BAD_UNITS	-1
#define PR_BYTES_BAD_FORMAT	-2

static ssize_t get_num_bytes(char *nbytes_str) {
  ssize_t nbytes = 0;
  unsigned long inb;
  char units, junk;
  int result;

  /* Scan in the given argument, checking for the leading number-of-bytes
   * as well as a trailing G, M, K, or B (case-insensitive).  The junk
   * variable is catch arguments like "2g2" or "number-letter-whatever".
   *
   * NOTE: There is no portable way to scan in an ssize_t, so we do unsigned
   * long and cast it.  This probably places a 32-bit limit on rlimit values.
   */
  if ((result = sscanf(nbytes_str, "%lu%c%c", &inb, &units, &junk)) == 2) {

    if (units != 'G' && units != 'g' &&
        units != 'M' && units != 'm' &&
        units != 'K' && units != 'k' &&
        units != 'B' && units != 'b')
      return PR_BYTES_BAD_UNITS;

    nbytes = (ssize_t)inb;

    /* Calculate the actual bytes, multiplying by the given units.  Doing
     * it this way means that <math.h> and -lm aren't required.
     */
    if (units == 'G' || units == 'g')
      nbytes *= (1024 * 1024 * 1024);

    if (units == 'M' || units == 'm')
      nbytes *= (1024 * 1024);

    if (units == 'K' || units == 'k')
      nbytes *= 1024;

    /* Silently ignore units of 'B' and 'b', as they don't affect
     * the requested number of bytes anyway.
     */

    /* NB: should we check for a maximum numeric value of calculated bytes?
     *  Probably not, as it varies (int to rlim_t) from platform to
     *  platform)...at least, not yet.
     */
    return nbytes;

  } else if (result == 1) {

    /* No units given.  Return the number of bytes as is. */
    return (ssize_t) inb;
  }

  /* Default return value: the given argument was badly formatted.
   */
  return PR_BYTES_BAD_FORMAT;
}

MODRET start_ifdefine(cmd_rec *cmd) {
  unsigned int ifdefine_ctx_count = 1;
  unsigned char not_define = FALSE, defined = FALSE;
  char buf[PR_TUNABLE_BUFFER_SIZE] = {'\0'}, *config_line = NULL;

  CHECK_ARGS(cmd, 1);

  if (*(cmd->argv[1]) == '!') {
    not_define = TRUE;
    (cmd->argv[1])++;
  }

  defined = define_exists(cmd->argv[1]);

  /* Return now if we don't need to consume the <IfDefine> section
   * configuration lines.
   */
  if ((!not_define && defined) || (not_define && !defined)) {
    log_debug(DEBUG3, "%s: found '%s' definition", cmd->argv[0], cmd->argv[1]);
    return HANDLED(cmd);

  } else
    log_debug(DEBUG3, "%s: skipping '%s' section", cmd->argv[0], cmd->argv[1]);

  /* Rather than communicating with parse_config_file() via some global
   * variable/flag the need to skip configuration lines, if the requested
   * module condition is not TRUE, read in the lines here (effectively
   * preventing them from being parsed) up to and including the closing
   * directive.
   */
  while (ifdefine_ctx_count && (config_line = get_config_line(buf,
      sizeof(buf))) != NULL) {

    if (!strncmp(config_line, "<IfDefine", 9))
      ifdefine_ctx_count++;

    if (!strcmp(config_line, "</IfDefine>"))
      ifdefine_ctx_count--;
  }

  /* If there are still unclosed <IfDefine> sections, signal an error.
   */
  if (ifdefine_ctx_count)
    CONF_ERROR(cmd, "unclosed <IfDefine> context");

  return HANDLED(cmd);
}

/* As with Apache, there is no way of cleanly checking whether an
 * <IfDefine> section is properly closed.  Extra </IfDefine> directives
 * will be silently ignored.
 */
MODRET end_ifdefine(cmd_rec *cmd) {
  return HANDLED(cmd);
}

MODRET start_ifmodule(cmd_rec *cmd) {
  unsigned int ifmodule_ctx_count = 1;
  unsigned char not_module = FALSE, found_module = FALSE;
  char buf[PR_TUNABLE_BUFFER_SIZE] = {'\0'}, *config_line = NULL;

  CHECK_ARGS(cmd, 1);

  if (*(cmd->argv[1]) == '!') {
    not_module = TRUE;
    (cmd->argv[1])++;
  }

  found_module = module_exists(cmd->argv[1]);

  /* Return now if we don't need to consume the <IfModule> section
   * configuration lines.
   */
  if ((!not_module && found_module) || (not_module && !found_module)) {
    log_debug(DEBUG3, "%s: found '%s' module", cmd->argv[0], cmd->argv[1]);
    return HANDLED(cmd);

  } else
    log_debug(DEBUG3, "%s: skipping '%s' section", cmd->argv[0], cmd->argv[1]);

  /* Rather than communicating with parse_config_file() via some global
   * variable/flag the need to skip configuration lines, if the requested
   * module condition is not TRUE, read in the lines here (effectively
   * preventing them from being parsed) up to and including the closing
   * directive.
   */
  while (ifmodule_ctx_count && (config_line = get_config_line(buf,
      sizeof(buf))) != NULL) {

    if (!strncmp(config_line, "<IfModule", 9))
      ifmodule_ctx_count++;

    if (!strcmp(config_line, "</IfModule>"))
      ifmodule_ctx_count--;
  }

  /* If there are still unclosed <IfModule> sections, signal an error.
   */
  if (ifmodule_ctx_count)
    CONF_ERROR(cmd, "unclosed <IfModule> context");

  return HANDLED(cmd);
}

/* As with Apache, there is no way of cleanly checking whether an
 * <IfModule> section is properly closed.  Extra </IfModule> directives
 * will be silently ignored.
 */
MODRET end_ifmodule(cmd_rec *cmd) {
  return HANDLED(cmd);
}

/* Syntax: Define parameter
 *
 * Configuration file equivalent of the -D command-line option for
 * specifying an <IfDefine> value.
 *
 * It is suggested the RLimitMemory (a good idea to use anyway) be
 * used if this directive is present, to prevent Defines was being
 * used by a malicious local user in a .ftpaccess file.
 */
MODRET set_define(cmd_rec *cmd) {

  /* Make sure there's at least one parameter; any others are ignored */
  CHECK_ARGS(cmd, 1);

  /* This directive can occur in any context, so no need for the
   * CHECK_CONF macro.
   */

  /* If this is the first such definition, allocate an array_header
   * for the definitions.  Note that this uses the permanent_pool
   * rather than the containing server's pool so that defined parameters
   * are properly globally visible.
   */
  if (!server_defines)
    server_defines = make_array(permanent_pool, 0, sizeof(char *));

  *((char **) push_array(server_defines)) = pstrdup(permanent_pool,
    cmd->argv[1]);

  return HANDLED(cmd);
}

MODRET add_include(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL|CONF_DIR);

  /* make sure the given path is a full path, not a relative one */
  if (*(cmd->argv[1]) != '/') {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
      "Unable to use relative path for configuration file '",
      cmd->argv[1], "'.", NULL));
  }

  if (parse_config_file(cmd->argv[1]) == -1)
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "Unable to include configuration "
      "file '", cmd->argv[1], "'.", NULL));

  return HANDLED(cmd);
}

MODRET set_debuglevel(cmd_rec *cmd) {
  config_rec *c = NULL;
  int debuglevel = -1;
  char *endp = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  /* Make sure the parameter is a valid number. */
  debuglevel = strtol(cmd->argv[1], &endp, 10);

  if (endp && *endp)
    CONF_ERROR(cmd, "not a valid number");

  /* Make sure the number is within the valid debug level range. */
  if (debuglevel < 0 || debuglevel > 9)
    CONF_ERROR(cmd, "invalid debug level configured");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[0]) = debuglevel;

  return HANDLED(cmd);
}

MODRET set_defaultaddress(cmd_rec *cmd) {
  p_in_addr_t *main_addr = NULL;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  c = add_config_param(cmd->argv[0], 1, NULL);

  if ((main_addr = inet_getaddr(c->pool, cmd->argv[1])) == NULL)
    return ERROR_MSG(cmd, NULL, pstrcat(cmd->tmp_pool,
      (cmd->argv)[0], ": unable to resolve \"", cmd->argv[1], "\"",
      NULL));

  c->argv[0] = main_addr;

  return HANDLED(cmd);
}

MODRET set_servername(cmd_rec *cmd) {
  server_rec *s = cmd->server;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL);

  s->ServerName = pstrdup(s->pool,cmd->argv[1]);
  return HANDLED(cmd);
}

MODRET set_servertype(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if (!strcasecmp(cmd->argv[1], "inetd"))
    ServerType = SERVER_INETD;

  else if (!strcasecmp(cmd->argv[1], "standalone"))
    ServerType = SERVER_STANDALONE;

  else
    CONF_ERROR(cmd,"type must be either 'inetd' or 'standalone'.");

  return HANDLED(cmd);
}

MODRET add_transferlog(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  c = add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_wtmplog(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  if (strcasecmp(cmd->argv[1], "NONE") == 0)
    bool = 0;
  else
    bool = get_boolean(cmd, 1);

  if (bool != -1) {
    c = add_config_param(cmd->argv[0], 1, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
    *((unsigned char *) c->argv[0]) = bool;
    c->flags |= CF_MERGEDOWN;

  } else
    CONF_ERROR(cmd, "expected boolean argument, or \"NONE\"");

  return HANDLED(cmd);
}

MODRET set_bind(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL);

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);

  return HANDLED(cmd);
}

MODRET set_serveradmin(cmd_rec *cmd) {
  server_rec *s = cmd->server;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL);

  s->ServerAdmin = pstrdup(s->pool, cmd->argv[1]);
  return HANDLED(cmd);
}

MODRET set_usereversedns(cmd_rec *cmd) {
  int bool = -1;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if ((bool = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  ServerUseReverseDNS = bool;

  return HANDLED(cmd);
}

MODRET set_scoreboardfile(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if (pr_set_scoreboard(cmd->argv[1]) < 0)
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unable to use '",
      cmd->argv[1], "': ", strerror(errno), NULL));

  return HANDLED(cmd);
}

MODRET set_scoreboardpath(cmd_rec *cmd) {
  CONF_ERROR(cmd, "deprecated. Use 'ScoreboardFile /path/to/scoreboard/file' instead");
}

MODRET set_serverport(cmd_rec *cmd) {
  server_rec *s = cmd->server;
  int port;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL);

  port = atoi(cmd->argv[1]);
  if (port < 0 || port > 65535)
    CONF_ERROR(cmd,"value must be between 0 and 65535");

  s->ServerPort = port;
  return HANDLED(cmd);
}

MODRET set_pidfile(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return HANDLED(cmd);
}

MODRET set_sysloglevel(cmd_rec *cmd) {
  config_rec *c = NULL;
  int level = 0;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((level = log_str2sysloglevel(cmd->argv[1])) < 0)
    CONF_ERROR(cmd, "SyslogLevel requires level keyword: one of "
      "emerg/alert/crit/error/warn/notice/info/debug");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[0]) = level;

  return HANDLED(cmd);
}

MODRET set_serverident(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  if (cmd->argc < 2 || cmd->argc > 3)
    CONF_ERROR(cmd, "wrong number of parameters");

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((bool = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  if (bool && cmd->argc == 3) {
    c = add_config_param(cmd->argv[0], 2, NULL, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
    *((unsigned char *) c->argv[0]) = !bool;
    c->argv[1] = pstrdup(c->pool, cmd->argv[2]);

  } else {

    c = add_config_param(cmd->argv[0], 1, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
    *((unsigned char *) c->argv[0]) = !bool;
  }

  return HANDLED(cmd);
}

MODRET set_defaultserver(cmd_rec *cmd) {
  int bool = -1;
  server_rec *s = NULL;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL);

  if ((bool = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  if (!bool)
    return HANDLED(cmd);

  /* DefaultServer is not allowed if already set somewhere */
  for (s = (server_rec *) server_list->xas_list; s; s = s->next)
    if (find_config(s->conf, CONF_PARAM, cmd->argv[0], FALSE))
      CONF_ERROR(cmd, "DefaultServer has already been set.");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;

  return HANDLED(cmd);
}

MODRET add_masqueradeaddress(cmd_rec *cmd) {
 config_rec *c = NULL;
 p_in_addr_t *masq_addr = NULL;
 char masq_ip[80] = {'\0'};

 CHECK_ARGS(cmd, 1);
 CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL);

 /* Make a copy of the given argument.  */
 sstrncpy(masq_ip, cmd->argv[1], sizeof(masq_ip));

 if ((masq_addr = inet_getaddr(cmd->server->pool, masq_ip)) == NULL)
   return ERROR_MSG(cmd, NULL, pstrcat(cmd->tmp_pool,
     (cmd->argv)[0], ": unable to resolve \"", masq_ip, "\"",
     NULL));

 c = add_config_param(cmd->argv[0], 1, (void *) masq_addr);
 return HANDLED(cmd);
}

MODRET set_maxinstances(cmd_rec *cmd) {
  int max;
  char *endp;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT);

  if (!strcasecmp(cmd->argv[1],"none"))
    max = 0;
  else {
    max = (int)strtol(cmd->argv[1],&endp,10);

    if ((endp && *endp) || max < 1)
      CONF_ERROR(cmd,"argument must be 'none' or a number greater than 0.");
  }

  ServerMaxInstances = max;
  return HANDLED(cmd);
}

/* usage: MaxConnectionRate rate [interval] */
MODRET set_maxconnrate(cmd_rec *cmd) {
  long conn_max = 0L;
  char *endp = NULL;

  if (cmd->argc-1 < 1 || cmd->argc-1 > 2)
    CONF_ERROR(cmd, "wrong number of parameters");
  CHECK_CONF(cmd, CONF_ROOT);

  conn_max = strtol(cmd->argv[1], &endp, 10);

  if (endp && *endp)
    CONF_ERROR(cmd, "invalid connection rate");

  if (conn_max < 0)
    CONF_ERROR(cmd, "connection rate must be positive");

  max_connects = conn_max;

  /* If the optional interval parameter is given, parse it. */
  if (cmd->argc-1 == 2) {
    max_connect_interval = atoi(cmd->argv[2]);

    if (max_connect_interval < 1)
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
        ": interval must be greater than zero", NULL));
  }

  return HANDLED(cmd);
}

MODRET set_timeoutidle(cmd_rec *cmd) {
  int timeout = -1;
  char *endp = NULL;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  timeout = (int) strtol(cmd->argv[1], &endp, 10);

  if ((endp && *endp) || timeout < 0 || timeout > 65535)
    CONF_ERROR(cmd, "timeout values must be between 0 and 65535");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = timeout;

  return HANDLED(cmd);
}

MODRET set_socketbindtight(cmd_rec *cmd) {
  int bool = -1;
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if ((bool = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "expected boolean argument.");

  SocketBindTight = bool;
  return HANDLED(cmd);
}

MODRET set_multilinerfc2228(cmd_rec *cmd) {
  int bool = -1;
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if ((bool = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "expected boolean argument.");

  MultilineRFC2228 = bool;
  return HANDLED(cmd);
}

MODRET set_identlookups(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((bool = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "expected boolean argument.");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;

  return HANDLED(cmd);
}

MODRET set_tcpbacklog(cmd_rec *cmd) {
  int backlog;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  backlog = atoi(cmd->argv[1]);

  if (backlog < 1 || backlog > 255)
    CONF_ERROR(cmd,"parameter must be a number between 1 and 255.");

  tcpBackLog = backlog;
  return HANDLED(cmd);
}

MODRET set_tcpreceivewindow(cmd_rec *cmd) {
  int rwin;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL);

  rwin = atoi(cmd->argv[1]);

  if (rwin < 1024)
    CONF_ERROR(cmd,"parameter must be number equal to or greater than 1024.");

  cmd->server->tcp_rwin = rwin;
  cmd->server->tcp_rwin_override = 1;
  return HANDLED(cmd);
}

MODRET set_tcpsendwindow(cmd_rec *cmd) {
  int swin;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL);

  swin = atoi(cmd->argv[1]);

  if (swin < 1024)
    CONF_ERROR(cmd,"parameter must be number equal to or greater than 1024.");

  cmd->server->tcp_swin = swin;
  cmd->server->tcp_swin_override = 1;
  return HANDLED(cmd);
}

MODRET set_tcpnodelay(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((bool = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;

  return HANDLED(cmd);
}

MODRET set_user(cmd_rec *cmd) {
  struct passwd *pw = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  /* 1.1.7, no longer force user/group lookup inside <Anonymous>
   * it's now defered until authentication occurs.
   */

  if (!cmd->config || cmd->config->config_type != CONF_ANON) {
    if ((pw = auth_getpwnam(cmd->tmp_pool, cmd->argv[1])) == NULL) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "Unknown user '",
        cmd->argv[1], "'.", NULL));
    }
  }

  if (pw) {
    config_rec *c = add_config_param("UserID", 1, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(uid_t));
    *((uid_t *) c->argv[0]) = pw->pw_uid;
  }

  add_config_param_str("UserName", 1, cmd->argv[1]);
  return HANDLED(cmd);
}

MODRET set_group(cmd_rec *cmd) {
  struct group *grp = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  if (!cmd->config || cmd->config->config_type != CONF_ANON) {
    if ((grp = auth_getgrnam(cmd->tmp_pool, cmd->argv[1])) == NULL) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "Unknown group '",
        cmd->argv[1], "'.", NULL));
    }
  }

  if (grp) {
    config_rec *c = add_config_param("GroupID", 1, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(gid_t));
    *((gid_t *) c->argv[0]) = grp->gr_gid;
  }

  add_config_param_str("GroupName", 1, cmd->argv[1]);
  return HANDLED(cmd);
}

MODRET set_umask(cmd_rec *cmd) {
  config_rec *c;
  char *endp;
  mode_t tmp_umask;

  CHECK_VARARGS(cmd, 1, 2);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|
    CONF_DIR|CONF_DYNDIR);

  tmp_umask = (mode_t) strtol(cmd->argv[1], &endp, 8);

  if (endp && *endp)
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", cmd->argv[1],
      "' is not a valid umask", NULL));

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(mode_t));
  *((mode_t *) c->argv[0]) = tmp_umask;
  c->flags |= CF_MERGEDOWN;

  /* Have we specified a directory umask as well?
   */
  if (CHECK_HASARGS(cmd, 2)) {

    /* allocate space for another mode_t.  Don't worry -- the previous
     * pointer was recorded in the Umask config_rec
     */
    tmp_umask = (mode_t) strtol(cmd->argv[2], &endp, 8);

    if (endp && *endp)
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", cmd->argv[2],
        "' is not a valid umask", NULL));

    c = add_config_param("DirUmask", 1, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(mode_t));
    *((mode_t *) c->argv[0]) = tmp_umask;
    c->flags |= CF_MERGEDOWN;
  }

  return HANDLED(cmd);
}

MODRET set_rlimitcpu(cmd_rec *cmd) {
#ifdef RLIMIT_CPU
  /* Make sure the directive has between 1 and 3 parameters */
  if (cmd->argc-1 < 1 || cmd->argc-1 > 3)
    CONF_ERROR(cmd, "wrong number of parameters");

  /* The context check for this directive depends on the first parameter.
   * For backwards compatibility, this parameter may be a number, or it
   * may be "daemon", "session", or "none".  If it happens to be
   * "daemon", then this directive should be in the CONF_ROOT context only.
   * Otherwise, it can appear in the full range of server contexts.
   */

  if (!strcmp(cmd->argv[1], "daemon")) {
    CHECK_CONF(cmd, CONF_ROOT);

  } else {
    CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
  }

  /* Handle the newer format, which uses "daemon" or "session" or "none"
   * as the first parameter.
   */
  if (!strcmp(cmd->argv[1], "daemon") ||
      !strcmp(cmd->argv[1], "session")) {
    config_rec *c = NULL;
    struct rlimit *rlim = pcalloc(cmd->server->pool, sizeof(struct rlimit));

    /* Retrieve the current values */
    if (getrlimit(RLIMIT_CPU, rlim) == -1)
      log_pri(PR_LOG_ERR, "error: getrlimit(RLIMIT_CPU): %s", strerror(errno));

    if (!strcasecmp("max", cmd->argv[2]))
      rlim->rlim_cur = RLIM_INFINITY;

    else {

      /* Check that the non-max argument is a number, and error out if not.
       */
      char *tmp = NULL;
      unsigned long num = strtoul(cmd->argv[2], &tmp, 10);

      if (tmp && *tmp)
        CONF_ERROR(cmd, "badly formatted argument");

      rlim->rlim_cur = num;
    }

    /* Handle the optional "hard limit" parameter, if present. */
    if (cmd->argc-1 == 3) {
      if (!strcasecmp("max", cmd->argv[3]))
        rlim->rlim_max = RLIM_INFINITY;

      else {

        /* Check that the non-max argument is a number, and error out if not.
         */
        char *tmp = NULL;
        unsigned long num = strtoul(cmd->argv[3], &tmp, 10);

        if (tmp && *tmp)
          CONF_ERROR(cmd, "badly formatted argument");

        rlim->rlim_max = num;
      }
    }

    c = add_config_param(cmd->argv[0], 2, (void *) rlim, NULL);
    c->argv[1] = pstrdup(c->pool, cmd->argv[1]);

  /* Handle the older format, which will have a number as the first
   * parameter.
   */
  } else {
    struct rlimit *rlim = pcalloc(cmd->server->pool, sizeof(struct rlimit));

    /* Retrieve the current values */
    if (getrlimit(RLIMIT_CPU, rlim) == -1)
      log_pri(PR_LOG_ERR, "error: getrlimit(RLIMIT_CPU): %s", strerror(errno));

    if (!strcasecmp("max", cmd->argv[1]))
      rlim->rlim_cur = RLIM_INFINITY;

    else {

      /* Check that the non-max argument is a number, and error out if not.
       */
      char *tmp = NULL;
      long num = strtol(cmd->argv[1], &tmp, 10);

      if (tmp && *tmp)
        CONF_ERROR(cmd, "badly formatted argument");

      rlim->rlim_cur = num;
    }

    /* Handle the optional "hard limit" parameter, if present. */
    if (cmd->argc-1 == 2) {
      if (!strcasecmp("max", cmd->argv[2]))
        rlim->rlim_max = RLIM_INFINITY;

      else {

        /* Check that the non-max argument is a number, and error out if not.
         */
        char *tmp = NULL;
        long num = strtol(cmd->argv[2], &tmp, 10);

        if (tmp && *tmp)
          CONF_ERROR(cmd, "badly formatted argument");

        rlim->rlim_max = num;
      }
    }

    add_config_param(cmd->argv[0], 2, (void *) rlim, NULL);
  }

  return HANDLED(cmd);
#else
  CONF_ERROR(cmd, "RLimitCPU is not supported on this platform");
#endif
}

MODRET set_rlimitmemory(cmd_rec *cmd) {
#if defined(RLIMIT_AS) || defined(RLIMIT_DATA) || defined(RLIMIT_VMEM)
  /* Make sure the directive has between 1 and 3 parameters */
  if (cmd->argc-1 < 1 || cmd->argc-1 > 3)
    CONF_ERROR(cmd, "wrong number of parameters");

  /* The context check for this directive depends on the first parameter.
   * For backwards compatibility, this parameter may be a number, or it
   * may be "daemon", "session", or "none".  If it happens to be
   * "daemon", then this directive should be in the CONF_ROOT context only.
   * Otherwise, it can appear in the full range of server contexts.
   */

  if (!strcmp(cmd->argv[1], "daemon")) {
    CHECK_CONF(cmd, CONF_ROOT);

  } else {
    CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
  }

  /* Handle the newer format, which uses "daemon" or "session" or "none"
   * as the first parameter.
   */
  if (!strcmp(cmd->argv[1], "daemon") ||
      !strcmp(cmd->argv[1], "session")) {
    config_rec *c = NULL;
    struct rlimit *rlim = pcalloc(cmd->server->pool, sizeof(struct rlimit));

    /* Retrieve the current values */
#if defined(RLIMIT_AS)
    if (getrlimit(RLIMIT_AS, rlim) == -1)
      log_pri(PR_LOG_ERR, "error: getrlimit(RLIMIT_AS): %s", strerror(errno));
#elif defined(RLIMIT_DATA)
    if (getrlimit(RLIMIT_DATA, rlim) == -1)
      log_pri(PR_LOG_ERR, "error: getrlimit(RLIMIT_DATA): %s", strerror(errno));
#elif defined(RLIMIT_VMEM)
    if (getrlimit(RLIMIT_VMEM, rlim) == -1)
      log_pri(PR_LOG_ERR, "error: getrlimit(RLIMIT_VMEM): %s", strerror(errno));
#endif

    if (!strcasecmp("max", cmd->argv[2]))
      rlim->rlim_cur = RLIM_INFINITY;

    else
      rlim->rlim_cur = get_num_bytes(cmd->argv[2]);

    /* Check for bad return values. */
    if (rlim->rlim_cur == PR_BYTES_BAD_UNITS)
      CONF_ERROR(cmd, "unknown units used");

    if (rlim->rlim_cur == PR_BYTES_BAD_FORMAT)
      CONF_ERROR(cmd, "badly formatted parameter");

    /* Handle the optional "hard limit" parameter, if present. */
    if (cmd->argc-1 == 3) {
      if (!strcasecmp("max", cmd->argv[3]))
        rlim->rlim_max = RLIM_INFINITY;

      else
        rlim->rlim_cur = get_num_bytes(cmd->argv[3]);

      /* Check for bad return values. */
      if (rlim->rlim_cur == PR_BYTES_BAD_UNITS)
        CONF_ERROR(cmd, "unknown units used");

      if (rlim->rlim_cur == PR_BYTES_BAD_FORMAT)
        CONF_ERROR(cmd, "badly formatted parameter");
    }

    c = add_config_param(cmd->argv[0], 2, (void *) rlim, NULL);
    c->argv[1] = pstrdup(c->pool, cmd->argv[1]);

  /* Handle the older format, which will have a number as the first
   * parameter.
   */
  } else {
    struct rlimit *rlim = pcalloc(cmd->server->pool, sizeof(struct rlimit));

    /* Retrieve the current values */
#if defined(RLIMIT_AS)
    if (getrlimit(RLIMIT_AS, rlim) == -1)
      log_pri(PR_LOG_ERR, "error: getrlimit(RLIMIT_AS): %s", strerror(errno));
#elif defined(RLIMIT_DATA)
    if (getrlimit(RLIMIT_DATA, rlim) == -1)
      log_pri(PR_LOG_ERR, "error: getrlimit(RLIMIT_DATA): %s", strerror(errno));
#elif defined(RLIMIT_VMEM)
    if (getrlimit(RLIMIT_VMEM, rlim) == -1)
      log_pri(PR_LOG_ERR, "error: getrlimit(RLIMIT_VMEM): %s", strerror(errno));
#endif

    if (!strcasecmp("max", cmd->argv[1]))
      rlim->rlim_cur = RLIM_INFINITY;

    else
      rlim->rlim_cur = get_num_bytes(cmd->argv[1]);

    /* Check for bad return values. */
    if (rlim->rlim_cur == PR_BYTES_BAD_UNITS)
      CONF_ERROR(cmd, "unknown units used");

    if (rlim->rlim_cur == PR_BYTES_BAD_FORMAT)
      CONF_ERROR(cmd, "badly formatted parameter");

    /* Handle the optional "hard limit" parameter, if present. */
    if (cmd->argc-1 == 2) {
      if (!strcasecmp("max", cmd->argv[2]))
        rlim->rlim_max = RLIM_INFINITY;

      else
        rlim->rlim_cur = get_num_bytes(cmd->argv[2]);

      /* Check for bad return values. */
      if (rlim->rlim_cur == PR_BYTES_BAD_UNITS)
        CONF_ERROR(cmd, "unknown units used");

      if (rlim->rlim_cur == PR_BYTES_BAD_FORMAT)
        CONF_ERROR(cmd, "badly formatted parameter");
    }

    add_config_param(cmd->argv[0], 2, (void *) rlim, NULL);
  }

  return HANDLED(cmd);
#else
  CONF_ERROR(cmd, "RLimitMemory is not supported on this platform");
#endif
}

MODRET set_rlimitopenfiles(cmd_rec *cmd) {
#if defined(RLIMIT_NOFILE) || defined(RLIMIT_OFILE)
  /* Make sure the directive has between 1 and 3 parameters */
  if (cmd->argc-1 < 1 || cmd->argc-1 > 3)
    CONF_ERROR(cmd, "wrong number of parameters");

  /* The context check for this directive depends on the first parameter.
   * For backwards compatibility, this parameter may be a number, or it
   * may be "daemon", "session", or "none".  If it happens to be
   * "daemon", then this directive should be in the CONF_ROOT context only.
   * Otherwise, it can appear in the full range of server contexts.
   */

  if (!strcmp(cmd->argv[1], "daemon")) {
    CHECK_CONF(cmd, CONF_ROOT);

  } else {
    CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
  }

  /* Handle the newer format, which uses "daemon" or "session" or "none"
   * as the first parameter.
   */
  if (!strcmp(cmd->argv[1], "daemon") ||
      !strcmp(cmd->argv[1], "session")) {
    config_rec *c = NULL;
    struct rlimit *rlim = pcalloc(cmd->server->pool, sizeof(struct rlimit));

    /* Retrieve the current values */
#if defined(RLIMIT_NOFILE)
    if (getrlimit(RLIMIT_NOFILE, rlim) == -1)
      log_pri(PR_LOG_ERR, "error: getrlimit(RLIMIT_NOFILE): %s",
        strerror(errno));
#elif defined(RLIMIT_OFILE)
    if (getrlimit(RLIMIT_OFILE, rlim) == -1)
      log_pri(PR_LOG_ERR, "error: getrlimit(RLIMIT_OFILE): %s",
        strerror(errno));
#endif

    if (!strcasecmp("max", cmd->argv[2]))
      rlim->rlim_cur = sysconf(_SC_OPEN_MAX);

    else {

      /* Check that the non-max argument is a number, and error out if not.
       */
      char *tmp = NULL;
      long num = strtol(cmd->argv[2], &tmp, 10);

      if (tmp && *tmp)
        CONF_ERROR(cmd, "badly formatted argument");

      rlim->rlim_cur = num;
    }

    /* Handle the optional "hard limit" parameter, if present. */
    if (cmd->argc-1 == 3) {
      if (!strcasecmp("max", cmd->argv[3]))
        rlim->rlim_max = sysconf(_SC_OPEN_MAX);

      else {

        /* Check that the non-max argument is a number, and error out if not.
         */
        char *tmp = NULL;
        long num = strtol(cmd->argv[3], &tmp, 10);

        if (tmp && *tmp)
          CONF_ERROR(cmd, "badly formatted argument");

        rlim->rlim_max = num;
      }
    }

    c = add_config_param(cmd->argv[0], 2, (void *) rlim, NULL);
    c->argv[1] = pstrdup(c->pool, cmd->argv[1]);

  /* Handle the older format, which will have a number as the first
   * parameter.
   */
  } else {
    struct rlimit *rlim = pcalloc(cmd->server->pool, sizeof(struct rlimit));

    /* Retrieve the current values */
#if defined(RLIMIT_NOFILE)
    if (getrlimit(RLIMIT_NOFILE, rlim) == -1)
      log_pri(PR_LOG_ERR, "error: getrlimit(RLIMIT_NOFILE): %s",
        strerror(errno));
#elif defined(RLIMIT_OFILE)
    if (getrlimit(RLIMIT_OFILE, rlim) == -1)
      log_pri(PR_LOG_ERR, "error: getrlimit(RLIMIT_OFILE): %s",
        strerror(errno));
#endif

    if (!strcasecmp("max", cmd->argv[1]))
      rlim->rlim_cur = sysconf(_SC_OPEN_MAX);

    else {

      /* Check that the non-max argument is a number, and error out if not.
       */
      char *tmp = NULL;
      long num = strtol(cmd->argv[1], &tmp, 10);

      if (tmp && *tmp)
        CONF_ERROR(cmd, "badly formatted argument");

      rlim->rlim_cur = num;
    }

    /* Handle the optional "hard limit" parameter, if present. */
    if (cmd->argc-1 == 2) {
      if (!strcasecmp("max", cmd->argv[2]))
        rlim->rlim_max = sysconf(_SC_OPEN_MAX);

      else {

        /* Check that the non-max argument is a number, and error out if not.
         */
        char *tmp = NULL;
        long num = strtol(cmd->argv[2], &tmp, 10);

        if (tmp && *tmp)
          CONF_ERROR(cmd, "badly formatted argument");

        rlim->rlim_max = num;
      }
    }

    add_config_param(cmd->argv[0], 2, (void *) rlim, NULL);
  }

  return HANDLED(cmd);
#else
  CONF_ERROR(cmd, "RLimitOpenFiles is not supported on this platform");
#endif
}

MODRET set_syslogfacility(cmd_rec *cmd) {
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

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  for (i = 0; factable[i].name; i++) {
    if (!strcasecmp(cmd->argv[1],factable[i].name)) {
      log_closesyslog();
      log_setfacility(factable[i].facility);

      pr_signals_block();
      PRIVS_ROOT
        switch (log_opensyslog(NULL)) {

        case -1:
          PRIVS_RELINQUISH
          pr_signals_unblock();
          CONF_ERROR(cmd, "unable to open syslog");
          break;

        case LOG_WRITEABLE_DIR:
          PRIVS_RELINQUISH
          pr_signals_unblock();
          CONF_ERROR(cmd,
            "you are attempting to log to a world writeable directory");
          break;

        case LOG_SYMLINK:
          PRIVS_RELINQUISH
          pr_signals_unblock();
          CONF_ERROR(cmd, "you are attempting to log to a symbolic link");
          break;

        default:
          break;
        }
      PRIVS_RELINQUISH
      pr_signals_unblock();

      return HANDLED(cmd);
    }
  }

  CONF_ERROR(cmd, "argument must be a valid syslog facility");
}

MODRET set_timesgmt(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  if ((bool = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;

  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_regex(cmd_rec *cmd, char *param, char *type) {
#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  regex_t *preg = NULL;
  config_rec *c = NULL;
  int res = 0;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|CONF_DIR|
    CONF_DYNDIR);

  log_debug(DEBUG4, "Compiling %s regex '%s'.", type, cmd->argv[1]);
  preg = pr_regexp_alloc();
  log_debug(DEBUG4, "Allocated %s regex at location %p.", type, preg);

  if ((res = regcomp(preg, cmd->argv[1], REG_EXTENDED|REG_NOSUB)) != 0) {
    char errstr[200] = {'\0'};

    regerror(res, preg, errstr, sizeof(errstr));
    pr_regexp_free(preg);

    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", cmd->argv[1], "' failed regex "
      "compilation: ", errstr, NULL));
  }

  c = add_config_param(param, 1, preg);
  c->flags |= CF_MERGEDOWN;
  return HANDLED(cmd);

#else /* no regular expression support at the moment */
  CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "The ", param,
                          " directive cannot be used on this system, "
                          "as you do not have POSIX compliant "
                          "regex support.", NULL));
#endif
}

MODRET set_allowfilter(cmd_rec *cmd) {
  return set_regex(cmd, cmd->argv[0], "allow");
}

MODRET set_denyfilter(cmd_rec *cmd) {
  return set_regex(cmd, cmd->argv[0], "deny");
}

MODRET set_passiveports(cmd_rec *cmd) {
  int pasv_min_port, pasv_max_port;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 2);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  pasv_min_port = atoi(cmd->argv[1]);
  pasv_max_port = atoi(cmd->argv[2]);

  /* Sanity check */
  if (pasv_min_port <= 0 || pasv_min_port > 65535)
    CONF_ERROR(cmd, "min port must be allowable port number");

  if (pasv_max_port <= 0 || pasv_max_port > 65535)
    CONF_ERROR(cmd, "max port must be allowable port number");

  if (pasv_min_port < 1024 || pasv_max_port < 1024)
    CONF_ERROR(cmd, "port numbers must be above 1023");

  if (pasv_max_port < pasv_min_port)
    CONF_ERROR(cmd, "min port must be equal to or less than max port");

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = pasv_min_port;
  c->argv[1] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[1]) = pasv_max_port;

  return HANDLED(cmd);
}

MODRET set_pathallowfilter(cmd_rec *cmd) {
  return set_regex(cmd, cmd->argv[0], "allow");
}

MODRET set_pathdenyfilter(cmd_rec *cmd) {
  return set_regex(cmd, cmd->argv[0], "deny");
}

MODRET set_allowforeignaddress(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  if ((bool = get_boolean(cmd,1)) == -1)
    CONF_ERROR(cmd,"expected boolean argument.");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;

  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_commandbuffersize(cmd_rec *cmd) {
  int size = 0;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  /* NOTE: need to add checks for maximum possible sizes, negative sizes. */
  size = atoi(cmd->argv[1]);

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = size;

  return HANDLED(cmd);
}

MODRET set_cdpath(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  c = add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET add_directory(cmd_rec *cmd) {
  config_rec *c;
  char *dir,*rootdir = NULL;
  int flags = 0;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  dir = cmd->argv[1];

  if (*dir != '/' && *dir != '~' &&
     (!cmd->config || cmd->config->config_type != CONF_ANON))
    CONF_ERROR(cmd,"relative pathname not allowed in non-anonymous blocks.");

  /* If in anonymous mode, and path is relative, just cat anon root
   * and relative path
   *
   * Note: This is no longer necessary, because we don't interpolate anonymous
   * directories at run-time.
   */
  if (cmd->config && cmd->config->config_type == CONF_ANON &&
     *dir != '/' && *dir != '~') {
    if (strcmp(dir, "*") != 0)
      dir = pdircat(cmd->tmp_pool, "/", dir, NULL);
    rootdir = cmd->config->name;

  } else {
    /* If the directory begins with ~, two possibilities:
     * ~username/... : resolve to absolute path for ~username
     * ~/... : intended to be defered until authenciation, where
     *         ~ will be replaced w/ user's home dir
     */

    if (*dir == '~' && (!*(dir+1) || *(dir+1) == '/'))
      flags |= CF_DEFER;

    else {
      dir = dir_best_path(cmd->tmp_pool, dir);

      if (!dir)
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, cmd->argv[1] ,": ",
          strerror(errno), NULL));
    }
  }

  /* Check to see that there isn't already a config for this directory,
   * but only if we're not in an <Anonymous> section.  Due to the way
   * in which later <Directory> checks are done, <Directory> blocks inside
   * <Anonymous> sections are handled differently than outside, probably
   * overriding their outside counterparts (if necessary).  This is
   * probably OK, as this overriding only takes effect for the <Anonymous>
   * user.
   */

  if (!check_context(cmd, CONF_ANON) &&
      find_config(cmd->server->conf, CONF_DIR, dir, FALSE) != NULL)
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
      cmd->argv[0], ": <Directory> section already configured for '",
      cmd->argv[1], "'", NULL));

  c = start_sub_config(dir);
  c->argc = 2;
  c->argv = pcalloc(c->pool,3*sizeof(void*));
  if (rootdir)
    c->argv[1] = pstrdup(c->pool,rootdir);

  c->config_type = CONF_DIR;
  c->flags |= flags;

  log_debug(DEBUG2, "<Directory %s>: adding section for resolved path '%s'",
    cmd->argv[1], dir);

  return HANDLED(cmd);
}

MODRET set_hidefiles(cmd_rec *cmd) {
#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  regex_t *regexp = NULL;
  config_rec *c = NULL;
  int res;
  unsigned int precedence = 0;
  unsigned char inverted = FALSE;

  int ctxt = (cmd->config && cmd->config->config_type != CONF_PARAM ?
    cmd->config->config_type : cmd->server->config_type ?
    cmd->server->config_type : CONF_ROOT);

  /* This directive must have either 1, or 3, arguments */
  if (cmd->argc-1 != 1 && cmd->argc-1 != 3)
    CONF_ERROR(cmd, "wrong number of parameters");

  CHECK_CONF(cmd, CONF_DIR|CONF_DYNDIR);

  /* Set the precedence for this config_rec based on its configuration
   * context.
   */
  if (ctxt & CONF_DIR)
    precedence = 1;

  else
    precedence = 2;

  /* Check for a "none" argument, which is used to nullify inherited
   * HideFiles configurations from parent directories.
   */
  if (!strcasecmp(cmd->argv[1], "none")) {
    log_debug(DEBUG4, "setting %s to NULL", cmd->argv[0]);
    add_config_param(cmd->argv[0], 1, NULL);
    return HANDLED(cmd);
  }

  /* Check for a leading '!' prefix, signifying regex negation */
  if (*cmd->argv[1] == '!') {
    inverted = TRUE;
    cmd->argv[1]++;
  }

  regexp = pr_regexp_alloc();

  if ((res = regcomp(regexp, cmd->argv[1], REG_EXTENDED|REG_NOSUB)) != 0) {
    char errstr[200] = {'\0'};

    regerror(res, regexp, errstr, sizeof(errstr));
    pr_regexp_free(regexp);

    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", cmd->argv[1],
      "' failed regex compilation: ", errstr, NULL));
  }

  /* If the directive was used with 3 arguments, then the optional
   * classifiers, and classifier expression, were used.  Make sure that
   * a valid classifier was used.
   */
  if (cmd->argc-1 == 3) {
    if (!strcmp(cmd->argv[2], "user") ||
        !strcmp(cmd->argv[2], "group") ||
        !strcmp(cmd->argv[2], "class")) {

      /* no-op */

    } else
      return ERROR_MSG(cmd, NULL, pstrcat(cmd->tmp_pool, cmd->argv[0],
        ": unknown classifier used: '", cmd->argv[2], "'", NULL));
  }

  if (cmd->argc-1 == 1) {
    c = add_config_param(cmd->argv[0], 3, NULL, NULL, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(regex_t *));
    *((regex_t **) c->argv[0]) = regexp;
    c->argv[1] = pcalloc(c->pool, sizeof(unsigned char));
    *((unsigned char *) c->argv[1]) = inverted;
    c->argv[2] = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) c->argv[2]) = precedence;

  } else if (cmd->argc-1 == 3) {
    array_header *acl = NULL;
    int argc = cmd->argc - 3;
    char **argv = cmd->argv + 2;

    acl = pr_parse_expression(cmd->tmp_pool, &argc, argv);

    c = add_config_param(cmd->argv[0], 0);
    c->argc = argc + 4;

    /* Add 5 to argc for the argv of the config_rec: one for the
     * regexp, one for the 'inverted' value, one for the precedence,
     * one for the classifier, and one for the terminating NULL
     */
    c->argv = pcalloc(c->pool, ((argc + 5) * sizeof(char *)));

    /* Capture the config_rec's argv pointer for doing the by-hand
     * population.
     */
    argv = (char **) c->argv;

    /* Copy in the regexp. */
    *argv = pcalloc(c->pool, sizeof(regex_t *));
    *((regex_t **) *argv++) = regexp;

    /* Copy in the 'inverted' flag */
    *argv = pcalloc(c->pool, sizeof(unsigned char));
    *((unsigned char *) *argv++) = inverted;

    /* Copy in the precedence. */
    *argv = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) *argv++) = precedence;

    /* Copy in the expression classifier */
    *argv++ = pstrdup(c->pool, cmd->argv[2]);

    /* now, copy in the expression arguments */
    if (argc && acl) {
      while (argc--) {
        *argv++ = pstrdup(c->pool, *((char **) acl->elts));
        acl->elts = ((char **) acl->elts) + 1;
      }
    }

    /* don't forget the terminating NULL */
    *argv = NULL;
  }

  c->flags |= CF_MERGEDOWN_MULTI;
  return HANDLED(cmd);

#else /* no regular expression support at the moment */
  CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "The HideFiles"
        " directive cannot be used on this system, "
        "as you do not have POSIX compliant "
        "regex support."));
#endif
}

MODRET set_hidenoaccess(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ANON|CONF_DIR);

  if ((bool = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "expected boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_hideuser(cmd_rec *cmd) {
  config_rec *c = NULL;
  struct passwd *pw = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ANON|CONF_DIR);

  pw = auth_getpwnam(cmd->tmp_pool, cmd->argv[1]);

  if (!pw)
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", cmd->argv[1],
      "' is not a valid user.", NULL));

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(uid_t));
  *((uid_t *) c->argv[0]) = pw->pw_uid;
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_hidegroup(cmd_rec *cmd) {
  config_rec *c = NULL;
  struct group *gr = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ANON|CONF_DIR);

  gr = auth_getgrnam(cmd->tmp_pool, cmd->argv[1]);

  if (!gr)
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", cmd->argv[1],
      "' is not a valid group.", NULL));

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(gid_t));
  *((gid_t *) c->argv[0]) = gr->gr_gid;
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET add_groupowner(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ANON|CONF_DIR|CONF_DYNDIR);

  c = add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET add_userowner(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ANON|CONF_DIR);

  c = add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_allowoverride(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;
  unsigned int precedence = 0;

  int ctxt = (cmd->config && cmd->config->config_type != CONF_PARAM ?
     cmd->config->config_type : cmd->server->config_type ?
     cmd->server->config_type : CONF_ROOT);

  /* This directive must have either 1 or 3 arguments */
  if (cmd->argc-1 != 1 && cmd->argc-1 != 3)
    CONF_ERROR(cmd, "missing arguments");

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|CONF_DIR);

  if ((bool = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "expected boolean argument");

  /* Set the precedence for this config_rec based on its configuration
   * context.
   */
  if (ctxt & CONF_GLOBAL)
    precedence = 1;

  /* These will never appear simultaneously */
  else if (ctxt & CONF_ROOT || ctxt & CONF_VIRTUAL)
    precedence = 2;

  else if (ctxt & CONF_ANON)
    precedence = 3;

  else if (ctxt & CONF_DIR)
    precedence = 4;

  /* If the directive was used with 3 arguments, then the optional
   * classifiers, and classifier expression, were used.  Make sure that
   * a valid classifier was used.
   */
  if (cmd->argc-1 == 3) {
    if (!strcmp(cmd->argv[2], "user") ||
        !strcmp(cmd->argv[2], "group") ||
        !strcmp(cmd->argv[2], "class")) {

      /* no-op */

    } else
      return ERROR_MSG(cmd, NULL, pstrcat(cmd->tmp_pool, cmd->argv[0],
        ": unknown classifier used: '", cmd->argv[2], "'", NULL));
  }

  if (cmd->argc-1 == 1) {
    c = add_config_param(cmd->argv[0], 2, NULL, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(int));
    *((int *) c->argv[0]) = bool;
    c->argv[1] = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) c->argv[1]) = precedence;

  } if (cmd->argc-1 == 3) {
    array_header *acl = NULL;
    int argc = cmd->argc - 3;
    char **argv = cmd->argv + 2;

    acl = pr_parse_expression(cmd->tmp_pool, &argc, argv);

    c = add_config_param(cmd->argv[0], 0);
    c->argc = argc + 3;

    /* Add 4 to argc for the argv of the config_rec: one for the
     * precedence, one for the compiled regexp pointer, one for the
     * classifier, and one for the terminating NULL.
     */
    c->argv = pcalloc(c->pool, ((argc + 4) * sizeof(char *)));

    /* Capture the config_rec's argv pointer for doing the by-hand
     * population.
     */
    argv = (char **) c->argv;

    /* Copy in the boolean argument */
    *argv = pcalloc(c->pool, sizeof(int));
    *((int *) *argv++) = bool;

    /* Copy in the precedence. */
    *argv = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) *argv++) = precedence;

    /* copy in the classifier */
    *argv++ = pstrdup(c->pool, cmd->argv[2]);

    /* Now, copy in the expression arguments */
    if (argc && acl) {
      while (argc--) {
        *argv++ = pstrdup(c->pool, *((char **) acl->elts));
        acl->elts = ((char **) acl->elts) + 1;
      }
    }

    /* Don't forget the terminating NULL */
    *argv = NULL;
  }

  c->flags |= CF_MERGEDOWN_MULTI;

  return HANDLED(cmd);
}

MODRET end_directory(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 0);
  CHECK_CONF(cmd, CONF_DIR);

  end_sub_config();

  return HANDLED(cmd);
}

MODRET add_anonymous(cmd_rec *cmd) {
  config_rec *c = NULL;
  char *dir;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  dir = cmd->argv[1];

  if (*dir != '/' && *dir != '~')
    CONF_ERROR(cmd,pstrcat(cmd->tmp_pool,"(",dir,") absolute pathname "
               "required.",NULL));

  if (strchr(dir,'*'))
    CONF_ERROR(cmd,pstrcat(cmd->tmp_pool,"(",dir,") wildcards not allowed "
               "in pathname.",NULL));

  if (!strcmp(dir,"/"))
    CONF_ERROR(cmd,"'/' not permitted for anonymous root directory.");

  if (*(dir+strlen(dir)-1) != '/')
    dir = pstrcat(cmd->tmp_pool,dir,"/",NULL);

  if (!dir)
    CONF_ERROR(cmd,pstrcat(cmd->tmp_pool,cmd->argv[1],": ",
               strerror(errno),NULL));

  c = start_sub_config(dir);

  c->config_type = CONF_ANON;
  return HANDLED(cmd);
}

MODRET end_anonymous(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 0);
  CHECK_CONF(cmd, CONF_ANON);

  end_sub_config();

  return HANDLED(cmd);
}

MODRET add_global(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 0);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL);

  c = start_sub_config("<Global>");
  c->config_type = CONF_GLOBAL;

  return HANDLED(cmd);
}

MODRET end_global(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 0);
  CHECK_CONF(cmd, CONF_GLOBAL);

  end_sub_config();

  return HANDLED(cmd);
}

MODRET add_limit(cmd_rec *cmd) {
  config_rec *c = NULL;
  int cargc;
  char **argv,**cargv;

  if (cmd->argc < 2)
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
    *argv++ = pstrdup(c->pool, *cargv++);

  *argv = NULL;

  return HANDLED(cmd);
}

MODRET set_order(cmd_rec *cmd) {
  int order = -1,argc = cmd->argc;
  char *arg = "",**argv = cmd->argv+1;
  config_rec *c = NULL;

  CHECK_CONF(cmd, CONF_LIMIT);

  while (--argc && *argv)
    arg = pstrcat(cmd->tmp_pool, arg, *argv++, NULL);

  if (!strcasecmp(arg, "allow,deny"))
    order = ORDER_ALLOWDENY;

  else if (!strcasecmp(arg, "deny,allow"))
    order = ORDER_DENYALLOW;

  else
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", arg, "': invalid argument",
      NULL));

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = order;

  return HANDLED(cmd);
}

MODRET set_allowdenyuser(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_CONF(cmd, CONF_LIMIT);

  if (cmd->argc < 2)
    CONF_ERROR(cmd, "wrong number of parameters");

  /* Is this a regular user expression, or a regular expression for
   * matching user names?
   */

  if (strcmp(cmd->argv[1], "regex") != 0) {
    char **argv = cmd->argv;
    int argc = cmd->argc-1;
    array_header *acl = pr_parse_expression(cmd->tmp_pool, &argc, argv);

    c = add_config_param(cmd->argv[0], 0);

    c->argc = argc;
    c->argv = pcalloc(c->pool, (argc+1) * sizeof(char*));
    argv = (char **) c->argv;

    while (argc--) {
      *argv++ = pstrdup(c->pool, *((char **) acl->elts));
      acl->elts = ((char **)acl->elts) + 1;
    }
    *argv = NULL;

  } else {
#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
    regex_t *preg;
    int res;

    if (cmd->argc != 3)
      CONF_ERROR(cmd, "wrong number of parameters");

    preg = pr_regexp_alloc();

    if ((res = regcomp(preg, cmd->argv[2], REG_EXTENDED|REG_NOSUB)) != 0) {
      char errstr[200] = {'\0'};

      regerror(res, preg, errstr, sizeof(errstr));
      pr_regexp_free(preg);

      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", cmd->argv[2], "' failed "
        "regex compilation: ", errstr, NULL));
    }

    /* The first NULL is used as the signal to the {Allow,Deny}User lookup
     * function to handle the config_rec's contents as a regular expression,
     * rather than a user list.
     */
    c = add_config_param(cmd->argv[0], 2, NULL, preg);
#else
    CONF_ERROR(cmd, "The 'regex' parameter cannot be used on this system, "
      "as you do not have POSIX compliant regex support");
#endif /* HAVE_REGEX_H and HAVE_REGCOMP */
  }

  return HANDLED(cmd);
}

MODRET set_allowdenygroup(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_CONF(cmd, CONF_LIMIT);

  if (cmd->argc < 2)
    CONF_ERROR(cmd, "wrong number of parameters");

  /* Is this a regular user expression, or a regular expression for
   * matching user names?
   */

  if (strcmp(cmd->argv[1], "regex") != 0) {
    char **argv = cmd->argv;
    int argc = cmd->argc-1;
    array_header *acl = pr_parse_expression(cmd->tmp_pool, &argc, argv);

    c = add_config_param(cmd->argv[0], 0);

    c->argc = argc;
    c->argv = pcalloc(c->pool, (argc+1) * sizeof(char*));
    argv = (char **) c->argv;

    while (argc--) {
      *argv++ = pstrdup(c->pool, *((char **) acl->elts));
      acl->elts = ((char **) acl->elts) + 1;
    }
    *argv = NULL;

  } else {
#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
    regex_t *preg;
    int res;

    if (cmd->argc != 3)
      CONF_ERROR(cmd, "wrong number of parameters");

    preg = pr_regexp_alloc();

    if ((res = regcomp(preg, cmd->argv[2], REG_EXTENDED|REG_NOSUB)) != 0) {
      char errstr[200] = {'\0'};

      regerror(res, preg, errstr, sizeof(errstr));
      pr_regexp_free(preg);

      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", cmd->argv[2], "' failed "
        "regex compilation: ", errstr, NULL));
    }

    /* The first NULL is used as the signal to the {Allow,Deny}Group lookup
     * function to handle the config_rec's contents as a regular expression,
     * rather than a group list.
     */
    c = add_config_param(cmd->argv[0], 2, NULL, preg);
#else
    CONF_ERROR(cmd, "The 'regex' parameter cannot be used on this system, "
      "as you do not have POSIX compliant regex support");
#endif /* HAVE_REGEX_H and HAVE_REGCOMP */
  }

  return HANDLED(cmd);
}

MODRET set_allowdeny(cmd_rec *cmd) {
  int argc;
  char *s,*ent,**argv;
  array_header *acl;
  config_rec *c;

  CHECK_CONF(cmd, CONF_LIMIT);

  /* Syntax: allow [from] [all|none]|host|network[,...] */
  acl = make_array(cmd->tmp_pool,cmd->argc,sizeof(char*));
  argc = cmd->argc-1; argv = cmd->argv;

  /* Skip optional "from" keyword */
  /* ! is allowed in front of a hostmask or IP, but NOT in front of
   * ALL or NONE
   */

  while(argc && *(argv+1)) {
    if (!strcasecmp("from",*(argv+1))) {
      argv++; argc--; continue;
    } else if (!strcasecmp("!all",*(argv+1)) ||
              !strcasecmp("!none",*(argv+1))) {
      CONF_ERROR(cmd,"negation operator (!) cannot be used with ALL/NONE");
    } else if (!strcasecmp("all",*(argv+1))) {
      *((char**)push_array(acl)) = "ALL";
      argc = 0;
    } else if (!strcasecmp("none",*(argv+1))) {
      *((char**)push_array(acl)) = "NONE";
      argc = 0;
    }
    break;
  }

  while(argc-- && *(++argv)) {
    s = pstrdup(cmd->tmp_pool,*argv);

    /* Parse the string into comma-delimited entries */
    while((ent = get_token(&s,",")) != NULL)
      if (*ent) {
        if (!strcasecmp(ent,"all") || !strcasecmp(ent,"none")) {
          acl->nelts = 0; argc = 0; break;
        }

        *((char**)push_array(acl)) = ent;
      }
  }

  if (!acl->nelts)
    CONF_ERROR(cmd,pstrcat(cmd->tmp_pool,"syntax: ", cmd->argv[0] ,
                   " [from] [all|none]|host|network[,...]",NULL));

  c = add_config_param(cmd->argv[0], 0);

  c->argc = acl->nelts;
  c->argv = pcalloc(c->pool, (c->argc+1) * sizeof(char *));
  argv = (char **) c->argv;

  while (acl->nelts--) {
    *argv++ = pstrdup(c->pool, *((char **) acl->elts));
    acl->elts = ((char **)acl->elts) + 1;
  }
  *argv = NULL;

  return HANDLED(cmd);
}

MODRET set_denyall(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 0);
  CHECK_CONF(cmd, CONF_LIMIT|CONF_ANON|CONF_DIR|CONF_DYNDIR);

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = TRUE;

  return HANDLED(cmd);
}

MODRET set_allowall(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 0);
  CHECK_CONF(cmd, CONF_LIMIT|CONF_ANON|CONF_DIR|CONF_DYNDIR);

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = TRUE;

  return HANDLED(cmd);
}

MODRET set_authorder(cmd_rec *cmd) {
  register unsigned int i = 0;
  config_rec *c = NULL;
  array_header *auth_module_order = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  /* Check to see if the directive has already been set */
  if (find_config(cmd->server->conf, CONF_PARAM, "AuthOrder", FALSE))
    CONF_ERROR(cmd, "AuthOrder has already been configured");

  c = add_config_param(cmd->argv[0], 1, NULL);
  auth_module_order = make_array(c->pool, 0, sizeof(char *));

  /* Make sure the given modules exist */
  for (i = 1; i < cmd->argc; i++) {
    if (!module_exists(cmd->argv[i]))
      return ERROR_MSG(cmd, NULL, pstrcat(cmd->tmp_pool,
        cmd->argv[0], ": no such module '", cmd->argv[i], "' installed",
        NULL));

    else
      *((char **) push_array(auth_module_order)) = pstrdup(c->pool,
        cmd->argv[i]);
  }

  c->argv[0] = (void *) auth_module_order;

  return HANDLED(cmd);
}

MODRET end_limit(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 0);
  CHECK_CONF(cmd, CONF_LIMIT);

  end_sub_config();

  return HANDLED(cmd);
}

MODRET set_ignorehidden(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_LIMIT);

  if ((bool = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "expected boolean argument.");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;

  return HANDLED(cmd);
}

MODRET set_displaylogin(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  c = add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_displayconnect(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);

  return HANDLED(cmd);
}

MODRET set_displayfirstchdir(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|CONF_DIR);

  c = add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_displayquit(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  c = add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_displaygoaway(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  c = add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET add_virtualhost(cmd_rec *cmd) {
  server_rec *s = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  /* Specifically block use of "0.0.0.0", as no client will ever be able
   * to use that address, meaning that such a vhost will never be reached.
   *
   * Note: once IPv6 support is added, also check for similar IPv6 versions.
   */
  if (strcmp(cmd->argv[1], "0.0.0.0") == 0)
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "illegal IP address: ",
      cmd->argv[1], NULL));

  if ((s = start_new_server(cmd->argv[1])) == NULL)
    CONF_ERROR(cmd, "unable to create virtual server configuration.");

  return HANDLED(cmd);
}

MODRET end_virtualhost(cmd_rec *cmd) {
  server_rec *s = NULL;
  p_in_addr_t *ipaddr = NULL;
  char *address = NULL;

  CHECK_ARGS(cmd, 0);
  CHECK_CONF(cmd, CONF_VIRTUAL);

  if (cmd->server->ServerAddress)
    address = cmd->server->ServerAddress;
  else
    address = inet_gethostname(cmd->tmp_pool);

  ipaddr = inet_getaddr(cmd->tmp_pool, address);

  /* Check if this server's address/port combination is already being used.
   */
  for (s = (server_rec *) server_list->xas_list; s; s = s->next) {

    /* Have to resort to duplicating some of fixup_servers()'s
     * functionality here, to do this check The Right Way(tm).
     */
    if (s != cmd->server) {
      char *serv_addr = NULL;
      p_in_addr_t *serv_ipaddr = NULL;

      if (s->ServerAddress)
        serv_addr = s->ServerAddress;
      else
        serv_addr = inet_gethostname(cmd->tmp_pool);

      serv_ipaddr = inet_getaddr(cmd->tmp_pool, serv_addr);

      if (ipaddr->s_addr == serv_ipaddr->s_addr &&
          cmd->server->ServerPort == s->ServerPort) {
        log_pri(PR_LOG_ERR, "error: \"%s\" address/port (%s:%d) already in use "
          "by \"%s\"", cmd->server->ServerName,
          inet_ascii(cmd->tmp_pool, ipaddr), cmd->server->ServerPort,
          s->ServerName ? s->ServerName : "ProFTPD");
        CONF_ERROR(cmd, "address/port configuration collision");
      }
    }
  }

  if (!end_new_server())
    CONF_ERROR(cmd, "must have matching <VirtualHost> directive");
    
  return HANDLED(cmd);
}

/* Display a file via a given response numeric.  File is displayed
 * in normal RFC959 multline mode, unless MultilineRFC2228 is set.
 * Returns: -1 on error
 *          0 if file display
 */

int core_display_file(const char *numeric, const char *fn, const char *fs) {
  pr_fh_t *fp = NULL;
  char buf[PR_TUNABLE_BUFFER_SIZE] = {'\0'};
  int len, classes_enabled = 0, *current_clients = NULL;
  unsigned int *max_clients = NULL;
  unsigned char *class_engine = NULL;
  off_t fs_size = 0;
  pool *p;
  xaset_t *s;
  config_rec *c = NULL;
  char *serverfqdn = main_server->ServerFQDN;
  char *outs, *mg_time, mg_size[12] = {'\0'}, mg_max[12] = "unlimited";
  char total_files_in[12] = {'\0'}, total_files_out[12] = {'\0'},
    total_files_xfer[12] = {'\0'};
  char mg_class_limit[12] = {'\0'}, mg_cur[12] = {'\0'},
    mg_xfer_bytes[12] = {'\0'}, mg_cur_class[12] = {'\0'};
  char mg_xfer_units[12] = {'\0'}, config_class_users[128] = {'\0'}, *user;
  unsigned char first = TRUE;

#if defined(HAVE_STATFS) || defined(HAVE_SYS_STATVFS_H) || defined(HAVE_SYS_VFS_H)
  fs_size = pr_fs_getsize((fs ? (char*)fs : (char*)fn));
  snprintf(mg_size, sizeof(mg_size), "%" PR_LU, fs_size);
#else
  snprintf(mg_size, sizeof(mg_size), "%" PR_LU, fs_size);
#endif

  if ((fp = pr_fsio_open_canon(fn, O_RDONLY)) == NULL)
    return -1;

  p = make_sub_pool(permanent_pool);

  s = (session.anon_config ? session.anon_config->subset : main_server->conf);

  mg_time = fmt_time(time(NULL));

  max_clients = get_param_ptr(s, "MaxClients", FALSE);

  current_clients = get_param_ptr(main_server->conf, "CURRENT-CLIENTS", FALSE);

  snprintf(mg_cur, sizeof(mg_cur), "%d", current_clients ? *current_clients: 1);

  class_engine = get_param_ptr(TOPLEVEL_CONF, "Classes", FALSE);

  if (class_engine && *class_engine == TRUE)
    classes_enabled = 1;

  if (classes_enabled && session.class && session.class->name) {
    int *class_users = NULL;

    snprintf(config_class_users, sizeof(config_class_users),
      "CURRENT-CLIENTS-CLASS-%s", session.class->name);

    class_users = get_param_ptr(main_server->conf, config_class_users, FALSE);

    snprintf(mg_cur_class, sizeof(mg_cur_class), "%d",
      class_users ? *class_users : 0);

    snprintf(mg_class_limit, sizeof(mg_class_limit), "%u",
      session.class->max_connections);

  } else {
    mg_cur_class[0] = 0;
    snprintf(mg_class_limit, sizeof(mg_class_limit), "%u",
      max_clients ? *max_clients : 0);
  }

  snprintf(mg_xfer_bytes, sizeof(mg_xfer_bytes), "%" PR_LU,
    session.total_bytes >> 10);
  snprintf(mg_xfer_units, sizeof(mg_xfer_units), "%" PR_LU "B",
    session.total_bytes);

  if (session.total_bytes >= 10240) {
    snprintf(mg_xfer_units, sizeof(mg_xfer_units), "%" PR_LU "kB",
      session.total_bytes >> 10);

  } else if ((session.total_bytes >> 10) >= 10240) {
    snprintf(mg_xfer_units, sizeof(mg_xfer_units), "%" PR_LU "MB",
      session.total_bytes >> 20);

  } else if ((session.total_bytes >> 20) >= 10240) {
    snprintf(mg_xfer_units, sizeof(mg_xfer_units), "%" PR_LU "GB",
      session.total_bytes >> 30);
  }

  snprintf(mg_max, sizeof(mg_max), "%u", max_clients ? *max_clients : 0);

  if ((user = get_param_ptr(main_server->conf, C_USER, FALSE)) == NULL)
    user = "";

  if ((c = find_config(main_server->conf, CONF_PARAM, "MasqueradeAddress",
      FALSE)) != NULL) {
    p_in_addr_t *masq_addr = (p_in_addr_t *) c->argv[0];
    serverfqdn = inet_getname(main_server->pool, masq_addr);
  }

  /* "Stringify" the file number for this session. */
  snprintf(total_files_in, sizeof(total_files_in), "%u",
    session.total_files_in);
  total_files_in[sizeof(total_files_in)-1] = '\0';

  snprintf(total_files_out, sizeof(total_files_out), "%u",
    session.total_files_out);
  total_files_out[sizeof(total_files_out)-1] = '\0';

  snprintf(total_files_xfer, sizeof(total_files_xfer), "%u",
    session.total_files_xfer);
  total_files_xfer[sizeof(total_files_xfer)-1] = '\0';

  while (pr_fsio_gets(buf, sizeof(buf), fp) != NULL) {
    buf[sizeof(buf)-1] = '\0';

    len = strlen(buf);

    while(len && (buf[len-1] == '\r' || buf[len-1] == '\n')) {
      buf[len-1] = '\0';
      len--;
    }

    outs = sreplace(p, buf,
      "%C", (session.cwd[0] ? session.cwd : "(none)"),
      "%E", main_server->ServerAdmin,
      "%F", mg_size,
      "%i", total_files_in,
      "%K", mg_xfer_bytes,
      "%k", mg_xfer_units,
      "%L", serverfqdn,
      "%M", mg_max,
      "%N", mg_cur,
      "%o", total_files_out,
      "%R", (session.c && session.c->remote_name ?
        session.c->remote_name : "(unknown)"),
      "%T", mg_time,
      "%t", total_files_xfer,
      "%U", user,
      "%u", session.ident_user,
      "%V", main_server->ServerName,
      "%x", (classes_enabled && session.class) ?  session.class->name : "",
      "%y", mg_cur_class,
      "%z", mg_class_limit,
      NULL);

    if (first) {
      pr_response_send_raw("%s-%s", numeric, outs);
      first = FALSE;

    } else {
      if (MultilineRFC2228)
        pr_response_send_raw("%s-%s", numeric, outs);
      else
        pr_response_send_raw(" %s", outs);
    }
  }

  pr_fsio_close(fp);
  return 0;
}

#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
MODRET regex_filters(cmd_rec *cmd) {
  regex_t *allow_regex = NULL, *deny_regex = NULL;

  /* Don't apply the filter checks to passwords (arguments to the PASS
   * command).
   */
  if (strcasecmp(cmd->argv[0], C_PASS) == 0)
    return DECLINED(cmd);

  /* Check for an AllowFilter */
  allow_regex = get_param_ptr(CURRENT_CONF, "AllowFilter", FALSE);

  if (allow_regex && cmd->arg &&
      regexec(allow_regex, cmd->arg, 0, NULL, 0) != 0) {
    log_debug(DEBUG2, "'%s %s' denied by AllowFilter", cmd->argv[0],
      cmd->arg);
    pr_response_add_err(R_550, "%s: Forbidden command argument", cmd->arg);
    return ERROR(cmd);
  }

  /* Check for a DenyFilter */
  deny_regex = get_param_ptr(CURRENT_CONF, "DenyFilter", FALSE);

  if (deny_regex && cmd->arg &&
      regexec(deny_regex, cmd->arg, 0, NULL, 0) == 0) {
    log_debug(DEBUG2, "'%s %s' denied by DenyFilter", cmd->argv[0],
      cmd->arg);
    pr_response_add_err(R_550, "%s: Forbidden command argument", cmd->arg);
    return ERROR(cmd);
  }

  return DECLINED(cmd);
}
#endif /* HAVE_REGEX_H && HAVE_REGCOMP */

MODRET core_clear_fs(cmd_rec *cmd) {
  /* Make sure any FS caches are clear before each command. */
  pr_fs_clear_cache();

  return DECLINED(cmd);
}

MODRET core_quit(cmd_rec *cmd) {
  char *display = NULL;

  if (session.sf_flags & SF_ANON)
    display = (char *)get_param_ptr(session.anon_config->subset,
      "DisplayQuit", FALSE);

  if (!display)
    display = (char *)get_param_ptr(cmd->server->conf, "DisplayQuit", FALSE);

  if (display) {
    core_display_file(R_221, display, NULL);

    /* Hack or feature, core_display_file() always puts a hyphen on the
     * last line
     */
    pr_response_send(R_221, "%s", "");

  } else
    pr_response_send(R_221, "Goodbye.");

#ifndef DEVEL_NO_DAEMON
  end_login(0);
#endif

  /* Even though end_login() does not return, this is necessary to avoid
   * compiler warnings.
   */
  return HANDLED(cmd);
}

/* per RFC959, directory responses for MKD and PWD should be
 * "dir_name" (w/ quote).  For directories that CONTAIN quotes,
 * the add'l quotes must be duplicated.
 */

static char *quote_dir(cmd_rec *cmd, char *dir) {
  return sreplace(cmd->tmp_pool,dir,"\"","\"\"",NULL);
}

MODRET core_pwd(cmd_rec *cmd) {
  CHECK_CMD_ARGS(cmd, 1);

  if (!dir_check(cmd->tmp_pool, cmd->argv[0], cmd->group, session.vwd, NULL)) {
    pr_response_add_err(R_550, "%s: %s", cmd->argv[0], strerror(errno));
    return ERROR(cmd);
  }

  pr_response_add(R_257,"\"%s\" is current directory.",
    quote_dir(cmd, session.vwd));

  return HANDLED(cmd);
}

MODRET core_pasv(cmd_rec *cmd) {
  union {
    p_in_addr_t addr;
    unsigned char u[4];
  } addr;

  union {
    unsigned short port;
    unsigned char u[2];
  } port;

  config_rec *c = NULL;

  CHECK_CMD_ARGS(cmd, 1);

  /* If we already have a passive listen data connection open, kill it. */
  if (session.d) {
    inet_close(session.d->pool, session.d);
    session.d = NULL;
  }

  if ((c = find_config(main_server->conf, CONF_PARAM, "PassivePorts",
      FALSE)) != NULL) {
    int pasv_min_port = *((int *) c->argv[0]);
    int pasv_max_port = *((int *) c->argv[1]);

    if (!(session.d = inet_create_connection_portrange(session.pool,
        NULL, session.c->local_ipaddr, pasv_min_port, pasv_max_port))) {

      /* If not able to open a passive port in the given range, default to
       * normal behavior (using INPORT_ANY), and log the failure.  This
       * indicates a too-small range configuration.
       */
      log_pri(PR_LOG_WARNING, "unable to find open port in PassivePorts range "
              "%d-%d: defaulting to INPORT_ANY", pasv_min_port, pasv_max_port);
    }
  }

  /* Open up the connection and pass it back. */
  if (!session.d)
    session.d = inet_create_connection(session.pool, NULL, -1,
      session.c->local_ipaddr, INPORT_ANY, FALSE);

  if (!session.d) {
    pr_response_add_err(R_425, "Unable to build data connection: "
      "Internal error");
    return ERROR(cmd);
  }

  inet_setblock(session.pool, session.d);
  inet_listen(session.pool, session.d, 1);

  session.d->instrm = pr_netio_open(session.pool, PR_NETIO_STRM_DATA,
    session.d->listen_fd, PR_NETIO_IO_RD);

  /* Now tell the client our address/port */
  session.data_port = session.d->local_port;
  session.sf_flags |= SF_PASSIVE;

  addr.addr = *session.d->local_ipaddr;

  /* Check for a MasqueradeAddress configuration record, and return that
   * addr if appropriate.
   */
  if ((c = find_config(main_server->conf, CONF_PARAM, "MasqueradeAddress",
      FALSE)) != NULL)
   addr.addr = *((p_in_addr_t *) c->argv[0]);

  port.port = htons(session.data_port);

  log_debug(DEBUG1,"Entering Passive Mode (%u,%u,%u,%u,%u,%u).",
            (int)addr.u[0],(int)addr.u[1],(int)addr.u[2],
            (int)addr.u[3],(int)port.u[0],(int)port.u[1]);

  pr_response_add(R_227, "Entering Passive Mode (%u,%u,%u,%u,%u,%u).",
               (int)addr.u[0],(int)addr.u[1],(int)addr.u[2],
               (int)addr.u[3],(int)port.u[0],(int)port.u[1]);

  return HANDLED(cmd);
}

MODRET core_port(cmd_rec *cmd) {
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
  unsigned char *allow_foreign_addr = NULL;

  CHECK_CMD_ARGS(cmd, 2);

  /* Format is h1,h2,h3,h4,p1,p2 (ASCII in network order) */
  a = pstrdup(cmd->tmp_pool,cmd->argv[1]);

  while(a && *a && cnt < 6) {
    arg = strsep(&a,",");

    if (!arg && a && *a) {
      arg = a;
      a = NULL;
    } else if (!arg)
      break;

    i = strtol(arg,&endp,10);
    if (*endp || i < 0 || i > 255)
      break;

    if (cnt < 4)
      addr.u[cnt++] = (unsigned char)i;
    else
      port.u[cnt++ - 4] = (unsigned char)i;
  }

  if (cnt != 6 || (a && *a)) {
    pr_response_add_err(R_501, "Illegal PORT command");
    return ERROR(cmd);
  }

  /* Make sure that the address specified matches the address from which
   * the control connection is coming.
   */

  allow_foreign_addr = get_param_ptr(TOPLEVEL_CONF, "AllowForeignAddress",
    FALSE);

  if (allow_foreign_addr && *allow_foreign_addr == FALSE) {
    if (addr.addr.s_addr != session.c->remote_ipaddr->s_addr || !port.port) {
      log_pri(PR_LOG_WARNING, "Refused PORT %s (address mismatch)", cmd->arg);
      pr_response_add_err(R_500, "Illegal PORT command");
      return ERROR(cmd);
    }
  }

  /* Additionally, make sure that the port number used is a "high
   * numbered" port, to avoid bounce attacks
   */

  if (ntohs(port.port) < 1024) {
    log_pri(PR_LOG_WARNING, "Refused PORT %s (bounce attack)", cmd->arg);
    pr_response_add_err(R_500, "Illegal PORT command");
    return ERROR(cmd);
  }

  memcpy(&session.data_addr, &addr.addr, sizeof(session.data_addr));
  session.data_port = ntohs(port.port);
  session.sf_flags &= (SF_ALL^SF_PASSIVE);

  /* If we already have a data connection open, kill it. */
  if (session.d) {
    inet_close(session.d->pool, session.d);
    session.d = NULL;
  }

  session.sf_flags |= SF_PORT;
  pr_response_add(R_200, "PORT command successful");

  return HANDLED(cmd);
}

MODRET core_help(cmd_rec *cmd) {
  int i,c = 0;
  char buf[9] = {'\0'};

  if (cmd->argc == 1) {
    /* Print help for all commands */
    char *outa[8];
    char *outs = "";

    memset(outa, '\0', sizeof(outa));

    pr_response_add(R_214,
      "The following commands are recognized (* =>'s unimplemented).");
    for (i = 0; _help[i].cmd; i++) {

      if (_help[i].implemented)
        outa[c++] = _help[i].cmd;
      else
        outa[c++] = pstrcat(cmd->tmp_pool,_help[i].cmd,"*",NULL);

      /* 8 rows */
      if (((i+1) % 8 == 0) || !_help[i+1].cmd) {
        int j;

        for (j = 0; j < 8; j++) {
          if (outa[j]) {
            snprintf(buf, sizeof(buf), "%-8s",outa[j]);
            buf[sizeof(buf)-1] = '\0';
            outs = pstrcat(cmd->tmp_pool,outs,buf,NULL);
          } else
            break;
        }

        if (*outs)
          pr_response_add(R_214, "%s", outs);
        outs = "";
        c = 0;
        memset(outa, '\0', sizeof(outa));
      }
    }

    pr_response_add(R_214,"Direct comments to %s.",
                         (cmd->server->ServerAdmin ? cmd->server->ServerAdmin :
                          "ftp-admin"));
  } else {
    char *cp;

    for (cp = cmd->argv[1]; *cp; cp++)
      *cp = toupper(*cp);

    if (!strcasecmp(cmd->argv[1],"SITE"))
      return call_module(&site_module,site_dispatch,cmd);

    for (i = 0; _help[i].cmd; i++)
      if (!strcasecmp(cmd->argv[1],_help[i].cmd)) {
        pr_response_add(R_214, "Syntax: %s %s", cmd->argv[1], _help[i].syntax);
        return HANDLED(cmd);
      }

    pr_response_add_err(R_502, "Unknown command '%s'.", cmd->argv[1]);
    return ERROR(cmd);
  }

  return HANDLED(cmd);
}

MODRET core_syst(cmd_rec *cmd) {
  pr_response_add(R_215, "UNIX Type: L8");
  return HANDLED(cmd);
}

int core_chgrp(cmd_rec *cmd, char *dir, uid_t uid, gid_t gid) {
  if (!dir_check(cmd->tmp_pool, "SITE_CHGRP", "WRITE", dir, NULL))
    return -1;

  return pr_fsio_chown(dir, uid, gid);
}

int core_chmod(cmd_rec *cmd, char *dir, mode_t mode) {
  if (!dir_check(cmd->tmp_pool, "SITE_CHMOD", "WRITE", dir, NULL))
    return -1;

  return pr_fsio_chmod(dir,mode);
}

MODRET _chdir(cmd_rec *cmd,char *ndir) {
  char *display = NULL;
  char *dir,*odir,*cdir;
  config_rec *cdpath;
  unsigned char show_symlinks = TRUE, *tmp = NULL;

  odir = ndir;

  if ((tmp = get_param_ptr(TOPLEVEL_CONF, "ShowSymlinks",
      FALSE)) != NULL)
    show_symlinks = *tmp;

  if (show_symlinks) {
    dir = dir_realpath(cmd->tmp_pool,ndir);

    if (!dir || !dir_check_full(cmd->tmp_pool,cmd->argv[0],cmd->group,dir,NULL) ||
        pr_fsio_chdir(dir, 0) == -1) {
      for (cdpath = find_config(main_server->conf,CONF_PARAM,"CDPath",TRUE);
          cdpath != NULL; cdpath =
            find_config_next(cdpath,cdpath->next,CONF_PARAM,"CDPath",TRUE)) {
        cdir = (char *) malloc(strlen(cdpath->argv[0]) + strlen(ndir) + 2);
        snprintf(cdir, strlen(cdpath->argv[0]) + strlen(ndir) + 2,
                 "%s%s%s", (char *) cdpath->argv[0],
                 ((char *) cdpath->argv[0])[strlen(cdpath->argv[0]) - 1] == '/' ? "" : "/",
                 ndir);
        dir = dir_realpath(cmd->tmp_pool,cdir);
        free(cdir);
        if (dir &&
           dir_check_full(cmd->tmp_pool,cmd->argv[0],cmd->group,dir,NULL) &&
           pr_fsio_chdir(dir, 0) != -1) {
          break;
        }
      }
      if (!cdpath) {
        pr_response_add_err(R_550, "%s: %s", odir, strerror(errno));
        return ERROR(cmd);
      }
    }
  } else {
    /* virtualize the chdir */
    ndir = dir_canonical_vpath(cmd->tmp_pool,ndir);
    dir = dir_realpath(cmd->tmp_pool,ndir);

    if (!dir || !dir_check_full(cmd->tmp_pool,cmd->argv[0],cmd->group,dir,NULL) ||
        pr_fsio_chdir_canon(ndir, 1) == -1) {

      for (cdpath = find_config(main_server->conf,CONF_PARAM,"CDPath",TRUE);
          cdpath != NULL; cdpath =
            find_config_next(cdpath,cdpath->next,CONF_PARAM,"CDPath",TRUE)) {
        cdir = (char *) malloc(strlen(cdpath->argv[0]) + strlen(ndir) + 2);
        snprintf(cdir, strlen(cdpath->argv[0]) + strlen(ndir) + 2,
                 "%s%s%s", (char *) cdpath->argv[0],
                ((char *)cdpath->argv[0])[strlen(cdpath->argv[0]) - 1] == '/' ? "" : "/",
                ndir);
        ndir = dir_canonical_vpath(cmd->tmp_pool,cdir);
        dir = dir_realpath(cmd->tmp_pool,ndir);
        free(cdir);
        if (dir &&
           dir_check_full(cmd->tmp_pool,cmd->argv[0],cmd->group,dir,NULL) &&
           pr_fsio_chdir_canon(ndir, 1) != -1) {
          break;
        }
      }
      if (!cdpath) {
        pr_response_add_err(R_550, "%s: %s", odir, strerror(errno));
        return ERROR(cmd);
      }
    }
  }

  sstrncpy(session.cwd, pr_fs_getcwd(), sizeof(session.cwd));
  sstrncpy(session.vwd, pr_fs_getvwd(), sizeof(session.vwd));

  pr_scoreboard_update_entry(getpid(),
    PR_SCORE_CWD, session.cwd,
    NULL);

  if (session.dir_config)
    display = (char*)get_param_ptr(session.dir_config->subset,
                                   "DisplayFirstChdir",FALSE);
  if (!display && session.anon_config)
    display = (char*)get_param_ptr(session.anon_config->subset,
                                   "DisplayFirstChdir",FALSE);
  if (!display)
    display = (char*)get_param_ptr(cmd->server->conf,
                                   "DisplayFirstChdir",FALSE);

  if (display) {
    config_rec *c;
    time_t last;
    struct stat sbuf;

    c = find_config(cmd->server->conf,CONF_USERDATA,session.cwd,FALSE);

    if (!c) {
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

    if (pr_fsio_stat(display, &sbuf) != -1 && !S_ISDIR(sbuf.st_mode) &&
       sbuf.st_mtime > last)
      core_display_file(R_250, display, session.cwd);
  }

  pr_response_add(R_250,"%s command successful.", cmd->argv[0]);
  return HANDLED(cmd);
}

MODRET core_rmd(cmd_rec *cmd) {
  char *dir;
#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  regex_t *preg;
#endif

  CHECK_CMD_MIN_ARGS(cmd, 2);

#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  preg = (regex_t *) get_param_ptr(TOPLEVEL_CONF, "PathAllowFilter", FALSE);

  if (preg && regexec(preg, cmd->arg, 0, NULL, 0) != 0) {
    log_debug(DEBUG2, "'%s %s' denied by PathAllowFilter", cmd->argv[0],
      cmd->arg);
    pr_response_add_err(R_550,"%s: Forbidden filename",cmd->arg);
    return ERROR(cmd);
  }

  preg = (regex_t *) get_param_ptr(TOPLEVEL_CONF, "PathDenyFilter", FALSE);

  if (preg && regexec(preg, cmd->arg, 0, NULL, 0) == 0) {
    log_debug(DEBUG2, "'%s %s' denied by PathDenyFilter", cmd->argv[0],
      cmd->arg);
    pr_response_add_err(R_550, "%s: Forbidden filename", cmd->arg);
    return ERROR(cmd);
  }
#endif

  /* If told to rmdir a symlink to a directory, don't;
     you can't rmdir a symlink, you delete it.  */
  dir = dir_canonical_path(cmd->tmp_pool,cmd->arg);

  if (!dir || !dir_check(cmd->tmp_pool,cmd->argv[0],cmd->group,dir,NULL) ||
     pr_fsio_rmdir(dir) == -1) {
    pr_response_add_err(R_550,"%s: %s",cmd->arg,strerror(errno));
    return ERROR(cmd);
  } else
    pr_response_add(R_250,"%s command successful.",cmd->argv[0]);

  return HANDLED(cmd);
}

MODRET core_mkd(cmd_rec *cmd) {
  char *dir;
  struct stat sbuf;
#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  regex_t *preg;
#endif

  CHECK_CMD_MIN_ARGS(cmd, 2);

  if (strchr(cmd->arg, '*')) {
    pr_response_add_err(R_550, "%s: Invalid directory name", cmd->argv[1]);
    return ERROR(cmd);
  }

#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
    preg = (regex_t *) get_param_ptr(TOPLEVEL_CONF, "PathAllowFilter", FALSE);

    if (preg && regexec(preg, cmd->arg, 0, NULL, 0) != 0) {
      log_debug(DEBUG2, "'%s %s' denied by PathAllowFilter", cmd->argv[0],
        cmd->arg);
      pr_response_add_err(R_550, "%s: Forbidden filename", cmd->arg);
      return ERROR(cmd);
    }

    preg = (regex_t *) get_param_ptr(TOPLEVEL_CONF, "PathDenyFilter", FALSE);

    if (preg && regexec(preg, cmd->arg, 0, NULL, 0) == 0) {
      log_debug(DEBUG2, "'%s %s' denied by PathDenyFilter", cmd->argv[0],
        cmd->arg);
      pr_response_add_err(R_550, "%s: Forbidden filename", cmd->arg);
      return ERROR(cmd);
    }
#endif

  dir = dir_canonical_path(cmd->tmp_pool,cmd->arg);

  if (!dir ||
      !dir_check_canon(cmd->tmp_pool, cmd->argv[0], cmd->group,dir, NULL) ||
       pr_fsio_mkdir(dir, 0777) == -1) {
    pr_response_add_err(R_550, "%s: %s", cmd->argv[1], strerror(errno));
    return ERROR(cmd);

  } else {
    if (session.fsuid != (uid_t) -1) {
      int err = 0,iserr = 0;

      pr_fsio_stat(dir, &sbuf);

      PRIVS_ROOT
      if (pr_fsio_chown(dir, session.fsuid, session.fsgid) == -1) {
        iserr++;
        err = errno;
      }
      PRIVS_RELINQUISH

      if (iserr)
        log_pri(PR_LOG_WARNING, "chown() as root failed: %s", strerror(err));

      else {
        if (session.fsgid != (gid_t) -1)
          log_debug(DEBUG2, "root chown(%s) to uid %lu, gid %lu successful",
            dir, (unsigned long) session.fsuid, (unsigned long) session.fsgid);

        else
          log_debug(DEBUG2, "root chown(%s) to uid %lu successful", dir,
            (unsigned long) session.fsuid);
      }

    } else if (session.fsgid != (gid_t) -1) {
      pr_fsio_stat(dir, &sbuf);

      if (pr_fsio_chown(dir, (uid_t) -1, session.fsgid) == -1)
        log_pri(PR_LOG_WARNING, "chown() failed: %s", strerror(errno));

      else
        log_debug(DEBUG2, "chown(%s) to gid %lu successful", dir,
          (unsigned long) session.fsgid);
    }

    pr_response_add(R_257, "\"%s\" - Directory successfully created",
      quote_dir(cmd, dir));
  }

  return HANDLED(cmd);
}

MODRET core_cwd(cmd_rec *cmd) {
  CHECK_CMD_MIN_ARGS(cmd, 2);
  return _chdir(cmd,cmd->arg);
}

MODRET core_cdup(cmd_rec *cmd) {
  CHECK_CMD_ARGS(cmd, 1);
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

MODRET core_mdtm(cmd_rec *cmd) {
  char *path;
  char buf[16] = {'\0'};
  struct tm *tm;
  struct stat sbuf;

  CHECK_CMD_MIN_ARGS(cmd, 2);

  path = dir_realpath(cmd->tmp_pool,cmd->arg);

  if (!path || !dir_check(cmd->tmp_pool,cmd->argv[0],cmd->group,path,NULL) ||
     pr_fsio_stat(path, &sbuf) == -1) {
    pr_response_add_err(R_550,"%s: %s",cmd->argv[1],strerror(errno));
    return ERROR(cmd);

  } else {

    if (!S_ISREG(sbuf.st_mode)) {
      pr_response_add_err(R_550,"%s: not a plain file.",cmd->argv[1]);
      return ERROR(cmd);

    } else {
      unsigned char *times_gmt = get_param_ptr(TOPLEVEL_CONF,
        "TimesGMT", FALSE);

      if (times_gmt && *times_gmt == TRUE)
         tm = gmtime(&sbuf.st_mtime);
      else
         tm = localtime(&sbuf.st_mtime);

      if (tm)
        snprintf(buf, sizeof(buf), "%04d%02d%02d%02d%02d%02d",
                tm->tm_year+1900,tm->tm_mon+1,tm->tm_mday,
                tm->tm_hour,tm->tm_min,tm->tm_sec);
      else
        snprintf(buf, sizeof(buf), "00000000000000");

      pr_response_add(R_213, "%s", buf);
    }
  }

  return HANDLED(cmd);
}

MODRET core_size(cmd_rec *cmd) {
  char *path;
  struct stat sbuf;

  CHECK_CMD_MIN_ARGS(cmd, 2);

  path = dir_realpath(cmd->tmp_pool,cmd->arg);

  if (!path ||
      !dir_check(cmd->tmp_pool, cmd->argv[0], cmd->group, path, NULL) ||
      pr_fsio_stat(path, &sbuf) == -1) {
    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(errno));
    return ERROR(cmd);

  } else {
    if (!S_ISREG(sbuf.st_mode)) {
      pr_response_add_err(R_550, "%s: not a regular file", cmd->arg);
      return ERROR(cmd);
    }
    else
      pr_response_add(R_213, "%" PR_LU, sbuf.st_size);
  }

  return HANDLED(cmd);
}

MODRET core_dele(cmd_rec *cmd) {
  char *path, *fullpath;
  struct stat st;

#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  regex_t *preg;
#endif

  CHECK_CMD_MIN_ARGS(cmd, 2);

#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  preg = (regex_t *) get_param_ptr(TOPLEVEL_CONF, "PathAllowFilter", FALSE);

  if (preg && regexec(preg, cmd->arg, 0, NULL, 0) != 0) {
    log_debug(DEBUG2, "'%s %s' denied by PathAllowFilter", cmd->argv[0],
      cmd->arg);
    pr_response_add_err(R_550, "%s: Forbidden filename", cmd->arg);
    return ERROR(cmd);
  }

  preg = (regex_t *) get_param_ptr(TOPLEVEL_CONF, "PathDenyFilter", FALSE);

  if (preg && regexec(preg, cmd->arg, 0, NULL, 0) == 0) {
    log_debug(DEBUG2, "'%s %s' denied by PathDenyFilter", cmd->argv[0],
      cmd->arg);
    pr_response_add_err(R_550, "%s: Forbidden filename", cmd->arg);
    return ERROR(cmd);
  }
#endif

  /* If told to delete a symlink, don't delete the file it points to!  */
  path = dir_canonical_path(cmd->tmp_pool, cmd->arg);

  /* Stat the path, before it is deleted, so that the size of the file
   * being deleted can be logged.
   */
  pr_fs_clear_cache();
  pr_fsio_stat(path, &st);

  if (!path ||
     !dir_check(cmd->tmp_pool, cmd->argv[0], cmd->group, path, NULL) ||
     pr_fsio_unlink(path) == -1) {
    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(errno));
    return ERROR(cmd);
  }

  fullpath = dir_abs_path(cmd->tmp_pool, cmd->arg, TRUE);

  if (session.sf_flags & SF_ANON) {
    log_xfer(0, session.c->remote_name, st.st_size, fullpath,
      (session.sf_flags & SF_ASCII ? 'a' : 'b'), 'd', 'a', session.anon_user,
      'c');

  } else {
    log_xfer(0, session.c->remote_name, st.st_size, fullpath,
      (session.sf_flags & SF_ASCII ? 'a' : 'b'), 'd', 'r', session.user, 'c');
  }

  pr_response_add(R_250, "%s command successful.", cmd->argv[0]);
  return HANDLED(cmd);
}

MODRET core_rnto(cmd_rec *cmd) {
  char *path;
  unsigned char *allow_overwrite = NULL;
  struct stat st;

#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  regex_t *preg;
#endif

  CHECK_CMD_MIN_ARGS(cmd, 2);

  if (!session.xfer.path) {
    if (session.xfer.p) {
      destroy_pool(session.xfer.p);
      memset(&session.xfer, '\0', sizeof(session.xfer));
    }

    pr_response_add_err(R_503, "Bad sequence of commands");
    return ERROR(cmd);
  }

#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  preg = (regex_t *) get_param_ptr(TOPLEVEL_CONF, "PathAllowFilter", FALSE);

  if (preg && regexec(preg, cmd->arg, 0, NULL, 0) != 0) {
    log_debug(DEBUG2, "'%s %s' denied by PathAllowFilter", cmd->argv[0],
      cmd->arg);
    pr_response_add_err(R_550, "%s: Forbidden filename", cmd->arg);
    destroy_pool(session.xfer.p);
    memset(&session.xfer, '\0', sizeof(session.xfer));

    return ERROR(cmd);
  }

  preg = (regex_t *) get_param_ptr(TOPLEVEL_CONF, "PathDenyFilter", FALSE);

  if (preg && regexec(preg, cmd->arg, 0, NULL, 0) == 0) {
    log_debug(DEBUG2, "'%s %s' denied by PathDenyFilter", cmd->argv[0],
      cmd->arg);
    pr_response_add_err(R_550, "%s: Forbidden filename", cmd->arg);
    destroy_pool(session.xfer.p);
    memset(&session.xfer, '\0', sizeof(session.xfer));

    return ERROR(cmd);
  }
#endif

  path = dir_canonical_path(cmd->tmp_pool, cmd->arg);

  allow_overwrite = get_param_ptr(CURRENT_CONF, "AllowOverwrite", FALSE);

  /* Deny the rename if AllowOverwrites are not allowed, and the destination
   * rename file already exists.
   */
  if ((!allow_overwrite || *allow_overwrite == FALSE) &&
      pr_fsio_stat(path, &st) == 0) {
    log_debug(DEBUG6, "AllowOverwrite denied permission for %s", cmd->arg);
    pr_response_add_err(R_550, "%s: Rename permission denied", cmd->arg);
    return ERROR(cmd);
  }

  if (!path || !dir_check_canon(cmd->tmp_pool,cmd->argv[0],cmd->group,path,NULL)
     || pr_fsio_rename(session.xfer.path, path) == -1) {
    pr_response_add_err(R_550, "Rename: %s", strerror(errno));
    destroy_pool(session.xfer.p);
    memset(&session.xfer, '\0', sizeof(session.xfer));

    return ERROR(cmd);
  }

  pr_response_add(R_250, "Rename successful");

  destroy_pool(session.xfer.p);
  memset(&session.xfer, '\0', sizeof(session.xfer));

  return HANDLED(cmd);
}

MODRET core_rnfr(cmd_rec *cmd) {
  char *path;
#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  regex_t *preg;
#endif

  CHECK_CMD_MIN_ARGS(cmd, 2);

#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  preg = (regex_t *) get_param_ptr(TOPLEVEL_CONF, "PathAllowFilter", FALSE);

  if (preg && regexec(preg, cmd->arg, 0, NULL, 0) != 0) {
    log_debug(DEBUG2, "'%s %s' denied by PathAllowFilter", cmd->argv[0],
      cmd->arg);
    pr_response_add_err(R_550, "%s: Forbidden filename", cmd->arg);
    return ERROR(cmd);
  }

  preg = (regex_t *) get_param_ptr(TOPLEVEL_CONF, "PathDenyFilter", FALSE);

  if (preg && regexec(preg, cmd->arg, 0, NULL, 0) == 0) {
    log_debug(DEBUG2, "'%s %s' denied by PathDenyFilter", cmd->argv[0],
      cmd->arg);
    pr_response_add_err(R_550, "%s: Forbidden filename", cmd->arg);
    return ERROR(cmd);
  }
#endif

  /* Allow renaming a symlink, even a dangling one.  */
  path = dir_canonical_path(cmd->tmp_pool,cmd->arg);

  if (!path || !dir_check(cmd->tmp_pool,cmd->argv[0],cmd->group,path,NULL) ||
     !exists(path)) {
    pr_response_add_err(R_550, "%s: %s", cmd->argv[1], strerror(errno));
    return ERROR(cmd);
  }

  /* We store the path in session.xfer.path */
  if (session.xfer.p) {
    destroy_pool(session.xfer.p);
    memset(&session.xfer, '\0', sizeof(session.xfer));
  }

  session.xfer.p = make_sub_pool(session.pool);
  session.xfer.path = pstrdup(session.xfer.p,path);
  pr_response_add(R_350, "File or directory exists, ready for destination name.");

  return HANDLED(cmd);
}

MODRET core_noop(cmd_rec *cmd) {
  pr_response_add(R_200, "NOOP command successful");
  return HANDLED(cmd);
}

MODRET core_feat(cmd_rec *cmd) {
  const char *feat = NULL;
  CHECK_CMD_ARGS(cmd, 1);

  pr_response_add(R_211, "Features:");

  feat = pr_feat_get();

  while (feat) {
    pr_response_add(R_DUP, " %s", feat);
    feat = pr_feat_get_next();
  }

  pr_response_add(R_DUP, "End");
  return HANDLED(cmd);
}

MODRET core_opts(cmd_rec *cmd) {
  char *opts_cmd = NULL, *cp = NULL;

  /* This is an ugly command to implement.
   */

  CHECK_CMD_MIN_ARGS(cmd, 2);

  /* First, check to see if the FTP command given is supported.  This involves
   * scanning through the master cmdtab for a CMD handler for that command.
   * Make sure to check for the command in an all-uppercase fashion.
   */

  opts_cmd = pstrdup(cmd->tmp_pool, cmd->argv[1]);

  for (cp = opts_cmd; *cp; cp++)
    *cp = toupper(*cp);

  if (!command_exists(opts_cmd)) {
    pr_response_add_err(R_501, "%s: %s not understood", cmd->argv[0],
      cmd->argv[1]);
    return ERROR(cmd);
  }

  /* If the command is valid, process any possible options that may have
   * been specified by the client.  At the moment, only the LIST and NLST
   * commands are capable of supporting options specified via OPTS.  Note
   * this is our interpretation of the reality of the situation; RFC959
   * does not officially sanction the /bin/ls switches often used by clients
   * when requesting listings.  No clients, as far as I know, use OPTS for
   * specifying options to LIST/NLST.
   *
   * NOTE: this hasn't been implemented yet. For now, if any options are
   * given, fail the command.
   */

  if (cmd->argc == 3) {
    pr_response_add_err(R_501, "%s: %s options '%s' not understood",
      cmd->argv[0], cmd->argv[1], cmd->argv[2]);
    return ERROR(cmd);
  }

  pr_response_add(R_200, "%s command successful", cmd->argv[0]);
  return HANDLED(cmd);
}

MODRET set_defaulttransfermode(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (strcasecmp(cmd->argv[1], "ascii") != 0 &&
      strcasecmp(cmd->argv[1], "binary") != 0)
    CONF_ERROR(cmd, "parameter must be 'ascii' or 'binary'.");

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);

  return HANDLED(cmd);
}

MODRET set_deferwelcome(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((bool = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;

  return HANDLED(cmd);
}

MODRET set_classes(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  if ((bool = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

static cdir_t *cdir_list = NULL;
static class_t *class_list = NULL;
static hostname_t *hostname_list = NULL;

static hostname_t *add_hostname(class_t *class, char *name)
{
        hostname_t *n;

        n = calloc(1, sizeof(hostname_t));
        n->hostname = strdup(name);
        n->next = hostname_list;
        n->class = class;
        hostname_list = n;
        return n;
}

static hostname_t *find_hostname(char *name)
{
  hostname_t *i;

  for (i = hostname_list; i != NULL; i = i->next)
    if (strcasecmp(i->hostname,name) == 0)
      return i;
  return NULL;
}

static cdir_t *add_cdir(class_t *class, u_int_32 address, u_int_8 netmask)
{
  cdir_t *n;

  n = calloc(1, sizeof(cdir_t));

  n->class = class;
  while (netmask--) {
    n->netmask >>= 1;
    n->netmask |= 0x80000000;
  }
  n->address = address & n->netmask;

  n->next = cdir_list;
  cdir_list = n;

  return n;
}

static cdir_t *find_cdir(u_int_32 address)
{
  cdir_t *c, *f;

  c = cdir_list;
  f = NULL;
  while (c) {
    /* within cdir range ? && more specific netmask ? */
    if (((address & c->netmask) == c->address) && (f == NULL || (f && (f->netmask < c->netmask))))
      f = c;

    c = c->next;
  }

  return f;
}

static class_t *add_class(char *name)
{
  class_t *n;

  n = calloc(1, sizeof(class_t));

  n->name = strdup(name);
  n->max_connections = 100;

  n->next = class_list;
  class_list = n;

  return n;
}

static class_t *get_class(char *name)
{
  class_t *c;

  c = class_list;
  while (c) {
    if (name && strcasecmp(name, c->name) == 0)
      return c;

    c = c->next;
  }

  return NULL;
}

class_t *find_class(p_in_addr_t *addr, char *remote_name)
{
  cdir_t *ip;
  hostname_t *host;
  class_t *c, *f;

  if ((ip = find_cdir(ntohl(addr->s_addr))) != NULL)
    return ip->class;

  if ((host = find_hostname(remote_name)) != NULL)
    return host->class;
  if ((host = find_hostname(inet_ntoa(*addr))) != NULL)
    return host->class;

  c = class_list;
  f = NULL;
  while (c) {
    if (c->preg && (regexec(c->preg, remote_name, 0, NULL, 0)) == 0)
      if (f == NULL || (f && f->max_connections < c->max_connections))
        f = c;
    c = c->next;
  }
  if (f)
    return f;
  else
    return get_class("default");
}

MODRET set_class(cmd_rec *cmd) {
  int bits, ret;
  class_t *n;
  p_in_addr_t *res;
  char *ptr, ipaddress[20] = {'\0'}, errmsg[80] = {'\0'};
  unsigned char *class_engine = NULL;
#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  regex_t *preg;
#endif

  CHECK_ARGS(cmd,3);
  CHECK_CONF(cmd,CONF_ROOT);

  /* Check to see that Classes have been enabled, and issue a warning
   * if not enabled.
   */
  class_engine = get_param_ptr(cmd->server->conf, "Classes", FALSE);

  if (!class_engine || *class_engine == FALSE)
    log_pri(PR_LOG_WARNING, "warning: Classes disabled - Class directive "
      "not in effect");

  /* setup "default" class if necesarry */
  if ((n = get_class("default")) == NULL)
    n = add_class("default");

  /* find class, add if necessary */
  if ((n = get_class(cmd->argv[1])) == NULL)
    n = add_class(cmd->argv[1]);

  /* what to do ? */
  if (strcasecmp(cmd->argv[2], "limit") == 0) {
    ret = atoi(cmd->argv[3]);
    if (ret < 0)
      ret = 100;
    n->max_connections = ret;
    log_debug(DEBUG4, "Class '%s' maxconnections set to %d.",
              n->name, n->max_connections);
  } else if (strcasecmp(cmd->argv[2], "regex") == 0) {
#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
    preg = pr_regexp_alloc();

    if ((ret = regcomp(preg, cmd->argv[3],
                      REG_EXTENDED|REG_NOSUB|REG_ICASE)) != 0) {
      regerror(ret, preg, errmsg, sizeof(errmsg));
      pr_regexp_free(preg);

      n->preg = NULL;
      log_pri(PR_LOG_ERR, "Failed regexp '%s' compilation: ", cmd->argv[3]);
    } else {
      n->preg = preg;
    }
#else
    CONF_ERROR(cmd, "regex-based classes cannot be used, as you do not have POSIX compliant regex support.");
#endif
  } else if (strcasecmp(cmd->argv[2], "ip") == 0) {
    sstrncpy(ipaddress, cmd->argv[3], sizeof(ipaddress));
    if ((ptr = strchr(ipaddress, '/')) == NULL) {
      log_pri(PR_LOG_ERR, "Class '%s' ipmask %s skipped.",
              cmd->argv[1], cmd->argv[3]);
      CONF_ERROR(cmd, "wrong syntax error.");
    } else {
      bits = atol(ptr + 1);

      if (bits < 0 || bits > 32) {
        log_pri(PR_LOG_ERR, "Class '%s' ipmask %s skipped: wrong netmask.",
                cmd->argv[1], cmd->argv[3]);
      }

      *ptr = 0;
    }

    if ((res = inet_getaddr(cmd->pool, ipaddress)) != NULL) {
      add_cdir(n, ntohl(res->s_addr), bits);
      log_debug(DEBUG4, "Class '%s' ipmask %p/%d added.",
                cmd->argv[1], res, bits);
    } else {
      log_pri(PR_LOG_ERR, "Class '%s' ip could not parse '%s'.",
              cmd->argv[1], cmd->argv[3]);
    }
  } else if (strcasecmp(cmd->argv[2], "host") == 0) {
    add_hostname(n,cmd->argv[3]);
  } else {
    CONF_ERROR(cmd, "unknown argument.");
  }

  return HANDLED(cmd);
}

/* Initialization/finalization routines
 */

static int core_init(void) {

  /* Add the additional features implemented by this module into the
   * list, to be displayed in response to a FEAT command.
   */
  pr_feat_add("MDTM");
  pr_feat_add("REST STREAM");
  pr_feat_add("SIZE");

  return 0;
}

static int core_sess_init(void) {
  config_rec *c = NULL;
  unsigned int *debug_level = NULL;

  /* Check for a server-specific TimeoutIdle */
  if ((c = find_config(main_server->conf, CONF_PARAM, "TimeoutIdle",
      FALSE)) != NULL)
    TimeoutIdle = *((int *) c->argv[0]);

  /* Check for a configured DebugLevel */
  if ((debug_level = get_param_ptr(main_server->conf, "DebugLevel",
      FALSE)) != NULL)
    log_setdebuglevel(*debug_level);

  /* Check for a server-specific AuthOrder. */
  if ((c = find_config(main_server->conf, CONF_PARAM, "AuthOrder",
      FALSE)) != NULL) {
    array_header *auth_module_order = (array_header *) c->argv[0];
    int modulec = 0;
    char **modulev = NULL;
    register unsigned int i = 0;
    const char *auth_syms[] = {
      "setpwent", "endpwent", "setgrent", "endgrent", "getpwent", "getgrent",
      "getpwnam", "getgrnam", "getpwuid", "getgrgid", "auth", "check",
      "uid_name", "gid_name", "name_uid", "name_gid", "getgroups", NULL
    };

    log_debug(DEBUG3, "AuthOrder in effect, resetting auth module order");

    modulec = auth_module_order->nelts;
    modulev = (char **) auth_module_order->elts;

    /* First, delete all auth symbols. */
    for (i = 0; auth_syms[i] != NULL; i++)
      pr_stash_remove_symbol(PR_SYM_AUTH, auth_syms[i], NULL);

    /* Now, cycle through the list of configured modules, re-adding their
     * auth symbols, in the order in which they appear.
     *
     * NOTE: What is needed is way to get at the module structure for a
     * module, by name.
     */

    if (m_authtable) {
      char buf[PR_TUNABLE_BUFFER_SIZE] = {'\0'};
      authtable *authtab = NULL;

      for (authtab = m_authtable; authtab && authtab->name; authtab++) {
        memset(buf, '\0', sizeof(buf));
        snprintf(buf, sizeof(buf), "mod_%s.c", authtab->m->name);
        buf[sizeof(buf)-1] = '\0';

        /* Iterate through the AuthOrder, looking for a match of the
         * name of the module owning the authtable pointer from the
         * master authtable.
         */
        for (i = 0; i < modulec; i++) {
          if (!strcmp(buf, modulev[i])) {

            /* Twiddle the module's priority field be insertion into the
             * symbol table, as the insertion operation does so based on that
             * priority.  This has no effect other than during symbol
             * insertion.
             */
            authtab->m->priority = modulec - i;
            pr_stash_add_symbol(PR_SYM_AUTH, authtab);
          }
        }
      }
    }

    /* NOTE: the master conf/cmd/auth tables/arrays should ideally be
     * rebuilt after this symbol shuffling, but it's not necessary at this
     * point.
     */
  }

  return 0;
}

/* Module API tables
 */

static conftable core_conftab[] = {
  { "<Anonymous>",		add_anonymous,			NULL },
  { "</Anonymous>",		end_anonymous,			NULL },
  { "<Directory>",		add_directory,			NULL },
  { "</Directory>",		end_directory,			NULL },
  { "<Global>",			add_global,			NULL },
  { "</Global>",		end_global,			NULL },
  { "<IfDefine>",		start_ifdefine,			NULL },
  { "</IfDefine>",		end_ifdefine,			NULL },
  { "<IfModule>",		start_ifmodule,			NULL },
  { "</IfModule>",		end_ifmodule,			NULL },
  { "<Limit>",			add_limit,			NULL },
  { "</Limit>", 		end_limit, 			NULL },
  { "<VirtualHost>",		add_virtualhost,		NULL },
  { "</VirtualHost>",		end_virtualhost,		NULL },
  { "Allow",			set_allowdeny,			NULL },
  { "AllowAll",			set_allowall,			NULL },
  { "AllowFilter",		set_allowfilter,		NULL },
  { "AllowForeignAddress",	set_allowforeignaddress,	NULL },
  { "AllowGroup",		set_allowdenygroup,		NULL },
  { "AllowOverride",		set_allowoverride,		NULL },
  { "AllowUser",		set_allowdenyuser,		NULL },
  { "AuthOrder",		set_authorder,			NULL },
  { "Bind",			set_bind,			NULL },
  { "CDPath",			set_cdpath,			NULL },
  { "Class",			set_class,			NULL },
  { "Classes",			set_classes,			NULL },
  { "CommandBufferSize",	set_commandbuffersize,		NULL },
  { "DebugLevel",		set_debuglevel,			NULL },
  { "DefaultAddress",		set_defaultaddress,		NULL },
  { "DefaultServer",		set_defaultserver,		NULL },
  { "DefaultTransferMode",	set_defaulttransfermode,	NULL },
  { "DeferWelcome",		set_deferwelcome,		NULL },
  { "Define",			set_define,			NULL },
  { "Deny",			set_allowdeny,			NULL },
  { "DenyAll",			set_denyall,			NULL },
  { "DenyFilter",		set_denyfilter,			NULL },
  { "DenyGroup",		set_allowdenygroup,		NULL },
  { "DenyUser",			set_allowdenyuser,		NULL },
  { "DisplayConnect",		set_displayconnect,		NULL },
  { "DisplayFirstChdir",	set_displayfirstchdir,		NULL },
  { "DisplayGoAway",		set_displaygoaway,		NULL },
  { "DisplayLogin",		set_displaylogin,		NULL },
  { "DisplayQuit",		set_displayquit,		NULL },
  { "Group",			set_group, 			NULL },
  { "GroupOwner",		add_groupowner,			NULL },
  { "HideFiles",		set_hidefiles,			NULL },
  { "HideGroup",		set_hidegroup,			NULL },
  { "HideNoAccess",		set_hidenoaccess,		NULL },
  { "HideUser",			set_hideuser,			NULL },
  { "IdentLookups",		set_identlookups,		NULL },
  { "IgnoreHidden",		set_ignorehidden,		NULL },
  { "Include",			add_include,	 		NULL },
  { "MasqueradeAddress",	add_masqueradeaddress,		NULL },
  { "MaxConnectionRate",	set_maxconnrate,		NULL },
  { "MaxInstances",		set_maxinstances,		NULL },
  { "MultilineRFC2228",		set_multilinerfc2228,		NULL },
  { "Order",			set_order,			NULL },
  { "PassivePorts",		set_passiveports,		NULL },
  { "PathAllowFilter",		set_pathallowfilter,		NULL },
  { "PathDenyFilter",		set_pathdenyfilter,		NULL },
  { "PidFile",			set_pidfile,	 		NULL },
  { "Port",			set_serverport, 		NULL },
  { "RLimitCPU",		set_rlimitcpu,			NULL },
  { "RLimitMemory",		set_rlimitmemory,		NULL },
  { "RLimitOpenFiles",		set_rlimitopenfiles,		NULL },
  { "ScoreboardFile",		set_scoreboardfile,		NULL },
  { "ServerAdmin",		set_serveradmin,		NULL },
  { "ServerIdent",		set_serverident,		NULL },
  { "ServerName",		set_servername, 		NULL },
  { "ServerType",		set_servertype,			NULL },
  { "SocketBindTight",		set_socketbindtight,		NULL },
  { "SyslogFacility",		set_syslogfacility,		NULL },
  { "SyslogLevel",		set_sysloglevel,		NULL },
  { "TimeoutIdle",		set_timeoutidle,		NULL },
  { "TimesGMT",			set_timesgmt,			NULL },
  { "TransferLog",		add_transferlog,		NULL },
  { "Umask",			set_umask,			NULL },
  { "UseReverseDNS",		set_usereversedns,		NULL },
  { "User",			set_user,			NULL },
  { "UserOwner",		add_userowner,			NULL },
  { "WtmpLog",			set_wtmplog,			NULL },
  { "tcpBackLog",		set_tcpbacklog,			NULL },
  { "tcpNoDelay",		set_tcpnodelay,			NULL },

  /* Deprecated */
  { "ScoreboardPath",		set_scoreboardpath,		NULL },
  { "tcpReceiveWindow",		set_tcpreceivewindow,		NULL },
  { "tcpSendWindow",		set_tcpsendwindow,		NULL },

  { NULL, NULL, NULL }
};

static cmdtable core_cmdtab[] = {
#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  { PRE_CMD, C_ANY, G_NONE,  regex_filters, FALSE, FALSE, CL_NONE },
#endif
  { PRE_CMD, C_ANY, G_NONE, core_clear_fs,FALSE, FALSE, CL_NONE },
  { CMD, C_HELP, G_NONE,  core_help,	FALSE,	FALSE, CL_INFO },
  { CMD, C_PORT, G_NONE,  core_port,	TRUE,	FALSE, CL_MISC },
  { CMD, C_PASV, G_NONE,  core_pasv,	TRUE,	FALSE, CL_MISC },
  { CMD, C_SYST, G_NONE,  core_syst,	FALSE,	FALSE, CL_INFO },
  { CMD, C_PWD,	 G_DIRS,  core_pwd,	TRUE,	FALSE, CL_INFO|CL_DIRS },
  { CMD, C_XPWD, G_DIRS,  core_pwd,	TRUE,	FALSE, CL_INFO|CL_DIRS },
  { CMD, C_CWD,	 G_DIRS,  core_cwd,	TRUE,	FALSE, CL_DIRS },
  { CMD, C_XCWD, G_DIRS,  core_cwd,	TRUE,	FALSE, CL_DIRS },
  { CMD, C_MKD,	 G_WRITE, core_mkd,	TRUE,	FALSE, CL_DIRS|CL_WRITE },
  { CMD, C_XMKD, G_WRITE, core_mkd,	TRUE,	FALSE, CL_DIRS|CL_WRITE },
  { CMD, C_RMD,	 G_WRITE, core_rmd,	TRUE,	FALSE, CL_DIRS|CL_WRITE },
  { CMD, C_XRMD, G_WRITE, core_rmd,	TRUE,	FALSE, CL_DIRS|CL_WRITE },
  { CMD, C_CDUP, G_DIRS,  core_cdup,	TRUE,	FALSE, CL_DIRS },
  { CMD, C_XCUP, G_DIRS,  core_cdup,	TRUE,	FALSE, CL_DIRS },
  { CMD, C_DELE, G_WRITE, core_dele,	TRUE,	FALSE, CL_WRITE },
  { CMD, C_MDTM, G_DIRS,  core_mdtm,	TRUE,	FALSE, CL_INFO },
  { CMD, C_RNFR, G_DIRS,  core_rnfr,	TRUE,	FALSE, CL_MISC },
  { CMD, C_RNTO, G_WRITE, core_rnto,	TRUE,	FALSE, CL_MISC },
  { CMD, C_SIZE, G_READ,  core_size,	TRUE,	FALSE, CL_INFO },
  { CMD, C_QUIT, G_NONE,  core_quit,	FALSE,	FALSE,  CL_INFO },
  { CMD, C_NOOP, G_NONE,  core_noop,	FALSE,	FALSE,  CL_MISC },
  { CMD, C_FEAT, G_NONE,  core_feat,	FALSE,	FALSE,  CL_INFO },
  { CMD, C_OPTS, G_NONE,  core_opts,    FALSE,	FALSE,	CL_MISC },
  { 0, NULL }
};

module core_module = {
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "core",

  /* Module configuration directive table */
  core_conftab,

  /* Module command handler table */
  core_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  core_init,

  /* Session initialization function */
  core_sess_init
};
