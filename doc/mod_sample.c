/*
 * The following is an *EXAMPLE* ProFTPD module.  While it can be compiled
 * in to ProFTPD, it is not by default, and doesn't really do anything all
 * that terribly functional.
 */

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
 * sample module for ProFTPD
 * $Id: mod_sample.c,v 1.1 1999-10-05 04:28:16 macgyver Exp $
 */

#include "conf.h"

/* This sample configuration directive handler will get called
 * whenever the "FooBarDirective" directive is encountered in the
 * configuration file.
 */

MODRET add_foobardirective(cmd_rec *cmd)
{
  int b;
  config_rec *c;

  /* The CHECK_ARGS macro checks the number of arguments passed to the
   * directive against what we want.  Note that this is *one* less than
   * cmd->argc, because cmd->argc includes cmd->argv[0] (the directive
   * itself).  If CHECK_ARGS fails, a generic error is sent to the user
   */

  CHECK_ARGS(cmd,1);

  /* The CHECK_CONF macro makes sure that this directive is not being
   * "used" in the wrong context (i.e. if the directive is only available
   * or applicable inside certain contexts).  In this case, we are allowing
   * the directive inside of <Anonymous> and <Limit>, but nowhere else.
   * If this macro fails a generic error is logged and the handler aborts.
   */

  CHECK_CONF(cmd,CONF_ANON|CONF_LIMIT);

  b = get_boolean(cmd,1);
  if(b == -1)				/* get_boolean couldn't find a */
    CONF_ERROR(cmd,                     /* valid boolean value         */
    "requires a boolean value");

  /* add_config_param adds a configuration paramater to our current
   * configuration context.
   */

  c = add_config_param("FooBarDirective",1,(void*)b);

  /* By adding the CF_MERGEDOWN flag to the parameter we just created
   * we are telling proftpd that this parameter should be copied and
   * "merged" into all "lower" contexts until it either hits a
   * parameter w/ the same name or bottoms out.
   *
   * Example _without_ CF_MERGEDOWN:
   *
   * <VirtualHost>
   *      |----------\
   *             <Anonymous>
   *                 | - FooBarDirective  <------- Config places it here
   *                 |-----------\
   *                         <Directory>  <------- Doesn't apply here
   *                             |-------------\
   *                                        <Limit> <--- Or here.....
   *
   * Now, if we specify CF_MERGDOWN, the tree ends up looking like:
   *
   * <VirtualHost>
   *      |----------\
   *             <Anonymous>
   *                 | - FooBarDirective  <------- Config places it here
   *                 |-----------\
   *                         <Directory>  <------- Now, it DOES apply here
   *                             | - FooBarDirective
   *                             |-------------\
   *                                        <Limit> <-------- And here ...
   *                                           | - FooBarDirective
   *
   */

  c->flags |= CF_MERGEDOWN;

  /* Tell proftpd that we handled the request w/ no problems.
   */

  return HANDLED(cmd);
}

/* Example of a PRE_CMD handler here, which simply logs all received
 * commands via log_debug().  We are careful to return DECLINED, otherwise
 * other PRE_CMD handlers wouldn't get the request.  Note that in order
 * for this to work properly, this module would need to be loaded _last_,
 * or after any other modules which don't return DECLINED for all
 * their precmds.  In practice you should always return DECLINED unless
 * you plan on having your module actually handle the command (or
 * deny it).
 */

MODRET pre_cmd(cmd_rec *cmd)
{
  log_debug(DEBUG0,"RECEIVED: command '%s', arguments '%s'.",
            cmd->argv[0],cmd->arg);

  return DECLINED(cmd);
}

/* Next, an example of a LOG_CMD handler, which receives all commands
 * _after_ they have been processed, and additional only IF they were
 * successful.
 */

MODRET log_cmd(cmd_rec *cmd)
{
  log_debug(DEBUG0,"SUCCESSFUL: command '%s', arguments '%s'.",
            cmd->argv[0],cmd->arg);

  return DECLINED(cmd);
}

/* Now, a _slightly_ more useful handler.  We define POST_CMD handlers
 * for RETR, STOR and LIST/NLST, so we can calculate total data transfer
 * for a session.
 */

static unsigned long total_rx = 0, total_tx = 0;

MODRET post_cmd_retr(cmd_rec *cmd)
{
  /* The global variable 'session' contains lots of important data after
   * a file/directory transfer of any kind.  It doesn't get cleared until
   * mod_xfer gets a LOG_CMD, so we can still get to it here.
   */

  total_tx += session.xfer.total_bytes;
  return DECLINED(cmd);
}

MODRET post_cmd_stor(cmd_rec *cmd)
{
  total_rx += session.xfer.total_bytes;
  return DECLINED(cmd);
}

MODRET post_cmd_list(cmd_rec *cmd)
{
  return post_cmd_retr(cmd);
}

MODRET post_cmd_nlst(cmd_rec *cmd)
{
  return post_cmd_retr(cmd);
}

MODRET cmd_xfoo(cmd_rec *cmd)
{
  char *path;

  if(cmd->argc < 2)
    return ERROR_MSG(cmd,R_500,"XFOO command needs at least one argument");

  path = dir_realpath(cmd->tmp_pool,cmd->arg);

  if(!path) {
    add_response_err(R_500,"It appears that '%s' does not exist.",cmd->arg);
    return ERROR(cmd);
  }

  add_response_err(R_200,"XFOO command successful (yeah right!)");
  return HANDLED(cmd);
}

/* There are three tables which act as the "glue" between proftpd and
 * a module.  None of the tables are _required_ (however having none would
 * make the module fairly useless).
 */

/* The first table is the "configuration directive" table.  It specifies
 * handler routines in the module which will be used during configuration
 * file parsing.
 */

static conftable sample_config[] = {
  { "FooBarDirective",		add_foobardirective,                 },
  { NULL }
};

/* Each module can supply up to two initialization routines (via
 * the module structure at the bottom of this file).  The first
 * init function is called immediately after the module is loaded,
 * while the second is called after proftpd is connected to a client,
 * and the main proftpd server (if not in inetd mode) has forked off.
 * The second init function's purpose is to let the module perform
 * any necessary work once a client is connected and proftpd is ready
 * to service the new client.  In inetd mode, the "child init" function
 * will be called immediately after proftpd is loaded, because proftpd
 * is _always_ in "child mode" when run from inetd.  Note that both
 * of these initialization routines are optional.  If you don't need
 * them (or only need one), simply set the function pointer to NULL
 * in the module structure.
 */

static int sample_init()
{
  /* do something useful here, right? */

  return 0;
}

static int sample_child_init()
{
  /* same here */

  return 0;
}

/* command table ...
 * first  : command "type" (see the doc/API for more info)
 *
 * second : command "name", or the actual null-terminated ascii text
 *          sent by a client (in uppercase) for this command.  see
 *          include/ftp.h for macros which define all rfced FTP protocol
 *          commands.  Can also be the special macro C_ANY, which receives
 *          ALL commands.
 *
 * third  : command "group" (used for access control via Limit directives),
 *          this can be either G_DIRS (for commands related to directory
 *          listing), G_READ (for commands related to reading files), 
 *          G_WRITE (for commands related to file writing), or the
 *          special G_NONE for those commands against which the
 *          special <Limit READ|WRITE|DIRS> will not be applied.
 *
 * fourth : function pointer to your handler
 *
 * fifth  : TRUE if the command cannot be used before authentication
 *          (via USER/PASS), otherwise FALSE.
 *
 * sixth  : TRUE if the command can be sent during a file transfer
 *          (note: as of 1.1.5, this is obsolete)
 *
 */

cmdtable sample_commands[] = {
  { PRE_CMD,	C_ANY,	G_NONE, pre_cmd, 	FALSE, FALSE },
  { LOG_CMD,	C_ANY,	G_NONE, log_cmd, 	FALSE, FALSE },
  { POST_CMD,	C_RETR, G_NONE, post_cmd_retr,	FALSE, FALSE },
  { POST_CMD,	C_STOR,	G_NONE, post_cmd_stor,	FALSE, FALSE },
  { POST_CMD,	C_APPE, G_NONE, post_cmd_stor,	FALSE, FALSE },
  { POST_CMD,	C_LIST,	G_NONE,	post_cmd_list,	FALSE, FALSE },
  { POST_CMD,	C_NLST, G_NONE, post_cmd_nlst,	FALSE, FALSE },
  { CMD,	"XFOO",	G_DIRS,	cmd_xfoo,	TRUE,  FALSE },
  { 0,		NULL }
};

module sample_module = {
  NULL,NULL,			/* Always NULL */
  0x20,				/* API Version 2.0 */
  "sample",
  sample_config,		/* Sample configuration handler table */
  sample_commands,		/* Sample command handler table */
  NULL,				/* No authentication handler table */
  sample_init,			/* Initialization function */
  sample_child_init		/* Post-fork "child mode" init */
};
