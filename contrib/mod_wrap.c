/*
 * ProFTPD: mod_wrap -- use Wietse Venema's TCP wrappers library for
 *                      access control
 *
 * Copyright (c) 2000 TJ Saunders
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
 * -- DO NOT MODIFY THE TWO LINES BELOW --
 * $Libraries: -lwrap$
 * $Id: mod_wrap.c,v 1.1 2000-10-08 21:36:51 macgyver Exp $
 *
 */

#include "conf.h"
#include "privs.h"
#include "tcpd.h"

/* these need to be defined for the libwrap functions -- default settings
 * are those from tcpd.h
 */

int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;

/* -------------------------------------------------------------------------
    Helper Functions
   ------------------------------------------------------------------------- */

/* Determine logging-in user's access table locations.  This function was
 * "borrowed" (ie plagiarized/copied/whatever) liberally from modules/
 * mod_auth.c -- the _true_ author is MacGuyver <macguyver@tos.net>.
 */

static char *_get_user_table(cmd_rec *command_rec, char *user, char *path) {

  char *realpath = NULL;
  struct passwd *pw;

  pw = auth_getpwnam(command_rec->pool, user);

  /* For the dir_realpath() function to work, some session members need to
   * be set.
   */
  session.user = pstrdup(command_rec->pool, pw->pw_name);
  session.login_uid = pw->pw_uid;

  PRIVS_USER;

  realpath = dir_realpath(command_rec->pool, path);

  PRIVS_RELINQUISH;

  if (realpath)
    path = realpath;

  return path;
}

/* yet more plagiarizing...this one raided from mod_auth's _auth_resolve_user()
 * function [in case you haven't noticed yet, I'm quite the hack, in the
 * _true_ sense of the world]. =) hmmm...I wonder if it'd be feasible
 * to make some of mod_auth's functions visible from src/auth.c?
 */

config_rec *_resolve_user(pool *pool, char **user, char **ournamep,
    char **anonnamep) {

  config_rec *conf, *top_conf;
  char *ourname,*anonname = NULL;
  int is_alias = 0, force_anon = 0;

  /* Precendence rules:
   *   1. Search for UserAlias directive.
   *   2. Search for Anonymous directive.
   *   3. Normal user login
   */

  ourname = (char*) get_param_ptr(main_server->conf, "UserName", FALSE);

  if (ournamep && ourname)
    *ournamep = ourname; 

  conf = find_config(main_server->conf, CONF_PARAM, "UserAlias", TRUE);

  if (conf) do {
    if (!strcmp(conf->argv[0], "*") || !strcmp(conf->argv[0], *user)) {
      is_alias = 1;
      break;
    }  

  } while ((conf = find_config_next(conf, conf->next, CONF_PARAM,
    "UserAlias", TRUE)) != NULL);

  /* if AuthAliasOnly is set, ignore this one and continue */
  top_conf = conf;

  while (conf && conf->parent &&
      find_config(conf->parent->set, CONF_PARAM, "AuthAliasOnly", FALSE)) {

    is_alias = 0;
    find_config_set_top(top_conf);
    conf = find_config_next(conf, conf->next, CONF_PARAM, "UserAlias", TRUE);

    if (conf && (!strcmp(conf->argv[0], "*") || !strcmp(conf->argv[0], *user)))
      is_alias = 1;
  }

  if (conf) {
    *user = conf->argv[1];

    /* If the alias is applied inside an <Anonymous> context, we have found
     * our anon block
     */

    if (conf->parent && conf->parent->config_type == CONF_ANON)
      conf = conf->parent;

    else
      conf = NULL;
  }

  /* Next, search for an anonymous entry */

  if (!conf)
    conf = find_config(main_server->conf, CONF_ANON, NULL, FALSE);

  else
    find_config_set_top(conf);

  if (conf) do {
    anonname = (char*) get_param_ptr(conf->subset, "UserName", FALSE);

    if (!anonname)
      anonname = ourname;

    if (anonname && !strcmp(anonname,*user)) {

      if (anonnamep)
        *anonnamep = anonname;
       break;
    }
  } while ((conf = find_config_next(conf, conf->next, CONF_ANON, NULL,
    FALSE)) != NULL);

  if (!is_alias && !force_anon) {

    if (find_config((conf ? conf->subset :
        main_server->conf), CONF_PARAM, "AuthAliasOnly", FALSE)) {
      
      if (conf && conf->config_type == CONF_ANON)
        conf = NULL;

      else
        *user = NULL;

      if (*user && find_config(main_server->conf, CONF_PARAM, "AuthAliasOnly",
          FALSE))
        *user = NULL;

      if ((!user || !conf) && anonnamep)
        *anonnamep = NULL;
    }
  }

  return conf;
}

int is_usable_file(char *filename) {

  struct stat statbuf;
  fsdir_t *fs_file;

  /* check the easy case first */
  if (filename == NULL)
    return 0;

  if (fs_stat(filename, &statbuf) == -1) {
    log_pri(LOG_INFO, "\"%s\": %s", filename, strerror(errno));
    return 0;
  }

  /* OK, the file exists.  Now, to make sure that the current process
   * can _read_ the file
   */

  fs_file = fs_open(filename, O_RDONLY, NULL);

  if (!fs_file) {
    log_pri(LOG_INFO, "\"%s\": %s", filename, strerror(errno));
    return 0;
  }

  return 1;
}

void log_allowed_request(int priority, struct request_info *request) {
  log_pri(priority, "connect from %s", eval_client(request));

  /* done */
  return;
}

void log_denied_request(int priority, struct request_info *request) {
  log_pri(priority, "refused connect from %s", eval_client(request));

  /* done */
  return;
}

/* -------------------------------------------------------------------------
    Configuration Handlers
   ------------------------------------------------------------------------- */

MODRET add_allow_file(cmd_rec *command_rec) {

  /* assume use of the standard TCP wrappers installation location */

  char *allow_filename = "/etc/hosts.allow";

  if (command_rec->argc == 1) {

    /* assume use of "/etc/hosts.allow" -- do nothing */
    ;

  } else if (command_rec->argc == 2) {

    /* use the user-given file, checking to make sure that it exists and
     * is readable.
     */

    allow_filename = command_rec->argv[1];

    /* if the filename begins with a '~', AND it is not immediately followed
     * by a '/' (ie '~/'), expand it out for checking and storing for later
     * lookups.  If the filename DOES begin with '~/', do the expansion later,
     * after authenication.  In other words, do checking of static filenames
     * now, and checking of dynamic (user-authentication-based) filenames
     * later.
     */

    if (allow_filename[0] == '/') {

      /* it's an absolute path, so the filename will be checked as is */

      if (!is_usable_file(allow_filename))
        CONF_ERROR(command_rec, "usage: must be a usable file");

    } else if (allow_filename[0] == '~' && allow_filename[1] != '/') {
      char *allow_real_file = NULL;

      allow_real_file = dir_realpath(command_rec->pool, allow_filename);

      if (allow_real_file == NULL || !is_usable_file(allow_real_file))
        CONF_ERROR(command_rec, "usage: must be a usable file");

      allow_filename = allow_real_file;

    } else if (allow_filename[0] != '~' && allow_filename[0] != '/') {

      /* no relative paths allowed */
      CONF_ERROR(command_rec,
        "usage: filename must start with \"/\" or \"~\"");

    } else {

      /* it's a determine-at-login-time filename -- check it later */
      ;
    }

  } else
    CONF_ERROR(command_rec, "syntax: invalid number of arguments");

  CHECK_CONF(command_rec, CONF_ROOT|CONF_ANON|CONF_VIRTUAL);

  add_config_param_str("HostsAllowFile", 1, (void *) allow_filename);

  /* done */
  return HANDLED(command_rec);
}

MODRET add_deny_file(cmd_rec *command_rec) {

  /* assume use of the standard TCP wrappers installation location */

  char *deny_filename = "/etc/hosts.deny";

  if (command_rec->argc == 1) {

    /* assume use of "/etc/hosts.deny" -- do nothing */
    ;

  } else if (command_rec->argc == 2) {

    /* use the user-given file, checking to make sure that it exists and
     * is readable.
     */

    deny_filename = command_rec->argv[1];

    /* if the filename begins with a '~', AND it is not immediately followed
     * by a '/' (ie '~/'), expand it out for checking and storing for later
     * lookups.  If the filename DOES begin with '~/', do the expansion later,
     * after authenication.  In other words, do checking of static filenames
     * now, and checking of dynamic (user-authentication-based) filenames
     * later.
     */

    if (deny_filename[0] == '/') {

      /* it's an absolute path, so the filename will be checked as is */

      if (!is_usable_file(deny_filename))
        CONF_ERROR(command_rec, "usage: must be a usable file");

    } else if (deny_filename[0] == '~' && deny_filename[1] != '/') {
      char *deny_real_file = NULL;

      deny_real_file = dir_realpath(command_rec->pool, deny_filename);

      if (deny_real_file == NULL || !is_usable_file(deny_real_file))
        CONF_ERROR(command_rec, "usage: must be a usable file");

      deny_filename = deny_real_file;

    } else if (deny_filename[0] != '~' && deny_filename[0] != '/') {

      /* no relative paths allowed */
      CONF_ERROR(command_rec,
        "usage: filename must start with \"/\" or \"~\"");

    } else {

      /* it's a determine-at-login-time filename -- check it later */
      ;
    }

  } else
    CONF_ERROR(command_rec, "syntax: invalid number of arguments");

  CHECK_CONF(command_rec, CONF_ROOT|CONF_ANON|CONF_VIRTUAL);

  add_config_param_str("HostsDenyFile", 1, (void *) deny_filename);

  /* done */
  return HANDLED(command_rec);
}

/* These two functions are copied, almost verbatim, from the set_sysloglevel()
 * function in modules/mod_core.c.  I hereby cite the source for this code
 * as MacGuyver <macguyver@tos.net>. =)
 */

MODRET set_allow_syslog_level(cmd_rec *command_rec) {
  CHECK_ARGS(command_rec, 1);
  CHECK_CONF(command_rec, CONF_ROOT|CONF_VIRTUAL|CONF_ANON);

  if(!strcasecmp(command_rec->argv[1], "emerg")) {
    add_config_param("HostsAllowSyslogLevel", 1, (void *) PR_LOG_EMERG);

  } else if(!strcasecmp(command_rec->argv[1], "alert")) {
    add_config_param("HostsAllowSyslogLevel", 1, (void *) PR_LOG_ALERT);

  } else if(!strcasecmp(command_rec->argv[1], "crit")) {
    add_config_param("HostsAllowSyslogLevel", 1, (void *) PR_LOG_CRIT);

  } else if(!strcasecmp(command_rec->argv[1], "error")) {
    add_config_param("HostsAllowSyslogLevel", 1, (void *) PR_LOG_ERR);

  } else if(!strcasecmp(command_rec->argv[1], "warn")) {
    add_config_param("HostsAllowSyslogLevel", 1, (void *) PR_LOG_WARNING);

  } else if(!strcasecmp(command_rec->argv[1], "notice")) {
    add_config_param("HostsAllowSyslogLevel", 1, (void *) PR_LOG_NOTICE);

  } else if(!strcasecmp(command_rec->argv[1], "info")) {
    add_config_param("HostsAllowSyslogLevel", 1, (void *) PR_LOG_INFO);

  } else if(!strcasecmp(command_rec->argv[1], "debug")) {
    add_config_param("HostsAllowSyslogLevel", 1, (void *) PR_LOG_DEBUG);

  } else {
    CONF_ERROR(command_rec, "HostsAllowSyslogLevel requires level keyword: "
      "one of emerg/alert/crit/error/warn/notice/info/debug");
  }

  return HANDLED(command_rec);
}

MODRET set_deny_syslog_level(cmd_rec *command_rec) {
  CHECK_ARGS(command_rec, 1);
  CHECK_CONF(command_rec, CONF_ROOT|CONF_VIRTUAL|CONF_ANON);

  if(!strcasecmp(command_rec->argv[1], "emerg")) {
    add_config_param("HostsDenySyslogLevel", 1, (void *) PR_LOG_EMERG);

  } else if(!strcasecmp(command_rec->argv[1], "alert")) {
    add_config_param("HostsDenySyslogLevel", 1, (void *) PR_LOG_ALERT);

  } else if(!strcasecmp(command_rec->argv[1], "crit")) {
    add_config_param("HostsDenySyslogLevel", 1, (void *) PR_LOG_CRIT);

  } else if(!strcasecmp(command_rec->argv[1], "error")) {
    add_config_param("HostsDenySyslogLevel", 1, (void *) PR_LOG_ERR);

  } else if(!strcasecmp(command_rec->argv[1], "warn")) {
    add_config_param("HostsDenySyslogLevel", 1, (void *) PR_LOG_WARNING);

  } else if(!strcasecmp(command_rec->argv[1], "notice")) {
    add_config_param("HostsDenySyslogLevel", 1, (void *) PR_LOG_NOTICE);

  } else if(!strcasecmp(command_rec->argv[1], "info")) {
    add_config_param("HostsDenySyslogLevel", 1, (void *) PR_LOG_INFO);

  } else if(!strcasecmp(command_rec->argv[1], "debug")) {
    add_config_param("HostsDenySyslogLevel", 1, (void *) PR_LOG_DEBUG);
  
  } else {
    CONF_ERROR(command_rec, "HostsDenySyslogLevel requires level keyword: "
      "one of emerg/alert/crit/error/warn/notice/info/debug");
  }

  return HANDLED(command_rec);
}

/* -------------------------------------------------------------------------
    Command Handlers
   ------------------------------------------------------------------------- */

MODRET handle_request(cmd_rec *command_rec) {

  /* these variables are names expected to be set by the TCP wrapper code
   */

  struct request_info request;

  char *user, *our_name, *anon_name = NULL;
  config_rec *conf = NULL;

  hosts_allow_table = NULL;
  hosts_deny_table = NULL;

  /* sneaky...found in mod_auth.c's cmd_pass() function.  Need to find the
   * login UID in order to resolve the possibly-login-dependent filename.
   */
  user = (char *) get_param_ptr(command_rec->server->conf, C_USER, FALSE);

  /* use mod_auth's _auth_resolve_user() [imported for use here] to get the
   * right configuration set, since the user may be loggin in anonymously,
   * and the session struct hasn't yet been set for that yet (thus short-
   * circuiting the easiest way to the get right context...the macros.
   */

  conf = _resolve_user(command_rec->pool, &user, &our_name, &anon_name);

  /* Retrieve the configured Hosts*File strings -- this is not as simple as
   * I would prefer [what I would prefer is a less-monolithic
   * mod_auth:_setup_environment(), but that's beside the point right now].
   * Unfortunately, just using the CURRENT_CONF macro won't do, as the
   * session.anon_config member isn't assigned until _after_ the C_PASS
   * PRE_CMD and CMD command handler chains have finished, since
   * it's _after_ the C_PASS command is handled that mod_auth's 
   * _setup_environment() [which builds/sets session.anon_config] function
   * is called.  By this time, the command handler won't have a chance to deny
   * the connection request if necessary.  So, the trick is, how to know
   * _when_ to look in the <Anonymous> config stuff (as it's handled a little
   * differently) for the Hosts*File parameters, and when not too, at this
   * point in the chain, where the engine has not yet verified that the
   * user requesting the connection is doing so as an anonymous user or
   * no?  Answer: pilfer mod_auth, and use it's _auth_resolve_user()! (see
   * above). =)
   */

  hosts_allow_table = (char *) get_param_ptr(
    conf ? conf->subset : CURRENT_CONF, "HostsAllowFile", FALSE);
  hosts_deny_table = (char *) get_param_ptr(
    conf ? conf->subset : CURRENT_CONF, "HostsDenyFile", FALSE);

  /* now, check the retrieved filename, and see if it requires a login-time
   * file
   */

  if (hosts_allow_table != NULL && hosts_allow_table[0] == '~' &&
      hosts_allow_table[1] == '/') {
    char *allow_real_table = NULL;

    allow_real_table = _get_user_table(command_rec, user, hosts_allow_table);

    if (!is_usable_file(allow_real_table)) {
      log_pri(LOG_INFO, "configured HostsAllowFile %s is unusable",
        hosts_allow_table);
      hosts_allow_table = NULL;

    } else
      hosts_allow_table = allow_real_table;
  }

  if (hosts_deny_table != NULL && hosts_deny_table[0] == '~' &&
      hosts_deny_table[1] == '/') {
    char *deny_real_table = NULL;

    deny_real_table = dir_realpath(command_rec->pool, hosts_deny_table);

    if (!is_usable_file(deny_real_table)) {
      log_pri(LOG_INFO, "configured HostsDenyFile %s is unusable",
        hosts_deny_table);
      hosts_deny_table = NULL;

    } else 
      hosts_deny_table = deny_real_table;
  }

  /* make sure that _both_ HostsAllowFile and HostsDenyFile are present.
   * If not, log the missing file, and by default allow request to succeed.
   */

  if (hosts_allow_table != NULL && hosts_deny_table != NULL) {

    /* most common case...nothing more necessary */

  } else if (hosts_allow_table == NULL && hosts_deny_table != NULL) {

    /* log the missing file */
    log_pri(LOG_INFO, "no usable HostsAllowFile -- allowing connection");

    return DECLINED(command_rec);

  } else if (hosts_allow_table != NULL && hosts_deny_table == NULL) {

    /* log the missing file */
    log_pri(LOG_INFO, "no usable HostsDenyFile -- allowing connection");

    return DECLINED(command_rec);

  } else {

    /* neither set -- assume the admin hasn't configured these directives
     * at all
     */

    return DECLINED(command_rec);
  }

  /* retrieve the user-defined syslog priorities, if any.  Fall back to the
   * defaults as seen in tcpd.h if not defined.
   */

  if ((allow_severity = get_param_int(CURRENT_CONF, "HostsAllowSyslogLevel",
      FALSE)) == -1)
    allow_severity = LOG_INFO;

  if ((deny_severity = get_param_int(CURRENT_CONF, "HostsDenySyslogLevel",
      FALSE)) == -1)
    deny_severity = LOG_WARNING;

  request_init(&request, RQ_DAEMON, "proftpd", RQ_FILE,
    session.c->rfd, 0);

  fromhost(&request);

  if (STR_EQ(eval_hostname(request.client), paranoid) ||
      !hosts_access(&request)) {

    /* if denying the connection, add an appropriate response for the client.
     */

    add_response_err(R_550,
      "Unable to connect to %s: connection refused",
      command_rec->server->ServerFQDN);

    add_response_err(R_DUP,
      "Please contact %s for more information",
      command_rec->server->ServerAdmin);

    /* log the denied connection */
    log_denied_request(deny_severity, &request);

    return ERROR(command_rec);
  }

  /* if request is allowable, return DECLINED (for engine to act as if this
   * handler was never called, else ERROR (for engine to abort processing and
   * deny request.
   */

  /* log the accepted connection */
  log_allowed_request(allow_severity, &request);

  return DECLINED(command_rec);
}

static conftable wrap_conftab[] = {
  { "HostsAllowSyslogLevel", set_allow_syslog_level, NULL },
  { "HostsDenySyslogLevel", set_deny_syslog_level, NULL },
  { "UseHostsAllowFile", add_allow_file, NULL },
  { "UseHostsDenyFile", add_deny_file, NULL },
  { NULL }
};

static cmdtable wrap_cmdtab[] = {
  { PRE_CMD, C_PASS, G_NONE, handle_request, FALSE, FALSE },
  { 0, NULL }
};

module wrap_module = {

  /* pointer to the next module -- _always_ NULL for user-defined modules */
  NULL,

  /* pointer to the previous module -- _always_ NULL for user-defined */
  /* modules */
  NULL,

  /* Module API version 2.0 */
  0x20,

  /* the module name */
  "wrap",

  /* module configuration handler table */
  wrap_conftab,

  /* module command handler table */
  wrap_cmdtab,

  /* module authentication handler table */
  NULL,

  /* module initialization function */
  NULL,

  /* module "child mode" post-fork initialization function */
  NULL
};
