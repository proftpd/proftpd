/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (C) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
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
 * Authentication module for ProFTPD
 * $Id: mod_auth.c,v 1.61 2001-06-18 17:35:06 flood Exp $
 */

#include "conf.h"
#include "privs.h"

/* From the core module */
extern int core_display_file(const char *,const char *,const char *);
extern pid_t mpid;

module auth_module;

static int logged_in = 0;
static int auth_tries = 0;

static void _do_user_counts();

/* Perform a chroot or equivalent action to lockdown the process into a
 * particular directory.
 */
static int lockdown(char *newroot)
{
  PRIVS_ROOT;
  
  log_debug(DEBUG1, "Preparing to chroot() the environment, path = '%s'",
	    newroot);
  
  if(chroot(newroot) == -1) {
    PRIVS_RELINQUISH;
    log_pri(LOG_ERR, "%s chroot(\"%s\"): %s", session.user,
	    newroot, strerror(errno));
    return -1;
  }
  
  PRIVS_RELINQUISH;

  log_debug(DEBUG1, "Environment successfully chroot()ed.");

  return 0;
}

/* check_auth is hooked into the main server's auth_hook function,
 * so that we can deny all commands until authentication is complete.
 */
int check_auth(cmd_rec *cmd) {
  if(get_param_int(cmd->server->conf,"authenticated",FALSE) != 1) {
    send_response(R_530,"Please login with USER and PASS.");
    return FALSE;
  }
  
  return TRUE;
}

int _auth_shutdown(CALLBACK_FRAME) {
  log_pri(LOG_ERR, "scheduled main_exit() never ran "
	  "[from auth:_login_timeout], terminating.");
  end_login(1);
  return 0;				/* Avoid compiler warning */
}

/* As for 1.2.0, timer callbacks are now non-reentrant, so it's
 * safe to call main_exit()
 */

int _login_timeout(CALLBACK_FRAME)
{
  /* Is this the proper behavior when timing out? */
  send_response_async(R_421,
		      "Login Timeout (%d seconds): "
		      "closing control connection.",
                      TimeoutLogin);
  
  main_exit((void*) LOG_NOTICE, "FTP login timed out, disconnected.",
	    (void*) 0, NULL);
  
/* should never be reached */
  return 0;		/* Don't restart the timer */
}

int auth_init_child()
{
  /* Start the login timer */
  if(TimeoutLogin)
    add_timer(TimeoutLogin,TIMER_LOGIN,&auth_module,_login_timeout);
   
  if ((char*)get_param_ptr(main_server->conf,"DisplayConnect",FALSE) != NULL)
    _do_user_counts();
   
  return 0;
}

int auth_init()
{
  /* By default, enable auth checking */
  set_auth_check(check_auth);
  return 0;
}

static int _do_auth(pool *p, xaset_t *conf, char *u, char *pw)
{
  char *cpw = NULL;
  config_rec *c;

  if(conf) {
    c = find_config(conf,CONF_PARAM,"UserPassword",FALSE);

    while(c) {
      if(!strcmp(c->argv[0],u)) {
        cpw = (char*)c->argv[1];
        break;
      }

      c = find_config_next(c,c->next,CONF_PARAM,"UserPassword",FALSE);
    }
  }


  if(cpw) {
    if(!auth_getpwnam(p,u))
      return AUTH_NOPWD;
    return auth_check(p,cpw,u,pw);
  }

  return auth_authenticate(p,u,pw);
}

/* Handle group based authentication, only checked if pw
 * based fails
 */

static config_rec *_auth_group(pool *p, char *user, char **group,
                               char **ournamep, char **anonnamep, char *pass)
{
  config_rec *c;
  char *ourname = NULL,*anonname = NULL;
  char **grmem;
  struct group *grp;

  ourname = (char*)get_param_ptr(main_server->conf,"UserName",FALSE);
  if(ournamep && ourname)
    *ournamep = ourname;

  c = find_config(main_server->conf,CONF_PARAM,"GroupPassword",TRUE);

  if(c) do {
    grp = auth_getgrnam(p,c->argv[0]);

    if(!grp)
      continue;

    for(grmem = grp->gr_mem; *grmem; grmem++)
      if(!strcmp(*grmem,user)) {
        if(auth_check(p,c->argv[1],user,pass) == 0)
          break;
      }

    if(*grmem) {
      if(group)
        *group = c->argv[0];

      if(c->parent)
        c = c->parent;

      if(c->config_type == CONF_ANON)
        anonname = (char*)get_param_ptr(c->subset,"UserName",FALSE);
      if(anonnamep)
        *anonnamep = anonname;
      if(anonnamep && !anonname && ourname)
        *anonnamep = ourname;
      
      break;
    }
  } while((c = find_config_next(c,c->next,CONF_PARAM,"GroupPassword",TRUE)) != NULL);

  return c;
}

static config_rec *_auth_anonymous_group(pool *p, char *user)
{
  config_rec *c;
  int ret = 0;

  /* retrieve the session group membership information, so that this check
   * may work properly
   */
  if (!session.gids && !session.groups &&
      (ret = get_groups(p, user, &session.gids, &session.groups)) < 1)
    log_debug(DEBUG2, "no supplemental groups found for user '%s'", user);

  c = find_config(main_server->conf,CONF_PARAM,"AnonymousGroup",FALSE);

  if(c) do {
    ret = group_expression((char**)c->argv);
  } while(!ret && (c = find_config_next(c,c->next,CONF_PARAM,"AnonymousGroup",FALSE)) != NULL);
 
  return ret ? c : NULL;
}

static config_rec *_auth_resolve_user(pool *p,char **user,
                                      char **ournamep,
                                      char **anonnamep)
{
  config_rec *c,*topc;
  char *ourname,*anonname = NULL;
  int is_alias = 0, force_anon = 0;

  /* Precendence rules:
   *   1. Search for UserAlias directive.
   *   2. Search for Anonymous directive.
   *   3. Normal user login
   */

  ourname = (char*)get_param_ptr(main_server->conf,"UserName",FALSE);

  if(ournamep && ourname)
    *ournamep = ourname; 

  c = find_config(main_server->conf,CONF_PARAM,"UserAlias",TRUE);
  if(c) do {
    if(!strcmp(c->argv[0], "*") || !strcmp(c->argv[0],*user)) {
      is_alias = 1;
      break;
    }  
  } while((c = find_config_next(c,c->next,CONF_PARAM,"UserAlias",TRUE)) != NULL);

  /* if AuthAliasOnly is set, ignore this one and continue */
  topc = c;

  while(c && c->parent &&
             find_config(c->parent->set,CONF_PARAM,"AuthAliasOnly",FALSE)) {
    is_alias = 0;
    find_config_set_top(topc);
    c = find_config_next(c,c->next,CONF_PARAM,"UserAlias",TRUE);
    if(c && (!strcmp(c->argv[0],"*") || !strcmp(c->argv[0],*user)))
      is_alias = 1;
  }

  if(c) {
    *user = c->argv[1];

    /* If the alias is applied inside an <Anonymous> context, we have found
     * our anon block
     */

    if(c->parent && c->parent->config_type == CONF_ANON)
      c = c->parent;
    else
      c = NULL;
  }

  /* Next, search for an anonymous entry */

  if(!c)
    c = find_config(main_server->conf,CONF_ANON,NULL,FALSE);
  else
    find_config_set_top(c);

  if(c) do {
    anonname = (char*)get_param_ptr(c->subset,"UserName",FALSE);
    if(!anonname)
      anonname = ourname;

    if(anonname && !strcmp(anonname,*user)) {
       if(anonnamep)
         *anonnamep = anonname;
       break;
    }
  } while((c = find_config_next(c,c->next,CONF_ANON,NULL,FALSE)) != NULL);

  if(!c) {
    c = _auth_anonymous_group(p,*user);

    if(c)
      force_anon = 1;
  }

  if(!is_alias && !force_anon) {
    if(find_config((c ? c->subset :
                   main_server->conf),CONF_PARAM,"AuthAliasOnly",FALSE)) {
      
      if(c && c->config_type == CONF_ANON)
        c = NULL;
      else
        *user = NULL;

      if(*user && find_config(main_server->conf,CONF_PARAM,"AuthAliasOnly",FALSE))
        *user = NULL;

      if((!user || !c) && anonnamep)
        *anonnamep = NULL;
    }
  }

  return c;
}

static int _auth_check_ftpusers(xaset_t *s, const char *user)
{
  int res = 1;
  FILE *fp;
  char *u,buf[256] = {'\0'};

  if(get_param_int(s,"UseFtpUsers",FALSE) != 0) {
    PRIVS_ROOT;
    fp = fopen(FTPUSERS_PATH,"r");
    PRIVS_RELINQUISH;

    if(!fp)
      return res;

    while(fgets(buf,sizeof(buf)-1,fp)) {
      buf[sizeof(buf)-1] = '\0'; CHOP(buf);

      u = buf; while(isspace((UCHAR)*u) && *u) u++;

      if(!*u || *u == '#')
        continue;

      if(!strcmp(u,user)) {
        res = 0;
        break;
      }
    }

    fclose(fp);
  }

  return res;
}

static int _auth_check_shell(xaset_t *s, const char *shell)
{
  int res = 1;
  FILE *shellf;
  char buf[256] = {'\0'};

  if(get_param_int(s,"RequireValidShell",FALSE) != 0 &&
     (shellf = fopen(VALID_SHELL_PATH,"r")) != NULL) {
    res = 0;
    while(fgets(buf,sizeof(buf)-1,shellf)) {
      buf[sizeof(buf)-1] = '\0'; CHOP(buf);

      if(!strcmp(shell,buf)) {
        res = 1;
        break;
      }
    }

    fclose(shellf);
  }

  return res;
}

/* Determine any applicable chdirs
 */

static char *_get_default_chdir(pool *p, xaset_t *conf)
{
  config_rec *c;
  char *dir = NULL;
  int ret;

  c = find_config(conf,CONF_PARAM,"DefaultChdir",FALSE);

  while(c) {
    /* Check the groups acl */
    if(c->argc < 2) {
      dir = c->argv[0];
      break;
    }

    ret = group_expression(((char**)c->argv)+1);

    if(ret) {
      dir = c->argv[0];
      break;
    }

    c = find_config_next(c,c->next,CONF_PARAM,"DefaultChdir",FALSE);
  }

  /* if the directory is relative, concatenate w/ session.cwd
   */

  if(dir && *dir != '/' && *dir != '~')
    dir = pdircat(p,session.cwd,dir,NULL);

  return dir;
}

/* Determine if the user (non-anon) needs a default root dir
 * other than /
 */

static char *_get_default_root(pool *p)
{
  config_rec *c;
  char *dir = NULL;
  int ret;

  c = find_config(main_server->conf,CONF_PARAM,"DefaultRoot",FALSE);

  while(c) {
    /* Check the groups acl */
    if(c->argc < 2) {
      dir = c->argv[0];
      break;
    }

    ret = group_expression(((char**)c->argv)+1);

    if(ret) {
      dir = c->argv[0];
      break;
    }

    c = find_config_next(c,c->next,CONF_PARAM,"DefaultRoot",FALSE);
  }

  if(dir) {
    if(!strcmp(dir,"/"))
      dir = NULL;
    else {
      char *realdir;

      /*
      ** We need to be the final user here so that if the user has their home
      ** directory with a mode the user proftpd is running (ie the User
      ** directive) as can not traverse down, we can still have the default
      ** root as ~/public_html/
      */
      PRIVS_USER;

      realdir = dir_realpath(p,dir);

      PRIVS_RELINQUISH;

      if(realdir)
        dir = realdir;
    }
  }

  return dir;
}

static struct passwd *passwd_dup(pool *p, struct passwd *pw)
{
  struct passwd *npw;
      
  npw = pcalloc(p,sizeof(struct passwd));
   
  npw->pw_name = pstrdup(p,pw->pw_name);
  npw->pw_passwd = pstrdup(p,pw->pw_passwd);
  npw->pw_uid = pw->pw_uid;
  npw->pw_gid = pw->pw_gid;
  npw->pw_gecos = pstrdup(p,pw->pw_gecos);
  npw->pw_dir = pstrdup(p,pw->pw_dir);
  npw->pw_shell = pstrdup(p,pw->pw_shell);
      
  return npw;
}

static void ensure_open_passwd(pool *p)
{
  /* Make sure pass/group is open.
   */
  auth_setpwent(p);
  auth_setgrent(p);

  /* On some unices the following is necessary to ensure the files
   * are open.  (BSDI 3.1)
   */
  auth_getpwent(p);
  auth_getgrent(p);
}

/* Next function (the biggie) handles all authentication, setting
 * up chroot() jail, etc.
 */
static int _setup_environment(pool *p, char *user, char *pass)
{
  struct passwd *pw;
  struct stat sbuf;
  config_rec *c;
  char *origuser,*ourname,*anonname = NULL,*anongroup = NULL,*ugroup = NULL;
  char ttyname[20] = {'\0'}, *defaulttransfermode;
  char *defroot = NULL,*defchdir = NULL,*xferlog = NULL;
  int aclp,i,force_anon = 0,wtmp_log = -1,res = 0,showsymlinks;

  /********************* Authenticate the user here *********************/

  session.hide_password = TRUE;

  origuser = user;
  c = _auth_resolve_user(p,&user,&ourname,&anonname);

  if(!user) {
    log_auth(LOG_NOTICE,"USER %s: user is not a UserAlias from %s [%s] to %s:%i",
             origuser,session.c->remote_name,
             inet_ascii(p,session.c->remote_ipaddr),
             inet_ascii(p,session.c->local_ipaddr),
             session.c->local_port);
    goto auth_failure;
  }

  /* If c != NULL from this point on, we have an anonymous login */
  aclp = login_check_limits(main_server->conf,FALSE,TRUE,&i);

  if((pw = auth_getpwnam(p,user)) == NULL) {
    log_auth(LOG_NOTICE,"USER %s: no such user found from %s [%s] to %s:%i",
               user,session.c->remote_name,
               inet_ascii(p,session.c->remote_ipaddr),
               inet_ascii(p,session.c->local_ipaddr),
               session.c->local_port);
    goto auth_failure;
  }

  /* security: other functions perform pw lookups, thus we need to make
   * a local copy of the user just looked up
   */

  pw = passwd_dup(p,pw);

  if(pw->pw_uid == 0) {
    /* If RootLogin is set to true, we allow this... even though we
     * still log a warning. :)
     */

    if(get_param_int((c ? c->subset : main_server->conf),
		     "RootLogin", FALSE) != 1) {
      log_auth(LOG_CRIT, "SECURITY VIOLATION: root login attempted.");
      return 0;
    } else {
      log_auth(LOG_WARNING, "ROOT FTP login successful.");
    }
  }
  
  session.user = pstrdup(p, pw->pw_name);
  session.group = pstrdup(p, auth_gid_name(p, pw->pw_gid));

  /* Set the login_uid and login_uid */
  session.login_uid = pw->pw_uid;
  session.login_gid = pw->pw_gid;
  
  /* Get the supplemental groups */
  if (!session.gids && !session.groups &&
      (res = get_groups(p, pw->pw_name, &session.gids, &session.groups)) < 1)
    log_debug(DEBUG2, "no supplemental groups found for user '%s'",
      pw->pw_name);


  /* set force_anon (for AnonymousGroup) and build a custom
   * anonymous config for this session.
   */
  if(c && c->config_type != CONF_ANON) {
    force_anon = 1;

    defroot = _get_default_root(session.pool);
    if(!defroot)
      defroot = pstrdup(session.pool,pw->pw_dir);

    c = (config_rec*)pcalloc(session.pool,sizeof(config_rec));
    c->config_type = CONF_ANON;
    c->name = defroot;

    anonname = pw->pw_name;

    /* hackery, we trick everything else by pointing the subset
     * at the main server's configuration.  tricky, eh?
     */
     c->subset = main_server->conf;
  }

  if(c) {
    if(!force_anon) {
        anongroup = (char*)get_param_ptr(c->subset,"GroupName",FALSE);
      if(!anongroup)
        anongroup = (char*)get_param_ptr(main_server->conf,"GroupName",FALSE);
    }

    if(!login_check_limits(c->subset,FALSE,TRUE,&i) || (!aclp && !i) ){
      log_auth(LOG_NOTICE, "ANON %s (Login failed): Limit access denies "
	       "login.", origuser);
      goto auth_failure;
    }
  }

  if(!c && !aclp) {
    log_auth(LOG_NOTICE, "USER %s (Login failed): Limit access denies login.",
	     origuser);
    goto auth_failure;
  }

  if(!c || get_param_int(c->subset,"AnonRequirePassword",FALSE) == 1) {
    int authcode;
    char *user_name;

    user_name = user;

    /* if 'AuthUsingAlias' set and we're logging in under an alias,
     * then auth using that alias.
     */
    if(c && origuser && strcasecmp(user,origuser) &&
       get_param_int(c->subset,"AuthUsingAlias",FALSE) == 1) {
      user_name = origuser;
      log_auth(LOG_NOTICE, "ANON AUTH: User %s, Auth Alias %s",
	       user, user_name);
    }
    
    if(c)
      authcode = _do_auth(p,c->subset,user_name,pass);
    else
      authcode = _do_auth(p,main_server->conf,user_name,pass);

    if(authcode) {
      /* Normal authentication has failed, see if group authentication
       * passes
       */

      if((c = _auth_group(p,user,&anongroup,&ourname,&anonname,pass)) != NULL) {
        if(c->config_type != CONF_ANON) {
          c = NULL;
          ugroup = anongroup; anongroup = NULL;
        }

        authcode = 0;
      }
    }
      
    bzero(pass,strlen(pass));

    switch(authcode) {
    case AUTH_NOPWD:
      log_auth(LOG_NOTICE, "USER %s (Login failed): No such user found.",
	       user);
      goto auth_failure;
      
    case AUTH_BADPWD:
      log_auth(LOG_NOTICE, "USER %s (Login failed): Incorrect password.",
	       origuser);
      goto auth_failure;

    case AUTH_AGEPWD:
      log_auth(LOG_NOTICE, "USER %s (Login failed): Password expired.",
	       user);
      goto auth_failure;

    case AUTH_DISABLEDPWD:
      log_auth(LOG_NOTICE, "USER %s (Login failed): Account disabled.",
	       user);
      goto auth_failure;

    default:
      break;
    };
    
    if(authcode != 0)
      goto auth_failure;
  } else if(c && get_param_int(c->subset, "AnonRequirePassword", FALSE) != 1) {
    session.hide_password = FALSE;
  }
  
/* Flood - 7/10/97, not sure what setutent() was used for, but it
 * certainly looks unnecessary now.
 */

 /* setutent(); */

  auth_setgrent(p);

  if(!_auth_check_shell((c ? c->subset : main_server->conf),pw->pw_shell)) {
    log_auth(LOG_NOTICE, "USER %s (Login failed): Invalid shell.", user);
    goto auth_failure;
  }

  if(!_auth_check_ftpusers((c ? c->subset : main_server->conf),pw->pw_name)) {
    log_auth(LOG_NOTICE, "USER %s (Login failed): User in %s.",
	     user, FTPUSERS_PATH);
    goto auth_failure;
  }

  if(c) {
    struct group *grp;
    int add_userdir;
    char *u;
    
    u = (char *) get_param_int(main_server->conf, C_USER, FALSE);
                                                                              
    add_userdir = get_param_int((c ? c->subset : main_server->conf),
				"UserDirRoot", FALSE);
    
    /* If resolving an <Anonymous> user, make sure that user's groups
     * are set properly for the check of the home directory path (which
     * depend on those supplemental group memberships).  Additionally,
     * temporarily switch to the new user's uid.
     */

    block_signals();
    
    PRIVS_ROOT;
    if ((res = set_groups(p, pw->pw_gid, session.gids)) < 0)
      log_pri(LOG_ERR, "error: unable to set groups: %s",
        strerror(errno));
#ifdef __hpux
    setresuid(0,0,0);
    setresgid(0,0,0);
#else
    setuid(0);
    setgid(0);
#endif
    PRIVS_SETUP(pw->pw_uid,pw->pw_gid);
    
    if(add_userdir > 0 && strcmp(u, user))
      session.anon_root = dir_realpath(p, pdircat(p, c->name,
					       u, NULL));
    else
      session.anon_root = dir_realpath(p, c->name);
   
    /* Check access using access_check() which uses euid instead of ruid,
     * if everything is ok copy it into the session pool. -jss 2/22/2001
     */
    
    if(session.anon_root && access_check(session.anon_root, X_OK) != 0)
      session.anon_root = NULL;
    else
      session.anon_root = pstrdup(session.pool,session.anon_root);
    
    /* return all privileges back to that of the daemon, for now */
    PRIVS_ROOT;
    if ((res = set_groups(p, daemon_gid, daemon_gids)) < 0)
      log_pri(LOG_ERR, "error: unable to set groups: %s",
        strerror(errno));
#ifdef __hpux
    setresuid(0,0,0);
    setresgid(0,0,0);
#else
    setuid(0);
    setgid(0);
#endif
    PRIVS_SETUP(daemon_uid, daemon_gid);

    unblock_signals();
    
    /* Sanity check, make sure we have daemon_uid and daemon_gid back */
#ifdef HAVE_GETEUID
    if(getegid() != daemon_gid ||
       geteuid() != daemon_uid) {

      PRIVS_RELINQUISH;
      
      log_pri(LOG_ERR,"changing from %s back to daemon uid/gid: %s",
            session.user, strerror(errno));

      end_login(1);
    }
#endif /* HAVE_GETEUID */
    
    if(get_param_int(c->subset, "AnonRequirePassword", FALSE) == 1)
      session.anon_user = pstrdup(session.pool, origuser);
    else
      session.anon_user = pstrdup(session.pool, pass);
    
    if(!session.anon_root) {
      log_pri(LOG_ERR, "%s: Directory %s is not accessible.",
              session.user, c->name);
      add_response_err(R_530, "Unable to set anonymous privileges.");
      goto auth_failure;
    }
    
    sstrncpy(session.cwd, "/", sizeof(session.cwd));
    xferlog = get_param_ptr(c->subset,"TransferLog",FALSE);

    if(anongroup) {
      grp = auth_getgrnam(p,anongroup);
      if(grp) {
        pw->pw_gid = grp->gr_gid;
        session.group = pstrdup(p,grp->gr_name);
      }
    }
  } else {
    struct group *grp;
    char *homedir;
    
    if(ugroup) {
      grp = auth_getgrnam(p,ugroup);
      if(grp) {
        pw->pw_gid = grp->gr_gid;
        session.group = pstrdup(p,grp->gr_name);
      }
    }

    /* attempt to resolve any possible symlinks */
    PRIVS_USER
    homedir = dir_realpath(p, pw->pw_dir);
    PRIVS_RELINQUISH

    if(homedir)
      sstrncpy(session.cwd, homedir, MAX_PATH_LEN);
    else
      sstrncpy(session.cwd, pw->pw_dir, MAX_PATH_LEN);
  }

  /* Get default chdir (if any) */
  defchdir = _get_default_chdir(p,(c ? c->subset : main_server->conf));
  
  if(defchdir)
    sstrncpy(session.cwd, defchdir, MAX_PATH_LEN);

  /* check limits again to make sure deny/allow directives still permit
   * access.
   */

  if(!login_check_limits((c ? c->subset : main_server->conf),FALSE,TRUE,&i))
  {
    log_auth(LOG_NOTICE, "%s %s: Limit access denies login.",
	     (c != NULL) ? "ANON" : "USER", origuser);
    goto auth_failure;
  }
  
  /* perform a dir fixup */
  resolve_defered_dirs(main_server);
  fixup_dirs(main_server,CF_DEFER);

  /* If running under an anonymous context, resolve all <Directory>
   * blocks inside it
   */
  if(c && c->subset)
    resolve_anonymous_dirs(c->subset);

  log_auth(LOG_NOTICE, "%s %s: Login successful.",
	   (c != NULL) ? "ANON" : "USER",
	   origuser);

  /* Write the login to wtmp.  This must be done here because we won't
   * have access after we give up root.  This can result in falsified
   * wtmp entries if an error kicks the user out before we get
   * through with the login process.  Oh well.
   */

#if (defined(BSD) && (BSD >= 199103))
  snprintf(ttyname, sizeof(ttyname), "ftp%ld",(long)getpid());
#else
  snprintf(ttyname, sizeof(ttyname), "ftpd%d",(int)getpid());
#endif

  /* Perform wtmp logging only if not turned off in <Anonymous>
   * or the current server
   */
  if(c)
    wtmp_log = get_param_int(c->subset, "WtmpLog", FALSE);

  if(wtmp_log == -1)
    wtmp_log = get_param_int(main_server->conf, "WtmpLog", FALSE);

  PRIVS_ROOT;

  if(wtmp_log != 0) {
    log_wtmp(ttyname, session.user, session.c->remote_name,
             session.c->remote_ipaddr);
    session.wtmp_log = TRUE;
  }

  /* Open the /var/run log for later writing */
  log_open_run(mpid, FALSE, TRUE);
  /* Open /var/log/ files */
  if(!xferlog) {
    if(c)
      xferlog = get_param_ptr(c->subset, "TransferLog", FALSE);
    if(!xferlog)
      xferlog = get_param_ptr(main_server->conf, "TransferLog", FALSE);
    if(!xferlog)
      xferlog = XFERLOG_PATH;
  }

  if(strcasecmp(xferlog, "NONE") == 0)
    log_open_xfer(NULL);
  else
    log_open_xfer(xferlog);

  if ((res = set_groups(p, pw->pw_gid, session.gids)) < 0)
    log_pri(LOG_ERR, "error: unable to set groups: %s",
      strerror(errno));

  PRIVS_RELINQUISH;

  /* Now check to see if the user has an applicable DefaultRoot */
  if(!c && (defroot = _get_default_root(session.pool))) {

    ensure_open_passwd(p);

    if(lockdown(defroot) == -1) {
      add_response_err(R_530, "Unable to set default root directory.");
      end_login(1);
    }

    session.anon_root = defroot;

    /* Re-calc the new cwd based on this root dir.  If not applicable
     * place the user in / (of defroot)
     */

    if(strncmp(session.cwd,defroot,strlen(defroot)) == 0) {
      char *newcwd = &session.cwd[strlen(defroot)];

      if(*newcwd == '/')
        newcwd++;
      session.cwd[0] = '/';
      sstrncpy(&session.cwd[1], newcwd, sizeof(session.cwd));
    }
  }

  if(c)
    ensure_open_passwd(p);

  if(c && lockdown(session.anon_root) == -1) {
    add_response_err(R_530, "Unable to set anonymous privileges.");
    end_login(1);
  }

  /* new in 1.1.x, I gave in and we don't give up root permanently..
   * sigh.
   */

#ifndef __hpux
  block_signals();

  PRIVS_ROOT;

  setuid(0);
  setgid(0);

  PRIVS_SETUP(pw->pw_uid,pw->pw_gid);

  unblock_signals();
#else
  session.uid = session.ouid = pw->pw_uid;
  session.gid = pw->pw_gid;
  PRIVS_RELINQUISH;
#endif

#ifdef HAVE_GETEUID
  if(getegid() != pw->pw_gid ||
     geteuid() != pw->pw_uid) {

    PRIVS_RELINQUISH;

    add_response_err(R_530, "Unable to set user privileges.");
    log_pri(LOG_ERR, "%s setregid() or setreuid(): %s",
            session.user, strerror(errno));

    end_login(1);
  }
#endif

  /*
   *  session.uid = pw->pw_uid;
   */

  /* Overwrite original uid, so PRIVS_ macros no longer 
   * try to do anything 
   */

  /*
   * session.ouid = pw->pw_uid;
   * session.gid = pw->pw_gid;
   */

  /* chdir to the proper directory, do this even if anonymous
   * to make sure we aren't outside our chrooted space.
   */

  showsymlinks = get_param_int((c ? c->subset : main_server->conf),
                               "ShowSymlinks",FALSE);

  if(showsymlinks == -1)
    showsymlinks = 1;

  /* if the home directory is NULL or "", reject the login
   */
  if (pw->pw_dir == NULL || !strcmp(pw->pw_dir, "")) {
    log_pri(LOG_ERR, "error: user %s home directory is NULL or \"\"",
      session.user);
    end_login(1);
  }

  /* attempt to change to the correct directory -- use session.cwd first.
   * This will contain the DefaultChdir directory, if configured...
   */
  if(fs_chdir_canon(session.cwd,!showsymlinks) == -1) {
    add_response_err(R_530, "Unable to chdir()");
    log_pri(LOG_ERR, "%s chdir(\"%s\"): %s", session.user, session.cwd,
      strerror(errno));

    /* in this case, if DefaultChdir is not used, then session.cwd _is_
     * the user's home directory, and the fs_chdir_canon() failed for
     * a valid reason -- and there's no good fallback.  Thus, end the
     * login here.
     */
    if (!defchdir)
      end_login(1);

    if (session.anon_root != NULL || defroot) {

      /* ...else if DefaultRoot is configured, chdir to the root (this is
       * guaranteed to succeed, otherwise the login operation would have
       * failed before now
       */
      log_debug(DEBUG2, "unable to chdir to %s, defaulting to chroot "
        "directory %s", session.cwd,
        (session.anon_root ? session.anon_root : defroot));

      if (fs_chdir_canon("/", !showsymlinks) == -1)
        end_login(1);

    } else {

      /* no DefaultRoot, failed DefaultChdir -- default to the user's home
       * directory.  This should never fail, either, as a logging in user
       * is required to have a home directory -- yes, but that home
       * directory is not guaranteed to be valid. ;)
       */
      log_debug(DEBUG2, "unable to chdir to %s, default to home directory %s",
        session.cwd, pw->pw_dir);

      if (fs_chdir_canon(pw->pw_dir, !showsymlinks) == -1)
        end_login(1);
    }
  }

  sstrncpy(session.cwd, fs_getcwd(), sizeof(session.cwd));
  sstrncpy(session.vwd, fs_getvwd(), sizeof(session.vwd));

  /* check dynamic configuration */
  if (fs_stat(session.cwd, &sbuf) != -1)
    build_dyn_config(p, session.cwd, &sbuf, 1);

  if(c) {
    if(!session.hide_password)
      session.proc_prefix =
      pstrcat(permanent_pool,session.c->remote_name,
              ": anonymous/",pass,NULL);
    else
      session.proc_prefix =
      pstrcat(permanent_pool,session.c->remote_name,
              ": anonymous",NULL);

    session.anon_config = c;
    session.flags = SF_ANON;
  } else {
    session.proc_prefix = pstrdup(permanent_pool,session.c->remote_name);
            
    session.flags = 0;
  }

  /* While closing the pointer to the password database would avoid any
   * potential attempt to hijack this information, it is unfortunately needed
   * in a chroot()ed environment.  Otherwise, mappings from UIDs to names,
   * among other things, would fail. - MacGyver
   */
  /* auth_endpwent(p); */

  /* Default transfer mode is ASCII */
  defaulttransfermode = (char*)get_param_ptr(CURRENT_CONF, "DefaultTransferMode", FALSE);
  if (defaulttransfermode && strcasecmp(defaulttransfermode, "binary") == 0)
	session.flags &= (SF_ALL^SF_ASCII);
  else
	session.flags |= SF_ASCII;

  /* Authentication complete, user logged in, now kill the login
   * timer.
   */

  log_run_address(session.c->remote_name, session.c->remote_ipaddr);
  log_run_cwd(session.cwd);
  main_set_idle();

  remove_timer(TIMER_LOGIN,&auth_module);

  /* these copies are made from the permanent_pool, instead of the more
   * volatile pool used originally, in order that the copied data maintain
   * its integrity for the lifetime of the session.
   */
  session.user = pstrdup(permanent_pool,session.user);
  session.group = pstrdup(permanent_pool,session.group);
  session.gids = copy_array(permanent_pool, session.gids);

  /* session.groups is an array of strings, so we must copy the string data
   * as well as the pointers. -jss 02/28/2001
   */
  session.groups = copy_array_str(permanent_pool, session.groups);

  return 1;

auth_failure:
  session.user = session.group = NULL;
  session.gids = session.groups = NULL;
  session.wtmp_log = 0;
  return 0;
}

/* This function counts the number of connected users. It only fills in the 
   CURRENT_CLASS based counters and an estimate for the number of clients. The
   primary prupose is to make it so that the %N/%y escapes work in a 
   DisplayConnect greeting */
static void _do_user_counts()
{
  logrun_t *l;
  int cur = -1, ccur = -1;
  char config_class_users[128] = {'\0'};
  xaset_t *conf = NULL;
  
  if(get_param_int(main_server->conf, "Classes", FALSE) != 1)
    return;

  if (!session.class)
    return;
  
  /* Determine how many users are currently connected */
  PRIVS_ROOT;
  while((l = log_read_run(NULL)) != NULL)
      /* Make sure it matches our current server */
      if(l->server_ip.s_addr == main_server->ipaddr->s_addr &&
         l->server_port == main_server->ServerPort) {
	 
	cur++;
        if(strcasecmp(l->class, session.class->name) == 0)
        	ccur++;
      }
  PRIVS_RELINQUISH;
  
  /* This silliness is needed to get past the broken HP/UX 11.x compiler.
   */
  conf = CURRENT_CONF;
  remove_config(CURRENT_CONF, "CURRENT-CLIENTS", FALSE);
  add_config_param_set(&conf, "CURRENT-CLIENTS", 1, (void *) cur);
  
  remove_config(CURRENT_CONF,"CURRENT-CLASS",FALSE);
  add_config_param_set(&conf, "CURRENT-CLASS", 1, session.class->name);
  
  snprintf(config_class_users, sizeof(config_class_users), "%s-%s",
	   "CURRENT-CLIENTS-CLASS", session.class->name);
  remove_config(CURRENT_CONF, config_class_users, FALSE);
  add_config_param_set(&conf, config_class_users, 1, ccur);
}

static void _auth_check_count(cmd_rec *cmd, char *user) {
  long cur = 0, hcur = 0, ccur = 0, hostsperuser = 0, usersessions = 0;
  logrun_t *l;
  config_rec *c, *maxc;
  char *origuser, config_class_users[128] = {'\0'};
  int classes_enabled = 0;
  
  if((classes_enabled = get_param_int(main_server->conf,
				      "Classes", FALSE)) != 1)
    classes_enabled = 0;
  
  /* NOTE: there is an assumption here that if Classes have been enabled,
   * there will be a corresponding Class defined.  This can cause a
   * SIGSEGV if not caught.
   *
   * The catch is this: if Classes are enabled, but find_class() returns
   *  NULL, act as if Classes are disabled. -- TJ
   */
  if (classes_enabled && session.class == NULL)
      classes_enabled = 0;
  
  /* Determine how many users are currently connected.
   */
  origuser = user;
  c = _auth_resolve_user(cmd->tmp_pool, &user, NULL, NULL);

  /* Gather our statistics.
   */
  if(user) {
    PRIVS_ROOT;
    
    while((l = log_read_run(NULL)) != NULL) {
      int samehost = 0;
      
      /* Make sure it matches our current server.
       */
      if(l->server_ip.s_addr == main_server->ipaddr->s_addr &&
         l->server_port == main_server->ServerPort) {
        if((c && c->config_type == CONF_ANON && !strcmp(l->user, user)) ||
	   !c) {
          char *s, *d, ip[32] = {'\0'};
          int mpos = sizeof(ip) - 1;
	  
          cur++;
	  
          s = strchr(l->address, '[');
          d = ip;
	  
          if(s != NULL)
	    s++;
	  
          while(*s && *s != ']' && d < ip + mpos)
	    *d++ = *s++;
	  
          *d = '\0';
	  
	  /* Count up sessions on a per-host basis.
	   */
          if(!strcmp(ip, inet_ntoa(*session.c->remote_ipaddr))) {
	    samehost++;
            hcur++;
	  }
	  
	  /* Take a per-user count of connections.
	   */
	  if(!strcmp(l->user, user)) {
	    usersessions++;
	    
	    /* Count up unique hosts.
	     */
	    if(!samehost)
	      hostsperuser++;
	  }
        }
	
        if(classes_enabled && strcasecmp(l->class, session.class->name) == 0)
        	ccur++;
      }
    }
    
    PRIVS_RELINQUISH;
  }
  
  remove_config(cmd->server->conf, "CURRENT-CLIENTS", FALSE);
  add_config_param_set(&cmd->server->conf, "CURRENT-CLIENTS", 1, (void *) cur);
  
  if(classes_enabled) {
    remove_config(cmd->server->conf, "CURRENT-CLASS", FALSE);
    add_config_param_set(&cmd->server->conf, "CURRENT-CLASS", 1,
			 session.class->name);

    snprintf(config_class_users, sizeof(config_class_users), "%s-%s",
	     "CURRENT-CLIENTS-CLASS", session.class->name);
    remove_config(cmd->server->conf, config_class_users, FALSE);
    add_config_param_set(&cmd->server->conf, config_class_users, 1, ccur);
    
    /* Too many users in this class?
     */
    if(ccur >= session.class->max_connections) {
      char *display = NULL;
      
      if(session.flags & SF_ANON)
	display = (char*) get_param_ptr(session.anon_config->subset,
					"DisplayGoAway",FALSE);
      
      if(!display)
	display = (char*) get_param_ptr(cmd->server->conf,
					"DisplayGoAway",FALSE);
      
      if(display)
	core_display_file(R_530, display, NULL);
      else
	send_response(R_530, "Too many users in your class, "
		      "please try again later.");
      
      remove_config(cmd->server->conf, C_USER, FALSE);
      remove_config(cmd->server->conf, C_PASS, FALSE);
      
      log_auth(LOG_NOTICE, "Connection refused (max clients for class %s).",
	       session.class->name);
      
      end_login(0);
    }
  }

  /* Try to determine what MaxClients or MaxHosts applies to the user
   * (if any) and count through the runtime file to see
   * if this would exceed the max.
   */
  maxc = find_config((c ? c->subset : cmd->server->conf),
		     CONF_PARAM, "MaxClientsPerHost", FALSE);
  
  if(maxc) {
    int max = (int) maxc->argv[0];
    char *maxstr = "Sorry, the maximum number clients (%m) from your host are "
      "already connected.";
    char maxn[10] = {'\0'};
    
    snprintf(maxn, sizeof(maxn), "%d", max);
    
    if(maxc->argc > 1)
      maxstr = maxc->argv[1];
    
    if(hcur >= max) {
      send_response(R_530, "%s",
		    sreplace(cmd->tmp_pool,maxstr, "%m", maxn, NULL));
      
      remove_config(cmd->server->conf, C_USER, FALSE);
      remove_config(cmd->server->conf, C_PASS, FALSE);

      log_auth(LOG_NOTICE, "Connection refused (max clients per host %d).",
	       max);
      
      end_login(0);
    }
  }
  
  maxc = find_config((c ? c->subset : cmd->server->conf),
		     CONF_PARAM, "MaxClients", FALSE);

  if(maxc) {
    int max = (int) maxc->argv[0];
    char *maxstr = "Sorry, the maximum number of allowed clients (%m) "
      "already connected.";
    char maxn[10] = {'\0'};
    
    snprintf(maxn, sizeof(maxn), "%d", max);

    if(maxc->argc > 1)
      maxstr = maxc->argv[1];
    
    if(cur >= max) {
      send_response(R_530, "%s",
		    sreplace(cmd->tmp_pool, maxstr, "%m", maxn, NULL));

      log_auth(LOG_NOTICE, "Connection refused (max clients %d).", max);

      remove_config(cmd->server->conf, C_USER, FALSE);
      remove_config(cmd->server->conf, C_PASS, FALSE);

      end_login(0);
    }
  }

  maxc = find_config((c ? c->subset : cmd->server->conf),
		     CONF_PARAM, "MaxHostsPerUser", FALSE);
  
  if(maxc) {
    int max = (int) maxc->argv[0];
    char *maxstr = "Sorry, the maximum number of hosts (%m) for this user "
      "already connected.";
    char maxn[10] = {'\0'};
    
    snprintf(maxn, sizeof(maxn), "%d", max);
    
    if(maxc->argc > 1)
      maxstr = maxc->argv[1];
    
    if(hostsperuser >= max) {
      send_response(R_530, "%s",
		    sreplace(cmd->tmp_pool,maxstr, "%m", maxn, NULL));
      
      remove_config(cmd->server->conf, C_USER, FALSE);
      remove_config(cmd->server->conf, C_PASS, FALSE);

      log_auth(LOG_NOTICE, "Connection refused (max clients per host %d).",
	       max);
      
      end_login(0);
    }
  }
}

/* close the passwd and group databases, because libc won't let us see new
 * entries to these files without this (only in PersistentPasswd mode)
 * jss 3/14/2001
 */

MODRET pre_cmd_user(cmd_rec *cmd) {
  auth_endpwent(cmd->tmp_pool);
  auth_endgrent(cmd->tmp_pool);

  return DECLINED(cmd);
}

MODRET cmd_user(cmd_rec *cmd) {
  int nopass = 0;
  config_rec *c;
  char *user, *origuser;
  int failnopwprompt = 0, aclp, i;

  if(logged_in)
    return ERROR_MSG(cmd,R_503,"You are already logged in!");

  if(cmd->argc < 2)
    return ERROR_MSG(cmd,R_500,"'USER': command requires a parameter.");

  user = cmd->arg;

  remove_config(cmd->server->conf, C_USER, FALSE);
  remove_config(cmd->server->conf, C_PASS, FALSE);

  add_config_param_set(&cmd->server->conf, C_USER, 1,
		       pstrdup(cmd->server->pool, user));
  
  origuser = user;
  c = _auth_resolve_user(cmd->tmp_pool,&user,NULL,NULL);

  switch(get_param_int((c && c->config_type == CONF_ANON ? c->subset :
                     main_server->conf),"LoginPasswordPrompt",FALSE)) {
  case 0:
    failnopwprompt = 1;
    break;

  default:
    failnopwprompt = 0;
    break;
  }
  
  if(failnopwprompt) {
    if(!user) {
      remove_config(cmd->server->conf, C_USER, FALSE);
      remove_config(cmd->server->conf, C_PASS, FALSE);

      log_pri(LOG_NOTICE, "USER %s (Login failed): Not a UserAlias.",
	      origuser);
      send_response(R_530,"Login incorrect.");

      end_login(0);
    }

    aclp = login_check_limits(main_server->conf,FALSE,TRUE,&i);

    if(c && c->config_type != CONF_ANON) {
      c = (config_rec *) pcalloc(session.pool, sizeof(config_rec));
      c->config_type = CONF_ANON;
      c->name = "";	/* don't really need this yet */
      c->subset = main_server->conf;
    }

    if(c) {
      if(!login_check_limits(c->subset,FALSE,TRUE,&i) || (!aclp && !i) ) {
	remove_config(cmd->server->conf, C_USER, FALSE);
	remove_config(cmd->server->conf, C_PASS, FALSE);

	log_auth(LOG_NOTICE, "ANON %s: Limit access denies login.",
		 origuser);
	send_response(R_530, "Login incorrect.");

	end_login(0);
      }
    }
    
    if(!c && !aclp) {
      remove_config(cmd->server->conf, C_USER, FALSE);
      remove_config(cmd->server->conf, C_PASS, FALSE);
      
      log_auth(LOG_NOTICE, "USER %s: Limit access denies login.", origuser);
      send_response(R_530, "Login incorrect.");
      
      end_login(0);
    }
  }
  
  _auth_check_count(cmd, origuser);
  
  if(c && user && get_param_int(c->subset, "AnonRequirePassword", FALSE) != 1)
    nopass++;
  
  if(nopass)
    add_response(R_331, "Anonymous login ok, send your complete email "
		 "address as your password.");
  else
    add_response(R_331, "Password required for %s.", cmd->argv[1]);

  session.gids = NULL;
  session.groups = NULL;
  session.user = NULL;
  session.group = NULL;

  return HANDLED(cmd);
}

/* close the passwd and group databases (see pre_cmd_user)
 * jss 3/14/2001
 */

MODRET pre_cmd_pass(cmd_rec *cmd) {
  auth_endpwent(cmd->tmp_pool);
  auth_endgrent(cmd->tmp_pool);
  return DECLINED(cmd);
}

MODRET cmd_pass(cmd_rec *cmd) {
  char *display = NULL;
  char *user, *grantmsg;
  int res = 0;
  
  if(logged_in)
    return ERROR_MSG(cmd, R_503, "You are already logged in!");
  
  user = (char *) get_param_ptr(cmd->server->conf, C_USER, FALSE);
  
  if(!user) {
    remove_config(cmd->server->conf, C_USER, FALSE);
    remove_config(cmd->server->conf, C_PASS, FALSE);
    
    return ERROR_MSG(cmd, R_503, "Login with USER first.");
  }
  
  _auth_check_count(cmd, user);
  
  if((res = _setup_environment(cmd->tmp_pool,user,cmd->arg)) == 1) {
    add_config_param_set(&cmd->server->conf,"authenticated",1,(void*)1);
    set_auth_check(NULL);

    remove_config(cmd->server->conf, C_PASS, FALSE);

    if(session.flags & SF_ANON) {
      add_config_param_set(&cmd->server->conf, C_PASS, 1,
			   pstrdup(cmd->server->pool, cmd->arg));
      display = (char*) get_param_ptr(session.anon_config->subset,
				      "DisplayLogin", FALSE);
    }
    
    if(!display)
      display = (char*) get_param_ptr(cmd->server->conf,
				      "DisplayLogin", FALSE);

    if(display)
      core_display_file(R_230, display, NULL);
    
    if((grantmsg = (char*)get_param_ptr((session.anon_config ?
        session.anon_config->subset : cmd->server->conf),
        "AccessGrantMsg",FALSE)) != NULL) {
      grantmsg = sreplace(cmd->tmp_pool, grantmsg, "%u", user, NULL);

      add_response(R_230, "%s", grantmsg, NULL);
    } else {
      if(session.flags & SF_ANON)
        add_response(R_230, "Anonymous access granted, restrictions apply.");
      else
        add_response(R_230, "User %s logged in.", user);
    }
    
    logged_in = 1;
    return HANDLED(cmd);
  }

  remove_config(cmd->server->conf, C_USER, FALSE);
  remove_config(cmd->server->conf, C_PASS, FALSE);
  
  if(res == 0) {
    int max;
    char *denymsg = NULL;

    /* check for AccessDenyMsg */
    if ((denymsg = (char *) get_param_ptr((session.anon_config ?
        session.anon_config->subset : cmd->server->conf),
        "AccessDenyMsg", FALSE)) != NULL) {
      denymsg = sreplace(cmd->tmp_pool, denymsg, "%u", user, NULL);
    }

    max = get_param_int(main_server->conf,"MaxLoginAttempts",FALSE);
    if(max == -1)
      max = 3;

    if(++auth_tries >= max) {
      if (denymsg)
        send_response(R_530, "%s", denymsg, NULL);
      else
      send_response(R_530,"Login incorrect");

      log_auth(LOG_NOTICE, "Maximum login attempts exceeded.");
      end_login(0);
    }

    if (denymsg)
      return ERROR_MSG(cmd, R_530, denymsg);
    else
    return ERROR_MSG(cmd,R_530,"Login incorrect.");
  }

  return HANDLED(cmd);
}


MODRET cmd_acct(cmd_rec *cmd) {
  add_response(R_502, "ACCT command not implemented.");
  return HANDLED(cmd);
}


MODRET cmd_rein(cmd_rec *cmd) {
  add_response(R_502, "REIN command not implemented.");
  return HANDLED(cmd);
}


MODRET set_rootlogin(cmd_rec *cmd) {
  int bool;
  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);
  
  if ((bool = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "expected boolean argument.");
 
  add_config_param("RootLogin", 1, (void*) bool);
  return HANDLED(cmd);
}

MODRET set_loginpasswordprompt(cmd_rec *cmd) {
  config_rec *c;
  int bool;
  
  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);
 
  if ((bool = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "expected boolean argument.");
  
  c = add_config_param("LoginPasswordPrompt", 1, (void*) bool);
  c->flags |= CF_MERGEDOWN;
  
  return HANDLED(cmd);
}

MODRET add_defaultroot(cmd_rec *cmd) {
  config_rec *c;
  char *dir,**argv;
  int argc;
  array_header *acl = NULL;
  
  CHECK_CONF(cmd, CONF_ROOT | CONF_VIRTUAL | CONF_GLOBAL);
  
  if(cmd->argc < 2)
    CONF_ERROR(cmd,"syntax: DefaultRoot <directory> [<group-expression>]");
  
  argv = cmd->argv;
  argc = cmd->argc - 2;
  
  dir = *++argv;
  
  /* dir must be / or ~
   */
  if(*dir != '/' && *dir != '~')
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "(", dir, ") absolute pathname "
			    "required.", NULL));
  
  if(strchr(dir, '*'))
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "(", dir, ") wildcards not allowed "
			    "in pathname.", NULL));
  
  if(*(dir + strlen(dir) - 1) != '/')
    dir = pstrcat(cmd->tmp_pool, dir, "/", NULL);
  
  acl = parse_group_expression(cmd->tmp_pool, &argc, argv);
  
  c = add_config_param("DefaultRoot", 0);
  
  c->argc = argc + 1;
  c->argv = pcalloc(c->pool, (argc + 2) * sizeof(char *));
  argv = (char **) c->argv;
  *argv++ = pstrdup(permanent_pool, dir);
  
  if(argc && acl)
    while(argc--) {
      *argv++ = pstrdup(permanent_pool, *((char **) acl->elts));
      acl->elts = ((char **) acl->elts) + 1;
    }

  *argv = NULL;
  return HANDLED(cmd);
}

MODRET add_defaultchdir(cmd_rec *cmd) {
  config_rec *c;
  char *dir,**argv;
  int argc;
  array_header *acl = NULL;

  CHECK_CONF(cmd, CONF_ROOT | CONF_VIRTUAL | CONF_ANON | CONF_GLOBAL);
  
  if(cmd->argc < 2)
    CONF_ERROR(cmd, "syntax: DefaultChdir <directory> [<group-expression>]");
  
  argv = cmd->argv;
  argc = cmd->argc - 2;
  
  dir = *++argv;
  
  if(strchr(dir, '*'))
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "(", dir, ") wildcards not allowed "
			    "in pathname.", NULL));

  if(*(dir + strlen(dir) - 1) != '/')
    dir = pstrcat(cmd->tmp_pool, dir, "/", NULL);
  
  acl = parse_group_expression(cmd->tmp_pool, &argc, argv);
  
  c = add_config_param("DefaultChdir", 0);
  
  c->argc = argc + 1;
  c->argv = pcalloc(c->pool, (argc + 2) * sizeof(char *));
  argv = (char **) c->argv;
  *argv++ = pstrdup(permanent_pool, dir);
  
  if(argc && acl)
    while(argc--) {
      *argv++ = pstrdup(permanent_pool, *((char **) acl->elts));
      acl->elts = ((char **) acl->elts) + 1;
    }
  
  *argv = NULL;
  return HANDLED(cmd);
}

MODRET add_userdirroot (cmd_rec *cmd) {
  int bool;
  CHECK_ARGS(cmd,1);
  CHECK_CONF (cmd, CONF_ANON);

  if ((bool = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "expected boolean argument.");

  add_config_param("UserDirRoot", 1, (void *) bool);
  return HANDLED(cmd);
}

static conftable auth_config[] = {
  { "RootLogin",		set_rootlogin,			NULL },
  { "LoginPasswordPrompt",	set_loginpasswordprompt,	NULL },
  { "DefaultRoot",		add_defaultroot,		NULL },
  { "DefaultChdir",		add_defaultchdir,		NULL },
  { "UserDirRoot",		add_userdirroot,		NULL },
  { NULL,			NULL,				NULL }
};

static cmdtable auth_commands[] = {
  { PRE_CMD, C_USER, G_NONE, pre_cmd_user, FALSE, FALSE, CL_AUTH },
  { CMD, C_USER, G_NONE, cmd_user,	FALSE,	FALSE, CL_AUTH },
  { PRE_CMD, C_PASS, G_NONE, pre_cmd_pass, FALSE, FALSE, CL_AUTH },
  { CMD, C_PASS, G_NONE, cmd_pass,	FALSE,  FALSE, CL_AUTH },
  { CMD, C_ACCT, G_NONE, cmd_acct,	FALSE,  FALSE, CL_AUTH },
  { CMD, C_REIN, G_NONE, cmd_rein,	FALSE,  FALSE, CL_AUTH },
  { 0, NULL }
};

/* Module interface */

module auth_module = {
  NULL,NULL,				/* Always NULL */
  0x20,					/* API Version 2.0 */
  "auth",
  auth_config,	
  auth_commands,
  NULL,
  auth_init,auth_init_child
};

