/*
 * ProFTPD: mod_sql -- SQL frontend and user interface.
 * Time-stamp: <1999-10-04 03:58:01 root>
 * Copyright (c) 1998-1999 Johnie Ingram.
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

#define MOD_SQL_VERSION "mod_sql/3.02"

/* This is mod_sql, contrib software for proftpd 1.2.0rc3 and above.
   Originally written and maintained as 'mod_sqlpw' by Johnie 
   Ingram <johnie@netgod.net>.
   
   With many changes by Andrew Houghton <aah@acm.org>
   Currently maintained by Andrew Houghton.
*/

#include "conf.h"
#include "privs.h"
#include "fs.h"

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

/* Uncomment the following define to allow OpenSSL hashed password checking */
/* #define HAVE_OPENSSL */

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#endif

/* backend function declarations -- each backend *MUST* declare these
 *
 * sql_backend_escape_string( )
 *
 * sql_backend_check_auth( )
 *
 * sql_backend_check_connectinfo( )
 *
 */

unsigned int sql_backend_escape_string(char *, char *, unsigned int);
int sql_backend_check_auth(cmd_rec *, const char *, const char *);
int sql_backend_check_connectinfo(char *);

struct sqldata_struc
{
  int rowcount;
  int fieldcount;
  char **data;
};

typedef struct sqldata_struc sqldata_t;

/* on the assumption that logging will turn into a bitmask later */
#define DEBUG_FUNC DEBUG5
#define DEBUG_AUTH DEBUG4
#define DEBUG_INFO DEBUG3
#define DEBUG_WARN DEBUG2

/* default information for tables and fields */
#define SQL_DEFAULT_USERTABLE         "users"
#define SQL_DEFAULT_USERNAMEFIELD     "userid"
#define SQL_DEFAULT_USERUIDFIELD      "uid"
#define SQL_DEFAULT_USERGIDFIELD      "gid"
#define SQL_DEFAULT_USERPASSWORDFIELD "password"
#define SQL_DEFAULT_USERSHELLFIELD    "shell"

#define SQL_DEFAULT_GROUPTABLE        "groups"
#define SQL_DEFAULT_GROUPNAMEFIELD    "groupname"
#define SQL_DEFAULT_GROUPGIDFIELD     "gid"
#define SQL_DEFAULT_GROUPMEMBERSFIELD "members"

/* default minimum id / default uid / default gid info. 
 * uids and gids less than SQL_MIN_ID get automatically
 * mapped to the defaults, below.  These can be
 * overridden using directives
 */
#define SQL_MIN_ID 999
#define SQL_DEFAULT_UID 65533
#define SQL_DEFAULT_GID 65533


#define BUFSIZE 32

/* this struct holds invariant information for the current session */
static struct
{
  /*
   * info valid after getpwnam 
   */

  char *authuser;               /* current authorized user */

  /*
   * generic status information 
   */

  int authoritative;            /* is this module authoritative? */
  int doauth;                   /* should we bother doing auth at all? */
  int dogroupauth;              /* should we do group auth */
  int connected;                /* are we connected to the database? */
  int sqlauthorized;            /* Set if sql auth was used. */

  /*
   * user table and field information 
   */

  char *usrtable;               /* user info table name */
  char *usrfield;               /* user name field */
  char *pwdfield;               /* user password field */
  char *uidfield;               /* user uid field */
  char *gidfield;               /* user gid field */
  char *homedirfield;           /* user homedir field */
  char *shellfield;             /* user login shell field */

  /*
   * group table and field information 
   */

  char *grptable;               /* group info table name */
  char *grpfield;               /* group name field */
  char *grpgidfield;            /* group gid field */
  char *grpmembersfield;        /* group members field */

  /*
   * logging table and field information 
   */
  /*
   * NOT CURRENTLY USED ( well, not really ) 
   */

  char *logtable;               /* log info table name */
  char *logcountfield;          /* counter: # of logins */

  /*
   * other information 
   */

  char *where;                  /* where clause */
  array_header *authlist;       /* auth handler list */
  char *defaulthomedir;         /* default homedir if no field specified */
  int buildhomedir;             /* create homedir if it doesn't exist? */

  uid_t minid;                  /* users UID must be this or greater */
  uid_t defaultuid;             /* default UID if none in database */
  gid_t defaultgid;             /* default GID if none in database */

  /*
   * STILL NOT SURE 
   */

  char *sql_fstor;              /* fstor int(11) NOT NULL DEFAULT '0', */
  char *sql_fretr;              /* fretr int(11) NOT NULL DEFAULT '0', */
  char *sql_bstor;              /* bstor int(11) NOT NULL DEFAULT '0', */
  char *sql_bretr;              /* bretr int(11) NOT NULL DEFAULT '0', */


  char *sql_fhost;              /* fhost varchar(50), */
  char *sql_faddr;              /* faddr char(15), */
  char *sql_ftime;              /* ftime timestamp, */

  char *sql_fcdir;              /* fcdir varchar(255), */

  char *sql_frate;              /* frate int(11) NOT NULL DEFAULT '5', */
  char *sql_fcred;              /* fcred int(2) NOT NULL DEFAULT '15', */
  char *sql_brate;              /* brate int(11) NOT NULL DEFAULT '5', */
  char *sql_bcred;              /* bcred int(2) NOT NULL DEFAULT '150000', */

  char *sql_hittable;
  char *sql_dir;
  char *sql_filename;
  char *sql_hits;

}
cmap;

/* **************************************************************** */
/* Functions make_cmd and dispatch liberally stolen from auth.c.    */

static cmd_rec *_make_cmd(pool * cp, int argc, ...)
{
  va_list args;
  cmd_rec *c;
  int i;

  c = pcalloc(cp, sizeof(cmd_rec));
  c->argc = argc;
  c->symtable_index = -1;

  c->argv = pcalloc(cp, sizeof(void *) * (argc + 1));
  c->argv[0] = MOD_SQL_VERSION;
  va_start(args, argc);

  for (i = 0; i < argc; i++)
    c->argv[i + 1] = (void *) va_arg(args, char *);

  va_end(args);

  return c;
}

static modret_t *_dispatch_sql(cmd_rec * cmd, char *match)
{
  authtable *m;
  modret_t *mr = NULL;

  m = mod_find_auth_symbol(match, &cmd->symtable_index, NULL);
  while (m) {
    mr = call_module_auth(m->m, m->handler, cmd);
    if (MODRET_ISHANDLED(mr) || MODRET_ISERROR(mr))
      break;
    m = mod_find_auth_symbol(match, &cmd->symtable_index, m);
  }

  if (MODRET_ISERROR(mr) && !MODRET_HASDATA(mr))
    log_debug(DEBUG_WARN, "%s: Aiee! sql internal!  %s", MOD_SQL_VERSION,
              MODRET_ERRMSG(mr));

  return mr;
}

/*****************************************************************
 *
 * SQL FUNCTIONS
 *
 *****************************************************************/

MODRET modsql_open(cmd_rec * cmd)
{
  cmd_rec *c;
  modret_t *mr;

  c = _make_cmd(cmd ? cmd->tmp_pool : permanent_pool, 0);
  mr = _dispatch_sql(c, "dbd_open");

  if (c->tmp_pool)
    destroy_pool(c->tmp_pool);

  return mr;
}

MODRET modsql_close(cmd_rec * cmd)
{
  cmd_rec *c;
  modret_t *mr;

  c = _make_cmd(cmd ? cmd->tmp_pool : permanent_pool, 0);
  mr = _dispatch_sql(c, "dbd_close");

  if (c->tmp_pool)
    destroy_pool(c->tmp_pool);

  return mr;
}

MODRET modsql_update(cmd_rec * cmd, const char *query)
{
  cmd_rec *c;
  modret_t *mr;

  c = _make_cmd(cmd->tmp_pool, 1, query);
  mr = _dispatch_sql(c, "dbd_update");

  if (c->tmp_pool)
    destroy_pool(c->tmp_pool);

  return mr;
}

MODRET modsql_select(cmd_rec * cmd, const char *query)
{
  cmd_rec *c;
  modret_t *mr;

  c = _make_cmd(cmd->tmp_pool, 1, query);
  mr = _dispatch_sql(c, "dbd_select");

  if (c->tmp_pool)
    destroy_pool(c->tmp_pool);

  return mr;
}

MODRET modsql_queryuser(cmd_rec * cmd, const char *user, const char *query,
                        int update)
{
  char *realquery;

  if (update)
    realquery = pstrcat(cmd->tmp_pool, "update ", cmap.usrtable,
                        " set ", query, " where ", cmap.usrfield, " = '",
                        user, "' ", cmap.where, NULL);
  else
    realquery = pstrcat(cmd->tmp_pool, "select ", query, " from ",
                        cmap.usrtable, " where ", cmap.usrfield,
                        " = '", user, "' ", cmap.where, NULL);

  return (update) ? modsql_update(cmd, realquery)
      : modsql_select(cmd, realquery);
}

static char *_uservar(cmd_rec * cmd, const char *user, const char *var)
{
  cmd_rec *c;
  modret_t *mr;
  char *query;
  sqldata_t *sd;

  query = pstrcat(cmd->tmp_pool, "select ", var, " from ",
                  cmap.usrtable, " where ", cmap.usrfield,
                  " = '", user, "' ", cmap.where, NULL);

  c = _make_cmd(cmd->tmp_pool, 1, query);

  mr = _dispatch_sql(c, "dbd_select");

  if (c->tmp_pool)
    destroy_pool(c->tmp_pool);
  if (MODRET_ISHANDLED(mr)) {
    sd = mr->data;
    if ((!sd) || (!sd->data) || (!sd->data[0])) {
      return NULL;
    }
    return sd->data[0];
  }

  return NULL;
}


/*****************************************************************
 *
 * AUTHENTICATION FUNCTIONS
 *
 *****************************************************************/

static int check_auth_crypt(cmd_rec * cmd, const char *c_clear,
                            const char *c_hash)
{
  int success = 0;

  log_debug(DEBUG_FUNC, "%s: entering check_auth_crypt", MOD_SQL_VERSION);

  if (!strcmp((char *) crypt(c_clear, c_hash), c_hash))
    success = 1;

  log_debug(DEBUG_FUNC, "%s: exiting  check_auth_crypt", MOD_SQL_VERSION);

  return success;
}

static int check_auth_plaintext(cmd_rec * cmd, const char *c_clear,
                                const char *c_hash)
{
  int success = 0;

  log_debug(DEBUG_FUNC, "%s: entering check_auth_plaintext", MOD_SQL_VERSION);

  if (!strcmp(c_clear, c_hash))
    success = 1;

  log_debug(DEBUG_FUNC, "%s: exiting  check_auth_plaintext", MOD_SQL_VERSION);

  return success;
}

static int check_auth_empty(cmd_rec * cmd, const char *c_clear,
                            const char *c_hash)
{
  int success = 0;

  log_debug(DEBUG_FUNC, "%s: entering check_auth_empty", MOD_SQL_VERSION);

  if (!strcmp(c_hash, ""))
    success = 1;

  log_debug(DEBUG_FUNC, "%s: exiting  check_auth_empty", MOD_SQL_VERSION);

  return success;
}

static int check_auth_backend(cmd_rec * cmd, const char *c_clear,
                              const char *c_hash)
{
  int success = 0;

  log_debug(DEBUG_FUNC, "%s: entering check_auth_backend", MOD_SQL_VERSION);

  success = sql_backend_check_auth(cmd, c_clear, c_hash);

  log_debug(DEBUG_FUNC, "%s: exiting  check_auth_backend", MOD_SQL_VERSION);

  return success;
}

#ifdef HAVE_OPENSSL
static int check_auth_openssl(cmd_rec * cmd, const char *c_clear,
                              const char *c_hash)
{
  /*
   * c_clear : plaintext password provided by user c_hash : combination
   * digest name and hashed value, of the form {digest}hash 
   */

  EVP_MD_CTX mdctx;
  EVP_ENCODE_CTX EVP_Encode;
  const EVP_MD *md;
  unsigned char md_value[EVP_MAX_MD_SIZE];
  int md_len, returnValue;

  char buff[EVP_MAX_KEY_LENGTH];

  char *digestname;             /* pointer to the name of the digest function 
                                 */
  char *hashvalue;              /* pointer to the hashed value we're
                                 * comparing to */
  char *copyhash;               /* temporary copy of the c_hash string */

  log_debug(DEBUG_FUNC, "%s: entering check_auth_openssl", MOD_SQL_VERSION);
  if (c_hash[0] != '{') {
    log_debug(DEBUG_AUTH, "%s: ssl digest/hash doesn't start with '{'",
              MOD_SQL_VERSION);
    log_debug(DEBUG_FUNC, "%s: exiting  check_auth_openssl", MOD_SQL_VERSION);
    return 0;
  }

  /*
   * we need a copy of c_hash 
   */
  copyhash = pstrdup(cmd->tmp_pool, c_hash);

  digestname = copyhash + 1;

  hashvalue = (char *) strchr(copyhash, '}');

  if (hashvalue == NULL) {
    log_debug(DEBUG_AUTH, "%s: ssl digest/hash doesn't contain '}'",
              MOD_SQL_VERSION);
    log_debug(DEBUG_FUNC, "%s: exiting  check_auth_openssl", MOD_SQL_VERSION);
    return 0;
  }

  *hashvalue = '\0';
  hashvalue++;

  OpenSSL_add_all_digests();

  md = EVP_get_digestbyname(digestname);

  if (!md) {
    log_debug(DEBUG_AUTH, "%s: ssl get_digestbyname failed for digest '%s'",
              MOD_SQL_VERSION, digestname);
    log_debug(DEBUG_FUNC, "%s: exiting  check_auth_openssl", MOD_SQL_VERSION);
    return 0;
  }

  EVP_DigestInit(&mdctx, md);
  EVP_DigestUpdate(&mdctx, c_clear, strlen(c_clear));
  EVP_DigestFinal(&mdctx, md_value, &md_len);

  EVP_EncodeInit(&EVP_Encode);
  EVP_EncodeBlock(buff, md_value, md_len);

  returnValue = strcmp(buff, hashvalue);

  if (returnValue) {
    log_debug(DEBUG_AUTH, "%s: ssl match failed; given: '%s' computed: '%s'",
              MOD_SQL_VERSION, hashvalue, buff);
  }

  log_debug(DEBUG_FUNC, "%s: exiting  check_auth_openssl", MOD_SQL_VERSION);
  return !returnValue;
}
#endif

/*
 * support for general-purpose authentication schemes 
 */

#define PLAINTEXT_AUTH_FLAG     1<<0
#define CRYPT_AUTH_FLAG         1<<1
#define BACKEND_AUTH_FLAG       1<<2
#define EMPTY_AUTH_FLAG         1<<3
#ifdef HAVE_OPENSSL
#define OPENSSL_AUTH_FLAG       1<<4
#endif

typedef int (*auth_func_ptr) (cmd_rec *, const char *, const char *);

typedef struct
{
  char *name;
  auth_func_ptr check_function;
  int flag;
}
auth_type_entry;

static auth_type_entry supported_auth_types[] = {
  {"Plaintext", check_auth_plaintext, PLAINTEXT_AUTH_FLAG},
  {"Crypt", check_auth_crypt, CRYPT_AUTH_FLAG},
  {"Backend", check_auth_backend, BACKEND_AUTH_FLAG},
  {"Empty", check_auth_empty, EMPTY_AUTH_FLAG},
#ifdef HAVE_OPENSSL
  {"OpenSSL", check_auth_openssl, OPENSSL_AUTH_FLAG},
#endif
  /*
   * add additional encryption types below 
   */
  {NULL, NULL, 0}
};

static auth_type_entry *get_auth_entry(char *name)
{
  auth_type_entry *ate = supported_auth_types;

  while (ate->name) {
    if (!strcasecmp(ate->name, name)) {
      return ate;
    }
    ate++;
  }
  return NULL;
}

/*****************************************************************
 *
 * INTERNAL HELPER FUNCTIONS
 *
 *****************************************************************/

static void show_group(struct group *g)
{
  /* this is an expeditious hack */
  char members[2048] = {'\0'};
  char **member = NULL;
  int flag = 0;

  log_debug(DEBUG_FUNC, "%s: entering show_group", MOD_SQL_VERSION);

  if (g == NULL ) {
    log_debug(DEBUG_INFO, "%s: NULL group to show_group", MOD_SQL_VERSION);
    log_debug(DEBUG_FUNC, "%s: exiting  show_group", MOD_SQL_VERSION);
    return;
  }

  member = g->gr_mem;

  while (*member != NULL) {
    if (flag) strcat(members, ", ");
    strcat(members, *member); 
    flag = 1;
    member++;
  } 

  log_debug(DEBUG_INFO, "%s: grp.gr_name : %s", MOD_SQL_VERSION, g->gr_name);
  log_debug(DEBUG_INFO, "%s: grp.gr_gid  : %u", MOD_SQL_VERSION, g->gr_gid);
  log_debug(DEBUG_INFO, "%s: grp.gr_mem  : %s", MOD_SQL_VERSION, members);

  log_debug(DEBUG_FUNC, "%s: exiting  show_group", MOD_SQL_VERSION);

  return;
}

static void show_passwd(struct passwd *p)
{
  log_debug(DEBUG_FUNC, "%s: entering show_passwd", MOD_SQL_VERSION);

  if (p == NULL ) {
    log_debug(DEBUG_INFO, "%s: NULL group to show_passwd", MOD_SQL_VERSION);
    log_debug(DEBUG_FUNC, "%s: exiting  show_passwd", MOD_SQL_VERSION);
    return;
  }

  log_debug(DEBUG_INFO, "%s: pwd.pw_name  : %s", MOD_SQL_VERSION, p->pw_name);
  log_debug(DEBUG_INFO, "%s: pwd.pw_uid   : %u", MOD_SQL_VERSION, p->pw_uid);
  log_debug(DEBUG_INFO, "%s: pwd.pw_gid   : %u", MOD_SQL_VERSION, p->pw_gid);
  log_debug(DEBUG_INFO, "%s: pwd.pw_shell : %s", MOD_SQL_VERSION, p->pw_shell);
  log_debug(DEBUG_INFO, "%s: pwd.pw_dir   : %s", MOD_SQL_VERSION, p->pw_dir);

  log_debug(DEBUG_FUNC, "%s: exiting  show_passwd", MOD_SQL_VERSION);
  
  return;
}

static int build_homedir(cmd_rec *cmd, char *path, mode_t omode, uid_t uid, gid_t gid)
{
  struct stat st;
  mode_t old_umask;
  int retval = 0;
  char *local_ptr;
  char *local_path;
  int userdir_flag = 0;
  gid_t p_gid;
  uid_t p_uid;

  log_debug(DEBUG_FUNC, "%s: entering build_homedir(%s,omode,%i,%i)",
            MOD_SQL_VERSION, path, uid, gid);

  /* we assume we're handed a null-terminated string defining the
   * user's home directory. we walk it, directory by directory,
   * creating it if it doesn't exist.  path must start with '/'
   */

  if (path[0] != '/') {
    log_debug(DEBUG_WARN, "%s: no '/' at start of user's homedir", MOD_SQL_VERSION);
    log_debug(DEBUG_FUNC, "%s: exiting  build_homedir", MOD_SQL_VERSION);
    return -1;
  }

  /* sanity check -- make sure the path doesn't exist */
  if (!fs_stat(path, &st)) {
    log_debug(DEBUG_WARN, "%s: user's homedir already exists", MOD_SQL_VERSION);
    log_debug(DEBUG_FUNC, "%s: exiting  build_homedir", MOD_SQL_VERSION);
    return 0;
  } else if (errno != ENOENT) {
    log_debug(DEBUG_WARN, "%s: problem with stat of user's homedir", MOD_SQL_VERSION);
    log_debug(DEBUG_FUNC, "%s: exiting  build_homedir", MOD_SQL_VERSION);
    return -1;
  }

  /* make our local copy of path, adding a '/' if necessary..
   * after this call, we're *guaranteed* a terminating '/'.  We use
   * this info later. */

  if ( path[(strlen(path) - 1)] == '/' )
    local_path = pstrdup(cmd->tmp_pool, path);
  else
    local_path = pstrcat(cmd->tmp_pool, path, "/", NULL);

  /* gain root for dir creation process */
  p_gid = getegid();
  p_uid = geteuid();
  PRIVS_ROOT;

  /* skip the leading '/' */
  local_ptr = local_path + 1;

  while ( ( local_ptr = strchr( local_ptr, '/' ) ) != NULL ) {
    *local_ptr = '\0';

    if ( *(local_ptr + 1) == '\0' )
      userdir_flag = 1;

    if ( fs_stat( local_path, &st ) ) {
      /* if the stat failed.. */
      if (errno == ENOENT) {
	/* and it's 'cause the directory doesn't exist */
	if ( !userdir_flag ) {
	  /* if it's an intermediate dir */
	  if ( mkdir(local_path, S_IRWXU | S_IRWXG | S_IRWXO ) ) {
	    return -1;
	  } else {
	    fs_chown(local_path, p_uid, p_gid );
	  }
	} else {
	  /* this is the user's homedir, and the final directory  */
	  old_umask = umask(0);
	  umask( old_umask & ~(S_IWUSR | S_IXUSR | S_IRUSR) );
	  if ( mkdir(local_path, omode) ) {
	    umask( old_umask );
	    return -1;
	  } else {
	    fs_chown(local_path, uid, gid);
	  }
	  umask( old_umask );
	}
      } else {
	/* we failed for a reason other than no such
	 * directory, so we return an error */
	return -1;
      }
    }
    
    /* fix local_ptr, and bump it */
    *local_ptr = '/';
    local_ptr++;
  }

  /* relinquish root privileges */
  PRIVS_RELINQUISH;

  log_debug(DEBUG_FUNC, "%s: exiting  build_homedir", MOD_SQL_VERSION);
  return (retval);
}

static struct passwd *_sql_getpasswd(cmd_rec * cmd, struct passwd *p)
{
  char *query = NULL;
  sqldata_t *sd = NULL;
  modret_t *mr = NULL;
  struct passwd *pwd = NULL;
  char *username = NULL;
  char uidstr[BUFSIZE] = { '\0' };
  char *temp_ptr = NULL;
  struct stat st;

  if (p == NULL)
    return NULL;

  if (!cmap.homedirfield && !cmap.defaulthomedir) {
    return NULL;
  }

  if (p->pw_name != NULL) {
    username = pstrdup(cmd->tmp_pool, p->pw_name);

    /*
     * double check that the user exists.. 
     */
    temp_ptr = _uservar(cmd, username, cmap.usrfield);
    if (temp_ptr == NULL)
      return NULL;

  } else {
    /*
     * translate our uid into the username 
     */
    snprintf(uidstr, BUFSIZE, "%d", (uid_t) p->pw_uid);

    query = pstrcat(cmd->tmp_pool, "select ", cmap.usrfield, " from ",
                    cmap.usrtable, " where ", cmap.uidfield, " = ",
                    uidstr, " limit 1", NULL);

    mr = modsql_select(cmd, query);

    if (!MODRET_HASDATA(mr)) {
      return NULL;
    }

    sd = (sqldata_t *) mr->data;

    if ((!sd) || (!sd->data) || (!sd->data[0])) {
      return NULL;
    }

    username = pstrdup(cmd->tmp_pool, sd->data[0]);
  }

  pwd = pcalloc(session.pool, sizeof(struct passwd));

  if (cmap.defaulthomedir) {
    temp_ptr = cmap.defaulthomedir;
  } else {
    temp_ptr = _uservar(cmd, username, cmap.homedirfield);
  }
  pwd->pw_dir = pstrdup(session.pool, temp_ptr);

  pwd->pw_name = pstrdup(session.pool, username);

  if (cmap.uidfield) {
    temp_ptr = _uservar(cmd, username, cmap.uidfield);
    pwd->pw_uid = atoi(temp_ptr ? temp_ptr : "0");
  }

  if (pwd->pw_uid < cmap.minid)
    pwd->pw_uid = cmap.defaultuid;

  if (cmap.gidfield) {
    temp_ptr = _uservar(cmd, username, cmap.gidfield);
    pwd->pw_gid = atoi(temp_ptr ? temp_ptr : "0");
  }

  if (pwd->pw_gid < cmap.minid)
    pwd->pw_gid = cmap.defaultgid;

  temp_ptr = _uservar(cmd, username, cmap.shellfield);
  pwd->pw_shell = temp_ptr ? temp_ptr : "";

  log_debug(DEBUG_INFO, "%s: user \"%s\" (%i/%i) for %s", MOD_SQL_VERSION,
            username, pwd->pw_uid, pwd->pw_gid, pwd->pw_dir);

  cmap.authuser = pstrdup(session.pool, username);

  /*
   * finally, build the user's homedir if necessary 
   */

  if (cmap.buildhomedir && (stat(pwd->pw_dir, &st) == -1 && errno == ENOENT)) {
    build_homedir(cmd, pwd->pw_dir, S_IRWXU | S_IRWXG | S_IRWXO, pwd->pw_uid,
                  pwd->pw_gid);
  }

  return pwd;
}

static struct group *_sql_getgroup(cmd_rec * cmd, struct group *g)
{
  struct group *grp = NULL;
  modret_t *mr = NULL;
  char *query = NULL;
  int cnt = 0;
  sqldata_t *sd = NULL;
  char *groupname = NULL;
  char gidstr[BUFSIZE] = { '\0' };
  char **rows = NULL;
  int numrows = 0;
  array_header *ah = NULL;
  char *members = NULL;
  char *member = NULL;

  if (g == NULL)
    return NULL;

  if (g->gr_name != NULL) {
    groupname = pstrdup(cmd->tmp_pool, g->gr_name);
  } else {
    /*
     * translate our gid into the groupname 
     */
    snprintf(gidstr, BUFSIZE, "%d", (gid_t) g->gr_gid);

    query = pstrcat(cmd->tmp_pool, "select ", cmap.grpfield, " from ",
                    cmap.grptable, " where ", cmap.grpgidfield, " = ",
                    gidstr, " limit 1", NULL);

    mr = modsql_select(cmd, query);

    if (!MODRET_HASDATA(mr)) {
      return NULL;
    }

    sd = (sqldata_t *) mr->data;

    if ((!sd) || (!sd->data) || (!sd->data[0])) {
      return NULL;
    }

    groupname = pstrdup(cmd->tmp_pool, sd->data[0]);
  }

  query = pstrcat(cmd->tmp_pool, "select ", cmap.grpfield, ", ",
                  cmap.grpgidfield, ", ", cmap.grpmembersfield,
                  " from ", cmap.grptable, " where ",
                  cmap.grpfield, " = '", groupname, "'", NULL);

  mr = modsql_select(cmd, query);

  if (!MODRET_HASDATA(mr))
    return NULL;

  sd = (sqldata_t *) mr->data;

  rows = sd->data;
  numrows = sd->rowcount;

  if ((!sd) || (!sd->data) || (!sd->data[1])) {
    return NULL;
  }

  grp = (struct group *) pcalloc(session.pool, sizeof(struct group));

  grp->gr_name = pstrdup(session.pool, groupname);
  grp->gr_passwd = NULL;
  grp->gr_gid = (gid_t) strtoul(rows[1], NULL, 10);

  /*
   * painful.. we need to walk through the returned rows and fill in our
   * members. Every third element in a row is a member field, and every
   * member field can have multiple members.
   */

  ah = make_array(cmd->tmp_pool, 10, sizeof(char *));

  for (cnt = 0; cnt < numrows; cnt++) {
    members = rows[(cnt * 3) + 2];
    /* if the row is null, continue.. */
    if (members == NULL) continue;

    /* for each member in the list, toss 'em into the array */
    for (member = strtok(members, ","); member; member = strtok(NULL, ",")) {
      *((char **) push_array(ah)) = pstrdup(session.pool, member);
    }      
  }

  grp->gr_mem = (char **) pcalloc(session.pool, sizeof(char *) * (ah->nelts + 1));
  memcpy(grp->gr_mem, ah->elts, ah->nelts * sizeof(char *));
  grp->gr_mem[ ah->nelts ]='\0';
  
  show_group( grp );
  return grp;
}


/* 
 * fixup_SQLAuthTypes: this will go away in 1.3
 */

static array_header *fixup_SQLAuthTypes(array_header * ah)
{
  log_debug(DEBUG_FUNC, "%s: entering fixup_SQLAuthTypes", MOD_SQL_VERSION);

  /*
   * if SQLAuthTypes is not set for this level, we create it based on current
   * values of the various Password directives. 
   */
  if (!ah) {
    ah = make_array(session.pool, 5, sizeof(auth_type_entry *));

    /*
     * the order here is simply my belief about what's most secure to least..
     * fairly arbitrary, really.. 
     */

#ifdef HAVE_OPENSSL
    if (get_param_int(main_server->conf, "SQLSSLHashedPasswords", FALSE) > 0) {
      *((auth_type_entry **) push_array(ah)) = get_auth_entry("OpenSSL");
    }
#endif
    if (get_param_int(main_server->conf, "SQLEncryptedPasswords", FALSE) > 0) {
      *((auth_type_entry **) push_array(ah)) = get_auth_entry("Crypt");
    }
    if (get_param_int(main_server->conf, "SQLScrambledPasswords", FALSE) > 0) {
      *((auth_type_entry **) push_array(ah)) = get_auth_entry("Backend");
    }
    if (get_param_int(main_server->conf, "SQLPlaintextPasswords", FALSE) > 0) {
      *((auth_type_entry **) push_array(ah)) = get_auth_entry("Plaintext");
    }
    if (get_param_int(main_server->conf, "SQLEmptyPasswords", FALSE) > 0) {
      *((auth_type_entry **) push_array(ah)) = get_auth_entry("Empty");
    }
  }

  log_debug(DEBUG_FUNC, "%s: exiting  fixup_SQLAuthTypes", MOD_SQL_VERSION);
  return ah;
}

/* 
 * fixup_SQLWhereClause
 *
 */

static char *fixup_SQLWhereClause(char *clause)
{
  config_rec *c;
  char *key = NULL;
  char *keyfield = NULL;
  char *whereclause = "";

  /*
   * at start, clause == SQLWhereClause.  
   */
  if (clause) {
    whereclause = pstrcat(session.pool, " and (", clause, ")", NULL);
  } else {
    /*
     * SQLWhereClause doesn't exist -- this whole section goes away in 1.3 
     */
    if ((c =
         find_config(main_server->conf, CONF_PARAM, "SQLKey", FALSE)) != NULL)
      key = c->argv[0];

    if ((c =
         find_config(main_server->conf, CONF_PARAM, "SQLKeyField",
                     FALSE)) != NULL)
      keyfield = c->argv[0];

    /*
     * if both are set 
     */
    if (key && keyfield) {
      whereclause =
          pstrcat(session.pool, " and (", keyfield, " = ", key, ")", NULL);
    }
  }

  return whereclause;
}

static void _setstats(cmd_rec * cmd, int fstor, int fretr,
                      int bstor, int bretr)
{
  /*
   * if anyone has a better way of doing this, let me know.. 
   */
  char query[256] = { '\0' };

  snprintf(query, sizeof(query),
           "%s = %s + %i, %s = %s + %i, %s = %s + %i, %s = %s + %i",
           cmap.sql_fstor, cmap.sql_fstor, fstor,
           cmap.sql_fretr, cmap.sql_fretr, fretr,
           cmap.sql_bstor, cmap.sql_bstor, bstor, cmap.sql_bretr,
           cmap.sql_bretr, bretr);

  modsql_queryuser(cmd, cmap.authuser, query, TRUE);
}

/*****************************************************************
 *
 * CLIENT COMMAND HANDLERS
 *
 *****************************************************************/

MODRET pre_cmd_quit(cmd_rec * cmd)
{
  if (!cmap.doauth)
    return DECLINED(cmd);

  log_debug(DEBUG_FUNC, "%s: entering pre_cmd_quit", MOD_SQL_VERSION);

  modsql_close(cmd);

  log_debug(DEBUG_FUNC, "%s: exiting  pre_cmd_quit", MOD_SQL_VERSION);

  return DECLINED(cmd);
}

MODRET post_cmd_stor(cmd_rec * cmd)
{
  if (!cmap.doauth)
    return DECLINED(cmd);

  log_debug(DEBUG_FUNC, "%s: entering post_cmd_stor", MOD_SQL_VERSION);

  if (cmap.sql_fstor)
    _setstats(cmd, 1, 0, session.xfer.total_bytes, 0);

  log_debug(DEBUG_FUNC, "%s: exiting  post_cmd_stor", MOD_SQL_VERSION);

  return DECLINED(cmd);
}

MODRET cmd_retr(cmd_rec * cmd)
{
  int i;
  char *path, *filename, *query;

  if (!cmap.doauth)
    return DECLINED(cmd);

  log_debug(DEBUG_FUNC, "%s: entering cmd_retr", MOD_SQL_VERSION);

  if (cmap.sql_hittable) {
    path = dir_realpath(cmd->tmp_pool, cmd->argv[1]);

    if (cmap.sql_dir && cmap.sql_dir[0]) {
      for (i = strlen(path), filename = path + i;
           *filename != '/' && i > 1; i--)
        filename--;
      *filename++ = 0;
      query = pstrcat(cmd->tmp_pool, "update ", cmap.sql_hittable,
                      " set ", cmap.sql_hits, " = ", cmap.sql_hits,
                      " + 1 where ", cmap.sql_dir, " = '", ++path,
                      "' and ", cmap.sql_filename, " = '", filename, "'", NULL);
    } else {
      query = pstrcat(cmd->tmp_pool, "update ", cmap.sql_hittable,
                      " set ", cmap.sql_hits, " = ", cmap.sql_hits,
                      " + 1 where ", cmap.sql_filename, " = '", path, "'", NULL);
    }

    modsql_update(cmd, query);
  }

  log_debug(DEBUG_FUNC, "%s: exiting  cmd_retr", MOD_SQL_VERSION);

  return DECLINED(cmd);
}

MODRET post_cmd_retr(cmd_rec * cmd)
{
  if (!cmap.doauth)
    return DECLINED(cmd);

  log_debug(DEBUG_FUNC, "%s: entering post_cmd_retr", MOD_SQL_VERSION);

  if (cmap.sql_fretr)
    _setstats(cmd, 0, 1, 0, session.xfer.total_bytes);

  log_debug(DEBUG_FUNC, "%s: exiting  post_cmd_retr", MOD_SQL_VERSION);

  return DECLINED(cmd);
}

MODRET log_cmd_pass(cmd_rec * cmd)
{
  char *query;

  if (!cmap.doauth)
    return DECLINED(cmd);

  log_debug(DEBUG_FUNC, "%s: entering log_cmd_pass", MOD_SQL_VERSION);

  if (cmap.sql_fhost) {
    query = pstrcat(cmd->tmp_pool, cmap.sql_fhost, " = '",
                    session.c->remote_name, "', ", cmap.sql_faddr,
                    " = '", inet_ntoa(*session.c->remote_ipaddr),
                    "', ", cmap.sql_ftime, " = now()", NULL);
    modsql_queryuser(cmd, cmap.authuser, query, TRUE);
  }

  if (cmap.logcountfield) {
    query = pstrcat(cmd->tmp_pool, cmap.logcountfield, " = ",
                    cmap.logcountfield, " + 1", NULL);
    modsql_queryuser(cmd, cmap.authuser, query, TRUE);
  }

  /*
   * Ideally, we could do what mod_sqlpw did here: Autononpersistence:
   * disconnect now if no other feature is being used. however, the addition 
   * of the getgrgid, name_gid, etc. calls makes this impossible.  Maybe we
   * could add a directive allowing disconnect and thereby ruining all
   * auth functions?
   */

  /*
   * if ( !cmap.sql_fstor && !cmap.sql_fcdir && !cmap.sql_hittable )
   *     modsql_close( cmd );
   */

  log_debug(DEBUG_FUNC, "%s: exiting  log_cmd_pass", MOD_SQL_VERSION);

  return DECLINED(cmd);
}

MODRET log_cmd_cwd(cmd_rec * cmd)
{
  if (!cmap.doauth)
    return DECLINED(cmd);

  log_debug(DEBUG_FUNC, "%s: entering log_cmd_cwd", MOD_SQL_VERSION);

  if (cmap.sql_fcdir) {
    char *query = pstrcat(cmd->tmp_pool, cmap.sql_fcdir, " = '",
                          session.cwd, "'", NULL);
    modsql_queryuser(cmd, cmap.authuser, query, TRUE);
  }

  log_debug(DEBUG_FUNC, "%s: exiting  log_cmd_cwd", MOD_SQL_VERSION);

  return DECLINED(cmd);
}

/*****************************************************************
 *
 * AUTH COMMAND HANDLERS
 *
 *****************************************************************/

MODRET auth_cmd_setpwent(cmd_rec * cmd)
{
  if (!cmap.doauth)
    return DECLINED(cmd);

  log_debug(DEBUG_FUNC, "%s: entering auth_cmd_setpwent", MOD_SQL_VERSION);

  log_debug(DEBUG_WARN, "%s: setpwent is UNIMPLEMENTED", MOD_SQL_VERSION);

  log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_setpwent", MOD_SQL_VERSION);

  return cmap.authoritative ? ERROR(cmd) : DECLINED(cmd);
}

MODRET auth_cmd_getpwent(cmd_rec * cmd)
{
  if (!cmap.doauth)
    return DECLINED(cmd);

  log_debug(DEBUG_FUNC, "%s: entering auth_cmd_getpwent", MOD_SQL_VERSION);

  log_debug(DEBUG_WARN, "%s: getpwent is UNIMPLEMENTED", MOD_SQL_VERSION);

  log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_getpwent", MOD_SQL_VERSION);

  return cmap.authoritative ? HANDLED(cmd) : DECLINED(cmd);
}

MODRET auth_cmd_endpwent(cmd_rec * cmd)
{
  if (!cmap.doauth)
    return DECLINED(cmd);

  log_debug(DEBUG_FUNC, "%s: entering auth_cmd_endpwent", MOD_SQL_VERSION);

  log_debug(DEBUG_WARN, "%s: endpwent is UNIMPLEMENTED", MOD_SQL_VERSION);

  log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_endpwent", MOD_SQL_VERSION);

  return cmap.authoritative ? HANDLED(cmd) : DECLINED(cmd);
}

MODRET auth_cmd_setgrent(cmd_rec * cmd)
{
  if (!cmap.doauth)
    return DECLINED(cmd);

  if (!cmap.dogroupauth)
    return cmap.authoritative ? ERROR(cmd) : DECLINED(cmd);

  log_debug(DEBUG_FUNC, "%s: entering auth_cmd_setgrent", MOD_SQL_VERSION);

  log_debug(DEBUG_WARN, "%s: setgrent is UNIMPLEMENTED", MOD_SQL_VERSION);

  log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_setgrent", MOD_SQL_VERSION);

  return cmap.authoritative ? HANDLED(cmd) : DECLINED(cmd);
}

MODRET auth_cmd_getgrent(cmd_rec * cmd)
{
  if (!cmap.doauth)
    return DECLINED(cmd);

  if (!cmap.dogroupauth)
    return cmap.authoritative ? ERROR(cmd) : DECLINED(cmd);

  log_debug(DEBUG_FUNC, "%s: entering auth_cmd_getgrent", MOD_SQL_VERSION);

  log_debug(DEBUG_WARN, "%s: getgrent is UNIMPLEMENTED", MOD_SQL_VERSION);

  log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_getgrent", MOD_SQL_VERSION);

  return cmap.authoritative ? HANDLED(cmd) : DECLINED(cmd);
}

MODRET auth_cmd_endgrent(cmd_rec * cmd)
{
  if (!cmap.doauth)
    return DECLINED(cmd);

  if (!cmap.dogroupauth)
    return cmap.authoritative ? ERROR(cmd) : DECLINED(cmd);

  log_debug(DEBUG_FUNC, "%s: entering auth_cmd_endgrent", MOD_SQL_VERSION);

  log_debug(DEBUG_WARN, "%s: endgrent is UNIMPLEMENTED", MOD_SQL_VERSION);

  log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_endgrent", MOD_SQL_VERSION);

  return cmap.authoritative ? HANDLED(cmd) : DECLINED(cmd);
}

MODRET auth_cmd_getpwnam(cmd_rec * cmd)
{
  struct passwd *pw;
  struct passwd lpw;

  if (!cmap.doauth)
    return DECLINED(cmd);

  log_debug(DEBUG_FUNC, "%s: entering auth_cmd_getpwnam", MOD_SQL_VERSION);

  lpw.pw_uid = -1;
  lpw.pw_name = pstrdup(cmd->tmp_pool, cmd->argv[0]);
  pw = _sql_getpasswd(cmd, &lpw);

  if (pw == NULL) {
    log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_getpwnam", MOD_SQL_VERSION);
    return cmap.authoritative ? ERROR(cmd) : DECLINED(cmd);
  }

  log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_getpwnam", MOD_SQL_VERSION);

  return mod_create_data(cmd, pw);
}

MODRET auth_cmd_getpwuid(cmd_rec * cmd)
{
  struct passwd *pw;
  struct passwd lpw;

  if (!cmap.doauth)
    return DECLINED(cmd);

  log_debug(DEBUG_FUNC, "%s: entering auth_cmd_getpwuid", MOD_SQL_VERSION);

  lpw.pw_uid = (uid_t) cmd->argv[0];
  lpw.pw_name = NULL;
  pw = _sql_getpasswd(cmd, &lpw);

  if (pw == NULL) {
    log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_getpwuid", MOD_SQL_VERSION);
    return cmap.authoritative ? ERROR(cmd) : DECLINED(cmd);
  }

  log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_getpwuid", MOD_SQL_VERSION);

  return mod_create_data(cmd, pw);
}

MODRET auth_cmd_getgrnam(cmd_rec * cmd)
{
  struct group *gr;
  struct group lgr;

  if (!cmap.doauth)
    return DECLINED(cmd);

  if (!cmap.dogroupauth)
    return cmap.authoritative ? ERROR(cmd) : DECLINED(cmd);

  log_debug(DEBUG_FUNC, "%s: entering auth_cmd_getgrnam", MOD_SQL_VERSION);

  lgr.gr_gid = -1;
  lgr.gr_name = pstrdup(cmd->tmp_pool, cmd->argv[0]);
  gr = _sql_getgroup(cmd, &lgr);

  if (gr == NULL) {
    log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_getgrnam", MOD_SQL_VERSION);
    return cmap.authoritative ? ERROR(cmd) : DECLINED(cmd);
  }

  log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_getgrnam", MOD_SQL_VERSION);
  return mod_create_data(cmd, gr);
}

MODRET auth_cmd_getgrgid(cmd_rec * cmd)
{
  struct group *gr;
  struct group lgr;

  if (!cmap.doauth)
    return DECLINED(cmd);

  if (!cmap.dogroupauth)
    return cmap.authoritative ? ERROR(cmd) : DECLINED(cmd);

  log_debug(DEBUG_FUNC, "%s: entering auth_cmd_getgrgid", MOD_SQL_VERSION);

  lgr.gr_gid = (gid_t) cmd->argv[0];
  lgr.gr_name = NULL;
  gr = _sql_getgroup(cmd, &lgr);

  if (gr == NULL) {
    log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_getgrgid", MOD_SQL_VERSION);
    return cmap.authoritative ? ERROR(cmd) : DECLINED(cmd);
  }

  log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_getgrgid", MOD_SQL_VERSION);
  return mod_create_data(cmd, gr);
}

MODRET auth_cmd_auth(cmd_rec * cmd)
{
  char *query, **row;
  modret_t *mr;
  char *user = cmd->argv[0];
  sqldata_t *sd;

  if (!cmap.doauth)
    return DECLINED(cmd);

  log_debug(DEBUG_FUNC, "%s: entering auth_cmd_auth", MOD_SQL_VERSION);

  query = pstrcat(cmd->tmp_pool, "select ", cmap.pwdfield, " from ",
                  cmap.usrtable, " where ", cmap.usrfield,
                  " = '", user, "' ", cmap.where, " limit 1", NULL);

  mr = modsql_select(cmd, query);

  if (!(MODRET_HASDATA(mr))) {
    /*
     * nothing from db? 
     */
    log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_auth", MOD_SQL_VERSION);
    return cmap.authoritative ? ERROR(cmd) : DECLINED(cmd);
  }

  sd = mr->data;

  row = sd->data;

  /* sanity check */
  if ((row == NULL) || (row[0] == NULL)) {
    log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_auth", MOD_SQL_VERSION);
    return cmap.authoritative ? ERROR(cmd) : DECLINED(cmd);
  }    

  if (auth_check(cmd->tmp_pool, row[0], user, cmd->argv[1])) {
    log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_auth", MOD_SQL_VERSION);
    return cmap.authoritative ? ERROR(cmd) : DECLINED(cmd);
  }

  log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_auth", MOD_SQL_VERSION);

  return HANDLED(cmd);
}

MODRET auth_cmd_check(cmd_rec * cmd)
{
  /*
   * should we bother to see if the hashed password is what we have in the
   * database? or do we simply assume it is, and ignore the fact that we're
   * being passed the username, too? 
   */

  array_header *ah = cmap.authlist;
  auth_type_entry *auth_entry;
  char *c_hash;
  char *c_clear;
  int success = 0;
  int cnt = 0;

  if (!cmap.doauth)
    return DECLINED(cmd);

  log_debug(DEBUG_FUNC, "%s: entering auth_cmd_check", MOD_SQL_VERSION);

  if (cmd->argv[0] == NULL) {
    log_debug(DEBUG_AUTH, "%s: NULL hashed password ", MOD_SQL_VERSION);
  } else if (cmd->argv[2] == NULL) {
    log_debug(DEBUG_AUTH, "%s: NULL clear password ", MOD_SQL_VERSION);
  } else {
    c_hash = pstrdup(cmd->tmp_pool, cmd->argv[0]);
    c_clear = pstrdup(cmd->tmp_pool, cmd->argv[2]);

    for (cnt = 0; cnt < ah->nelts; cnt++) {
      auth_entry = ((auth_type_entry **) ah->elts)[cnt];
      log_debug(DEBUG_AUTH, "%s: checking auth_type %s", MOD_SQL_VERSION,
		auth_entry->name);
      
      if (auth_entry->check_function(cmd, c_clear, c_hash)) {
	log_debug(DEBUG_AUTH, "%s: '%s' auth handler reports success",
		  MOD_SQL_VERSION, auth_entry->name);
	success = 1;
	break;
      }
    }
  }

  log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_check", MOD_SQL_VERSION);

  if (success) {
    cmap.sqlauthorized = 1;
    return HANDLED(cmd);
  }

  return cmap.authoritative ? ERROR(cmd) : DECLINED(cmd);
}

MODRET auth_cmd_uid_name(cmd_rec * cmd)
{
  modret_t *mr = NULL;
  char *query = NULL;
  sqldata_t *sd = NULL;
  char *username = NULL;

  char uidstr[BUFSIZE] = { '\0' };

  if (!cmap.doauth)
    return DECLINED(cmd);

  log_debug(DEBUG_FUNC, "%s: entering auth_cmd_uid_name", MOD_SQL_VERSION);

  snprintf(uidstr, BUFSIZE, "%d", (uid_t) cmd->argv[0]);

  query = pstrcat(cmd->tmp_pool, "select ", cmap.usrfield, " from ",
                  cmap.usrtable, " where ", cmap.uidfield, " = ",
                  uidstr, " limit 1", NULL);

  mr = modsql_select(cmd, query);

  if (!MODRET_HASDATA(mr))
    return cmap.authoritative ? ERROR(cmd) : DECLINED(cmd);

  sd = (sqldata_t *) mr->data;

  if ((!sd) || (!sd->data) || (!sd->data[0])) {
    return cmap.authoritative ? ERROR(cmd) : DECLINED(cmd);
  }

  username = sd->data[0];

  log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_uid_name", MOD_SQL_VERSION);
  return mod_create_data(cmd, username);
}

MODRET auth_cmd_gid_name(cmd_rec * cmd)
{
  modret_t *mr = NULL;
  char *query = NULL;
  sqldata_t *sd;
  char *groupname = NULL;

  char gidstr[BUFSIZE] = { '\0' };

  if (!cmap.doauth)
    return DECLINED(cmd);

  if (!cmap.dogroupauth)
    return cmap.authoritative ? ERROR(cmd) : DECLINED(cmd);

  log_debug(DEBUG_FUNC, "%s: entering auth_cmd_gid_name", MOD_SQL_VERSION);

  snprintf(gidstr, BUFSIZE, "%d", (gid_t) cmd->argv[0]);

  query = pstrcat(cmd->tmp_pool, "select ", cmap.grpfield, " from ",
                  cmap.grptable, " where ", cmap.grpgidfield, " = ",
                  gidstr, " limit 1", NULL);

  mr = modsql_select(cmd, query);

  if (!MODRET_HASDATA(mr))
    return cmap.authoritative ? ERROR(cmd) : DECLINED(cmd);

  sd = (sqldata_t *) mr->data;

  if ((!sd) || (!sd->data) || (!sd->data[0])) {
    return cmap.authoritative ? ERROR(cmd) : DECLINED(cmd);
  }

  groupname = sd->data[0];

  log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_gid_name", MOD_SQL_VERSION);
  return mod_create_data(cmd, groupname);
}

MODRET auth_cmd_name_uid(cmd_rec * cmd)
{
  char *uid;

  if (!cmap.doauth)
    return DECLINED(cmd);

  log_debug(DEBUG_FUNC, "%s: entering auth_cmd_name_uid", MOD_SQL_VERSION);

  uid = _uservar(cmd, cmd->argv[0], cmap.uidfield);

  log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_name_uid", MOD_SQL_VERSION);

  if (!uid) {
    return cmap.authoritative ? ERROR(cmd) : DECLINED(cmd);
  }

  return mod_create_data(cmd, (void *) atol(uid));
}

MODRET auth_cmd_name_gid(cmd_rec * cmd)
{
  modret_t *mr = NULL;
  char *query = NULL;
  sqldata_t *sd;
  gid_t groupid = NULL;

  if (!cmap.doauth)
    return DECLINED(cmd);

  if (!cmap.dogroupauth)
    return cmap.authoritative ? ERROR(cmd) : DECLINED(cmd);

  log_debug(DEBUG_FUNC, "%s: entering auth_cmd_name_gid", MOD_SQL_VERSION);

  query = pstrcat(cmd->tmp_pool, "select ", cmap.grpgidfield, " from ",
                  cmap.grptable, " where ", cmap.grpfield, " = ",
                  cmd->argv[0], " limit 1", NULL);

  mr = modsql_select(cmd, query);

  if (!MODRET_HASDATA(mr))
    return cmap.authoritative ? ERROR(cmd) : DECLINED(cmd);

  sd = (sqldata_t *) mr->data;

  if ((!sd) || (!sd->data) || (!sd->data[0])) {
    return cmap.authoritative ? ERROR(cmd) : DECLINED(cmd);
  }

  groupid = atol(sd->data[0]);

  log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_name_gid", MOD_SQL_VERSION);
  return mod_create_data(cmd, (void *) groupid);
}

MODRET auth_cmd_getstats(cmd_rec * cmd)
{
  modret_t *mr;
  char *query;
  sqldata_t *sd;

  if (!cmap.doauth)
    return DECLINED(cmd);

  log_debug(DEBUG_FUNC, "%s: entering auth_cmd_getstats", MOD_SQL_VERSION);

  if (cmap.sql_fstor) {
    query = pstrcat(cmd->tmp_pool, "select ", cmap.sql_fstor, ", ",
                    cmap.sql_fretr, ", ", cmap.sql_bstor, ", ",
                    cmap.sql_bretr, " from ", cmap.usrtable, " where ",
                    cmap.usrfield, " = '", cmap.authuser, "' ", cmap.where,
                    NULL);

    mr = modsql_select(cmd, query);

    if (MODRET_HASDATA(mr)) {
      log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_getstats",
                MOD_SQL_VERSION);
      /*
       * construct a better MODRET 
       */
      sd = mr->data;
      return mod_create_data(cmd, sd->data);
    }
  }

  log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_getstats", MOD_SQL_VERSION);

  return DECLINED(cmd);
}

MODRET auth_cmd_getratio(cmd_rec * cmd)
{
  modret_t *mr;
  char *query;
  sqldata_t *sd;

  if (!cmap.doauth)
    return DECLINED(cmd);

  log_debug(DEBUG_FUNC, "%s: entering auth_cmd_getratio", MOD_SQL_VERSION);

  if (cmap.sql_frate) {
    query = pstrcat(cmd->tmp_pool, "select ", cmap.sql_frate, ", ",
                    cmap.sql_fcred, ", ", cmap.sql_brate, ", ",
                    cmap.sql_bcred, " from ", cmap.usrtable, " where ",
                    cmap.usrfield, " = '", cmap.authuser, "' ", cmap.where,
                    NULL);

    mr = modsql_select(cmd, query);

    if (MODRET_HASDATA(mr)) {
      log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_getratio",
                MOD_SQL_VERSION);
      /*
       * construct a better MODRET 
       */
      sd = mr->data;
      return mod_create_data(cmd, sd->data);
    }
  }

  log_debug(DEBUG_FUNC, "%s: exiting  auth_cmd_getratio", MOD_SQL_VERSION);

  return DECLINED(cmd);
}

/*****************************************************************
 *
 * CONFIGURATION DIRECTIVE HANDLERS
 *
 *****************************************************************/

MODRET set_sqlloghosts(cmd_rec * cmd)
{
  int b;

  CHECK_CONF(cmd, CONF_ROOT | CONF_GLOBAL);

  switch (cmd->argc - 1) {
  default:
    CONF_ERROR(cmd, "requires a boolean or 3 field names: "
               "fhost faddr ftime");
  case 1:
    if ((b = get_boolean(cmd, 1)) == -1)
      CONF_ERROR(cmd, "requires a boolean or 3 field names: "
                 "fhost faddr ftime");
    if (b)
      add_config_param_str("SQLLogHosts", 3, "fhost", "faddr", "ftime");
    break;

  case 3:
    add_config_param_str("SQLLogHosts", 3,
                         (void *) cmd->argv[1], (void *) cmd->argv[2],
                         (void *) cmd->argv[3]);
  }

  return HANDLED(cmd);
}

MODRET set_sqllogstats(cmd_rec * cmd)
{
  int b;

  CHECK_CONF(cmd, CONF_ROOT | CONF_GLOBAL);

  switch (cmd->argc - 1) {
  default:
    CONF_ERROR(cmd, "requires a boolean or 4 field names: "
               "fstor fretr bstor bretr");
  case 1:
    if ((b = get_boolean(cmd, 1)) == -1)
      CONF_ERROR(cmd, "requires a boolean or 4 field names: "
                 "fstor fretr bstor bretr");
    if (b)
      add_config_param_str("SQLLogStats", 4,
                           "fstor", "fretr", "bstor", "bretr");
    break;

  case 4:
    add_config_param_str("SQLLogStats", 4,
                         (void *) cmd->argv[1], (void *) cmd->argv[2],
                         (void *) cmd->argv[3], (void *) cmd->argv[4]);
  }

  return HANDLED(cmd);
}

MODRET set_sqlloghits(cmd_rec * cmd)
{
  CHECK_CONF(cmd, CONF_ROOT | CONF_GLOBAL);

  switch (cmd->argc - 1) {
  default:
    CONF_ERROR(cmd, "requires a table or table plus 3 fields: "
               "[table] filename count dir");
  case 1:
    add_config_param_str("SQLLogHits", 4, (void *) cmd->argv[1],
                         "filename", "count", "");
    break;
  case 3:
    add_config_param_str("SQLLogHits", 4,
                         (void *) cmd->argv[1], (void *) cmd->argv[2],
                         (void *) cmd->argv[3], "");

  case 4:
    add_config_param_str("SQLLogHits", 4,
                         (void *) cmd->argv[1], (void *) cmd->argv[2],
                         (void *) cmd->argv[3], (void *) cmd->argv[4]);
  }

  return HANDLED(cmd);
}

MODRET set_sqllogdirs(cmd_rec * cmd)
{
  int b;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT | CONF_GLOBAL);

  if ((b = get_boolean(cmd, 1)) == -1)
    add_config_param_str("SQLLogDirs", 1, (void *) cmd->argv[1]);
  else if (b)
    add_config_param_str("SQLLogDirs", 1, "fcdir");

  return HANDLED(cmd);
}

MODRET set_sqlratios(cmd_rec * cmd)
{
  int b;

  CHECK_CONF(cmd, CONF_ROOT | CONF_GLOBAL);

  switch (cmd->argc - 1) {
  default:
    CONF_ERROR(cmd, "requires a boolean or 4 field names: "
               "frate fcred brate bcred");
  case 1:
    if ((b = get_boolean(cmd, 1)) == -1)
      CONF_ERROR(cmd, "requires a boolean or 4 field names: "
                 "frate fcred brate bcred");
    if (b)
      add_config_param_str("SQLRatios", 4,
                           "frate", "fcred", "brate", "bcred");
    break;

  case 4:
    add_config_param_str("SQLRatios", 4,
                         (void *) cmd->argv[1], (void *) cmd->argv[2],
                         (void *) cmd->argv[3], (void *) cmd->argv[4]);
  }

  return HANDLED(cmd);
}

MODRET add_virtualstr(cmd_rec * cmd)
{
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT | CONF_GLOBAL | CONF_VIRTUAL);

  add_config_param_str(cmd->argv[0], 1, (void *) cmd->argv[1]);

  return HANDLED(cmd);
}

MODRET add_virtualbool(cmd_rec * cmd)
{
  int b;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT | CONF_GLOBAL | CONF_VIRTUAL);

  b = get_boolean(cmd, 1);
  if (b == -1)
    CONF_ERROR(cmd, "requires a boolean value");

  c = add_config_param(cmd->argv[0], 1, (void *) b);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_sqlusertablefield(cmd_rec * cmd)
{
  return add_virtualstr(cmd);
}

MODRET set_sqlusernamefield(cmd_rec * cmd)
{
  return add_virtualstr(cmd);
}

MODRET set_sqluidfield(cmd_rec * cmd)
{
  return add_virtualstr(cmd);
}

MODRET set_sqlgidfield(cmd_rec * cmd)
{
  return add_virtualstr(cmd);
}

MODRET set_sqlpasswordfield(cmd_rec * cmd)
{
  return add_virtualstr(cmd);
}

MODRET set_sqlhomedirfield(cmd_rec * cmd)
{
  return add_virtualstr(cmd);
}

MODRET set_sqllogincountfield(cmd_rec * cmd)
{
  return add_virtualstr(cmd);
}

MODRET set_sqlshellfield(cmd_rec * cmd)
{
  return add_virtualstr(cmd);
}

MODRET set_sqlhomedir(cmd_rec * cmd)
{
  return add_virtualstr(cmd);
}

MODRET set_sqlhomedirondemand(cmd_rec * cmd)
{
  return add_virtualbool(cmd);
}

MODRET set_sqlauthoritative(cmd_rec * cmd)
{
  return add_virtualbool(cmd);
}

MODRET set_sqldoauth(cmd_rec * cmd)
{
  return add_virtualbool(cmd);
}

MODRET set_sqldogroupauth(cmd_rec * cmd)
{
  return add_virtualbool(cmd);
}

MODRET set_sqlconnectinfo(cmd_rec * cmd)
{
  config_rec *c;
  char *info = NULL;
  char *user = "";
  char *pass = "";
  char *conf_warning =
      "use of SQLConnectInfo cannot be combined with MySQLInfo, PostgresInfo or PostgresPort Directives.";

  if (find_config(main_server->conf, CONF_PARAM, "MySQLInfo", FALSE) ||
      find_config(main_server->conf, CONF_PARAM, "PostgresInfo", FALSE) ||
      find_config(main_server->conf, CONF_PARAM, "PostgresPort", FALSE)) {
    log_debug(DEBUG_WARN, "%s: %s", MOD_SQL_VERSION, conf_warning);
    CONF_ERROR(cmd, conf_warning);
  }

  CHECK_CONF(cmd, CONF_ROOT | CONF_GLOBAL | CONF_GLOBAL);

  if ((cmd->argc < 2) || (cmd->argc > 4))
    CONF_ERROR(cmd, "requires 1, 2, or 3 values.  Check the mod_sql docs.");

  if (cmd->argc > 1)
    info = cmd->argv[1];

  if (cmd->argc > 2)
    user = cmd->argv[2];

  if (cmd->argc > 3)
    pass = cmd->argv[3];

  c = add_config_param_str("SQLConnectInfo", 3,
                           (void *) info, (void *) user, (void *) pass);

  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_sqlgrouptable(cmd_rec * cmd)
{
  return add_virtualstr(cmd);
}

MODRET set_sqlgroupnamefield(cmd_rec * cmd)
{
  return add_virtualstr(cmd);
}

MODRET set_sqlgroupgidfield(cmd_rec * cmd)
{
  return add_virtualstr(cmd);
}

MODRET set_sqlgroupmembersfield(cmd_rec * cmd)
{
  return add_virtualstr(cmd);
}

MODRET set_sqlauthtypes(cmd_rec * cmd)
{
  config_rec *c;
  array_header *ah;
  char *conf_warning =
      "use of SQLAuthTypes cannot be combined with old-style SQL...Password Directives.";
  auth_type_entry *auth_entry;
  auth_type_entry **auth_handle;
  int cnt;

  CHECK_CONF(cmd, CONF_ROOT | CONF_GLOBAL | CONF_VIRTUAL);

  /*
   * need *at least* one handler 
   */
  if (cmd->argc < 2) {
    CONF_ERROR(cmd, "expected at least one handler type");
  }

  if (                          /* big yucky check goes away in 1.3 */
#ifdef HAVE_OPENSSL
       find_config(main_server->conf, CONF_PARAM, "SQLSSLHashedPasswords",
                   FALSE) ||
#endif
       find_config(main_server->conf, CONF_PARAM, "SQLScrambledPasswords",
                   FALSE)
       || find_config(main_server->conf, CONF_PARAM, "SQLEncryptedPasswords",
                      FALSE)
       || find_config(main_server->conf, CONF_PARAM, "SQLPlaintextPasswords",
                      FALSE)
       || find_config(main_server->conf, CONF_PARAM, "SQLEmptyPasswords",
                      FALSE)) {
    log_debug(DEBUG_WARN, "%s: %s", MOD_SQL_VERSION, conf_warning);
    CONF_ERROR(cmd, conf_warning);
  }

  ah = make_array(permanent_pool, cmd->argc - 1, sizeof(auth_type_entry *));

  /*
   * walk through our cmd->argv 
   */
  for (cnt = 1; cnt < cmd->argc; cnt++) {
    auth_entry = get_auth_entry(cmd->argv[cnt]);
    if (auth_entry == NULL) {
      log_debug(DEBUG_WARN, "%s: unknown auth handler '%s'", MOD_SQL_VERSION,
                cmd->argv[cnt]);
      CONF_ERROR(cmd, "unknown auth handler");
    }

    auth_handle = (auth_type_entry **) push_array(ah);
    *auth_handle = auth_entry;
  }

  c = add_config_param("SQLAuthTypes", 1, (void *) ah);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_sqlwhereclause(cmd_rec * cmd)
{
  char *conf_warning =
      "use of SQLWhereClause cannot be combined with old-style SQLKey/SQLKeyField Directives.";

  if (find_config(main_server->conf, CONF_PARAM, "SQLKey", FALSE) ||
      find_config(main_server->conf, CONF_PARAM, "SQLKeyField", FALSE)) {
    log_debug(DEBUG_WARN, "%s: %s", MOD_SQL_VERSION, conf_warning);
    CONF_ERROR(cmd, conf_warning);
  }

  return add_virtualstr(cmd);
}

MODRET set_sqlminid(cmd_rec * cmd)
{
  config_rec *c;
  unsigned long val;
  char *endptr = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT | CONF_GLOBAL | CONF_VIRTUAL);

  val = strtoul(cmd->argv[1], &endptr, 10);

  if (*endptr != NULL) {
    CONF_ERROR(cmd, "requires a numeric argument");
  }

  /*
   * whee! need to check if in the legal range for uid_t and gid_t 
   */
  /*
   * however, I can't think of a cross-platform way of doing this.. if
   * anyone knows of a way to find the MAX uid_t/gid_t, let me know.. 
   */
  if ((val == ULONG_MAX) && (errno == ERANGE)) {
    CONF_ERROR(cmd, "the value given is outside the legal range");
  }

  c = add_config_param("SQLMinID", 1, (void *) (uid_t) val);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_sqldefaultuid(cmd_rec * cmd)
{
  config_rec *c;
  uid_t val;
  char *endptr = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT | CONF_GLOBAL | CONF_VIRTUAL);

  val = strtoul(cmd->argv[1], &endptr, 10);

  if (*endptr != NULL) {
    CONF_ERROR(cmd, "requires a numeric argument");
  }

  /*
   * whee! need to check is in the legal range for uid_t 
   */
  if ((val == ULONG_MAX) && (errno == ERANGE)) {
    CONF_ERROR(cmd, "the value given is outside the legal range");
  }

  c = add_config_param("SQLDefaultUID", 1, (void *) val);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_sqldefaultgid(cmd_rec * cmd)
{
  config_rec *c;
  gid_t val;
  char *endptr = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT | CONF_GLOBAL | CONF_VIRTUAL);

  val = strtoul(cmd->argv[1], &endptr, 10);

  if (*endptr != NULL) {
    CONF_ERROR(cmd, "requires a numeric argument");
  }

  /*
   * whee! need to check is in the legal range for gid_t 
   */
  if ((val == ULONG_MAX) && (errno == ERANGE)) {
    CONF_ERROR(cmd, "the value given is outside the legal range");
  }

  c = add_config_param("SQLDefaultGID", 1, (void *) val);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_sqlscrambledpasswords(cmd_rec * cmd)
{
  char *dep_warning =
      "use of SQLScrambledPasswords is DEPRECATED.  Use SQLAuthTypes instead.";
  char *conf_warning =
      "use of SQLScrambledPasswords cannot be combined with use of SQLAuthTypes.";

  log_debug(DEBUG_WARN, "%s: %s", MOD_SQL_VERSION, conf_warning);
  log_pri(LOG_WARNING, "%s: %s", MOD_SQL_VERSION, dep_warning);

  if (find_config(main_server->conf, CONF_PARAM, "SQLAuthTypes", FALSE)) {
    log_debug(DEBUG_WARN, "%s: %s", MOD_SQL_VERSION, conf_warning);
    CONF_ERROR(cmd, conf_warning);
  }

  return add_virtualbool(cmd);
}

MODRET set_sqlsslhashedpasswords(cmd_rec * cmd)
{
  char *dep_warning =
      "use of SQLSSLHashedPasswords is DEPRECATED.  Use SQLAuthTypes instead.";
  char *conf_warning =
      "use of SQLSSLHashedPasswords cannot be combined with use of SQLAuthTypes.";

  log_debug(DEBUG_WARN, "%s: %s", MOD_SQL_VERSION, conf_warning);
  log_pri(LOG_WARNING, "%s: %s", MOD_SQL_VERSION, dep_warning);

  if (find_config(main_server->conf, CONF_PARAM, "SQLAuthTypes", FALSE)) {
    log_debug(DEBUG_WARN, "%s: %s", MOD_SQL_VERSION, conf_warning);
    CONF_ERROR(cmd, conf_warning);
  }

  return add_virtualbool(cmd);
}

MODRET set_sqlencryptedpasswords(cmd_rec * cmd)
{
  char *dep_warning =
      "use of SQLEncryptedPasswords is DEPRECATED.  Use SQLAuthTypes instead.";
  char *conf_warning =
      "use of SQLEncryptedPasswords cannot be combined with use of SQLAuthTypes.";

  log_debug(DEBUG_WARN, "%s: %s", MOD_SQL_VERSION, conf_warning);
  log_pri(LOG_WARNING, "%s: %s", MOD_SQL_VERSION, dep_warning);

  if (find_config(main_server->conf, CONF_PARAM, "SQLAuthTypes", FALSE)) {
    log_debug(DEBUG_WARN, "%s: %s", MOD_SQL_VERSION, conf_warning);
    CONF_ERROR(cmd, conf_warning);
  }

  return add_virtualbool(cmd);
}

MODRET set_sqlplaintextpasswords(cmd_rec * cmd)
{
  char *dep_warning =
      "use of SQLPlaintextPasswords is DEPRECATED.  Use SQLAuthTypes instead.";
  char *conf_warning =
      "use of SQLPlaintextPasswords cannot be combined with use of SQLAuthTypes.";

  log_debug(DEBUG_WARN, "%s: %s", MOD_SQL_VERSION, conf_warning);
  log_pri(LOG_WARNING, "%s: %s", MOD_SQL_VERSION, dep_warning);

  if (find_config(main_server->conf, CONF_PARAM, "SQLAuthTypes", FALSE)) {
    log_debug(DEBUG_WARN, "%s: %s", MOD_SQL_VERSION, conf_warning);
    CONF_ERROR(cmd, conf_warning);
  }

  return add_virtualbool(cmd);
}

MODRET set_sqlkeyfield(cmd_rec * cmd)
{
  char *dep_warning =
      "use of SQLKeyField is DEPRECATED.  Use SQLWhereClause instead.";
  char *conf_warning =
      "use of SQLKeyField cannot be combined with use of SQLWhereClause.";

  log_debug(DEBUG_WARN, "%s: %s", MOD_SQL_VERSION, conf_warning);
  log_pri(LOG_WARNING, "%s: %s", MOD_SQL_VERSION, dep_warning);

  if (find_config(main_server->conf, CONF_PARAM, "SQLWhereClause", FALSE)) {
    log_debug(DEBUG_WARN, "%s: %s", MOD_SQL_VERSION, conf_warning);
    CONF_ERROR(cmd, conf_warning);
  }

  return add_virtualstr(cmd);
}

MODRET set_sqlkey(cmd_rec * cmd)
{
  char *dep_warning =
      "use of SQLKey is DEPRECATED.  Use SQLWhereClause instead.";
  char *conf_warning =
      "use of SQLKey cannot be combined with use of SQLWhereClause.";

  log_debug(DEBUG_WARN, "%s: %s", MOD_SQL_VERSION, conf_warning);
  log_pri(LOG_WARNING, "%s: %s", MOD_SQL_VERSION, dep_warning);

  if (find_config(main_server->conf, CONF_PARAM, "SQLWhereClause", FALSE)) {
    log_debug(DEBUG_WARN, "%s: %s", MOD_SQL_VERSION, conf_warning);
    CONF_ERROR(cmd, conf_warning);
  }

  return add_virtualstr(cmd);
}

MODRET set_sqlemptypasswords(cmd_rec * cmd)
{
  char *dep_warning =
      "use of SQLEmptyPasswords is DEPRECATED.  Use SQLAuthTypes instead.";
  char *conf_warning =
      "use of SQLEmptyPasswords cannot be combined with use of SQLAuthTypes.";

  log_debug(DEBUG_WARN, "%s: %s", MOD_SQL_VERSION, conf_warning);
  log_pri(LOG_WARNING, "%s: %s", MOD_SQL_VERSION, dep_warning);

  if (find_config(main_server->conf, CONF_PARAM, "SQLAuthTypes", FALSE)) {
    log_debug(DEBUG_WARN, "%s: %s", MOD_SQL_VERSION, conf_warning);
    CONF_ERROR(cmd, conf_warning);
  }

  return add_virtualbool(cmd);
}

MODRET set_mysqlinfo(cmd_rec * cmd)
{
  config_rec *c;
  char *user;
  char *info;
  char *pass;

  char *dep_warning =
      "use of MySQLInfo is DEPRECATED.  Use SQLConnectInfo instead.";
  char *conf_warning =
      "use of MySQLInfo cannot be combined with use of SQLConnectInfo, PostgresInfo, or PostgresPort.";

  log_debug(DEBUG_WARN, "%s: %s", MOD_SQL_VERSION, conf_warning);
  log_pri(LOG_WARNING, "%s: %s", MOD_SQL_VERSION, dep_warning);

  if (find_config(main_server->conf, CONF_PARAM, "SQLWhereClause", FALSE)) {
    log_debug(DEBUG_WARN, "%s: %s", MOD_SQL_VERSION, conf_warning);
    CONF_ERROR(cmd, conf_warning);
  }

  CHECK_ARGS(cmd, 4);
  CHECK_CONF(cmd, CONF_ROOT | CONF_GLOBAL | CONF_VIRTUAL);

  user = cmd->argv[2];
  pass = cmd->argv[3];
  info = pstrcat(permanent_pool, cmd->argv[4], "@", cmd->argv[1], NULL);

  c = add_config_param_str("SQLConnectInfo", 3,
                           (void *) info, (void *) user, (void *) pass);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_postgresinfo(cmd_rec * cmd)
{
  config_rec *c;
  config_rec *pinfo;
  config_rec *pport;

  int setpinfo = 0;
  int setpport = 0;

  char *user = NULL;
  char *pass = NULL;
  char *info = NULL;
  char *port = NULL;
  char *host = NULL;
  char *db = NULL;

  char *dep_warning =
      "use of PostgresInfo and PostgresPort is DEPRECATED.  Use SQLConnectInfo instead.";
  char *conf_warning =
      "use of PostgresInfo and PostgresPort cannot be combined with use of SQLConnectInfo or MySQLInfo.";

  log_debug(DEBUG_WARN, "%s: %s", MOD_SQL_VERSION, conf_warning);
  log_pri(LOG_WARNING, "%s: %s", MOD_SQL_VERSION, dep_warning);

  if (find_config(main_server->conf, CONF_PARAM, "SQLConnectInfo", FALSE) ||
      find_config(main_server->conf, CONF_PARAM, "SQLConnectInfo", FALSE)) {
    log_debug(DEBUG_WARN, "%s: %s", MOD_SQL_VERSION, conf_warning);
    CONF_ERROR(cmd, conf_warning);
  }

  CHECK_CONF(cmd, CONF_ROOT | CONF_GLOBAL | CONF_VIRTUAL);

  /*
   * We have to get *both* the PostgresInfo and PostgresPort data.  This is
   * inefficient, both in space and in time, but users shouldn't be using
   * deprecated directives. 
   */

  pinfo = find_config(main_server->conf, CONF_PARAM, "PostgresInfo", FALSE);
  pport = find_config(main_server->conf, CONF_PARAM, "PostgresPort", FALSE);

  setpinfo = !strcasecmp(cmd->argv[0], "postgresinfo");
  setpport = !strcasecmp(cmd->argv[0], "postgresport");

  if (setpinfo) {
    if ((cmd->argc != 3) && (cmd->argc != 5))
      CONF_ERROR(cmd, "requires 2 or 4 items: " "host [user pass] dbname");
  }

  if (setpport) {
    CHECK_ARGS(cmd, 1);
  }

  /*
   * choices: 1) we're setting pinfo, we have no pport: create
   * SQLConnectInfo & PostgresInfo 2) we're setting pinfo, we have pport:
   * create SQLConnectInfo & PostgresInfo 2) we're setting pport, we have no
   * pinfo: create PostgresPort 3) we're setting pport, we have pinfo: create 
   * SQLConnectInfo & PostgresPort 
   */

  /*
   * if we have PostgresInfo already, let's get it.. 
   */
  if (pinfo) {
    host = pinfo->argv[0];
    user = pinfo->argv[1];
    pass = pinfo->argv[2];
    db = pinfo->argv[3];
  }

  /*
   * if we have PostgresPort already, let's get it.. 
   */
  if (pport) {
    port = pport->argv[0];
  }

  /*
   * if we're setting PostgresInfo, let's update it.. 
   */
  if (setpinfo) {
    if (cmd->argc == 3) {
      host = cmd->argv[1];
      db = cmd->argv[2];
    } else {
      host = cmd->argv[1];
      user = cmd->argv[2];
      pass = cmd->argv[3];
      db = cmd->argv[4];
    }

    c = add_config_param_str("PostgresInfo", 4,
                             (void *) host,
                             (void *) user, (void *) pass, (void *) db);
    c->flags |= CF_MERGEDOWN;
  }

  /*
   * if we're setting PostgresPort, let's update it.. 
   */
  if (setpport) {
    port = cmd->argv[1];

    c = add_config_param_str("PostgresPort", 1, (void *) port);

    c->flags |= CF_MERGEDOWN;
  }


  /*
   * if we have pinfo, or we're setting pinfo, set SQLConnectInfo 
   */
  if (pinfo || setpinfo) {
    if (!port)
      info = pstrcat(permanent_pool, db, "@", host, NULL);
    else
      info = pstrcat(permanent_pool, db, "@", host, ":", port, NULL);

    c = add_config_param_str("SQLConnectInfo", 3,
                             (void *) info, (void *) user, (void *) pass);
    c->flags |= CF_MERGEDOWN;
  }

  return HANDLED(cmd);
}

/*****************************************************************
 *
 * INITIALIZATION / FORK HANDLERS
 *
 *****************************************************************/

static int sql_init(void)
{
  /*
   * when we implement uid/gid cacheing as per mod_ldap, initialization goes
   * here. 
   */
  return 0;
}

static int sql_getconf()
{
  config_rec *c;
  modret_t *mr;
  void *temp_ptr;

  log_debug(DEBUG_FUNC, "%s: entering sql_getconf", MOD_SQL_VERSION);

  /*
   * construct our internal cache structure for this fork 
   */

  memset(&cmap, 0, sizeof(cmap));

  /*
   * If we have no SQLConnectInfo, set doauth to off and bail 
   */
  if (!find_config(main_server->conf, CONF_PARAM, "SQLConnectInfo", FALSE)) {
    cmap.doauth = 0;
    return 0;
  }

  /*
   * SQLDoAuth defaults to YES 
   */
  cmap.doauth = get_param_int(main_server->conf, "SQLDoAuth", FALSE);
  if (cmap.doauth == -1)
    cmap.doauth = 1;

  /*
   * SQLDoGroupAuth defaults to YES 
   */
  cmap.dogroupauth =
      get_param_int(main_server->conf, "SQLDoGroupAuth", FALSE);
  if (cmap.dogroupauth == -1)
    cmap.dogroupauth = 1;

  /*
   * SQLAuthoritative defaults to NO 
   */
  cmap.authoritative =
      get_param_int(main_server->conf, "SQLAuthoritative", FALSE);
  if (cmap.authoritative == -1)
    cmap.authoritative = 0;

  /*
   * SQLHomedirOnDemand defaults to NO 
   */
  cmap.buildhomedir =
      get_param_int(main_server->conf, "SQLHomedirOnDemand", FALSE);
  if (cmap.buildhomedir == -1)
    cmap.buildhomedir = 0;

  temp_ptr = get_param_ptr(main_server->conf, "SQLUserTable", FALSE);
  cmap.usrtable = temp_ptr ? temp_ptr : SQL_DEFAULT_USERTABLE;

  temp_ptr = get_param_ptr(main_server->conf, "SQLUsernameField", FALSE);
  cmap.usrfield = temp_ptr ? temp_ptr : SQL_DEFAULT_USERNAMEFIELD;

  temp_ptr = get_param_ptr(main_server->conf, "SQLPasswordField", FALSE);
  cmap.pwdfield = temp_ptr ? temp_ptr : SQL_DEFAULT_USERPASSWORDFIELD;

  temp_ptr = get_param_ptr(main_server->conf, "SQLUidField", FALSE);
  cmap.uidfield = temp_ptr ? temp_ptr : SQL_DEFAULT_USERUIDFIELD;

  temp_ptr = get_param_ptr(main_server->conf, "SQLGidField", FALSE);
  cmap.gidfield = temp_ptr ? temp_ptr : SQL_DEFAULT_USERGIDFIELD;

  cmap.logcountfield =
      get_param_ptr(main_server->conf, "SQLLoginCountField", FALSE);

  temp_ptr = get_param_ptr(main_server->conf, "SQLWhereClause", FALSE);
  cmap.where = fixup_SQLWhereClause((char *) temp_ptr);

  temp_ptr = get_param_ptr(main_server->conf, "SQLAuthTypes", FALSE);
  cmap.authlist = fixup_SQLAuthTypes((array_header *) temp_ptr);

  temp_ptr = get_param_ptr(main_server->conf, "SQLShellField", FALSE);
  cmap.shellfield = temp_ptr ? temp_ptr : SQL_DEFAULT_USERSHELLFIELD;

  cmap.defaulthomedir = get_param_ptr(main_server->conf, "SQLHomedir", FALSE);
  cmap.homedirfield =
      get_param_ptr(main_server->conf, "SQLHomedirField", FALSE);

  temp_ptr = get_param_ptr(main_server->conf, "SQLMinID", FALSE);
  cmap.minid = temp_ptr ? ((uid_t) temp_ptr) : SQL_MIN_ID;

  temp_ptr = get_param_ptr(main_server->conf, "SQLDefaultUID", FALSE);
  cmap.defaultuid = temp_ptr ? ((uid_t) temp_ptr) : SQL_DEFAULT_UID;

  temp_ptr = get_param_ptr(main_server->conf, "SQLDefaultGID", FALSE);
  cmap.defaultgid = temp_ptr ? ((gid_t) temp_ptr) : SQL_DEFAULT_GID;

  temp_ptr = get_param_ptr(main_server->conf, "SQLGroupTable", FALSE);
  cmap.grptable = temp_ptr ? temp_ptr : SQL_DEFAULT_GROUPTABLE;

  temp_ptr = get_param_ptr(main_server->conf, "SQLGroupnameField", FALSE);
  cmap.grpfield = temp_ptr ? temp_ptr : SQL_DEFAULT_GROUPNAMEFIELD;

  temp_ptr = get_param_ptr(main_server->conf, "SQLGroupGIDField", FALSE);
  cmap.grpgidfield = temp_ptr ? temp_ptr : SQL_DEFAULT_GROUPGIDFIELD;

  temp_ptr = get_param_ptr(main_server->conf, "SQLGroupMembersField", FALSE);
  cmap.grpmembersfield = temp_ptr ? temp_ptr : SQL_DEFAULT_GROUPMEMBERSFIELD;

  if ((c = find_config(main_server->conf, CONF_PARAM, "SQLLogHosts", FALSE))) {
    cmap.sql_fhost = c->argv[0];
    cmap.sql_faddr = c->argv[1];
    cmap.sql_ftime = c->argv[2];
  }

  if ((c = find_config(main_server->conf, CONF_PARAM, "SQLLogStats", FALSE))) {
    cmap.sql_fstor = c->argv[0];
    cmap.sql_fretr = c->argv[1];
    cmap.sql_bstor = c->argv[2];
    cmap.sql_bretr = c->argv[3];
  }

  if ((c = find_config(main_server->conf, CONF_PARAM, "SQLRatios", FALSE))) {
    if (!cmap.sql_fstor) {
      log_pri(LOG_WARNING,
              "%s: warning: SQLRatios directive ineffective without SQLLogStats on",
              MOD_SQL_VERSION);
      log_debug(DEBUG_WARN,
                "%s: warning: SQLRatios directive ineffective without SQLLogStats on",
                MOD_SQL_VERSION);
    }
    cmap.sql_frate = c->argv[0];
    cmap.sql_fcred = c->argv[1];
    cmap.sql_brate = c->argv[2];
    cmap.sql_bcred = c->argv[3];
  }

  if ((c = find_config(main_server->conf, CONF_PARAM, "SQLLogHits", FALSE))) {
    cmap.sql_hittable = c->argv[0];
    cmap.sql_filename = c->argv[1];
    cmap.sql_hits = c->argv[2];
    cmap.sql_dir = c->argv[3];
  }

  cmap.sql_fcdir = get_param_ptr(main_server->conf, "SQLLogDirs", FALSE);

  if (!(cmap.defaulthomedir || cmap.homedirfield)
      && !cmap.sql_fhost && !cmap.sql_fstor && !cmap.sql_fcdir) {
    log_debug(DEBUG_FUNC, "%s: exiting  sql_getconf", MOD_SQL_VERSION);
    return 0;
  }

  mr = modsql_open(NULL);
  if (MODRET_ISHANDLED(mr)) {
    log_debug(DEBUG_INFO, "%s: backend successfully connected.",
              MOD_SQL_VERSION);
    log_debug(DEBUG_INFO, "%s: SQLDoAuth         : %s", MOD_SQL_VERSION,
              (cmap.doauth ? "true" : "false"));
    log_debug(DEBUG_INFO, "%s: usertable         : %s", MOD_SQL_VERSION,
              cmap.usrtable);
    log_debug(DEBUG_INFO, "%s: userid field      : %s", MOD_SQL_VERSION,
              cmap.usrfield);
    log_debug(DEBUG_INFO, "%s: password field    : %s", MOD_SQL_VERSION,
              cmap.pwdfield);
    log_debug(DEBUG_INFO, "%s: uid field         : %s", MOD_SQL_VERSION,
              cmap.uidfield);
    log_debug(DEBUG_INFO, "%s: gid field         : %s", MOD_SQL_VERSION,
              cmap.gidfield);
    log_debug(DEBUG_INFO, "%s: shell field       : %s", MOD_SQL_VERSION,
              cmap.shellfield);
    log_debug(DEBUG_INFO, "%s: homedir field     : %s", MOD_SQL_VERSION,
              (cmap.homedirfield ? cmap.homedirfield : "(default)"));
    log_debug(DEBUG_INFO, "%s: default homedir   : %s", MOD_SQL_VERSION,
              (cmap.defaulthomedir ? cmap.defaulthomedir : "(none)"));
    log_debug(DEBUG_INFO, "%s: homedirondemand   : %s", MOD_SQL_VERSION,
              (cmap.buildhomedir ? "true" : "false"));

    log_debug(DEBUG_INFO, "%s: SQLDoGroupAuth    : %s", MOD_SQL_VERSION,
              (cmap.dogroupauth ? "true" : "false"));
    log_debug(DEBUG_INFO, "%s: group table       : %s", MOD_SQL_VERSION,
              cmap.grptable);
    log_debug(DEBUG_INFO, "%s: groupname field   : %s", MOD_SQL_VERSION,
              cmap.grpfield);
    log_debug(DEBUG_INFO, "%s: grp gid field     : %s", MOD_SQL_VERSION,
              cmap.grpgidfield);
    log_debug(DEBUG_INFO, "%s: grp members field : %s", MOD_SQL_VERSION,
              cmap.grpmembersfield);

    log_debug(DEBUG_INFO, "%s: SQLMinID          : %u", MOD_SQL_VERSION,
              cmap.minid);
    log_debug(DEBUG_INFO, "%s: SQLDefaultUID     : %u", MOD_SQL_VERSION,
              cmap.defaultuid);
    log_debug(DEBUG_INFO, "%s: SQLDefaultGID     : %u", MOD_SQL_VERSION,
              cmap.defaultgid);



    if (cmap.sql_fhost)
      log_debug(DEBUG_INFO, "%s: sql_fhost         : %s", MOD_SQL_VERSION,
                cmap.sql_fhost);
    if (cmap.sql_fstor)
      log_debug(DEBUG_INFO, "%s: sql_fstor         : %s", MOD_SQL_VERSION,
                cmap.sql_fstor);
    if (cmap.sql_frate)
      log_debug(DEBUG_INFO, "%s: sql_frate         : %s", MOD_SQL_VERSION,
                cmap.sql_frate);
    if (cmap.sql_hittable)
      log_debug(DEBUG_INFO, "%s: sql_hittable      : %s", MOD_SQL_VERSION,
                cmap.sql_hittable);
    if (cmap.sql_fcdir)
      log_debug(DEBUG_INFO, "%s: sql_fcdir         : %s", MOD_SQL_VERSION,
                cmap.sql_fcdir);
  } else {
    memset(&cmap, 0, sizeof(cmap));
    log_debug(DEBUG_INFO, "%s: no backend could connect", MOD_SQL_VERSION);
    log_debug(DEBUG_INFO, "%s: SQLDoAuth         : %s", MOD_SQL_VERSION,
              (cmap.doauth ? "true" : "false"));
    log_debug(DEBUG_INFO, "%s: SQLDoGroupAuth    : %s", MOD_SQL_VERSION,
              (cmap.dogroupauth ? "true" : "false"));
  }

  log_debug(DEBUG_FUNC, "%s: exiting  sql_getconf", MOD_SQL_VERSION);

  return 0;
}

/*****************************************************************
 *
 * HANDLER TABLES
 *
 *****************************************************************/

static conftable sql_conftab[] = {
  {"SQLAuthoritative", set_sqlauthoritative, NULL},
  {"SQLDoAuth", set_sqldoauth, NULL},
  {"SQLDoGroupAuth", set_sqldogroupauth, NULL},

  {"SQLConnectInfo", set_sqlconnectinfo, NULL},

  {"SQLUserTable", set_sqlusertablefield, NULL},
  {"SQLUsernameField", set_sqlusernamefield, NULL},
  {"SQLUidField", set_sqluidfield, NULL},
  {"SQLGidField", set_sqlgidfield, NULL},
  {"SQLPasswordField", set_sqlpasswordfield, NULL},
  {"SQLHomedirField", set_sqlhomedirfield, NULL},
  {"SQLShellField", set_sqlshellfield, NULL},

  {"SQLGroupTable", set_sqlgrouptable, NULL},
  {"SQLGroupnameField", set_sqlgroupnamefield, NULL},
  {"SQLGroupGIDField", set_sqlgroupgidfield, NULL},
  {"SQLGroupMembersField", set_sqlgroupmembersfield, NULL},

  {"SQLAuthTypes", set_sqlauthtypes, NULL},
  {"SQLWhereClause", set_sqlwhereclause, NULL},

  {"SQLMinID", set_sqlminid, NULL},
  {"SQLDefaultUID", set_sqldefaultuid, NULL},
  {"SQLDefaultGID", set_sqldefaultgid, NULL},

  {"SQLLogHosts", set_sqlloghosts, NULL},
  {"SQLLogStats", set_sqllogstats, NULL},
  {"SQLLogHits", set_sqlloghits, NULL},
  {"SQLLogDirs", set_sqllogdirs, NULL},
  {"SQLRatios", set_sqlratios, NULL},

  {"SQLLoginCountField", set_sqllogincountfield, NULL},
  {"SQLHomedir", set_sqlhomedir, NULL},
  {"SQLHomedirOnDemand", set_sqlhomedirondemand, NULL},

  /*
   * The following are DEPRECATED. Expect them to disappear in 1.3 
   */

  {"SQLScrambledPasswords", set_sqlscrambledpasswords, NULL},
#ifdef HAVE_OPENSSL
  {"SQLSSLHashedPasswords", set_sqlsslhashedpasswords, NULL},
#endif
  {"SQLEncryptedPasswords", set_sqlencryptedpasswords, NULL},
  {"SQLPlaintextPasswords", set_sqlplaintextpasswords, NULL},
  {"SQLKeyField", set_sqlkeyfield, NULL},
  {"SQLKey", set_sqlkey, NULL},
  {"SQLEmptyPasswords", set_sqlemptypasswords, NULL},

  {"MySQLInfo", set_mysqlinfo, NULL},
  {"PostgresInfo", set_postgresinfo, NULL},
  {"PostgresPort", set_postgresinfo, NULL},

  {NULL, NULL, NULL}
};

static cmdtable sql_cmdtab[] = {
  {PRE_CMD, C_QUIT, G_NONE, pre_cmd_quit, FALSE, FALSE},
  {POST_CMD, C_STOR, G_NONE, post_cmd_stor, FALSE, FALSE},
  {CMD, C_RETR, G_NONE, cmd_retr, FALSE, FALSE},
  {POST_CMD, C_RETR, G_NONE, post_cmd_retr, FALSE, FALSE},
  {LOG_CMD, C_PASS, G_NONE, log_cmd_pass, FALSE, FALSE},
  {LOG_CMD, C_CWD, G_NONE, log_cmd_cwd, FALSE, FALSE},
  {LOG_CMD, C_CDUP, G_NONE, log_cmd_cwd, FALSE, FALSE},
  {0, NULL}
};

static authtable sql_authtab[] = {
  {0, "setpwent", auth_cmd_setpwent},
  {0, "getpwent", auth_cmd_getpwent},
  {0, "endpwent", auth_cmd_endpwent},
  {0, "setgrent", auth_cmd_setgrent},
  {0, "getgrent", auth_cmd_getgrent},
  {0, "endgrent", auth_cmd_endgrent},
  {0, "getpwnam", auth_cmd_getpwnam},
  {0, "getpwuid", auth_cmd_getpwuid},
  {0, "getgrnam", auth_cmd_getgrnam},
  {0, "getgrgid", auth_cmd_getgrgid},
  {0, "auth", auth_cmd_auth},
  {0, "check", auth_cmd_check},
  {0, "uid_name", auth_cmd_uid_name},
  {0, "gid_name", auth_cmd_gid_name},
  {0, "name_uid", auth_cmd_name_uid},
  {0, "name_gid", auth_cmd_name_gid},
  {0, "getstats", auth_cmd_getstats},
  {0, "getratio", auth_cmd_getratio},
  {0, NULL, NULL}
};

module sql_module = {
  NULL, NULL,                   /* Always NULL */
  0x20,                         /* API Version 2.0 */
  "sql",
  sql_conftab,                  /* SQL configuration handler table */
  sql_cmdtab,                   /* SQL command handler table */
  sql_authtab,                  /* SQL authentication handler table */
  sql_init,                     /* Pre-fork "parent mode" init */
  sql_getconf                   /* Post-fork "child mode" init */
};
