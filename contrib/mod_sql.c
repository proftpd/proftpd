/*
 * ProFTPD: mod_sql -- SQL frontend
 * Copyright (c) 1998-1999 Johnie Ingram.
 * Copyright (c) 2001 Andrew Houghton.
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

#define _MOD_VERSION "mod_sql/4.08"

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

/* Uncomment the following define to allow OpenSSL hashed password checking;  
 * you'll also need to link with OpenSSL's crypto library ( -lcrypto ) 
 */
/* #define HAVE_OPENSSL */

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#endif

#include "conf.h"
#include "privs.h"
#include "fs.h"
#include "../contrib/mod_sql.h"

/* default information for tables and fields */
#define MODSQL_DEF_USERTABLE         "users"
#define MODSQL_DEF_USERNAMEFIELD     "userid"
#define MODSQL_DEF_USERUIDFIELD      "uid"
#define MODSQL_DEF_USERGIDFIELD      "gid"
#define MODSQL_DEF_USERPASSWORDFIELD "password"
#define MODSQL_DEF_USERSHELLFIELD    "shell"
#define MODSQL_DEF_USERHOMEDIRFIELD  "homedir"

#define MODSQL_DEF_GROUPTABLE        "groups"
#define MODSQL_DEF_GROUPNAMEFIELD    "groupname"
#define MODSQL_DEF_GROUPGIDFIELD     "gid"
#define MODSQL_DEF_GROUPMEMBERSFIELD "members"

/* default minimum id / default uid / default gid info. 
 * uids and gids less than MODSQL_MIN_USER_UID and
 * MODSQL_MIN_USER_GID, respectively, get automatically
 * mapped to the defaults, below.  These can be
 * overridden using directives
 */
#define MODSQL_MIN_USER_UID 999
#define MODSQL_MIN_USER_GID 999
#define MODSQL_DEF_UID 65533
#define MODSQL_DEF_GID 65533

#define MODSQL_BUFSIZE 32

/* Named Query defines */
#define SQL_SELECT_C "SELECT"
#define SQL_INSERT_C "INSERT"
#define SQL_UPDATE_C "UPDATE"
#define SQL_FREEFORM_C "FREEFORM"

/* authmask defines */
#define SQL_AUTH_USERS             (1<<0)
#define SQL_AUTH_GROUPS            (1<<1)
#define SQL_AUTH_USERS_DEFINITIVE  (1<<2)
#define SQL_AUTH_GROUPS_DEFINITIVE (1<<3)
#define SQL_AUTH_USERSET           (1<<4)
#define SQL_AUTH_GROUPSET          (1<<5)
#define SQL_FAST_USERSET           (1<<6)
#define SQL_FAST_GROUPSET          (1<<7)

#define SQL_GROUPS             (cmap.authmask & SQL_AUTH_GROUPS)
#define SQL_USERS              (cmap.authmask & SQL_AUTH_USERS)
#define SQL_GROUPSET           (cmap.authmask & SQL_AUTH_GROUPSET)
#define SQL_USERSET            (cmap.authmask & SQL_AUTH_USERSET)
#define SQL_FASTGROUPS         (cmap.authmask & SQL_FAST_GROUPSET)
#define SQL_FASTUSERS          (cmap.authmask & SQL_FAST_USERSET)
#define SQL_GROUPGOD           (cmap.authmask & SQL_AUTH_GROUPS_DEFINITIVE)
#define SQL_USERGOD            (cmap.authmask & SQL_AUTH_USERS_DEFINITIVE)

/*
 * externs, function signatures.. whatever necessary to make
 * the compiler happy..
 */
extern response_t *resp_list,*resp_err_list;
static char *_sql_where(pool *p, int cnt, ...);


pool *sql_pool;

/*
 * cache functions and typedefs
 */

#define CACHE_SIZE         13

typedef struct cache_entry {
  struct cache_entry *list_next;
  struct cache_entry *bucket_next;
  void *data;
} cache_entry_t;

typedef unsigned int ( * val_func ) ( const void * ); 
typedef int ( * cmp_func ) ( const void *, const void * );

typedef struct {
  /* memory pool for this object */
  pool *pool;

  /* cache buckets */
  cache_entry_t *buckets[ CACHE_SIZE ];

  /* cache functions */
  val_func hash_val;
  cmp_func cmp;

  /* list pointers */
  cache_entry_t *head;

  /* list size */
  unsigned int nelts;
} cache_t;

cache_t *group_name_cache;
cache_t *group_gid_cache;
cache_t *passwd_name_cache;
cache_t *passwd_uid_cache;

static cache_t *make_cache( pool *p, val_func hash_val, cmp_func cmp )
{
  cache_t *res;

  if ( ( p == NULL ) || ( hash_val == NULL ) || 
       ( cmp == NULL ) )
    return NULL;

  res = ( cache_t * ) pcalloc( p, sizeof( cache_t ) );

  res->pool = p;
  res->hash_val = hash_val;
  res->cmp = cmp;

  res->head = NULL;

  res->nelts = 0;

  return res;
}

static cache_entry_t *cache_addentry( cache_t *cache, void *data )
{
  cache_entry_t *entry;
  int hashval;

  if ( ( cache == NULL ) || ( data == NULL ) ) return NULL;

  /* create the entry */
  entry = ( cache_entry_t * ) pcalloc( cache->pool, 
				       sizeof( cache_entry_t ) );
  entry->data = data;

  /* deal with the list */

  if ( cache->head == NULL ) {
    cache->head = entry;
  } else {
    entry->list_next = cache->head;
    cache->head = entry;
  }

  /* deal with the buckets */
  hashval = cache->hash_val( data ) % CACHE_SIZE;
  if ( cache->buckets[ hashval ] == NULL ) {
    cache->buckets[ hashval ] = entry;
  } else {
    entry->bucket_next = cache->buckets[ hashval ];
    cache->buckets[ hashval ] = entry;
  }
  
  cache->nelts++;

  return entry;
}

static void *cache_findvalue( cache_t *cache, void *data )
{
  cache_entry_t *entry;
  int hashval;

  if ( ( cache == NULL ) || ( data == NULL ) ) return NULL;
  
  hashval = cache->hash_val( data ) % CACHE_SIZE;

  entry = cache->buckets[ hashval ];
  while ( entry != NULL ) {
    if ( cache->cmp( data, entry->data ) )
      break;
    else
      entry = entry->bucket_next;
  }

  return ( ( entry == NULL ) ? NULL : entry->data );
}


/* this struct holds invariant information for the current session */

static struct
{
  /*
   * info valid after getpwnam 
   */

  char *authuser;               /* current authorized user */
  struct passwd *authpasswd;    /* and their passwd struct */

  /*
   * generic status information 
   */

  int status;                   /* is mod_sql on? */
  int authmask;                 /* authentication mask.  
				 * see set_sqlauthenticate for info */

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
  char *userwhere;              /* users where clause */

  /*
   * group table and field information 
   */

  char *grptable;               /* group info table name */
  char *grpfield;               /* group name field */
  char *grpgidfield;            /* group gid field */
  char *grpmembersfield;        /* group members field */
  char *groupwhere;             /* groups where clause */

  /*
   * other information 
   */

  array_header *authlist;       /* auth handler list */
  char *defaulthomedir;         /* default homedir if no field specified */
  int buildhomedir;             /* create homedir if it doesn't exist? */

  uid_t minid;                  /* users UID must be this or greater */
  uid_t minuseruid;             /* users UID must be this or greater */
  gid_t minusergid;             /* users UID must be this or greater */
  uid_t defaultuid;             /* default UID if none in database */
  gid_t defaultgid;             /* default GID if none in database */

  cache_entry_t *curr_group;    /* next group in group array for getgrent */
  cache_entry_t *curr_passwd;   /* next passwd in passwd array for getpwent */
  int group_cache_filled;
  int passwd_cache_filled;

  /*
   * mod_ratio data -- someday this needs to be removed from mod_sql
   */

  char *sql_fstor;              /* fstor int(11) NOT NULL DEFAULT '0', */
  char *sql_fretr;              /* fretr int(11) NOT NULL DEFAULT '0', */
  char *sql_bstor;              /* bstor int(11) NOT NULL DEFAULT '0', */
  char *sql_bretr;              /* bretr int(11) NOT NULL DEFAULT '0', */

  char *sql_frate;              /* frate int(11) NOT NULL DEFAULT '5', */
  char *sql_fcred;              /* fcred int(2) NOT NULL DEFAULT '15', */
  char *sql_brate;              /* brate int(11) NOT NULL DEFAULT '5', */
  char *sql_bcred;              /* bcred int(2) NOT NULL DEFAULT '150000', */

  /*
   * precomputed strings
   */
  char *usrfields;
  char *grpfields;
}
cmap;

cmd_rec *_sql_make_cmd(pool * cp, int argc, ...)
{
  pool *newpool = NULL;
  cmd_rec *c = NULL;
  va_list args;
  int i = 0;

  newpool = make_named_sub_pool( cp, "temp sql pool" );
  c = pcalloc(newpool, sizeof(cmd_rec));
  c->argc = argc;
  c->symtable_index = -1;
  c->pool = newpool;
  
  c->argv = pcalloc(newpool, sizeof(void *) * (argc));
  c->tmp_pool = newpool;

  va_start(args, argc);

  for (i = 0; i < argc; i++)
    c->argv[i] = (void *) va_arg(args, char *);

  va_end(args);

  return c;
}

void _sql_free_cmd( cmd_rec *cmd )
{
  destroy_pool( cmd->pool );

  return;
}

static void _sql_check_cmd(cmd_rec *cmd, char *msg)
{
  if ((!cmd) || (!cmd->tmp_pool)) {
    log_pri(PR_LOG_ERR, _MOD_VERSION ": '%s' was passed an invalid cmd_rec. "
	    "Shutting down.", msg);
    log_debug(DEBUG_WARN, _MOD_VERSION ": '%s' was passed an invalid cmd_rec. "
	      "Shutting down.", msg);
    end_login(1);
  }    
  return;
}

static modret_t *_sql_check_response(modret_t * mr)
{
  if (!MODRET_ISERROR(mr))
    return mr;

  log_debug(DEBUG_WARN, _MOD_VERSION ": unrecoverable backend error");
  log_debug(DEBUG_WARN, _MOD_VERSION ": (err) '%s'", mr->mr_numeric);
  log_debug(DEBUG_WARN, _MOD_VERSION ": (msg) '%s'", mr->mr_message);

  end_login(1);

  /* make the compiler happy */
  return NULL;
}

static modret_t * _sql_dispatch(cmd_rec *cmd, char *cmdname)
{
  modret_t *mr = NULL;
  int i = 0;

  for(i = 0; sql_cmdtable[i].command; i++)
    if(!strcmp(cmdname,sql_cmdtable[i].command)) {
      block_signals();
      mr = sql_cmdtable[i].handler(cmd);
      unblock_signals();
      return mr;
    }

  log_debug(DEBUG_WARN, _MOD_VERSION ": unknown backend handler '%s'",
	    cmdname );
  return ERROR(cmd);
}

static char *_sql_strip_spaces( pool *p, char *str )
{
  char *nstr = NULL;
  char *curr = NULL;
  char *walk = NULL;

  if (!str) return NULL;

  /* return string may be as long as original */
  nstr = (char *) pcalloc( p, sizeof(char) * strlen(str) + 1);

  curr = nstr;
  walk = str;

  while(*walk) {
    if (*walk != ' ')
      *curr++ = *walk;
    walk++;
  }

  *curr = '\0';

  return nstr;
}

/*****************************************************************
 *
 * AUTHENTICATION FUNCTIONS
 *
 *****************************************************************/

static modret_t *check_auth_crypt(cmd_rec * cmd, const char *c_clear,
				  const char *c_hash)
{
  int success = 0;

  if (*c_hash == '\0') return ERROR_INT(cmd,AUTH_BADPWD);

  success = !strcmp((char *) crypt(c_clear, c_hash), c_hash);

  return success ? HANDLED(cmd) : ERROR_INT(cmd,AUTH_BADPWD);
}

static modret_t *check_auth_plaintext(cmd_rec * cmd, const char *c_clear,
				      const char *c_hash)
{
  int success = 0;

  if (*c_hash == '\0' ) return ERROR_INT(cmd,AUTH_BADPWD);

  success = !strcmp(c_clear, c_hash);

  return success ? HANDLED(cmd) : ERROR_INT(cmd,AUTH_BADPWD);
}

static modret_t *check_auth_empty(cmd_rec * cmd, const char *c_clear,
				  const char *c_hash)
{
  int success = 0;

  success = !strcmp(c_hash, "");

  return success ? HANDLED(cmd) : ERROR_INT(cmd,AUTH_BADPWD);
}

static modret_t *check_auth_backend(cmd_rec * cmd, const char *c_clear,
				    const char *c_hash)
{
  modret_t * mr = NULL;

  if (*c_hash == '\0' ) return ERROR_INT(cmd, AUTH_BADPWD);

  mr = _sql_dispatch( _sql_make_cmd(cmd->tmp_pool, 3, "default", 
				    c_clear, c_hash),
		      "sql_checkauth" );

  return mr;
}

#ifdef HAVE_OPENSSL
static modret_t *check_auth_openssl(cmd_rec * cmd, const char *c_clear,
				    const char *c_hash)
{
  /*
   * c_clear : plaintext password provided by user 
   * c_hash  : combination digest name and hashed 
   *           value, of the form {digest}hash 
   */

  EVP_MD_CTX mdctx;
  EVP_ENCODE_CTX EVP_Encode;
  const EVP_MD *md;
  unsigned char md_value[EVP_MAX_MD_SIZE];
  int md_len, returnValue;

  char buff[EVP_MAX_KEY_LENGTH];

  char *digestname;             /* ptr to name of the digest function */
  char *hashvalue;              /* ptr to hashed value we're comparing to */
  char *copyhash;               /* temporary copy of the c_hash string */

  if (c_hash[0] != '{') {
    return ERROR_INT(cmd, AUTH_BADPWD);
  }

  /*
   * we need a copy of c_hash 
   */
  copyhash = pstrdup(cmd->tmp_pool, c_hash);

  digestname = copyhash + 1;

  hashvalue = (char *) strchr(copyhash, '}');

  if (hashvalue == NULL) {
    return ERROR_INT(cmd, AUTH_BADPWD);
  }

  *hashvalue = '\0';
  hashvalue++;

  OpenSSL_add_all_digests();

  md = EVP_get_digestbyname(digestname);

  if (!md) {
    return ERROR_INT(cmd, AUTH_BADPWD);
  }

  EVP_DigestInit(&mdctx, md);
  EVP_DigestUpdate(&mdctx, c_clear, strlen(c_clear));
  EVP_DigestFinal(&mdctx, md_value, &md_len);

  EVP_EncodeInit(&EVP_Encode);
  EVP_EncodeBlock(buff, md_value, md_len);

  returnValue = strcmp(buff, hashvalue);

  return returnValue ? ERROR_INT(cmd, AUTH_BADPWD) : HANDLED(cmd);
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

typedef modret_t *(*auth_func_ptr) (cmd_rec *, const char *, const char *);

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

/* find who core thinks is the user, and return a (backend-escaped) 
 * version of that name */
static char *_sql_realuser( cmd_rec *cmd )
{
  modret_t *mr = NULL;
  char *user = NULL;

  /* this is the userid given by the user */
  user = (char *) get_param_ptr(main_server->conf, C_USER, FALSE);

  /* do we need to check for useralias?
   * see mod_time.c, get_user_cmd_times() */

  mr = _sql_dispatch( _sql_make_cmd( cmd->tmp_pool, 2, "default", user ),
		      "sql_escapestring" );
  _sql_check_response(mr);

  return mr ? (char *) mr->data : NULL;
}

char *_sql_where(pool *p, int cnt, ...)
{
  int tcnt;
  int flag;
  int len;
  char *res, *tchar;
  va_list dummy;

  flag = 0;

  len = 0;
  va_start(dummy,cnt);
  for (tcnt = 0; tcnt<cnt; tcnt++) {
    res = va_arg(dummy, char *);
    if (res != NULL && *res != '\0') {
      if (flag++) len += 5;
      len += strlen(res);
      len += 2;
    }
  }
  va_end(dummy);

  if (!len) return NULL;

  res = (char *) pcalloc(p, sizeof(char) * (len+1));
  flag = 0;

  va_start(dummy,cnt);
  for (tcnt = 0; tcnt<cnt; tcnt++) {
    tchar = va_arg(dummy, char *);
    if (tchar != NULL && *tchar != '\0') {
      if (flag++) sstrcat(res, " and ", len+1);
      sstrcat(res, "(", len+1);
      sstrcat(res, tchar, len+1);
      sstrcat(res, ")", len+1);
    }
  }
  va_end(dummy);

  return res;
}

static int _sql_strcmp( const char *s1, const char *s2 )
{
  if ( ( s1 == NULL ) || ( s2 == NULL ) ) return 1;

  return strcmp( s1, s2 );
}

static unsigned int _group_gid( const void *val ) 
{
  if ( val == NULL ) return 0;

  return ( ( struct group * ) val )->gr_gid;
} 

static unsigned int _group_name( const void *val )
{
  char *name;
  int cnt;
  unsigned int nameval = 0;

  if ( val == NULL ) return 0;

  name = ( ( struct group * ) val )->gr_name;

  if ( name == NULL ) return 0;

  for ( cnt=0; cnt < strlen( name ); cnt++ ) {
    nameval += name[cnt];
  }

  return nameval;
}

static int _groupcmp ( const void *val1, const void *val2 ) 
{
  if ( ( val1 == NULL ) || ( val2 == NULL ) ) return 0;
  
  /* either the groupnames match or the gids match */
  
  if ( _sql_strcmp( ( ( struct group * ) val1 )->gr_name, 
		    ( ( struct group * ) val2 )->gr_name )  == 0 )
    return 1;

  if ( ( ( struct group * ) val1 )->gr_gid == 
       ( ( struct group * ) val2 )->gr_gid )
    return 1;

  return 0;
}

static unsigned int _passwd_uid( const void *val ) 
{
  if ( val == NULL ) return 0;

  return ( ( struct passwd * ) val )->pw_uid;
} 

static unsigned int _passwd_name( const void *val )
{
  char *name;
  int cnt;
  unsigned int nameval = 0;

  if ( val == NULL ) return 0;

  name = ( ( struct passwd * ) val )->pw_name;

  if ( name == NULL ) return 0;

  for ( cnt=0; cnt < strlen( name ); cnt++ ) {
    nameval += name[cnt];
  }

  return nameval;
}

static int _passwdcmp ( const void *val1, const void *val2 )
{
  if ( ( val1 == NULL ) || ( val2 == NULL ) ) return 0;
  
  /* either the usernames match or the uids match */
  if ( _sql_strcmp( ( ( struct passwd * ) val1 )->pw_name, 
		    ( ( struct passwd * ) val2 )->pw_name )  == 0 )
    return 1;

  if ( ( ( struct passwd * ) val1 )->pw_uid == 
       ( ( struct passwd * ) val2 )->pw_uid )
    return 1;

  return 0;
}

static void show_group(struct group *g)
{
  /* this is an expeditious hack */
  char members[2048] = {'\0'};
  char **member = NULL;
  int flag = 0;

  if (g == NULL ) {
    log_debug(DEBUG_INFO, _MOD_VERSION ": NULL group to show_group");
    return;
  }

  member = g->gr_mem;

  while (*member != NULL) {
    if (flag) strncat( members, ", ", 2048 - strlen( members ) );
    strncat(members, *member, 2048 - strlen( members ) ); 
    flag = 1;
    member++;
  } 

  log_debug(DEBUG_INFO, _MOD_VERSION ": grp.gr_name : %s", g->gr_name);
  log_debug(DEBUG_INFO, _MOD_VERSION ": grp.gr_gid  : %u", g->gr_gid);
  log_debug(DEBUG_INFO, _MOD_VERSION ": grp.gr_mem  : %s", members);

  return;
}

static void show_passwd(struct passwd *p)
{
  if (p == NULL ) {
    log_debug(DEBUG_INFO, _MOD_VERSION ": NULL group to show_passwd");
    return;
  }

  log_debug(DEBUG_INFO, _MOD_VERSION ": pwd.pw_name  : %s", p->pw_name);
  log_debug(DEBUG_INFO, _MOD_VERSION ": pwd.pw_uid   : %u", p->pw_uid);
  log_debug(DEBUG_INFO, _MOD_VERSION ": pwd.pw_gid   : %u", p->pw_gid);
  log_debug(DEBUG_INFO, _MOD_VERSION ": pwd.pw_shell : %s", p->pw_shell);
  log_debug(DEBUG_INFO, _MOD_VERSION ": pwd.pw_dir   : %s", p->pw_dir);

  return;
}

static int build_homedir(cmd_rec *cmd, char *path, mode_t omode, 
			 uid_t uid, gid_t gid)
{
  struct stat st;
  mode_t old_umask;
  int retval = 0;
  char *local_ptr;
  char *local_path;
  int userdir_flag = 0;
  gid_t p_gid;
  uid_t p_uid;

  log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> build_homedir(%s,omode,%i,%i)",
            path, uid, gid);

  /* we assume we're handed a null-terminated string defining the
   * user's home directory. we walk it, directory by directory,
   * creating it if it doesn't exist.  path must start with '/'
   */

  if (path[0] != '/') {
    log_debug(DEBUG_WARN, _MOD_VERSION ": no '/' at start of user's homedir");
    log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< build_homedir");
    return -1;
  }

  /* sanity check -- make sure the path doesn't exist */
  if (!fs_stat(path, &st)) {
    log_debug(DEBUG_WARN, _MOD_VERSION ": user's homedir already exists");
    log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< build_homedir");
    return 0;
  } else if (errno != ENOENT) {
    log_debug(DEBUG_WARN, _MOD_VERSION ": problem with stat of user's homedir");
    log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< build_homedir");
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

  log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< build_homedir");
  return (retval);
}

/* _sql_addpasswd: creates a passwd and adds it to the passwd struct
 *  cache if it doesn't already exist.  Returns the created passwd
 *  struct, or the pre-existing struct if there was one.
 *
 * DOES NOT CHECK ARGUMENTS.  CALLING FUNCTIONS NEED TO MAKE SURE
 * THEY PASS VALID DATA
 */
static struct passwd *_sql_addpasswd(cmd_rec *cmd, char *username, 
				     char *password, uid_t uid, gid_t gid, 
				     char *shell, char *dir)
{
  struct passwd *cached = NULL;
  struct passwd *pwd = NULL;

  pwd = pcalloc(cmd->tmp_pool, sizeof(struct passwd));
  pwd->pw_name = username;

  /* check to make sure the entry doesn't exist in the cache */
  if ( ((cached = (struct passwd *) 
	 cache_findvalue( passwd_name_cache, pwd)) != NULL )) {
    pwd = cached;
    log_debug( DEBUG_INFO, _MOD_VERSION ": cache hit for user '%s'", pwd->pw_name );
  } else {
    pwd = pcalloc(sql_pool, sizeof(struct passwd));
    pwd->pw_name = pstrdup(sql_pool, username);
    pwd->pw_passwd = pstrdup(sql_pool, password);
    
    pwd->pw_uid = uid;
    pwd->pw_gid = gid;
    
    pwd->pw_shell = pstrdup(sql_pool, shell);
    pwd->pw_dir = pstrdup(sql_pool, dir);
    
    cache_addentry( passwd_name_cache, pwd );
    cache_addentry( passwd_uid_cache, pwd );
    log_debug( DEBUG_INFO, _MOD_VERSION ": cache miss for user '%s'", pwd->pw_name );
    log_debug( DEBUG_INFO, _MOD_VERSION ": user '%s' cached", pwd->pw_name );
    show_passwd( pwd );
  }

  return pwd;
}

static struct passwd *_sql_getpasswd(cmd_rec * cmd, struct passwd *p)
{
  sql_data_t * sd = NULL;
  modret_t *mr = NULL;
  struct passwd *pwd = NULL;
  char uidstr[MODSQL_BUFSIZE] = { '\0' };
  char *usrwhere, *where;
  char *realname;
  int index = 0;

  char *username = NULL;
  char *password = NULL;
  char *shell = NULL;
  char *dir = NULL;
  uid_t uid = 0;
  gid_t gid = 0;

  if (p == NULL) {
    log_debug( DEBUG_WARN, _MOD_VERSION ": _sql_getpasswd called with NULL passwd struct; this should never happen.");
    return NULL;
  }

  if (!cmap.homedirfield && !cmap.defaulthomedir) {
    return NULL;
  }

  /* check to see if the passwd already exists in one of the passwd caches */
  if ( ((pwd = (struct passwd *) 
	 cache_findvalue( passwd_name_cache, p )) != NULL ) ||
       ((pwd = (struct passwd *) 
	 cache_findvalue( passwd_uid_cache, p )) != NULL )) {
    log_debug( DEBUG_AUTH, _MOD_VERSION ": cache hit for user '%s'", pwd->pw_name );
    return pwd;
  }

  if (p->pw_name != NULL) {
    realname = _sql_strip_spaces(cmd->tmp_pool, p->pw_name);

    mr = _sql_dispatch( _sql_make_cmd( cmd->tmp_pool, 2, "default", realname ),
			"sql_escapestring" );
    _sql_check_response(mr);

    username =(char *) mr->data;

    usrwhere = pstrcat(cmd->tmp_pool, cmap.usrfield, "='", username, "'", NULL);

    log_debug( DEBUG_WARN, _MOD_VERSION ": cache miss for user '%s'", realname);
  } else {
    /* assume we have a uid */
    snprintf(uidstr, MODSQL_BUFSIZE, "%d", (uid_t) p->pw_uid);

    usrwhere = pstrcat(cmd->tmp_pool, cmap.uidfield, " = ", uidstr, NULL);

    log_debug( DEBUG_WARN, _MOD_VERSION ": cache miss for uid '%s'", uidstr );
  }

  where = _sql_where(cmd->tmp_pool, 2, usrwhere, cmap.userwhere );

  mr = _sql_dispatch( _sql_make_cmd( cmd->tmp_pool, 5,
				     "default",
				     cmap.usrtable,
				     cmap.usrfields,
				     where,
				     "1" ),
		      "sql_select" );
  _sql_check_response(mr);
				     
  sd = (sql_data_t *) mr->data;

  /* if we have no data.. */
  if (sd->rnum == 0) return NULL;

  index = 0;

  username = sd->data[index++];
  password = sd->data[index++];
  
  uid = cmap.defaultuid;
  if (cmap.uidfield) {
    if (sd->data[index]) {
      uid = atoi(sd->data[index++]);
    } else {
      index++;
    }
  }
   
  gid = cmap.defaultgid;
  if (cmap.gidfield) {
    if (sd->data[index]) {
      gid = atoi(sd->data[index++]);
    } else {
      index++;
    }
  }

  if (cmap.defaulthomedir)
    dir =  cmap.defaulthomedir;
  else 
    dir = sd->data[index++];

  if (cmap.shellfield)
    shell = sd->data[index++];
  else
    shell =  "";
  
  if (uid < cmap.minuseruid)
    uid = cmap.defaultuid;
  if (gid < cmap.minusergid)
    gid = cmap.defaultgid;

  return _sql_addpasswd( cmd, username, password, uid, gid, shell, dir );
}

/* _sql_addgroup: creates a group and adds it to the group struct
 *  cache if it doesn't already exist.  Returns the created group
 *  struct, or the pre-existing struct if there was one.
 *
 * DOES NOT CHECK ARGUMENTS.  CALLING FUNCTIONS NEED TO MAKE SURE
 * THEY PASS VALID DATA
 */
static struct group *_sql_addgroup(cmd_rec *cmd, char *groupname, gid_t gid,
				   array_header *ah)
{
  struct group *cached = NULL;
  struct group *grp = NULL;

  int cnt = 0;

  grp = pcalloc(cmd->tmp_pool, sizeof(struct group));
  grp->gr_name = groupname;

  /* check to make sure the entry doesn't exist in the cache */
  if ((cached = (struct group *) cache_findvalue( group_name_cache, grp)) != NULL) {
    grp = cached;
    log_debug( DEBUG_INFO, _MOD_VERSION ": cache hit for group '%s'", grp->gr_name );
  } else {
    grp = pcalloc(sql_pool, sizeof(struct group));
    grp->gr_name = pstrdup(sql_pool, groupname);
    grp->gr_gid = gid;

    /* finish filling in the group */
    grp->gr_mem = (char **) pcalloc(sql_pool, sizeof(char *) * (ah->nelts + 1));

    for ( cnt = 0; cnt < ah->nelts; cnt++ ) {
      grp->gr_mem[cnt] = pstrdup(sql_pool, ((char **) ah->elts)[cnt]);
    }
    grp->gr_mem[ ah->nelts ]='\0';

    cache_addentry( group_name_cache, grp );
    cache_addentry( group_gid_cache, grp );
    log_debug( DEBUG_INFO, _MOD_VERSION ": cache miss for group '%s'", grp->gr_name );
    log_debug( DEBUG_INFO, _MOD_VERSION ": group '%s' cached", grp->gr_name );
    show_group( grp );
  }

  return grp;
}

static struct group *_sql_getgroup(cmd_rec * cmd, struct group *g)
{
  struct group *grp = NULL;
  modret_t *mr = NULL;
  int cnt = 0;
  sql_data_t *sd = NULL;
  char *groupname = NULL;
  char gidstr[MODSQL_BUFSIZE] = { '\0' };
  char **rows = NULL;
  int numrows = 0;
  array_header *ah = NULL;
  char *members = NULL;
  char *member = NULL;
  char *grpwhere;
  char *where;
  char *iterator;

  gid_t gid = 0;
  
  if (g == NULL) {
    log_debug( DEBUG_WARN, _MOD_VERSION ": _sql_getgroup called with NULL group struct; this should never happen.");
    return NULL;
  }

  /* check to see if the group already exists in one of the group caches */
  if (((grp = (struct group *) cache_findvalue(group_name_cache, g))!=NULL) ||
      ((grp = (struct group *) cache_findvalue(group_gid_cache, g))!=NULL)) {
    log_debug( DEBUG_AUTH, _MOD_VERSION
	       ": cache hit for group %s", grp->gr_name );
    return grp;
  }

  if (g->gr_name != NULL) {
    groupname = g->gr_name;
  } else {
    /* get groupname from gid */
    snprintf(gidstr, MODSQL_BUFSIZE, "%d", (gid_t) g->gr_gid);

    grpwhere = pstrcat(cmd->tmp_pool, cmap.grpgidfield, " = ", gidstr, NULL);
    where = _sql_where(cmd->tmp_pool, 2, grpwhere, cmap.groupwhere);

    mr = _sql_dispatch( _sql_make_cmd( cmd->tmp_pool, 5,
				       "default",
				       cmap.grptable,
				       cmap.grpfield,
				       where,
				       "1" ),
			"sql_select" );
    _sql_check_response(mr);

    sd = (sql_data_t *) mr->data;

    /* if we have no data.. */
    if (sd->rnum == 0) return NULL;

    groupname = sd->data[0];
  }

  grpwhere = pstrcat(cmd->tmp_pool, cmap.grpfield, " = '", groupname, "'", NULL);
  where = _sql_where(cmd->tmp_pool, 2, grpwhere, cmap.groupwhere);
  
  mr = _sql_dispatch( _sql_make_cmd( cmd->tmp_pool, 4,
				     "default",
				     cmap.grptable,
				     cmap.grpfields,
				     where ),
		      "sql_select" );
  _sql_check_response(mr);
  
  sd = (sql_data_t *) mr->data;
 
  /* if we have no data... */
  if (sd->rnum == 0) return NULL;
 
  rows = sd->data;
  numrows = sd->rnum;
  
  gid = (gid_t) strtoul(rows[1], NULL, 10);
  
  /*
   * painful.. we need to walk through the returned rows and fill in our
   * members. Every third element in a row is a member field, and every
   * member field can have multiple members.
   */
  
  ah = make_array(cmd->tmp_pool, 10, sizeof(char *));
  
  for (cnt = 0; cnt < numrows; cnt++) {
    members = rows[(cnt * 3) + 2];
    iterator=members;
    
    /* if the row is null, continue.. */
    if (members == NULL) continue;
    
    /* for each member in the list, toss 'em into the array.  no
     * need to copy the string -- _sql_addgroup will do it for us 
     */
    for (member = strsep(&iterator, " ,"); member; member = strsep(&iterator, " ,")) {
      if (*member=='\0') continue;
      *((char **) push_array(ah)) = member;
    }      
  }
  
  return _sql_addgroup( cmd, groupname, gid, ah );
}

static void _setstats(cmd_rec * cmd, int fstor, int fretr,
                      int bstor, int bretr)
{
  /*
   * if anyone has a better way of doing this, let me know.. 
   */
  char query[256] = { '\0' };
  char *usrwhere, *where;
  modret_t *mr = NULL;

  snprintf(query, sizeof(query),
           "%s = %s + %i, %s = %s + %i, %s = %s + %i, %s = %s + %i",
           cmap.sql_fstor, cmap.sql_fstor, fstor,
           cmap.sql_fretr, cmap.sql_fretr, fretr,
           cmap.sql_bstor, cmap.sql_bstor, bstor,
	   cmap.sql_bretr, cmap.sql_bretr, bretr);

  usrwhere = pstrcat(cmd->tmp_pool, cmap.usrfield, " = '", _sql_realuser(cmd), "'", NULL);
  where = _sql_where(cmd->tmp_pool, 2, usrwhere, cmap.userwhere );

  mr = _sql_dispatch( _sql_make_cmd( cmd->tmp_pool, 4, "default", cmap.usrtable,
				query, where ), "sql_update" );
  _sql_check_response(mr);

}

/*****************************************************************
 *
 * CLIENT COMMAND HANDLERS
 *
 *****************************************************************/

MODRET post_cmd_stor(cmd_rec * cmd)
{
  _sql_check_cmd(cmd, "post_cmd_stor");

  log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> post_cmd_stor");

  if (!cmap.status) return DECLINED(cmd);

  if (cmap.sql_fstor)
    _setstats(cmd, 1, 0, session.xfer.total_bytes, 0);

  log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< post_cmd_stor");

  return DECLINED(cmd);
}

MODRET post_cmd_retr(cmd_rec * cmd)
{
  _sql_check_cmd(cmd, "post_cmd_retr");

  if (!cmap.status) return DECLINED(cmd);

  log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> post_cmd_retr");

  if (cmap.sql_fretr)
    _setstats(cmd, 0, 1, 0, session.xfer.total_bytes);

  log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< post_cmd_retr");

  return DECLINED(cmd);
}

static char *resolve_tag(cmd_rec *cmd, char tag) 
{
  char arg[256] = {'\0'}, *argp;

  switch(tag) {
  case 'A':
    {
      char *pass;

      argp=arg;
      pass=get_param_ptr(main_server->conf, C_PASS, FALSE);
      if (!pass)
	pass = "UNKNOWN";
      
      sstrncpy( argp, pass, sizeof(arg));
    }
    break;
  case 'b':
    argp=arg;
    if (session.xfer.p)
      snprintf(argp, sizeof(arg), "%lu", session.xfer.total_bytes);
    else
      sstrncpy( argp, "0", sizeof(arg));
    break;
  case 'c':
    argp=arg;
    if (get_param_int(TOPLEVEL_CONF, "Classes", FALSE) > 0)
      sstrncpy(argp, session.class->name, sizeof(arg));
    else
      sstrncpy(argp, "-", sizeof(arg));
    break;
  case 'd':
    argp = session.cwd;
    if (!argp)
      argp="-";
    break;
  case 'f':
    argp = arg;
    if(session.xfer.p && session.xfer.path) {
      char *fullpath;
      fullpath = dir_abs_path(cmd->tmp_pool,session.xfer.path,TRUE);
      sstrncpy(argp, fullpath, sizeof(arg));
    } else {
      sstrncpy(argp, "-", sizeof(arg));
    }
    
    break;
  case 'F':
    argp = arg;
    if(session.xfer.p && session.xfer.path) {
      sstrncpy(argp, session.xfer.path, sizeof(arg));
    } else {
      sstrncpy(argp, "-", sizeof(arg));
    }
    break;
  case 'h':
    argp = arg;
    sstrncpy(argp, session.c->remote_name, sizeof(arg));
    break;
  case 'a':
    argp = arg;
    sstrncpy(argp, inet_ntoa(*session.c->remote_ipaddr), sizeof(arg));
    break;
  case 'l':
    argp = arg;
    sstrncpy(argp, session.ident_user, sizeof(arg));
    break;
  case 'm':
    argp = arg;
    sstrncpy(argp, cmd->argv[0], sizeof(arg));
    break;
  case 'p': 
    argp = arg;
    snprintf(argp, sizeof(arg), "%d", cmd->server->ServerPort);
    break;
  case 'P':
    argp = arg;
    snprintf(argp, sizeof(arg), "%u",(unsigned int)getpid());
    break;
  case 'u':
    argp = arg;
    
    if(!session.user) {
      char *u;
      
      u = get_param_ptr(main_server->conf,"UserName",FALSE);
      if(!u)
	u = "root";
      
      sstrncpy(argp, u, sizeof(arg));
    } else {
      sstrncpy(argp, session.user, sizeof(arg));
    }
    break;
  case 'r':
    argp = arg;
    if(!strcasecmp(cmd->argv[0],"PASS") && session.hide_password)
      sstrncpy(argp, "PASS (hidden)", sizeof(arg));
    else
      sstrncpy(argp, get_full_cmd(cmd), sizeof(arg));
    break;
  case 's':
    argp = arg;
    {
      response_t *r;
      
      r = (resp_list ? resp_list : resp_err_list);
      
      for(; r && !r->num; r=r->next) ;
      if(r && r->num)
	sstrncpy(argp,r->num,sizeof(arg));
      else
	sstrncpy(argp,"-",sizeof(arg));
    }
    break;
  case 'T':
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
      
      snprintf(argp, sizeof(arg), "%lu.%03lu", (unsigned long) end_time.tv_sec,
	       (unsigned long) (end_time.tv_usec / 1000));
    } else {
      sstrncpy(argp,"0.0",sizeof(arg));
    }
    break;
  case 'v':
    argp = arg;
    sstrncpy(argp,cmd->server->ServerName,sizeof(arg));
    break;
  case '%':
    argp = "%";
    break;
  default:
    argp="{UNKNOWN TAG}";
    break;
  }

  return pstrdup( cmd->tmp_pool, argp );
}

static char *_named_query_type(cmd_rec *cmd, char *name)
{
  config_rec *c = NULL;
  char *query = NULL;

  query = pstrcat(cmd->tmp_pool, "SQLNamedQuery_", name, NULL);
  c = find_config(main_server->conf, CONF_PARAM, query, FALSE);

  if (c)
    return c->argv[0];

  return NULL;
}

static modret_t *_process_named_query(cmd_rec *cmd, char *name)
{
  config_rec *c;
  char *query, *tmp, *argp;
  char outs[4096] = {'\0'}, *outsp;
  char *esc_arg = NULL;
  modret_t *mr = NULL;
  int num = 0;
  char *argc = 0;
  char *endptr = NULL;

  log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> _process_named_query");

  /* check for a query by that name */

  query = pstrcat(cmd->tmp_pool, "SQLNamedQuery_", name, NULL);

  c = find_config(main_server->conf, CONF_PARAM, query, FALSE);
  if (c) {
    /* select string fixup */
    memset(outs, '\0', sizeof(outs));
    outsp = outs;

    for (tmp = c->argv[1]; *tmp; ) {
      if(*tmp == '%') {
	if (*(++tmp) == '{') {
	  char *query;
	  
	  if (*tmp!='\0') query = ++tmp;
	  
	  /* find the argument number to use */
	  while ( *tmp && *tmp!='}' ) tmp++;
	  
	  argc = pstrndup(cmd->tmp_pool, query, (tmp - query));
	  if (argc) {
	    num = strtol(argc, &endptr, 10);
	    
	    if ((*endptr != NULL) || (num < 0) || 
		((cmd->argc - 3 ) < num)) {
	      return ERROR_MSG(cmd, _MOD_VERSION, "reference out-of-bounds in query");
	    }
	  } else {
	    return ERROR_MSG(cmd, _MOD_VERSION, "malformed reference %{?} in query");
	  }
	   
	  esc_arg = cmd->argv[num+2];
	} else {
	  argp=resolve_tag( cmd, *tmp);
	  mr = _sql_dispatch( _sql_make_cmd( cmd->tmp_pool, 2, "default", 
					     argp ), "sql_escapestring" );
	  _sql_check_response(mr);
	  esc_arg = (char *) mr->data;
	}
	
	strcat( outs, esc_arg );
	outsp += strlen(esc_arg);
	
	if ( *tmp!='\0' ) tmp++;
      } else {
	*outsp++ = *tmp++;
      }
    }
      
    *outsp++ = 0;

    /* construct our return data based on the type of query */
    if (!strcasecmp(c->argv[0], SQL_UPDATE_C)) {
      query = pstrcat(cmd->tmp_pool, c->argv[2], " SET ", outs, NULL);
      mr = _sql_dispatch( _sql_make_cmd( cmd->tmp_pool, 2, "default", query), 
			  "sql_update");
    } else if (!strcasecmp(c->argv[0], SQL_INSERT_C)) {
      query = pstrcat(cmd->tmp_pool, "INTO ", c->argv[2], " VALUES (",
		     outs, ")", NULL);
      mr = _sql_dispatch( _sql_make_cmd( cmd->tmp_pool, 2, "default", query), 
			  "sql_insert");
    } else if (!strcasecmp(c->argv[0], SQL_FREEFORM_C)) {
      mr = _sql_dispatch( _sql_make_cmd( cmd->tmp_pool, 2, "default", outs), 
			  "sql_query");
    } else if (!strcasecmp(c->argv[0], SQL_SELECT_C)) {
      mr = _sql_dispatch( _sql_make_cmd( cmd->tmp_pool, 2, "default", outs), 
			  "sql_select");
    } else {
      mr = ERROR_MSG(cmd, _MOD_VERSION, "unknown NamedQuery type");
    }
  } else {
    mr = ERROR(cmd);
  }
 
  log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< _process_named_query");

  return mr;
}

MODRET log_master(cmd_rec * cmd)
{
  char *name = NULL;
  char *qname = NULL;
  char *type = NULL;
  config_rec *c = NULL;
  modret_t *mr = NULL;

  _sql_check_cmd(cmd, "log_master");

  if (!cmap.status) return DECLINED(cmd);
  
  /* handle explicit queries */
  name = pstrcat(cmd->tmp_pool, "SQLLog_", cmd->argv[0], NULL);
  
  c = find_config(main_server->conf, CONF_PARAM, name, FALSE);

  if (c) {
    do {
      log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> log_master");

      qname = c->argv[0];
      type = _named_query_type(cmd, qname);

      if (type) {
	if ((!strcasecmp(type, SQL_UPDATE_C)) || 
	    (!strcasecmp(type, SQL_FREEFORM_C)) ||
	    (!strcasecmp(type, SQL_INSERT_C))) {
	  mr = _process_named_query( cmd, qname );
	  if (c->argc == 2) _sql_check_response(mr);
	} else {
	  log_debug(DEBUG_WARN, _MOD_VERSION ": named query '%s' is not"
		    " an INSERT, UPDATE, or FREEFORM query",
		    qname);
	}
      } else {
	log_debug(DEBUG_WARN, _MOD_VERSION ": named query '%s' cannot be"
		  " found",
		  qname);
      }

      log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< log_master");
    } while((c = find_config_next(c, c->next, 
				  CONF_PARAM, name, FALSE)) != NULL);
  }
  
  /* handle implit queries */
  name = pstrcat(cmd->tmp_pool, "SQLLog_*", cmd->argv[0], NULL);
  
  c = find_config(main_server->conf, CONF_PARAM, name, FALSE);

  if (c) {
    do {
      log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> log_master");

      qname = c->argv[0];
      type = _named_query_type(cmd, qname);

      if (type) {
	if ((!strcasecmp(type, SQL_UPDATE_C)) || 
	    (!strcasecmp(type, SQL_FREEFORM_C)) ||
	    (!strcasecmp(type, SQL_INSERT_C))) {
	  mr = _process_named_query( cmd, qname );
	  if (c->argc == 2) _sql_check_response(mr);
	} else {
	  log_debug(DEBUG_WARN, _MOD_VERSION ": named query '%s' is not"
		    " an INSERT, UPDATE, or FREEFORM query",
		    qname);
	}
      } else {
	log_debug(DEBUG_WARN, _MOD_VERSION ": named query '%s' cannot be"
		  " found",
		  qname);
      }

      log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< log_master");
    } while((c = find_config_next(c, c->next, 
				  CONF_PARAM, name, FALSE)) != NULL);
  }

  return DECLINED(cmd);
}

MODRET err_master(cmd_rec * cmd)
{
  char *name = NULL;
  char *qname = NULL;
  char *type = NULL;
  config_rec *c = NULL;
  modret_t *mr = NULL;

  _sql_check_cmd(cmd, "err_master");

  if (!cmap.status) return DECLINED(cmd);
  
  /* handle explicit errors */
  name = pstrcat(cmd->tmp_pool, "SQLLog_ERR_", cmd->argv[0], NULL);
  
  c = find_config(main_server->conf, CONF_PARAM, name, FALSE);

  if (c) {
    do {
      log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> err_master");

      qname = c->argv[0];
      type = _named_query_type(cmd, qname);

      if (type) {
	if ((!strcasecmp(type, SQL_UPDATE_C)) || 
	    (!strcasecmp(type, SQL_FREEFORM_C)) ||
	    (!strcasecmp(type, SQL_INSERT_C))) {
	  mr = _process_named_query( cmd, qname );
	  if (c->argc == 2) _sql_check_response(mr);
	} else {
	  log_debug(DEBUG_WARN, _MOD_VERSION ": named query '%s' is not"
		    " an INSERT, UPDATE, or FREEFORM query",
		    qname);
	}
      } else {
	log_debug(DEBUG_WARN, _MOD_VERSION ": named query '%s' cannot be"
		  " found",
		  qname);
      }

      log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< err_master");
    } while((c = find_config_next(c, c->next, 
				  CONF_PARAM, name, FALSE)) != NULL);
  }
  
  /* handle implicit errors */
  name = pstrcat(cmd->tmp_pool, "SQLLog_ERR_*", NULL);
  
  c = find_config(main_server->conf, CONF_PARAM, name, FALSE);

  if (c) {
    do {
      log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> err_master");

      qname = c->argv[0];
      type = _named_query_type(cmd, qname);

      if (type) {
	if ((!strcasecmp(type, SQL_UPDATE_C)) || 
	    (!strcasecmp(type, SQL_FREEFORM_C)) ||
	    (!strcasecmp(type, SQL_INSERT_C))) {
	  mr = _process_named_query( cmd, qname );
	  if (c->argc == 2) _sql_check_response(mr);
	} else {
	  log_debug(DEBUG_WARN, _MOD_VERSION ": named query '%s' is not"
		    " an INSERT, UPDATE, or FREEFORM query",
		    qname);
	}
      } else {
	log_debug(DEBUG_WARN, _MOD_VERSION ": named query '%s' cannot be"
		  " found",
		  qname);
      }

      log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< err_master");
    } while((c = find_config_next(c, c->next, 
				  CONF_PARAM, name, FALSE)) != NULL);
  }

  return DECLINED(cmd);
}

MODRET info_master(cmd_rec * cmd)
{
  char *type = NULL;
  char *name = NULL;
  config_rec *c = NULL;
  char outs[4096] = {'\0'}, *outsp;
  char *argp = NULL; 
  char *tmp = NULL;
  modret_t *mr = NULL;
  sql_data_t *sd = NULL;

  _sql_check_cmd(cmd, "info_master");

  if (!cmap.status) return DECLINED(cmd);

  /* process explicit handlers */
  name = pstrcat(cmd->tmp_pool, "SQLShowInfo_", cmd->argv[0], NULL);
  
  c = find_config(main_server->conf, CONF_PARAM, name, FALSE);
  if (c) {
    log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> info_master");

    /* we now have at least one config_rec.  Take the output string from 
     * each, and process it -- resolve tags, and when we find a named 
     * query, run it and get info from it. 
     */

    do {
      memset(outs, '\0', sizeof(outs));
      outsp = outs;

      for (tmp = c->argv[1]; *tmp; ) {
	if(*tmp == '%') {
	  /* is the tag a named_query reference?  If so, process the 
	   * named query, otherwise process it as a normal tag.. 
	   */
	  
	  if (*(++tmp) == '{') {
	    char *query;

	    if (*tmp!='\0') query = ++tmp;
	    
	    /* get the name of the query */
	    while ( *tmp && *tmp!='}' ) tmp++;
	    
	    query = pstrndup(cmd->tmp_pool, query, (tmp - query));

	    /* make sure it's a SELECT query */
	    
	    type = _named_query_type(cmd, query);
	    if (type && ((!strcasecmp(type, SQL_SELECT_C )) ||
			 (!strcasecmp(type, SQL_FREEFORM_C )))) {
	      mr = _process_named_query(cmd, query);
	      
	      if (MODRET_ISERROR(mr)) {
		argp = "{null}";
	      } else {
		sd = (sql_data_t *) mr->data;
		if ((sd->rnum == 0) || (!sd->data[0]))
		  argp = "{null}";
		else
		  argp = sd->data[0];
	      }
	    } else {
	      argp = "{null}";
	    }
	  } else {
	    argp=resolve_tag( cmd, *tmp);
	  }

	  strcat( outs, argp );
	  outsp += strlen(argp);

	  if (*tmp!='\0') tmp++;
	} else {
	  *outsp++ = *tmp++;
	}
      }
      
      *outsp++ = 0;

      /* add the response */
      add_response( c->argv[0], outs);

    } while((c = find_config_next(c, c->next, CONF_PARAM, name, FALSE)) != NULL);

    log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< info_master");
  }

  /* process implicit handlers */
  name = pstrcat(cmd->tmp_pool, "SQLShowInfo_*", NULL);
  
  c = find_config(main_server->conf, CONF_PARAM, name, FALSE);
  if (c) {
    log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> info_master");

    /* we now have at least one config_rec.  Take the output string from 
     * each, and process it -- resolve tags, and when we find a named 
     * query, run it and get info from it. 
     */

    do {
      memset(outs, '\0', sizeof(outs));
      outsp = outs;

      for (tmp = c->argv[1]; *tmp; ) {
	if(*tmp == '%') {
	  /* is the tag a named_query reference?  If so, process the 
	   * named query, otherwise process it as a normal tag.. 
	   */
	  
	  if (*(++tmp) == '{') {
	    char *query;

	    if (*tmp!='\0') query = ++tmp;
	    
	    /* get the name of the query */
	    while ( *tmp && *tmp!='}' ) tmp++;
	    
	    query = pstrndup(cmd->tmp_pool, query, (tmp - query));

	    /* make sure it's a SELECT query */
	    
	    type = _named_query_type(cmd, query);
	    if (type && ((!strcasecmp(type, SQL_SELECT_C )) ||
			 (!strcasecmp(type, SQL_FREEFORM_C )))) {
	      mr = _process_named_query(cmd, query);
	      
	      if (MODRET_ISERROR(mr)) {
		argp = "{null}";
	      } else {
		sd = (sql_data_t *) mr->data;
		if ((sd->rnum == 0) || (!sd->data[0]))
		  argp = "{null}";
		else
		  argp = sd->data[0];
	      }
	    } else {
	      argp = "{null}";
	    }
	  } else {
	    argp=resolve_tag( cmd, *tmp);
	  }

	  strcat( outs, argp );
	  outsp += strlen(argp);

	  if (*tmp!='\0') tmp++;
	} else {
	  *outsp++ = *tmp++;
	}
      }
      
      *outsp++ = 0;

      /* add the response */
      add_response( c->argv[0], outs);

    } while((c = find_config_next(c, c->next, CONF_PARAM, name, FALSE)) != NULL);

    log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< info_master");
  }

  return DECLINED(cmd);
}

MODRET errinfo_master(cmd_rec * cmd)
{
  char *type = NULL;
  char *name = NULL;
  config_rec *c = NULL;
  char outs[4096] = {'\0'}, *outsp;
  char *argp = NULL; 
  char *tmp = NULL;
  modret_t *mr = NULL;
  sql_data_t *sd = NULL;

  _sql_check_cmd(cmd, "errinfo_master");

  if (!cmap.status) return DECLINED(cmd);

  /* process explicit handlers */
  name = pstrcat(cmd->tmp_pool, "SQLShowInfo_ERR_", cmd->argv[0], NULL);
  
  c = find_config(main_server->conf, CONF_PARAM, name, FALSE);
  if (c) {
    log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> errinfo_master");

    /* we now have at least one config_rec.  Take the output string from 
     * each, and process it -- resolve tags, and when we find a named 
     * query, run it and get info from it. 
     */

    do {
      memset(outs, '\0', sizeof(outs));
      outsp = outs;

      for (tmp = c->argv[1]; *tmp; ) {
	if(*tmp == '%') {
	  /* is the tag a named_query reference?  If so, process the 
	   * named query, otherwise process it as a normal tag.. 
	   */
	  
	  if (*(++tmp) == '{') {
	    char *query;

	    if (*tmp!='\0') query = ++tmp;
	    
	    /* get the name of the query */
	    while ( *tmp && *tmp!='}' ) tmp++;
	    
	    query = pstrndup(cmd->tmp_pool, query, (tmp - query));

	    /* make sure it's a SELECT query */
	    
	    type = _named_query_type(cmd, query);
	    if (type && ((!strcasecmp(type, SQL_SELECT_C )) ||
			 (!strcasecmp(type, SQL_FREEFORM_C )))) {
	      mr = _process_named_query(cmd, query);
	      
	      if (MODRET_ISERROR(mr)) {
		argp = "{null}";
	      } else {
		sd = (sql_data_t *) mr->data;
		if ((sd->rnum == 0) || (!sd->data[0]))
		  argp = "{null}";
		else
		  argp = sd->data[0];
	      }
	    } else {
	      argp = "{null}";
	    }
	  } else {
	    argp=resolve_tag( cmd, *tmp);
	  }

	  strcat( outs, argp );
	  outsp += strlen(argp);

	  if (*tmp!='\0') tmp++;
	} else {
	  *outsp++ = *tmp++;
	}
      }
      
      *outsp++ = 0;

      /* add the response */
      add_response_err( c->argv[0], outs);

    } while((c = find_config_next(c, c->next, CONF_PARAM, name, FALSE)) != NULL);

    log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< errinfo_master");
  }

  /* process implicit handlers */
  name = pstrcat(cmd->tmp_pool, "SQLShowInfo_ERR_*", NULL);
  
  c = find_config(main_server->conf, CONF_PARAM, name, FALSE);
  if (c) {
    log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> errinfo_master");

    /* we now have at least one config_rec.  Take the output string from 
     * each, and process it -- resolve tags, and when we find a named 
     * query, run it and get info from it. 
     */

    do {
      memset(outs, '\0', sizeof(outs));
      outsp = outs;

      for (tmp = c->argv[1]; *tmp; ) {
	if(*tmp == '%') {
	  /* is the tag a named_query reference?  If so, process the 
	   * named query, otherwise process it as a normal tag.. 
	   */
	  
	  if (*(++tmp) == '{') {
	    char *query;

	    if (*tmp!='\0') query = ++tmp;
	    
	    /* get the name of the query */
	    while ( *tmp && *tmp!='}' ) tmp++;
	    
	    query = pstrndup(cmd->tmp_pool, query, (tmp - query));

	    /* make sure it's a SELECT query */
	    
	    type = _named_query_type(cmd, query);
	    if (type && ((!strcasecmp(type, SQL_SELECT_C )) ||
			 (!strcasecmp(type, SQL_FREEFORM_C )))) {
	      mr = _process_named_query(cmd, query);
	      
	      if (MODRET_ISERROR(mr)) {
		argp = "{null}";
	      } else {
		sd = (sql_data_t *) mr->data;
		if ((sd->rnum == 0) || (!sd->data[0]))
		  argp = "{null}";
		else
		  argp = sd->data[0];
	      }
	    } else {
	      argp = "{null}";
	    }
	  } else {
	    argp=resolve_tag( cmd, *tmp);
	  }

	  strcat( outs, argp );
	  outsp += strlen(argp);

	  if (*tmp!='\0') tmp++;
	} else {
	  *outsp++ = *tmp++;
	}
      }
      
      *outsp++ = 0;

      /* add the response */
      add_response( c->argv[0], outs);

    } while((c = find_config_next(c, c->next, CONF_PARAM, name, FALSE)) != NULL);

    log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< errinfo_master");
  }

  return DECLINED(cmd);
}

/* sql_lookup: used by third-party modules to get data via a SQL query.  
 * Third party module must pass a legitimate cmd_rec (including tmp_pool), 
 * and the cmd_rec must have only one argument: the name of a SQLNamedQuery.
 *
 * Returns:
 *
 * DECLINED if mod_sql isn't on
 * ERROR    if named query doesn't exist
 * 
 * SHUTS DOWN if query caused an error
 * 
 * otherwise:
 *
 * array_header * in the data slot with the returned data.  It is up to the
 * calling function to know how many pieces of data to expect, and how to
 * parse them.
 */
MODRET sql_lookup(cmd_rec *cmd)
{
  char *type = NULL;
  modret_t *mr = NULL;
  sql_data_t *sd = NULL;
  array_header *ah = NULL;
  int cnt = 0;

  _sql_check_cmd(cmd, "sql_lookup");

  if (!cmap.status) return DECLINED(cmd);

  log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> sql_lookup");

  if (cmd->argc < 1) return ERROR(cmd);

  type = _named_query_type(cmd, cmd->argv[1]);
  if (type && ((!strcasecmp(type, SQL_SELECT_C )) ||
	       (!strcasecmp(type, SQL_FREEFORM_C )))) {
    mr = _process_named_query(cmd, cmd->argv[1]);
    
    if (!MODRET_ISERROR(mr)) {
      sd = (sql_data_t *) mr->data;

      ah = make_array(session.pool, (sd->rnum * sd->fnum) , sizeof(char *));

      /* the right way to do this is to preserve the abstraction of the array
       * header so things don't blow up when it gets freed */
      for (cnt =0; cnt< (sd->rnum * sd->fnum); cnt++) {
	*((char **) push_array(ah)) = sd->data[cnt];
      }

      mr = mod_create_data(cmd, (void *) ah);
    } else {
      /* we have an error, log it and die */
      _sql_check_response(mr);
    }
  } else {
    mr = ERROR(cmd);
  }

  log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< sql_lookup");
  return mr;
}

MODRET sql_change(cmd_rec *cmd)
{
  char *type = NULL;
  modret_t *mr = NULL;

  _sql_check_cmd(cmd, "sql_change");

  if (!cmap.status) return DECLINED(cmd);

  log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> sql_change");

  if (cmd->argc < 1) return ERROR(cmd);

  type = _named_query_type(cmd, cmd->argv[1]);
  if (type && ((!strcasecmp(type, SQL_INSERT_C)) || 
	       (!strcasecmp(type, SQL_UPDATE_C)) ||
	       (!strcasecmp(type, SQL_FREEFORM_C)))) {
    /* fixup the cmd_rec */

    mr = _process_named_query(cmd, cmd->argv[1]);
    
    if (MODRET_ISERROR(mr)) {
      /* we have an error, log it and die */
      _sql_check_response(mr);
    }
  } else {
    mr = ERROR(cmd);
  }

  log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< sql_change");
  return mr;
}

/*****************************************************************
 *
 * AUTH COMMAND HANDLERS
 *
 *****************************************************************/

MODRET cmd_setpwent(cmd_rec * cmd)
{
  sql_data_t *sd = NULL;
  modret_t *mr = NULL;
  char *where = NULL;
  int index = 0;
  int cnt = 0;

  char *username = NULL;
  char *password = NULL;
  char *shell = NULL;
  char *dir = NULL;
  uid_t uid = 0;
  gid_t gid = 0;
  
  struct passwd lpw;

  _sql_check_cmd(cmd, "cmd_setpwent");

  if (!SQL_USERSET)
    return (SQL_USERGOD ? mod_create_data(cmd,(void *)0):DECLINED(cmd));

  log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> cmd_setpwent");

  /* if we've already filled the passwd cache, just reset the curr_passwd */
  if ( cmap.passwd_cache_filled ) {
    cmap.curr_passwd = passwd_name_cache->head;
    log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_setpwent");
    return (SQL_USERGOD ? mod_create_data( cmd, (void *) 1 ) : DECLINED(cmd));
  }

  /* single select or not? */
  if (SQL_FASTUSERS) {
    /* retrieve our list of passwds */
    where = _sql_where(cmd->tmp_pool, 1, cmap.userwhere );

    mr = _sql_dispatch( _sql_make_cmd( cmd->tmp_pool, 4, "default",
				       cmap.usrtable, cmap.usrfields, where ),
			"sql_select" );
    _sql_check_response(mr);
  
    sd = (sql_data_t *) mr->data;
    
    /* walk through the array, adding users to the cache */
    for ( index = 0, cnt = 0; cnt < sd->rnum; cnt++ ) {
      username = sd->data[index++];

      /* if the username is NULL, skip it */
      if ( username == NULL ) continue;

      password = sd->data[index++];
      
      uid = cmap.defaultuid;
      if (cmap.uidfield) {
	if (sd->data[index]) {
	  uid = atoi(sd->data[index++]);
	} else {
	  index++;
	}
      }
      
      gid = cmap.defaultgid;
      if (cmap.gidfield) {
	if (sd->data[index]) {
	  gid = atoi(sd->data[index++]);
	} else {
	  index++;
	}
      }

      if (cmap.defaulthomedir)
	dir =  cmap.defaulthomedir;
      else
	dir = sd->data[index++];

      if (cmap.shellfield)
	shell = sd->data[index++];
      else
	shell =  "";
      
      if (uid < cmap.minuseruid)
	uid = cmap.defaultuid;
      if (gid < cmap.minusergid)
	gid = cmap.defaultgid;
      
      _sql_addpasswd(cmd, username, password, uid, gid, shell, dir);
    } 
  } else {
    /* retrieve our list of passwds */
    where = _sql_where(cmd->tmp_pool, 1, cmap.userwhere );
    
    mr = _sql_dispatch( _sql_make_cmd( cmd->tmp_pool, 4, "default",
				       cmap.usrtable, cmap.usrfield, where ),
			"sql_select" );
    _sql_check_response(mr);
    
    sd = (sql_data_t *) mr->data;
    
    for ( cnt = 0; cnt < sd->rnum; cnt++ ) {
      username = sd->data[cnt];
      
      /* if the username is NULL for whatever reason, skip it */
      if ( username == NULL ) continue;
      
      /* otherwise, add it to the cache */
      lpw.pw_uid = -1;
      lpw.pw_name = username;
      _sql_getpasswd(cmd, &lpw);
    }
  }
  
  cmap.passwd_cache_filled = 1;
  cmap.curr_passwd = passwd_name_cache->head;

  log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_setpwent");

  return (SQL_USERGOD ? mod_create_data( cmd, (void *) 1 ) : DECLINED(cmd));
}

MODRET cmd_getpwent(cmd_rec * cmd)
{
  struct passwd *pw;
  modret_t *mr;

  _sql_check_cmd(cmd, "cmd_getpwent");

  if (!SQL_USERSET)
    return (SQL_USERGOD ? mod_create_data(cmd,(void *)NULL):DECLINED(cmd));

  log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> cmd_getpwent");

  /* make sure our passwd cache is complete  */
  if ( !cmap.passwd_cache_filled ) {
    mr = cmd_setpwent(cmd);
    if ( mr->data == ( void * ) 0 ) {
      /* something didn't work in the setpwent call */
      log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_getpwent");
      return (SQL_USERGOD  ? mod_create_data( cmd, (void *) NULL ) : DECLINED(cmd));
    }
  }

  if ( cmap.curr_passwd != NULL ) {
    pw = ( struct passwd * ) cmap.curr_passwd->data;
    cmap.curr_passwd = cmap.curr_passwd->list_next;
  } else {
    pw = NULL;
  }

  log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_getpwent");

  if ( pw == NULL )
    return (SQL_USERGOD ? mod_create_data( cmd, (void *) pw) : DECLINED(cmd) );

  return mod_create_data( cmd, (void *) pw);
}

MODRET cmd_endpwent(cmd_rec * cmd)
{
  _sql_check_cmd(cmd, "cmd_endpwent");

  if (!SQL_USERSET)
    return (SQL_USERGOD ? mod_create_data(cmd,(void *)0):DECLINED(cmd));
  
  log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> cmd_endpwent");
  
  cmap.curr_passwd = NULL;
  
  log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_endpwent");
  
  return (SQL_USERGOD ? mod_create_data( cmd, (void *) 0 ) : DECLINED(cmd));
}

MODRET cmd_setgrent(cmd_rec * cmd)
{
  modret_t *mr = NULL;
  sql_data_t *sd = NULL;
  int cnt = 0;
  struct group lgr;
  gid_t gid;
  char *groupname = NULL;
  char *grp_mem = NULL;
  char *where = NULL;
  array_header *ah =NULL;
  char *iterator = NULL;
  char *member = NULL;

  _sql_check_cmd(cmd, "cmd_setgrent");

  if (!SQL_GROUPSET)
    return (SQL_GROUPGOD ? mod_create_data(cmd,(void *)0):DECLINED(cmd));

  log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> cmd_setgrent");

  /* if we've already filled the passwd group, just reset curr_group */
  if ( cmap.group_cache_filled ) {
    cmap.curr_group = group_name_cache->head;
    log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_setgrent");
    return (SQL_GROUPGOD ? mod_create_data( cmd, (void *) 1 ) : DECLINED(cmd));
  }

  if (SQL_FASTGROUPS) {
    /* retrieve our list of groups */
    where = _sql_where(cmd->tmp_pool, 1, cmap.groupwhere);
    
    mr = _sql_dispatch( _sql_make_cmd( cmd->tmp_pool, 6, "default",
				       cmap.grptable, cmap.grpfields, where, NULL ),
			"sql_select");
    _sql_check_response(mr);
    
    sd = (sql_data_t *) mr->data;
    
    /* for each group, fill our array header and call _sql_addgroup */

    for ( cnt = 0; cnt < sd->rnum; cnt ++ ) {
      /* if the groupname is NULL for whatever reason, skip the row */
      groupname = sd->data[cnt * 3];
      if ( groupname == NULL ) continue;

      gid = (gid_t) atol(sd->data[(cnt * 3) + 1]);
      grp_mem = sd->data[(cnt * 3) + 2];
      
      ah = make_array(cmd->tmp_pool, 10, sizeof(char *));
      iterator = grp_mem;

      for (member = strsep(&iterator, " ,"); member; member = strsep(&iterator, " ,")) {
	if (*member=='\0') continue;
	*((char **) push_array(ah)) = member;
      }

      _sql_addgroup(cmd, groupname, gid, ah);
    }
  } else {
    /* retrieve our list of groups */
    where = _sql_where(cmd->tmp_pool, 1, cmap.groupwhere);
    
    mr = _sql_dispatch( _sql_make_cmd( cmd->tmp_pool, 6, "default",
				       cmap.grptable, cmap.grpfield, where, NULL, "DISTINCT" ),
			"sql_select");
    _sql_check_response(mr);
    
    sd = (sql_data_t *) mr->data;
    
    for ( cnt = 0; cnt < sd->rnum; cnt++ ) {
      groupname = sd->data[cnt];
      
      /* if the groupname is NULL for whatever reason, skip it */
      if ( groupname == NULL ) continue;
      
      /* otherwise, add it to the cache */
      lgr.gr_gid = -1;
      lgr.gr_name = groupname;
      
      _sql_getgroup(cmd, &lgr);
    }
  }
  
  cmap.group_cache_filled = 1;
  cmap.curr_group = group_name_cache->head;

  log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_setgrent");

  return (SQL_GROUPGOD ? mod_create_data( cmd, (void *) 1 ) : DECLINED(cmd));
}

MODRET cmd_getgrent(cmd_rec * cmd)
{
  struct group *gr;
  modret_t *mr;

  _sql_check_cmd(cmd, "cmd_getgrent");

  if (!SQL_GROUPSET)
    return (SQL_GROUPGOD ? mod_create_data(cmd,(void *)NULL):DECLINED(cmd));

  log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> cmd_getgrent");

  /* make sure our group cache is complete  */
  if ( !cmap.group_cache_filled ) {
    mr = cmd_setgrent(cmd);
    if ( mr->data == ( void * ) 0 ) {
      /* something didn't work in the setgrent call */
      log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_getgrent");
      return (SQL_GROUPGOD ? mod_create_data( cmd, (void *) NULL ) : DECLINED(cmd));
    }
  }

  if ( cmap.curr_group != NULL ) {
    gr = ( struct group * ) cmap.curr_group->data;
    cmap.curr_group = cmap.curr_group->list_next;
  } else {
    gr = NULL;
  }

  log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_getgrent");

  if ( gr == NULL )
    return (SQL_GROUPGOD ? mod_create_data( cmd, (void *) gr) : DECLINED(cmd));

  return mod_create_data( cmd, (void *) gr);
}

MODRET cmd_endgrent(cmd_rec * cmd)
{
  _sql_check_cmd(cmd, "cmd_endgrent");

  if (!SQL_GROUPSET)
    return (SQL_GROUPGOD ? mod_create_data(cmd,(void *)0):DECLINED(cmd));

  log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> cmd_endgrent");

  cmap.curr_group = NULL;

  log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_endgrent");

  return (SQL_GROUPGOD ? mod_create_data( cmd, (void *) 0 ) : DECLINED(cmd));
}

MODRET cmd_getpwnam(cmd_rec * cmd)
{
  struct passwd *pw;
  struct passwd lpw;

  _sql_check_cmd(cmd, "getpwnam");

  if (!SQL_USERS)
    return DECLINED(cmd);

  log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> cmd_getpwnam");

  lpw.pw_uid = -1;
  lpw.pw_name = cmd->argv[0];
  pw = _sql_getpasswd(cmd, &lpw);

  if (pw == NULL) {
    log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_getpwnam");
    return SQL_USERGOD ? ERROR(cmd) : DECLINED(cmd);
  }

  log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_getpwnam");

  return mod_create_data(cmd, pw);
}

MODRET cmd_getpwuid(cmd_rec * cmd)
{
  struct passwd *pw;
  struct passwd lpw;

  _sql_check_cmd(cmd, "cmd_getpwuid");

  if (!SQL_USERS)
    return DECLINED(cmd);

  log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> cmd_getpwuid");

  lpw.pw_uid = (uid_t) cmd->argv[0];
  lpw.pw_name = NULL;
  pw = _sql_getpasswd(cmd, &lpw);

  if (pw == NULL) {
    log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_getpwuid");
    return SQL_USERGOD ? ERROR(cmd) : DECLINED(cmd);
  }

  log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_getpwuid");

  return mod_create_data(cmd, pw);
}

MODRET cmd_getgrnam(cmd_rec * cmd)
{
  struct group *gr;
  struct group lgr;

  _sql_check_cmd(cmd, "cmd_getgrname");

  if (!SQL_GROUPS)
    return DECLINED(cmd);

  log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> cmd_getgrnam");

  lgr.gr_gid = -1;
  lgr.gr_name = cmd->argv[0];
  gr = _sql_getgroup(cmd, &lgr);

  if (gr == NULL) {
    log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_getgrnam");
    return SQL_GROUPGOD ? ERROR(cmd) : DECLINED(cmd);
  }

  log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_getgrnam");
  return mod_create_data(cmd, gr);
}

MODRET cmd_getgrgid(cmd_rec * cmd)
{
  struct group *gr;
  struct group lgr;

  _sql_check_cmd(cmd, "cmd_getgrgid");

  if (!SQL_GROUPS)
    return DECLINED(cmd);

  log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> cmd_getgrgid");

  lgr.gr_gid = (gid_t) cmd->argv[0];
  lgr.gr_name = NULL;
  gr = _sql_getgroup(cmd, &lgr);

  if (gr == NULL) {
    log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_getgrgid");
    return SQL_GROUPGOD ? ERROR(cmd) : DECLINED(cmd);
  }

  log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_getgrgid");
  return mod_create_data(cmd, gr);
}

MODRET cmd_auth(cmd_rec * cmd)
{
  char *user = NULL;
  struct passwd lpw, *pw;
  modret_t *mr = NULL;

  _sql_check_cmd(cmd, "cmd_auth");

  if (!SQL_USERS)
    return DECLINED(cmd);

  log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> cmd_auth");

  /* fix up the username -- we don't accept spaces anywhere in there */
  user = _sql_strip_spaces( cmd->tmp_pool, cmd->argv[0] );

  /* escape our username */
  mr = _sql_dispatch( _sql_make_cmd( cmd->tmp_pool, 2, "default", 
				     user ), "sql_escapestring" );
  _sql_check_response(mr);
  
  user = (char *) mr->data;

  lpw.pw_uid = -1;
  lpw.pw_name = cmd->argv[0];

  if ((pw = _sql_getpasswd(cmd, &lpw)) && 
      !auth_check(cmd->tmp_pool, pw->pw_passwd, cmd->argv[0], cmd->argv[1])) {
    log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_auth");
    return HANDLED(cmd);
  } else {
    log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_auth");
    return ( SQL_USERGOD ? ERROR_INT(cmd,AUTH_BADPWD) : DECLINED(cmd) );
  }
}

MODRET cmd_check(cmd_rec * cmd)
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
  struct passwd lpw;
  struct stat st;
  modret_t *mr = NULL;

  _sql_check_cmd(cmd, "cmd_check");

  if (!SQL_USERS)
    return DECLINED(cmd);

  log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> cmd_check");

  if (cmd->argv[0] == NULL) {
    log_debug(DEBUG_AUTH, _MOD_VERSION ": NULL hashed password ");
  } else if (cmd->argv[2] == NULL) {
    log_debug(DEBUG_AUTH, _MOD_VERSION ": NULL clear password ");
  } else {
    c_hash = cmd->argv[0];
    c_clear = cmd->argv[2];

    for (cnt = 0; cnt < ah->nelts; cnt++) {
      auth_entry = ((auth_type_entry **) ah->elts)[cnt];
      log_debug(DEBUG_AUTH, _MOD_VERSION ": checking auth_type %s",
		auth_entry->name);

      mr = auth_entry->check_function(cmd, c_clear, c_hash);
      if (!MODRET_ISERROR(mr)) {
	log_debug(DEBUG_AUTH, _MOD_VERSION ": '%s' auth handler reports success",
		  auth_entry->name);
	success = 1;
	break;
      }
    }
  }

  if (success) {
    /* this and the associated hack in cmd_uid_name are to support
     * uid reuse in the database -- people (for whatever reason) are
     * reusing uids/gids multiple times, and the displayed owner in a 
     * LIST or NLST needs to match the current user if possible.  This
     * depends on the fact that if we get success, the user exists in the
     * database ( -- is this always true? ).
     */

    lpw.pw_uid = -1;
    lpw.pw_name = cmd->argv[1];
    cmap.authpasswd = _sql_getpasswd(cmd, &lpw);

    /*
     * finally, build the user's homedir if necessary 
     */
    
    if (cmap.buildhomedir && cmap.authpasswd &&
	(stat(cmap.authpasswd->pw_dir, &st) == -1 && errno == ENOENT)) {
      build_homedir(cmd, cmap.authpasswd->pw_dir, 
		    S_IRWXU | S_IRWXG | S_IRWXO, 
		    cmap.authpasswd->pw_uid,
		    cmap.authpasswd->pw_gid);
    }
    
    log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_check");
    return HANDLED(cmd);
  }

  log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_check");

  if (!success)
    return SQL_USERGOD ? ERROR(cmd) : DECLINED(cmd);

  return mr;
}

MODRET cmd_uid_name(cmd_rec * cmd)
{
  struct passwd *pw;
  struct passwd lpw;
  char uidstr[MODSQL_BUFSIZE] = {'\0'};

  _sql_check_cmd(cmd, "cmd_uid_name");

  if (!SQL_USERS)
    return DECLINED(cmd);

  log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> cmd_uid_name");

  lpw.pw_uid = (uid_t) cmd->argv[0];
  lpw.pw_name = NULL;

  /* check to see if we're looking up the current user */
  if ( cmap.authpasswd && (lpw.pw_uid == cmap.authpasswd->pw_uid)) {
    log_debug(DEBUG_INFO, _MOD_VERSION ": matched current user");
    pw = cmap.authpasswd;
  } else {
    pw = _sql_getpasswd(cmd, &lpw);
  }

  log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_uid_name");

  if (pw == NULL) {
    if (!SQL_USERGOD)
      return DECLINED(cmd);

    snprintf( uidstr, MODSQL_BUFSIZE, "%d", (uid_t) cmd->argv[0]);
    return mod_create_data(cmd, uidstr);
  }

  return mod_create_data(cmd, pw->pw_name);
}

MODRET cmd_gid_name(cmd_rec * cmd)
{
  struct group *gr;
  struct group lgr;
  char gidstr[MODSQL_BUFSIZE]={'\0'};

  _sql_check_cmd(cmd, "cmd_gid_name");

  if (!SQL_GROUPS) {
    return DECLINED(cmd);
  }

  log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> cmd_gid_name");

  lgr.gr_gid = (gid_t) cmd->argv[0];
  lgr.gr_name = NULL;
  gr = _sql_getgroup(cmd, &lgr);

  log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_gid_name");

  if (gr == NULL) {
    if (!SQL_GROUPGOD)
      return DECLINED(cmd);

    snprintf( gidstr, MODSQL_BUFSIZE, "%d", (gid_t) cmd->argv[0]);
    return mod_create_data(cmd, gidstr);
  }

  return mod_create_data(cmd, gr->gr_name);
}

MODRET cmd_name_uid(cmd_rec * cmd)
{
  struct passwd *pw;
  struct passwd lpw;

  _sql_check_cmd(cmd, "cmd_name_uid");

  if (!SQL_USERS) {
    return DECLINED(cmd);
  }

  log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> cmd_name_uid");

  lpw.pw_uid = -1;
  lpw.pw_name = cmd->argv[0];

  /* check to see if we're looking up the current user */
  if (cmap.authpasswd && 
      (strcmp(lpw.pw_name, cmap.authpasswd->pw_name) == 0)) {
    log_debug(DEBUG_INFO, _MOD_VERSION ": matched current user");
    pw = cmap.authpasswd;
  } else {
    pw = _sql_getpasswd(cmd, &lpw);
  }

  if (pw == NULL) {
    log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_name_uid");
    return SQL_USERGOD ? ERROR(cmd) : DECLINED(cmd);
  }

  log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_name_gid");

  return mod_create_data(cmd, (void *) pw->pw_uid);
}

MODRET cmd_name_gid(cmd_rec * cmd)
{
  struct group *gr;
  struct group lgr;

  _sql_check_cmd(cmd, "cmd_name_gid");

  if (!SQL_GROUPS) {
    return DECLINED(cmd);
  }

  log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> cmd_name_gid");

  lgr.gr_gid = -1;
  lgr.gr_name = cmd->argv[0];
  gr = _sql_getgroup(cmd, &lgr);

  if (gr == NULL) {
    log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_name_gid");
    return SQL_GROUPGOD ? ERROR(cmd) : DECLINED(cmd);
  }

  log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_name_gid");

  return mod_create_data(cmd, (void *) gr->gr_gid);
}

MODRET cmd_getstats(cmd_rec * cmd)
{
  modret_t *mr;
  char *query;
  sql_data_t *sd;
  char *usrwhere, *where;

  _sql_check_cmd(cmd, "cmd_getstats");

  log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> cmd_getstats");

  if (!cmap.sql_fstor) {
    return DECLINED(cmd);
  }

  usrwhere = pstrcat(cmd->tmp_pool, cmap.usrfield, " = '", _sql_realuser(cmd), "'", NULL);
  where = _sql_where(cmd->tmp_pool, 2, usrwhere, cmap.userwhere );
  
  query = pstrcat(cmd->tmp_pool, cmap.sql_fstor, ", ",
		  cmap.sql_fretr, ", ", cmap.sql_bstor, ", ",
		  cmap.sql_bretr, NULL );
  
  mr = _sql_dispatch( _sql_make_cmd( cmd->tmp_pool, 4, "default",
				     cmap.usrtable, query, where ),
		      "sql_select" );
  _sql_check_response(mr);
  
  log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_getstats");

  sd = mr->data;

  if (sd->rnum == 0)
    return ERROR(cmd);

  return mod_create_data(cmd, sd->data);
}

MODRET cmd_getratio(cmd_rec * cmd)
{
  modret_t *mr;
  char *query;
  sql_data_t *sd;
  char *usrwhere, *where;

  _sql_check_cmd(cmd, "cmd_getratio");

  if (!cmap.sql_frate) {
    return DECLINED(cmd);
  }

  log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> cmd_getratio");

  usrwhere = pstrcat(cmd->tmp_pool, cmap.usrfield, " = '", _sql_realuser(cmd), "'", NULL);
  where = _sql_where(cmd->tmp_pool, 2, usrwhere, cmap.userwhere );
  
  query = pstrcat(cmd->tmp_pool, cmap.sql_frate, ", ",
		  cmap.sql_fcred, ", ", cmap.sql_brate, ", ",
		  cmap.sql_bcred, NULL);
  
  mr = _sql_dispatch( _sql_make_cmd( cmd->tmp_pool, 4, "default",
				     cmap.usrtable, query, where ),
		      "sql_select" );
  _sql_check_response(mr);
  
  log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< cmd_getratio");

  sd = mr->data;

  if (sd->rnum == 0)
    return ERROR(cmd);

  return mod_create_data(cmd, sd->data);
}

/*****************************************************************
 *
 * CONFIGURATION DIRECTIVE HANDLERS
 *
 *****************************************************************/

MODRET set_sqlratiostats(cmd_rec * cmd)
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
      add_config_param_str("SQLRatioStats", 4,
                           "fstor", "fretr", "bstor", "bretr");
    break;

  case 4:
    add_config_param_str("SQLRatioStats", 4,
                         (void *) cmd->argv[1], (void *) cmd->argv[2],
                         (void *) cmd->argv[3], (void *) cmd->argv[4]);
  }

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

MODRET add_virtualstr(char * name, cmd_rec * cmd)
{
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT | CONF_GLOBAL | CONF_VIRTUAL);

  add_config_param_str(name, 1, (void *) cmd->argv[1]);

  return HANDLED(cmd);
}

MODRET add_virtualbool(char * name, cmd_rec * cmd)
{
  int b;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT | CONF_GLOBAL | CONF_VIRTUAL);

  b = get_boolean(cmd, 1);
  if (b == -1)
    CONF_ERROR(cmd, "requires a boolean value");

  c = add_config_param(name, 1, (void *) b);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_sqluserinfo(cmd_rec * cmd)
{
  /* SQLUserInfo table(s) usernamefield passwdfield uid gid homedir shell */

  CHECK_ARGS(cmd, 7);
  CHECK_CONF(cmd, CONF_ROOT | CONF_GLOBAL | CONF_VIRTUAL);

  /* required to exist - not even going to check them. */
  add_config_param_str("SQLUserTable", 1, (void *) cmd->argv[1]);
  add_config_param_str("SQLUsernameField", 1, (void *) cmd->argv[2]);
  add_config_param_str("SQLPasswordField", 1, (void *) cmd->argv[3]);

  /* these could be "NULL" */
  if (strncasecmp("null", cmd->argv[4], 4))
    add_config_param_str("SQLUidField", 1, (void *) cmd->argv[4]);
  if (strncasecmp("null", cmd->argv[5], 4))
    add_config_param_str("SQLGidField", 1, (void *) cmd->argv[5]);
  if (strncasecmp("null", cmd->argv[6], 4))
    add_config_param_str("SQLHomedirField", 1, (void *) cmd->argv[6]);
  if (strncasecmp("null", cmd->argv[7], 4))
    add_config_param_str("SQLShellField", 1, (void *) cmd->argv[7]);

  return HANDLED(cmd);
}

MODRET set_sqluserwhereclause(cmd_rec * cmd)
{
  return add_virtualstr( "SQLUserWhereClause", cmd);
}

MODRET set_sqlgroupinfo(cmd_rec * cmd)
{
  /* SQLGroupInfo table(s) groupnamefield gidfield membersfield */

  CHECK_ARGS(cmd, 4);
  CHECK_CONF(cmd, CONF_ROOT | CONF_GLOBAL | CONF_VIRTUAL);

  /* required to exist - not even going to check them. */
  add_config_param_str("SQLGroupTable", 1, (void *) cmd->argv[1]);
  add_config_param_str("SQLGroupnameField", 1, (void *) cmd->argv[2]);
  add_config_param_str("SQLGroupGIDField", 1, (void *) cmd->argv[3]);
  add_config_param_str("SQLGroupMembersField", 1, (void *) cmd->argv[4]);

  return HANDLED(cmd);
}

MODRET set_sqlgroupwhereclause(cmd_rec * cmd)
{
  return add_virtualstr( "SQLGroupWhereClause", cmd);
}

MODRET set_sqldefaulthomedir(cmd_rec * cmd)
{
  return add_virtualstr( "SQLDefaultHomedir", cmd);
}

MODRET set_sqlhomedirondemand(cmd_rec * cmd)
{
  return add_virtualbool( "SQLHomedirOnDemand", cmd);
}

MODRET set_sqllog(cmd_rec * cmd)
{
  /* SQLLog cmdlist query-name*/

  config_rec * c;
  char *name, *namep;
  char *cmds;
  char *iterator;

  CHECK_CONF(cmd, CONF_ROOT | CONF_GLOBAL | CONF_VIRTUAL);

  if ((cmd->argc < 3) || (cmd->argc > 4)) {
    CONF_ERROR( cmd, "expected cmdlist query-name [IGNORE_ERRORS]" );
  }

  /* for each element in the command list, add a 'SQLLog_CMD' config_rec..
   * this is an optimization that speeds up logging and also simplifies the
   * logging code, since there's no need to run through and parse a bunch
   * of potenitally unused SQLLog statements each time any command is run.
   */
  
  cmds= cmd->argv[1];
  iterator=cmds;

  for (name = strsep( &iterator, ", " ); name; name = strsep( &iterator, ", ")) {
    if ( *name=='\0' ) continue;
    for (namep = name; *namep != '\0'; namep++)
      *namep =  toupper( *namep );
    
    name = pstrcat( cmd->tmp_pool, "SQLLog_", name, NULL);
    
    if ((cmd->argc == 4) && (!strcasecmp(cmd->argv[3], "IGNORE_ERRORS"))) {
      c = add_config_param_str(name, 2, cmd->argv[2], "ignore");
    } else {
      c = add_config_param_str(name, 1, cmd->argv[2]);
    }

    c->flags |= CF_MERGEDOWN;
  }
  
  return HANDLED(cmd);
}

MODRET set_sqlnamedquery(cmd_rec * cmd)
{
  /* SQLNamedQuery name type query-string */

  config_rec *c = NULL;
  char *name = NULL;

  CHECK_CONF(cmd, CONF_ROOT | CONF_GLOBAL | CONF_VIRTUAL);

  if (cmd->argc < 3) {
    CONF_ERROR( cmd, "requires at least 2 arguments" );
  }

  name = pstrcat( cmd->tmp_pool, "SQLNamedQuery_", cmd->argv[1], NULL );

  if (!strcasecmp(cmd->argv[2], "SELECT")) {
    if (cmd->argc != 4) 
      CONF_ERROR(cmd, "expected 'SELECT' query-string");

    c=add_config_param_str(name, 2, SQL_SELECT_C, cmd->argv[3] );
  } else if (!strcasecmp(cmd->argv[2], "FREEFORM")) {
    if (cmd->argc != 4) 
      CONF_ERROR(cmd, "expected 'FREEFORM' query-string");

    c=add_config_param_str(name, 2, SQL_FREEFORM_C, cmd->argv[3] );
  } else if (!strcasecmp(cmd->argv[2], "INSERT")) {
    if (cmd->argc != 5) 
      CONF_ERROR(cmd, "expected 'INSERT' query-string table-name");

    c=add_config_param_str(name, 3, SQL_INSERT_C, cmd->argv[3], cmd->argv[4] );
  } else if (!strcasecmp(cmd->argv[2], "UPDATE")) {
    if (cmd->argc != 5) 
      CONF_ERROR(cmd, "expected 'UPDATE' query-string table-name");

    c=add_config_param_str(name, 3, SQL_UPDATE_C, cmd->argv[3], cmd->argv[4] );
  } else {
    CONF_ERROR(cmd, "type must be SELECT, INSERT, UPDATE, or FREEFORM");
  }

  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_sqlshowinfo(cmd_rec * cmd)
{
  /* SQLShowInfo cmdlist numeric format-string */

  config_rec *c = NULL;
  char *iterator = NULL;
  char *namep = NULL;
  char *name = NULL;
  char *cmds = NULL;

  CHECK_ARGS(cmd, 3);
  CHECK_CONF(cmd, CONF_ROOT | CONF_GLOBAL | CONF_VIRTUAL);

  cmds = pstrdup(cmd->tmp_pool, cmd->argv[1]);
  iterator = cmds;

  for (name = strsep( &iterator, ", " ); name; name=strsep( &iterator, ", ")) {
    if ( *name=='\0' ) continue;
    for (namep = name; *namep != '\0'; namep++)
      *namep=toupper(*namep);
    
    name = pstrcat( cmd->tmp_pool, "SQLShowInfo_", name, NULL);
    
    c = add_config_param_str(name, 2, cmd->argv[2], cmd->argv[3] );
    c->flags |= CF_MERGEDOWN;
  }

  return HANDLED(cmd);
}

MODRET set_sqlauthenticate(cmd_rec * cmd)
{
  config_rec *c = NULL;
  char *arg = NULL;
  int authmask = 0;
  int cnt = 0;

  int groupset_flag = 0;
  int userset_flag = 0;
  int groups_flag = 0;
  int users_flag = 0;

  CHECK_CONF(cmd, CONF_ROOT | CONF_GLOBAL | CONF_VIRTUAL);

  if ((cmd->argc<2) || (cmd->argc>5))
    CONF_ERROR(cmd, "requires 1 to 4 arguments. Check the mod_sql docs.");

  /* we're setting our authmask here -- we have a bunch of checks needed to
   * make sure users aren't trying to screw around with us.
   */

  if ((cmd->argc == 2) && !strcasecmp(cmd->argv[1], "on")) {
    authmask = SQL_AUTH_GROUPSET | SQL_AUTH_USERSET | 
      SQL_AUTH_USERS | SQL_AUTH_GROUPS;
  } else if (!((cmd->argc == 2) && !strcasecmp(cmd->argv[1], "off"))) {
    for (cnt = 1; cnt < cmd->argc; cnt++) {
      arg = cmd->argv[cnt];
      
      if (!strncasecmp("groupset", arg, 8)) {
	if (groupset_flag)
	  CONF_ERROR(cmd, "groupset already set");
	
	if (!strcasecmp("groupsetfast", arg)) {
	  authmask |= SQL_FAST_GROUPSET;
	} else if (strlen(arg) > 8) {
	  CONF_ERROR(cmd, "unknown argument");
	}
	
	authmask |= SQL_AUTH_GROUPSET;
	groupset_flag = 1;
      } else if (!strncasecmp("userset", arg, 7)) {
	if (userset_flag)
	  CONF_ERROR(cmd, "userset already set");
	
	if (!strcasecmp("usersetfast", arg)) {
	  authmask |= SQL_FAST_USERSET;
	} else if (strlen(arg) > 7) {
	  CONF_ERROR(cmd, "unknown argument");
	}
	
	authmask |= SQL_AUTH_USERSET;
	userset_flag = 1;
      } else if (!strncasecmp("groups", arg, 6)) {
	if (groups_flag)
	  CONF_ERROR(cmd, "groups already set");
	
	if (!strcasecmp("groups*", arg)) {
	  authmask |= SQL_AUTH_GROUPS_DEFINITIVE;
	} else if (strlen(arg) > 6) {
	  CONF_ERROR(cmd, "unknown argument");
	}
	
	authmask |= SQL_AUTH_GROUPS;
	groups_flag = 1;
      } else if (!strncasecmp("users", arg, 5)) {
	if (users_flag)
	  CONF_ERROR(cmd, "users already set");
	
	if (!strcasecmp("users*", arg)) {
	  authmask |= SQL_AUTH_USERS_DEFINITIVE;
	} else if (strlen(arg) > 5) {
	  CONF_ERROR(cmd, "unknown argument");
	}
	
	authmask |= SQL_AUTH_USERS;
	users_flag = 1;
      } else {
	CONF_ERROR( cmd, "unknown argument");
      }
    } 
  }
  
  /* finally, fixup if we've received groupset with no groups,
   * or userset with no users
   */
  if ((groupset_flag && !groups_flag) ||
      (userset_flag && !users_flag)) {
    CONF_ERROR( cmd, "groupset and userset have no meaning without "
		"a corresponding groups or users argument.");
  }

  c = add_config_param("SQLAuthenticate", 1, (void *) authmask);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}


MODRET set_sqlconnectinfo(cmd_rec * cmd)
{
  config_rec *c;
  char *info = NULL;
  char *user = "";
  char *pass = "";
  char *ttl = NULL;

  CHECK_CONF(cmd, CONF_ROOT | CONF_GLOBAL | CONF_VIRTUAL);

  if ((cmd->argc < 2) || (cmd->argc > 5))
    CONF_ERROR(cmd, "requires 1 to 4 arguments.  Check the mod_sql docs.");

  if (cmd->argc > 1)
    info = cmd->argv[1];

  if (cmd->argc > 2)
    user = cmd->argv[2];

  if (cmd->argc > 3)
    pass = cmd->argv[3];

  if (cmd->argc > 4)
    ttl = cmd->argv[4];
  else
    ttl = "0";

  c = add_config_param_str("SQLConnectInfo", 4,
                           (void *) info, (void *) user, (void *) pass, (void *) ttl);

  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_sqlauthtypes(cmd_rec * cmd)
{
  config_rec *c;
  array_header *ah;
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

  ah = make_array( permanent_pool, cmd->argc - 1, sizeof(auth_type_entry *));

  /*
   * walk through our cmd->argv 
   */
  for (cnt = 1; cnt < cmd->argc; cnt++) {
    auth_entry = get_auth_entry(cmd->argv[cnt]);
    if (auth_entry == NULL) {
      log_debug(DEBUG_WARN, _MOD_VERSION ": unknown auth handler '%s'",
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

MODRET set_sqlminid(cmd_rec * cmd)
{
  config_rec *c;
  unsigned long val;
  char *endptr = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT | CONF_GLOBAL | CONF_VIRTUAL);

  val = strtoul(cmd->argv[1], &endptr, 10);

  if (*endptr != '\0') {
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

MODRET set_sqlminuseruid(cmd_rec * cmd)
{
  config_rec *c = NULL;
  unsigned long val;
  char *endptr = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT | CONF_GLOBAL | CONF_VIRTUAL);

  val = strtoul(cmd->argv[1], &endptr, 10);

  if (*endptr != '\0') {
    CONF_ERROR(cmd, "requires a numeric argument");
  }

  /*
   * whee! need to check if in the legal range for uid_t
   */
  /*
   * however, I can't think of a cross-platform way of doing this.. if
   * anyone knows of a way to find the MAX uid_t, let me know.. 
   */
  if ((val == ULONG_MAX) && (errno == ERANGE)) {
    CONF_ERROR(cmd, "the value given is outside the legal range");
  }

  c = add_config_param("SQLMinUserUID", 1, (void *) (uid_t) val);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_sqlminusergid(cmd_rec * cmd)
{
  config_rec *c = NULL;
  unsigned long val;
  char *endptr = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT | CONF_GLOBAL | CONF_VIRTUAL);

  val = strtoul(cmd->argv[1], &endptr, 10);

  if (*endptr != '\0') {
    CONF_ERROR(cmd, "requires a numeric argument");
  }

  /*
   * whee! need to check if in the legal range for gid_t 
   */
  /*
   * however, I can't think of a cross-platform way of doing this.. if
   * anyone knows of a way to find the MAX gid_t, let me know.. 
   */
  if ((val == ULONG_MAX) && (errno == ERANGE)) {
    CONF_ERROR(cmd, "the value given is outside the legal range");
  }

  c = add_config_param("SQLMinUserGID", 1, (void *) (gid_t) val);
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

  if (*endptr != '\0') {
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

  if (*endptr != '\0') {
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

MODRET set_deprecated(cmd_rec * cmd)
{
  int cnt, numdeps=23;
  char *depmap[] = {"SQLUsernameField", "SQLUserInfo",
		    "SQLUidField", "SQLUserInfo",
		    "SQLGidField", "SQLUserInfo",
		    "SQLPasswordField", "SQLUserInfo",
		    "SQLHomedirField", "SQLUserInfo",
		    "SQLShellField", "SQLUserInfo",
		    "SQLGroupnameField", "SQLGroupInfo",
		    "SQLGroupGIDField", "SQLGroupInfo",
		    "SQLGroupMembersField", "SQLGroupInfo",
		    "SQLLogHosts", "SQLLog",
		    "SQLLogHits", "SQLLog",
		    "SQLLogDirs", "SQLLog",
		    "SQLLoginCountField", "SQLLog",
		    "SQLHomedir", "SQLDefaultHomedir",
		    "SQLWhereClause", "SQLUserWhereClause",
		    "SQLUserTable", "SQLUserInfo",
		    "SQLGroupTable", "SQLGroupInfo",
		    "SQLDoGroupAuth", "SQLAuthenticate",
		    "SQLDoAuth", "SQLAuthenticate",
		    "SQLProcessPwEnt", "SQLAuthenticate",
		    "SQLProcessGrEnt", "SQLAuthenticate",
		    "SQLAuthoritative", "SQLAuthenticate",
		    "SQLLogStats", "SQLRatioStats"
  };

  /* find the deprecated directive that triggered this.. */

  for (cnt=0; cnt < numdeps; cnt++) {
    if (!strcasecmp(cmd->argv[0], depmap[cnt*2])) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "deprecated directive; check the mod_sql docs for '",
			      depmap[cnt*2+1], "'", NULL) );
    }
  }
  
  CONF_ERROR(cmd, "unknown deprecated directive.  Please check the mod_sql docs.");

  return DECLINED(cmd);
}

/*****************************************************************
 *
 * INITIALIZATION / FORK HANDLERS
 *
 *****************************************************************/

static int sql_init(void)
{

  return 0;
}

static int sql_getconf()
{
  char *authstr = NULL;
  config_rec *c = NULL;
  void *temp_ptr = NULL;
  cmd_rec *cmd = NULL;
  modret_t *mr = NULL;
  sql_data_t *sd = NULL;
  int percall = 0;
  char *fieldset = NULL;
  pool *tmp_pool = NULL;

  /* build a temporary pool */
  tmp_pool = make_named_sub_pool( session.pool, "temp sql init pool" );

  /* get our backend info and toss it up */
  cmd = _sql_make_cmd( tmp_pool, 1, "foo" );
  mr = _sql_dispatch( cmd, "sql_identify" );
  _sql_check_response(mr);

  sd = (sql_data_t *) mr->data;

  log_debug(DEBUG_INFO, _MOD_VERSION ": backend module '%s'", sd->data[0]);
  log_debug(DEBUG_INFO, _MOD_VERSION ": backend api    '%s'", sd->data[1]);

  _sql_free_cmd(cmd);

  log_debug(DEBUG_FUNC, _MOD_VERSION ": >>> sql_getconf");

  sql_pool = make_named_sub_pool( session.pool, "mod_sql pool" );

  group_name_cache = make_cache( sql_pool, _group_name, _groupcmp );
  passwd_name_cache = make_cache( sql_pool, _passwd_name, _passwdcmp );
  group_gid_cache = make_cache( sql_pool, _group_gid, _groupcmp );
  passwd_uid_cache = make_cache( sql_pool, _passwd_uid, _passwdcmp );

  cmap.group_cache_filled = 0;
  cmap.passwd_cache_filled = 0;

  cmap.curr_group = NULL;
  cmap.curr_passwd = NULL;

  /*
   * construct our internal cache structure for this fork 
   */

  memset(&cmap, 0, sizeof(cmap));

  cmap.authmask = get_param_int(main_server->conf, "SQLAuthenticate", FALSE);
  if (cmap.authmask == -1) 
    cmap.authmask = SQL_AUTH_GROUPS | SQL_AUTH_USERS | SQL_AUTH_GROUPSET | SQL_AUTH_USERSET;

  /* SQLHomedirOnDemand defaults to NO */
  cmap.buildhomedir =
      get_param_int(main_server->conf, "SQLHomedirOnDemand", FALSE);
  if (cmap.buildhomedir == -1) cmap.buildhomedir = 0;

  cmap.defaulthomedir = get_param_ptr(main_server->conf, "SQLDefaultHomedir", FALSE);

  temp_ptr = get_param_ptr(main_server->conf, "SQLUserTable", FALSE);
  
  /* if we have no SQLUserTable, SQLUserInfo was not used -- default all */
  
  if (!temp_ptr) {
    cmap.usrtable = MODSQL_DEF_USERTABLE;
    cmap.usrfield = MODSQL_DEF_USERNAMEFIELD;
    cmap.pwdfield = MODSQL_DEF_USERPASSWORDFIELD;
    cmap.uidfield = MODSQL_DEF_USERUIDFIELD;
    cmap.gidfield = MODSQL_DEF_USERGIDFIELD;
    cmap.homedirfield = MODSQL_DEF_USERHOMEDIRFIELD;
    cmap.shellfield = MODSQL_DEF_USERSHELLFIELD;
  } else {
    cmap.usrtable = temp_ptr;
    cmap.usrfield = get_param_ptr(main_server->conf, "SQLUsernameField", FALSE);
    cmap.pwdfield = get_param_ptr(main_server->conf, "SQLPasswordField", FALSE);
    cmap.uidfield = get_param_ptr(main_server->conf, "SQLUidField", FALSE);
    cmap.gidfield = get_param_ptr(main_server->conf, "SQLGidField", FALSE);
    cmap.homedirfield = get_param_ptr(main_server->conf, "SQLHomedirField", FALSE);
    cmap.shellfield = get_param_ptr(main_server->conf, "SQLShellField", FALSE);
  }

  /* build the userfieldset */
  fieldset = pstrcat(tmp_pool, cmap.usrfield, ", ", cmap.pwdfield, NULL);
  if (cmap.uidfield)
    fieldset = pstrcat(tmp_pool, fieldset, ", ", cmap.uidfield, NULL);
  if (cmap.gidfield)
    fieldset = pstrcat(tmp_pool, fieldset, ", ", cmap.gidfield, NULL);
  if ((!cmap.defaulthomedir) && cmap.homedirfield)
    fieldset = pstrcat(tmp_pool, fieldset, ", ", cmap.homedirfield, NULL);
  if (cmap.shellfield)
    fieldset = pstrcat(tmp_pool, fieldset, ", ", cmap.shellfield, NULL);
  cmap.usrfields = pstrdup(sql_pool, fieldset);

  temp_ptr = get_param_ptr(main_server->conf, "SQLGroupTable", FALSE);
  
  /* if we have no temp_ptr, SQLGroupInfo was not used - default all */
  if (!temp_ptr) {
    cmap.grptable = MODSQL_DEF_GROUPTABLE;
    cmap.grpfield = MODSQL_DEF_GROUPNAMEFIELD;
    cmap.grpgidfield = MODSQL_DEF_GROUPGIDFIELD;
    cmap.grpmembersfield = MODSQL_DEF_GROUPMEMBERSFIELD;
  } else {
    cmap.grptable = get_param_ptr(main_server->conf, "SQLGroupTable", FALSE);
    cmap.grpfield = get_param_ptr(main_server->conf, "SQLGroupnameField", FALSE);
    cmap.grpgidfield = get_param_ptr(main_server->conf, "SQLGroupGIDField", FALSE);
    cmap.grpmembersfield = get_param_ptr(main_server->conf, "SQLGroupMembersField", FALSE);
  }

  /* build the groupfieldset */
  fieldset = pstrcat(tmp_pool, cmap.grpfield, ", ", cmap.grpgidfield,
		     ", ", cmap.grpmembersfield, NULL);
  cmap.grpfields = pstrdup(sql_pool, fieldset);

  temp_ptr = get_param_ptr(main_server->conf, "SQLUserWhereClause", FALSE);
  cmap.userwhere = temp_ptr ? pstrcat(sql_pool, "(", temp_ptr, ")", NULL) : "";

  temp_ptr = get_param_ptr(main_server->conf, "SQLGroupWhereClause", FALSE);
  cmap.groupwhere = temp_ptr ? pstrcat(sql_pool, "(", temp_ptr, ")", NULL) : "";

  temp_ptr = get_param_ptr(main_server->conf, "SQLAuthTypes", FALSE);
  cmap.authlist = temp_ptr;

  temp_ptr = get_param_ptr(main_server->conf, "SQLMinID", FALSE);
  if ( temp_ptr ) {
    cmap.minuseruid = (uid_t) temp_ptr;
    cmap.minusergid = (gid_t) temp_ptr;
  } else {
    temp_ptr = get_param_ptr(main_server->conf, "SQLMinUserUID", FALSE);
    cmap.minuseruid = temp_ptr ? ((uid_t) temp_ptr) : MODSQL_MIN_USER_UID;

    temp_ptr = get_param_ptr(main_server->conf, "SQLMinUserGID", FALSE);
    cmap.minusergid = temp_ptr ? ((uid_t) temp_ptr) : MODSQL_MIN_USER_GID;
  }

  temp_ptr = get_param_ptr(main_server->conf, "SQLDefaultUID", FALSE);
  cmap.defaultuid = temp_ptr ? ((uid_t) temp_ptr) : MODSQL_DEF_UID;

  temp_ptr = get_param_ptr(main_server->conf, "SQLDefaultGID", FALSE);
  cmap.defaultgid = temp_ptr ? ((gid_t) temp_ptr) : MODSQL_DEF_GID;

  if ((c = find_config(main_server->conf, CONF_PARAM, "SQLRatioStats", FALSE))) {
    cmap.sql_fstor = c->argv[0];
    cmap.sql_fretr = c->argv[1];
    cmap.sql_bstor = c->argv[2];
    cmap.sql_bretr = c->argv[3];
  }

  if ((c = find_config(main_server->conf, CONF_PARAM, "SQLRatios", FALSE))) {
    if (!cmap.sql_fstor) {
      log_pri(LOG_WARNING, _MOD_VERSION
              ": warning: SQLRatios directive ineffective without SQLRatioStats on");
      log_debug(DEBUG_WARN, _MOD_VERSION
                ": warning: SQLRatios directive ineffective without SQLRatioStats on");
    }
    cmap.sql_frate = c->argv[0];
    cmap.sql_fcred = c->argv[1];
    cmap.sql_brate = c->argv[2];
    cmap.sql_bcred = c->argv[3];
  }

  if ((!cmap.homedirfield) && (!cmap.defaulthomedir)) {
    cmap.authmask ^= SQL_AUTH_USERS;
    log_pri(LOG_WARNING, _MOD_VERSION ": warning: no homedir field and no default specified. User authentication is OFF");
    log_debug(DEBUG_WARN, _MOD_VERSION ": warning: no homedir field and no default specified. User authentication is OFF");
  }

  if (!(c = find_config(main_server->conf, CONF_PARAM, "SQLConnectInfo", FALSE))) {
    cmap.authmask = 0;
    cmap.status = 0;
    cmap.sql_fstor = NULL;
    cmap.sql_frate = NULL;
    log_pri(LOG_WARNING, _MOD_VERSION ": warning: no SQLConnectInfo specified. mod_sql is OFF");
    log_debug(DEBUG_WARN, _MOD_VERSION ": warning: no SQLConnectInfo specified. mod_sql is OFF");
  } else {
    if (!strcasecmp(c->argv[3], "percall")) percall = 1;

    cmd = _sql_make_cmd(tmp_pool, 5, "default", c->argv[1], c->argv[2], c->argv[0], c->argv[3]);
    mr = _sql_dispatch(cmd,"sql_defineconnection");
    _sql_check_response(mr);
    _sql_free_cmd(cmd);
  
    if (!percall) {
      cmd = _sql_make_cmd( tmp_pool, 1, "default" );
      mr = _sql_dispatch(cmd, "sql_open");
      _sql_check_response(mr);
      _sql_free_cmd(cmd);
      log_debug(DEBUG_INFO, _MOD_VERSION ": backend successfully connected.",
		_MOD_VERSION);
    } else {
      log_debug(DEBUG_INFO, _MOD_VERSION ": backend will not be checked until first use.",
		_MOD_VERSION);
    }

    cmap.status = 1;
  }

  log_debug(DEBUG_INFO, _MOD_VERSION ": mod_sql status     : %s",
	    cmap.status ? "on" : "off" );

  authstr = "";

  if (SQL_USERS) {
    if (SQL_USERGOD) {
      authstr = pstrcat( tmp_pool, authstr, "users* ", NULL);
    } else {
      authstr = pstrcat( tmp_pool, authstr, "users ", NULL);
    }
  }

  if (SQL_GROUPS) {
    if (SQL_GROUPGOD) {
      authstr = pstrcat( tmp_pool, authstr, "groups* ", NULL);
    } else {
      authstr = pstrcat( tmp_pool, authstr, "groups ", NULL);
    }
  }

  if (SQL_USERSET) {
    if (SQL_FASTUSERS) {
      authstr = pstrcat( tmp_pool, authstr, "userset(fast) ", NULL);
    } else {
      authstr = pstrcat( tmp_pool, authstr, "userset ", NULL);
    }
  }

  if (SQL_GROUPSET) {
    if (SQL_FASTGROUPS) {
      authstr = pstrcat( tmp_pool, authstr, "groupset(fast)", NULL);
    } else {
      authstr = pstrcat( tmp_pool, authstr, "groupset", NULL);
    }
  }

  log_debug(DEBUG_INFO, _MOD_VERSION ": authenticate       : %s",
	    (!authstr || *authstr=='\0') ? "off" : authstr);

  if (SQL_USERS || cmap.sql_fstor || cmap.sql_frate) {
    log_debug(DEBUG_INFO, _MOD_VERSION ": usertable          : %s",
	      cmap.usrtable);
    log_debug(DEBUG_INFO, _MOD_VERSION ": userid field       : %s",
	      cmap.usrfield);
  }
  if (SQL_USERS) {
    log_debug(DEBUG_INFO, _MOD_VERSION ": password field     : %s",
	      cmap.pwdfield);
    log_debug(DEBUG_INFO, _MOD_VERSION ": uid field          : %s",
	      (cmap.uidfield ? cmap.uidfield : "NULL"));
    log_debug(DEBUG_INFO, _MOD_VERSION ": gid field          : %s",
	      (cmap.gidfield ? cmap.gidfield : "NULL"));
    if (cmap.defaulthomedir) {
      log_debug(DEBUG_INFO, _MOD_VERSION ": homedir(defaulted) : '%s'",
		cmap.defaulthomedir);
    } else {
      log_debug(DEBUG_INFO, _MOD_VERSION ": homedir field      : %s",
		cmap.homedirfield);
    } 
    log_debug(DEBUG_INFO, _MOD_VERSION ": shell field        : %s",
	      (cmap.shellfield ? cmap.shellfield : "NULL"));
    log_debug(DEBUG_INFO, _MOD_VERSION ": homedirondemand    : %s",
	      (cmap.buildhomedir ? "true" : "false"));
  }

  if (SQL_GROUPS) {
    log_debug(DEBUG_INFO, _MOD_VERSION ": group table        : %s",
	      cmap.grptable);
    log_debug(DEBUG_INFO, _MOD_VERSION ": groupname field    : %s",
	      cmap.grpfield);
    log_debug(DEBUG_INFO, _MOD_VERSION ": grp gid field      : %s",
	      cmap.grpgidfield);
    log_debug(DEBUG_INFO, _MOD_VERSION ": grp members field  : %s",
	      cmap.grpmembersfield);
  }

  if (SQL_USERS) {
    log_debug(DEBUG_INFO, _MOD_VERSION ": SQLMinUserUID      : %u",
	      cmap.minuseruid);
    log_debug(DEBUG_INFO, _MOD_VERSION ": SQLMinUserGID      : %u",
	      cmap.minusergid);
  }
   
  if (SQL_GROUPS) {
    log_debug(DEBUG_INFO, _MOD_VERSION ": SQLDefaultUID      : %u",
	      cmap.defaultuid);
    log_debug(DEBUG_INFO, _MOD_VERSION ": SQLDefaultGID      : %u",
	      cmap.defaultgid);
  }

  if (cmap.sql_fstor) {
    log_debug(DEBUG_INFO, _MOD_VERSION ": sql_fstor          : %s",
	      cmap.sql_fstor);
    log_debug(DEBUG_INFO, _MOD_VERSION ": sql_fretr          : %s",
	      cmap.sql_fretr);
    log_debug(DEBUG_INFO, _MOD_VERSION ": sql_bstor          : %s",
	      cmap.sql_bstor);
    log_debug(DEBUG_INFO, _MOD_VERSION ": sql_bretr          : %s",
	      cmap.sql_bretr);
  }

  if (cmap.sql_frate) {
    log_debug(DEBUG_INFO, _MOD_VERSION ": sql_frate          : %s",
	      cmap.sql_frate);
    log_debug(DEBUG_INFO, _MOD_VERSION ": sql_fcred          : %s",
	      cmap.sql_fcred);
    log_debug(DEBUG_INFO, _MOD_VERSION ": sql_brate          : %s",
	      cmap.sql_brate);
    log_debug(DEBUG_INFO, _MOD_VERSION ": sql_bcred          : %s",
	      cmap.sql_bcred);
  }

  log_debug(DEBUG_FUNC, _MOD_VERSION ": <<< sql_getconf");

  /* get rid of the temp pool */
  destroy_pool( tmp_pool );

  return 0;
}

/*****************************************************************
 *
 * HANDLER TABLES
 *
 *****************************************************************/

static conftable sql_conftab[] = {
  {"SQLAuthenticate", set_sqlauthenticate, NULL},

  {"SQLConnectInfo", set_sqlconnectinfo, NULL},
  {"SQLAuthTypes", set_sqlauthtypes, NULL},

  {"SQLUserInfo", set_sqluserinfo, NULL},
  {"SQLUserWhereClause", set_sqluserwhereclause, NULL},

  {"SQLGroupInfo", set_sqlgroupinfo, NULL},
  {"SQLGroupWhereClause", set_sqlgroupwhereclause, NULL},

  {"SQLMinID", set_sqlminid, NULL},
  {"SQLMinUserUID", set_sqlminuseruid, NULL},
  {"SQLMinUserGID", set_sqlminusergid, NULL},
  {"SQLDefaultUID", set_sqldefaultuid, NULL},
  {"SQLDefaultGID", set_sqldefaultgid, NULL},

  {"SQLRatios", set_sqlratios, NULL},
  {"SQLRatioStats", set_sqlratiostats, NULL},

  {"SQLDefaultHomedir", set_sqldefaulthomedir, NULL},
  {"SQLHomedirOnDemand", set_sqlhomedirondemand, NULL},

  {"SQLLog", set_sqllog, NULL},
  {"SQLNamedQuery", set_sqlnamedquery, NULL},
  {"SQLShowInfo", set_sqlshowinfo, NULL},

  /* deprecated and not supported, but at least we warn about it */

  {"SQLProcessGrEnt", set_deprecated, NULL},
  {"SQLProcessPwEnt", set_deprecated, NULL},
  {"SQLAuthoritative", set_deprecated, NULL},
  {"SQLDoAuth", set_deprecated, NULL},
  {"SQLDoGroupAuth", set_deprecated, NULL},
  {"SQLGroupTable", set_deprecated, NULL},
  {"SQLUsernameField", set_deprecated, NULL},
  {"SQLUserTable", set_deprecated, NULL},
  {"SQLUidField", set_deprecated, NULL},
  {"SQLGidField", set_deprecated, NULL},
  {"SQLPasswordField", set_deprecated, NULL},
  {"SQLHomedirField", set_deprecated, NULL},
  {"SQLShellField", set_deprecated, NULL},
  {"SQLGroupnameField", set_deprecated, NULL},
  {"SQLGroupGIDField", set_deprecated, NULL},
  {"SQLGroupMembersField", set_deprecated, NULL},
  {"SQLLogHosts", set_deprecated, NULL},
  {"SQLLogHits", set_deprecated, NULL},
  {"SQLLogDirs", set_deprecated, NULL},
  {"SQLLogStats", set_deprecated, NULL},
  {"SQLLoginCountField", set_deprecated, NULL},
  {"SQLHomedir", set_deprecated, NULL},
  {"SQLWhereClause", set_deprecated, NULL},

  {NULL, NULL, NULL}
};

static cmdtable sql_cmdtab[] = {
  {PRE_CMD,      C_QUIT,       G_NONE, log_master,     FALSE, FALSE},
  {POST_CMD,     C_STOR,       G_NONE, post_cmd_stor,  FALSE, FALSE},
  {POST_CMD,     C_RETR,       G_NONE, post_cmd_retr,  FALSE, FALSE},
  {POST_CMD,     C_ANY,        G_NONE, info_master,    FALSE, FALSE},
  {POST_CMD_ERR, C_ANY,        G_NONE, errinfo_master, FALSE, FALSE},
  {LOG_CMD,      C_ANY,        G_NONE, log_master,     FALSE, FALSE},
  {LOG_CMD_ERR,  C_ANY,        G_NONE, err_master,     FALSE, FALSE},
  {CMD,          "sql_lookup", G_NONE, sql_lookup,     FALSE, FALSE},
  {CMD,          "sql_change", G_NONE, sql_change,     FALSE, FALSE}, 
  {0, NULL}
};

static authtable sql_authtab[] = {
  {0, "setpwent", cmd_setpwent},
  {0, "getpwent", cmd_getpwent},
  {0, "endpwent", cmd_endpwent},
  {0, "setgrent", cmd_setgrent},
  {0, "getgrent", cmd_getgrent},
  {0, "endgrent", cmd_endgrent},
  {0, "getpwnam", cmd_getpwnam},
  {0, "getpwuid", cmd_getpwuid},
  {0, "getgrnam", cmd_getgrnam},
  {0, "getgrgid", cmd_getgrgid},
  {0, "auth", cmd_auth},
  {0, "check", cmd_check},
  {0, "uid_name", cmd_uid_name},
  {0, "gid_name", cmd_gid_name},
  {0, "name_uid", cmd_name_uid},
  {0, "name_gid", cmd_name_gid},
  {0, "getstats", cmd_getstats},
  {0, "getratio", cmd_getratio},
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
