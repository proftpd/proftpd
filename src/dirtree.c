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

/* Read configuration file(s), and manage server/configuration structures.
 * $Id: dirtree.c,v 1.120 2003-10-10 05:37:08 castaglia Exp $
 */

#include "conf.h"

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

#ifdef HAVE_REGEX_H
# include <regex.h>
#endif

xaset_t *server_list = NULL;
server_rec *main_server = NULL;
int tcpBackLog = PR_TUNABLE_DEFAULT_BACKLOG;
int SocketBindTight = FALSE;
char ServerType = SERVER_STANDALONE;
int ServerMaxInstances = 0;
int ServerUseReverseDNS = TRUE;
int TimeoutIdle = PR_TUNABLE_TIMEOUTIDLE;
int TimeoutNoXfer = PR_TUNABLE_TIMEOUTNOXFER;
int TimeoutStalled = PR_TUNABLE_TIMEOUTSTALLED;
char MultilineRFC2228 = 0;

/* from src/pool.c */
extern pool *global_config_pool;

/* Used by find_config_* */
xaset_t *find_config_top = NULL;

static void _mergedown(xaset_t *, int);

/* Used by get_param_int_next & get_param_ptr_next as "placeholders" */
static config_rec *_last_param_int = NULL;
static config_rec *_last_param_ptr = NULL;
static unsigned char _kludge_disable_umask = 0;

array_header *server_defines = NULL;

/* Used only while reading configuration files */

static struct {
  pool *tpool;
  array_header *sstack,*cstack;
  server_rec **curserver;
  config_rec **curconfig;
} conf;

typedef struct conf_stack_struc {
  struct conf_stack_struc *cs_next;
  pool *cs_pool;
  pr_fh_t *cs_file;
  unsigned int cs_lineno;
} conf_stack_t;

static conf_stack_t *config_stack = NULL;

static int allow_dyn_config(void) {
  config_rec *c = NULL;
  unsigned int ctxt_precedence = 0;
  unsigned char have_user_limit, have_group_limit, have_class_limit,
    have_all_limit;
  unsigned char allow = TRUE;

  have_user_limit = have_group_limit = have_class_limit =
    have_all_limit = FALSE;

  c = find_config(CURRENT_CONF, CONF_PARAM, "AllowOverride", FALSE);

  while (c) {
    if (c->argc == 3) {
      if (!strcmp(c->argv[2], "user")) {

        if (pr_user_or_expression((char **) &c->argv[3])) {
          if (*((unsigned int *) c->argv[1]) > ctxt_precedence) {

            /* Set the context precedence. */
            ctxt_precedence = *((unsigned int *) c->argv[1]);

            allow = *((int *) c->argv[0]);

            have_group_limit = have_class_limit = have_all_limit = FALSE;
            have_user_limit = TRUE;
          }
        }

      } else if (!strcmp(c->argv[2], "group")) {

        if (pr_group_and_expression((char **) &c->argv[3])) {
          if (*((unsigned int *) c->argv[1]) > ctxt_precedence) {

            /* Set the context precedence. */
            ctxt_precedence = *((unsigned int *) c->argv[1]);

            allow = *((int *) c->argv[0]);

            have_user_limit = have_class_limit = have_all_limit = FALSE;
            have_group_limit = TRUE;
          }
        }

      } else if (!strcmp(c->argv[2], "class")) {

        if (pr_class_or_expression((char **) &c->argv[3])) {
          if (*((unsigned int *) c->argv[1]) > ctxt_precedence) {

            /* Set the context precedence. */
            ctxt_precedence = *((unsigned int *) c->argv[1]);

            allow = *((int *) c->argv[0]);

            have_user_limit = have_group_limit = have_all_limit = FALSE;
            have_class_limit = TRUE;
          }
        }
      }

    } else {

      if (*((unsigned int *) c->argv[1]) > ctxt_precedence) {

        /* Set the context precedence. */
        ctxt_precedence = *((unsigned int *) c->argv[1]);

        allow = *((int *) c->argv[0]);

        have_user_limit = have_group_limit = have_class_limit = FALSE;
        have_all_limit = TRUE;
      }
    }

    c = find_config_next(c, c->next, CONF_PARAM, "AllowOverride", FALSE);
  }

  /* Print out some nice debugging information. */
  if (have_user_limit || have_group_limit ||
      have_class_limit || have_all_limit) {
    log_debug(DEBUG4, "AllowOverride %s %s%s .ftpaccess files",
      allow ? "allows" : "denies",
      have_user_limit ? "user " : have_group_limit ? "group " :
      have_class_limit ? "class " : "all",
      have_user_limit ? session.user : have_group_limit ? session.group :
      have_class_limit ? session.class->name : "");
  }

  return allow;
}

/* Imported this function from modules/mod_ls.c -- it belongs more with the
 * dir_* functions here, rather than the ls_* functions there.
 */

/* Return true if dir is ".", "./", "../", or "..". */
int is_dotdir(const char *dir) {
  if (strcmp(dir, ".") == 0 || strcmp(dir, "./") == 0 ||
      strcmp(dir, "..") == 0 || strcmp(dir, "../") == 0)
    return TRUE;

  return FALSE;
}

/* Lookup the best configuration set from which to retrieve configuration
 * values if the config_rec can appear in <Directory>.  This function
 * works around the issue caused by using the cached directory pointer
 * in session.dir_config.
 *
 * The issue with using session.dir_config is that it is assigned when
 * the client changes directories or doing other directory lookups, and so
 * dir_config may actually point to the configuration for a directory other
 * than the target directory for an uploaded, for example.  Unfortunately,
 * it is more expensive to lookup the configuration for the target directory
 * every time.  Perhaps some caching of looked up directory configurations
 * into a table, rather than a single pointer like session.dir_config,
 * might help.
 */
xaset_t *get_dir_ctxt(pool *p, char *dir_path) {
  config_rec *c = NULL;
  char *full_path = dir_path;

  if (session.chroot_path) {
    if (*dir_path != '/')
      full_path = pdircat(p, session.chroot_path, session.cwd, dir_path, NULL);

    else
      full_path = pdircat(p, session.chroot_path, dir_path, NULL);

  } else if (*dir_path != '/')
    full_path = pdircat(p, session.cwd, dir_path, NULL);

  c = dir_match_path(p, full_path);

  return c ? c->subset : session.anon_config ? session.anon_config->subset :
    main_server->conf;
}

/* Substitute any appearance of the %u variable in the given string with
 * the value.
 */
char *path_subst_uservar(pool *path_pool, char **path) {
  char *new_path = NULL, *substr = NULL, *substr_path = NULL;

  /* Sanity check. */
  if (!path_pool || !path || !*path) {
    errno = EINVAL;
    return NULL;
  }

  /* If no %u string present, do nothing. */
  if (!strstr(*path, "%u"))
    return *path;

  /* First, deal with occurrences of "%u[index]" strings.  Note that
   * with this syntax, the '[' and ']' characters become invalid in paths,
   * but only if that '[' appears after a "%u" string -- certainly not
   * a common phenomenon (I hope).  This means that in the future, an escape
   * mechanism may be needed in this function.  Caveat emptor.
   */

  substr_path = *path;

  while ((substr = strstr(substr_path, "%u[")) != NULL) {
    int i = 0;
    char *substr_end = NULL, *substr_dup = NULL, *endp = NULL;
    char ref_char[2] = {'\0', '\0'};

    /* Now, find the closing ']'. If not found, it is a syntax error;
     * continue on without processing this occurrence.
     */
    if ((substr_end = strchr(substr, ']')) == NULL)

      /* Just end here. */
      break;

    /* Make a copy of the entire substring. */
    substr_dup = pstrdup(path_pool, substr);

    /* The substr_end variable (used as an index) should work here, too
     * (trying to obtain the entire substring).
     */
    substr_dup[substr_end - substr + 1] = '\0';

    /* Advance the substring pointer by three characters, so that it is
     * pointing at the character after the '['.
     */
    substr += 3;

    /* If the closing ']' is the next character after the opening '[', it
     * is a syntax error.
     */
    if (substr_end == substr) {

      /* Do not forget to advance the substring search path pointer. */
      substr_path = substr;

      continue;
    }

    /* Temporarily set the ']' to '\0', to make it easy for the string
     * scanning below.
     */
    *substr_end = '\0';

    /* Scan the index string into a number, watching for bad strings. */
    i = strtol(substr, &endp, 10);

    if (endp && *endp) {
      substr_path = substr;
      continue;
    }

    /* Make sure that index is within bounds. */
    if (i < 0 || i > strlen(session.user) - 1) {

      /* Put the closing ']' back. */
      *substr_end = ']';

      /* Syntax error. Advance the substring search path pointer, and move
       * on.
       */
      substr_path = substr;

      continue;
    }

    ref_char[0] = session.user[i];

    /* Put the closing ']' back. */
    *substr_end = ']';

    /* Now, to substitute the whole "%u[index]" substring with the
     * referenced character/string.
     */
    substr_path = sreplace(path_pool, substr_path, substr_dup, ref_char, NULL);
  }

  /* Check for any bare "%u", and handle those if present. */
  if (strstr(substr_path, "%u"))
    new_path = sreplace(path_pool, substr_path, "%u", session.user, NULL);
  else
    new_path = substr_path;

  return new_path;
}

/* Check for configured HideFiles directives, and check the given filename
 * (not _path_, just filename) against those regexes if configured. Returns
 * FALSE if filename should be shown/listed, TRUE if it should not
 * be visible.
 */
unsigned char dir_hide_file(const char *path) {
#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  char *file_name = NULL, *dir_name = NULL;
  config_rec *c = NULL;
  regex_t *regexp = NULL;
  pool *tmp_pool = make_sub_pool(session.pool);
  unsigned int ctxt_precedence = 0;
  unsigned char have_user_regex, have_group_regex, have_class_regex,
    have_all_regex, inverted = FALSE;

  have_user_regex = have_group_regex = have_class_regex = have_all_regex =
    FALSE;

  /* Separate the given path into directory and file components. */
  dir_name = pstrdup(tmp_pool, path);

  if ((file_name = strrchr(dir_name, '/')) != NULL) {
    file_name = '\0';
    file_name++;

  } else
    file_name = dir_name;

  /* Check for any configured HideFiles */
  c = find_config(get_dir_ctxt(tmp_pool, dir_name), CONF_PARAM, "HideFiles",
    FALSE);

  while (c) {
    if (c->argc >= 4) {

      /* check for a specified "user" classifier first... */
      if (strcmp(c->argv[3], "user") == 0) {
        if (pr_user_or_expression((char **) &c->argv[4])) {

          if (*((unsigned int *) c->argv[2]) > ctxt_precedence) {
            ctxt_precedence = *((unsigned int *) c->argv[2]);

            regexp = *((regex_t **) c->argv[0]);
            inverted = *((unsigned char *) c->argv[1]);

            have_group_regex = have_class_regex = have_all_regex = FALSE;
            have_user_regex = TRUE;
          }
        }

      /* ...then for a "group" classifier... */
      } else if (strcmp(c->argv[3], "group") == 0) {
        if (pr_group_and_expression((char **) &c->argv[4])) {
          if (*((unsigned int *) c->argv[2]) > ctxt_precedence) {
            ctxt_precedence = *((unsigned int *) c->argv[2]);

            regexp = *((regex_t **) c->argv[0]);
            inverted = *((unsigned char *) c->argv[1]);

            have_user_regex = have_class_regex = have_all_regex = FALSE;
            have_group_regex = TRUE;
          }
        }

      /* ...finally, for a "class" classifier.  NOTE: mod_time's
       * class_expression functionality should really be added into the
       * core code at some point.  When that happens, then this code will
       * need to be updated to process class-expressions.
       */
      } else if (strcmp(c->argv[3], "class") == 0) {
        if (pr_class_or_expression((char **) &c->argv[4])) {
          if (*((unsigned int *) c->argv[2]) > ctxt_precedence) {
            ctxt_precedence = *((unsigned int *) c->argv[2]);

            regexp = *((regex_t **) c->argv[0]);
            inverted = *((unsigned char *) c->argv[1]);

            have_user_regex = have_group_regex = have_all_regex = FALSE;
            have_class_regex = TRUE;
          }
        }
      }

    } else if (c->argc == 1) {

      /* This is the "none" HideFiles parameter. */
      destroy_pool(tmp_pool);
      return FALSE;

    } else {
      if (*((unsigned int *) c->argv[2]) > ctxt_precedence) {
        ctxt_precedence = *((unsigned int *) c->argv[2]);

        regexp = *((regex_t **) c->argv[0]);
        inverted = *((unsigned char *) c->argv[1]);

        have_user_regex = have_group_regex = have_class_regex = FALSE;
        have_all_regex = TRUE;
      }
    }

    c = find_config_next(c, c->next, CONF_PARAM, "HideFiles", FALSE);
  }


  if (have_user_regex || have_group_regex ||
      have_class_regex || have_all_regex) {

    log_debug(DEBUG4, "checking HideFiles pattern for current %s",
      have_user_regex ? "user" : have_group_regex ? "group" :
      have_class_regex ? "class" : "session");

    if (regexec(regexp, file_name, 0, NULL, 0) != 0) {
      destroy_pool(tmp_pool);

      /* The file failed to match the HideFiles regex, which means it should
       * be treated as a "visible" file.  If the regex was 'inverted', though,
       * switch the result.
       */
      return (inverted ? TRUE : FALSE);

    } else {
      destroy_pool(tmp_pool);

      /* The file matched the HideFiles regex, which means it should be
       * considered a "hidden" file.  If the regex was 'inverted', though,
       * switch the result.
       */
      return (inverted ? FALSE : TRUE);
    }
    destroy_pool(tmp_pool);
  }
#endif /* !HAVE_REGEX_H and !HAVE_REGCOMP */

  /* Return FALSE by default. */
  return FALSE;	
}

unsigned char define_exists(const char *definition) {

  /* Check the list of specified definitions, if present.
   */
  if (server_defines) {
    char **defines = server_defines->elts;
    register unsigned int i = 0;

    for (i = 0; i < server_defines->nelts; i++) {
      if (defines[i] && !strcmp(defines[i], definition))
        return TRUE;
    }
  }

  /* default */
  return FALSE;
}

void kludge_disable_umask(void) {
  _kludge_disable_umask = TRUE;
}

void kludge_enable_umask(void) {
  _kludge_disable_umask = FALSE;
}

char *get_word(char **cp, unsigned char ignore_comments) {
  char *ret,*dst;
  char quote_mode = 0;

  if (!cp || !*cp || !**cp)
    return NULL;

  while (**cp && isspace((int) **cp)) (*cp)++;

  if (!**cp)
    return NULL;

  ret = dst = *cp;

  /* Stop processing at start of an inline comment. */
  if (!ignore_comments && **cp == '#')
    return NULL;

  if (**cp == '\"') {
    quote_mode++;
    (*cp)++;
  }

  while (**cp && (quote_mode ? (**cp != '\"') : !isspace((int) **cp))) {
    if (**cp == '\\' && quote_mode) {
      /* escaped char */
      if (*((*cp)+1))
        *dst = *(++(*cp));
    }

    *dst++ = **cp;
    ++(*cp);
  }

  if (**cp) (*cp)++;
  *dst = '\0';

  return ret;
}

cmd_rec *pr_cmd_alloc(pool *p, int argc, ...) {
  pool *newpool = NULL;
  cmd_rec *c = NULL;
  va_list args;

  newpool = make_sub_pool(p);
  c = pcalloc(newpool, sizeof(cmd_rec));
  c->argc = argc;
  c->stash_index = -1;
  c->pool = newpool;
  c->tmp_pool = make_sub_pool(c->pool);

  if (argc) {
    register unsigned int i = 0;

    c->argv = pcalloc(newpool, sizeof(void *) * (argc));
    va_start(args, argc);

    for (i = 0; i < argc; i++)
      c->argv[i] = (void *) va_arg(args, char *);

    va_end(args);
  }

  return c;
}

static conf_stack_t *push_config_stack(pr_fh_t *fh, unsigned int lineno) {
  pool *tmp_pool = make_sub_pool(permanent_pool);
  conf_stack_t *cs = pcalloc(tmp_pool, sizeof(conf_stack_t));

  cs->cs_next = NULL;
  cs->cs_pool = tmp_pool;
  cs->cs_file = fh;
  cs->cs_lineno = lineno;

  if (!config_stack)
    config_stack = cs;

  else {
    cs->cs_next = config_stack;
    config_stack = cs;
  }

  return cs;
}

static void pop_config_stack(void) {
  conf_stack_t *cs = config_stack;
  config_stack = cs->cs_next;

  destroy_pool(cs->cs_pool);
}

/* This functions returns the next line from the configuration stream,
 * skipping commented-out lines and trimming trailing and leading whitespace,
 * returning, in effect, the next line of configuration data on which to
 * act.  At present, the configuration stream is indicated by the static
 * conf_stack pr_fh_t pointer -- in the future, this might change to a
 * more generic and flexible configuration stream data type (eg confstream_t).
 * This function has the advantage that it can be called by functions that
 * don't have access to that FILE pointer, such as the <IfDefine> and <IfModule>
 * configuration handlers.  In the future, the requirement will be that
 * functions wishing to access the configuration stream _must_ call
 * set_config_stack() prior to calling all configuration stream functions
 * (of which this is one of but several potential such functions).
 */
char *get_config_line(char *buf, size_t len) {

  /* Always use the config stream at the top of the stack. */
  conf_stack_t *cs = config_stack;

  if (!cs->cs_file)
    return NULL;

  /* Check for error conditions. */
  while ((pr_fsio_getline(buf, len, cs->cs_file, &(cs->cs_lineno))) != NULL) {
    char *bufp = NULL;
    size_t buflen = strlen(buf);

    /* Trim off the trailing newline, if present. */
    if (buflen && buf[buflen - 1] == '\n')
      buf[buflen - 1] = '\0';

    /* Trim off any leading whitespace. */
    for (bufp = buf; *bufp && isspace((int) *bufp); bufp++);

    /* Check for commented or blank lines at this point, and just continue on
     * to the next configuration line if found.  If not, return the
     * configuration line.
     */
    if (*bufp == '#' || !*bufp) {
      continue;

    } else {

      /* Copy the value of bufp back into the pointer passed in
       * and return it.
       */
      buf = bufp;

      return buf;
    }
  }

  return NULL;
}

static cmd_rec *get_config_cmd(pool *ppool) {
  char buf[PR_TUNABLE_BUFFER_SIZE] = {'\0'}, *word = NULL;
  cmd_rec *new_cmd = NULL;
  pool *new_pool = NULL;
  array_header *tarr = NULL;

  while (get_config_line(buf, sizeof(buf)-1) != NULL) {
    char *bufp = buf;

    /* Build a new pool for the command structure and array */
    new_pool = make_sub_pool(ppool);
    new_cmd = (cmd_rec *) pcalloc(new_pool, sizeof(cmd_rec));
    new_cmd->pool = new_pool;
    tarr = make_array(new_pool,4,sizeof(char**));

    /* Add each word to the array */
    while ((word = get_word(&bufp, FALSE)) != NULL) {
      char *tmp = pstrdup(new_pool, word);

      *((char **)push_array(tarr)) = tmp; /* pstrdup(new_pool,word); */
      new_cmd->argc++;
    }

    *((char **)push_array(tarr)) = NULL;

    /* The array header's job is done, we can forget about it and
     * it will get purged when the command's pool is cleared
     */

    new_cmd->argv = (char **)tarr->elts;

    /* Perform a fixup on configuration directives so that:
     * -argv[0]--  -argv[1]-- ----argv[2]-----
     * <Option     /etc/adir  /etc/anotherdir>
     *   .. becomes ..
     * -argv[0]--  -argv[1]-  ----argv[2]----
     * <Option>    /etc/adir  /etc/anotherdir
     */

    if (new_cmd->argc && *(new_cmd->argv[0]) == '<') {
      char *cp = new_cmd->argv[new_cmd->argc-1];

      if (*(cp + strlen(cp)-1) == '>' && new_cmd->argc > 1) {
        if (!strcmp(cp, ">")) {
          new_cmd->argv[new_cmd->argc-1] = NULL;
          new_cmd->argc--;
        } else
          *(cp + strlen(cp)-1) = '\0';

        cp = new_cmd->argv[0];
        if (*(cp + strlen(cp)-1) != '>')
          new_cmd->argv[0] = pstrcat(new_cmd->pool,cp, ">",NULL);
      }
    }

    return new_cmd;
  }

  return NULL;
}

static void init_dyn_stacks(pool *p, config_rec *top) {
  conf.sstack = make_array(p,1,sizeof(server_rec*));
  conf.curserver = (server_rec**)push_array(conf.sstack);
  *conf.curserver = main_server;
  conf.cstack = make_array(p,3,sizeof(config_rec*));
  conf.curconfig = (config_rec**)push_array(conf.cstack);
  *conf.curconfig = NULL;
  conf.curconfig = (config_rec**)push_array(conf.cstack);
  *conf.curconfig = top;
}

static void free_dyn_stacks(void) {
  memset(&conf, '\0', sizeof(conf));
}

void init_conf_stacks(void) {
  pool *conf_pool = make_sub_pool(permanent_pool);

  conf.tpool = conf_pool;
  conf.sstack = make_array(conf_pool, 1, sizeof(server_rec *));
  conf.curserver = (server_rec **) push_array(conf.sstack);
  *conf.curserver = main_server;
  conf.cstack = make_array(conf_pool, 10, sizeof(config_rec *));
  conf.curconfig = (config_rec **) push_array(conf.cstack);
  *conf.curconfig = NULL;
}

void free_conf_stacks(void) {
  destroy_pool(conf.tpool);
  memset(&conf, '\0', sizeof(conf));
}

/* Used by modules to start/end configuration sections */

server_rec *start_new_server(const char *addrstr) {
  server_rec *s;
  pool *p;

  p = make_sub_pool(permanent_pool);

  s = (server_rec *) pcalloc(p, sizeof(server_rec));
  s->pool = p;
  s->config_type = CONF_VIRTUAL;

  /* Have to make sure it ends up on the end of the chain, otherwise
   * main_server becomes useless.
   */
  xaset_insert_end(server_list, (xasetmember_t *) s);
  s->set = server_list;
  if (addrstr)
    s->ServerAddress = pstrdup(s->pool, addrstr);

  /* Default server port */
  s->ServerPort = pr_inet_getservport(s->pool, "ftp", "tcp");

  conf.curserver = (server_rec **) push_array(conf.sstack);
  *conf.curserver = s;

  return s;
}

server_rec *end_new_server(void) {
  if (!*conf.curserver)
    return NULL;

  if (conf.curserver == (server_rec**)conf.sstack->elts)
    return NULL; /* Disallow underflows */

  conf.curserver--;
  conf.sstack->nelts--;

  return *conf.curserver;
}

/* Starts a sub-configuration */

config_rec *start_sub_config(const char *name) {
  config_rec *c = NULL, *parent = *conf.curconfig;
  pool *c_pool = NULL, *parent_pool = NULL;
  xaset_t **set = NULL;

  if (parent) {
    parent_pool = parent->pool;
    set = &parent->subset;

  } else {
    parent_pool = (*conf.curserver)->pool;
    set = &(*conf.curserver)->conf;
  }

  /* Allocate a sub-pool for this config_rec.  Note: special exception for
   * <Global> configs -- the parent pool is global_config_pool (a pool just for
   * this context), not the pool of the parent server.  This keeps <Global>
   * config recs from being freed prematurely, and helps to avoid memory leaks.
   */
  if (strcmp(name, "<Global>") == 0) {
    if (!global_config_pool)
      global_config_pool = make_sub_pool(permanent_pool);
    parent_pool = global_config_pool;
  }

  c_pool = make_sub_pool(parent_pool);
  c = (config_rec *) pcalloc(c_pool, sizeof(config_rec));

  if (!*set)
    *set = xaset_create(parent_pool, NULL);

  xaset_insert(*set, (xasetmember_t*)c);

  c->pool = c_pool;
  c->set = *set;
  c->parent = parent;

  if (name)
    c->name = pstrdup(c->pool, name);

  if (parent && (parent->config_type == CONF_DYNDIR))
    c->flags |= CF_DYNAMIC;

  /* Now insert another level onto the stack */
  if (!*conf.curconfig)
    *conf.curconfig = c;

  else {
    conf.curconfig = (config_rec**)push_array(conf.cstack);
    *conf.curconfig = c;
  }

  return c;
}

/* Pop one level off the stack */
config_rec *end_sub_config(unsigned char *empty) {
  config_rec *c = *conf.curconfig;

  /* Note that if the current config is empty, it should simply be removed.
   * Such empty configs can happen for <Directory> sections that
   * contain no directives, for example.
   */

  if (conf.curconfig == (config_rec **) conf.cstack->elts) {
    if (!c->subset || !c->subset->xas_list) {
      xaset_remove(c->set, (xasetmember_t *) c);
      destroy_pool(c->pool);

      if (empty)
        *empty = TRUE;
    }

    if (*conf.curconfig)
      *conf.curconfig = NULL;
    return NULL;
  }

  if (!c->subset || !c->subset->xas_list) {
    xaset_remove(c->set, (xasetmember_t *) c);
    destroy_pool(c->pool);

    if (empty)
      *empty = TRUE;
  }

  conf.curconfig--;
  conf.cstack->nelts--;

  return *conf.curconfig;
}

/* Adds a config_rec to the specified set */
config_rec *add_config_set(xaset_t **set, const char *name) {
  pool *conf_pool = NULL, *set_pool = NULL;
  config_rec *c, *parent = NULL;

  if (!*set) {

    /* Allocate a subpool from permanent_pool for the set. */
    set_pool = make_sub_pool(permanent_pool);
    *set = xaset_create(set_pool,NULL);
    (*set)->mempool = set_pool;

    /* Now, make a subpool for the config_rec to be allocated. */
    conf_pool = make_sub_pool(set_pool);

  } else {

    /* Find the parent set for the config_rec to be allocated. */
    if ((*set)->xas_list)
      parent = ((config_rec*)((*set)->xas_list))->parent;

    /* Allocate a subpool for the config_rec from the parent's pool. */
    conf_pool = make_sub_pool((*set)->mempool);
  }

  c = (config_rec *) pcalloc(conf_pool, sizeof(config_rec));

  c->pool = conf_pool;
  c->set = *set;
  c->parent = parent;
  if (name)
    c->name = pstrdup(conf_pool, name);
  xaset_insert_end(*set, (xasetmember_t*)c);

  return c;
}

/* Adds a config_rec on the current "level" */
config_rec *add_config(const char *name) {
  server_rec *s = *conf.curserver;
  config_rec *parent = NULL, *c = *conf.curconfig;
  pool *p = NULL;
  xaset_t **set = NULL;

  if (c) {
    parent = c;
    p = c->pool;
    set = &c->subset;

  } else {
    parent = NULL;

    if (!s->conf || !s->conf->xas_list)
      p = make_sub_pool(s->pool);
    else
      p = ((config_rec*)s->conf->xas_list)->pool;

    set = &s->conf;
  }

  if (!*set)
    *set = xaset_create(p, NULL);

  c = add_config_set(set, name);
  c->parent = parent;

  return c;
}

array_header *pr_parse_expression(pool *p, int *argc, char **argv) {
  array_header *acl = NULL;
  int cnt = *argc;
  char *s, *ent;

  if (cnt) {
    acl = make_array(p, cnt, sizeof(char *));

    while (cnt-- && *(++argv)) {
      s = pstrdup(p, *argv);

      while ((ent = get_token(&s, ",")) != NULL)
        if (*ent)
          *((char **) push_array(acl)) = ent;
    }

    *argc = acl->nelts;

  } else
    *argc = 0;

  return acl;
}

/* Boolean "class-expression" AND matching, returns TRUE if the expression
 * evaluates to TRUE.
 */
unsigned char pr_class_and_expression(char **expr) {
  unsigned char found;
  char *class;

  if (!session.class)
    return FALSE;

  for (; *expr; expr++) {
    class = *expr;
    found = FALSE;

    if (*class == '!') {
      found = !found;
      class++;
    }

    if (strcmp(session.class->name, class) == 0)
      found = !found;

    if (!found)
      return FALSE;
  }

  return TRUE;
}

/* Boolean "class-expression" OR matching, returns TRUE if the expression
 * evaluates to TRUE.
 */
unsigned char pr_class_or_expression(char **expr) {
  unsigned char found;
  char *class;

  if (!session.class)
    return FALSE;

  for (; *expr; expr++) {
    class = *expr;
    found = FALSE;

    if (*class == '!') {
      found = !found;
      class++;
    }

    if (strcmp(session.class->name, class) == 0)
      found = !found;

    if (found)
      return TRUE;
  }

  return FALSE;
}

/* Boolean "group-expression" AND matching, returns TRUE if the expression
 * evaluates to TRUE.
 */
unsigned char pr_group_and_expression(char **expr) {
  unsigned char found;
  char *grp;

  for (; *expr; expr++) {
    grp = *expr;
    found = FALSE;

    if (*grp == '!') {
      found = !found;
      grp++;
    }

    if (session.group && strcmp(session.group, grp) == 0)
      found = !found;

    else if (session.groups) {
      register int i = 0;

      for (i = session.groups->nelts-1; i >= 0; i--)
        if (strcmp(*(((char **) session.groups->elts) + i), grp) == 0) {
          found = !found;
          break;
        }
    }

    if (!found)
      return FALSE;
  }

  return TRUE;
}

/* Boolean "group-expression" OR matching, returns TRUE if the expression
 * evaluates to TRUE.
 */
unsigned char pr_group_or_expression(char **expr) {
  unsigned char found;
  char *grp;

  for (; *expr; expr++) {
    grp = *expr;
    found = FALSE;

    if (*grp == '!') {
      found = !found;
      grp++;
    }

    if (session.group && strcmp(session.group, grp) == 0)
      found = !found;

    else if (session.groups) {
      register int i = 0;

      for (i = session.groups->nelts-1; i >= 0; i--)
        if (strcmp(*(((char **) session.groups->elts) + i), grp) == 0) {
          found = !found;
          break;
        }
    }

    if (found)
      return TRUE;
  }

  return FALSE;
}

/* Boolean "user-expression" AND matching, returns TRUE if the expression
 * evaluates to TRUE.
 */
unsigned char pr_user_and_expression(char **expr) {
  unsigned char found;
  char *user;

  for (; *expr; expr++) {
    user = *expr;
    found = FALSE;

    if (*user == '!') {
      found = !found;
      user++;
    }

    if (strcmp(session.user, user) == 0)
      found = !found;

    if (!found) 
      return FALSE;
  }

  return TRUE;
}

/* Boolean "user-expression" OR matching, returns TRUE if the expression
 * evaluates to TRUE.
 */
unsigned char pr_user_or_expression(char **expr) {
  unsigned char found;
  char *user;

  for (; *expr; expr++) {
    user = *expr;
    found = FALSE;

    if (*user == '!') {
      found = !found;
      user++;
    }

    if (strcmp(session.user, user) == 0)
      found = !found;

    if (found)
      return TRUE;
  }

  return FALSE;
}
/* Per-directory configuration */

static int _strmatch(register char *s1, register char *s2) {
  register int len = 0;

  while (*s1 && *s2 && *s1++ == *s2++)
    len++;

  return len;
}

static config_rec *recur_match_path(pool *p, xaset_t *s, char *path) {
  char *tmp_path = NULL;
  config_rec *c = NULL, *res = NULL;

  if (!s)
    return NULL;

  for (c = (config_rec *) s->xas_list; c; c = c->next)
    if (c->config_type == CONF_DIR) {
      tmp_path = c->name;

      if (c->argv[1]) {
        if (*(char *)(c->argv[1]) == '~')
          c->argv[1] = dir_canonical_path(c->pool, (char *) c->argv[1]);

        tmp_path = pdircat(p, (char *) c->argv[1], tmp_path, NULL);
      }

      /* Exact path match */
      if (strcmp(tmp_path, path) == 0)
        return c;

      if (!strstr(tmp_path, "/*")) {
        size_t tmplen = strlen(tmp_path);

        /* Trim a trailing path separator, if present. */
        if (*tmp_path && *(tmp_path + tmplen - 1) == '/' && tmplen > 1) {
          *(tmp_path + tmplen - 1) = '\0';

          if (strcmp(tmp_path, path) == 0)
            return c;
        }

        tmp_path = pdircat(p, tmp_path, "*", NULL);
      }

      /* Temporary measure until we figure what's going on with
       * gnu fnmatch
       *
       * Hmm...wonder what this is, and if it's still an issue.  I love
       * cryptic comments in other people's code. :)
       *
       * - MacGyver
       */

#if 0
      if (pr_fnmatch(tmp_path, path, PR_FNM_PATHNAME) == 0) {
#else
      if (pr_fnmatch(tmp_path, path, 0) == 0) {
#endif
        if (c->subset) {
          if ((res = recur_match_path(p, c->subset, path)))
            return res;
        }

        return c;
      }
    }

  return NULL;
}

config_rec *dir_match_path(pool *p, char *path) {
  config_rec *res = NULL;
  char *tmp = NULL;
  size_t tmplen;

  if (!p || !path || !*path)
    return NULL;

  tmp = pstrdup(p, path);
  tmplen = strlen(tmp);

  if (*(tmp + tmplen - 1) == '*') {
    *(tmp + tmplen - 1) = '\0';
    tmplen = strlen(tmp);
  }

  if (*(tmp + tmplen - 1) == '/' && tmplen > 1)
    *(tmp + tmplen - 1) = '\0';

  if (session.anon_config) {
    res = recur_match_path(p, session.anon_config->subset, tmp);

    if (!res) {
      if (session.chroot_path &&
          !strncmp(session.chroot_path, tmp, strlen(session.chroot_path)))
        return NULL;
    }
  }

  if (!res)
    res = recur_match_path(p, main_server->conf, tmp);

  return res;
}

static int _dir_check_op(pool *p, xaset_t *c, int op, uid_t uid, gid_t gid,
    mode_t mode) {
  int res = 1, user_perms = 0;
  uid_t *u = NULL;
  gid_t *g = NULL, *gidp = NULL;
  unsigned char *hide_no_access = NULL;

  if (!c)
    return 1;				/* Default is to allow */

  /* Attempt to match the UID and GID of the file against that of the
   * current user and groups.
   */
  if (uid == session.uid) {

    /* The UID of the file is that of the current user. */
    user_perms |= (mode & S_IRWXU);

  } else if (gid == session.gid) {

    /* The primary GID of the file is that of the current user. */
    user_perms |= (mode & S_IRWXG);

  } else {
    unsigned char found_gid_match = FALSE;

    if (session.gids) {
      register unsigned int i = 0;

      /* Loop through the user's auxiliary groups, checking if these
       * memberships match that of the file
       */
      for (i = session.gids->nelts, gidp = (gid_t *) session.gids->elts;
         i; i--, gidp++) {

        /* Matched an auxiliary GID against the file GID. */
        if (*gidp == gid) {
          found_gid_match = TRUE;
          user_perms |= (mode & S_IRWXG);
          break;
        }
      }
    }

    /* No matching GIDs.  Assume the current user can read, as other,
     * by default.
     */
    if (!found_gid_match)
      user_perms |= (mode & S_IRWXO);
  }

  switch (op) {
  case OP_HIDE:
    u = (uid_t *) get_param_ptr(c, "HideUser", FALSE);

    while (u && *u != (uid_t) -1 && (*u != uid || *u == session.uid))
      u = (uid_t *) get_param_ptr_next("HideUser", FALSE);

    if (u && *u == uid) {
      res = 0;
      break;
    }

    g = (gid_t *) get_param_ptr(c, "HideGroup", FALSE);

    while (g && *g != (gid_t) -1 && (*g != gid || *g == session.gid))
      g = (gid_t *) get_param_ptr_next("HideGroup", FALSE);

    if (g && *g == gid) {
      res = 0;
      break;
    }

    hide_no_access = get_param_ptr(c, "HideNoAccess", FALSE);

    if (hide_no_access && *hide_no_access == TRUE) {
      if (S_ISDIR(mode)) {

        /* check to see if the mode of this directory allows the
         * current user to list its contents
         */
        res = user_perms &= (S_IXUSR|S_IXGRP|S_IXOTH);

      } else {

        /* check to see if the mode of this file allows the current
         * user to read it.  The below expression is fairly compact,
         * but achieves its goal, which is:
         *
         * If the file is readable (by user, group, or other)
         *   return > 1 (the user_perms work for this)
         *
         * If the file is unreadable
         *   return 0 (which user_perms will be)
         */
        res = user_perms &= (S_IRUSR|S_IRGRP|S_IROTH);
      }
    }
    break;

  case OP_COMMAND:
    {
      unsigned char *allow_all = get_param_ptr(c, "AllowAll", FALSE),
        *deny_all = get_param_ptr(c, "DenyAll", FALSE);

      if (allow_all && *allow_all == TRUE)
        /* nop */;

      else if (deny_all && *deny_all == TRUE) {
        res = 0;
        errno = EACCES;
      }
    }
    break;

  }

  return res;
}

int dir_check_op_mode(pool *p, char *path, int op, uid_t uid, gid_t gid,
    mode_t mode) {
  char *fullpath;
  xaset_t *c;
  config_rec *sc;

  if (*path != '/')
    fullpath = pdircat(p, session.cwd, path, NULL);
  else
    fullpath = pstrdup(p, path);

  if (session.chroot_path)
    fullpath = pdircat(p, session.chroot_path, fullpath, NULL);

  c = CURRENT_CONF;
  sc = recur_match_path(p, c, fullpath);

  return _dir_check_op(p, sc ? sc->subset : c, op, uid, gid, mode);
}

static int _check_user_access(xaset_t *set, char *name) {
  int res = 0;
  config_rec *c = find_config(set, CONF_PARAM, name, FALSE);

  while (c) {
#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
    if (c->argc == 2 && c->argv[0] == NULL) {
      regex_t *preg = (regex_t *) c->argv[1];

      if (regexec(preg, session.user, 0, NULL, 0) == 0) {
        res = TRUE;
        break;
      }

    } else {
#endif /* HAVE_REGEX_H and HAVE_REGCOMP */
      res = pr_user_or_expression((char **) c->argv);

      if (res)
        break;

#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
    }
#endif /* HAVE_REGEX_H and HAVE_REGCOMP */

    c = find_config_next(c, c->next, CONF_PARAM, name, FALSE);
  }

  return res;
}

static int _check_group_access(xaset_t *set, char *name) {
  int res = 0;
  config_rec *c = find_config(set, CONF_PARAM, name, FALSE);

  while (c) {

#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
    if (c->argc == 2 && c->argv[0] == NULL) {
      regex_t *preg = (regex_t *) c->argv[1];
      
      if (session.group && regexec(preg, session.group, 0, NULL, 0) == 0) {
        res = TRUE;
        break;

      } else if (session.groups) {
        register int i = 0;

        for (i = session.groups->nelts-1; i >= 0; i--)
          if (regexec(preg, *(((char **) session.groups->elts) + i), 0,
              NULL, 0) == 0) {
            res = TRUE;
            break;
          }
      }
    
    } else {
#endif /* HAVE_REGEX_H and HAVE_REGCOMP */
      res = pr_group_and_expression((char **) c->argv);

      if (res)
        break;

#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
    }
#endif /* HAVE_REGEX_H and HAVE_REGCOMP */

    c = find_config_next(c, c->next, CONF_PARAM, name, FALSE);
  }

  return res;
}

/* returns 1 if explicit match
 * returns -1 if explicit mismatch (i.e. "NONE")
 * returns 0 if no match
 */

/* XXX much nasty ACL code, screaming to be reimplemented. */

int match_ip(pr_netaddr_t *cli_addr, const char *cli_str,
    const char *acl_match) {
  char acl_str[PR_TUNABLE_BUFFER_SIZE] = {'\0'};
  char *mask,*cp;
  int cidr_mode = 0, cidr_bits;
  struct in_addr cidr_addr;
  u_int_32 cidr_mask = 0;

  if (!strcasecmp(acl_match, "ALL"))
    return 1;

  if (!strcasecmp(acl_match, "NONE"))
    return -1;

  memset(acl_str, '\0', sizeof(acl_str));
  mask = acl_str;

  if (*acl_match == '.') {
    *mask++ = '*';
    *mask = '\0';
    sstrcat(acl_str, acl_match, sizeof(acl_str));

  } else if (*(acl_match + strlen(acl_match) - 1) == '.') {
    sstrcat(acl_str, acl_match, sizeof(acl_str));
    sstrcat(acl_str, "*", sizeof(acl_str));

  /* Check for CIDR notation. */
  } else if ((cp = strchr(acl_match, '/')) != NULL) {
    /* first portion of CIDR should be dotted quad, second portion
     * is netmask
     */
    sstrncpy(acl_str, acl_match, (cp-acl_match)+1 <= sizeof(acl_str) ?
                                 (cp-acl_match)+1 :  sizeof(acl_str));
    cidr_bits = atoi(cp+1);

    if (cidr_bits > 0 && cidr_bits < 33) {
      int shift = 32 - cidr_bits;

      cidr_mode = 1;
      while (cidr_bits--)
	cidr_mask = (cidr_mask << 1) | 1;
      cidr_mask = cidr_mask << shift;
#ifdef HAVE_INET_ATON
      if (inet_aton(mask, &cidr_addr) == 0)
	return 0;
#else
      cidr_addr.s_addr = inet_addr(mask);
#endif
      cidr_addr.s_addr &= htonl(cidr_mask);

    } else {
      return 0;
    }

  } else {
    sstrcat(acl_str, acl_match, sizeof(acl_str));
  }

  if (cidr_mode) {
/* NOTE: encapsulation breakage note/IPv6 change needed here. */
#if 0
    if ((cli_addr->s_addr & htonl(cidr_mask)) == cidr_addr.s_addr)
#endif
      return 1;

  } else {
    pr_netaddr_t *acl_addr = NULL;
    int fnm_flags = PR_FNM_NOESCAPE|PR_FNM_CASEFOLD;
    pool *tmp_pool = make_sub_pool(permanent_pool);
    const char *acl_ascii = NULL, *cli_ascii = NULL;

    if (strpbrk(acl_str, "[*?") == NULL)
      acl_addr = pr_netaddr_get_addr(tmp_pool, acl_str, NULL);

    /* As acl_str may contain the '*' globbing character, an attempt
     * to resolve it to an IP address may very well fail, in which case this
     * will be NULL.  Handle this case accordingly.
     */
    acl_ascii = acl_addr ? pr_netaddr_get_ipstr(acl_addr) : acl_str;
    cli_ascii = pr_netaddr_get_ipstr(cli_addr);

    log_debug(DEBUG6, "comparing addresses '%s' (%s) and '%s' (%s)",
      acl_str, acl_ascii, cli_str, cli_ascii);

    if (!pr_fnmatch(acl_str, cli_str, fnm_flags) ||
        !pr_fnmatch(acl_str, cli_ascii, fnm_flags) ||
        !pr_fnmatch(acl_ascii, cli_ascii, fnm_flags)) {
      log_debug(DEBUG6, "addresses match");
      destroy_pool(tmp_pool);
      return 1;

    } else
      log_debug(DEBUG6, "addresses do not match");

    destroy_pool(tmp_pool);
  }

  return 0;
}

/* As of 1.2.0rc3, a '!' character in front of the IP address
 * negates the logic (i.e. doesn't match).
 *
 * Here are our rules for matching an IP/host list:
 *
 * (negate-cond-1 && negate-cond-2 && ... negate-cond-n) &&
 * (cond-1 || cond-2 || ... cond-n)
 *
 * This boils down to the following two rules:
 *
 * 1. ALL negative ('!') conditions must evaluate to
 * logically TRUE.
 *
 * .. and ..
 *
 * 2. One (or more) normal conditions must evaluate to
 * logically TRUE.
 */

/* Check an ACL for negative (!) rules and make sure all of them evaluate to
 * TRUE.  Default (if none exist) is TRUE.
 */
static int _check_ip_negative(const config_rec *c) {
  char *arg,**argv;
  int argc;

  for (argc = c->argc, argv = (char **)c->argv; argc; argc--, argv++) {
    arg = *argv;
    if (*arg != '!')
      continue;

    arg++;
    switch (match_ip(session.c->remote_addr, session.c->remote_name, arg)) {
      case 1:
        /* This actually means we DIDN'T match, and it's ok to short circuit
         * everything (negative)
         */
        return FALSE;

      case -1:
        /* -1 signifies a NONE match, which isn't valid for negative
         * conditions.
         */
        log_pri(PR_LOG_ERR, "ooops, it looks like !NONE was used in an ACL "
          "somehow.");
        return FALSE;

      default:
        /* This means our match is actually true and we can continue */
        break;
    }
  }

  /* If we got this far either all conditions were TRUE or there were no
   * conditions.
   */

  return TRUE;
}

/* Check an ACL for positive conditions, short-circuiting if ANY of them are
 * TRUE.  Default return is FALSE.
 */
static int _check_ip_positive(const config_rec *c) {
  char *arg,**argv;
  int argc;

  for (argc = c->argc, argv = (char **)c->argv; argc; argc--, argv++) {
    arg = *argv;
    if (*arg == '!')
      continue;

    switch (match_ip(session.c->remote_addr, session.c->remote_name, arg)) {
      case 1:
        /* Found it! */
        return TRUE;

      case -1:
        /* Special value "NONE", meaning nothing can match, so we can
         * short-circuit on this as well.
         */
        return FALSE;

      default:
        /* No match, keep trying */
        break;
    }
  }

  /* default return value is FALSE */
  return FALSE;
}

static int _check_ip_access(xaset_t *set, char *name) {
  int res = FALSE;

  config_rec *c = find_config(set, CONF_PARAM, name, FALSE);

  while (c) {
    /* If the negative check failed (default is success), short-circuit and
     * return FALSE
     */
    if (_check_ip_negative(c) != TRUE)
      return FALSE;

    /* Otherwise, continue on with boolean or check */
    if (_check_ip_positive(c) == TRUE)
      res = TRUE;

    /* Continue on, in case there are other acls that need to be checked
     * (multiple acls are logically OR'd)
     */
    c = find_config_next(c, c->next, CONF_PARAM, name, FALSE);
  }

  return res;
}

/* 1 if allowed, 0 otherwise */

static int _check_limit_allow(config_rec *c) {
  unsigned char *allow_all = NULL;

  /* If session.groups is null, this means no authentication
   * attempt has been made, so we simply check for the
   * very existance of an AllowGroup, and assume (for now) it's
   * allowed.  This works because later calls to _check_limit_allow
   * WILL have filled in the group members and we can truely check
   * group membership at that time.  Same goes for AllowUser.
   */

  if (!session.user) {
    if (find_config(c->subset, CONF_PARAM, "AllowUser", FALSE))
      return 1;

  } else if (_check_user_access(c->subset, "AllowUser"))
    return 1;

  if (!session.groups) {
    if (find_config(c->subset, CONF_PARAM, "AllowGroup", FALSE))
      return 1;

  } else if (_check_group_access(c->subset, "AllowGroup"))
    return 1;

  if (_check_ip_access(c->subset, "Allow"))
    return 1;

  allow_all = get_param_ptr(c->subset, "AllowAll", FALSE);

  if (allow_all && *allow_all == TRUE)
    return 1;

  return 0;
}

static int _check_limit_deny(config_rec *c) {
  unsigned char *deny_all = get_param_ptr(c->subset, "DenyAll", FALSE);

  if (deny_all && *deny_all == TRUE)
    return 1;

  if (session.user && _check_user_access(c->subset, "DenyUser"))
    return 1;

  if (session.groups && _check_group_access(c->subset, "DenyGroup"))
    return 1;

  if (_check_ip_access(c->subset, "Deny"))
    return 1;

  return 0;
}

/* _check_limit returns 1 if allowed, 0 if implicitly allowed,
 * and -1 if implicitly denied and -2 if explicitly denied.
 */

static int _check_limit(config_rec *c) {
  int *tmp = get_param_ptr(c->subset, "Order", FALSE);
  int order = tmp ? *tmp : ORDER_ALLOWDENY;

  if (order == ORDER_DENYALLOW) {
    /* Check deny first */

    if (_check_limit_deny(c))
      /* Explicit deny */
      return -2;

    if (_check_limit_allow(c))
      /* Explicit allow */
      return 1;

    /* Implicit deny */
    return -1;
  }

  /* Check allow first */
  if (_check_limit_allow(c))
    /* Explicit allow */
    return 1;

  if (_check_limit_deny(c))
    /* Explicit deny */
    return -2;

  /* Implicit allow */
  return 0;
}

/* Note: if and == 1, the logic is short circuited so that the first
 * failure results in a FALSE return from the entire function, if and
 * == 0, an ORing operation is assumed and the function will return
 * TRUE if any <limit LOGIN> allows access.
 */

int login_check_limits(xaset_t *set, int recurse, int and, int *found) {
  int res = and;
  int rfound;
  config_rec *c;
  int argc;
  char **argv;

  *found = 0;

  if (!set || !set->xas_list)
    return TRUE;			/* default is to allow */

  /* First check top level */
  for (c = (config_rec*)set->xas_list; c; c=c->next)
    if (c->config_type == CONF_LIMIT) {
      for (argc = c->argc, argv = (char **)c->argv; argc; argc--, argv++)
        if (!strcasecmp("LOGIN",*argv))
          break;

      if (argc) {
        if (and) {
          switch (_check_limit(c)) {
          case 1: res = (res && TRUE); (*found)++; break;
	  case -1:
          case -2: res = (res && FALSE); (*found)++; break;
          }
          if (!res)
            break;
        } else
          switch (_check_limit(c)) {
          case 1: res = TRUE;
	  case -1:
          case -2: (*found)++; break;
          }
      }
    }

  if ( ((res && and) || (!res && !and && *found)) && recurse ) {
    for (c = (config_rec*)set->xas_list; c; c=c->next)
      if (c->config_type == CONF_ANON && c->subset && c->subset->xas_list) {
       if (and) {
         res = (res && login_check_limits(c->subset,recurse,and,&rfound));
         (*found) += rfound;
         if (!res)
           break;
       } else {
         int rres;

         rres = login_check_limits(c->subset,recurse,and,&rfound);
         if (rfound)
           res = (res || rres);
         (*found) += rfound;
         if (res)
           break;
       }
     }
  }

  if (!*found && !and)
    return TRUE;			/* Default is to allow */
  return res;
}

/* Check limit directives.
 */
static int _check_limits(xaset_t *set, char *cmd, int hidden) {
  int res = 1, ignore_hidden = -1;
  config_rec *lc = NULL;

  errno = 0;

  if (!set)
    return res;

  for (lc = (config_rec*)set->xas_list;
      lc && (res == 1); lc = lc->next) {

    if (lc->config_type == CONF_LIMIT) {
      register unsigned int i = 0;

      for (i = 0; i < lc->argc; i++) {
        if (!strcasecmp(cmd, (char *) (lc->argv[i])))
          break;
      }
	
      if (i == lc->argc)
        continue;
	
      /* Found a <Limit> directive associated with the current command.
       * ignore_hidden defaults to -1, if an explicit IgnoreHidden off is seen,
       * it is set to 0 and the check will not be done again up the chain.  If
       * an explicit "IgnoreHidden on" is seen, checking short-circuits and we
       * set ENOENT.
       */

      if (hidden && ignore_hidden == -1) {
        unsigned char *ignore = get_param_ptr(lc->subset, "IgnoreHidden",
          FALSE);

        if (ignore)
          ignore_hidden = *ignore;

        if (ignore_hidden == 1) {
          res = 0;
          errno = ENOENT;
          break;
        }
      }

      switch (_check_limit(lc)) {
        case 1:
          res++;
          break;
	
        case -1:
        case -2:
          res = 0;
          break;
	
        default:
          continue;
      }
    }
  }

  if (!res && !errno)
    errno = EACCES;

  return res;
}

int dir_check_limits(config_rec *c, char *cmd, int hidden) {
  int res = 1;

  for (; c && (res == 1); c = c->parent)
    res = _check_limits(c->subset, cmd, hidden);

  if (!c && (res == 1))
    /* vhost or main server has been reached without an explicit permit or deny,
     * so try the current server.
     */
    res = _check_limits(main_server->conf, cmd, hidden);

  return res;
}

void build_dyn_config(pool *p, char *_path, struct stat *_sbuf,
    unsigned char recurse) {
  char *fullpath = NULL, *path = NULL, *dynpath = NULL, *cp = NULL;
  struct stat sbuf;
  config_rec *d = NULL;
  pr_fh_t *fp = NULL;
  cmd_rec *cmd = NULL;
  xaset_t **set = NULL;
  int isfile, removed = 0;

  /* Switch through each directory, from "deepest" up looking for
   * new or updated .ftpaccess files
   */

  if (!_path)
    return;

  /* Check to see whether .ftpaccess files are allowed to be parsed. */
  if (!allow_dyn_config())
    return;

  path = pstrdup(p, _path);

  memcpy(&sbuf, _sbuf, sizeof(sbuf));

  if (S_ISDIR(sbuf.st_mode))
    dynpath = pdircat(p, path, "/.ftpaccess", NULL);
  else
    dynpath = NULL;

  while (path) {
    if (session.chroot_path) {
      fullpath = pdircat(p, session.chroot_path, path, NULL);

      if (strcmp(fullpath, "/") &&
          *(fullpath + strlen(fullpath) - 1) == '/')
        *(fullpath + strlen(fullpath) - 1) = '\0';

    } else
      fullpath = path;

    if (dynpath)
      isfile = pr_fsio_stat(dynpath, &sbuf);

    else
      isfile = -1;

    d = dir_match_path(p, fullpath);

    if (!d && isfile != -1) {
      set = (session.anon_config ? &session.anon_config->subset :
             &main_server->conf);

      d = add_config_set(set, fullpath);
      d->config_type = CONF_DIR;
      d->argc = 1;
      d->argv = pcalloc(d->pool, 2 * sizeof (void *));

    } else if (d) {
      config_rec *newd,*dnext;

      if (isfile != -1 &&
          strcmp(d->name, fullpath) != 0) {
        set = &d->subset;
        newd = add_config_set(set, fullpath);
        newd->config_type = CONF_DIR;
        newd->argc = 1;
        newd->argv = pcalloc(newd->pool, 2 * sizeof(void *));
	newd->parent = d;

        d = newd;

      } else if (strcmp(d->name, fullpath) == 0 &&
          (isfile == -1 ||
           sbuf.st_mtime > (d->argv[0] ? *((time_t *) d->argv[0]) : 0))) {

        set = (d->parent ? &d->parent->subset : &main_server->conf);

	if (d->subset && d->subset->xas_list) {

       	  /* Remove all old dynamic entries. */
          for (newd = (config_rec *)d->subset->xas_list; newd; newd = dnext) {
	    dnext = newd->next;

            if (newd->flags & CF_DYNAMIC) {
              xaset_remove(d->subset, (xasetmember_t *) newd);
              removed++;
            }
          }
	}

        if (d->subset && !d->subset->xas_list) {
          destroy_pool(d->subset->mempool);
          d->subset = NULL;
          d->argv[0] = NULL;

	  /* If the file has been removed and no entries exist in this
           * dynamic entry, remove it completely.
           */
          if (isfile == -1)
            xaset_remove(*set, (xasetmember_t *) d);
        }
      }
    }

    if (isfile != -1 && d &&
        sbuf.st_mtime > (d->argv[0] ? *((time_t *) d->argv[0]) : 0)) {

      /* File has been modified or not loaded yet */
      d->argv[0] = pcalloc(d->pool, sizeof(time_t));
      *((time_t *) d->argv[0]) = sbuf.st_mtime;

      if ((fp = pr_fsio_open(dynpath, O_RDONLY)) != NULL) {
        unsigned char updated = FALSE;
        conf_stack_t *cs = NULL;

        removed = 0;

        /* Push the configuration stream information onto the stack of
         * configuration streams being parsed.
         */
        cs = push_config_stack(fp, 0);

        init_dyn_stacks(p, d);
        d->config_type = CONF_DYNDIR;

        while ((cmd = get_config_cmd(p)) != NULL) {

          /* while() loops should always handle signals. */
          pr_signals_handle();

          if (cmd->argc) {
            conftable *c;
            char found = 0;
            modret_t *mr;

            cmd->server = *conf.curserver;
            cmd->config = *conf.curconfig;

            for (c = m_conftable; c->directive; c++) {
              if (!strcasecmp(c->directive, cmd->argv[0])) {
                cmd->argv[0] = c->directive;
                found++;

                if ((mr = call_module(c->m, c->handler, cmd)) != NULL) {
                  if (MODRET_ERRMSG(mr)) {
                    log_pri(PR_LOG_WARNING, "warning: %s", MODRET_ERRMSG(mr));
		  }
                }

		if (MODRET_ISDECLINED(mr))
                  found--;

		destroy_pool(cmd->tmp_pool);
              }
            }

            if (!found)
              log_pri(PR_LOG_WARNING,
                "warning: unknown configuration directive '%s' on "
                "line %d of '%s'", cmd->argv[0], cs->cs_lineno,
                dynpath);

            else
              updated = TRUE;
          }

          destroy_pool(cmd->pool);
        }

        if (updated)
	  log_debug(DEBUG5, "dynamic configuration added/updated for %s",
            fullpath);

        d->config_type = CONF_DIR;
        free_dyn_stacks();

        _mergedown(*set, TRUE);

        /* Pop this configuration stream from the stack. */
        pop_config_stack();

        pr_fsio_close(fp);
      }
    }

    if (isfile == -1 && removed && d && set) {
      log_debug(DEBUG5, "dynamic configuration removed for %s", fullpath);
      _mergedown(*set, FALSE);
    }

    if (!recurse)
      break;

    cp = strrchr(path, '/');

    if (cp && strcmp(path, "/") != 0)
      *cp = '\0';
    else
      path = NULL;

    if (path) {
      if (*(path + strlen(path) - 1) == '*')
        *(path +strlen(path) - 1) = '\0';

      dynpath = pdircat(p, path, "/.ftpaccess", NULL);
    }
  }
}

/* dir_check_full() fully recurses the path passed
 * returns 1 if operation is allowed on current path,
 * or 0 if not.
 */

/* dir_check_full() and dir_check() both take a `hidden' argument which is a
 * pointer to an integer. This is provided so that they can tell the calling
 * function if an entry should be hidden or not.  This is used by mod_ls to
 * determine if a file should be displayed.  Note that in this context, hidden
 * means "hidden by configuration" (HideUser, etc), NOT "hidden because it's a
 * .dotfile".
 */

int dir_check_full(pool *pp, char *cmd, char *group, char *path, int *hidden) {
  char *fullpath, *owner, *tmp = NULL;
  config_rec *c;
  struct stat sbuf;
  pool *p;
  mode_t _umask = (mode_t) -1;
  int res = 1, isfile;
  int op_hidden = FALSE, regex_hidden = FALSE;

  if (!path) {
    errno = EINVAL;
    return -1;
  }

  p = make_sub_pool(pp);

  /* flood -- this is no longer needed, as all paths passed to
   * dir_check should have gone through either dir_canonical or
   * dir_real first (depending on if they are supposed to pre-exist

  fullpath = dir_realpath(p,path);

  if (!fullpath)
    fullpath = pdircat(p,session.cwd,path,NULL);
  else
    path = fullpath;
  */

  fullpath = path;

  if (session.chroot_path)
    fullpath = pdircat(p, session.chroot_path, fullpath, NULL);

  log_debug(DEBUG5, "in dir_check_full(): path = '%s', fullpath = '%s'.",
            path, fullpath);

  /* Check and build all appropriate dynamic configuration entries */
  pr_fs_clear_cache();
  if ((isfile = pr_fsio_stat(path, &sbuf)) == -1)
    memset(&sbuf, '\0', sizeof(sbuf));

  build_dyn_config(p, path, &sbuf, TRUE);

  /* Check to see if this path is hidden by HideFiles. */
  if ((tmp = strrchr(fullpath, '/')) != NULL)
    regex_hidden = dir_hide_file(++tmp);
  else
    regex_hidden = dir_hide_file(fullpath);

  /* Cache a pointer to the set of configuration data for this directory in
   * session.dir_config.
   */
  session.dir_config = c = dir_match_path(p, fullpath);

  if (!c && session.anon_config)
    c = session.anon_config;

  if (!_kludge_disable_umask) {
    /* Check for a directory Umask.
     */
    if (S_ISDIR(sbuf.st_mode) ||
        !strcasecmp(cmd, C_MKD) || !strcasecmp(cmd, C_XMKD)) {
      mode_t *dir_umask = (mode_t *) get_param_ptr(CURRENT_CONF, "DirUmask",
        FALSE);

      if (dir_umask == NULL)
        _umask = (mode_t) -1;
      else
        _umask = *dir_umask;
    }

    /* It's either a file, or we had no directory Umask.
     */
    if (_umask == (mode_t) -1) {
      mode_t *file_umask = (mode_t *) get_param_ptr(CURRENT_CONF, "Umask",
        FALSE);

      if (file_umask == NULL)
        _umask = (mode_t) 0022;
      else
        _umask = *file_umask;
    }
  }

  session.fsuid = (uid_t) -1;
  session.fsgid = (gid_t) -1;

  if ((owner = get_param_ptr(CURRENT_CONF, "UserOwner", FALSE)) != NULL) {
    /* Attempt chown on all new files. */
    struct passwd *pw;

    if ((pw = auth_getpwnam(p, owner)) != NULL)
      session.fsuid = pw->pw_uid;
  }

  if ((owner = get_param_ptr(CURRENT_CONF, "GroupOwner", FALSE)) != NULL) {
    /* Attempt chgrp on all new files. */
    struct group *gr;

    if ((gr = auth_getgrnam(p,owner)) != NULL)
      session.fsgid = gr->gr_gid;
  }

  if (isfile != -1) {

    /* Check to see if the current config "hides" the path or not
     */

    op_hidden = !_dir_check_op(p,CURRENT_CONF,OP_HIDE,sbuf.st_uid,sbuf.st_gid,
                                 sbuf.st_mode);

    res = _dir_check_op(p,CURRENT_CONF,OP_COMMAND,sbuf.st_uid,sbuf.st_gid,
      sbuf.st_mode);
  }

  if (res) {

    /* Note that dir_check_limits() also handles IgnoreHidden.  If it is set,
     * these return 0 (no access), and also set errno to ENOENT so it looks
     * like the file doesn't exist.
     */
    res = dir_check_limits(c, cmd, op_hidden || regex_hidden);

    /* If specifically allowed, res will be > 1 and we don't want to
     * check the command group limit.
     */
    if (res == 1 && group)
      res = dir_check_limits(c, group, op_hidden || regex_hidden);

    /* if still == 1, no explicit allow so check lowest priority "ALL" group */
    if (res == 1)
      res = dir_check_limits(c, "ALL", op_hidden || regex_hidden);
  }

  if (res && _umask != (mode_t) -1)
    log_debug(DEBUG5, "in dir_check_full(): setting umask to %04o (was %04o)",
        (unsigned int)_umask, (unsigned int)umask(_umask));

  destroy_pool(p);

  if (hidden)
    *hidden = op_hidden || regex_hidden;

  return res;
}

/* dir_check() checks the current dir configuration against the path,
 * if it matches (partially), a search is done only in the subconfig,
 * otherwise handed off to dir_check_full
 */

int dir_check(pool *pp, char *cmd, char *group, char *path, int *hidden) {
  char *fullpath, *owner, *tmp = NULL;
  config_rec *c;
  struct stat sbuf;
  pool *p;
  mode_t _umask = (mode_t) -1;
  int res = 1, isfile;
  int op_hidden = FALSE, regex_hidden = FALSE;

  if (!path) {
    errno = EINVAL;
    return -1;
  }

  p = make_sub_pool(pp);

  fullpath = path;

  if (session.chroot_path)
    fullpath = pdircat(p, session.chroot_path, fullpath, NULL);

  c = (session.dir_config ? session.dir_config :
        (session.anon_config ? session.anon_config : NULL));

  if (!c || strncmp(c->name, fullpath, strlen(c->name)) != 0) {
    destroy_pool(p);
    return dir_check_full(pp, cmd, group, path, hidden);
  }

  /* Check and build all appropriate dynamic configuration entries */
  pr_fs_clear_cache();
  if ((isfile = pr_fsio_stat(path, &sbuf)) == -1)
    memset(&sbuf, 0, sizeof(sbuf));

  build_dyn_config(p, path, &sbuf, FALSE);

  /* Check to see if this path is hidden by HideFiles. */
  if ((tmp = strrchr(fullpath, '/')) != NULL)
    regex_hidden = dir_hide_file(++tmp);
  else
    regex_hidden = dir_hide_file(fullpath);

  /* Cache a pointer to the set of configuration data for this directory in
   * session.dir_config.
   */
  session.dir_config = c = dir_match_path(p, fullpath);

  if (!c && session.anon_config)
    c = session.anon_config;

  if (!_kludge_disable_umask) {
    /* Check for a directory Umask.
     */
    if (S_ISDIR(sbuf.st_mode) ||
        !strcasecmp(cmd, C_MKD) || !strcasecmp(cmd, C_XMKD)) {
      mode_t *dir_umask = (mode_t *) get_param_ptr(CURRENT_CONF, "DirUmask",
        FALSE);

      _umask = dir_umask ? *dir_umask : (mode_t) -1;
    }

    /* It's either a file, or we had no directory Umask.
     */
    if (_umask == (mode_t) -1) {
      mode_t *file_umask = (mode_t *) get_param_ptr(CURRENT_CONF, "Umask",
        FALSE);

      _umask = file_umask ? *file_umask : (mode_t) 0022;
    }
  }

  session.fsuid = (uid_t) -1;
  session.fsgid = (gid_t) -1;

  if ((owner = get_param_ptr(CURRENT_CONF, "UserOwner", FALSE)) != NULL) {

    /* Attempt chown() on all new files. */
    struct passwd *pw = auth_getpwnam(p, owner);

    if (pw != NULL)
      session.fsuid = pw->pw_uid;
  }

  if ((owner = get_param_ptr(CURRENT_CONF, "GroupOwner",FALSE)) != NULL) {

    /* Attempt chgrp() on all new files. */
    struct group *gr = auth_getgrnam(p, owner);

    if (gr != NULL)
      session.fsgid = gr->gr_gid;
  }

  if (isfile != -1) {

    /* if not already marked as hidden by its name, check to see if the path
     * is to be hidden by nature of its mode
     */
    op_hidden = !_dir_check_op(p, CURRENT_CONF, OP_HIDE, sbuf.st_uid,
    			         sbuf.st_gid, sbuf.st_mode);

    res = _dir_check_op(p, CURRENT_CONF, OP_COMMAND, sbuf.st_uid, sbuf.st_gid,
			sbuf.st_mode);
  }

  if (res) {
    res = dir_check_limits(c, cmd, op_hidden || regex_hidden);

    /* If specifically allowed, res will be > 1 and we don't want to
     * check the command group limit
     */

    if (res == 1 && group)
      res = dir_check_limits(c, group, op_hidden || regex_hidden);

    /* if still == 1, no explicit allow so check lowest priority "ALL" group */
    if (res == 1)
      res = dir_check_limits(c, "ALL", op_hidden || regex_hidden);
  }

  if (res && _umask != (mode_t) -1)
    log_debug(DEBUG5, "in dir_check(): setting umask to %04o (was %04o)",
        (unsigned int)_umask, (unsigned int)umask(_umask));

  destroy_pool(p);

  if (hidden)
    *hidden = op_hidden || regex_hidden;

  return res;
}

/* dir_check_canon() canonocalizes as much of the path as possible (which may
 * not be all of it, as the target may not yet exist) then we hand off to
 * dir_check().
 */
int dir_check_canon(pool *pp, char *cmd, char *group, char *path, int *hidden) {
  return dir_check(pp, cmd, group, dir_best_path(pp, path), hidden);
}

/* Move all the members (i.e. a "branch") of one config set to a different
 * parent.
 */
static void _reparent_all(config_rec *newparent, xaset_t *set) {
  config_rec *c,*cnext;

  if (!newparent->subset)
    newparent->subset = xaset_create(newparent->pool,NULL);

  for (c = (config_rec*)set->xas_list; c; c = cnext) {
    cnext = c->next;
    xaset_remove(set, (xasetmember_t*)c);
    xaset_insert(newparent->subset, (xasetmember_t*)c);
    c->set = newparent->subset;
    c->parent = newparent;
  }
}

/* Recursively find the most appropriate place to move a CONF_DIR
 * directive to.
 */

static config_rec *_find_best_dir(xaset_t *set,char *path,int *matchlen)
{
  config_rec *c,*res = NULL,*rres;
  int len,imatchlen,tmatchlen;

  *matchlen = 0;

  if (!set || !set->xas_list)
    return NULL;

  for (c = (config_rec*)set->xas_list; c; c=c->next) {
    if (c->config_type == CONF_DIR) {
      if (!strcmp(c->name,path))
        continue;				/* Don't examine the current */
      len = strlen(c->name);
      while (len > 0 &&
             (*(c->name+len-1) == '*' || *(c->name+len-1) == '/'))
        len--;

      /*
       * Just a partial match on the pathname does not mean that the longer
       * path is the subdirectory of the other -- they might just be sharing
       * the last path component!
       * /var/www/.1
       * /var/www/.14
       *            ^ -- not /, not subdir
       * /var/www/.1
       * /var/www/.1/images
       *            ^ -- /, is subdir
       */
      if (strlen(path) > len && path[len] != '/')
          continue;

      if (!strncmp(c->name,path,len) &&
         len < strlen(path)) {
           rres = _find_best_dir(c->subset,path,&imatchlen);
           tmatchlen = _strmatch(path,c->name);
           if (!rres && tmatchlen > *matchlen) {
             res = c;
             *matchlen = tmatchlen;
           } else if (imatchlen > *matchlen) {
             res = rres;
             *matchlen = imatchlen;
           }
         }
    }
  }

  return res;
}

/* Reorder all the CONF_DIR configuration sections, so that they are
 * in directory tree order
 */

static void _reorder_dirs(xaset_t *set, int mask) {
  config_rec *c = NULL, *cnext = NULL, *newparent = NULL;
  int tmp, defer = 0;

  if (!set || !set->xas_list)
    return;

  if (!(mask & CF_DEFER))
    defer = 1;

  for (c = (config_rec *) set->xas_list; c; c = cnext) {
    cnext = c->next;

    if (c->config_type == CONF_DIR) {
      if (mask && !(c->flags & mask))
        continue;

      if (defer && (c->flags & CF_DEFER))
        continue;

      /* If <Directory *> is used inside <Anonymous>, move all
       * the directives from '*' into the higher level.
       */
      if (strcmp(c->name, "*") == 0 &&
          c->parent &&
          c->parent->config_type == CONF_ANON) {

        if (c->subset)
          _reparent_all(c->parent, c->subset);

        xaset_remove(c->parent->subset, (xasetmember_t*) c);

      } else {
        newparent = _find_best_dir(set, c->name, &tmp);
        if (newparent) {
          if (!newparent->subset)
            newparent->subset = xaset_create(newparent->pool, NULL);

          xaset_remove(c->set, (xasetmember_t *) c);
          xaset_insert(newparent->subset, (xasetmember_t *) c);
          c->set = newparent->subset;
          c->parent = newparent;
        }
      }
    }
  }

  /* Top level is now sorted, now we recursively sort all the sublevels. */
  for (c = (config_rec *) set->xas_list; c; c = c->next)
    if (c->config_type == CONF_DIR || c->config_type == CONF_ANON)
      _reorder_dirs(c->subset, mask);
}

static void debug_dump_config(xaset_t *s,char *indent) {
  config_rec *c = NULL;

  if (!indent)
    indent = "";

  for (c = (config_rec *) s->xas_list; c; c = c->next) {
    log_debug(DEBUG5, "%s%s", indent, c->name);
    if (c->subset)
      debug_dump_config(c->subset, pstrcat(c->pool, indent, " ", NULL));
  }
}

static void _mergedown(xaset_t *s,int dynamic)
{
  config_rec *c,*dest,*newconf;
  int argc;
  void **argv,**sargv;

  if (!s || !s->xas_list)
    return;

  for (c = (config_rec*)s->xas_list; c; c=c->next)
    if ((c->flags & CF_MERGEDOWN) ||
        (c->flags & CF_MERGEDOWN_MULTI))
      for (dest = (config_rec*)s->xas_list; dest; dest=dest->next)
        if (dest->config_type == CONF_ANON ||
           dest->config_type == CONF_DIR) {

          /* If an option of the same name/type is found in the
           * next level down, it overrides, so we don't merge.
           */
          if ((c->flags & CF_MERGEDOWN) &&
              find_config(dest->subset, c->config_type, c->name, FALSE))
            continue;

          if (!dest->subset)
            dest->subset = xaset_create(dest->pool,NULL);

          newconf = add_config_set(&dest->subset,c->name);
          newconf->config_type = c->config_type;
          newconf->flags = c->flags | (dynamic ? CF_DYNAMIC : 0);
          newconf->argc = c->argc;
          newconf->argv = pcalloc(newconf->pool, (c->argc+1)*sizeof(void*));
          argv = newconf->argv; sargv = c->argv;
          argc = newconf->argc;
          while (argc--)
            *argv++ = *sargv++;
          *argv++ = NULL;
        }

  /* Top level merged, recursively merge lower levels */
  for (c = (config_rec*)s->xas_list; c; c=c->next)
    if (c->subset && (c->config_type == CONF_ANON ||
                     c->config_type == CONF_DIR))
      _mergedown(c->subset,dynamic);
}

/* iterate through <Directory> blocks inside of anonymous and
 * resolve each one.
 */

void resolve_anonymous_dirs(xaset_t *clist)
{
  config_rec *c;
  char *realdir;

  if (!clist)
    return;

  for (c = (config_rec*)clist->xas_list; c; c=c->next) {
    if (c->config_type == CONF_DIR) {
      if (c->argv[1]) {
        realdir = dir_best_path(c->pool,c->argv[1]);
        if (realdir)
          c->argv[1] = realdir;
        else {
          realdir = dir_canonical_path(c->pool,c->argv[1]);
          if (realdir)
            c->argv[1] = realdir;
        }
      }

      if (c->subset)
        resolve_anonymous_dirs(c->subset);
    }
  }
}

/* Iterate through directory configuration items and resolve ~ references. */
void resolve_deferred_dirs(server_rec *s) {
  config_rec *c;
  char *realdir;

  if (!s || !s->conf)
    return;

  for (c = (config_rec*)s->conf->xas_list; c; c=c->next) {
    if (c->config_type == CONF_DIR && (c->flags & CF_DEFER)) {

      /* Check for any expandable variables. */
      c->name = path_subst_uservar(c->pool, &c->name);

      realdir = dir_best_path(c->pool,c->name);

      if (realdir)
        c->name = realdir;

      else {
        realdir = dir_canonical_path(c->pool,c->name);
        if (realdir)
          c->name = realdir;
      }
    }
  }
}

static void _copy_recur(xaset_t **set, pool *p, config_rec *c,
    config_rec *new_parent) {
  config_rec *newconf;
  int argc;
  void **argv,**sargv;

  if (!*set)
    *set = xaset_create(p,NULL);

  newconf = add_config_set(set,c->name);
  newconf->config_type = c->config_type;
  newconf->flags = c->flags;
  newconf->parent = new_parent;
  newconf->argc = c->argc;

  if (c->argc) {
    newconf->argv = pcalloc(newconf->pool, (c->argc+1)*sizeof(void*));
    argv = newconf->argv;
    sargv = c->argv;
    argc = newconf->argc;

    while (argc--)
      *argv++ = *sargv++;

    if (argv)
      *argv++ = NULL;
  }

  if (c->subset)
    for (c = (config_rec*)c->subset->xas_list; c; c=c->next)
      _copy_recur(&newconf->subset,p,c,newconf);
}

static
void _copy_global_to_all(xaset_t *set)
{
  server_rec *s;
  config_rec *c;

  if (!set || !set->xas_list)
    return;

  for (c = (config_rec*)set->xas_list; c; c=c->next)
    for (s = (server_rec*) server_list->xas_list; s; s=s->next)
      _copy_recur(&s->conf,s->pool,c,NULL);
}

static void fixup_globals(void) {
  server_rec *s = NULL, *smain = NULL;
  config_rec *c = NULL, *cnext = NULL;

  smain = (server_rec*) server_list->xas_list;
  for (s = smain; s; s=s->next) {
    /* loop through each top level directive looking for a CONF_GLOBAL
     * context
     */
    if (!s->conf || !s->conf->xas_list)
      continue;

    for (c = (config_rec*)s->conf->xas_list; c; c=cnext) {
      cnext = c->next;
      if (c->config_type == CONF_GLOBAL) {
        /* copy the contents of the block to all other servers
         * (including this one), then pull the block "out of play".
         */
        if (c->subset && c->subset->xas_list)
          _copy_global_to_all(c->subset);
        xaset_remove(s->conf, (xasetmember_t*)c);
        if (!s->conf->xas_list) {
          destroy_pool(s->conf->mempool);
          s->conf = NULL;
        }
      }
    }
  }
}

void fixup_dirs(server_rec *s, int mask) {
  if (!s || !s->conf)
    return;

  _reorder_dirs(s->conf, mask);

  /* Merge mergeable configuration items down. */
  _mergedown(s->conf, FALSE);

  log_debug(DEBUG5, "%s", "");
  log_debug(DEBUG5, "Config for %s:", s->ServerName);
  debug_dump_config(s->conf, NULL);
}

config_rec *find_config_next(config_rec *prev, config_rec *c, int type,
                             const char *name, int recurse)
{
  config_rec *top = c;

  /* We do two searches (if recursing) so that we find the "deepest"
   * level first.
   */

  if (!c && !prev)
    return NULL;

  if (!prev)
    prev = top;

  if (recurse) {
    do {
      config_rec *res = NULL;

      for (c = top; c; c=c->next) {
        if (c->subset && c->subset->xas_list) {
          config_rec *subc = NULL;

          for (subc = (config_rec *) c->subset->xas_list; subc;
              subc = subc->next) {
            if ((res = find_config_next(NULL, subc, type, name, recurse+1)))
              return res;
          }
        }
      }

      /* If deep recursion yielded no match try the current subset */
      /* NOTE: the string comparison here is specifically case sensitive.
       * The config_rec names are supplied by the modules and intentionally
       * case sensitive (they shouldn't be verbatim from the config file)
       * Do NOT change this to strcasecmp(), no matter how tempted you are
       * to do so, it will break stuff. ;)
       */
      for (c = top; c; c=c->next) {
        if ((type == -1 || type == c->config_type) &&
            (!name || !strcmp(name,c->name)))
          return c;
      }

      /* Restart the search at the previous level if required */
      if (prev->parent && recurse == 1 &&
         prev->parent->next &&
         prev->parent->set != find_config_top) {
        prev = top = prev->parent->next; c = top;
        continue;
      }

      break;
    } while (TRUE);

  } else {
    for (c = top; c; c=c->next) {
      if ((type == -1 || type == c->config_type) &&
         (!name || !strcmp(name, c->name)))
        return c;
    }
  }

  return NULL;
}

void find_config_set_top(config_rec *c)
{
  if (c && c->parent)
    find_config_top = c->parent->set;
  else
    find_config_top = NULL;
}


config_rec *find_config(xaset_t *set, int type, const char *name, int recurse)
{
  if (!set || !set->xas_list)
    return NULL;

  find_config_set_top((config_rec*)set->xas_list);

  return find_config_next(NULL, (config_rec*)set->xas_list,type,name,recurse);
}

/* These next two functions return the first argument in a
 * CONF_PARAM configuration entry.  If more than one or all
 * parameters are needed, the caller will need to use find_config,
 * and iterate through the argv themselves.
 * _int returns -1 if the config name is not found, _ptr returns
 * NULL.
 */

long get_param_int(xaset_t *set,const char *name,int recurse)
{
  config_rec *c;

  if (!set) {
    _last_param_int = NULL;
    return -1;
  }

  c = find_config(set,CONF_PARAM,name,recurse);

  if (c && c->argc) {
    _last_param_int = c;
    return (long)c->argv[0];
  }

  _last_param_int = NULL;
  return -1;  /* Parameters aren't allowed to contain neg. integers anyway */
}

long get_param_int_next(const char *name,int recurse)
{
  config_rec *c;

  if (!_last_param_int || !_last_param_int->next) {
    _last_param_int = NULL;
    return -1;
  }

  c = find_config_next(_last_param_int,_last_param_int->next,
                       CONF_PARAM,name,recurse);

  if (c && c->argc) {
    _last_param_int = c;
    return (long)c->argv[0];
  }

  _last_param_int = NULL;
  return -1;
}

void *get_param_ptr(xaset_t *set,const char *name,int recurse)
{
  config_rec *c;

  if (!set) {
    _last_param_ptr = NULL;
    return NULL;
  }

  c = find_config(set,CONF_PARAM,name,recurse);

  if (c && c->argc) {
    _last_param_ptr = c;
    return c->argv[0];
  }

  _last_param_ptr = NULL;
  return NULL;
}

void *get_param_ptr_next(const char *name,int recurse)
{
  config_rec *c;

  if (!_last_param_ptr || !_last_param_ptr->next) {
    _last_param_ptr = NULL;
    return NULL;
  }

  c = find_config_next(_last_param_ptr,_last_param_ptr->next,
                       CONF_PARAM,name,recurse);

  if (c && c->argv) {
    _last_param_ptr = c;
    return c->argv[0];
  }

  _last_param_ptr = NULL;
  return NULL;
}

int remove_config(xaset_t *set, const char *name,int recurse)
{
  server_rec *s = (conf.curserver ? *conf.curserver : main_server);
  config_rec *c;
  int found = 0;
  xaset_t *fset;

  while ((c = find_config(set, -1, name, recurse)) != NULL) {
    found++;

    fset = c->set;
    xaset_remove(fset, (xasetmember_t *) c);

    /* if the set is empty, and has no more contained members in
     * the xas_list, destroy the set
     */
    if (!fset->xas_list) {

      /* first, set any pointers to the container of the set to NULL
       */
      if (c->parent && c->parent->subset == fset)
        c->parent->subset = NULL;

      else if (s->conf == fset)
        s->conf = NULL;

      /* next, destroy the set's pool, which destroys the set as well
       */
        destroy_pool(fset->mempool);

    } else {

      /* if the set was not empty, destroy only the requested config_rec
       */
      destroy_pool(c->pool);
    }
  }

  return found;
}

config_rec *add_config_param_set(xaset_t **set,const char *name,int num,...)
{
  config_rec *c = add_config_set(set,name);
  void **argv;
  va_list ap;

  if (c) {
    c->config_type = CONF_PARAM;
    c->argc = num;
    c->argv = pcalloc(c->pool, (num+1) * sizeof(void *));

    argv = c->argv;
    va_start(ap,num);

    while (num-- > 0)
      *argv++ = va_arg(ap, void *);

    va_end(ap);
  }

  return c;
}

config_rec *add_config_param_str(const char *name, int num, ...) {
  config_rec *c = add_config(name);
  char *arg = NULL;
  void **argv = NULL;
  va_list ap;

  if (c) {
    c->config_type = CONF_PARAM;
    c->argc = num;
    c->argv = pcalloc(c->pool, (num+1) * sizeof(char *));

    argv = c->argv;
    va_start(ap, num);

    while (num-- > 0) {
      arg = va_arg(ap, char *);
      if (arg)
        *argv++ = pstrdup(c->pool, arg);
      else
        *argv++ = NULL;
    }

    va_end(ap);
  }

  return c;
}

config_rec *add_config_param(const char *name, int num, ...) {
  config_rec *c = add_config(name);
  void **argv;
  va_list ap;

  if (c) {
    c->config_type = CONF_PARAM;
    c->argc = num;
    c->argv = pcalloc(c->pool, (num+1) * sizeof(void*));

    argv = c->argv;
    va_start(ap, num);

    while (num-- > 0)
      *argv++ = va_arg(ap, void *);

    va_end(ap);
  }

  return c;
}

int parse_config_file(const char *fname) {
  pr_fh_t *fh = NULL;
  conf_stack_t *cs = NULL;
  cmd_rec *cmd = NULL;
  modret_t *mr = NULL;
  pool *tmp_pool = make_sub_pool(permanent_pool);

  log_debug(DEBUG2, "parsing '%s' configuration", fname);

  if ((fh = pr_fsio_open(fname, O_RDONLY)) == NULL) {
    destroy_pool(tmp_pool);
    return -1;
  }

  /* Push the configuration stream information onto the stack of
   * configuration streams.
   */
  cs = push_config_stack(fh, 0);

  while ((cmd = get_config_cmd(tmp_pool)) != NULL) {
    if (cmd->argc) {
      conftable *c;
      char found = 0;

      cmd->server = *conf.curserver;
      cmd->config = *conf.curconfig;

      for (c = m_conftable; c->directive; c++)
        if (!strcasecmp(c->directive, cmd->argv[0])) {
          cmd->argv[0] = c->directive;
          ++found;

          if ((mr = call_module(c->m, c->handler, cmd)) != NULL) {
            if (MODRET_ISERROR(mr)) {
              log_pri(PR_LOG_ERR, "Fatal: %s", MODRET_ERRMSG(mr));
              exit(1);
            }
          }

          if (MODRET_ISDECLINED(mr))
            found--;

          destroy_pool(cmd->tmp_pool);
        }

       if (!found) {
         log_pri(PR_LOG_ERR, "Fatal: unknown configuration directive '%s' on "
           "line %d of '%s'.", cmd->argv[0], cs->cs_lineno, fname);
         exit(1);
       }
    }

    destroy_pool(cmd->pool);
  }

  /* Pop this configuration stream from the stack. */
  pop_config_stack();

  pr_fsio_close(fh);

  destroy_pool(tmp_pool);
  return 0;
}

/* Go through each server configuration and complain if important information
 * is missing (post reading configuration files).  Otherwise, fill in defaults
 * where applicable.
 */
int fixup_servers(void) {
  config_rec *c = NULL;
  server_rec *s = NULL, *next_s = NULL;

  fixup_globals();

  s = (server_rec *) server_list->xas_list;
  if (s && !s->ServerName)
    s->ServerName = pstrdup(s->pool, "ProFTPD");

  for (; s; s = next_s) {
    unsigned char *default_server = NULL;

    next_s = s->next;

    if (!s->ServerAddress)
      s->ServerAddress = pr_netaddr_get_localaddr_str(s->pool);

    s->addr = pr_netaddr_get_addr(s->pool, s->ServerAddress, NULL);
    if (s->addr == NULL) {
      log_pri(PR_LOG_ERR, "error: unable to determine IP address of '%s'",
        s->ServerAddress);
      xaset_remove(server_list, (xasetmember_t *) s);
      continue;
    }

    s->ServerFQDN = pr_netaddr_get_dnsstr(s->addr);

    if (!s->ServerFQDN)
      s->ServerFQDN = s->ServerAddress;

    if (!s->ServerAdmin)
      s->ServerAdmin = pstrcat(s->pool, "root@", s->ServerFQDN, NULL);

    if (!s->ServerName) {
      server_rec *m = (server_rec *) server_list->xas_list;
      s->ServerName = pstrdup(s->pool, m->ServerName);
    }

    if (!s->tcp_rcvbuf_len)
      s->tcp_rcvbuf_len = PR_TUNABLE_DEFAULT_RCVBUF;

    if (!s->tcp_sndbuf_len)
      s->tcp_sndbuf_len = PR_TUNABLE_DEFAULT_SNDBUF;

    if ((c = find_config(s->conf, CONF_PARAM, "MasqueradeAddress",
        FALSE)) != NULL) {
      log_pri(PR_LOG_INFO, "%s:%d masquerading as %s",
        pr_netaddr_get_ipstr(s->addr), s->ServerPort,
        pr_netaddr_get_ipstr((pr_netaddr_t *) c->argv[0]));
    }

    /* Honor the DefaultServer directive only if SocketBindTight is not
     * in effect.
     */
    default_server= get_param_ptr(s->conf, "DefaultServer", FALSE);

    if (default_server && *default_server == TRUE) {
      if (!SocketBindTight)
        pr_netaddr_set_sockaddr_any(s->addr);
      else
        log_pri(PR_LOG_NOTICE,
          "SocketBindTight in effect, ignoring DefaultServer");
    }

    fixup_dirs(s, 0);
  }

  /* Make sure there actually are server_recs remaining in the server_list
   * before continuing.  Badly configured/resolved vhosts are rejected, and
   * it's possible to have all vhosts (even the default) rejected.
   */
  if (server_list->xas_list == NULL) {
    log_pri(PR_LOG_NOTICE, "error: no valid servers configured");
    return -1;
  }

  pr_inet_clear();
  return 0;
}

void init_config(void) {
  pool *conf_pool = make_sub_pool(permanent_pool);

  /* Make sure global_config_pool is destroyed */
  if (global_config_pool) {
    destroy_pool(global_config_pool);
    global_config_pool = NULL;
  }

  if (server_list) {
    server_rec *s, *s_next;

    /* Free the old configuration completely */
    for (s = (server_rec *) server_list->xas_list; s; s = s_next) {
      s_next = s->next;
      destroy_pool(s->pool);
    }
    destroy_pool(server_list->mempool);
  }

  server_list = xaset_create(conf_pool, NULL);

  conf_pool = make_sub_pool(permanent_pool);
  main_server = (server_rec *) pcalloc(conf_pool, sizeof(server_rec));
  xaset_insert(server_list, (xasetmember_t *) main_server);

  main_server->pool = conf_pool;
  main_server->set = server_list;

  /* Default server port */
  main_server->ServerPort = pr_inet_getservport(main_server->pool,
    "ftp", "tcp");
}

/* These functions are used by modules to help parse configuration.
 */

unsigned char check_context(cmd_rec *cmd, int allowed) {
  int ctxt = (cmd->config && cmd->config->config_type != CONF_PARAM ?
     cmd->config->config_type : cmd->server->config_type ?
     cmd->server->config_type : CONF_ROOT);

  if (ctxt & allowed)
    return TRUE;

  /* default */
  return FALSE;
}

char *get_context_name(cmd_rec *cmd) {
  static char cbuf[20];

  if (!cmd->config || cmd->config->config_type == CONF_PARAM) {
    if (cmd->server->config_type == CONF_VIRTUAL)
      return "<VirtualHost>";
    else
      return "server config";
  }

  memset(cbuf,'\0',sizeof(cbuf));
  switch (cmd->config->config_type) {
  case CONF_DIR: return "<Directory>";
  case CONF_ANON: return "<Anonymous>";
  case CONF_LIMIT: return "<Limit>";
  case CONF_DYNDIR: return ".ftpaccess";
  case CONF_GLOBAL: return "<Global>";
  case CONF_USERDATA: return "user data";
  default:
    /* in 1.3/2.0, should dispatch to modules here */
  snprintf(cbuf, sizeof(cbuf), "%d", cmd->config->config_type);
  return cbuf;
  }
}

int get_boolean(cmd_rec *cmd, int av)
{
  char *cp = cmd->argv[av];

  /* Boolean string can be "on", "off", "yes", "no", "true", "false",
   * "1" or "0."
   */

  if (!strcasecmp(cp, "on"))
    return 1;
  if (!strcasecmp(cp, "off"))
    return 0;
  if (!strcasecmp(cp, "yes"))
    return 1;
  if (!strcasecmp(cp, "no"))
    return 0;
  if (!strcasecmp(cp, "true"))
    return 1;
  if (!strcasecmp(cp, "false"))
    return 0;
  if (!strcasecmp(cp, "1"))
    return 1;
  if (!strcasecmp(cp, "0"))
    return 0;

  return -1;
}

char *get_full_cmd(cmd_rec *cmd) {
  pool *p = cmd->tmp_pool;
  char *res = "";

  if (cmd->arg && *cmd->arg)
    res = pstrcat(p, cmd->argv[0], " ", cmd->arg, NULL);

  else if (cmd->argc > 1) {
    register unsigned int i = 0;
    res = cmd->argv[0];

    for (i = 1; i < cmd->argc; i++)
      res = pstrcat(p, res, cmd->argv[i], " ", NULL);

    while (res[strlen(res)-1] == ' ' && *res)
      res[strlen(res)-1] = '\0';

  } else
    res = pstrdup(p, cmd->argv[0]);

  return res;
}
