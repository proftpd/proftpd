/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
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

/*
 * Module handling routines
 */

#include "conf.h"

/* This local structure vastly speeds up symbol lookups. */
struct stash {
  struct stash *next,*prev;
  pool *sym_pool;
  const char *sym_name;
  pr_stash_type_t sym_type;
  module *sym_module;

  union {
    conftable *sym_conf;
    cmdtable *sym_cmd;
    authtable *sym_auth;
    cmdtable *sym_hook;
    void *sym_generic;
  } ptr;
};

/* Symbol hashes for each type */
static xaset_t *symbol_table[PR_TUNABLE_HASH_TABLE_SIZE];
static pool *symbol_pool = NULL;
static struct stash *curr_sym = NULL;

static xaset_t *installed_modules = NULL;
static array_header *mconfarr;			/* masterconf array */
static array_header *mcmdarr;			/* mastercmd array */
static array_header *mautharr;			/* masterauth array */

conftable *m_conftable; 			/* Master conf table */
cmdtable *m_cmdtable;				/* Master cmd table */
authtable *m_authtable;				/* Master auth table */

module *curr_module = NULL;			/* Current running module */

extern module *static_modules[];

typedef struct mod_cb {
  struct mod_cb *next, *prev;

  int (*module_cb)(void);
} module_cb_t;

static pool *daemon_cb_pool = NULL;
static xaset_t *daemon_startups = NULL;

static pool *postparse_init_pool = NULL;
static xaset_t *postparse_inits = NULL;

/* Symbol stash lookup code and management */

/* This wrapper will be used in the future to track when to rehash through
 * the symbol memory, to prevent symbol_pool from growing too large.
 */
static struct stash *sym_alloc(void) {
  static unsigned int count = 0;

  pool *sub_pool = make_sub_pool(symbol_pool);
  struct stash *sym = pcalloc(sub_pool, sizeof(struct stash));
  sym->sym_pool = sub_pool; 

  count++;

  return sym;
}

static int sym_cmp(struct stash *s1, struct stash *s2) {
  int ret;

  ret = strcmp(s1->sym_name,s2->sym_name);

  /* higher priority modules must go BEFORE lower priority in the
   * hash tables.
   */

  if (!ret) {
    if (s1->sym_module->priority > s2->sym_module->priority)
      ret = -1;
    else if (s1->sym_module->priority < s2->sym_module->priority)
      ret = 1;
  }

  return ret;
}

static int symtab_hash(const char *name) {
  unsigned char *cp = NULL;
  int total = 0;

  for (cp = (unsigned char *)name; *cp; cp++)
    total += (int)*cp;

  return (total < PR_TUNABLE_HASH_TABLE_SIZE ? total :
    (total % PR_TUNABLE_HASH_TABLE_SIZE));
}

int pr_stash_add_symbol(pr_stash_type_t sym_type, void *data) {
  struct stash *sym = NULL;
  int idx = 0;

  if (!data) {
    errno = EINVAL;
    return -1;
  }

  switch (sym_type) {
    case PR_SYM_CONF:
      sym = sym_alloc();
      sym->sym_type = PR_SYM_CONF;
      sym->sym_name = ((conftable *) data)->directive;
      sym->sym_module = ((conftable *) data)->m;
      sym->ptr.sym_conf = data;
      break;

    case PR_SYM_CMD:
      sym = sym_alloc();
      sym->sym_type = PR_SYM_CMD;
      sym->sym_name = ((cmdtable *) data)->command;
      sym->sym_module = ((cmdtable *) data)->m;
      sym->ptr.sym_cmd = data;
      break;

    case PR_SYM_AUTH:
      sym = sym_alloc();
      sym->sym_type = PR_SYM_AUTH;
      sym->sym_name = ((authtable *) data)->name;
      sym->sym_module = ((authtable *) data)->m;
      sym->ptr.sym_auth = data;
      break;

    case PR_SYM_HOOK:
      sym = sym_alloc();
      sym->sym_type = PR_SYM_HOOK;
      sym->sym_name = ((cmdtable *) data)->command;
      sym->sym_module = ((cmdtable *) data)->m;
      sym->ptr.sym_hook = data;
      break;

    default:
      errno = EINVAL;
      return -1;
  }

  idx = symtab_hash(sym->sym_name);

  if (!symbol_table[idx])
    symbol_table[idx] = xaset_create(permanent_pool, (XASET_COMPARE) sym_cmp);

  xaset_insert_sort(symbol_table[idx], (xasetmember_t *) sym, TRUE);
  return idx;
}

static struct stash *stash_lookup(pr_stash_type_t sym_type,
    const char *name, int idx) {
  struct stash *sym = NULL;

  if (name && symbol_table[idx]) {
    for (sym = (struct stash *) symbol_table[idx]->xas_list; sym;
        sym = sym->next)
      if (sym->sym_type == sym_type && !strcmp(sym->sym_name, name))
        break;
  }

  return sym;
}

static struct stash *stash_lookup_next(pr_stash_type_t sym_type,
    const char *name, int idx, void *prev) {
  struct stash *sym = NULL;
  int last_hit = 0;

  if (symbol_table[idx]) {
    for (sym = (struct stash *) symbol_table[idx]->xas_list; sym;
        sym = sym->next) {
      if (last_hit && sym->sym_type == sym_type && !strcmp(sym->sym_name, name))
        break;
      if (sym->ptr.sym_generic == prev)
        last_hit++;
    }
  }

  return sym;
}

void *pr_stash_get_symbol(pr_stash_type_t sym_type, const char *name,
    void *prev, int *idx_cache) {
  int idx;
  struct stash *sym = NULL;

  if (idx_cache && *idx_cache != -1)
    idx = *idx_cache;

  else {

    idx = symtab_hash(name);
    if (idx_cache)
      *idx_cache = idx;
  }

  if (prev)
    curr_sym = sym = stash_lookup_next(sym_type, name, idx, prev);
  else
    curr_sym = sym = stash_lookup(sym_type, name, idx);

  switch (sym_type) {
    case PR_SYM_CONF:
      return sym ? sym->ptr.sym_conf : NULL;

    case PR_SYM_CMD:
      return sym ? sym->ptr.sym_cmd : NULL;

    case PR_SYM_AUTH:
      return sym ? sym->ptr.sym_auth : NULL;

    case PR_SYM_HOOK:
      return sym ? sym->ptr.sym_hook : NULL;
  }

  /* In case the compiler complains */
  return NULL;
}

int pr_stash_remove_symbol(pr_stash_type_t sym_type, const char *sym_name,
    module *sym_module) {
  int count = 0, symtab_idx = 0;

  if (!sym_name) {
    errno = EINVAL;
    return -1;
  }

  symtab_idx = symtab_hash(sym_name);

  switch (sym_type) {
    case PR_SYM_CONF: {
      int idx = -1;
      conftable *tab = NULL;

      tab = pr_stash_get_symbol(PR_SYM_CONF, sym_name, NULL, &idx);

      while (tab) {

        /* Note: this works because of a hack: the symbol look functions
         * set a static pointer, curr_sym, to point to the struct stash
         * just looked up.  curr_sym will not be NULL if pr_stash_get_symbol()
         * returns non-NULL.
         */

        if (!sym_module || curr_sym->sym_module == sym_module) {
          xaset_remove(symbol_table[symtab_idx], (xasetmember_t *) curr_sym);
          destroy_pool(curr_sym->sym_pool);
        }

        tab = pr_stash_get_symbol(PR_SYM_CONF, sym_name, NULL, &idx);
      }

      break;
    }

    case PR_SYM_CMD: {
      int idx = -1;
      cmdtable *tab = NULL;

      tab = pr_stash_get_symbol(PR_SYM_CMD, sym_name, NULL, &idx);

      while (tab) {

        /* Note: this works because of a hack: the symbol look functions
         * set a static pointer, curr_sym, to point to the struct stash
         * just looked up.  
         */

        if (!sym_module || curr_sym->sym_module == sym_module) {
          xaset_remove(symbol_table[symtab_idx], (xasetmember_t *) curr_sym);
          destroy_pool(curr_sym->sym_pool);
        }

        tab = pr_stash_get_symbol(PR_SYM_CMD, sym_name, NULL, &idx);
      }

      break;
    }

    case PR_SYM_AUTH: {
      int idx = -1;
      authtable *tab = NULL;

      tab = pr_stash_get_symbol(PR_SYM_AUTH, sym_name, NULL, &idx);

      while (tab) {

        /* Note: this works because of a hack: the symbol look functions
         * set a static pointer, curr_sym, to point to the struct stash
         * just looked up.  
         */

        if (!sym_module || curr_sym->sym_module == sym_module) {
          xaset_remove(symbol_table[symtab_idx], (xasetmember_t *) curr_sym);
          destroy_pool(curr_sym->sym_pool);
        }

        tab = pr_stash_get_symbol(PR_SYM_AUTH, sym_name, NULL, &idx);
      }

      break;
    }

    case PR_SYM_HOOK: {
      int idx = -1;
      cmdtable *tab = NULL;

      tab = pr_stash_get_symbol(PR_SYM_HOOK, sym_name, NULL, &idx);

      while (tab) {
        if (!sym_module || curr_sym->sym_module == sym_module) {
          xaset_remove(symbol_table[symtab_idx], (xasetmember_t *) curr_sym);
          destroy_pool(curr_sym->sym_pool);
        }

        tab = pr_stash_get_symbol(PR_SYM_HOOK, sym_name, NULL, &idx);
      }

      break;
    }

    default:
      errno = EINVAL;
      return -1;
  }

  return count;
}

/* functions to manage modular privdata structure inside cmd_rec */
privdata_t *mod_privdata_alloc(cmd_rec *cmd, char *tag, int size)
{
  privdata_t **pp;
  privdata_t *p;

  if (!tag)
    return NULL;

  p = pcalloc(cmd->pool,sizeof(privdata_t));

  p->tag = pstrdup(cmd->pool,tag);
  if (size)
    p->value.ptr_val = pcalloc(cmd->pool,size);
  p->m = curr_module;

  if (!cmd->privarr)
    cmd->privarr = make_array(cmd->pool,2,sizeof(privdata_t*));

  pp = (privdata_t**)push_array(cmd->privarr);
  *pp = p;

  cmd->private = (privdata_t*)cmd->privarr->elts;
  return p;
}

privdata_t *mod_privdata_find(cmd_rec *cmd, char *tag, module *m)
{
  int i;
  privdata_t **p;

  if (!tag)
    return NULL;

  if (!m)
    m = curr_module;

  for (i = 0, p = (privdata_t**)cmd->privarr->elts; i < cmd->privarr->nelts; i++, p++) {
    if (!strcmp((*p)->tag,tag) && (m == ANY_MODULE || (*p)->m == m))
      break;
  }

  return (i < cmd->privarr->nelts ? *p : NULL);
}

modret_t *call_module_auth(module *m, modret_t *(*func)(cmd_rec*), cmd_rec *cmd)
{
  modret_t *res;
  module *prev_module = curr_module;

  if (!cmd->tmp_pool)
    cmd->tmp_pool = make_sub_pool(cmd->pool);

  curr_module = m;
  res = func(cmd);
  curr_module = prev_module;

  return res;
}

modret_t *call_module_cmd(module *m, modret_t *(*func)(cmd_rec*), cmd_rec *cmd)
{
  modret_t *res;
  module *prev_module = curr_module;

  if (!cmd->tmp_pool)
    cmd->tmp_pool = make_sub_pool(cmd->pool);

  curr_module = m;
  res = func(cmd);
  curr_module = prev_module;

  return res;
}

modret_t *call_module(module *m, modret_t *(*func)(cmd_rec*), cmd_rec *cmd)
{
  modret_t *res;
  module *prev_module = curr_module;

  if (!cmd->tmp_pool)
    cmd->tmp_pool = make_sub_pool(cmd->pool);

  curr_module = m;
  res = func(cmd);
  curr_module = prev_module;

  /* Note that we don't clear the pool here because the function may
   * return data which resides in this pool.
   */
  return res;
}

modret_t *mod_create_data(cmd_rec *cmd,void *d)
{
  modret_t *ret;

  ret = pcalloc(cmd->tmp_pool,sizeof(modret_t));
  ret->data = d;

  return ret;
}

modret_t *mod_create_ret(cmd_rec *cmd,unsigned char err,char *n,char *m)
{
  modret_t *ret;

  ret = pcalloc(cmd->tmp_pool,sizeof(modret_t));
  ret->mr_handler_module = curr_module;
  ret->mr_error = err;
  if (n)
    ret->mr_numeric = pstrdup(cmd->tmp_pool,n);
  if (m)
    ret->mr_message = pstrdup(cmd->tmp_pool,m);

  return ret;
}

modret_t *mod_create_error(cmd_rec *cmd,int mr_errno)
{
  modret_t *ret;

  ret = pcalloc(cmd->tmp_pool,sizeof(modret_t));
  ret->mr_handler_module = curr_module;
  ret->mr_error = mr_errno;

  return ret;
}

/* Called after forking in order to inform/initialize modules
 * need to know we are a child and have a connection.
 */
int module_session_init(void) {
  module *prev_module = curr_module;
  module *m;

  for (m = (module*) installed_modules->xas_list; m; m=m->next)
    if (m && m->module_init_session_cb) {
      curr_module = m;
      m->module_init_session_cb();
    }

  curr_module = prev_module;
  return 0;
}

unsigned char command_exists(char *name) {
  cmdtable *cmdtab = pr_stash_get_symbol(PR_SYM_CMD, name, NULL, NULL);

  while (cmdtab && cmdtab->cmd_type != CMD)
    cmdtab = pr_stash_get_symbol(PR_SYM_CMD, name, cmdtab, NULL);

  return (cmdtab ? TRUE : FALSE);
}

unsigned char module_exists(const char *name) {
  char buf[PR_TUNABLE_BUFFER_SIZE] = {'\0'};
  register unsigned int i = 0;

  /* Check the list of compiled-in modules. */
  for (i = 0; static_modules[i]; i++) {
    memset(buf, '\0', sizeof(buf));
    snprintf(buf, sizeof(buf), "mod_%s.c", (static_modules[i])->name);
    buf[sizeof(buf)-1] = '\0';

    if (!strcmp(buf, name))
      return TRUE;
  }

  /* default */
  return FALSE;
}

void list_modules(void) {
  register unsigned int i = 0;
  module *m = NULL;

  printf("Compiled-in modules:\n");
  for (i = 0; static_modules[i]; i++) {
    m = static_modules[i];
    printf("  mod_%s.c\n", m->name);
  }
}

int module_daemon_startup(void) {
  module_cb_t *di = NULL;

  if (!daemon_startups)
    return 0;

  for (di = (module_cb_t *) daemon_startups->xas_list; di; di = di->next)
    di->module_cb();

  return 0;
}

int module_preparse_init(void) {
  int numconf = 0,numcmd = 0,numauth = 0;
  module *m;
  conftable *conf = NULL;
  cmdtable *cmd = NULL;
  authtable *auth = NULL;
  register unsigned int i = 0;

  installed_modules = xaset_create(permanent_pool,NULL);

  for (i = 0; static_modules[i]; i++) {
    m = static_modules[i];
    m->priority = m->auth_priority = i;

    if (m->api_version < PR_MODULE_API_VERSION) {
      log_pri(PR_LOG_ERR, "Fatal: module '%s' API version (0x%x) is too old "
        "(need at least 0x%x)", m->name, m->api_version, PR_MODULE_API_VERSION);
	exit(1);
    }

    if (!m->module_init_cb ||
        (m->module_init_cb() >= 0)) {
      xaset_insert(installed_modules, (xasetmember_t *) m);

      if (m->conftable)
        for (conf = m->conftable; conf->directive; conf++)
          ++numconf;

      if (m->cmdtable)
        for (cmd = m->cmdtable; cmd->command; cmd++)
          ++numcmd;

      if (m->authtable)
        for (auth = m->authtable; auth->name; auth++)
          ++numauth;

    } else
      log_pri(PR_LOG_ERR, "error: initialization of 'mod_%s' module failed",
        m->name);
  }

  /* Allow for an empty entry */
  ++numconf;
  ++numcmd;
  ++numauth;

  /* Create an array to store the master conf dispatch table */
  mconfarr = make_array(permanent_pool, numconf, sizeof(conftable));
  mcmdarr = make_array(permanent_pool, numcmd, sizeof(cmdtable));
  mautharr = make_array(permanent_pool, numauth, sizeof(authtable));

  for (m = (module *) installed_modules->xas_list; m; m = m->next) {

    if (m->conftable) {
      for (conf = m->conftable; conf->directive; conf++) {
        conftable *conftab = (conftable *) push_array(mconfarr);
        memcpy(conftab, conf, sizeof(conftable));
        conftab->m = m;

        pr_stash_add_symbol(PR_SYM_CONF, conftab);
      }
    }

    if (m->cmdtable) {
      for (cmd = m->cmdtable; cmd->command; cmd++) {
        cmdtable *cmdtab = (cmdtable *) push_array(mcmdarr);
        memcpy(cmdtab, cmd, sizeof(cmdtable));
        cmdtab->m = m;

        pr_stash_add_symbol(PR_SYM_CMD, cmdtab);
      }
    }

    if (m->authtable) {
      for (auth = m->authtable; auth->name; auth++) {
        authtable *authtab = (authtable *) push_array(mautharr);
        memcpy(authtab, auth, sizeof(authtable));
        authtab->m = m;

        pr_stash_add_symbol(PR_SYM_AUTH, authtab);
      }
    }
  }

  /* add a null entry (pcalloc zeros the memory for us) */
  push_array(mconfarr);
  push_array(mcmdarr);
  push_array(mautharr);

  m_conftable = (conftable *) mconfarr->elts;
  m_cmdtable = (cmdtable *) mcmdarr->elts;
  m_authtable = (authtable *) mautharr->elts;

  return 0;
}

int module_postparse_init(void) {
  module_cb_t *pp = NULL;

  if (!postparse_inits)
    return 0;

  for (pp = (module_cb_t *) postparse_inits->xas_list; pp; pp = pp->next)
    pp->module_cb();

  return 0;
}

void pr_register_daemon_startup(int (*cb)(void)) {
  module_cb_t *di = NULL;

  if (!daemon_cb_pool)
    daemon_cb_pool = make_sub_pool(permanent_pool);

  if (!daemon_startups)
    daemon_startups = xaset_create(daemon_cb_pool, NULL);

  di = pcalloc(daemon_cb_pool, sizeof(module_cb_t));
  di->module_cb = cb;

  xaset_insert(daemon_startups, (xasetmember_t *) di);
}

void pr_register_postparse_init(int (*cb)(void)) {
  module_cb_t *pp = NULL;

  if (!postparse_init_pool)
    postparse_init_pool = make_sub_pool(permanent_pool);

  if (!postparse_inits)
    postparse_inits = xaset_create(postparse_init_pool, NULL);

  pp = pcalloc(postparse_init_pool, sizeof(module_cb_t));
  pp->module_cb = cb;

  xaset_insert(postparse_inits, (xasetmember_t *) pp);
}

void module_remove_daemon_startups(void) {
  if (daemon_startups)
    daemon_startups = NULL;

  if (daemon_cb_pool) {
    destroy_pool(daemon_cb_pool);
    daemon_cb_pool = NULL;
  }
}

void module_remove_postparse_inits(void) {
  if (postparse_inits)
    postparse_inits = NULL;

  if (postparse_init_pool) {
    destroy_pool(postparse_init_pool);
    postparse_init_pool = NULL;
  }
}

int pr_init_stash(void) {
  if (symbol_pool)
    symbol_pool = make_sub_pool(permanent_pool); 
  memset(symbol_table, '\0', sizeof(symbol_table));

  return 0;
}
