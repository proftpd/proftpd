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
 * Module handling routines
 */

#include "conf.h"

/* local symbol hash structure to vastly speed up module symbol lookups
 */
#define SYM_CONF				1
#define SYM_CMD					2
#define SYM_AUTH				3

struct symbol_hash {
  struct	symbol_hash *next,*prev;
  char		*sym_name;			/* pointer to the directive,
                                                   command, or other symbol */
  char		sym_type;			/* one of the SYM_* macros */
  module	*sym_module;

  union {
    conftable	*sym_conf;
    cmdtable    *sym_cmd;
    authtable	*sym_auth;
    void	*sym_generic;
  } ptr;
};

/* symbol hashes for each type */
xaset_t *authsymtab[PR_TUNABLE_HASH_TABLE_SIZE];
static xaset_t *symtable[PR_TUNABLE_HASH_TABLE_SIZE];

static xaset_t *installed_modules = NULL;
static array_header *mconfarr;			/* masterconf array */
static array_header *mcmdarr;			/* mastercmd array */
static array_header *mautharr;			/* masterauth array */

conftable *m_conftable; 			/* Master conf table */
cmdtable *m_cmdtable;				/* Master cmd table */
authtable *m_authtable;				/* Master auth table */

module *curmodule = NULL;			/* Current running module */

extern module *static_modules[];

typedef struct postparse_cb {
  struct postparse_cb *next, *prev;

  int (*module_postparse_init_cb)(void);
} postparse_t;

static pool *postparse_init_pool = NULL;
static xaset_t *postparse_inits = NULL;

/* hash lookup code and management */

static int authsym_cmp(pr_authsym_t *authsym1, pr_authsym_t *authsym2) {
  int result;

  result = strcmp(authsym1->name, authsym2->name);

  /* Higher priority modules must go BEFORE lower priority modules in the
   * hash table.
   */
  if (!result) {
    if (authsym1->module->auth_priority > authsym2->module->auth_priority)
      result = -1;

    else if (authsym1->module->auth_priority < authsym2->module->auth_priority)
      result = 1;
  }

  return result;
}

static int sym_cmp(struct symbol_hash *s1, struct symbol_hash *s2) {
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

static int _hash_index(char *name) {
  unsigned char *cp;
  int total = 0;

  for (cp = (unsigned char *)name; *cp; cp++)
    total += (int)*cp;

  return (total < PR_TUNABLE_HASH_TABLE_SIZE ? total :
    (total % PR_TUNABLE_HASH_TABLE_SIZE));
}

static int _hash_insert(struct symbol_hash *sym) {
  int idx;

  idx = _hash_index(sym->sym_name);
  if (!symtable[idx])
    symtable[idx] = xaset_create(permanent_pool, (XASET_COMPARE) sym_cmp);

  xaset_insert_sort(symtable[idx], (xasetmember_t *)sym, TRUE);
  return idx;
}

static int _hash_insert_conf(conftable *conf) {
  struct symbol_hash *sym;

  sym = pcalloc(permanent_pool,sizeof(struct symbol_hash));
  sym->sym_type = SYM_CONF;
  sym->sym_name = conf->directive;
  sym->ptr.sym_conf = conf;
  sym->sym_module = conf->m;
  return _hash_insert(sym);
}

static int _hash_insert_cmd(cmdtable *cmd) {
  struct symbol_hash *sym;

  sym = pcalloc(permanent_pool,sizeof(struct symbol_hash));
  sym->sym_type = SYM_CMD;
  sym->sym_name = cmd->command;
  sym->ptr.sym_cmd = cmd;
  sym->sym_module = cmd->m;
  return _hash_insert(sym);
}

static int _hash_insert_auth(authtable *auth) {
  struct symbol_hash *sym;

  sym = pcalloc(permanent_pool,sizeof(struct symbol_hash));
  sym->sym_type = SYM_AUTH;
  sym->sym_name = auth->name;
  sym->ptr.sym_auth = auth;
  sym->sym_module = auth->m;

  insert_authsym(authsymtab, auth);

  return _hash_insert(sym);
}

int insert_authsym(xaset_t **authsym_tab, authtable *authtab) {
  pool *authsym_pool = NULL;
  pr_authsym_t *authsym = NULL;
  unsigned int idx = 0;

  /* Determine the hash/index for this auth symbol. */
  idx = _hash_index(authtab->name);

  /* Allocate memory for the auth hash table, if necessary. */
  authsym_pool = make_sub_pool(permanent_pool);

  if (!authsym_tab[idx])
    authsym_tab[idx] = xaset_create(authsym_pool,
      (XASET_COMPARE) authsym_cmp);

  /* Due to the way in which xaset_create() assigns the mempool member
   * of an xaset_t, the passed in pool (in the above call, authsym_pool)
   * _is_ the mempool member, so it can be reused here.  Doesn't mean it
   * _should_ be that way, though.
   */
  authsym = pcalloc(authsym_pool, sizeof(pr_authsym_t));

  authsym->name = authtab->name;
  authsym->module = authtab->m;
  authsym->table = authtab;

  /* Insert the symbol into the hash in sorted order. */
  return xaset_insert_sort(authsym_tab[idx], (xasetmember_t *) authsym, TRUE);
}

static pr_authsym_t *authsym_find(int idx, char *symbol) {
  pr_authsym_t *authsym = NULL;

  if (symbol && authsymtab[idx]) {
    for (authsym = (pr_authsym_t *) authsymtab[idx]->xas_list; authsym;
        authsym = authsym->next)

      /* this comparison is here to handle possible hash collisions */
      if (!strcmp(authsym->name, symbol))
        break;
  }

  return authsym;
}

static pr_authsym_t *authsym_find_next(int idx, char *symbol,
    authtable *prev) {
  pr_authsym_t *authsym = NULL;
  int last_hit = 0;

  if (authsymtab[idx]) {
    for (authsym = (pr_authsym_t *) authsymtab[idx]->xas_list; authsym;
        authsym = authsym->next)

      /* this comparison is here to handle possible hash collisions */
      if (last_hit && !strcmp(authsym->name, symbol))
        break;
      if (authsym->table == prev)
        last_hit++;
  }

  return authsym;
}

static struct symbol_hash *_hash_find(int idx, char *name, int type) {
  struct symbol_hash *sym = NULL;

  if (name && symtable[idx]) {
    for (sym = (struct symbol_hash *) symtable[idx]->xas_list; sym;
        sym = sym->next)
      if (sym->sym_type == type && !strcmp(sym->sym_name, name))
        break;
  }

  return sym;
}

static struct symbol_hash *_hash_find_next(int idx, char *name, int type,
    void *last) {
  struct symbol_hash *sym = NULL;
  int last_hit = 0;

  if (symtable[idx]) {
    for (sym = (struct symbol_hash *) symtable[idx]->xas_list; sym;
        sym = sym->next) {
      if (last_hit && sym->sym_type == type && !strcmp(sym->sym_name, name))
        break;
      if (sym->ptr.sym_generic == last)
        last_hit++;
    }
  }

  return sym;
}

conftable *mod_find_conf_symbol(char *name, int *idx_cache, conftable *last) {
  int idx;
  struct symbol_hash *sym;

  if (idx_cache && *idx_cache != -1)
    idx = *idx_cache;

  else {
    idx = _hash_index(name);
    if (idx_cache)
      *idx_cache = idx;
  }

  if (last)
    sym = _hash_find_next(idx, name, SYM_CONF, last);
  else
    sym = _hash_find(idx, name, SYM_CONF);

  return (sym ? sym->ptr.sym_conf : NULL);
}

cmdtable *mod_find_cmd_symbol(char *name, int *idx_cache, cmdtable *last) {
  int idx;
  struct symbol_hash *sym;

  if (idx_cache && *idx_cache != -1)
    idx = *idx_cache;

  else {
    idx = _hash_index(name);
    if (idx_cache)
      *idx_cache = idx;
  }

  if (last)
    sym = _hash_find_next(idx, name, SYM_CMD, last);
  else
    sym = _hash_find(idx, name, SYM_CMD);

  return (sym ? sym->ptr.sym_cmd : NULL);
}

authtable *mod_find_auth_symbol(char *name, int *idx_cache, authtable *last) {
  int idx;
  struct symbol_hash *sym;

  if (idx_cache && *idx_cache != -1)
    idx = *idx_cache;

  else {
    idx = _hash_index(name);
    if (idx_cache)
      *idx_cache = idx;
  }

  if (last)
    sym = _hash_find_next(idx, name, SYM_AUTH, last);
  else
    sym = _hash_find(idx, name, SYM_AUTH);

  return (sym ? sym->ptr.sym_auth : NULL);
}

authtable *get_auth_symbol(char *symbol, int *cached_idx, authtable *prev) {
  int idx;
  pr_authsym_t *authsym;

  if (cached_idx && *cached_idx != -1) {
    idx = *cached_idx;

  } else {
    idx = _hash_index(symbol);

    if (cached_idx)
      *cached_idx = idx;
  }

  if (prev)
    authsym = authsym_find_next(idx, symbol, prev);
  else
    authsym = authsym_find(idx, symbol);

  return (authsym ? authsym->table : NULL);
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
  p->m = curmodule;

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
    m = curmodule;

  for (i = 0, p = (privdata_t**)cmd->privarr->elts; i < cmd->privarr->nelts; i++, p++) {
    if (!strcmp((*p)->tag,tag) && (m == ANY_MODULE || (*p)->m == m))
      break;
  }

  return (i < cmd->privarr->nelts ? *p : NULL);
}

modret_t *call_module_auth(module *m, modret_t *(*func)(cmd_rec*), cmd_rec *cmd)
{
  modret_t *res;
  module *prev_module = curmodule;

  if (!cmd->tmp_pool)
    cmd->tmp_pool = make_sub_pool(cmd->pool);

  curmodule = m;
  res = func(cmd);
  curmodule = prev_module;

  return res;
}

modret_t *call_module_cmd(module *m, modret_t *(*func)(cmd_rec*), cmd_rec *cmd)
{
  modret_t *res;
  module *prev_module = curmodule;

  if (!cmd->tmp_pool)
    cmd->tmp_pool = make_sub_pool(cmd->pool);

  curmodule = m;
  res = func(cmd);
  curmodule = prev_module;

  return res;
}

modret_t *call_module(module *m, modret_t *(*func)(cmd_rec*), cmd_rec *cmd)
{
  modret_t *res;
  module *prev_module = curmodule;

  if (!cmd->tmp_pool)
    cmd->tmp_pool = make_sub_pool(cmd->pool);

  curmodule = m;
  res = func(cmd);
  curmodule = prev_module;

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
  ret->mr_handler_module = curmodule;
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
  ret->mr_handler_module = curmodule;
  ret->mr_error = mr_errno;

  return ret;
}

/* Called after forking in order to inform/initialize modules
 * need to know we are a child and have a connection.
 */
int module_session_init(void) {
  module *prev_module = curmodule;
  module *m;

  for (m = (module*) installed_modules->xas_list; m; m=m->next)
    if (m && m->module_init_session_cb) {
      curmodule = m;
      m->module_init_session_cb();
    }

  curmodule = prev_module;
  return 0;
}

unsigned char command_exists(char *name) {
  cmdtable *cmdtab = mod_find_cmd_symbol(name, NULL, NULL);

  while (cmdtab && cmdtab->cmd_type != CMD)
    cmdtab = mod_find_cmd_symbol(name, NULL, cmdtab);

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

int module_preparse_init(void) {
  int numconf = 0,numcmd = 0,numauth = 0;
  module *m;
  conftable *c,*wrk;
  cmdtable *cmd,*cmdwrk;
  authtable *auth,*authwrk;
  register unsigned int i = 0;

  memset(symtable, '\0', sizeof(symtable));
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
        (m->module_init_cb() != -1)) {
      xaset_insert(installed_modules, (xasetmember_t*)m);

      if (m->conftable)
        for (c = m->conftable; c->directive; c++)
          ++numconf;

      if (m->cmdtable)
        for (cmd = m->cmdtable; cmd->command; cmd++)
          ++numcmd;

      if (m->authtable)
        for (auth = m->authtable; auth->name; auth++)
          ++numauth;
    }
  }

  /* Allow for an empty entry */
  ++numconf;
  ++numcmd;
  ++numauth;

  /* Create an array to store the master conf dispatch table */
  mconfarr = make_array(permanent_pool, numconf, sizeof(conftable));
  mcmdarr = make_array(permanent_pool, numcmd, sizeof(cmdtable));
  mautharr = make_array(permanent_pool, numauth, sizeof(authtable));

  for (m = (module*)installed_modules->xas_list; m; m=m->next) {

    if (m->conftable)
      for (c = m->conftable; c->directive; c++) {
        wrk = (conftable*)push_array(mconfarr);
        memcpy(wrk, c, sizeof(conftable));
        wrk->m = m;

        /* insert into our hash table */
        _hash_insert_conf(wrk);
      }

    if (m->cmdtable)
      for (cmd = m->cmdtable; cmd->command; cmd++) {
        cmdwrk = (cmdtable*)push_array(mcmdarr);
        memcpy(cmdwrk, cmd, sizeof(cmdtable));
        cmdwrk->m = m;

        _hash_insert_cmd(cmdwrk);
      }

    if (m->authtable)
      for (auth = m->authtable; auth->name; auth++) {
        authwrk = (authtable*)push_array(mautharr);
        memcpy(authwrk, auth, sizeof(authtable));
        authwrk->m = m;

        _hash_insert_auth(authwrk);
      }
  }

  /* add a null entry (pcalloc zeros the memory for us) */
  push_array(mconfarr);
  push_array(mcmdarr);
  push_array(mautharr);

  m_conftable = (conftable*)mconfarr->elts;
  m_cmdtable = (cmdtable*)mcmdarr->elts;
  m_authtable = (authtable*)mautharr->elts;

  return 0;
}

int module_postparse_init(void) {
  postparse_t *pp = NULL;

  if (!postparse_inits)
    return 0;

  for (pp = (postparse_t *) postparse_inits->xas_list; pp; pp = pp->next)
    pp->module_postparse_init_cb();

  return 0;
}

void pr_register_postparse_init(int (*cb)(void)) {
  postparse_t *pp = NULL;

  if (!postparse_init_pool)
    postparse_init_pool = make_sub_pool(permanent_pool);

  if (!postparse_inits)
    postparse_inits = xaset_create(postparse_init_pool, NULL);

  pp = pcalloc(postparse_init_pool, sizeof(postparse_t));
  pp->module_postparse_init_cb = cb;

  xaset_insert(postparse_inits, (xasetmember_t *) pp);
}

void module_remove_postparse_inits(void) {
  if (postparse_inits)
    postparse_inits = NULL;

  if (postparse_init_pool) {
    destroy_pool(postparse_init_pool);
    postparse_init_pool = NULL;
  }
}

