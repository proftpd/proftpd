/*
 * ProFTPD: mod_wrap2_file -- a mod_wrap2 sub-module for supplying IP-based
 *                            access control data via file-based tables
 *
 * Copyright (c) 2002-2007 TJ Saunders
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
 * As a special exemption, TJ Saunders gives permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 *
 * $Id: mod_wrap2_file.c,v 1.2 2007-06-25 22:55:55 castaglia Exp $
 */

#include "mod_wrap2.h"

#define MOD_WRAP2_FILE_VERSION		"mod_wrap2_file/1.1"

static char *filetab_clients_list = NULL;
static char *filetab_daemons_list = NULL;
static char *filetab_options_list = NULL;

#ifndef MOD_WRAP2_FILE_BUFFER_SIZE
# define MOD_WRAP2_FILE_BUFFER_SIZE	PR_TUNABLE_BUFFER_SIZE
#endif

static void filetab_parse_table(wrap2_table_t *filetab) {
  unsigned int lineno = 0;
  char buf[MOD_WRAP2_FILE_BUFFER_SIZE] = {'\0'};

  while (pr_fsio_getline(buf, sizeof(buf), (pr_fh_t *) filetab->tab_handle,
      &lineno) != NULL) {
    size_t buflen = strlen(buf);

    if (buf[buflen - 1] != '\n') {
      wrap2_log("file '%s': missing newline or line too long (%u) at %u",
        filetab->tab_name, buflen, lineno);
      continue;
    } 

    if (buf[0] == '#' || buf[strspn(buf, " \t\r\n")] == 0)
      continue;

    filetab_daemons_list = buf;

    filetab_clients_list = wrap2_strsplit(buf, ':');
    if (filetab_clients_list == 0) {
      wrap2_log("file '%s': missing \":\" separator at %u",
        filetab->tab_name, lineno);
      continue;
    }

    filetab_options_list = wrap2_strsplit(filetab_clients_list, ':');    
  }
}

static int filetab_close_cb(wrap2_table_t *filetab) {
  int res = pr_fsio_close((pr_fh_t *) filetab->tab_handle);
  filetab->tab_handle = NULL;
  return res;
}

static char *filetab_fetch_clients_cb(wrap2_table_t *filetab,
    const char *name) {

  /* If this table/file has not yet been parsed, parse it. */
  if (*((unsigned char *) filetab->tab_data) == FALSE) {
    filetab_parse_table(filetab);    
    *((unsigned char *) filetab->tab_data) = TRUE;
  }

  return filetab_clients_list;
}

static char *filetab_fetch_daemons_cb(wrap2_table_t *filetab,
    const char *name) {

  /* If this table/file has not yet been parsed, parse it. */
  if (*((unsigned char *) filetab->tab_data) == FALSE) {
    filetab_parse_table(filetab);
    *((unsigned char *) filetab->tab_data) = TRUE;
  }

  return filetab_daemons_list;
}

static char *filetab_fetch_options_cb(wrap2_table_t *filetab,
    const char *name) {

  /* If this table/file has not yet been parsed, parse it. */
  if (*((unsigned char *) filetab->tab_data) == FALSE) {
    filetab_parse_table(filetab);
    *((unsigned char *) filetab->tab_data) = TRUE;
  }

  return filetab_options_list;
}

static wrap2_table_t *filetab_open_cb(pool *parent_pool, char *srcinfo) {
  wrap2_table_t *tab = NULL;
  pool *tab_pool = make_sub_pool(parent_pool);

  /* Do not allow relative paths. */
  if (*srcinfo != '/' &&
      *srcinfo != '~') {
    wrap2_log("error: table relative paths are forbidden: '%s'", srcinfo);
    destroy_pool(tab_pool);
    errno = EINVAL;
    return NULL;
  }

  /* If the path starts with a tilde, expand it out. */
  if (srcinfo[0] == '~' &&
      srcinfo[1] == '/') {
    char *path = NULL;

    PRIVS_USER
    path = dir_realpath(tab_pool, srcinfo);
    PRIVS_RELINQUISH

    if (path)
      srcinfo = path;
  }

  tab = (wrap2_table_t *) pcalloc(tab_pool, sizeof(wrap2_table_t));
  tab->tab_pool = tab_pool;

  /* Open the table handle */
  while ((tab->tab_handle = (void *) pr_fsio_open(srcinfo, O_RDONLY)) == NULL) {
    if (errno == EINTR) {
      pr_signals_handle();
      continue;
    }

    destroy_pool(tab->tab_pool);
    return NULL;
  }

  tab->tab_name = pstrdup(tab->tab_pool, srcinfo);

  /* Set the necessary callbacks. */
  tab->tab_close = filetab_close_cb;
  tab->tab_fetch_clients = filetab_fetch_clients_cb;
  tab->tab_fetch_daemons = filetab_fetch_daemons_cb;
  tab->tab_fetch_options = filetab_fetch_options_cb;

  /* Use the tab_data member as a Boolean flag. */
  tab->tab_data = pcalloc(tab->tab_pool, sizeof(unsigned char));
  *((unsigned char *) tab->tab_data) = FALSE;

  return tab;
}

static int filetab_init(void) {

  /* Initialize the wrap source objects for type "file". */
  wrap2_register("file", filetab_open_cb);

  return 0;
}

module wrap2_file_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "wrap2_file",

  /* Module configuration handler table */
  NULL,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  filetab_init,

  /* Session initialization function */
  NULL,

  /* Module version */
  MOD_WRAP2_FILE_VERSION
};
