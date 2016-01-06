/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2016 The ProFTPD Project team
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
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, Public Flood Software/MacGyver aka Habeeb J. Dihu
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

/* Path hiding module */

#include "conf.h"
#include "privs.h"

#define MOD_HIDING_VERSION		"mod_hiding/0.5"

module hiding_module;

/* Configuration handlers
 */

/* usage: HideFiles [!]pattern */
MODRET set_hidefiles(cmd_rec *cmd) {
#ifdef PR_USE_REGEX
  pr_regex_t *pre = NULL;
  config_rec *c = NULL;
  unsigned int precedence = 0;
  unsigned char negated = FALSE, none = FALSE;
  char *ptr;

  int ctxt = (cmd->config && cmd->config->config_type != CONF_PARAM ?
    cmd->config->config_type : cmd->server->config_type ?
    cmd->server->config_type : CONF_ROOT);

  /* This directive must have either 1, or 3, arguments */
  if (cmd->argc-1 != 1 &&
      cmd->argc-1 != 3) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_DIR|CONF_DYNDIR);

  /* Set the precedence for this config_rec based on its configuration
   * context.
   */
  if (ctxt & CONF_DIR) {
    precedence = 1;

  } else {
    precedence = 2;
  }

  /* Check for a leading '!' prefix, signifying regex negation */
  ptr = cmd->argv[1];
  if (*ptr == '!') {
    negated = TRUE;
    ptr++;

  } else {
    /* Check for a "none" argument, which is used to nullify inherited
     * HideFiles configurations from parent directories.
     */
    if (strcasecmp(ptr, "none") == 0) {
      none = TRUE;
    }
  }

  if (!none) {
    int res;

    pre = pr_regexp_alloc(&hiding_module);

    res = pr_regexp_compile(pre, ptr, REG_EXTENDED|REG_NOSUB);
    if (res != 0) {
      char errstr[200] = {'\0'};

      pr_regexp_error(res, pre, errstr, sizeof(errstr));
      pr_regexp_free(NULL, pre);

      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", ptr,
        "' failed regex compilation: ", errstr, NULL));
    }
  }

  /* If the directive was used with 3 arguments, then the optional
   * classifiers, and classifier expression, were used.  Make sure that
   * a valid classifier was used.
   */
  if (cmd->argc-1 == 3) {
    if (strncmp(cmd->argv[2], "user", 5) == 0 ||
        strncmp(cmd->argv[2], "group", 6) == 0 ||
        strncmp(cmd->argv[2], "class", 6) == 0) {

      /* no-op */

    } else {
      return PR_ERROR_MSG(cmd, NULL, pstrcat(cmd->tmp_pool, cmd->argv[0],
        ": unknown classifier used: '", cmd->argv[2], "'", NULL));
    }
  }

  if (cmd->argc-1 == 1) {
    c = add_config_param(cmd->argv[0], 3, NULL, NULL, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(pr_regex_t *));
    *((pr_regex_t **) c->argv[0]) = pre;
    c->argv[1] = pcalloc(c->pool, sizeof(unsigned char));
    *((unsigned char *) c->argv[1]) = negated;
    c->argv[2] = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) c->argv[2]) = precedence;

  } else if (cmd->argc-1 == 3) {
    array_header *acl = NULL;
    int argc = cmd->argc - 3;
    void **argv;

    argv = &(cmd->argv[2]);

    acl = pr_expr_create(cmd->tmp_pool, &argc, (char **) argv);
    if (acl == NULL) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error creating expression: ",
        strerror(errno), NULL));
    }

    c = add_config_param(cmd->argv[0], 0);
    c->argc = argc + 4;

    /* Add 5 to argc for the argv of the config_rec: one for the
     * regexp, one for the 'negated' value, one for the precedence,
     * one for the classifier, and one for the terminating NULL
     */
    c->argv = pcalloc(c->pool, ((argc + 5) * sizeof(void *)));

    /* Capture the config_rec's argv pointer for doing the by-hand
     * population.
     */
    argv = c->argv;

    /* Copy in the regexp. */
    *argv = pcalloc(c->pool, sizeof(pr_regex_t *));
    *((pr_regex_t **) *argv++) = pre;

    /* Copy in the 'negated' flag */
    *argv = pcalloc(c->pool, sizeof(unsigned char));
    *((unsigned char *) *argv++) = negated;

    /* Copy in the precedence. */
    *argv = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) *argv++) = precedence;

    /* Copy in the expression classifier */
    *argv++ = pstrdup(c->pool, cmd->argv[2]);

    /* now, copy in the expression arguments */
    if (argc && acl) {
      while (argc-- > 0) {
        *argv++ = pstrdup(c->pool, *((char **) acl->elts));
        acl->elts = ((char **) acl->elts) + 1;
      }
    }

    /* don't forget the terminating NULL */
    *argv = NULL;
  }

  c->flags |= CF_MERGEDOWN_MULTI;
  return PR_HANDLED(cmd);

#else /* no regular expression support at the moment */
  CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "The HideFiles directive cannot be "
    "used on this system, as you do not have POSIX compliant regex support",
    NULL));
#endif
}

MODRET set_hidegroup(cmd_rec *cmd) {
  config_rec *c = NULL;
  char *group = NULL;
  int inverted = FALSE;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ANON|CONF_DIR);

  group = cmd->argv[1];
  if (*group == '!') {
    inverted = TRUE;
    group++;
  }

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  c->argv[0] = pstrdup(c->pool, group);
  c->argv[1] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[1]) = inverted;

  c->flags |= CF_MERGEDOWN;
  return PR_HANDLED(cmd);
}

MODRET set_hidenoaccess(cmd_rec *cmd) {
  int no_access = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ANON|CONF_DIR);

  no_access = get_boolean(cmd, 1);
  if (no_access == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = no_access;
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

MODRET set_hideuser(cmd_rec *cmd) {
  config_rec *c = NULL;
  char *user = NULL;
  int inverted = FALSE;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ANON|CONF_DIR);

  user = cmd->argv[1];
  if (*user == '!') {
    inverted = TRUE;
    user++;
  }

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  c->argv[0] = pstrdup(c->pool, user);
  c->argv[1] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[1]) = inverted;

  c->flags |= CF_MERGEDOWN;
  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET hiding_post_pass(cmd_rec *cmd) {
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "UseHiding", FALSE);
  if (c != NULL) {
  }

  return PR_DECLINED(cmd);
}

/* Event listeners
 */

#if defined(PR_SHARED_MODULE)
static void hiding_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp((char *) event_data, "mod_hiding.c") == 0) {
    pr_event_unreigster(&hiding_module, NULL, NULL);
    pr_hiding_unregister(&hiding_module, NULL);
  }
}
#endif /* PR_SHARED_MODULE */

/* Module initialization
 */
static int hiding_mod_init(void) {
#if defined(PR_SHARED_MODULE)
  pr_event_register(&hiding_module, "core.module-unload", hiding_mod_unload_ev,
    NULL);
#endif /* PR_SHARED_MODULE */

  return 0;
}

static int hiding_sess_init(void) {
  return 0;
}

/* Module API tables
 */

static conftable hiding_conftab[] = {
  { "HideFiles",		set_hidefiles,		NULL },
  { "HideGroup",		set_hidegroup,		NULL },
  { "HideNoAccess",		set_hidenoaccess,	NULL },
  { "HideUser",			set_hideuser,		NULL },

  { NULL, NULL, NULL }
};

static cmdtable hiding_cmdtab[] = {
  { POST_CMD,	C_PASS,	G_NONE,	hiding_post_pass, FALSE, FALSE,	CL_AUTH },
  { 0, NULL }
};

module hiding_module = {
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "hiding",

  /* Module configuration directive table */
  hiding_conftab,

  /* Module command handler table */
  hiding_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  hiding_mod_init,

  /* Session initialization function */
  hiding_sess_init,

  /* Module version */
  MOD_HIDING_VERSION
};
