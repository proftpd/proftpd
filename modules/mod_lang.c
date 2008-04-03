/*
 * ProFTPD: mod_lang -- a module for handling the LANG command [RFC2640]
 *
 * Copyright (c) 2006-2008 The ProFTPD Project
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
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * $Id: mod_lang.c,v 1.7 2008-04-03 01:34:18 castaglia Exp $
 */

#include "conf.h"

#define MOD_LANG_VERSION		"mod_lang/0.8"

#if PROFTPD_VERSION_NUMBER < 0x0001030101
# error "ProFTPD 1.3.1rc1 or later required"
#endif

#if PR_USE_NLS

module lang_module;

static const char *lang_default = "en";
static int lang_engine = TRUE;
static pool *lang_pool = NULL;
static pr_table_t *lang_tab = NULL;

/* Support routines
 */

static int lang_supported(const char *lang) {
  if (strcmp(lang, "en") != 0)
    return -1;

  return 0;
}

/* Configuration handlers
 */

/* usage: LangDefault lang */
MODRET set_langdefault(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: LangEngine on|off */
MODRET set_langengine(cmd_rec *cmd) {
  int bool;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

/* usage: LangPath path */
MODRET set_langpath(cmd_rec *cmd) {
  CHECK_CONF(cmd, CONF_ROOT);

  return PR_HANDLED(cmd);
}

/* usage: UseEncoding on|off|local-charset client-charset */
MODRET set_useencoding(cmd_rec *cmd) {
  config_rec *c;

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (cmd->argc == 2) {
    int bool = -1;

    bool = get_boolean(cmd, 1);
    if (bool == -1) {
      CONF_ERROR(cmd, "expected Boolean parameter");
    }

    c = add_config_param(cmd->argv[0], 1, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(int));
    *((int *) c->argv[0]) = bool;

  } else if (cmd->argc == 3) {
    c = add_config_param_str(cmd->argv[0], 2, cmd->argv[1], cmd->argv[2]);

  } else {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET lang_lang(cmd_rec *cmd) {
  unsigned char *authenticated;

  if (!lang_engine)
    return PR_DECLINED(cmd);

  if (!dir_check(cmd->tmp_pool, cmd->argv[0], cmd->group, session.cwd, NULL)) {
    pr_log_debug(DEBUG4, MOD_LANG_VERSION ": LANG command denied by <Limit>");
    pr_response_add_err(R_500, _("Unable to handle command"));
    return PR_ERROR(cmd);
  }

  /* If the user has already authenticated (and thus possibly chrooted),
   * deny the command.  Once chrooted, we will not have access to the
   * message catalog files anymore.
   *
   * True, the user may not have been chrooted, but if we allow non-chrooted
   * users to issue LANG commands while chrooted users cannot, it can
   * constitute an information leak.  Best to avoid that altogether.
   */
  authenticated = get_param_ptr(cmd->server->conf, "authenticated", FALSE);
  if (authenticated &&
      *authenticated == TRUE) {
    pr_response_add_err(R_500, _("Unable to handle command"));
    return PR_ERROR(cmd);
  }

  if (cmd->argc > 2) {
    pr_response_add_err(R_501, _("Invalid number of arguments"));
    return PR_ERROR(cmd);
  }

  if (cmd->argc == 1) {
    pr_log_debug(DEBUG7, MOD_LANG_VERSION
      ": resetting to default language '%s'", lang_default);

    /* XXX Reset stuff here */

    pr_response_add(R_200, _("Using default language %s"), lang_default);
    return PR_HANDLED(cmd);
  }

  if (lang_supported(cmd->argv[1]) < 0) {
    pr_response_add_err(R_504, _("Language %s not supported"), cmd->argv[1]);
    return PR_ERROR(cmd);
  }

  /* If successful, remove the previous FEAT line for LANG, and update it
   * with a new one showing the currently selected language.
   */

  /* XXX As currently implemented, pr_feat_remove() allows for a memory
   * leak in the feat pool.  This means that a malicious client could
   * send LANG repeatedly, and cause proftpd memory usage to grow
   * (albeit very slowly).  Perhaps the LANG command should only be
   * accepted N number of times?
   */

  pr_response_add(R_200, _("Using language %s"), cmd->argv[1]);
  return PR_HANDLED(cmd);
}

MODRET lang_utf8(cmd_rec *cmd) {
  register unsigned int i;
  int bool;
  const char *curr_encoding;
  char *method;

  method = pstrdup(cmd->tmp_pool, cmd->argv[0]);

  /* Convert underscores to spaces in the method name, for prettier
   * logging.
   */
  for (i = 0; method[i]; i++) {
    if (method[i] == '_')
      method[i] = ' ';
  }

  if (cmd->argc != 2) {
    pr_response_add_err(R_501, _("'%s' not understood"), method);
    return PR_ERROR(cmd);
  }

  bool = get_boolean(cmd, 1);
  if (bool < 0) {
    pr_response_add_err(R_501, _("'%s' not understood"), method);
    return PR_ERROR(cmd);
  }

  curr_encoding = pr_encode_get_encoding();

  if (pr_encode_is_utf8(curr_encoding) == TRUE) {
    if (bool) {
      /* Client requested that we use UTF8, and we already are.  Nothing
       * more needs to be done.
       */
      pr_response_add(R_200, _("UTF8 set to on"));

    } else {
      config_rec *c;

      /* Client requested that we NOT use UTF8, and we are.  Need to disable
       * encoding, then, unless the UseEncoding setting dictates that we
       * must.
       */

      c = find_config(main_server->conf, CONF_PARAM, "UseEncoding", FALSE);
      if (c) {
        /* We have explicit UseEncoding instructions; we cannot change
         * the encoding use as requested by the client.
         */
        pr_log_debug(DEBUG5, MOD_LANG_VERSION
          ": unable to accept 'OPTS UTF8 off' due to UseEncoding directive in "
          "config file");
        pr_response_add_err(R_451, _("Unable to accept %s"), method);
        return PR_ERROR(cmd);

      } else {
        pr_log_debug(DEBUG5, MOD_LANG_VERSION
          ": disabling use of UTF8 encoding as per client's request");

        /* No explicit UseEncoding instructions; we can turn off encoding. */
        pr_encode_disable_encoding();
        pr_fs_use_encoding(FALSE);

        pr_response_add(R_200, _("UTF8 set to off"));
      }
    }

  } else {

    if (bool) {
      config_rec *c;

      /* Client requested that we use UTF8, and we currently are not.
       * Enable UTF8 encoding, unless the UseEncoding setting dictates that
       * we cannot.
       */

      c = find_config(main_server->conf, CONF_PARAM, "UseEncoding", FALSE);
      if (c) {
        /* We have explicit UseEncoding instructions. */
        pr_log_debug(DEBUG5, MOD_LANG_VERSION
          ": unable to accept 'OPTS UTF8 on' due to UseEncoding directive in "
          "config file");
        pr_response_add_err(R_451, _("Unable to accept %s"), method);
        return PR_ERROR(cmd);

      } else {
        pr_log_debug(DEBUG5, MOD_LANG_VERSION
          ": enabling use of UTF8 encoding as per client's request");

        /* No explicit UseEncoding instructions; we can turn on encoding. */
        if (pr_encode_enable_encoding("UTF8") < 0) {
          pr_log_debug(DEBUG3, MOD_LANG_VERSION
            ": error enabling UTF8 encoding: %s", strerror(errno));
          pr_response_add_err(R_451, _("Unable to accept %s"), method);
          return PR_ERROR(cmd);

        } else {
          pr_fs_use_encoding(FALSE);
          pr_response_add(R_200, _("UTF8 set to off"));
        }
      }

    } else {
      /* Client requested that we not use UTF8, and we are not.  Nothing more
       * needs to be done.
       */
      pr_response_add(R_200, _("UTF8 set to off"));
    }
  }

  return PR_HANDLED(cmd);
}

/* Event handlers
 */

static void lang_postparse_ev(const void *event_data, void *user_data) {
  config_rec *c;

  /* Scan the LangPath for the .mo files to read in. */
  const char *lang_path = PR_LOCALE_DIR;
#ifdef HAVE_LIBINTL_H
  const char *locale_path = NULL;
#endif

  c = find_config(main_server->conf, CONF_PARAM, "LangPath", FALSE);
  if (c) {

    /* XXX How to make the configured path exported to any interested
     * callers, e.g. modules that need to call bindtextdomain() for
     * their own catalogs?
     */

    lang_path = c->argv[0];
  }

#ifdef HAVE_LIBINTL_H
  pr_log_debug(DEBUG4, MOD_LANG_VERSION
    ": binding to text domain 'proftpd' using locale path '%s'", lang_path);
  locale_path = bindtextdomain("proftpd", lang_path); 
  if (locale_path == NULL) {
    pr_log_pri(PR_LOG_NOTICE, MOD_LANG_VERSION
      ": unable to bind to text domain 'proftpd' using locale path '%s': %s",
      lang_path, strerror(errno));
  }
#else
  pr_log_debug(DEBUG2, MOD_LANG_VERSION
    ": unable to bind to text domain 'proftpd', lacking libintl support");
#endif /* !HAVE_LIBINTL_H */

  /* Iterate through the server_rec list, checking each for a configured
   * LangDefault.  If configured, make sure that the specified lang
   * is supported.
   */

  c = find_config(main_server->conf, CONF_PARAM, "LangDefault", FALSE);
  if (c) {

    /* If the selected default language is not in LangPath,
     * default to "en".
     */
  }
}

static void lang_restart_ev(const void *event_data, void *user_data) {
  destroy_pool(lang_pool);
  lang_tab = NULL;

  lang_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(lang_pool, MOD_LANG_VERSION);
}

/* Initialization functions
 */

static int lang_init(void) {
  if (setlocale(LC_ALL, "") == NULL) {
    pr_log_pri(PR_LOG_NOTICE, "unable to set LC_ALL: %s", strerror(errno));
    return -1;
  }

  /* Preserve the POSIX/portable handling of number formatting; local
   * formatting of decimal points, for example, can cause problems with
   * numbers in SQL queries.
   */
  if (setlocale(LC_NUMERIC, "C") == NULL) {
    pr_log_pri(PR_LOG_NOTICE, "unable to set LC_NUMERIC: %s",
      strerror(errno));
  }

  lang_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(lang_pool, MOD_LANG_VERSION);

  pr_event_register(&lang_module, "core.postparse", lang_postparse_ev, NULL);
  pr_event_register(&lang_module, "core.restart", lang_restart_ev, NULL);

  return 0;
}

static int lang_sess_init(void) {
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "LangEngine", FALSE);
  if (c)
    lang_engine = *((int *) c->argv[0]);

  if (!lang_engine)
    return 0;

  c = find_config(main_server->conf, CONF_PARAM, "UseEncoding", FALSE);
  if (c) {
    if (c->argc == 1) {
      int bool;

      bool = *((int *) c->argv[0]);
      if (bool) {
        pr_feat_add("UTF8");
        pr_fs_use_encoding(TRUE);

      } else {
        pr_fs_use_encoding(FALSE);
      }

    } else {
      char *local_charset, *client_charset;

      local_charset = c->argv[0];
      client_charset = c->argv[1];

      if (pr_encode_set_charset_encoding(local_charset, client_charset) < 0) {
        pr_log_pri(PR_LOG_NOTICE, MOD_LANG_VERSION
          ": error setting local charset '%s', client charset '%s': %s",
          local_charset, client_charset, strerror(errno));
        pr_fs_use_encoding(FALSE);

      } else {
        pr_log_debug(DEBUG3, MOD_LANG_VERSION ": using local charset '%s', "
          "client charset '%s' for path encoding", local_charset,
          client_charset);
        pr_fs_use_encoding(TRUE);

        /* If the client charset specified happens to be UTF8, we need to
         * make sure it shows up in FEAT.
         */
        if (strcasecmp(client_charset, "UTF8") == 0 ||
            strcasecmp(client_charset, "UTF-8") == 0) {
          pr_feat_add("UTF8");
        }
      }
    }

  } else {
    /* Default is to use UTF8. */
    pr_feat_add("UTF8");
    pr_fs_use_encoding(TRUE);
  }

  /* Configure a proper FEAT line, for our supported languages and our
   * default language.
   */
  pr_feat_add("LANG en");

  return 0;
}

/* Module API tables
 */

static conftable lang_conftab[] = {
  { "LangDefault",	set_langdefault,	NULL },
  { "LangEngine",	set_langengine,		NULL },
  { "LangPath",		set_langpath,		NULL },
  { "UseEncoding",	set_useencoding,	NULL },
  { NULL }
};

static cmdtable lang_cmdtab[] = {
  { CMD,	C_LANG,			G_NONE,	lang_lang,	FALSE,	FALSE },
  { CMD,	C_OPTS "_UTF8",		G_NONE,	lang_utf8,	FALSE,	FALSE },
  { 0, NULL }
};

module lang_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "lang",

  /* Module configuration handler table */
  lang_conftab,

  /* Module command handler table */
  lang_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  lang_init,

  /* Session initialization function */
  lang_sess_init,

  /* Module version */
  MOD_LANG_VERSION
};

#endif /* PR_USE_NLS */
