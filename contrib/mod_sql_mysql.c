/*
 * ProFTPD: mod_mysql -- Support for connecting to MySQL databases.
 * Time-stamp: <1999-10-04 03:21:21 root>
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

#define MOD_SQL_MYSQL_VERSION "mod_sql_mysql/3.0"

/* -- DO NOT MODIFY THE LINE BELOW UNLESS YOU FEEL LIKE IT --
 * $Libraries: -lm -lmysqlclient $
 */

/* This is mod_mysql, contrib software for proftpd 1.2.0pre3 and above.
   For more information contact Johnie Ingram <johnie@netgod.net>.

   History Log:

   * 2001-02-07: Fixed Bug #457 -- "Speed improvement for mod_mysql" 
     <aah@acm.org>

   * 2001-02-07: Fixed Bug #458 -- "mysql.h requirement breaks module 
     independence" <aah@acm.org>

   * 1999-09-19: v2.0: Most directives split into mod_sql; invented API.

*/

#include "conf.h"
#include <mysql/mysql.h>

/* *INDENT-OFF* */

static MYSQL mod_mysql_server;
static MYSQL *mysqldb = 0;

struct sqldata_struc {
  int rowcount;
  int fieldcount;
  char **data;
};

typedef struct sqldata_struc sqldata_t;

/* Maximum username field to expect, etc. */
#define ARBITRARY_MAX                   128

static struct
{
  char *sql_host;   /* Data for connecting, set by MySQLInfo. */
  char *sql_user;
  char *sql_pass;
  char *sql_dbname;
  
  unsigned int sql_port;

  int ok;
  int opens;
} g;

/* *INDENT-ON* */

/* **************************************************************** */

MODRET sql_cmd_close(cmd_rec * cmd)
{
  log_debug(DEBUG5, "%s: close [%i] for %s", MOD_SQL_MYSQL_VERSION, g.opens,
            cmd->argv[0]);

  if (!g.ok || g.opens--)
    return DECLINED(cmd);

  if (mysqldb) {
    log_debug(DEBUG4, "%s: disconnecting: %s", MOD_SQL_MYSQL_VERSION,
              mysql_stat(mysqldb));
    mysql_close(mysqldb);
  }
  mysqldb = NULL;
  return DECLINED(cmd);
}

MODRET sql_cmd_open(cmd_rec * cmd)
{
  if (!g.ok)
    return DECLINED(cmd);

  g.opens++;

  log_debug(DEBUG5, "%s: open [%i] for %s", MOD_SQL_MYSQL_VERSION, g.opens,
            cmd->argv[0]);

  if (g.opens > 1)
    return HANDLED(cmd);

  mysql_init(&mod_mysql_server);
  mysqldb = mysql_real_connect(&mod_mysql_server, g.sql_host,
                               g.sql_user, g.sql_pass, g.sql_dbname,
                               g.sql_port, NULL, 0);

  if (!mysqldb) {
    log_pri(LOG_ERR, "%s: client %s connect FAILED to %s@%s",
            MOD_SQL_MYSQL_VERSION, mysql_get_client_info(), g.sql_user,
            g.sql_host);
    g.ok = FALSE;
    g.opens = 0;
    return DECLINED(cmd);
  }

  log_debug(DEBUG5, "%s: connect OK %s -> %s (%s@%s)", MOD_SQL_MYSQL_VERSION,
            mysql_get_client_info(), mysql_get_server_info(mysqldb),
            g.sql_user, g.sql_host);

  return HANDLED(cmd);
}

MODRET _do_query(cmd_rec * cmd, const char *query, int update)
{
  int error = 1;

  if (!g.ok)
    return DECLINED(cmd);

  block_signals();

  /*
   * This forces a quick ping of the remote server, so we know if its there. 
   */
  if (mysqldb)
    mysql_ping(mysqldb);

  if (!mysqldb || ((error = mysql_query(mysqldb, query))
                   && !strcasecmp(mysql_error(mysqldb),
                                  "mysql server has gone"))) {
    /*
     * We need to restart the server link. 
     */
    if (mysqldb)
      log_pri(LOG_ERR, "%s: server has wandered off (%s/%s)",
              MOD_SQL_MYSQL_VERSION, g.sql_host, g.sql_dbname);
    sql_cmd_open(cmd);
    if (!mysqldb)
      return DECLINED(cmd);
    error = mysql_select_db(mysqldb, g.sql_dbname)
        || mysql_query(mysqldb, query);
  }

  unblock_signals();

  if (error) {
    log_debug(DEBUG4, "%s: %s failed: \"%s\": %s", MOD_SQL_MYSQL_VERSION,
              (update) ? "update" : "select", query, mysql_error(mysqldb));
    return DECLINED(cmd);
  }

  log_debug(DEBUG5, "%s: %s OK: [%s] \"%s\"", MOD_SQL_MYSQL_VERSION,
            (update) ? "update" : "select", g.sql_dbname, query);
  return HANDLED(cmd);
}

MODRET sql_cmd_update(cmd_rec * cmd)
{
  return _do_query(cmd, cmd->argv[1], TRUE);
}

MODRET sql_cmd_select(cmd_rec * cmd)
{
  MODRET mr;
  MYSQL_RES *result;
  MYSQL_ROW sql_row;
  int i, j;
  sqldata_t *sd;

  mr = _do_query(cmd, cmd->argv[1], FALSE);
  if (!MODRET_ISHANDLED(mr))
    return DECLINED(mr);

  if ((result = mysql_store_result(mysqldb))) {
    int rcount = mysql_num_rows(result);
    int fcount = mysql_num_fields(result);
    int count = rcount * fcount;

    char **data = pcalloc(cmd->tmp_pool, sizeof(char *) * (count + 1));
    for (i = 0, count = 0; i < rcount; i++) {
      sql_row = mysql_fetch_row(result);
      for (j = 0; j < fcount; j++)
        data[count++] = pstrdup(cmd->tmp_pool, sql_row[j]);
    }
    mysql_free_result(result);
    data[count] = NULL;

    sd = (sqldata_t *) pcalloc(cmd->tmp_pool, sizeof(sqldata_t));
    sd->rowcount = rcount;
    sd->fieldcount = fcount;
    sd->data = data;
    mr->data = sd;
  }
  return mr;
}

static authtable mysql_authtab[] = {
  {0, "dbd_open", sql_cmd_open},
  {0, "dbd_close", sql_cmd_close},
  {0, "dbd_update", sql_cmd_update},
  {0, "dbd_select", sql_cmd_select},

  {0, NULL, NULL}
};

/* **************************************************************** */

static int mysql_modinit()
{
  return 0;
}

static int mysql_childinit()
{
  config_rec *c = NULL;
  char *info = NULL;
  char *pass = NULL;
  char *user = NULL;

  char *db = NULL;
  char *host = NULL;
  char *port = NULL;

  char *havehost = NULL;
  char *haveport = NULL;

  c = find_config(CURRENT_CONF, CONF_PARAM, "SQLConnectInfo", FALSE);

  if (!c) {
    /*
     * should log 
     */
    return 0;
  }

  info = c->argv[0];
  user = c->argv[1];
  pass = c->argv[2];

  db = pstrdup(session.pool, info);

  havehost = strchr(db, '@');
  haveport = strchr(db, ':');

  /*
   * if haveport, parse it, otherwise default it. 
   * if haveport, set it to '\0'
   *
   * if havehost, parse it, otherwise default it.
   * if havehost, set it to '\0'
   */

  if (haveport) {
    port = haveport + 1;
    *haveport = '\0';
  } else {
    port = "3306";
  }

  if (havehost) {
    host = havehost + 1;
    *havehost = '\0';
  } else {
    host = "localhost";
  }

  memset(&g, 0, sizeof(g));

  g.sql_user = pstrdup(session.pool, user);
  g.sql_pass = pstrdup(session.pool, pass);

  g.sql_host = host;
  g.sql_dbname = db;
  g.sql_port = atoi(port);

  g.ok = TRUE;

  log_debug(DEBUG5, "%s: configured: %s@%s:%d for %s",
            MOD_SQL_MYSQL_VERSION, g.sql_dbname, g.sql_host,
            g.sql_port, g.sql_user);
  return 0;
}

module sql_mysql_module = {
  NULL, NULL,                   /* Always NULL */
  0x20,                         /* API Version 2.0 */
  "mysql",
  NULL,                         /* SQL configuration handler table */
  NULL,                         /* SQL command handler table */
  mysql_authtab,                /* SQL authentication handler table */
  mysql_modinit,                /* Pre-fork "parent-mode" init */
  mysql_childinit               /* Post-fork "child mode" init */
};

unsigned int sql_backend_escape_string(char *to, char *from, unsigned int len)
{
  return mysql_escape_string(to, from, len);
}

int sql_backend_check_auth(cmd_rec * cmd, const char *c_clear,
                           const char *c_hash)
{
  MYSQL_RES *result;
  MYSQL_ROW row;
  char *query;
  int success = 0;

  log_debug(DEBUG5, "%s: entering sql_auth_backend_check_auth",
            MOD_SQL_MYSQL_VERSION);

  query = pstrcat(cmd->tmp_pool, "select PASSWORD('", c_clear, "')", NULL);

  if (mysql_query(mysqldb, query))
    return 0;

  if ((result = mysql_store_result(mysqldb))) {
    row = mysql_fetch_row(result);

    log_debug(DEBUG4, "%s: PASSWORD(clear)=='%s'  actual=='%s'",
              MOD_SQL_MYSQL_VERSION, row[0], c_hash);

    if (!strcmp(row[0], c_hash))
      success = 1;

    mysql_free_result(result);
  }

  log_debug(DEBUG5, "%s: exiting  sql_auth_backend_check_auth",
            MOD_SQL_MYSQL_VERSION);

  return success;
}
