/*
 * ProFTPD: mod_sql_postgres -- Support for connecting to postgresql databases.
 * Time-stamp: <1999-10-04 03:22:02 root>
 * Copyright (c) 1999 Johnie Ingram.
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

/* bumping the version to 3.0 to match everything else */

#define MOD_SQL_POSTGRES_VERSION "mod_sql_postgres/3.0"

/* -- DO NOT MODIFY THE LINE BELOW UNLESS YOU FEEL LIKE IT --
 * $Libraries: -lm -lpq $
 */

/* This is mod_sql_postgres, contrib software for proftpd 1.2.0pre7 and above.
   For more information contact Johnie Ingram <johnie@netgod.net>.

   History Log:

   * 1999-09-19: v1.0: Initial attempted (modelled off mod_mysql).
*/

#include "conf.h"
#include <libpq-fe.h>

/* *INDENT-OFF* */

static PGconn *conn = 0;

/* Maximum username field to expect, etc. */
#define ARBITRARY_MAX                   128

#define MODPG_TTY NULL
#define MODPG_OPTIONS NULL

struct sqldata_struc {
  int rowcount;
  int fieldcount;
  char **data;
};

typedef struct sqldata_struc sqldata_t;


static struct
{
  char *sql_host;   /* Data for connecting, from PostgresInfo. */
  char *sql_user;
  char *sql_pass;
  char *sql_dbname;
  char *sql_dbport;

  char *sql_usertable;
  char *sql_userid;
  char *sql_passwd;

  int ok;
  int opens;
  PGresult *res;
} g;

/* *INDENT-ON* */

/* **************************************************************** */

MODRET sql_cmd_close(cmd_rec * cmd)
{
  log_debug(DEBUG5, "%s: close [%i] for %s", MOD_SQL_POSTGRES_VERSION,
            g.opens, cmd->argv[0]);

  if (!g.ok || g.opens--)
    return DECLINED(cmd);

  if (conn) {
    log_debug(DEBUG4, "%s: disconnecting: %s/%s", MOD_SQL_POSTGRES_VERSION,
              g.sql_host, g.sql_dbname);
    PQfinish(conn);
  }
  conn = NULL;
  return DECLINED(cmd);
}

MODRET sql_cmd_open(cmd_rec * cmd)
{
  if (!g.ok)
    return DECLINED(cmd);

  g.opens++;
  log_debug(DEBUG5, "%s: open [%i] for %s", MOD_SQL_POSTGRES_VERSION, g.opens,
            cmd->argv[0]);
  if (g.opens > 1)
    return HANDLED(cmd);

  if (g.sql_user)
    conn = PQsetdbLogin(g.sql_host, g.sql_dbport, MODPG_OPTIONS, MODPG_TTY,
                        g.sql_dbname, g.sql_user, g.sql_pass);
  else
    conn = PQsetdb(g.sql_host, g.sql_dbport, MODPG_OPTIONS, MODPG_TTY,
                   g.sql_dbname);

  if (PQstatus(conn) == CONNECTION_BAD) {
    log_pri(LOG_ERR, "%s: connect FAILED to %s/%s", MOD_SQL_POSTGRES_VERSION,
            g.sql_host, g.sql_dbname);
    PQfinish(conn);
    g.ok = FALSE;
    conn = NULL;
    g.opens = 0;
    return DECLINED(cmd);
  }
  log_debug(DEBUG5, "%s: connect OK (%s/%s)", MOD_SQL_POSTGRES_VERSION,
            g.sql_host, g.sql_dbname);

  return HANDLED(cmd);
}

MODRET _do_query(cmd_rec * cmd, const char *query, int update)
{
  PGnotify *not;

  if (!g.ok)
    return DECLINED(cmd);

  block_signals();

  PQconsumeInput(conn);
  while ((not = PQnotifies(conn)) != NULL) {
    log_pri(DEBUG3, "%s: async NOTIFY of '%s' from backend pid '%d'",
            MOD_SQL_POSTGRES_VERSION, not->relname, not->be_pid);
    free(not);
  }

  g.res = PQexec(conn, query);
  if (!g.res || PQstatus(conn) == CONNECTION_BAD) {
    /*
     * We need to restart the server link. 
     */
    if (conn)
      log_pri(LOG_ERR, "%s: server has wandered off (%s/%s)",
              MOD_SQL_POSTGRES_VERSION, g.sql_host, g.sql_dbname);
    sql_cmd_open(cmd);
    if (!conn)
      return DECLINED(cmd);
    g.res = PQexec(conn, query);
  }

  unblock_signals();

  if (update) {
    if (PQresultStatus(g.res) != PGRES_COMMAND_OK) {
      /*
       * Absorb the ugly newline. 
       */
      char errbuf[ARBITRARY_MAX];
      sstrncpy(errbuf, PQerrorMessage(conn), sizeof(errbuf));
      log_debug(DEBUG4, "%s: update failed: \"%s\": %s",
                MOD_SQL_POSTGRES_VERSION, query, errbuf);
      return DECLINED(cmd);
    }
  } else {
    if (PQresultStatus(g.res) != PGRES_TUPLES_OK) {
    log_debug(DEBUG4, %s: select failed:\"%s\": %s", MOD_SQL_POSTGRES_VERSION,
                query,
                PQerrorMessage(conn));
      return DECLINED(cmd);
    }
  }

  log_debug(DEBUG5, "%s: %s OK: [%s] \"%s\"", MOD_SQL_POSTGRES_VERSION
            (update) ? "update" : "select", g.sql_dbname, query);
  return HANDLED(cmd);
}

MODRET sql_cmd_update(cmd_rec * cmd)
{
  MODRET mr;
  mr = _do_query(cmd, cmd->argv[1], TRUE);
  PQclear(g.res);
  return mr;
}

MODRET sql_cmd_select(cmd_rec * cmd)
{
  MODRET mr;
  int i, j;
  sqldata_t *sd;

  mr = _do_query(cmd, cmd->argv[1], FALSE);
  if (!MODRET_ISHANDLED(mr))
    return DECLINED(mr);

  if (PQresultStatus(g.res) == PGRES_TUPLES_OK) {
    int tcount = PQntuples(g.res);
    int fcount = PQnfields(g.res);
    int count = tcount * fcount;

    char **data = pcalloc(cmd->tmp_pool, sizeof(char *) * (count + 1));
    count = 0;

    for (i = 0; i < tcount; i++) {
      for (j = 0; j < fcount; j++) {
        data[count++] = pstrdup(cmd->tmp_pool, PQgetvalue(g.res, i, j));
      }
    }
    data[count] = NULL;

    sd = (sqldata_t *) pcalloc(cmd->tmp_pool, sizeof(sqldata_t));
    sd->rowcount = tcount;
    sd->fieldcount = fcount;
    sd->data = data;
    mr->data = sd;
  }
  PQclear(g.res);
  return mr;
}

static authtable sql_postgres_authtab[] = {
  {0, "dbd_open", sql_cmd_open},
  {0, "dbd_close", sql_cmd_close},
  {0, "dbd_update", sql_cmd_update},
  {0, "dbd_select", sql_cmd_select},

  {0, NULL, NULL}
};

/* **************************************************************** */

static int sql_postgres_modinit()
{
  return 0;
}


static int sql_postgres_modconf()
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
    port = "5432";
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
  g.sql_dbport = port;

  g.ok = TRUE;
  log_debug(DEBUG5, "%s: configured: db %s at %s port %s",
            MOD_SQL_POSTGRES_VERSION, g.sql_dbname, g.sql_host, g.sql_dbport);
  return 0;
}

module sql_postgres_module = {
  NULL, NULL,                   /* Always NULL */
  0x20,                         /* API Version 2.0 */
  "sql_postgres",
  NULL,                         /* SQL configuration handler table */
  NULL,                         /* SQL command handler table */
  sql_postgres_authtab,         /* SQL authentication handler table */
  sql_postgres_modinit,         /* Pre-fork "parent-mode" init */
  sql_postgres_modconf          /* Post-fork "child mode" init */
};


unsigned int sql_backend_escape_string(char *to, char *from, unsigned int len)
{
  stncpy(to, from, len);

  if (strlen(from) >= len)
    to[len - 1] = '\0';

  return strlen(from);
}

int sql_backend_check_auth(cmd_rec * cmd, const char *c_clear,
                           const char *c_hash)
{
  return 0;
}
