/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2009 The ProFTPD Project team
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
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 *
 * $Id: session.c,v 1.1 2009-02-14 03:59:11 castaglia Exp $
 */

#include "conf.h"

const char *pr_session_get_protocol(int flags) {
  const char *sess_proto;

  sess_proto = pr_table_get(session.notes, "protocol", NULL);
  if (sess_proto == NULL) {
    sess_proto = "ftp";
  }

  if (!(flags & PR_SESS_PROTO_FL_LOGOUT)) {
    /* Return the protocol as is. */
    return sess_proto;
  }

  /* Otherwise, we need to return either "FTP" or "SSH2", for consistency. */
  if (strcmp(sess_proto, "ftp") == 0 ||
      strcmp(sess_proto, "ftps") == 0) {
    return "FTP";
  
  } else if (strcmp(sess_proto, "ssh2") == 0 ||
             strcmp(sess_proto, "sftp") == 0 ||
             strcmp(sess_proto, "scp") == 0) {
    return "SSH2";
  }

  /* Should never reach here, but just in case... */
  return "unknown";
}

int pr_session_set_protocol(const char *sess_proto) {
  int count, res;

  if (sess_proto == NULL) {
    errno = EINVAL;
    return -1;
  }

  count = pr_table_exists(session.notes, "protocol");
  if (count > 0) {
    res = pr_table_set(session.notes, pstrdup(session.pool, "protocol"),
      pstrdup(session.pool, sess_proto), 0);
    return res;
  }

  res = pr_table_add(session.notes, pstrdup(session.pool, "protocol"),
    pstrdup(session.pool, sess_proto), 0);
  return res;
}

const char *pr_session_get_ttyname(pool *p) {
  char sess_ttyname[32];
  const char *sess_proto, *tty_proto = NULL;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  sess_proto = pr_table_get(session.notes, "protocol", NULL);
  if (sess_proto) {
    if (strcmp(sess_proto, "ftp") == 0 ||
        strcmp(sess_proto, "ftps") == 0) {
#if (defined(BSD) && (BSD >= 199103))
      tty_proto = "ftp";
#else
      tty_proto = "ftpd";
#endif

    } else if (strcmp(sess_proto, "ssh2") == 0 ||
               strcmp(sess_proto, "sftp") == 0 ||
               strcmp(sess_proto, "scp") == 0) {
#if (defined(BSD) && (BSD >= 199103))
      tty_proto = "ssh";
#else
      tty_proto = "sshd";
#endif
    }
  }

  if (tty_proto == NULL) {
#if (defined(BSD) && (BSD >= 199103))
    tty_proto = "ftp";
#else
    tty_proto = "ftpd";
#endif
  }

  memset(sess_ttyname, '\0', sizeof(sess_ttyname));
#if (defined(BSD) && (BSD >= 199103))
  snprintf(sess_ttyname, sizeof(sess_ttyname), "%s%ld", tty_proto,
    (long) (session.pid ? session.pid : getpid()));
#else
  snprintf(sess_ttyname, sizeof(sess_ttyname), "%s%d", tty_proto,
    (int) (session.pid ? session.pid : getpid()));
#endif
  sess_ttyname[sizeof(sess_ttyname)-1] = '\0';

  return pstrdup(p, sess_ttyname);
}
