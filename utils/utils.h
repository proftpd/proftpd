/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
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

/* Scoreboard routines.
 *
 * $Id: utils.h,v 1.1 2002-09-25 23:45:24 castaglia Exp $
 */

#ifndef UTIL_SCOREBOARD_H
#define UTIL_SCOREBOARD_H

#include "config.h"
#include "version.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_SYS_FILE_H
# include <sys/file.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#include "default_paths.h"

typedef struct in_addr p_in_addr_t;

#define	FALSE	0
#define TRUE	1

#define MAX_PATH_LEN	256

/* UTIL_SCOREBOARD_VERSION is used for checking for scoreboard compatibility
 */
#define UTIL_SCOREBOARD_VERSION        0x01040000

/* Structure used as a header for scoreboard files.
 */
#define UTIL_SCOREBOARD_MAGIC			0xdeadbeef

typedef struct {

  /* Always 0xDEADBEEF */
  unsigned long sch_magic;

  /* Version of proftpd that created the scoreboard file */
  unsigned long sch_version;

  /* PID of the process to which this scoreboard belongs, or zero if inetd */
  pid_t sch_pid;

  /* Time when the daemon wrote this header */
  time_t sch_uptime;

} pr_scoreboard_header_t;

/* Structure used for writing scoreboard file entries.
 */

typedef struct {
  pid_t	sce_pid;
  uid_t sce_uid;
  gid_t sce_gid;
  char sce_user[80];
  p_in_addr_t sce_server_ip;
  unsigned short sce_server_port;
  char sce_server_name[32], sce_addr[80];
  char sce_class[32];
  char sce_cwd[80];
  char sce_cmd[256];
  time_t sce_begin_idle, sce_begin_session;
  off_t sce_xfer_size, sce_xfer_done;

} pr_scoreboard_entry_t;

/* Scoreboard error values */
#define UTIL_SCORE_ERR_BAD_MAGIC	-2
#define UTIL_SCORE_ERR_OLDER_VERSION	-3
#define UTIL_SCORE_ERR_NEWER_VERSION	-4

const char *util_get_scoreboard(void);
int util_set_scoreboard(const char *);

int util_close_scoreboard(void);
int util_open_scoreboard(int, pid_t *);
pr_scoreboard_entry_t *util_scoreboard_read_entry(void);

#endif /* UTIL_SCOREBOARD_H */
