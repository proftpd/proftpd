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

/* General options
 * $Id: proftpd.h,v 1.40 2003-01-02 18:25:18 castaglia Exp $
 */

#ifndef PR_PROFTPD_H
#define PR_PROFTPD_H

#ifndef TRUE
#define TRUE				1
#endif

#ifndef FALSE
#define FALSE				0
#endif

#define CALLBACK_FRAME			LPARAM p1,LPARAM p2,LPARAM p3,void *data
#define ASSERT(x)			assert(x)
#include <assert.h>
#define MAX_PATH_LEN			256

typedef unsigned long LPARAM;   /* Longest bitsize compatible with
                                 * a scalar and largest pointer
                                 * (platform dependant)
                                 */

/* adjust per platform */
/* unsigned 32 bit integer */
typedef unsigned long u_int_32;
/* unsigned 16 bit integer */
typedef unsigned short u_int_16;
/* unsigned 8 bit integer */
typedef unsigned char u_int_8;

typedef unsigned char UCHAR;
typedef unsigned int UINT;
typedef unsigned long ULONG;

typedef int (*callback_t)(CALLBACK_FRAME);

/* Class structure */

typedef struct class_struc {
  struct class_struc *next;

  char *name;				/* class name */
  int max_connections;			/* max number of users in this class */
  void *preg;				/* compiled regexp */

} class_t;


typedef struct cdir_struc {
  struct cdir_struc *next;

  u_int_32 address;
  u_int_32 netmask;
  class_t *class;
} cdir_t;

typedef struct hostname_struc {
  struct hostname_struc *next;
  char *hostname;
  class_t *class;
} hostname_t;

struct conn_struc;
struct cmd_struc;
struct IO_Request;
struct IO_File;
struct config_struc;

typedef struct {
  pool *pool;

  volatile int sf_flags;		/* Session/State flags */
  volatile int sp_flags;		/* Session/Protection flags */

  p_in_addr_t data_addr;		/* Remote data address */
  short data_port;			/* Remote data port */

  unsigned char ident_lookups;		/* Is RFC931 (ident) protocol used? */
  char *ident_user;			/* User identified by ident protocol */

  const char *rfc2228_mech;		/* RFC2228 authentication mechanism
					 * used
					 */

  char cwd[MAX_PATH_LEN];		/* Current working directory */
  char vwd[MAX_PATH_LEN];		/* Current virtual working directory */

  struct config_struc *dir_config;	/* Closest matching configuration
                                         * for current operation
                                         */

  /* The uid/gids are manipulated by the PRIVS macros in
   * privs.h
   */

  int disable_id_switching;		/* disable uid/gid switching */
  uid_t uid,ouid;                       /* current and original UIDs */
  gid_t gid;                            /* current gid */

  array_header *gids;
  array_header *groups;

  /* fsuid/fsgid are used for automagic chown after creation or upload,
   * they are initially -1, meaning no chown/chgrp.
   */
  uid_t fsuid;				/* Saved file UID */
  gid_t fsgid;				/* Saved file GID */

  char *user,*group;			/* username/groupname after login */
  uid_t login_uid;                      /* UID after login, but before
                                         * session.uid is changed */
  gid_t login_gid;                      /* GID after login, but before
                                         * session.gid is changed */

  class_t *class;			/* session class */
  char *proc_prefix;			/* The "prefix" of our process name */

  int wtmp_log;				/* Are we logging to wtmp? */
  struct conn_struc *c;			/* Control connection */
  struct conn_struc *d;			/* Data connection */

  struct IO_Request *d_req;		/* Active data connection request */

  int hide_password;			/* Hide password in logs/ps listing */

  char *chroot_path;			/* Chroot directory */

  struct config_struc *anon_config;	/* Anonymous FTP configuration */
  char *anon_user;			/* E-mail address sent to us */

  off_t restart_pos;			/* Restart marked position */

  struct {
    struct pool *p;

    int xfer_type;     /* xfer session attributes, default/append/hidden */
    int direction;
    char *filename;			/* As shown to user */
    char *path;				/* As used in transfer */
    char *path_hidden;			/* As used in hidden stor */

    unsigned int bufsize,buflen;

    struct timeval start_time;		/* Time current transfer started */
    off_t file_size;			/* Total size of file (if known) */
    off_t total_bytes;			/* Total bytes transfered */

    char *bufstart,*buf;
  } xfer;

  /* Total number of bytes transfered in this session. */
  off_t total_bytes;

  /* Total number of files uploaded in this session. */
  unsigned int total_files_in;

  /* Total number of files downloaded in this session. */
  unsigned int total_files_out;

  /* Total number of files transfered (both uploaded and downloaded) in
   * this session.
   */
  unsigned int total_files_xfer;

} session_t;

/* Daemon identity values, defined in main.c */
extern uid_t daemon_uid;
extern gid_t daemon_gid;
extern array_header *daemon_gids;

/* Possible values for xfer.xfer_type, mutually exclusive */
#define STOR_DEFAULT	0
#define STOR_APPEND	1
#define STOR_HIDDEN	2
#define STOR_UNIQUE	3

extern session_t	session;
extern char		ServerType;
extern char		MultilineRFC2228;
extern const char	*pwdfname,*grpfname;

/* Session/State flags */

#define SF_PASSIVE	(1 << 0)	/* Data connection is in passive mode */
#define SF_ABORT	(1 << 1)	/* Abort in progess */
#define SF_XFER		(1 << 2)	/* Transfer in progress */
#define SF_ASCII	(1 << 3)	/* ASCII mode transfer */
#define SF_ASCII_OVERRIDE (1 << 4)	/* ASCII override this xfer only */
#define SF_ANON		(1 << 5)	/* Anonymous (chroot) login */
#define SF_POST_ABORT	(1 << 6)	/* After abort has occured */
#define SF_PORT		(1 << 7)	/* Port command given */

#define SF_ALL		(SF_PASSIVE|SF_ABORT|SF_XFER|SF_ASCII| \
                        SF_ASCII_OVERRIDE|SF_ANON|SF_POST_ABORT|SF_PORT)

/* Session/Protection flags (RFC 2228) */

#define SP_CCC		(1 << 0)	/* Clear command channel */
#define SP_ENC		(1 << 1)	/* Privacy protected command */
#define SP_MIC		(1 << 2)	/* Integrity protected command */
#define SP_CONF		(1 << 3)	/* Confidentiality protected command */

/* Macro to test global abort flag */
#define XFER_ABORTED	(session.sf_flags & SF_ABORT)

/* Server Types */
#define SERVER_INETD		0
#define SERVER_STANDALONE	1

/* Signals */
#define RECEIVED_SIG_REHASH	0x0001
#define RECEIVED_SIG_EXIT	0x0002
#define RECEIVED_SIG_SHUTDOWN	0x0004
#define RECEIVED_SIG_SEGV	0x0008
#define RECEIVED_SIG_TERMINATE	0x0010
#define RECEIVED_SIG_XCPU	0x0020
#define RECEIVED_SIG_TERM_OTHER	0x0040
#define RECEIVED_SIG_ABORT	0x0080
#define RECEIVED_SIG_DEBUG	0x0100
#define RECEIVED_SIG_CHLD	0x0200
#define RECEIVED_SIG_ALRM	0x0400

/* Timers */
#define TIMER_LOGIN		1
#define TIMER_IDLE		2
#define TIMER_NOXFER		3
#define TIMER_STALLED		4
#define TIMER_SESSION		5

/* Misc Prototypes */

void end_login(int);
void pr_signals_handle(void);
void session_exit(int, void *, int, void *);
void session_set_idle(void);
void pr_rehash_register_handler(void *, void(*)(void *));
void set_daemon_rlimits(void);
void set_session_rlimits(void);

#endif /* PR_PROFTPD_H */
