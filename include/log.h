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

/* Logging, either to syslog or stderr, as well as debug logging
 * and debug levels.
 *
 * $Id: log.h,v 1.11 2002-06-23 19:03:22 castaglia Exp $
 */

#ifndef __LOG_H
#define __LOG_H

#ifndef LOG_AUTHPRIV
#define LOG_AUTHPRIV LOG_AUTH
#endif

#if !defined(WTMP_FILE) && defined(_PATH_WTMP)
#define WTMP_FILE _PATH_WTMP
#endif

/* Structure used as a header for /var/run/proftpd-*
 */

#define LOGRUN_MAGIC			0xdeadbeef

typedef struct {
  unsigned long r_magic;		/* always 0xdeadbeef */
  unsigned long r_version;		/* version of proftpd created with */
  unsigned long r_size;			/* Size of each entry (including first) */
} logrun_header_t;

/* Structure used for writing to /var/run/proftpd-*
 */

typedef struct {
  pid_t	pid;
  uid_t uid;
  gid_t gid;
  p_in_addr_t server_ip;
  unsigned short server_port;
  time_t idle_since;
  char user[100],op[200];
  unsigned long transfer_size,transfer_complete;
  char address[80],cwd[100];
  char class[32], spare[100];
} logrun_t;

/* These are the debug levels, higher numbers print more debugging
 * info.  DEBUG0 (the default) prints nothing.
 */

#define DEBUG9		9
#define DEBUG8		8
#define DEBUG7		7
#define DEBUG6		6
#define DEBUG5		5
#define DEBUG4		4
#define	DEBUG3		3
#define DEBUG2		2
#define DEBUG1		1
#define DEBUG0		0

/* These are log levels used to determine at which level we should log to.
 */
#ifdef HAVE_SYSLOG

#define PR_LOG_EMERG     LOG_EMERG     /* system is unusable */
#define PR_LOG_ALERT     LOG_ALERT     /* action must be taken immediately */
#define PR_LOG_CRIT      LOG_CRIT      /* critical conditions */
#define PR_LOG_ERR       LOG_ERR       /* error conditions */
#define PR_LOG_WARNING   LOG_WARNING   /* warning conditions */
#define PR_LOG_NOTICE    LOG_NOTICE    /* normal but significant condition */
#define PR_LOG_INFO      LOG_INFO      /* informational */
#define PR_LOG_DEBUG     LOG_DEBUG     /* debug-level messages */

#define PR_LOG_LEVELMASK LOG_PRIMASK   /* mask off the level value */

#else

#define	PR_LOG_EMERG		0	/* system is unusable */
#define	PR_LOG_ALERT		1	/* action must be taken immediately */
#define	PR_LOG_CRIT		2	/* critical conditions */
#define	PR_LOG_ERR		3	/* error conditions */
#define	PR_LOG_WARNING		4	/* warning conditions */
#define	PR_LOG_NOTICE		5	/* normal but significant condition */
#define	PR_LOG_INFO		6	/* informational */
#define	PR_LOG_DEBUG		7	/* debug-level messages */

#define	PR_LOG_LEVELMASK	7	/* mask off the level value */

#endif

/* log_openfile() return values */
#define LOG_WRITEABLE_DIR	-2
#define LOG_SYMLINK		-3

/* log modes */
#define LOG_SCOREBOARD_MODE     0644
#define LOG_SYSTEM_MODE         0640
#define LOG_XFER_MODE           0644

char *fmt_time(time_t);
int log_wtmp(char *, char *, char *, p_in_addr_t *);
void log_setfacility(int);
int log_openfile(const char *, int *, mode_t);
int log_opensyslog(const char *);
void log_closesyslog(void);
void log_pri(int, char *, ...);
void log_auth(int, char *, ...);
void log_stderr(int);
int  log_setdebuglevel(int);
void log_debug(int, char *, ...);
void log_discard(void);
void init_log(void);
void log_run_setpath(const char *);
const char *log_run_getpath(void);
int log_open_checkpath(void);
int log_run_checkpath(void);
void log_run_address(const char *, const p_in_addr_t *);
void log_run_cwd(const char *);
int log_add_run(pid_t, time_t *, char *, char *, p_in_addr_t *, unsigned short,
  unsigned long, unsigned long, char *, ...);
logrun_t *log_read_run(pid_t *);
int log_open_run(pid_t, int, int);
int log_close_run(void);
void log_rm_run(void);
int log_open_xfer(const char *);
void log_close_xfer(void);
int log_xfer(int, char *, off_t, char *, char, char, char, char *, char);

#endif /* __LOG_H */
