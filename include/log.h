/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
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

/* Logging, either to syslog or stderr, as well as debug logging
 * and debug levels.
 * $Id: log.h,v 1.1 1998-10-18 02:24:41 flood Exp $
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
  char spare[100];
} logrun_t;

/* These are the debug levels, higher numbers print more debugging
 * info.  DEBUG0 (the default) prints nothing.
 */

#define DEBUG5		5
#define DEBUG4		4
#define	DEBUG3		3
#define DEBUG2		2
#define DEBUG1		1
#define DEBUG0		0

char *fmt_time(time_t);
int log_wtmp(char*,char*,char*,p_in_addr_t*);
void log_setfacility(int);
int log_opensyslog(const char *);
void log_closesyslog();
void log_pri(int,char*,...);
void log_auth(int,char*,...);
void log_stderr(int);
int  log_setdebuglevel(int);
void log_debug(int,char*,...);
void log_discard();
void init_log();
void log_run_setpath(const char *);
const char *log_run_getpath(void);
int log_run_checkpath(void);
void log_run_address(const char *, const p_in_addr_t*);
void log_run_cwd(const char *);
int log_add_run(pid_t,time_t*,char*,p_in_addr_t*,unsigned short,
                unsigned long,unsigned long,char*,...);
logrun_t *log_read_run(pid_t*);
int log_open_run(pid_t,int,int);
int log_close_run();
void log_rm_run();
int log_open_xfer(const char*);
void log_close_xfer();
int log_xfer(int xfertime,char *remhost,unsigned long fsize,
              char *fname,char xfertype,char direction,
              char access,char *user);

#endif /* __LOG_H */
