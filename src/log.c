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

/*
 * ProFTPD logging support.
 *
 * $Id: log.c,v 1.55 2003-02-12 19:03:36 castaglia Exp $
 */

#include "conf.h"

#include <signal.h>

#define LOGBUFFER_SIZE	2048

static int syslog_open = FALSE;
static int syslog_discard = FALSE;
static int logstderr = TRUE;
static int debug_level = DEBUG0;	/* Default is no debug logging */
static int facility = LOG_DAEMON;
static int set_facility = -1;
static char systemlog_fn[MAX_PATH_LEN] = {'\0'};
static char systemlog_host[256] = {'\0'};
static int systemlog_fd = -1;

static int xfer_fd = -1;

int syslog_sockfd = -1;

char *fmt_time(time_t t) {
  static char buf[30];
  static char *mons[] =
  { "Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec" };
  static char *days[] =
  { "Sun","Mon","Tue","Wed","Thu","Fri","Sat" };
  struct tm *tr;

  memset(buf, '\0', sizeof(buf));
  if ((tr = localtime(&t)) != NULL) {
    snprintf(buf,sizeof(buf), "%s %s %2d %02d:%02d:%02d %d",
            days[tr->tm_wday],
            mons[tr->tm_mon],
            tr->tm_mday,
            tr->tm_hour,
            tr->tm_min,
            tr->tm_sec,
            tr->tm_year + 1900);
  } else
    buf[0] = '\0';
  buf[sizeof(buf)-1] = '\0';

  return buf;
}

void log_close_xfer(void) {
  if (xfer_fd != -1)
    close(xfer_fd);

  xfer_fd = -1;
}

int log_open_xfer(const char *path) {

  if (!path) {
    if (xfer_fd != -1)
      log_close_xfer();
    return 0;
  }

  if (xfer_fd == -1) {
    log_debug(DEBUG6, "opening TransferLog '%s'", path);
    log_openfile(path, &xfer_fd, LOG_XFER_MODE);
  }

  return xfer_fd;
}

int log_xfer(long xfertime, char *remhost, off_t fsize, char *fname,
    char xfertype, char direction, char access_mode, char *user,
    char abort_flag) {

  char buf[LOGBUFFER_SIZE] = {'\0'}, fbuf[LOGBUFFER_SIZE] = {'\0'};
  register unsigned int i = 0;

  if (xfer_fd == -1 || !remhost || !user || !fname)
    return 0;

  for (i = 0; (i + 1 < sizeof(fbuf)) && fname[i] != '\0'; i++) {
    fbuf[i] = (isspace((int) fname[i]) || iscntrl((int) fname[i])) ? '_' :
      fname[i];
  }
  fbuf[i] = '\0';

  snprintf(buf, sizeof(buf),
    "%s %ld %s %" PR_LU " %s %c _ %c %c %s ftp %c %s %c\n",
    fmt_time(time(NULL)), xfertime, remhost, fsize, fbuf, xfertype, direction,
    access_mode, user, session.ident_lookups == TRUE ? '1' : '0',
    (session.ident_lookups == TRUE && strcmp(session.ident_user,
      "UNKNOWN")) ? session.ident_user : "*", abort_flag);
  buf[sizeof(buf)-1] = '\0';

  return write(xfer_fd, buf, strlen(buf));
}

/* This next function logs an entry to wtmp, it MUST be called as
 * root BEFORE a chroot occurs.
 * Note: This has some portability ifdefs in it.  They *should* work,
 * but I haven't been able to test them.
 */

int log_wtmp(char *line, const char *name, const char *host, p_in_addr_t *ip) {
  struct stat buf;
  struct utmp ut;
  int res = 0;
  static int fd = -1;

#if (defined(SVR4) || defined(__SVR4)) && \
    !(defined(LINUX) || defined(__hpux) || defined (_AIX))
  /* This "auxilliary" utmp doesn't exist under linux. */
#ifdef __sparcv9
  struct futmpx utx;
  time_t t;
#else
  struct utmpx utx;
#endif
  static int fdx = -1;

  if (fdx < 0 && (fdx = open(WTMPX_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
    log_pri(PR_LOG_WARNING, "wtmpx %s: %s", WTMPX_FILE, strerror(errno));
    return -1;
  }

  /* Unfortunately, utmp string fields are terminated by '\0' if they are
   * shorter than the size of the field, but if they are exactly the size of
   * the field they don't have to be terminated at all.  Frankly, this sucks.
   * Insane if you ask me.  Unless there's massive uproar, I prefer to err on
   * the side of caution and always null-terminate our strings.
   */
  if (fstat(fdx,&buf) == 0) {
    memset(&utx,0,sizeof(utx));
    sstrncpy(utx.ut_user,name,sizeof(utx.ut_user));
    sstrncpy(utx.ut_id, "ftp",sizeof(utx.ut_user));
    sstrncpy(utx.ut_line,line,sizeof(utx.ut_line));
    sstrncpy(utx.ut_host,host,sizeof(utx.ut_host));
    utx.ut_syslen = strlen(utx.ut_host)+1;
    utx.ut_pid = getpid();
#ifdef __sparcv9
    time(&t);
    utx.ut_tv.tv_sec = (time32_t)t;
#else
    time(&utx.ut_tv.tv_sec);
#endif
    if (*name)
      utx.ut_type = USER_PROCESS;
    else
      utx.ut_type = DEAD_PROCESS;
#ifdef HAVE_UT_UT_EXIT
    utx.ut_exit.e_termination = 0;
    utx.ut_exit.e_exit = 0;
#endif /* HAVE_UT_UT_EXIT */
    if (write(fdx, (char *)&utx,sizeof(utx)) != sizeof(utx))
      ftruncate(fdx, buf.st_size);
  } else {
    log_debug(DEBUG0, "%s fstat(): %s",WTMPX_FILE,strerror(errno));
    res = -1;
  }

#else /* Non-SVR4 systems */

  if (fd < 0 && (fd = open(WTMP_FILE,O_WRONLY|O_APPEND,0)) < 0) {
    log_pri(PR_LOG_WARNING, "wtmp %s: %s", WTMP_FILE, strerror(errno));
    return -1;
  }

  if (fstat(fd,&buf) == 0) {
    memset(&ut,0,sizeof(ut));
#ifdef HAVE_UTMAXTYPE
#ifdef LINUX
    if (ip)
      memcpy(&ut.ut_addr,ip,sizeof(ut.ut_addr));
#else
    sstrncpy(ut.ut_id, "ftp",sizeof(ut.ut_id));
#ifdef HAVE_UT_UT_EXIT
    ut.ut_exit.e_termination = 0;
    ut.ut_exit.e_exit = 0;
#endif /* HAVE_UT_UT_EXIT */
#endif
    sstrncpy(ut.ut_line,line,sizeof(ut.ut_line));
    if (name && *name)
      sstrncpy(ut.ut_user,name,sizeof(ut.ut_user));
    ut.ut_pid = getpid();
    if (name && *name)
      ut.ut_type = USER_PROCESS;
    else
      ut.ut_type = DEAD_PROCESS;
#else  /* !HAVE_UTMAXTYPE */
    sstrncpy(ut.ut_line,line,sizeof(ut.ut_line));
    if (name && *name)
      sstrncpy(ut.ut_name,name,sizeof(ut.ut_name));
#endif /* HAVE_UTMAXTYPE */

#ifdef HAVE_UT_UT_HOST
    if (host && *host)
      sstrncpy(ut.ut_host,host,sizeof(ut.ut_host));
#endif /* HAVE_UT_UT_HOST */

    time(&ut.ut_time);
    if (write(fd, (char *)&ut,sizeof(ut)) != sizeof(ut))
      ftruncate(fd,buf.st_size);
  } else {
    log_debug(DEBUG0, "%s fstat(): %s",WTMP_FILE,strerror(errno));
    res = -1;
  }
#endif /* SVR4 */

  return res;
}

int log_openfile(const char *log_file, int *log_fd, mode_t log_mode) {
  pool *tmp_pool = NULL;
  char *tmp = NULL, *lf;
  unsigned char *allow_log_symlinks = NULL;
  struct stat sbuf;

  /* sanity check */
  if (!log_file || !log_fd) {
    errno = EINVAL;
    return -1;
  }

  /* Make a temporary copy of log_file in case it's a constant */
  tmp_pool = make_sub_pool(permanent_pool);
  lf = pstrdup(tmp_pool, log_file);

  if ((tmp = strrchr(lf, '/')) == NULL) {
    log_debug(DEBUG0, "inappropriate log file: %s", lf);
    destroy_pool(tmp_pool);
    return -1;
  }

  /* Set the path separator to zero, in order to obtain the directory
   * name, so that checks of the directory may be made.
   */
  *tmp = '\0';

  if (stat(lf, &sbuf) == -1) {
    log_debug(DEBUG0, "error: unable to stat() %s: %s", lf,
      strerror(errno));
    destroy_pool(tmp_pool);
    return -1;
  }

  /* The path must be in a valid directory */
  if (!S_ISDIR(sbuf.st_mode)) {
    log_debug(DEBUG0, "error: %s is not a directory", lf);
    destroy_pool(tmp_pool);
    return -1;
  }

  /* Do not log to world-writeable directories */
  if (sbuf.st_mode & S_IWOTH) {
    log_debug(DEBUG0, "error: %s is a world writeable directory", lf);
    destroy_pool(tmp_pool);
    return LOG_WRITEABLE_DIR;
  }

  /* Restore the path separator so that checks on the file itself may be
   * done.
   */
  *tmp = '/';

  allow_log_symlinks = get_param_ptr(main_server->conf, "AllowLogSymlinks",
    FALSE);

  if (!allow_log_symlinks || *allow_log_symlinks == FALSE) {

    /* Prevent a race condition between stat() and open() by opening the
     * file now, _then_ checking to see if it's a symlink
     */
    if ((*log_fd = open(lf, O_APPEND|O_CREAT|O_WRONLY,
          log_mode)) == -1) {
      destroy_pool(tmp_pool);
      return -1;
    }

    /* Stat the file using the descriptor, not the path */
    if (fstat(*log_fd, &sbuf) != -1 && S_ISLNK(sbuf.st_mode)) {
      log_debug(DEBUG0, "error: %s is a symbolic link", lf);
      close(*log_fd);
      *log_fd = -1;
      destroy_pool(tmp_pool);
      return LOG_SYMLINK;
    }

  } else
    if ((*log_fd = open(lf, O_CREAT|O_APPEND|O_WRONLY, log_mode)) == -1) {
      destroy_pool(tmp_pool);
      return -1;
    }

  destroy_pool(tmp_pool);
  return 0;
}

int log_opensyslog(const char *fn) {
  int res = 0;

  if (set_facility != -1)
    facility = set_facility;

  if (fn) {
    memset(systemlog_fn, '\0', sizeof(systemlog_fn));
    sstrncpy(systemlog_fn, fn, sizeof(systemlog_fn));
  }

  if (!*systemlog_fn) {

    /* The child may have inherited a valid socket from the parent. */
    pr_closelog(syslog_sockfd);

    if ((syslog_sockfd = pr_openlog("proftpd", LOG_NDELAY|LOG_PID,
        facility)) < 0)
      return -1;
    systemlog_fd = -1;

  } else if ((res = log_openfile(systemlog_fn, &systemlog_fd,
      LOG_SYSTEM_MODE)) < 0) {
    memset(systemlog_fn, '\0', sizeof(systemlog_fn));
    return res;
  }

  syslog_open = TRUE;
  return 0;
}

void log_closesyslog(void) {
  if (systemlog_fd != -1) {
    close(systemlog_fd);
    systemlog_fd = -1;

  } else {
    pr_closelog(syslog_sockfd);
    syslog_sockfd = -1;
  }

  syslog_open = FALSE;
}

void log_setfacility(int f) {
  set_facility = f;
}

void log_discard(void) {
  syslog_discard = TRUE;
}

static void log(int priority, int f, char *s) {
  unsigned int *max_priority = NULL;
  char serverinfo[PR_TUNABLE_BUFFER_SIZE] = {'\0'};

  memset(serverinfo, '\0', sizeof(serverinfo));

  if (main_server && main_server->ServerFQDN) {
    snprintf(serverinfo, sizeof(serverinfo), "%s", main_server->ServerFQDN);
    serverinfo[sizeof(serverinfo)-1] = '\0';

    if (session.c && session.c->remote_name) {
      snprintf(serverinfo + strlen(serverinfo),
        sizeof(serverinfo) - strlen(serverinfo), " (%s[%s])",
        session.c->remote_name, inet_ntoa(*session.c->remote_ipaddr));
      serverinfo[sizeof(serverinfo)-1] = '\0';
    }
  }

  if (logstderr) {
    fprintf(stderr, "%s - %s\n", serverinfo, s);
    return;
  }

  if (syslog_discard)
    return;

  if (systemlog_fd != -1) {
    char buf[LOGBUFFER_SIZE] = {'\0'};
    time_t tt = time(NULL);
    struct tm *t;

    t = localtime(&tt);
    strftime(buf, sizeof(buf), "%b %d %H:%M:%S ", t);
    buf[sizeof(buf) - 1] = '\0';

    if (*serverinfo) {
      snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
	       "%s proftpd[%u] %s: %s\n", systemlog_host,
	       (unsigned int) getpid(), serverinfo, s);
    } else {
      snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
	       "%s proftpd[%u]: %s\n", systemlog_host,
	       (unsigned int) getpid(), s);
    }

    buf[sizeof(buf) - 1] = '\0';
    write(systemlog_fd, buf, strlen(buf));
    return;
  }

  if (set_facility != -1)
    f = set_facility;

  if (f != facility || !syslog_open)
    syslog_sockfd = pr_openlog("proftpd", LOG_NDELAY|LOG_PID, f);

  if ((max_priority = get_param_ptr(main_server->conf, "SyslogLevel",
      FALSE)) != NULL && priority > *max_priority)
    return;

  if (*serverinfo)
    pr_syslog(syslog_sockfd, priority, "%s - %s\n", serverinfo, s);
  else
    pr_syslog(syslog_sockfd, priority, "%s\n", s);

  if (!syslog_open) {
    pr_closelog(syslog_sockfd);
    syslog_sockfd = -1;

  } else if (f != facility)
    syslog_sockfd = pr_openlog("proftpd", LOG_NDELAY|LOG_PID, facility);
}

void log_pri(int priority, const char *fmt, ...) {
  char buf[LOGBUFFER_SIZE] = {'\0'};
  va_list msg;

  va_start(msg, fmt);
  vsnprintf(buf, sizeof(buf), fmt, msg);
  va_end(msg);

  /* Always make sure the buffer is NUL-terminated. */
  buf[sizeof(buf) - 1] = '\0';

  log(priority, facility, buf);
}

/* Like log_pri(), but sends the log entry in the LOG_AUTHPRIV
 * facility (presumable it doesn't need to be seen by everyone
 */

void log_auth(int priority, const char *fmt, ...) {
  char buf[LOGBUFFER_SIZE] = {'\0'};
  va_list msg;

  va_start(msg, fmt);
  vsnprintf(buf, sizeof(buf), fmt, msg);
  va_end(msg);

  /* Always make sure the buffer is NUL-terminated. */
  buf[sizeof(buf) - 1] = '\0';

  log(priority, LOG_AUTHPRIV, buf);
}

/* Disable logging to stderr, should be done right before forking
 * or disassociation from controlling tty.  After disabling stderr
 * logging, all messages go to syslog.
 */
void log_stderr(int bool) {
  logstderr = bool;
}

/* Set the debug logging level, see log.h for constants.  Higher
 * numbers mean print more, DEBUG0 (0) == print no debugging log
 * (default)
 */
int log_setdebuglevel(int level) {
  int old_level = debug_level;
  debug_level = level;
  return old_level;
}

/* Convert a string into the matching syslog level value.  Return -1
 * if no matching level is found.
 */
int log_str2sysloglevel(const char *name) {

  if (strcasecmp(name, "emerg") == 0)
    return PR_LOG_EMERG;

  else if (strcasecmp(name, "alert") == 0)
    return PR_LOG_ALERT;

  else if (strcasecmp(name, "crit") == 0)
    return PR_LOG_CRIT;

  else if (strcasecmp(name, "error") == 0)
    return PR_LOG_ERR;

  else if (strcasecmp(name, "warn") == 0)
    return PR_LOG_WARNING;

  else if (strcasecmp(name, "notice") == 0)
    return PR_LOG_NOTICE;

  else if (strcasecmp(name, "info") == 0)
    return PR_LOG_INFO;

  else if (strcasecmp(name, "debug") == 0)
    return PR_LOG_DEBUG;

  return -1;
}

void log_debug(int level, const char *fmt, ...) {
  char buf[LOGBUFFER_SIZE] = {'\0'};
  va_list msg;

  if (debug_level < level)
    return;

  memset(buf, '\0', sizeof(buf));
  va_start(msg, fmt);
  vsnprintf(buf, sizeof(buf), fmt, msg);
  va_end(msg);

  /* Always make sure the buffer is NUL-terminated. */
  buf[sizeof(buf) - 1] = '\0';

  log(PR_LOG_DEBUG, facility, buf);
}

void init_log(void) {
  char buf[256] = {'\0'};

  if (gethostname(buf, sizeof(buf)) == -1)
    sstrncpy(buf, "localhost", sizeof(buf));

  sstrncpy(systemlog_host, inet_validate(buf), sizeof(systemlog_host));
  memset(systemlog_fn, '\0', sizeof(systemlog_fn));
  log_closesyslog();
}
