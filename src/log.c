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

/*
 * ProFTPD logging support
 * $Id: log.c,v 1.9 1999-09-17 07:31:45 macgyver Exp $
 */

/* History Log:
 *
 * 4/24/97 0.99.0pl1
 *   Added log_debug() and log_setdebuglevel() in order to facilitate
 *   altering the amount of debugging info printed or syslogged.
 *   Also added a command line argument (-d,--debug) to alter the
 *   debug level at runtime.  See main.c.
 */

/* AIX requires this to be the first thing in the file. */
#if defined(_AIX) && !defined(__GNUC__)
#pragma alloca
#endif

#include "conf.h"

#include <signal.h>

static int syslog_open = FALSE;
static int syslog_discard = FALSE;
static int logstderr = TRUE;
static int debug_level = DEBUG0;	/* Default is no debug logging */
static int facility = LOG_DAEMON;
static int set_facility = -1;
static char *syslog_fn = NULL;
static char *syslog_hostname;
static int syslog_fd = -1;
static int runfd = -1;
static char scoreboard_path[MAX_PATH_LEN] = RUN_DIR;
static char *runfn = NULL;
static char *runcwd = NULL;
static char *address = NULL;
static size_t runsize = 0;
static int xferfd = -1;

char *fmt_time(time_t t)
{
  static char buf[30];
  static char *mons[] =
  { "Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec" };
  static char *days[] =
  { "Sun","Mon","Tue","Wed","Thu","Fri","Sat" };
  struct tm *tr;

  if((tr = localtime(&t)) != NULL) {
    snprintf(buf,sizeof(buf),"%s %s %2d %02d:%02d:%02d %d",
            days[tr->tm_wday],
            mons[tr->tm_mon],
            tr->tm_mday,
            tr->tm_hour,
            tr->tm_min,
            tr->tm_sec,
            tr->tm_year + 1900);
  } else
    buf[0] = '\0';
  
  return buf;
}

void log_close_xfer()
{
  if(xferfd != -1)
    close(xferfd);
  xferfd = -1;
}

int log_open_xfer(const char *fn)
{
  if(!fn) {
    if(xferfd != -1)
      log_close_xfer();
    return 0;
  }

  if(xferfd == -1)
    xferfd = open(fn,O_WRONLY|O_APPEND|O_CREAT,0644);

  return xferfd;
}

int log_xfer(int xfertime,char *remhost,unsigned long fsize,
             char *fname,char xfertype,char direction,
             char access,char *user)
{
  char buf[1024], fbuf[1024];
  int i;

  if(xferfd == -1)
    return 0;

  for(i = 0; (i + 1 < sizeof(fbuf)) && fname[i] != '\0'; i++) {
    fbuf[i] = (isspace(fname[i]) || iscntrl(fname[i])) ? '_' : fname[i];
  }
  
  fbuf[i] = '\0';
  
  snprintf(buf,sizeof(buf),"%s %d %s %lu %s %c _ %c %c %s ftp 0 *\n",
	   fmt_time(time(NULL)),xfertime,remhost,fsize,
	   fbuf,xfertype,direction,access,user);

  return(write(xferfd,buf,strlen(buf)));
}

void log_rm_run()
{
  if(runfd > -1)
    close(runfd);
  if(runfn)
    unlink(runfn);

  runfd = -1;
}

int log_close_run()
{
  if(runfd == -1)
    return 0;

  close(runfd);
  runfd = -1;
  return 0;
}

const char *log_run_getpath(void)
{
  return scoreboard_path;
}

void log_run_setpath(const char *path)
{
  sstrncpy(scoreboard_path,path,sizeof(scoreboard_path));
  if(scoreboard_path[strlen(scoreboard_path)-1] == '/')
    scoreboard_path[strlen(scoreboard_path)-1] = '\0';
}

int log_run_checkpath(void)
{
  struct stat sbuf;

  if(stat(scoreboard_path,&sbuf) < 0)
    return -1;

  if(!S_ISDIR(sbuf.st_mode)) {
    errno = ENOTDIR;
    return -1;
  }

  return 0;
}

int log_open_run(pid_t mpid, int trunc, int allow_update)
{
  char fname[256];
  logrun_header_t hdr;
  int i;

  if(runfd > -1)
    return 0;

  if(!mpid)
    snprintf(fname, sizeof(fname), "%s/proftpd-inetd",scoreboard_path);
  else
    snprintf(fname, sizeof(fname), "%s/proftpd-%d",scoreboard_path,(int)mpid);

  runfn = pstrdup(permanent_pool,fname);
  if((runfd = open(runfn,O_RDWR|O_CREAT|(trunc ? O_TRUNC : 0),
                   0644)) == -1)
    return -1;

  /* Attempt to read header */
  i = read(runfd, &hdr, sizeof(hdr));

  if(i <= 0) {
    char buf[sizeof(logrun_t)];
    runsize = sizeof(logrun_t);
    
    hdr.r_magic = LOGRUN_MAGIC;
    hdr.r_version = INTERNAL_VERSION;
    hdr.r_size = sizeof(logrun_t);
    bzero(buf,sizeof(logrun_t));
    bcopy(&hdr,buf,sizeof(hdr));
    write(runfd,buf,runsize);
    fsync(runfd);

    return runfd;
  }

  if(i < sizeof(hdr)) {
    /* File is corrupt, etc, silently rm it */
    if(allow_update) {
      log_rm_run();
      return log_open_run(mpid,trunc,allow_update);
    }
    return -1;
  }

  if(hdr.r_magic != LOGRUN_MAGIC) {
    /* Old version or corrupt */
    log_pri(LOG_NOTICE,"run-time scoreboard file '%s' is corrupted or old version.",fname);
    if(allow_update) {
      log_rm_run();
      return log_open_run(mpid,trunc,allow_update);
    }
    return -1;
  }

  if(hdr.r_version < INTERNAL_VERSION) {
    log_pri(LOG_NOTICE,"run-time scoreboard file '%s' is old version.",fname);
    if(allow_update) {
      log_rm_run();
      return log_open_run(mpid,trunc,allow_update);
    }
    return -1;
  }

  if(hdr.r_version > INTERNAL_VERSION) {
    log_pri(LOG_NOTICE,"run-time scoreboard file '%s' appears to be from a newer version of proftpd (%s).",
            fname,VERSION);
    log_close_run();
    return -1;
  }

  runsize = (size_t)hdr.r_size;
  return runfd;
}

static int _pid_exists(pid_t pid)
{
#ifdef LINUX
  char procfn[20];
  struct stat sbuf;
#endif
  int res;

  res = kill(pid,SIGCONT);
#ifdef LINUX
  snprintf(procfn, sizeof(procfn), "/proc/%d",pid);    
  if( (res == -1 && errno == EPERM) || !res ||
    stat(procfn,&sbuf) != -1)
#else
  if( (res == -1 && errno == EPERM) || !res )
#endif
    return 1;
  return 0;
}

static size_t _read_hdr(int fd)
{
  logrun_header_t hdr;

  if(read(fd,&hdr,sizeof(hdr)) != sizeof(hdr))
    return 0;

  if(hdr.r_magic != LOGRUN_MAGIC)
    /* Old version or corrupt */
    return 0;

  if(hdr.r_version != INTERNAL_VERSION)
    return 0;

  lseek(fd, hdr.r_size, SEEK_SET);
  return (size_t)hdr.r_size;
}

static int _read_run(int fd, size_t size, logrun_t *ent)
{
  unsigned char *buf;
  logrun_t *tmp;

  buf = (unsigned char*)alloca(size);

  while(read(fd,buf,size) == size) {
    tmp = (logrun_t*)buf;

    if(tmp->pid) {
      /* Try to determine if the process still exists */

      bcopy(tmp,ent,sizeof(logrun_t));
      return _pid_exists(ent->pid);
    }
  }

  return -1;
}

logrun_t *log_read_run(pid_t *mpid)
{
  static DIR *dir = NULL;
  static struct dirent *dent = NULL;
  static int fd = -1;
  static logrun_t ent;
  static size_t size = 0;
  char *cp,buf[256];

  errno = 0;
  if(!dir) {
    dir = opendir(scoreboard_path);
    if(!dir)
      return NULL;
  }

  while(fd != -1) {
    switch(_read_run(fd,size,&ent)) {
    case 1:
      errno = 0;
      return &ent;
    case -1:
      close(fd); fd = -1; break;
    }
  }

  while((dent = readdir(dir)) != NULL)
    if(strncmp(dent->d_name,"proftpd",7) == 0) {
      cp = rindex(dent->d_name,'-');
      if(cp) {
        cp++;
        if(mpid)
          *mpid = (pid_t)atoi(cp);
        snprintf(buf, sizeof(buf), "%s/%s",scoreboard_path,dent->d_name);
        fd = open(buf,O_RDONLY,0644);

        if(fd != -1) {
          size = _read_hdr(fd);
          if(!size) {
            close(fd);
            fd = -1;
          }

          while(fd != -1) {
            switch(_read_run(fd,size,&ent)) {
            case 1: errno = 0; return &ent;
            case -1: close(fd); fd = -1; errno = 0;
            }
          }
        } else
          return NULL;
      }
    }

  closedir(dir);
  dir = NULL;

  return NULL;
}

void log_run_address(const char *remote_name, const p_in_addr_t *remote_ipaddr)
{
  char buf[1024];

  snprintf(buf,sizeof(buf),"%s [%s]",remote_name,inet_ntoa(*remote_ipaddr));
  buf[1023] = '\0';
  address = pstrdup(permanent_pool,buf);
}

void log_run_cwd(const char *cwd)
{
  if(!runcwd)
    runcwd = pcalloc(permanent_pool,MAX_PATH_LEN);
  
  sstrncpy(runcwd,cwd,MAX_PATH_LEN);
}

/* log_add_run() logs the current process and connection information to
 * the scoreboard_path/proftpd-[master_daemon_pid] file.  If an existing record
 * for the current pid is found, it is overwritten.  Passing user ==
 * NULL clears the entry.
 */

int log_add_run(pid_t mpid, time_t *idle_since, char *user,
                p_in_addr_t *server_ip, unsigned short server_port, 
                unsigned long tx_size, unsigned long tx_done, char *op, ...)
{
  logrun_t ent,fent;
  int res = 0,c,first = -1;
  va_list msg;
  char buf[1500] = "";

#ifndef HAVE_FLOCK
  struct flock arg;
#endif

  c = runsize;

  if(op) {
    va_start(msg,op);
    vsnprintf(buf,sizeof(buf),op,msg);
    va_end(msg);
    buf[sizeof(buf)-1] = '\0';
  }

  if(runfd == -1)
    log_open_run(mpid,FALSE,FALSE);

  if(runfd == -1)
    return -1;

  bzero(&ent,sizeof(ent));
  ent.pid = getpid();
  ent.uid = geteuid();
  ent.gid = getegid();

#ifdef HAVE_FLOCK
  flock(runfd,LOCK_EX);
#else
  arg.l_type = F_WRLCK; arg.l_whence = arg.l_start = arg.l_len = 0;
  fcntl(runfd, F_SETLKW, &arg);
#endif

  if(lseek(runfd,runsize,SEEK_SET) != -1) {
    while(read(runfd,(char*)&fent,sizeof(fent)) == sizeof(fent) &&
          fent.pid != ent.pid) {
      if((!fent.pid || !_pid_exists(fent.pid)) && first == -1)
        first = c;
      c += sizeof(fent);
    }

    if(fent.pid == ent.pid) {
      bcopy(&fent,&ent,sizeof(ent));
      first = -1;
      lseek(runfd,c,SEEK_SET);
    } else
      lseek(runfd,runsize,SEEK_END);
  }

  if(idle_since)
    ent.idle_since = *idle_since;
  else
    ent.idle_since = 0;

  if(user) {
    bzero(ent.user,sizeof(ent.user));
    sstrncpy(ent.user,user,sizeof(ent.user));
  }
  if(buf[0]) {
    bzero(ent.op,sizeof(ent.op));
    sstrncpy(ent.op,buf,sizeof(ent.op));
  }

  if(server_ip)
    bcopy(server_ip,&ent.server_ip,sizeof(ent.server_ip));
  if(server_port)
    ent.server_port = server_port;

  if(tx_size) {
    ent.transfer_size = tx_size;
    ent.transfer_complete = tx_done;
  } else {
    ent.transfer_size = 0;
    ent.transfer_complete = 0;
  }

  if(runcwd) {
    sstrncpy(ent.cwd,runcwd,sizeof(ent.cwd));
    ent.cwd[sizeof(ent.cwd)-1] = '\0';
  } else
    bzero(ent.cwd,sizeof(ent.cwd));

  if(address) {
    sstrncpy(ent.address,address,sizeof(ent.address));
    ent.address[sizeof(ent.address)-1] = '\0';
  } else
    bzero(ent.address,sizeof(ent.address));

  if(!user) {
    if(fent.pid == ent.pid) {
      bzero(&ent,sizeof(ent));
      res = write(runfd,(char*)&ent,sizeof(ent));
    }
  } else {
    if(first != -1)
      lseek(runfd,first,SEEK_SET);
    res = write(runfd,(char*)&ent,sizeof(ent));
  }

  /* 11/16/97 - fsync() causes the kernel to flush related file buffers to
   * disk, not necessary here.
   */

  /* fsync(runfd); */

#ifdef HAVE_FLOCK
  flock(runfd,LOCK_UN);
#else
  arg.l_type = F_UNLCK; arg.l_whence = arg.l_start = arg.l_len = 0;
  fcntl(runfd, F_SETLKW, &arg);
#endif

  return res;
}

/* This next function logs an entry to wtmp, it MUST be called as
 * root BEFORE a chroot occurs.
 * Note: This has some portability ifdefs in it.  They *should* work,
 * but I haven't been able to test them.
 */

int log_wtmp(char *line, char *name, char *host, p_in_addr_t *ip)
{
  struct stat buf;
  struct utmp ut;
  int res = 0;
  static int fd = -1;

#if defined(SVR4) || defined(__SVR4)
#if !(defined(LINUX) || defined(__hpux) || defined (_AIX))
  /* This "auxilliary" utmp doesn't exist under linux. */
  struct utmpx utx;
  static int fdx = -1;

  if(fdx < 0 && (fdx = open(WTMPX_FILE, O_WRONLY | O_APPEND, 0)) < 0) {
    log_pri(LOG_WARNING,"wtmpx %s: %s",WTMPX_FILE,strerror(errno));
    return -1;
  }

  if(fstat(fdx,&buf) == 0) {
    memset(&utx,0,sizeof(utx));
    sstrncpy(utx.ut_user,name,sizeof(utx.ut_user));
    sstrncpy(utx.ut_id,"ftp",sizeof(utx.ut_user));
    sstrncpy(utx.ut_line,line,sizeof(utx.ut_line));
    sstrncpy(utx.ut_host,host,sizeof(utx.ut_host));
    utx.ut_syslen = strlen(utx.ut_host)+1;
    utx.ut_pid = getpid();
    time(&utx.ut_tv.tv_sec);
    if(*name)
      utx.ut_type = USER_PROCESS;
    else
      utx.ut_type = DEAD_PROCESS;
    utx.ut_exit.e_termination = 0;
    utx.ut_exit.e_exit = 0;
    if(write(fdx,(char*)&utx,sizeof(utx)) != sizeof(utx))
      ftruncate(fdx, buf.st_size);
  } else {
    log_debug(DEBUG0,"%s fstat(): %s",WTMPX_FILE,strerror(errno));
    res = -1;
  }

#endif
#endif /* SVR4 */

  if(fd < 0 && (fd = open(WTMP_FILE,O_WRONLY|O_APPEND,0)) < 0) {
    log_pri(LOG_WARNING,"wtmp %s: %s",WTMP_FILE,strerror(errno));
    return -1;
  }
 
  if(fstat(fd,&buf) == 0) {
    memset(&ut,0,sizeof(ut));
#ifdef HAVE_UTMAXTYPE
#ifdef LINUX
    if(ip)
      memcpy(&ut.ut_addr,ip,sizeof(ut.ut_addr));
#else
    sstrncpy(ut.ut_id,"ftp",sizeof(ut.ut_id));
    ut.ut_exit.e_termination = 0;
    ut.ut_exit.e_exit = 0;
#endif
    sstrncpy(ut.ut_line,line,sizeof(ut.ut_line));
    if(name && *name)
      sstrncpy(ut.ut_user,name,sizeof(ut.ut_user));
    ut.ut_pid = getpid();
    if(name && *name)
      ut.ut_type = USER_PROCESS;
    else
      ut.ut_type = DEAD_PROCESS;
#else  /* !HAVE_UTMAXTYPE */
    sstrncpy(ut.ut_line,line,sizeof(ut.ut_line));
    if(name && *name)
      sstrncpy(ut.ut_name,name,sizeof(ut.ut_name));
#endif /* HAVE_UTMAXTYPE */

#ifdef HAVE_UT_UT_HOST
    if(host && *host)
      sstrncpy(ut.ut_host,host,sizeof(ut.ut_host));
#endif /* HAVE_UT_UT_HOST */

    time(&ut.ut_time);
    if(write(fd,(char*)&ut,sizeof(ut)) != sizeof(ut))
      ftruncate(fd,buf.st_size);
  } else {
    log_debug(DEBUG0,"%s fstat(): %s",WTMP_FILE,strerror(errno));
    res = -1;
  }

  return res;
}

int log_opensyslog(const char *fn)
{
  char *ptr;
  struct stat statbuf;
  
  if(set_facility != -1)
    facility = set_facility;

  if(fn)
    syslog_fn = pstrdup(permanent_pool,fn);

  if(!syslog_fn) {
    openlog("proftpd",LOG_NDELAY|LOG_PID,facility);
    syslog_open = TRUE;
    syslog_fd = -1;
  } else {
    if((ptr = rindex(syslog_fn, '/')) == NULL) {
      log_debug(DEBUG0, "%s rindex failed", syslog_fn);
      syslog_fn = NULL;
      return -1;
    }
    
    *ptr = '\0';

    if(stat(syslog_fn, &statbuf) == -1) {
      log_debug(DEBUG0, "%s stat: %s", syslog_fn, strerror(errno));
      syslog_fn = NULL;
      return -1;
    }

    if(!S_ISDIR(statbuf.st_mode)) {
      log_debug(DEBUG0, "%s is not a directory", syslog_fn);
      syslog_fn = NULL;
      return -1;
    }
    
    if(statbuf.st_mode & S_IXOTH) {
      log_debug(DEBUG0, "%s is a world writeable directory", syslog_fn);
      syslog_fn = NULL;
      return -2;
    }
    
    *ptr = '/';
    syslog_fd = open(syslog_fn,O_CREAT|O_APPEND|O_WRONLY,0640);
    if(syslog_fd == -1) {
      syslog_fn = NULL;
      return -1;
    }

    syslog_open = TRUE;
  }

  return 0;
}

void log_closesyslog()
{
  if(syslog_fd != -1)
    close(syslog_fd);
  else
    closelog();

  syslog_fd = -1;
  syslog_open = FALSE;
}

void log_setfacility(int f)
{
  set_facility = f;
}

void log_discard()
{
  syslog_discard = TRUE;
}

void log(int priority, int f, char *s)
{
  if(logstderr) {
    fprintf(stderr,"%s\n",s);
    return;
  }

  if(syslog_discard)
    return;

  if(syslog_fd != -1) {
    char buf[1024];
    time_t tt = time(NULL);
    struct tm *t;

    t = localtime(&tt);
    strftime(buf,sizeof(buf),"%b %d %H:%M:%S ",t);
    buf[sizeof(buf) - 1] = '\0';
    snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
             "%s proftpd[%u]: %s",syslog_hostname,
             (unsigned int)getpid(),s);

    buf[sizeof(buf)-1] = '\0';
    write(syslog_fd,buf,strlen(buf));
    write(syslog_fd,"\n",1);
    return;
  }

  if(set_facility != -1)
    f = set_facility;

  if(f != facility || !syslog_open)
    openlog("proftpd", LOG_NDELAY | LOG_PID, f);

  syslog(priority, "%s\n", s);

  if(!syslog_open)
    closelog();
  else if(f != facility)
    openlog("proftpd", LOG_NDELAY | LOG_PID, facility);
}

void log_pri(int priority,char *fmt,...)
{
  char buf[1024];
  va_list msg;

  va_start(msg,fmt);
  vsnprintf(buf, sizeof(buf), fmt, msg);
  va_end(msg);

  buf[1023] = '\0';

  log(priority,facility,buf);
}

/* Like log_pri(), but sends the log entry in the LOG_AUTHPRIV
 * facility (presumable it doesn't need to be seen by everyone
 */

void log_auth(int priority, char *fmt, ...)
{
  char buf[1024];
  va_list msg;

  va_start(msg,fmt);
  vsnprintf(buf, sizeof(buf), fmt, msg);
  va_end(msg);

  buf[1023] = '\0';

  log(priority, LOG_AUTHPRIV, buf);
}

/* Disable logging to stderr, should be done right before forking
 * or disassociation from controlling tty.  After disabling stderr
 * logging, all messages go to syslog.
 */

void log_stderr(int bool)
{
  logstderr = bool;
}

/* Set the debug logging level, see log.h for constants.  Higher
 * numbers mean print more, DEBUG0 (0) == print no debugging log
 * (default)
 */

int log_setdebuglevel(int level)
{
  int old_level = debug_level;
  debug_level = level;
  return old_level;
}

void log_debug(int level,char *str,...)
{
  char buf[1024];
  va_list msg;

  if(debug_level < level)
    return;

  va_start(msg,str);
  vsnprintf(buf, sizeof(buf), str, msg);
  va_end(msg);

  buf[1023] = '\0';

  log(LOG_DEBUG, facility, buf);
}

void init_log()
{
  char buf[256];

  if(gethostname(buf, sizeof(buf)) == -1)
    sstrncpy(buf, "localhost", sizeof(buf));
  
  syslog_hostname = inet_validate(pstrdup(permanent_pool, buf));
}
