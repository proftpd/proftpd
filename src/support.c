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

/* Various basic support routines for ProFTPD, used by all modules
 * and not specific to one or another.
 * $Id: support.c,v 1.7 1999-09-17 07:31:45 macgyver Exp $
 */

/* History Log:
 * 10/29/97 current: 0.99.0pl9, next: 0.99.0pl10
 *   Added get_fs_size(), used to determine the amount of space
 *   available on a filesystem (if supported)
 *
 * 7/9/97 current: 0.99.0pl6, next: 0.99.0pl7
 *   Added exit handler chain, works identically to libc atexit(),
 *   however atexit() can't be used because proftpd often terminates
 *   with _exit() rather than exit().
 *
 * 5/12/97 current: 0.99.0pl1, next: 0.99.0pl2
 *   Added check_shutmsg function which checks for the existance
 *   of the shutdown file, and returns timing information
 *   about an impending shutdown.  Also added, str_interpolate,
 *   to interpolate custom "%x" metas.
 *
 * 4/30/97 current: 0.99.0pl1, next: 0.99.0pl2
 *   Fixed bug in dir_interpolate that was not 0-terminating
 *   all strings.
 *
 * 4/24/97 current: 0.99.0pl1, next: 0.99.0pl2
 *   Oops... forgot to check for empty username in dir_interpolate(),
 *   so commands like "cd ~" aren't working.
 *   Status: Fixed.
 *
 * 4/25/97 current: 0.99.0pl1, next: 0.99.0pl2
 *   Added schedule() and run_schedule() to allow async routines
 *   (called from an alarm or inside the _ioreq_service() to
 *   schedule a function to run after the next `n' loops)
 *   The function (run_schedule() is called from io.c) will
 *   run at an "undetermined" later time (async), when
 *   no I/O is in progress (basically, allowing the schedule
 *   of a "low priority" function.  The higher the loop count
 *   (via nloops), the later it will run.
 */

#include "conf.h"

#include <signal.h>

#ifdef HAVE_SYS_STATVFS_H
# include <sys/statvfs.h>
#elif defined(HAVE_SYS_VFS_H)
# include <sys/vfs.h>
#endif

#ifdef AIX3
#include <sys/statfs.h>
#endif

typedef struct _exithandler {
  struct _exithandler *next,*prev;

  void (*f)();
} exithandler_t;

typedef struct _sched {
  struct _sched *next,*prev;

  void (*f)(void*,void*,void*,void*);
  int loops;
  void *a1,*a2,*a3,*a4;
} sched_t;

static xaset_t *scheds = NULL;
static xaset_t *exits = NULL;

/* performs "hard block" of all important signals (as opposed to 
 * block_alarms) */
static void _block_signals(int block)
{
  static sigset_t sigset;

  if(block) {
    sigemptyset(&sigset);

    sigaddset(&sigset,SIGTERM);
    sigaddset(&sigset,SIGCHLD);
    sigaddset(&sigset,SIGUSR1);
    sigaddset(&sigset,SIGINT);
    sigaddset(&sigset,SIGQUIT);
    sigaddset(&sigset,SIGALRM);
    sigaddset(&sigset,SIGIO);
#ifdef SIGBUS
    sigaddset(&sigset,SIGBUS);
#endif
    sigaddset(&sigset,SIGHUP);

    sigprocmask(SIG_BLOCK,&sigset,NULL);
  } else
    sigprocmask(SIG_UNBLOCK,&sigset,NULL);
}

void block_signals()
{
  _block_signals(1);
}

void unblock_signals()
{
  _block_signals(0);
}

void add_exit_handler(void (*f)())
{
  exithandler_t *e;

  if(!exits)
    exits = xaset_create(permanent_pool,NULL);

  e = pcalloc(permanent_pool,sizeof(exithandler_t));
  e->f = f;
  xaset_insert(exits,(xasetmember_t*)e);
}

void run_exit_handlers()
{
  exithandler_t *e;

  if(!exits)
    return;

  for(e = (exithandler_t*)exits->xas_list; e; e=e->next)
    e->f();
}

void schedule(void (*f)(void*,void*,void*,void*),int nloops,
              void *a1, void *a2, void *a3, void *a4)
{
  pool *p;
  sched_t *s;

  if(!scheds) {
   p = make_sub_pool(permanent_pool);
   scheds = xaset_create(p,NULL);
  } else
   p = scheds->mempool;

  s = (sched_t*)pcalloc(p,sizeof(sched_t));
  s->f = f;
  s->a1 = a1;
  s->a2 = a2;
  s->a3 = a3;
  s->a4 = a4;
  s->loops = nloops;
  xaset_insert(scheds,(xasetmember_t*)s);
}

void run_schedule()
{
  sched_t *s,*snext;

  handle_sig_alarm();
  if(!scheds || !scheds->xas_list)
    return;

  for(s = (sched_t*)scheds->xas_list; s; s=snext) {
    snext = s->next;

    if(s->loops-- <= 0) {
      s->f(s->a1,s->a2,s->a3,s->a4);
      xaset_remove(scheds,(xasetmember_t*)s);
    }
  }
}

/* Returns TRUE if there is a scheduled function waiting */
int schedulep()
{
  handle_sig_alarm();
  return (scheds && scheds->xas_list);
}

/* Interpolates a pathname, expanding ~ notation if necessary
 */

char *dir_interpolate(pool *p, const char *path)
{
  struct passwd *pw;
  char *user,*tmp;
  char *ret = (char*)path;

  if(!ret)
    return NULL;

  if(*ret == '~') {
    user = pstrdup(p,ret+1);
    tmp = index(user,'/');

    if(tmp)
      *tmp++ = '\0';

    if(!*user)
      user = session.user;

    pw = auth_getpwnam(p,user);

    if(!pw) {
      errno = ENOENT;
      return NULL;
    }

    ret = pdircat(p,pw->pw_dir,tmp,NULL);
  }

  return ret;
}

/* dir_best_path() creates the "most" fully canonicalized path possible
 * (i.e. if path components at the end don't exist, they are ignored
 */

char *dir_best_path(pool *p, const char *path)
{
  char workpath[MAXPATHLEN];
  char realpath[MAXPATHLEN];
  char *target = NULL, *ntarget;
  int fini = 0;

  if(*path == '~') {
    if(fs_interpolate(path,workpath,MAXPATHLEN) == -1)
      fs_dircat(workpath,sizeof(workpath),fs_getcwd(),path);
  } else
    fs_dircat(workpath,sizeof(workpath),fs_getcwd(),path);

  fs_clean_path(pstrdup(p,workpath),workpath,MAXPATHLEN);

  while(!fini && workpath[0]) {
    if(fs_resolve_path(workpath,realpath,MAXPATHLEN,0) != -1)
      break;
  
    ntarget = rindex(workpath,'/');
    if(ntarget) {
      if(target)
        fs_dircat(workpath,sizeof(workpath),workpath,target);

      target = ntarget;
      *target++ = '\0';
    } else
      fini++;
  }

  if(!fini && workpath[0]) {
    if(target)
      fs_dircat(workpath,sizeof(workpath),realpath,target);
    else
      sstrncpy(workpath,realpath,sizeof(workpath));
  } else
    fs_dircat(workpath,sizeof(workpath),"/",target);

  return pstrdup(p,workpath);
}

char *dir_canonical_path(pool *p, const char *path)
{
  char buf[MAXPATHLEN];
  char work[MAXPATHLEN];

  if(*path == '~') {
    if(fs_interpolate(path,work,MAXPATHLEN) == -1)
      fs_dircat(work,sizeof(work),fs_getcwd(),path);
  } else
    fs_dircat(work,sizeof(work),fs_getcwd(),path);

  fs_clean_path(work,buf,MAXPATHLEN);
  return pstrdup(p,buf);
}

/* dir_realpath() is needed to properly dereference symlinks (getcwd() may
 * not work if permissions cause problems somewhere up the tree).
 */

char *dir_realpath(pool *p, const char *path)
{
  char buf[MAXPATHLEN];

  if(fs_resolve_partial(path,buf,MAXPATHLEN,0) == -1)
    return NULL;

  return pstrdup(p,buf);
}

char *dir_virtual_chdir(pool *p, const char *path)
{
  char buf[MAXPATHLEN];
  char work[MAXPATHLEN];

  if(*path == '~') {
    if(fs_interpolate(path,work,MAXPATHLEN) == -1)
      fs_dircat(work,sizeof(work),fs_getvwd(),path);
  } else
    fs_dircat(work,sizeof(work),fs_getvwd(),path);

  fs_clean_path(work,buf,MAXPATHLEN);
  return pstrdup(p,buf);
}

/* Takes a directory and returns it's absolute version.  ~username
 * references are appropriately interpolated.  "Absolute" includes
 * a *full* reference based on the root directory, not upon a chrooted
 * dir.
 */

char *dir_abs_path(pool *p, const char *path, int interpolate)
{
  char *res = NULL;

  if(interpolate)
    path = dir_interpolate(p,path);
  
  if(!path)
    return NULL;  
    
  if(*path != '/') {
    if(session.anon_root)
      res = pdircat(p,session.anon_root,fs_getcwd(),path,NULL);
    else
      res = pdircat(p,fs_getcwd(),path,NULL);
  } else if(session.anon_root)
    res = pdircat(p,session.anon_root,path,NULL);
  else
    res = pstrdup(p,path);

  return res;
}

static mode_t _symlink(char *path, ino_t last_inode, int rcount)
{
  char buf[255];
  struct stat sbuf;

  if(++rcount >= 32) {
    errno = ELOOP;
    return 0;
  }

  bzero(buf,sizeof(buf));

  if(fs_readlink(path,buf,sizeof(buf)) == -1)
    return (mode_t)0;

  if(fs_lstat(buf,&sbuf) != -1) {
    if(sbuf.st_ino && (ino_t)sbuf.st_ino == last_inode) {
      errno = ELOOP;
      return 0;
    }

    if(S_ISLNK(sbuf.st_mode))
      return _symlink(buf,(ino_t)sbuf.st_ino,rcount);
    return sbuf.st_mode;
  }

  return 0;
}

mode_t file_mode(char *path)
{
  struct stat sbuf;
  mode_t res = 0;

  if(fs_stat(path,&sbuf) != -1) {
    if(S_ISLNK(sbuf.st_mode))
      res = _symlink(path,(ino_t)0,0);
    else
      res = sbuf.st_mode;
  }

  return res;
}

/* dirp == -1, don't care if file or directory */

static int _exists(char *path, int dirp)
{
  mode_t fmode;

  if((fmode = file_mode(path)) != 0) {
    if(dirp == 1 && !S_ISDIR(fmode))
      return FALSE;
    else if(dirp == 0 && S_ISDIR(fmode))
      return FALSE;
    return TRUE;
  }

  return FALSE;
}

int file_exists(char *path)
{
  return _exists(path,0);
}

int dir_exists(char *path)
{
  return _exists(path,1);
}

int exists(char *path)
{
  return _exists(path,-1);
}

char *strip_end(char *s, char *ch)
{
  int i = strlen(s);

  while(i && strchr(ch,*(s+i-1))) {
    *(s+i-1) = '\0';
    i--;
  }

  return s;
}

/* get_token tokenizes a string, increments the src pointer to
 * the next non-separator in the string.  If the src string is
 * empty or NULL, the next token returned is NULL.
 */

char *get_token(char **s, char *sep)
{
  char *res;

  if(!s || !*s || !**s)
    return NULL;

  res = *s;

  while(**s && !strchr(sep,**s)) (*s)++;

  if(**s) {
    *(*s)++ = '\0';
  }

  return res;
}

/* safe_token tokenizes a string, and increments the pointer to
 * the next non-white space character.  It's "safe" because it
 * never returns NULL, only an empty string if no token remains
 * in the source string.
 */

char *safe_token(char **s)
{
  char *res = "";

  if(!s || !*s)
    return res;

  while(isspace((UCHAR)**s) && **s) (*s)++;

  if(**s) {
    res = *s;

    while(!isspace((UCHAR)**s) && **s) (*s)++;

    if(**s)
      *(*s)++ = '\0';

    while(isspace((UCHAR)**s) && **s) (*s)++;
  }

  return res;
}

/* Checks for the existance of SHUTMSG_PATH.  deny and disc are
 * filled with the times to deny new connections and disconnect
 * existing ones.
 */

int check_shutmsg(time_t *shut, time_t *deny, time_t *disc, char *msg, 
                  size_t msg_size)
{
  FILE *fp;
  char *deny_str,*disc_str,*cp,buf[1025];
  char hr[3],mn[3];
  time_t now,shuttime = (time_t)0;
  struct tm tm;

  if(file_exists(SHUTMSG_PATH) && (fp = fopen(SHUTMSG_PATH,"r"))) {
    if((cp = fgets(buf,sizeof(buf),fp)) != NULL) {
      buf[1024] = '\0'; CHOP(cp);

      /* We use this to fill in dst, timezone, etc */
      time(&now);
      tm = *(localtime(&now));

      tm.tm_year = atoi(safe_token(&cp)) % 100;
      tm.tm_mon = atoi(safe_token(&cp));
      tm.tm_mday = atoi(safe_token(&cp));
      tm.tm_hour = atoi(safe_token(&cp));
      tm.tm_min = atoi(safe_token(&cp));
      tm.tm_sec = atoi(safe_token(&cp));

      deny_str = safe_token(&cp);
      disc_str = safe_token(&cp);

      if((shuttime = mktime(&tm)) == (time_t)-1) {
        fclose(fp);
        return 0;
      }

      if(deny) {
        if(strlen(deny_str) == 4) {
          sstrncpy(hr,deny_str,sizeof(hr)); hr[2] = '\0'; deny_str += 2;
          sstrncpy(mn,deny_str,sizeof(mn)); mn[2] = '\0';
          
          *deny = shuttime - ((atoi(hr) * 3600) + (atoi(mn) * 60));
        } else
          *deny = shuttime;
      }

      if(disc) {
        if(strlen(disc_str) == 4) {
          sstrncpy(hr,disc_str,sizeof(hr)); hr[2] = '\0'; disc_str += 2;
          sstrncpy(mn,disc_str,sizeof(mn)); mn[2] = '\0';

          *disc = shuttime - ((atoi(hr) * 3600) + (atoi(mn) * 60));
        } else
          *disc = shuttime;
      }

      if(fgets(buf,sizeof(buf),fp) && msg) {
        buf[255] = '\0';
	CHOP(buf);
        sstrncpy(msg,buf,msg_size-1);
      }
    }

    fclose(fp);
    if(shut)
      *shut = shuttime;
    return 1;
  }

  return 0;
}

char *make_arg_str(pool *p,int argc,char **argv)
{
  char *res = "";

  while(argc--)
    if(*res)
      res = pstrcat(p,res," ",*argv++,NULL);
    else
      res = pstrcat(p,res,*argv++,NULL);

  return res;
}

char *sreplace(pool *p, char *s, ...)
{
  va_list args;
  char *m,*r,*src = s,*cp;
  char **mptr,**rptr;
  char *marr[33],*rarr[33];
  char buf[2048];
  int mlen = 0,rlen = 0;

  cp = buf;
  *cp = '\0';
  
  bzero(marr,sizeof(marr));

  va_start(args,s);

  while((m = va_arg(args,char*)) != NULL && mlen < 32) {
    if((r = va_arg(args,char*)) == NULL)
      break;

    marr[mlen] = m;
    rarr[mlen++] = r;
  }

  va_end(args);

  while(*src) {
    for(mptr = marr, rptr = rarr; *mptr; mptr++, rptr++) {
      mlen = strlen(*mptr);
      rlen = strlen(*rptr);

      if(strncmp(src,*mptr,mlen) == 0) {
        sstrncpy(cp,*rptr,sizeof(buf) - strlen(buf));
	if(((cp + rlen) - buf + 1) > sizeof(buf)) {
	  log_pri(LOG_ERR,
		  "Warning, attempt to overflow internal ProFTPD buffers.");
	  cp = buf + sizeof(buf) - 1;
	  goto done;
	} else {
	  cp += rlen;
	}
	
        src += mlen;
        break;
      }
    }
    
    if(!*mptr) {
      if((cp - buf + 1) > sizeof(buf)) {
	log_pri(LOG_ERR,
		"Warning, attempt to overflow internal ProFTPD buffers.");
	cp = buf + sizeof(buf) - 1;
      }
      *cp++ = *src++;
    }
  }
  
 done:
  *cp = '\0';

  return pstrdup(p,buf);
}

/* Simple multiplication & division doesn't work with very large
 * filesystems (overflows 32 bits).  This code should handle it.
 */

static
unsigned long _calc_fs(unsigned long blocks, unsigned long bsize)
{
  unsigned long bl_lo,bl_hi;
  unsigned long res_lo,res_hi,tmp;

  bl_lo = blocks & 0x0000ffff;
  bl_hi = blocks & 0xffff0000;

  tmp = (bl_hi >> 16) * bsize;
  res_hi = tmp & 0xffff0000;
  res_lo = (tmp & 0x0000ffff) << 16;
  res_lo += bl_lo * bsize;

  if(res_hi & 0xfc000000)		/* overflow */
	return 0;

  return (res_lo >> 10) | (res_hi << 6);
}

#ifdef HAVE_SYS_STATVFS_H
unsigned long get_fs_size(char *s)
{
  struct statvfs vfs;

  if(statvfs(s,&vfs) != 0)
    return 0;

  return _calc_fs(vfs.f_bavail,vfs.f_frsize);
}
#elif defined(HAVE_SYS_VFS_H)
unsigned long get_fs_size(char *s)
{
  struct statfs vfs;

  if(statfs(s,&vfs) != 0)
    return 0;

  return _calc_fs(vfs.f_bavail,vfs.f_bsize);
}
#endif /* HAVE_SYS_STATVFS/HAVE_SYS_VFS */

/* "safe" strcat, saves room for \0 at end of dest, and refuses to copy
 * more than "n" bytes.
 */

char *sstrcat(char *dest, const char *src, size_t n) {
  register char *d;
  
  for(d = dest; *d && n > 1; d++, n--) ;
  
  while(n-- > 1 && *src)
    *d++ = *src++;
  
  *d = 0;
  return dest;
}

/* "safe" strncpy, saves room for \0 at end of dest, and refuses to copy
 * more than "n" bytes.
 */
char *sstrncpy(char *dest, const char *src, size_t n) {
  register char *d;
  
  if(!dest || !src)
    return NULL;
  
  for(d = dest; *src && n > 1; n--)
    *d++ = *src++;
  
  *d = 0;
  
  return dest;
}
