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

/* Various basic support routines for ProFTPD, used by all modules
 * and not specific to one or another.
 * $Id: support.c,v 1.39 2002-10-17 00:37:45 castaglia Exp $
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

static pool *exithandler_pool = NULL;

typedef struct _exithandler {
  struct _exithandler *next,*prev;

  void (*exit)();
} exithandler_t;

typedef struct _sched {
  struct _sched *next,*prev;

  pool *pool;
  void (*f)(void*,void*,void*,void*);
  int loops;
  void *a1,*a2,*a3,*a4;
} sched_t;

static xaset_t *scheds = NULL;
static xaset_t *exits = NULL;

/* Masks/unmasks all important signals (as opposed to * block_alarms)
 */
static void mask_signals(unsigned char block) {
  static sigset_t sigset;

  if (block) {
    sigemptyset(&sigset);

    sigaddset(&sigset,SIGTERM);
    sigaddset(&sigset,SIGCHLD);
    sigaddset(&sigset,SIGUSR1);
    sigaddset(&sigset,SIGINT);
    sigaddset(&sigset,SIGQUIT);
    sigaddset(&sigset,SIGALRM);
#ifdef SIGIO
    sigaddset(&sigset,SIGIO);
#endif
#ifdef SIGBUS
    sigaddset(&sigset,SIGBUS);
#endif
    sigaddset(&sigset,SIGHUP);

    sigprocmask(SIG_BLOCK,&sigset,NULL);

  } else {
    sigprocmask(SIG_UNBLOCK,&sigset,NULL);

    /* If unmasking, handle any signals that may have been delivered while
     * masked.
     */
    pr_handle_signals();
  }
}

void block_signals(void) {
  mask_signals(TRUE);
}

void unblock_signals(void) {
  mask_signals(FALSE);
}

void add_exit_handler(void (*exit)()) {
  exithandler_t *e = NULL;

  if (!exithandler_pool)
    exithandler_pool = make_sub_pool(permanent_pool);

  if (!exits)
    exits = xaset_create(exithandler_pool, NULL);

  e = pcalloc(exithandler_pool, sizeof(exithandler_t));
  e->exit = exit;

  xaset_insert(exits, (xasetmember_t *) e);
}

void remove_exit_handlers(void) {
  if (exits)
    exits = NULL;

  if (exithandler_pool) {
    destroy_pool(exithandler_pool);
    exithandler_pool = NULL;
  }
}

void run_exit_handlers(void) {
  exithandler_t *e = NULL;

  if (!exits)
    return;

  for (e = (exithandler_t *) exits->xas_list; e; e = e->next)
    e->exit();
}

void schedule(void (*f)(void*,void*,void*,void*),int nloops,
              void *a1, void *a2, void *a3, void *a4)
{
  pool *p, *sub_pool;
  sched_t *s;

  if (!scheds) {
   p = make_sub_pool(permanent_pool);
   scheds = xaset_create(p, NULL);

  } else
   p = scheds->mempool;

  sub_pool = make_sub_pool(p);

  s = pcalloc(sub_pool, sizeof(sched_t));
  s->pool = sub_pool;
  s->f = f;
  s->a1 = a1;
  s->a2 = a2;
  s->a3 = a3;
  s->a4 = a4;
  s->loops = nloops;
  xaset_insert(scheds,(xasetmember_t*)s);
}

void run_schedule(void) {
  sched_t *s,*snext;

  if(!scheds || !scheds->xas_list)
    return;

  for(s = (sched_t*)scheds->xas_list; s; s=snext) {
    snext = s->next;

    if(s->loops-- <= 0) {
      s->f(s->a1,s->a2,s->a3,s->a4);
      xaset_remove(scheds,(xasetmember_t*)s);
      destroy_pool(s->pool);
    }
  }
}

/*
** Get the maximum size of a file name (pathname component).
** If a directory file descriptor, e.g. the d_fd DIR structure element,
** is not available, the second argument should be 0.
**
** Note: a POSIX compliant system typically should NOT define NAME_MAX,
** since the value almost certainly varies across different file system types.
** Refer to POSIX 1003.1a, Section 2.9.5, Table 2-5.
** Alas, current (Jul 2000) Linux systems define NAME_MAX anyway.
** NB: NAME_MAX_GUESS is defined in support.h.
*/
int
get_name_max(char *dirname, int dir_fd)
{
	int	name_max = 0;
#if defined(HAVE_FPATHCONF) || defined(HAVE_PATHCONF)
	char	*msgfmt = "";

# if defined(HAVE_FPATHCONF)
	if ( dir_fd > 0 ) {
		name_max = fpathconf(dir_fd, _PC_NAME_MAX);
		msgfmt = "fpathconf(%s, _PC_NAME_MAX) = %d, errno = %d";
	}
	else
# endif
# if defined(HAVE_PATHCONF)
	if ( dirname != NULL ) {
		name_max = pathconf(dirname, _PC_NAME_MAX);
		msgfmt = "pathconf(%s, _PC_NAME_MAX) = %d, errno = %d";
	}
	else
# endif
		/* no data provided to use either pathconf() or fpathconf() */
		return -1;
	if ( name_max < 0 ) {
		/*
		** NB: errno may not be set if the failure is due
		** to a limit or option not being supported.
		*/
		log_debug(DEBUG1, msgfmt,
				dirname ? dirname : "(NULL)", name_max, errno);
	}
#else
	name_max = NAME_MAX_GUESS;
#endif

	return name_max;
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
  char workpath[MAXPATHLEN + 1] = {'\0'};
  char realpath[MAXPATHLEN + 1] = {'\0'};
  char *target = NULL, *ntarget;
  int fini = 0;

  if(*path == '~') {
    if(fs_interpolate(path,workpath,MAXPATHLEN) != 1)
      fs_dircat(workpath,sizeof(workpath),fs_getcwd(),path);
  } else {
    fs_dircat(workpath,sizeof(workpath),fs_getcwd(),path);
  }

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
  char buf[MAXPATHLEN + 1]  = {'\0'};
  char work[MAXPATHLEN + 1] = {'\0'};

  if(*path == '~') {
    if(fs_interpolate(path,work,MAXPATHLEN) != 1)
      fs_dircat(work, sizeof(work), fs_getcwd(), path);
  } else {
    fs_dircat(work, sizeof(work), fs_getcwd(), path);
  }
  
  fs_clean_path(work, buf, MAXPATHLEN);
  return pstrdup(p, buf);
}

/* dir_realpath() is needed to properly dereference symlinks (getcwd() may
 * not work if permissions cause problems somewhere up the tree).
 */

char *dir_realpath(pool *p, const char *path)
{
  char buf[MAXPATHLEN + 1] = {'\0'};

  if(fs_resolve_partial(path,buf,MAXPATHLEN,0) == -1)
    return NULL;

  return pstrdup(p,buf);
}

char *dir_virtual_chdir(pool *p, const char *path)
{
  char buf[MAXPATHLEN + 1]  = {'\0'};
  char work[MAXPATHLEN + 1] = {'\0'};

  if(*path == '~') {
    if(fs_interpolate(path,work,MAXPATHLEN) != 1)
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

/* Return the mode (including the file type)
   of the file pointed to by symlink PATH, or 0 if it doesn't exist.
   Catch symlink loops using LAST_INODE and RCOUNT.  */

static mode_t _symlink(char *path, ino_t last_inode, int rcount)
{
  char buf[MAXPATHLEN + 1];
  struct stat sbuf;
  int i;

  if(++rcount >= 32) {
    errno = ELOOP;
    return 0;
  }

  memset(buf,'\0',sizeof(buf));

  i = fs_readlink(path,buf,sizeof(buf) - 1);
  if(i == -1)
    return (mode_t)0;
  buf[i] = '\0';

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

  if(fs_lstat(path,&sbuf) != -1) {
    if(S_ISLNK(sbuf.st_mode)) {
      res = _symlink(path,(ino_t)0,0);
      if (res == 0)
	/* a dangling symlink, but it exists to rename or delete. */
	res = sbuf.st_mode;
    }
    else
      res = sbuf.st_mode;
  }

  return res;
}

/* If DIRP == 1, fail unless PATH is an existing directory.
   If DIRP == 0, fail unless PATH is an existing non-directory.
   If DIRP == -1, fail unless PATH exists; the caller doesn't care whether
   PATH is a file or a directory. */

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

/* Perform access check for effective user id, similar to accessx(...,
 * ACC_SELF) on AIX.
 */
int access_check(char *path, int mode) {
  mode_t mask;
  struct stat buf;
  
  if(fs_stat(path, &buf) < 0) {
    errno = ENOENT;
    return -1;
  }
 
  /* If root, always return succeed. */
  if (session.uid == 0)
    return 0;

  /* Initialize `mask' to reflect the permission bits that are
   * applicable for the effective user. `mask' contains the user-bits
   * if the effective user id equals the id of the file owner. `mask'
   * contains the group bits if the group id is if the effective user
   * belongs to the group of the file. `mask' will always contain the
   * other bits of the permission bits.
   */
  mask = S_IROTH | S_IWOTH | S_IXOTH;
  
  if (buf.st_uid == session.uid)
    mask |= S_IRUSR|S_IWUSR|S_IXUSR;

  /* Check the current group, as well as all supplementary groups.
   * Fortunately, we have this information cached, so accessing it is
   * almost free.
   */
  if (buf.st_gid == session.gid) {
    mask |= S_IRGRP | S_IWGRP | S_IXGRP;

  } else {
    if (session.gids) {
      register unsigned int i = 0;

      for (i = 0; i < session.gids->nelts; i++) {
        if (buf.st_gid == ((gid_t *) session.gids->elts)[i]) {
	  mask |= S_IRGRP|S_IWGRP|S_IXGRP;
	  break;
        }
      }
    }
  }
  
  mask &= buf.st_mode;
  
  /* Perform requested access checks */
  if (mode & R_OK) {
    if (!(mask & (S_IRUSR|S_IRGRP|S_IROTH))) {
      errno = EACCES;
      return -1;
    }
  }
  
  if (mode & W_OK) {
    if (!(mask & (S_IWUSR|S_IWGRP|S_IWOTH))) {
      errno = EACCES;
      return -1;
    }
  }
  
  if (mode & X_OK) {
    if (!(mask & (S_IXUSR|S_IXGRP|S_IXOTH))) {
      errno = EACCES;
      return -1;
    }
  }

  /* F_OK already checked by checking the return value of stat */
  return 0;
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
  char *deny_str,*disc_str,*cp, buf[1025] = {'\0'};
  char hr[3] = {'\0'}, mn[3] = {'\0'};
  time_t now,shuttime = (time_t)0;
  struct tm tm;

  if(file_exists(SHUTMSG_PATH) && (fp = fopen(SHUTMSG_PATH,"r"))) {
    if((cp = fgets(buf,sizeof(buf),fp)) != NULL) {
      buf[sizeof(buf)-1] = '\0'; CHOP(cp);

      /* We use this to fill in dst, timezone, etc */
      time(&now);
      tm = *(localtime(&now));

      tm.tm_year = atoi(safe_token(&cp)) - 1900;
      tm.tm_mon = atoi(safe_token(&cp)) - 1;
      tm.tm_mday = atoi(safe_token(&cp));
      tm.tm_hour = atoi(safe_token(&cp));
      tm.tm_min = atoi(safe_token(&cp));
      tm.tm_sec = atoi(safe_token(&cp));

      deny_str = safe_token(&cp);
      disc_str = safe_token(&cp);

      if((shuttime = mktime(&tm)) == (time_t) - 1) {
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
        buf[sizeof(buf)-1] = '\0';
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

/* Make sure we don't display any sensitive information via argstr. Note:
 * make this a separate function in the future (get_full_cmd() or somesuch),
 * and have that function deal with creating a displayable string.  Once
 * RFC2228 support is added, PASS won't be the only command whose parameters
 * should not be displayed.
 */
char *make_arg_str(pool *p, int argc, char **argv) {
  char *res = "";

  /* Check for "sensitive" commands. */
  if (!strcmp(argv[0], "PASS") ||
      !strcmp(argv[0], "ADAT")) {
    argc = 2;
    argv[1] = "(hidden)";
  }

  while (argc--) {
    if (*res)
      res = pstrcat(p, res," ", *argv++, NULL);
    else
      res = pstrcat(p, res, *argv++, NULL);
  } 

  return res;
}

char *sreplace(pool *p, char *s, ...)
{
  va_list args;
  char *m,*r,*src = s,*cp;
  char **mptr,**rptr;
  char *marr[33],*rarr[33];
  char buf[2048] = {'\0'}, *pbuf = NULL;
  int  mlen = 0, rlen = 0;
  int  blen, dyn=1;

  cp = buf;
  *cp = '\0';
  
  memset(marr,'\0',sizeof(marr));
  memset(rarr,'\0',sizeof(rarr));
  blen=strlen(src)+1;

  va_start(args,s);

  while((m = va_arg(args,char*)) != NULL && mlen < 32) {
    if((r = va_arg(args,char*)) == NULL)
      break;
    blen += (strlen(r) - strlen(m));
    marr[mlen] = m;
    rarr[mlen++] = r;
  }

  va_end(args);

  /* Try to handle large buffer situations (i.e. escaping of MAXPATHLEN
   * (>2048) correctly, but do not allow very big buffer sizes, that may
   * be dangerous (BUFSIZ may be defined in stdio.h) in some library
   * functions.
   */
#ifndef BUFSIZ
#define BUFSIZ 8192
#endif

  if(blen < BUFSIZ) {
    cp = pbuf = (char *) pcalloc(p, ++blen);
  }
  
  if(!pbuf) {
    cp   = pbuf = buf;
    dyn  = 0;
    blen = sizeof(buf);
  }
  
  while(*src) {
    for(mptr = marr, rptr = rarr; *mptr; mptr++, rptr++) {
      mlen = strlen(*mptr);
      rlen = strlen(*rptr);

      if(strncmp(src,*mptr,mlen) == 0) {
        sstrncpy(cp,*rptr, blen - strlen(pbuf));
	if(((cp + rlen) - pbuf + 1) > blen) {
	  log_pri(PR_LOG_ERR,
		  "Warning, attempt to overflow internal ProFTPD buffers.");
	  cp = pbuf + blen - 1;
	  goto done;
	} else {
	  cp += rlen;
	}
	
        src += mlen;
        break;
      }
    }
    
    if(!*mptr) {
      if((cp - pbuf + 1) > blen) {
	log_pri(PR_LOG_ERR,
		"Warning, attempt to overflow internal ProFTPD buffers.");
	cp = pbuf + blen - 1;
      }
      *cp++ = *src++;
    }
  }
  
 done:
  *cp = '\0';

  if(dyn)
    return pbuf;
  return pstrdup(p,buf);
}

#if defined(HAVE_SYS_STATVFS_H) || defined(HAVE_SYS_VFS_H)
/* Simple multiplication & division doesn't work with very large
 * filesystems (overflows 32 bits).  This code should handle it.
 */

static off_t _calc_fs(size_t blocks, size_t bsize) {
  off_t bl_lo,bl_hi;
  off_t res_lo,res_hi,tmp;

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

# ifdef HAVE_SYS_STATVFS_H
off_t get_fs_size(char *s) {
  struct statvfs vfs;

  if(statvfs(s,&vfs) != 0)
    return 0;

  return _calc_fs(vfs.f_bavail,vfs.f_frsize);
}
# elif defined(HAVE_SYS_VFS_H)
off_t get_fs_size(char *s) {
  struct statfs vfs;

  if(statfs(s,&vfs) != 0)
    return 0;

  return _calc_fs(vfs.f_bavail,vfs.f_bsize);
}
# endif /* no HAVE_SYS_STATVFS/HAVE_SYS_VFS */
#endif /* no HAVE_SYS_STATVFS/HAVE_SYS_VFS */

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
  register char *d = dest;
  
  if(!dest)
    return NULL;
  
  if(src && *src) {
    for(; *src && n > 1; n--)
      *d++ = *src++;
  }
  
  *d = '\0';
  
  return dest;
}
