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

/* Various basic support routines for ProFTPD, used by all modules
 * and not specific to one or another.
 *
 * $Id: support.c,v 1.60 2003-08-01 01:05:25 castaglia Exp $
 */

#include "conf.h"

#include <signal.h>

#ifdef HAVE_SYS_STATVFS_H
# include <sys/statvfs.h>
#elif defined(HAVE_SYS_VFS_H)
# include <sys/vfs.h>
#elif defined(HAVE_SYS_MOUNT_H)
# include <sys/mount.h>
#endif

#ifdef AIX3
# include <sys/statfs.h>
#endif

static pool *exithandler_pool = NULL;

typedef struct exit_obj {
  struct exit_obj *next, *prev;

  void (*exit_cb)(void);
} exithandler_t;

typedef struct sched_obj {
  struct sched_obj *next, *prev;

  pool *pool;
  void (*f)(void*,void*,void*,void*);
  int loops;
  void *a1,*a2,*a3,*a4;
} sched_t;

static xaset_t *scheds = NULL;
static xaset_t *exits = NULL;

/* Masks/unmasks all important signals (as opposed to blocking alarms)
 */
static void mask_signals(unsigned char block) {
  static sigset_t mask_sigset;

  if (block) {
    sigemptyset(&mask_sigset);

    sigaddset(&mask_sigset, SIGTERM);
    sigaddset(&mask_sigset, SIGCHLD);
    sigaddset(&mask_sigset, SIGUSR1);
    sigaddset(&mask_sigset, SIGINT);
    sigaddset(&mask_sigset, SIGQUIT);
    sigaddset(&mask_sigset, SIGALRM);
#ifdef SIGIO
    sigaddset(&mask_sigset, SIGIO);
#endif
#ifdef SIGBUS
    sigaddset(&mask_sigset, SIGBUS);
#endif
    sigaddset(&mask_sigset, SIGHUP);

    sigprocmask(SIG_BLOCK, &mask_sigset, NULL);

  } else
    sigprocmask(SIG_UNBLOCK, &mask_sigset, NULL);
}

void pr_signals_block(void) {
  mask_signals(TRUE);
}

void pr_signals_unblock(void) {
  mask_signals(FALSE);
}

void pr_exit_register_handler(void (*exit_cb)(void)) {
  exithandler_t *e = NULL;

  if (!exithandler_pool)
    exithandler_pool = make_sub_pool(permanent_pool);

  if (!exits)
    exits = xaset_create(exithandler_pool, NULL);

  e = pcalloc(exithandler_pool, sizeof(exithandler_t));
  e->exit_cb = exit_cb;

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
    e->exit_cb();
}

void schedule(void (*f)(void*,void*,void*,void*),int nloops, void *a1,
    void *a2, void *a3, void *a4) {
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
  xaset_insert(scheds, (xasetmember_t*)s);
}

void run_schedule(void) {
  sched_t *s,*snext;

  if (!scheds || !scheds->xas_list)
    return;

  for (s = (sched_t*)scheds->xas_list; s; s=snext) {
    snext = s->next;

    if (s->loops-- <= 0) {
      s->f(s->a1,s->a2,s->a3,s->a4);
      xaset_remove(scheds, (xasetmember_t*)s);
      destroy_pool(s->pool);
    }
  }
}

/* Get the maximum size of a file name (pathname component).
 * If a directory file descriptor, e.g. the d_fd DIR structure element,
 * is not available, the second argument should be 0.
 *
 * Note: a POSIX compliant system typically should NOT define NAME_MAX,
 * since the value almost certainly varies across different file system types.
 * Refer to POSIX 1003.1a, Section 2.9.5, Table 2-5.
 * Alas, current (Jul 2000) Linux systems define NAME_MAX anyway.
 * NB: NAME_MAX_GUESS is defined in support.h.
 */
int get_name_max(char *dirname, int dir_fd) {
  int name_max = 0;
#if defined(HAVE_FPATHCONF) || defined(HAVE_PATHCONF)
  char *msgfmt = "";

# if defined(HAVE_FPATHCONF)
  if (dir_fd > 0) {
    name_max = fpathconf(dir_fd, _PC_NAME_MAX);
    msgfmt = "fpathconf(%s, _PC_NAME_MAX) = %d, errno = %d";
  } else
# endif
# if defined(HAVE_PATHCONF)
  if (dirname != NULL) {
    name_max = pathconf(dirname, _PC_NAME_MAX);
    msgfmt = "pathconf(%s, _PC_NAME_MAX) = %d, errno = %d";
  } else
# endif
  /* No data provided to use either pathconf() or fpathconf() */
  return -1;

  if (name_max < 0) {
    /* NB: errno may not be set if the failure is due to a limit or option
     * not being supported.
     */
    log_debug(DEBUG1, msgfmt, dirname ? dirname : "(NULL)", name_max, errno);
  }

#else
  name_max = NAME_MAX_GUESS;
#endif /* HAVE_FPATHCONF or HAVE_PATHCONF */

  return name_max;
}


/* Interpolates a pathname, expanding ~ notation if necessary
 */
char *dir_interpolate(pool *p, const char *path) {
  struct passwd *pw;
  char *user,*tmp;
  char *ret = (char *)path;

  if (!ret)
    return NULL;

  if (*ret == '~') {
    user = pstrdup(p, ret+1);
    tmp = strchr(user, '/');

    if (tmp)
      *tmp++ = '\0';

    if (!*user)
      user = session.user;

    pw = auth_getpwnam(p, user);

    if (!pw) {
      errno = ENOENT;
      return NULL;
    }

    ret = pdircat(p, pw->pw_dir, tmp, NULL);
  }

  return ret;
}

/* dir_best_path() creates the "most" fully canonicalized path possible
 * (i.e. if path components at the end don't exist, they are ignored
 */
char *dir_best_path(pool *p, const char *path) {
  char workpath[PR_TUNABLE_PATH_MAX + 1] = {'\0'};
  char realpath_buf[PR_TUNABLE_PATH_MAX + 1] = {'\0'};
  char *target = NULL, *ntarget;
  int fini = 0;

  if (*path == '~') {
    if (pr_fs_interpolate(path, workpath, sizeof(workpath)-1) != 1) {
      if (pr_fs_dircat(workpath, sizeof(workpath), pr_fs_getcwd(), path) < 0)
        return NULL;
    }

  } else {
    if (pr_fs_dircat(workpath, sizeof(workpath), pr_fs_getcwd(), path) < 0)
      return NULL;
  }

  pr_fs_clean_path(pstrdup(p, workpath), workpath, sizeof(workpath)-1);

  while (!fini && *workpath) {
    if (pr_fs_resolve_path(workpath, realpath_buf,
        sizeof(realpath_buf)-1, 0) != -1)
      break;

    ntarget = strrchr(workpath, '/');
    if (ntarget) {
      if (target) {
        if (pr_fs_dircat(workpath, sizeof(workpath), workpath, target) < 0)
          return NULL;
      }

      target = ntarget;
      *target++ = '\0';

    } else
      fini++;
  }

  if (!fini && *workpath) {
    if (target) {
      if (pr_fs_dircat(workpath, sizeof(workpath), realpath_buf, target) < 0)
        return NULL;

    } else
      sstrncpy(workpath, realpath_buf, sizeof(workpath));

  } else {
    if (pr_fs_dircat(workpath, sizeof(workpath), "/", target) < 0)
      return NULL;
  }

  return pstrdup(p, workpath);
}

char *dir_canonical_path(pool *p, const char *path) {
  char buf[PR_TUNABLE_PATH_MAX + 1]  = {'\0'};
  char work[PR_TUNABLE_PATH_MAX + 1] = {'\0'};

  if (*path == '~') {
    if (pr_fs_interpolate(path, work, sizeof(work)-1) != 1) {
      if (pr_fs_dircat(work, sizeof(work), pr_fs_getcwd(), path) < 0)
        return NULL;
    }

  } else {
    if (pr_fs_dircat(work, sizeof(work), pr_fs_getcwd(), path) < 0)
      return NULL;
  }

  pr_fs_clean_path(work, buf, sizeof(buf)-1);
  return pstrdup(p, buf);
}

char *dir_canonical_vpath(pool *p, const char *path) {
  char buf[PR_TUNABLE_PATH_MAX + 1]  = {'\0'};
  char work[PR_TUNABLE_PATH_MAX + 1] = {'\0'};

  if (*path == '~') {
    if (pr_fs_interpolate(path, work, sizeof(work)-1) != 1) {
      if (pr_fs_dircat(work, sizeof(work), pr_fs_getvwd(), path) < 0)
        return NULL;
    }

  } else {
    if (pr_fs_dircat(work, sizeof(work), pr_fs_getvwd(), path) < 0)
      return NULL;
  }

  pr_fs_clean_path(work, buf, sizeof(buf)-1);
  return pstrdup(p, buf);
}

/* dir_realpath() is needed to properly dereference symlinks (getcwd() may
 * not work if permissions cause problems somewhere up the tree).
 */
char *dir_realpath(pool *p, const char *path) {
  char buf[PR_TUNABLE_PATH_MAX + 1] = {'\0'};

  if (pr_fs_resolve_partial(path, buf, sizeof(buf)-1, 0) == -1)
    return NULL;

  return pstrdup(p, buf);
}

/* Takes a directory and returns it's absolute version.  ~username
 * references are appropriately interpolated.  "Absolute" includes
 * a *full* reference based on the root directory, not upon a chrooted
 * dir.
 */
char *dir_abs_path(pool *p, const char *path, int interpolate) {
  char *res = NULL;

  if (interpolate)
    path = dir_interpolate(p, path);

  if (!path)
    return NULL;

  if (*path != '/') {
    if (session.chroot_path)
      res = pdircat(p, session.chroot_path, pr_fs_getcwd(), path, NULL);
    else
      res = pdircat(p, pr_fs_getcwd(), path, NULL);

  } else if (session.chroot_path)
    res = pdircat(p, session.chroot_path, path, NULL);

  else
    res = pstrdup(p, path);

  return res;
}

/* Return the mode (including the file type) of the file pointed to by symlink
 * PATH, or 0 if it doesn't exist. Catch symlink loops using LAST_INODE and
 * RCOUNT.
 */
static mode_t _symlink(char *path, ino_t last_inode, int rcount) {
  char buf[PR_TUNABLE_PATH_MAX + 1];
  struct stat sbuf;
  int i;

  if (++rcount >= 32) {
    errno = ELOOP;
    return 0;
  }

  memset(buf, '\0', sizeof(buf));

  i = pr_fsio_readlink(path, buf, sizeof(buf) - 1);
  if (i == -1)
    return (mode_t)0;
  buf[i] = '\0';

  if (pr_fsio_lstat(buf, &sbuf) != -1) {
    if (sbuf.st_ino && (ino_t) sbuf.st_ino == last_inode) {
      errno = ELOOP;
      return 0;
    }

    if (S_ISLNK(sbuf.st_mode))
      return _symlink(buf, (ino_t) sbuf.st_ino, rcount);
    return sbuf.st_mode;
  }

  return 0;
}

mode_t file_mode(char *path) {
  struct stat sbuf;
  mode_t res = 0;

  pr_fs_clear_cache();
  if (pr_fsio_lstat(path, &sbuf) != -1) {
    if (S_ISLNK(sbuf.st_mode)) {
      res = _symlink(path, (ino_t) 0, 0);

      if (res == 0)
	/* a dangling symlink, but it exists to rename or delete. */
	res = sbuf.st_mode;

    } else
      res = sbuf.st_mode;
  }

  return res;
}

/* If DIRP == 1, fail unless PATH is an existing directory.
 * If DIRP == 0, fail unless PATH is an existing non-directory.
 * If DIRP == -1, fail unless PATH exists; the caller doesn't care whether
 * PATH is a file or a directory.
 */
static int _exists(char *path, int dirp) {
  mode_t fmode;

  if ((fmode = file_mode(path)) != 0) {
    if (dirp == 1 && !S_ISDIR(fmode))
      return FALSE;

    else if (dirp == 0 && S_ISDIR(fmode))
      return FALSE;

    return TRUE;
  }

  return FALSE;
}

int file_exists(char *path) {
  return _exists(path, 0);
}

int dir_exists(char *path) {
  return _exists(path, 1);
}

int exists(char *path) {
  return _exists(path, -1);
}

/* Perform access check for effective user id, similar to accessx(...,
 * ACC_SELF) on AIX.
 */
int access_check(char *path, int mode) {
  mode_t mask;
  struct stat buf;

  pr_fs_clear_cache();
  if (pr_fsio_stat(path, &buf) < 0) {
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

char *strip_end(char *s, char *ch) {
  int i = strlen(s);

  while (i && strchr(ch,*(s+i-1))) {
    *(s+i-1) = '\0';
    i--;
  }

  return s;
}

/* get_token tokenizes a string, increments the src pointer to
 * the next non-separator in the string.  If the src string is
 * empty or NULL, the next token returned is NULL.
 */
char *get_token(char **s, char *sep) {
  char *res;

  if (!s || !*s || !**s)
    return NULL;

  res = *s;

  while (**s && !strchr(sep,**s))
    (*s)++;

  if (**s)
    *(*s)++ = '\0';

  return res;
}

/* safe_token tokenizes a string, and increments the pointer to
 * the next non-white space character.  It's "safe" because it
 * never returns NULL, only an empty string if no token remains
 * in the source string.
 */
char *safe_token(char **s) {
  char *res = "";

  if (!s || !*s)
    return res;

  while (isspace((int) **s) && **s)
    (*s)++;

  if (**s) {
    res = *s;

    while (!isspace((int) **s) && **s)
      (*s)++;

    if (**s)
      *(*s)++ = '\0';

    while (isspace((int) **s) && **s)
      (*s)++;
  }

  return res;
}

/* Checks for the existance of SHUTMSG_PATH.  deny and disc are
 * filled with the times to deny new connections and disconnect
 * existing ones.
 */
int check_shutmsg(time_t *shut, time_t *deny, time_t *disc, char *msg,
                  size_t msg_size) {
  FILE *fp;
  char *deny_str,*disc_str,*cp, buf[PR_TUNABLE_BUFFER_SIZE+1] = {'\0'};
  char hr[3] = {'\0'}, mn[3] = {'\0'};
  time_t now,shuttime = (time_t)0;
  struct tm tm;

  if (file_exists(SHUTMSG_PATH) && (fp = fopen(SHUTMSG_PATH, "r"))) {
    if ((cp = fgets(buf, sizeof(buf),fp)) != NULL) {
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

      if ((shuttime = mktime(&tm)) == (time_t) - 1) {
        fclose(fp);
        return 0;
      }

      if (deny) {
        if (strlen(deny_str) == 4) {
          sstrncpy(hr,deny_str,sizeof(hr)); hr[2] = '\0'; deny_str += 2;
          sstrncpy(mn,deny_str,sizeof(mn)); mn[2] = '\0';

          *deny = shuttime - ((atoi(hr) * 3600) + (atoi(mn) * 60));
        } else
          *deny = shuttime;
      }

      if (disc) {
        if (strlen(disc_str) == 4) {
          sstrncpy(hr,disc_str,sizeof(hr)); hr[2] = '\0'; disc_str += 2;
          sstrncpy(mn,disc_str,sizeof(mn)); mn[2] = '\0';

          *disc = shuttime - ((atoi(hr) * 3600) + (atoi(mn) * 60));
        } else
          *disc = shuttime;
      }

      if (fgets(buf, sizeof(buf),fp) && msg) {
        buf[sizeof(buf)-1] = '\0';
	CHOP(buf);
        sstrncpy(msg, buf, msg_size-1);
      }
    }

    fclose(fp);
    if (shut)
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
  if (!strcmp(argv[0], C_PASS) ||
      !strcmp(argv[0], C_ADAT)) {
    argc = 2;
    argv[1] = "(hidden)";
  }

  while (argc--) {
    if (*res)
      res = pstrcat(p, res, " ", *argv++, NULL);
    else
      res = pstrcat(p, res, *argv++, NULL);
  }

  return res;
}

char *sreplace(pool *p, char *s, ...) {
  va_list args;
  char *m,*r,*src = s,*cp;
  char **mptr,**rptr;
  char *marr[33],*rarr[33];
  char buf[PR_TUNABLE_PATH_MAX] = {'\0'}, *pbuf = NULL;
  int mlen = 0, rlen = 0;
  int blen, dyn = 1;

  cp = buf;
  *cp = '\0';

  memset(marr, '\0', sizeof(marr));
  memset(rarr, '\0', sizeof(rarr));
  blen = strlen(src) + 1;

  va_start(args, s);

  while ((m = va_arg(args, char *)) != NULL && mlen < 32) {
    if ((r = va_arg(args, char *)) == NULL)
      break;
    blen += (strlen(r) - strlen(m));
    marr[mlen] = m;
    rarr[mlen++] = r;
  }

  va_end(args);

  /* Try to handle large buffer situations (i.e. escaping of PR_TUNABLE_PATH_MAX
   * (>2048) correctly, but do not allow very big buffer sizes, that may
   * be dangerous (BUFSIZ may be defined in stdio.h) in some library
   * functions.
   */
#ifndef BUFSIZ
# define BUFSIZ 8192
#endif

  if (blen < BUFSIZ)
    cp = pbuf = (char *) pcalloc(p, ++blen);

  if (!pbuf) {
    cp = pbuf = buf;
    dyn = 0;
    blen = sizeof(buf);
  }

  while (*src) {
    for (mptr = marr, rptr = rarr; *mptr; mptr++, rptr++) {
      mlen = strlen(*mptr);
      rlen = strlen(*rptr);

      if (strncmp(src, *mptr, mlen) == 0) {
        sstrncpy(cp, *rptr, blen - strlen(pbuf));
	if (((cp + rlen) - pbuf + 1) > blen) {
	  log_pri(PR_LOG_ERR,
		  "WARNING: attempt to overflow internal ProFTPD buffers");
	  cp = pbuf + blen - 1;
	  goto done;

	} else {
	  cp += rlen;
	}
	
        src += mlen;
        break;
      }
    }

    if (!*mptr) {
      if ((cp - pbuf + 1) > blen) {
	log_pri(PR_LOG_ERR,
		"WARNING: attempt to overflow internal ProFTPD buffers");
	cp = pbuf + blen - 1;
      }
      *cp++ = *src++;
    }
  }

 done:
  *cp = '\0';

  if (dyn)
    return pbuf;

  return pstrdup(p, buf);
}

/* "safe" memset() (code borrowed from OpenSSL).  This function should be
 * used to clear/scrub sensitive memory areas instead of memset() for the
 * reasons mentioned in this BugTraq thread:
 *
 *  http://online.securityfocus.com/archive/1/298598
 */

unsigned char memscrub_ctr = 0;

void pr_memscrub(void *ptr, size_t ptrlen) {
  unsigned char *p = ptr;
  size_t loop = ptrlen;

  while (loop--) {
    *(p++) = memscrub_ctr++;
    memscrub_ctr += (17 + (unsigned char)((int) p & 0xF));
  }

  if (memchr(ptr, memscrub_ctr, ptrlen))
    memscrub_ctr += 63;
}

/* "safe" strcat, saves room for \0 at end of dest, and refuses to copy
 * more than "n" bytes.
 */
char *sstrcat(char *dest, const char *src, size_t n) {
  register char *d;

  for (d = dest; *d && n > 1; d++, n--) ;

  while (n-- > 1 && *src)
    *d++ = *src++;

  *d = 0;
  return dest;
}

/* "safe" strncpy, saves room for \0 at end of dest, and refuses to copy
 * more than "n" bytes.
 */
char *sstrncpy(char *dest, const char *src, size_t n) {
  register char *d = dest;

  if (!dest)
    return NULL;

  if (src && *src) {
    for (; *src && n > 1; n--)
      *d++ = *src++;
  }

  *d = '\0';

  return dest;
}
