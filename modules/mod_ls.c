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

/* Directory listing module for ProFTPD.
 * $Id: mod_ls.c,v 1.74 2002-12-07 21:43:44 jwm Exp $
 */

#include "conf.h"

#ifndef GLOB_ABORTED
#define GLOB_ABORTED GLOB_ABEND
#endif

#define MAP_UID(x)	(fakeuser ? fakeuser : auth_uid_name(cmd->tmp_pool,(x)))
#define MAP_GID(x)	(fakegroup ? fakegroup : auth_gid_name(cmd->tmp_pool,(x)))

static void addfile(cmd_rec*,const char *, const char *, time_t);
static int outputfiles(cmd_rec*);

static int listfile(cmd_rec*, pool*, const char *name);
static int listdir(cmd_rec*, pool*, const char *name);

static int matches = 0;
static unsigned char strict_list_opts = FALSE;
static char *list_options = NULL;
static unsigned char list_show_symlinks = TRUE, list_times_gmt = TRUE;
static unsigned char show_symlinks_hold;
static int cmp(const void *a, const void *b);
static char *fakeuser, *fakegroup;
static mode_t fakemode;
static unsigned char have_fake_mode = FALSE;
static int ls_errno = 0;
static time_t ls_curtime = 0;

static unsigned char use_globbing = TRUE;

/* ls options */
static int
    opt_a = 0,
    opt_A = 0,
    opt_C = 0,
    opt_d = 0,
    opt_F = 0,
    opt_l = 0,
    opt_L = 0,
    opt_n = 0,
    opt_R = 0,
    opt_r = 0,
    opt_t = 0,
    opt_STAT = 0;

static char cwd[MAXPATHLEN + 1] = "";

/* Find a <Limit> block that limits the given command (which will probably
 * be LIST).  This code borrowed for src/dirtree.c's _dir_check_limit().
 * Note that this function is targeted specifically for ls commands (eg
 * LIST, NLST, DIRS, and ALL) that might be <Limit>'ed.
 */
static config_rec *_find_ls_limit(char *ftp_cmd) {
  config_rec *c = NULL, *limit_c = NULL;
  register int index;

  if (!ftp_cmd)
    return NULL;

  if (!session.dir_config)
    return NULL;

  /* determine whether this command is <Limit>'ed
   */
  for (c = session.dir_config; c; c = c->parent) {

    if (c->subset) {

      for (limit_c = (config_rec *) (c->subset->xas_list); limit_c;
          limit_c = limit_c->next) {

        if (limit_c->config_type == CONF_LIMIT) {

          for (index = 0; index < limit_c->argc; index++) {

            /* match any of the appropriate <Limit> arguments
             */
            if (!strcasecmp(ftp_cmd, (char *) (limit_c->argv[index])) ||
                !strcasecmp("DIRS", (char *) (limit_c->argv[index])) ||
                !strcasecmp("ALL", (char *) (limit_c->argv[index])))
              break;
          }

          if (index == limit_c->argc)
            continue;

          /* Found a <Limit> directive associated with the current command
           */
          return limit_c;
        }
      }
    }
  }

  return NULL;
}

static void push_cwd(char *_cwd, unsigned char *symhold) {
  if (!_cwd)
    _cwd = cwd;

  if (!symhold)
    *symhold = show_symlinks_hold;

  sstrncpy(_cwd, pr_fs_getcwd(), MAXPATHLEN + 1);
  *symhold = list_show_symlinks;
}

static void pop_cwd(char *_cwd, unsigned char *symhold) {
  if (!_cwd)
    _cwd = cwd;

  if (!symhold)
    *symhold = show_symlinks_hold;

  pr_fsio_chdir(_cwd, *symhold);
  list_show_symlinks = *symhold;
}

static int ls_perms_full(pool *p, cmd_rec *cmd, const char *path, int *hidden) {
  int ret, canon = 0;
  char *fullpath;
  mode_t *fake_mode = NULL;

  fullpath = dir_realpath(p, path);

  if (!fullpath) {
    fullpath = dir_canonical_path(p, path);
    canon = 1;
  }

  if (!fullpath)
    fullpath = pstrdup(p, path);

  if (canon)
    ret = dir_check_canon(p,cmd->argv[0],cmd->group,fullpath,hidden);
  else
    ret = dir_check(p,cmd->argv[0],cmd->group,fullpath,hidden);

  if (session.dir_config) {
    unsigned char *tmp = get_param_ptr(session.dir_config->subset,
      "ShowSymlinks", FALSE);

    if (tmp)
      list_show_symlinks = *tmp;
  }

  if ((fake_mode = get_param_ptr(CURRENT_CONF, "DirFakeMode", FALSE))) {
    fakemode = *fake_mode;
    have_fake_mode = TRUE;

  } else
    have_fake_mode = FALSE;

  return ret;
}

static int ls_perms(pool *p, cmd_rec *cmd, const char *path,int *hidden) {
  int ret;
  char fullpath[MAXPATHLEN + 1] = {'\0'};
  mode_t *fake_mode = NULL;

  /* no need to process dotdirs
   */
  if (is_dotdir(path))
    return 1;

  if (*path == '~')
    return ls_perms_full(p,cmd,path,hidden);

  if (*path != '/')
    pr_fs_clean_path(pdircat(p, pr_fs_getcwd(), path, NULL), fullpath,
      MAXPATHLEN);
  else
    pr_fs_clean_path(path, fullpath, MAXPATHLEN);

  ret = dir_check(p,cmd->argv[0],cmd->group,fullpath,hidden);

  if (session.dir_config) {
    unsigned char *tmp = get_param_ptr(session.dir_config->subset,
      "ShowSymlinks",FALSE);

    if (tmp)
      list_show_symlinks = *tmp;
  }

  if ((fake_mode = get_param_ptr(CURRENT_CONF, "DirFakeMode", FALSE))) {
    fakemode = *fake_mode;
    have_fake_mode = TRUE;

  } else
    have_fake_mode = FALSE;

  return ret;
}

/* sendline() now has an internal buffer, to help speed up LIST output.
 */
static int sendline(char *fmt, ...) {
  static char listbuf[PR_TUNABLE_BUFFER_SIZE] = {'\0'};
  va_list msg;
  char buf[1025] = {'\0'};
  int res = 0;

  /* A NULL fmt argument is the signal to flush the buffer */
  if (!fmt) {
    if ((res = data_xfer(listbuf, strlen(listbuf))) < 0)
      log_debug(DEBUG3, "data_xfer returned %d, error = %s.", res,
        strerror(PR_NETIO_ERRNO(session.d->outstrm)));

    memset(listbuf, '\0', sizeof(listbuf));
    return res;
  }

  va_start(msg, fmt);
  vsnprintf(buf, sizeof(buf), fmt, msg);
  va_end(msg);

  buf[1024] = '\0';

  /* If buf won't fit completely into listbuf, flush listbuf */
  if (strlen(buf) >= (sizeof(listbuf) - strlen(listbuf))) {
    if ((res = data_xfer(listbuf, strlen(listbuf))) < 0)
      log_debug(DEBUG3, "data_xfer returned %d, error = %s.", res,
        strerror(PR_NETIO_ERRNO(session.d->outstrm)));

    memset(listbuf, '\0', sizeof(listbuf));
  }

  sstrcat(listbuf, buf, sizeof(listbuf));
  return res;
}

static void ls_done(cmd_rec *cmd) {
  data_close(FALSE);
}

static char months[12][4] =
  { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

static int listfile(cmd_rec *cmd, pool *p, const char *name) {
  int		rval = 0, len;
  time_t	mtime;
  char		m[1024] = {'\0'},l[1024] = {'\0'};
  struct	stat st;

  struct	tm *t;
  char		suffix[2];
  int           hidden = 0;

  if (!p) p = cmd->tmp_pool;

  if (pr_fsio_lstat(name, &st) == 0) {
    suffix[0] = suffix[1] = '\0';

    if (S_ISLNK(st.st_mode) && (opt_L || !list_show_symlinks)) {
      /* Attempt to fully dereference symlink */
      struct stat l_st;

      pr_fs_clear_cache();
      if (pr_fsio_stat(name, &l_st) != -1) {
        memcpy(&st, &l_st, sizeof(struct stat));

        if ((len = pr_fsio_readlink(name, m, sizeof(m))) < 0)
          return 0;
        
        m[len] = '\0';

        if (!ls_perms_full(p, cmd, m, NULL))
          return 0;

      } else
        return 0;

    } else if (S_ISLNK(st.st_mode)) {

      if ((len = pr_fsio_readlink(name, l, sizeof(l))) < 0)
        return 0;

      l[len] = '\0';

      if (!ls_perms_full(p, cmd, l, &hidden))
        return 0;

    } else if (!ls_perms(p, cmd, name, &hidden))
      return 0;

    if (hidden)
      return 0;

    mtime = st.st_mtime;

    if (list_times_gmt)
      t = gmtime((time_t *) &mtime);
    else
      t = localtime((time_t *) &mtime);

    if (!t) {
      add_response_err(R_421,"Fatal error (localtime() returned NULL?!?)");
      return -1;
    }

    if (opt_F) {
      if (S_ISLNK(st.st_mode))
        suffix[0] = '@';

      else if (S_ISDIR(st.st_mode)) {
        suffix[0] = '/';
        rval = 1;

      } else if (st.st_mode & 0111)
        suffix[0] = '*';
    }

    if (opt_l) {
      sstrncpy(m, " ---------", sizeof(m));
      switch(st.st_mode & S_IFMT) {
      case S_IFREG:
        m[0] = '-';
        break;
      case S_IFLNK:
        m[0] = 'l';
        break;
      case S_IFSOCK:
        m[0] = 's';
        break;
      case S_IFBLK:
        m[0] = 'b';
        break;
      case S_IFCHR:
        m[0] = 'c';
        break;
      case S_IFIFO:
        m[0] = 'p';
        break;
      case S_IFDIR:
        m[0] = 'd';
        rval = 1;
        break;
      }

      if (m[0] != ' ') {
        char nameline[MAXPATHLEN + MAXPATHLEN + 128] = {'\0'};
        char timeline[6] = {'\0'};
        mode_t mode = st.st_mode;

        if (have_fake_mode) {
          mode = fakemode;

          if (S_ISDIR(st.st_mode)) {
            if (mode & S_IROTH) mode |= S_IXOTH;
            if (mode & S_IRGRP) mode |= S_IXGRP;
            if (mode & S_IRUSR) mode |= S_IXUSR;
          }
        }

        /*
         * The following lines were blatently ripped from stat.c, as shipped
         * with the debian 'stat' package. Can't have anything thinking I know
         * what I'm doing in here. :)
         */
        m[9] = (mode & S_IXOTH)
                ? ((mode & S_ISVTX) ? 't' : 'x')
                : ((mode & S_ISVTX) ? 'T' : '-');
        m[8] = (mode & S_IWOTH) ? 'w' : '-';
        m[7] = (mode & S_IROTH) ? 'r' : '-';
        m[6] = (mode & S_IXGRP)
                ? ((mode & S_ISGID) ? 's' : 'x')
                : ((mode & S_ISGID) ? 'S' : '-');
        m[5] = (mode & S_IWGRP) ? 'w' : '-';
        m[4] = (mode & S_IRGRP) ? 'r' : '-';
        m[3] = (mode & S_IXUSR) ? ((mode & S_ISUID)
                ? 's' : 'x')
                :  ((mode & S_ISUID) ? 'S' : '-');
        m[2] = (mode & S_IWUSR) ? 'w' : '-';
        m[1] = (mode & S_IRUSR) ? 'r' : '-';

        if (ls_curtime - mtime > 180 * 24 * 60 * 60)
          snprintf(timeline, sizeof(timeline), "%5d", t->tm_year+1900);

        else
          snprintf(timeline, sizeof(timeline), "%02d:%02d", t->tm_hour,
            t->tm_min);

        if (!opt_n) {

          /* Format nameline using user/group names. */
          snprintf(nameline, sizeof(nameline),
                   "%s %3d %-8s %-8s %8" PR_LU " %s %2d %s %s",
                   m, (int)st.st_nlink,
                   MAP_UID(st.st_uid), MAP_GID(st.st_gid), st.st_size,
                   months[t->tm_mon], t->tm_mday, timeline, name);

        } else {

          /* Format nameline using user/group IDs. */
          snprintf(nameline, sizeof(nameline),
                   "%s %3d %-8u %-8u %8" PR_LU " %s %2d %s %s",
                   m, (int)st.st_nlink,
                   (unsigned)st.st_uid, (unsigned)st.st_gid, st.st_size,
                   months[t->tm_mon], t->tm_mday, timeline, name);
        }

        if (S_ISLNK(st.st_mode)) {
          char *p = nameline + strlen(nameline);

          suffix[0] = '\0';
          if (opt_F && pr_fsio_stat(name, &st) == 0) {
            if (S_ISLNK(st.st_mode))
              suffix[0] = '@';

            else if (S_ISDIR(st.st_mode))
              suffix[0] = '/';

            else if (st.st_mode & 0111)
              suffix[0] = '*';
          }

          if (!opt_L && list_show_symlinks)
            snprintf(p, sizeof(nameline) - strlen(nameline) - 4, " -> %s", l);

          nameline[sizeof(nameline)-1] = '\0';
        }

        if (opt_STAT)
          add_response(R_211, "%s%s", nameline, suffix);
        else
          addfile(cmd, nameline, suffix, mtime);
      }

    } else {
      if (S_ISREG(st.st_mode) ||
         S_ISDIR(st.st_mode) ||
         S_ISLNK(st.st_mode))
           addfile(cmd,name,suffix,mtime);

    }
  }

  return rval;
}

static int colwidth = 0;
static int filenames = 0;

struct filename {
  struct filename *down;
  struct filename *right;
  int top;
  char line[1];
};

struct sort_filename {
  time_t mtime;
  char *name,*suffix;
};

static struct filename *head = NULL;
static struct filename *tail = NULL;
static array_header *sort_arr = NULL;
static pool *fpool = NULL;

static void addfile(cmd_rec *cmd, const char *name, const char *suffix, time_t mtime)
{
  struct 	filename *p;
  int		l;

  if (!name || !suffix)
    return;

  if (opt_t) {
    struct sort_filename *s;

    if (!fpool)
      fpool = make_sub_pool(cmd->tmp_pool);

    if (!sort_arr)
      sort_arr = make_array(fpool,50,sizeof(struct sort_filename));

    s = (struct sort_filename*)push_array(sort_arr);
    s->mtime = mtime;
    s->name = pstrdup(fpool,name);
    s->suffix = pstrdup(fpool,suffix);

    return;
  }

  matches++;

  l = strlen(name) + strlen(suffix);
  if (l > colwidth)
    colwidth = l;

  if (!fpool)
    fpool = make_sub_pool(cmd->tmp_pool);

  p = (struct filename*) pcalloc(fpool, sizeof(struct filename) + l + 1);

  snprintf(p->line, l + 1, "%s%s", name, suffix);

  if (tail)
    tail->down = p;
  else
    head = p;

  tail = p;
  filenames++;
}

static int _compare_file_mtime(
    const struct sort_filename *f1, const struct sort_filename *f2) {

  if (f1->mtime > f2->mtime)
    return -1;

  else if (f1->mtime < f2->mtime)
    return 1;

  return 0;
}

static int _compare_file_mtime_reversed(
    const struct sort_filename *f1, const struct sort_filename *f2) {
  return -_compare_file_mtime(f1, f2);
}

static void sortfiles(cmd_rec *cmd) {
  struct sort_filename *s = NULL;

  if (opt_t && sort_arr) {
    register unsigned int i = 0;

    qsort(sort_arr->elts, sort_arr->nelts, sizeof(struct sort_filename),
          (int (*)(const void*,const void*))
          (opt_r ? _compare_file_mtime_reversed : _compare_file_mtime));

    opt_t = 0;

    for (i = 0, s = (struct sort_filename *)sort_arr->elts;
        i < sort_arr->nelts; i++, s++)
      addfile(cmd, s->name, s->suffix, s->mtime);

    opt_t = 1;
  }

  sort_arr = NULL;
}

static int outputfiles(cmd_rec *cmd) {
  int n;
  struct filename *p = NULL, *q = NULL;

  if (opt_t)
    sortfiles(cmd);

  if (!head)		/* nothing to display */
    return 0;

  tail->down = NULL;
  tail = NULL;
  colwidth = ( colwidth | 7 ) + 1;
  if (opt_l || !opt_C)
    colwidth = 75;

  /* avoid division by 0 if colwidth > 75 */
  if (colwidth > 75)
    colwidth = 75;

  p = head;
  p->top = 1;
  n = (filenames + (75 / colwidth)-1) / (75 / colwidth);
  while(n && p) {
    p = p->down;
    if (p)
      p->top = 0;
    n--;
  }

  q = head;
  while(p) {
    p->top = q->top;
    q->right = p;
    q = q->down;
    p = p->down;
  }

  while(q) {
    q->right = NULL;
    q = q->down;
  }

  p = head;
  while(p && p->down && !p->down->top)
    p = p->down;
  if (p && p->down)
    p->down = NULL;

#if 0
  if (opt_l)
    if (sendline("total 0\n") < 0)
      return -1;
#endif

  p = head;
  while(p) {
    q = p;
    p = p->down;
    while(q) {
      char pad[6] = {'\0'};

      if (q->right) {
        sstrncpy(pad, "\t\t\t\t\t", sizeof(pad));
        pad[(colwidth + 7 - strlen(q->line)) / 8] = '\0';
      } else {
        sstrncpy(pad, "\n", sizeof(pad));
      }

      if (sendline("%s%s", q->line, pad) < 0)
        return -1;

      q = q->right;
    }
  }

  destroy_pool(fpool);
  fpool = NULL;
  sort_arr = NULL;
  head = tail = NULL;
  colwidth = 0;
  filenames = 0;

  /* flush the buffer */
  if (sendline(NULL) < 0)
    return -1;

  return 0;
}

static void discard_output(void) {
  if (fpool)
    destroy_pool(fpool);
  fpool = NULL;

  head = tail = NULL;
  colwidth = 0;
  filenames = 0;
}

static int cmp(const void *a, const void *b) {
  return strcmp(*(const char **)a, *(const char **)b);
}

static char **sreaddir(pool *workp, const char *dirname, const int sort) {
  DIR 		*d;
  struct	dirent *de;
  struct	stat st;
  int		i;
  char		**p;
  char		*s, *s_end;
  int		dsize, ssize;
  int		dirfd;

  if (pr_fsio_stat(dirname, &st) < 0)
    return NULL;

  if (!S_ISDIR(st.st_mode)) {
    errno = ENOTDIR;
    return NULL;
  }

  if ((d = pr_fsio_opendir(dirname)) == NULL)
    return NULL;

  /* It doesn't matter if the following guesses are wrong, but it slows
   * the system a bit and wastes some memory if they are wrong, so
   * don't guess *too* naively!
   *
   * 'dsize' must be greater than zero or we loop forever.
   * 'ssize' must be at least big enough to hold a maximum-length name.
   */
  dsize = (st.st_size / 4) + 10;	 /* Guess number of entries in dir */

  /*
  ** The directory has been opened already, but portably accessing the file
  ** descriptor inside the DIR struct isn't easy.  Some systems use "dd_fd" or
  ** "__dd_fd" rather than "d_fd".  Still others work really hard at opacity.
  */
#if defined(HAVE_STRUCT_DIR_D_FD)
  dirfd = d->d_fd;
#elif defined(HAVE_STRUCT_DIR_DD_FD)
  dirfd = d->dd_fd;
#elif defined(HAVE_STRUCT_DIR___DD_FD)
  dirfd = d->__dd_fd;
#else
  dirfd = 0;
#endif
  if ((ssize = get_name_max((char *) dirname, dirfd)) < 1 ) {
    log_debug(DEBUG1, "get_name_max(%s, %d) = %d, using %d",
              dirname, dirfd, ssize, NAME_MAX_GUESS);
    ssize = NAME_MAX_GUESS;
  }

  ssize *= ((dsize / 4) + 1);

  /* Allocate array for pointers to filenames */
  p = (char **) palloc(workp, dsize * sizeof(char *));

  /* Allocate first block for holding filenames themselves */
  s = (char *) palloc(workp, ssize * sizeof(char));
  s_end = s + (ssize * sizeof(char));

  i = 0;

  while ((de = pr_fsio_readdir(d)) != NULL) {
    if (i >= dsize - 1) {
      /* The test above goes off one item early in case this is the last item
       * in the directory and thus next time we will want to NULL-terminate
       * the array.
       */
      char **new_p;

      log_debug(DEBUG0,
                "Reallocating sreaddir buffer from %d entries to %d entries.",
                dsize, dsize * 2);

      /* Allocate bigger array for pointers to filenames */
      new_p = (char **) palloc(workp, 2 * dsize * sizeof(char *));

      /* Copy across */
      memcpy(new_p, p, dsize * sizeof(char *));
      dsize *= 2;

      /* We should do a pfree(workp, p), however there is no mechanism to free
       * a block...so we leak...bleed...just plain yucky.  Fortunately, this
       * only lasts a short time -- the memory pool used is freed when the
       * massive, recursive and ugly functions like listdir() and nlstdir()
       * finish calling this function.
       */
      p = new_p;
    }

    if (s + strlen(de->d_name) + 1 >= s_end) {
      log_debug(DEBUG0, "Allocating another sreaddir buffer of %d bytes.",
                ssize);

      /* Allocate another block for holding filenames themselves */
      /* (don't free the last one, elements of p[] still point at it! ) */
      s = (char *) palloc(workp, ssize * sizeof(char));
      s_end = s + (ssize * sizeof(char));
    }

    /* Append the filename to the block.
     */
    sstrncpy(s, de->d_name, strlen(de->d_name) + 1);
    p[i++] = s;
    s += strlen(de->d_name) + 1;
  }

  pr_fsio_closedir(d);

  /* This is correct, since the above is off by one element.
   */
  p[i] = NULL;

  if (sort)
    qsort(p, i, sizeof(char *), cmp);

  return p;
}

/* listdir required chdir first */
static int listdir(cmd_rec *cmd, pool *workp, const char *name) {
  char **dir;
  int dest_workp = 0;
  config_rec *c = NULL;
  unsigned char ignore_hidden = FALSE;

  if (XFER_ABORTED)
    return -1;

  if (!workp) {
    workp = make_sub_pool(cmd->tmp_pool);
    dest_workp++;

  } else {
    workp = make_sub_pool(workp);
    dest_workp++;
  }

  dir = sreaddir(workp, ".", TRUE);

  /* Search for relevant <Limit>'s to this LIST command.  If found,
   * check to see whether hidden files should be ignored.
   */
  if ((c = _find_ls_limit(cmd->argv[0])) != NULL) {
    unsigned char *ignore = get_param_ptr(c->subset, "IgnoreHidden", FALSE);

    if (ignore && *ignore == TRUE)
      ignore_hidden = TRUE;
  }

  if (dir) {
    char **s;
    char **r;

    int d = 0;

#if 0
    if (opt_l) {
      if (opt_STAT)
        add_response(R_211,"total 0");
      else if (sendline("total 0\n") < 0)
        return -1;
    }
#endif

    s = dir;
    while(*s) {
      if (**s == '.') {
        if (!opt_a && (!opt_A || is_dotdir(*s))) {
          d = 0;

        } else {

          /* Make sure IgnoreHidden is properly honored.  "." and
           * ".." are not to be treated as hidden files, though.
           */
          if (is_dotdir(*s) || !ignore_hidden)
            d = listfile(cmd,workp,*s);
        }

      } else {
        d = listfile(cmd,workp,*s);
      }

      if (!d)
        *s = NULL;

      s++;
    }

    if (outputfiles(cmd) < 0) {
      if (dest_workp)
        destroy_pool(workp);
      return -1;
    }

    r = dir;
    while (opt_R && r != s) {
      char cwd[MAXPATHLEN + 1] = {'\0'};
      unsigned char symhold;

      if (*r && (strcmp(*r, ".") == 0 || strcmp(*r, "..") == 0)) {
        r++;
        continue;
      }

      /* Add some signal processing to this while loop, as it can
       * potentially recurse deeply.
       */
      pr_handle_signals();

      push_cwd(cwd, &symhold);

      if (*r && ls_perms_full(workp,cmd,(char*)*r,NULL) &&
          !pr_fsio_chdir_canon(*r, !opt_L && list_show_symlinks)) {
        char *subdir;

        if (strcmp(name,".") == 0)
          subdir = *r;
        else
          subdir = pdircat(workp,name,*r,NULL);

        if (opt_STAT) {
          add_response(R_211, "%s", "");
          add_response(R_211, "%s:", subdir);

        } else if (sendline("\n%s:\n", subdir) < 0 ||
            sendline(NULL) < 0) {
          pop_cwd(cwd, &symhold);

          if (dest_workp)
            destroy_pool(workp);

          return -1;
        }

        if (listdir(cmd, workp, subdir) < 0) {
          pop_cwd(cwd, &symhold);

          if (dest_workp)
            destroy_pool(workp);

          return -1;
        }

        pop_cwd(cwd, &symhold);
      }
      r++;
    }
  }

  if (dest_workp)
    destroy_pool(workp);

  return 0;
}

static void ls_terminate(void) {
  if (!opt_STAT) {
    discard_output();
    if (!XFER_ABORTED) {  /* an error has occured, other than client ABOR */
      if (ls_errno)
        data_abort(ls_errno,FALSE);
      else
        data_abort((session.d && session.d->outstrm ?
                   PR_NETIO_ERRNO(session.d->outstrm) : errno),FALSE);
    }
    ls_errno = 0;

  } else if (ls_errno) {
    add_response(R_211, "ERROR: %s", strerror(ls_errno));
    ls_errno = 0;
  }
}

static void parse_list_opts(char **opt, int *glob_flags,
    unsigned char handle_plus_opts) {
  while (isspace((int) **opt))
    (*opt)++;

  /* Check for standard /bin/ls options */
  while (*opt && **opt == '-') {
    while ((*opt)++ && isalnum((int) **opt)) {
      switch (**opt) {
        case '1':
          opt_l = opt_C = 0;
          break;

        case 'A':
          opt_A = 1;
          break;

        case 'a':
          opt_a = 1;
          break;

        case 'C':
          opt_l = 0;
          opt_C = 1;
          break;

        case 'd':
          opt_d = 1;
          break;

        case 'F':
          opt_F = 1;
          break;

        case 'L':
          opt_L++;
          break;

        case 'l':
          opt_l = 1;
          opt_C = 0;
          break;

        case 'n':
          opt_n = 1;
          break;

        case 'R':
          opt_R = 1;
          break;

        case 'r':
          opt_r = 1;
          break;

        case 't':
          opt_t = 1;
          if (glob_flags)
            *glob_flags |= GLOB_NOSORT;
          break;
      }
    }

    while (isspace((int) **opt))
      (*opt)++;
  }

  if (!handle_plus_opts)
    return;

  /* Check for non-standard options */
  while (*opt && **opt == '+') {
    while ((*opt)++ && isalnum((int) **opt)) {
      switch (**opt) {
        case '1':
          opt_l = opt_C = 0;
          break;

        case 'A':
          opt_A = 0;
          break;

        case 'a':
          opt_a = 0;
          break;

        case 'C':
          opt_l = opt_C = 0;
          break;

        case 'd':
          opt_d = 0;
          break;

        case 'F':
          opt_F = 0;
          break;

        case 'L':
          opt_L = 0;
          break;

        case 'l':
          opt_l = opt_C = 0;
          break;

        case 'n':
          opt_n = 0;
          break;

        case 'R':
          opt_R = 0;
          break;

        case 'r':
          opt_r = 0;
          break;

        case 't':
          opt_t = 0;
          if (glob_flags)
            *glob_flags &= GLOB_NOSORT;
          break;
      }
    }

    while (isspace((int) **opt))
      (*opt)++;
  }
}

/* The main work for LIST and STAT (not NLST).  Returns -1 on error, 0 if
 * successful.
 */
static int dolist(cmd_rec *cmd, const char *opt, int clearflags) {
  int skiparg = 0;
  int glob_flags = GLOB_PERIOD;
  char *arg = (char*)opt;

  matches = 0;
  ls_curtime = time(NULL);

  if (clearflags) {
    opt_a = opt_C = opt_d = opt_F = opt_n = opt_r = opt_R = opt_t = opt_STAT = 0;
    opt_L = 0;
  }

  if (!strict_list_opts) {
    parse_list_opts(&arg, &glob_flags, FALSE);

  } else {

    /* Even if the user-given options are ignored, they still need to
     * "processed" (ie skip past options) in order to get to the paths.
     */
    while (*arg && isspace((int) *arg))
      arg++;

    while (arg && *arg == '-') {

      /* Advance to the next whitespace */
      while (*arg != '\0' && !isspace((int) *arg))
        arg++;

      while (isspace((int) *arg))
        arg++;
    }

    while (isspace((int) *arg))
      arg++;
  }

  if (list_options)
    parse_list_opts(&list_options, &glob_flags, TRUE);

  /* open data connection */
  if (!opt_STAT) {
    session.sf_flags |= SF_ASCII_OVERRIDE;
    if (data_open(NULL, "file list", PR_NETIO_IO_WR, 0) < 0)
      return -1;
  }

  if (arg && *arg) {
    int justone = 1;
    glob_t g;
    int    a;
    char   pbuffer[MAXPATHLEN + 1] = "";

    /* make sure the glob_t is initialized */
    memset(&g, '\0', sizeof(glob_t));

    if (*arg == '~') {
      struct passwd *pw;
      int i;
      const char *p;

      for(i = 0, p = arg + 1;
          (i < sizeof(pbuffer) - 1) && p && *p && *p != '/';
          pbuffer[i++] = *p++);
        
      pbuffer[i] = '\0';
        
      if ((pw = auth_getpwnam(cmd->tmp_pool,i ? pbuffer : session.user))) {
        snprintf(pbuffer, sizeof(pbuffer), "%s%s", pw->pw_dir, p);
      } else
        pbuffer[0] = '\0';
    }

    /* check perms on the directory/file we are about to scan */
    if (!ls_perms_full(cmd->tmp_pool, cmd,
                      (*pbuffer ? (char *) pbuffer : (char *) arg),NULL)) {
      a = -1;
      skiparg = TRUE;

    } else {

      skiparg = FALSE;

      if (use_globbing)
        a = pr_fs_glob(*pbuffer ? pbuffer : arg, glob_flags, NULL, &g);

      else {

        /* Trick the following code into using the non-glob() processed path */
        a = 0;
        g.gl_pathv = (char **) pcalloc(cmd->tmp_pool, 2 * sizeof(char *));
        g.gl_pathv[0] = (char *) pstrdup(cmd->tmp_pool,
          *pbuffer ? pbuffer : arg);
        g.gl_pathv[1] = NULL;
      }
    }

    if (!a) {
      char **path;
        
      path = g.gl_pathv;
      if (path && path[0] && path[1])
        justone = 0;
        
      while (path && *path) {
        struct stat st;

          /* I believe this code may be unnecessary here because it's only
           * used if args are passed to LIST/STAT, and then only to display
           * the initial directories/files from a glob.  listdir() will hide
           * .dotfiles correctly, so ...  jss - 2/20/01
           */

#if 0
          /* If we have a leading '.', two conditions must be true for us to
           * invalidate it:
           *
           * - opt_a is not set
           * - We don't have '.' or '..'.
           */
          if (**path == '.' && !opt_a && !is_dotdir(*path)) {
            **path = '\0';
            path++;
            continue;
          }
#endif

        if (pr_fsio_lstat(*path, &st) == 0) {
          mode_t target_mode, lmode;
          target_mode = st.st_mode;

          if (S_ISLNK(st.st_mode) && (lmode = file_mode((char*)*path)) != 0) {
            if (opt_L || !list_show_symlinks)
              st.st_mode = lmode;
            target_mode = lmode;
          }

          if (opt_d || !(S_ISDIR(target_mode))) {
            if (listfile(cmd,NULL,*path) < 0) {
              ls_terminate();
              if (use_globbing)
                pr_fs_globfree(&g);
              return -1;
            }
            **path = '\0';
          }
        } else {
          **path = '\0';
        }
        path++;
      }

      if (outputfiles(cmd) < 0) {
        ls_terminate();
        if (use_globbing)
          pr_fs_globfree(&g);
        return -1;
      }

      path = g.gl_pathv;
      while(path && *path) {
        if (**path && ls_perms_full(cmd->tmp_pool,cmd,*path,NULL)) {
          char cwd[MAXPATHLEN + 1] = {'\0'};
          unsigned char symhold;

          if (!justone) {
            if (opt_STAT) {
              add_response(R_211, "%s", "");
              add_response(R_211, "%s:", *path);

            } else {
              sendline("\n%s:\n", *path);
              sendline(NULL);
            }
          }

          push_cwd(cwd, &symhold);

          if (!pr_fsio_chdir_canon(*path, !opt_L && list_show_symlinks)) {
            int ret = listdir(cmd, NULL, *path);
            pop_cwd(cwd, &symhold);

            if (ret < 0) {
              ls_terminate();
              if (use_globbing)
                pr_fs_globfree(&g);
              return -1;
            }
          }
        }

        if (XFER_ABORTED) {
          discard_output();
          if (use_globbing)
            pr_fs_globfree(&g);
          return -1;
        }

        path++;
      }

    } else if (!skiparg) {
      if (a == GLOB_NOSPACE) {
        add_response(R_226,"Out of memory during globbing of %s", arg);
      } else if (a == GLOB_ABORTED) {
        add_response(R_226,"Read error during globbing of %s", arg);
      } else if (a != GLOB_NOMATCH) {
        add_response(R_226,"Unknown error during globbing of %s", arg);
      }
    }

    if (!skiparg && use_globbing)
      pr_fs_globfree(&g);

    if (XFER_ABORTED) {
      discard_output();
      return -1;
    }
  } else {

    if (ls_perms_full(cmd->tmp_pool, cmd, ".", NULL)) {

      if (opt_d) {
        if (listfile(cmd, NULL, ".") < 0) {
          ls_terminate();
          return -1;
        }

      } else {
        if (listdir(cmd, NULL, ".") < 0) {
          ls_terminate();
          return -1;
        }
      }
    }

    if (outputfiles(cmd) < 0) {
      ls_terminate();
      return -1;
    }
  }

  return 0;
}

/* display listing of a single file, no permission checking is done.
 * error is only returned if the data connection cannot be opened
 * or is aborted.
 */

static int nlstfile(cmd_rec *cmd, const char *file) {
  int res = 0;

  /* If the data connection isn't open, open it now. */
  if ((session.sf_flags & SF_XFER) == 0) {
    if (data_open(NULL, "file list", PR_NETIO_IO_WR, 0) < 0) {
      data_reset();
      return -1;
    }

    session.sf_flags |= SF_ASCII_OVERRIDE;
  }

  if (dir_hide_file(file))
    return 1;

  /* Be sure to flush the output */
  if ((res = sendline("%s\n", file)) < 0 ||
      (res = sendline(NULL)) < 0)
    return res;
        
  return 1;
}

/* Display listing of a directory, ACL checks performed on each entry,
 * sent in NLST fashion.  Files which are inaccessible via ACL are skipped,
 * error returned if data conn cannot be opened or is aborted.
 */
static int nlstdir(cmd_rec *cmd, const char *dir) {
  char **list, *p, *f,
       file[MAXPATHLEN + 1] = {'\0'};
  char cwd[MAXPATHLEN + 1]  = {'\0'};
  pool *workp;
  unsigned char symhold;
  int curdir = 0, i, count = 0, hidden = 0;
  mode_t mode;
  config_rec *c = NULL;
  unsigned char ignore_hidden = FALSE;

  workp = make_sub_pool(cmd->tmp_pool);

  if (!*dir || (*dir == '.' && !dir[1]) || strcmp(dir, "./") == 0) {
    curdir = 1;
    dir = "";

  } else
    push_cwd(cwd, &symhold);

  if (pr_fsio_chdir_canon(dir, !opt_L && list_show_symlinks)) {
    destroy_pool(workp);
    return 0;
  }

  if ((list = sreaddir(workp, ".", FALSE)) == NULL) {
    if (!curdir)
      pop_cwd(cwd, &symhold);
    destroy_pool(workp);
    return 0;
  }

  /* Search for relevant <Limit>'s to this NLST command.  If found,
   * check to see whether hidden files should be ignored.
   */
  if ((c = _find_ls_limit(cmd->argv[0])) != NULL) {
    unsigned char *ignore = get_param_ptr(c->subset, "IgnoreHidden", FALSE);

    if (ignore && *ignore == TRUE)
      ignore_hidden = TRUE;
  }

  while (*list && count >= 0) {
    p = *list; list++;

    if (*p == '.') {
      if (!opt_a && (!opt_A || is_dotdir(p)))
        continue;

      /* Make sure IgnoreHidden is properly honored. */
      else if (ignore_hidden)
        continue;
    }

    if ((i = pr_fsio_readlink(p, file, sizeof(file))) > 0) {
      file[i] = '\0';
      f = file;

    } else {
      f = p;
    }

    if (ls_perms(workp, cmd, f, &hidden)) {
      if (hidden)
        continue;

      /* If the data connection isn't open, open it now. */
      if ((session.sf_flags & SF_XFER) == 0) {
        if (data_open(NULL, "file list", PR_NETIO_IO_WR, 0) < 0) {
          data_reset();
          count = -1;
          continue;
        }

        session.sf_flags |= SF_ASCII_OVERRIDE;
      }

      if ((mode = file_mode(f)) == 0)
        continue;

      if (!curdir) {
        if (sendline("%s/%s\n", dir, p) < 0 || sendline(NULL) < 0)
          count = -1;
        else
          count++;

      } else {
        if (sendline("%s\n", p) < 0 || sendline(NULL) < 0)
          count = -1;
        else
          count++;
      }
    }
  }

  if (!curdir)
    pop_cwd(cwd, &symhold);

  destroy_pool(workp);

  return count;
}

/* The LIST command.  */
MODRET genericlist(cmd_rec *cmd) {
  int res = 0;
  unsigned char *tmp = NULL;
  mode_t *fake_mode = NULL;
  config_rec *c = NULL;

  if ((tmp = get_param_ptr(TOPLEVEL_CONF, "ShowSymlinks", FALSE)) != NULL)
    list_show_symlinks = *tmp;

  strict_list_opts = FALSE;

  if ((c = find_config(CURRENT_CONF, CONF_PARAM, "ListOptions",
      FALSE)) != NULL) {
    list_options = c->argv[0];
    strict_list_opts = *((unsigned char *) c->argv[1]);
  }

  fakeuser = get_param_ptr(CURRENT_CONF,"DirFakeUser",FALSE);

  /* check for a configured "logged in user" DirFakeUser
   */
  if (fakeuser && !strcmp(fakeuser, "~"))
    fakeuser = session.user;

  fakegroup = get_param_ptr(CURRENT_CONF,"DirFakeGroup",FALSE);

  /* check for a configured "logged in user" DirFakeGroup
   */
  if (fakegroup && !strcmp(fakegroup, "~"))
    fakegroup = session.group;

  if ((fake_mode = get_param_ptr(CURRENT_CONF, "DirFakeMode", FALSE))) {
    fakemode = *fake_mode;
    have_fake_mode = TRUE;

  } else
    have_fake_mode = FALSE;

  if ((tmp = get_param_ptr(TOPLEVEL_CONF, "TimesGMT", FALSE)) != NULL)
    list_times_gmt = *tmp;

  res = dolist(cmd, cmd->arg, TRUE);

  if (XFER_ABORTED) {
    data_abort(0, 0);
    res = -1;

  } else if (session.sf_flags & SF_XFER)
    ls_done(cmd);

  opt_l = 0;

  return (res == -1 ? ERROR(cmd) : HANDLED(cmd));
}

MODRET ls_log_nlst(cmd_rec *cmd) {
  data_cleanup();
  return DECLINED(cmd);
}

MODRET ls_err_nlst(cmd_rec *cmd) {
  data_cleanup();
  return DECLINED(cmd);
}

MODRET ls_stat(cmd_rec *cmd) {
  char *arg = cmd->arg;
  unsigned char *tmp = NULL;
  mode_t *fake_mode = NULL;
  config_rec *c = NULL;

  if (cmd->argc < 2) {
    add_response_err(R_500, "'%s' not understood.", get_full_cmd(cmd));
    return ERROR(cmd);
  }

  /* Get to the actual argument. */
  if (*arg == '-')
    while (arg && *arg && !isspace((int) *arg)) arg++;

  while (arg && *arg && isspace((int) *arg)) arg++;

  if ((tmp = get_param_ptr(TOPLEVEL_CONF, "ShowSymlinks", FALSE)) != NULL)
    list_show_symlinks = *tmp;

  strict_list_opts = FALSE;

  if ((c = find_config(CURRENT_CONF, CONF_PARAM, "ListOptions",
      FALSE)) != NULL) {
    list_options = c->argv[0];
    strict_list_opts = *((unsigned char *) c->argv[1]);
  }

  fakeuser = get_param_ptr(CURRENT_CONF,"DirFakeUser",FALSE);

  /* check for a configured "logged in user" DirFakeUser
   */
  if (fakeuser && !strcmp(fakeuser, "~"))
    fakeuser = session.user;

  fakegroup = get_param_ptr(CURRENT_CONF,"DirFakeGroup",FALSE);

  /* check for a configured "logged in user" DirFakeGroup
   */
  if (fakegroup && !strcmp(fakegroup, "~"))
    fakegroup = session.group;

  if ((fake_mode = get_param_ptr(CURRENT_CONF, "DirFakeMode", FALSE))) {
    fakemode = *fake_mode;
    have_fake_mode = TRUE;

  } else
    have_fake_mode = FALSE;

  if ((tmp = get_param_ptr(TOPLEVEL_CONF, "TimesGMT", FALSE)) != NULL)
    list_times_gmt = *tmp;

  opt_C = opt_d = opt_F = opt_R;
  opt_a = opt_l = opt_STAT = 1;

  add_response(R_211,"status of %s:", arg && *arg ? arg : ".");
  dolist(cmd,cmd->arg,FALSE);
  add_response(R_211,"End of Status");
  return HANDLED(cmd);
}

MODRET ls_list(cmd_rec *cmd) {
  MODRET ret;

  opt_l = 1;
  ret = genericlist(cmd);
  return ret;
}

/* NLST is a very simplistic directory listing, unlike LIST (which
 * emulates ls), it only sends a list of all files/directories
 * matching the glob(s).
 */

MODRET ls_nlst(cmd_rec *cmd) {
  char *target,line[MAXPATHLEN + 1] = {'\0'};
  int count = 0,ret = 0, hidden = 0;
  unsigned char *tmp = NULL;

  /* In case the client used NLST instead of LIST
   */
  if (cmd->argc > 1 && cmd->argv[1][0] == '-')
    return genericlist(cmd);

  if ((tmp = get_param_ptr(TOPLEVEL_CONF, "ShowSymlinks", FALSE)) != NULL)
    list_show_symlinks = *tmp;
        
  if (cmd->argc == 1)
    target = ".";
  else
    target = cmd->arg;
        
  /* If the target starts with '~' ... */
  if (*target == '~') {
    char pb[MAXPATHLEN + 1] = {'\0'};
    struct passwd *pw = NULL;
    int i = 0;
    const char *p = target;

    p++;

    while (*p && *p !='/' && i < MAXPATHLEN)
      pb[i++] = *p++;
    pb[i] = '\0';

    if ((pw = auth_getpwnam(cmd->tmp_pool,i ? pb : session.user))) {
      snprintf(pb, sizeof(pb), "%s%s", pw->pw_dir, p);
      sstrncpy(line, pb, sizeof(line));
      target = line;
    }
  }
        
  /* If the target is a glob, get the listing of files/dirs to send
   */
  if (use_globbing && strpbrk(target, "{[*?") != NULL) {
    glob_t g;
    char **path,*p;

    /* Make sure the glob_t is initialized */
    memset(&g, '\0', sizeof(glob_t));

    if (pr_fs_glob(target, GLOB_PERIOD,NULL, &g) != 0) {
      add_response_err(R_550, "No files found");
      return ERROR(cmd);
    }

    /* Iterate through each matching entry */
    path = g.gl_pathv;
    while (path && *path && ret >= 0) {
      struct stat st;
      int hidden = 0;

      p = *path;
      path++;

      if (*p == '.' && (!opt_A || is_dotdir(p)))
        continue;

      if (pr_fsio_stat(p, &st) == 0) {
        /* If it's a directory, hand off to nlstdir */
        if (S_ISDIR(st.st_mode))
          ret = nlstdir(cmd, p);

        else if (S_ISREG(st.st_mode) &&
            ls_perms(cmd->tmp_pool, cmd, p, &hidden)) {
          /* Don't display hidden files */
          if (hidden)
            continue;

          ret = nlstfile(cmd,p);
        }

        if (ret > 0)
          count += ret;
      }
    }

    pr_fs_globfree(&g);

  } else {

    /* A single target. If it's a directory, list the contents; if it's a
     * file, just list the file.
     */
    struct stat st;

    if (!ls_perms(cmd->tmp_pool, cmd, target, &hidden)) {
      add_response_err(R_550, "%s: %s", cmd->arg, strerror(errno));
      return ERROR(cmd);
    }

    /* Don't display hidden files */
    if (hidden) {
      config_rec *c = NULL;
      unsigned char *ignore_hidden = get_param_ptr(c->subset,
        "IgnoreHidden", FALSE);

      if ((c = _find_ls_limit(target)) != NULL &&
          (ignore_hidden && *ignore_hidden == TRUE))
        add_response_err(R_550, "%s: %s", cmd->arg, strerror(ENOENT));
      else
        add_response_err(R_550, "%s: %s", cmd->arg, strerror(EACCES));

      return ERROR(cmd);
    }

    /* Make sure the target is a file or directory,
     * and that we have access to it.
     */
    if (pr_fsio_stat(target, &st) < 0) {
      add_response_err(R_550, "%s: %s", cmd->arg, strerror(errno));
      return ERROR(cmd);
    }

    if (S_ISREG(st.st_mode))
      ret = nlstfile(cmd, target);

    else if (S_ISDIR(st.st_mode)) {
      if (access_check(target, R_OK) != 0) {
        add_response_err(R_550, "%s: %s", cmd->arg, strerror(errno));
        return ERROR(cmd);
      }

      ret = nlstdir(cmd,target);

    } else {
      add_response_err(R_550, "%s: Not a regular file", cmd->arg);
      return ERROR(cmd);
    }

    if (ret > 0)
      count += ret;
  }

  if (XFER_ABORTED) {
    data_abort(0, 0);
    ret = -1;

  } else {
    if (ret == 0 && !count && (session.sf_flags & SF_XFER) == 0) {
      add_response_err(R_550, "No files found");
      ret = -1;

    } else if (session.sf_flags & SF_XFER)

      /* Note that the data connection is NOT cleared here,
       * as an error in NLST still leaves data ready for
       * another command
       */
      ls_done(cmd);
  }

  return (ret < 0 ? ERROR(cmd) : HANDLED(cmd));
}

/* Check for the UseGlobbing setting, if any, after the PASS command has
 * been successfully handled.
 */
MODRET ls_post_pass(cmd_rec *cmd) {
  unsigned char *globbing = NULL;

  if ((globbing = get_param_ptr(TOPLEVEL_CONF, "UseGlobbing",
      FALSE)) != NULL && *globbing == FALSE) {
    log_debug(DEBUG3, "UseGlobbing: disabling globbing functionality");
    use_globbing = FALSE;
  }

  return DECLINED(cmd);
}

/* Configuration handlers
 */

MODRET _sethide(cmd_rec *cmd, const char *param) {
  int bool = -1;
  char *as = "ftp";
  config_rec *c = NULL;

  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL|
    CONF_DIR|CONF_DYNDIR);

  if (cmd->argc < 2 || cmd->argc > 3)
    CONF_ERROR(cmd,pstrcat(cmd->tmp_pool,"syntax: ",
               param," on|off [<id to display>]",NULL));

  if ((bool = get_boolean(cmd,1)) == -1)
     CONF_ERROR(cmd, "expected boolean argument");

  if (bool == TRUE) {
    /* use the configured id to display rather than the default "ftp" */
    if (cmd->argc > 2)
      as = cmd->argv[2];

    c = add_config_param_str(param, 1, as);

  } else {
    /* still need to add a config_rec to turn off the display of fake ids */
    c = add_config_param_str(param, 0);
  }

  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_dirfakeuser(cmd_rec *cmd) {
  return _sethide(cmd, cmd->argv[0]);
}

MODRET set_dirfakegroup(cmd_rec *cmd) {
  return _sethide(cmd, cmd->argv[0]);
}

MODRET set_dirfakemode(cmd_rec *cmd) {
  config_rec *c = NULL;
  char *endp = NULL;
  mode_t fake_mode;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|CONF_DIR|
    CONF_DYNDIR);

  fake_mode = (mode_t) strtol(cmd->argv[1], &endp, 8);

  if (endp && *endp)
    CONF_ERROR(cmd, "parameter must be an octal number");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(mode_t));
  *((mode_t *) c->argv[0]) = fake_mode;
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_listoptions(cmd_rec *cmd) {
  config_rec *c = NULL;

  if (cmd->argc-1 < 1 || cmd->argc-1 > 2)
    CONF_ERROR(cmd, "wrong number of parameters");

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|
    CONF_DIR|CONF_DYNDIR);

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  c->argv[0] = pstrdup(c->pool, cmd->argv[1]);
  c->argv[1] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[1]) = FALSE;
  c->flags |= CF_MERGEDOWN;

  /* Check for the optional "strict" argument. */
  if (cmd->argc-1 == 2 &&
      !strcasecmp(cmd->argv[2], "strict"))
    *((unsigned char *) c->argv[1]) = TRUE;

  return HANDLED(cmd);
}

MODRET set_showsymlinks(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  if ((bool = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_useglobbing(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  if ((bool = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_lsdefaultoptions(cmd_rec *cmd) {
  CONF_ERROR(cmd, "deprecated. Use ListOptions instead");
}

/* Module API tables
 */

static conftable ls_conftab[] = {
  { "DirFakeUser",	set_dirfakeuser,			NULL },
  { "DirFakeGroup",	set_dirfakegroup,			NULL },
  { "DirFakeMode",	set_dirfakemode,			NULL },
  { "ListOptions",	set_listoptions,			NULL },
  { "ShowSymlinks",	set_showsymlinks,			NULL },
  { "UseGlobbing",	set_useglobbing,			NULL },

  /* Deprecated */
  { "LsDefaultOptions",	set_lsdefaultoptions,			NULL },

  { NULL,		NULL,					NULL }
};

static cmdtable ls_cmdtab[] = {
  { CMD,  	C_NLST,	G_DIRS,	ls_nlst,	TRUE, FALSE, CL_DIRS },
  { CMD,	C_LIST,	G_DIRS,	ls_list,	TRUE, FALSE, CL_DIRS },
  { CMD, 	C_STAT,	G_DIRS,	ls_stat,	TRUE, FALSE, CL_DIRS },
  { POST_CMD,	C_PASS,	G_NONE,	ls_post_pass,	FALSE, FALSE },
  { LOG_CMD,	C_LIST,	G_NONE,	ls_log_nlst,	FALSE, FALSE },
  { LOG_CMD,	C_NLST, G_NONE,	ls_log_nlst,	FALSE, FALSE },
  { LOG_CMD_ERR,C_LIST, G_NONE, ls_err_nlst,   FALSE, FALSE },
  { LOG_CMD_ERR,C_NLST, G_NONE, ls_err_nlst,   FALSE, FALSE },
  { 0, NULL }
};

module ls_module = {
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "ls",

  /* Module configuration handler table */
  ls_conftab,

  /* Module command handler table */
  ls_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization */
  NULL,

  /* Session initialization */
  NULL
};
