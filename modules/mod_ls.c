/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (C) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
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

/* Directory listing module for ProFTPD.
 * $Id: mod_ls.c,v 1.31 2000-07-26 11:03:17 macgyver Exp $
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
static char *default_options;
static int showsymlinks, showsymlinks_hold, timesgmt = 0;
static int cmp(const void *a, const void *b);
static char *fakeuser, *fakegroup;
static umode_t fakemode;
static int fakemodep;
static int ls_errno = 0;
static time_t ls_curtime = 0;

/* ls options */
static int
    opt_a = 0,
    opt_A = 0,
    opt_C = 0,
    opt_d = 0,
    opt_F = 0,
    opt_l = 0,
    opt_L = 0,
    opt_R = 0,
    opt_r = 0,
    opt_t = 0,
    opt_STAT = 0;

static char cwd[MAXPATHLEN + 1] = "";

static void push_cwd(char *_cwd, int *symhold) {
  if(!_cwd)
    _cwd = cwd;

  if(!symhold)
    symhold = &showsymlinks_hold;

  sstrncpy(_cwd, fs_getcwd(), MAXPATHLEN + 1);
  *symhold = showsymlinks;
}

static void pop_cwd(char *_cwd, int *symhold)
{
  if(!_cwd)
    _cwd = cwd;

  if(!symhold)
    symhold = &showsymlinks_hold;

  fs_chdir(_cwd,*symhold);
  showsymlinks = *symhold;
}

static int ls_perms_full(pool *p, cmd_rec *cmd, const char *path, int *hidden)
{
  int ret,ishidden,canon = 0;
  char *fullpath;
  long _fakemode;

  fullpath = dir_realpath(p,path);

  if(!fullpath) {
    fullpath = dir_canonical_path(p,path);
    canon = 1;
  } if(!fullpath)
    fullpath = pstrdup(p,path);
  
  if(canon)
    ret = dir_check_canon(p,cmd->argv[0],cmd->group,fullpath,&ishidden);
  else
    ret = dir_check(p,cmd->argv[0],cmd->group,fullpath,&ishidden);

  if(hidden)
	*hidden = ishidden;
  
  if(ishidden)
  	return 0;

  if(session.dir_config) {
    showsymlinks = get_param_int(session.dir_config->subset,
                                 "ShowSymlinks",FALSE);

    if(showsymlinks == -1)
      showsymlinks = 1;
  }

  _fakemode = get_param_int(CURRENT_CONF,"DirFakeMode",FALSE);
  if(_fakemode != -1) {
    fakemode = (umode_t)_fakemode;
    fakemodep = 1;
  } else
    fakemodep = 0;

  return ret;
}

static int ls_perms(pool *p, cmd_rec *cmd, const char *path, int *hidden)
{
  int ret,ishidden;
  char fullpath[MAXPATHLEN + 1] = {'\0'};
  long _fakemode;

  if(*path == '~')
	return ls_perms_full(p,cmd,path,hidden);

  if(*path != '/')
  	fs_clean_path(pdircat(p,fs_getcwd(),path,NULL),fullpath,MAXPATHLEN);
  else
	fs_clean_path(path,fullpath,MAXPATHLEN);
  
  ret = dir_check(p,cmd->argv[0],cmd->group,fullpath,&ishidden);

  if(hidden)
	  *hidden = ishidden;
  
  if(ishidden)
    return 0;

  if(session.dir_config) {
    showsymlinks = get_param_int(session.dir_config->subset,
                                 "ShowSymlinks",FALSE);

    if(showsymlinks == -1)
      showsymlinks = 1;
  }

  _fakemode = get_param_int(CURRENT_CONF,"DirFakeMode",FALSE);
  if(_fakemode != -1) {
    fakemode = (umode_t)_fakemode;
    fakemodep = 1;
  } else
    fakemodep = 0;

  return ret;
}

static
int sendline(char *fmt, ...)
{
  va_list msg;
  char buf[1025] = {'\0'};
  int ret;

  va_start(msg,fmt);
  vsnprintf(buf,sizeof(buf),fmt,msg);
  va_end(msg);

  buf[1024] = '\0';

  ret = data_xfer(buf,strlen(buf));
  if(ret < 0) {
    log_debug(DEBUG3, "data_xfer returned %d, error = %s.",
              ret, strerror(session.d->outf->xerrno));
  }
  return ret;
}

static
void ls_done(cmd_rec *cmd)
{
  data_close(FALSE);
}

static
int listfile(cmd_rec *cmd, pool *p, const char *name)
{
  int		rval = 0, len;
  time_t	mtime;
  char		m[1024] = {'\0'},l[1024] = {'\0'};
  struct	stat st;
  char		months[12][4] =
  { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
  
  struct	tm *t;
  char		suffix[2];
  
  if(!p) p = cmd->tmp_pool;
  
  if(fs_lstat(name,&st) == 0) {
    suffix[0] = suffix[1] = '\0';

    if(S_ISLNK(st.st_mode) && (opt_L || !showsymlinks)) {
      /* attempt to fully dereference symlink */
      struct stat l_st;

      if(fs_stat(name,&l_st) != -1) {
        memcpy(&st,&l_st,sizeof(st));
	if((len = fs_readlink(name, m, sizeof(m))) < 0)
	  return 0;
	
	m[len] = '\0';
	
        if(!ls_perms_full(p,cmd,m,NULL))
          return 0;
      } else {
        return 0;
      }
    } else if(S_ISLNK(st.st_mode)) {
      if((len = fs_readlink(name, l, sizeof(l))) < 0)
	return 0;
      
      l[len] = '\0';
      
      if(!ls_perms_full(p,cmd,l,NULL))
        return 0;
    } else if(!ls_perms(p,cmd,name,NULL)) {
      return 0;
    }

    mtime = st.st_mtime;
    if(timesgmt)
      t = gmtime((time_t*) &mtime);
    else 
      t = localtime((time_t*) &mtime);
    
    if(!t) {
      add_response_err(R_421,"Fatal error (localtime() returned NULL?!?)");
      return -1;
    }
    
    if(opt_F) {
      if(S_ISLNK(st.st_mode))
        suffix[0] = '@';
      else if(S_ISDIR(st.st_mode)) {
        suffix[0] = '/';
        rval = 1;
      } else if(st.st_mode & 0111)
        suffix[0] = '*';
    }
    
    if(opt_l) {
      sstrncpy(m, " ---------", sizeof(m));
      switch(st.st_mode & S_IFMT) {
      case S_IFREG:
        m[0] = '-';
        break;
      case S_IFLNK:
        m[0] = 'l';
        break;
      case S_IFDIR:
        m[0] = 'd';
        rval = 1;
        break;
      }

      if(m[0] != ' ') {
        char nameline[MAXPATHLEN + MAXPATHLEN + 128] = {'\0'};
        char timeline[6] = {'\0'};
        umode_t mode = st.st_mode;

        if(fakemodep)
          mode = fakemode;

        if(mode & 256)
          m[1] = 'r';
        if(mode & 128)
          m[2] = 'w';
        if(mode & 64 || (fakemodep && (mode & 256) && S_ISDIR(st.st_mode)))
          m[3] = 'x';
        if(mode & 32)
          m[4] = 'r';
        if(mode & 16)
          m[5] = 'w';
        if(mode & 8 || (fakemodep && (mode & 32) && S_ISDIR(st.st_mode)))
          m[6] = 'x';
        if(mode & 4)
          m[7] = 'r';
        if(mode & 2)
          m[8] = 'w';
        if(mode & 1 || (fakemodep && (mode & 4) && S_ISDIR(st.st_mode)))
          m[9] = 'x';

        if(ls_curtime - mtime > 180 * 24 * 60 * 60)
          snprintf(timeline, sizeof(timeline), "%5d",t->tm_year+1900);
        else
          snprintf(timeline, sizeof(timeline), "%02d:%02d",t->tm_hour,t->tm_min);

        snprintf(nameline, sizeof(nameline), "%s %3d %-8s %-8s %8d %s %2d %s %s", m,
                (int)st.st_nlink, MAP_UID(st.st_uid), 
                MAP_GID(st.st_gid),
                (unsigned int)st.st_size, months[t->tm_mon],
                t->tm_mday, timeline, name);

        if(S_ISLNK(st.st_mode)) {
          char *p = nameline + strlen(nameline);

          suffix[0] = '\0';
          if(opt_F && fs_stat(name, &st) == 0) {
            if(S_ISLNK(st.st_mode))
              suffix[0] = '@';
            else if(S_ISDIR(st.st_mode))
              suffix[0] = '/';
            else if(st.st_mode & 0111)
              suffix[0] = '*';
          }

          snprintf(p, sizeof(nameline) - strlen(nameline) - 4, " -> %s", l);
          nameline[sizeof(nameline)-1] = '\0';
        }

	if(opt_STAT)
	  add_response(R_211,"%s%s",nameline,suffix);
	else
          addfile(cmd,nameline,suffix,mtime);
      }
    } else {
      if(S_ISREG(st.st_mode) ||
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

  if(!name || !suffix)
    return;

  if(opt_t) {
    struct sort_filename *s;

    if(!fpool)
      fpool = make_sub_pool(cmd->tmp_pool);

    if(!sort_arr)
      sort_arr = make_array(fpool,50,sizeof(struct sort_filename));

    s = (struct sort_filename*)push_array(sort_arr);
    s->mtime = mtime;
    s->name = pstrdup(fpool,name);
    s->suffix = pstrdup(fpool,suffix);

    return;
  }

  matches++;

  l = strlen(name) + strlen(suffix);
  if(l > colwidth)
    colwidth = l;

  if(!fpool)
    fpool = make_sub_pool(cmd->tmp_pool);

  p = (struct filename*) pcalloc(fpool, sizeof(struct filename) + l + 1);
#if 0
  log_debug(DEBUG4, "alloc: %d.\n", sizeof(struct filename) + l + 1);
#endif

  snprintf(p->line, l + 1, "%s%s", name, suffix);

  if(tail)
    tail->down = p;
  else
    head = p;

  tail = p;
  filenames++;
}

#if 0
static
void RANGE(void *ptr)
{
  char *cp = (char*)ptr;
  if(cp) {
   *cp;
  }
}
#endif

static
int _compare_file_mtime(const struct sort_filename *f1,
                        const struct sort_filename *f2)
{
  if(f1->mtime > f2->mtime)
    return -1;
  else if(f1->mtime < f2->mtime)
    return 1;

  return 0;
}

static
int _compare_file_mtime_reversed(const struct sort_filename *f1,
                        const struct sort_filename *f2)
{
  return -_compare_file_mtime(f1, f2);
}

static
void sortfiles(cmd_rec *cmd)
{
  struct sort_filename *s;
  int i;

  if(opt_t && sort_arr) {
    qsort(sort_arr->elts, sort_arr->nelts, sizeof(struct sort_filename),
          (int (*)(const void*,const void*))
	  (opt_r ? _compare_file_mtime_reversed : _compare_file_mtime));

    opt_t = 0;
    for(i = 0, s = (struct sort_filename*)sort_arr->elts; i < sort_arr->nelts; i++, s++)
      addfile(cmd,s->name,s->suffix,s->mtime);
    opt_t = 1;
  }
    
  sort_arr = NULL;
}

static
int outputfiles(cmd_rec *cmd)
{
  int		n;
  struct 	filename *p;
  struct	filename *q;

  if(opt_t)
    sortfiles(cmd);

  if(!head)		/* nothing to display */
    return 0;

  tail->down = NULL;
  tail = NULL;
  colwidth = ( colwidth | 7 ) + 1;
  if(opt_l || !opt_C)
    colwidth = 75;

  /* avoid division by 0 if colwidth > 75 */
  if(colwidth > 75)
    colwidth = 75;

  p = head;
  p->top = 1;
  n = (filenames + (75 / colwidth)-1) / (75 / colwidth);
  while(n && p) {
    p = p->down;
    if(p)
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
  if(p && p->down)
    p->down = NULL;

#if 0
  if(opt_l)
    if(sendline("total 0\n") < 0)
      return -1;
#endif
  
  p = head;
  while(p) {
    q = p;
    p = p->down;
    while(q) {
      char pad[6] = {'\0'};

      if(q->right) {
        sstrncpy(pad, "\t\t\t\t\t", sizeof(pad));
        pad[(colwidth + 7 - strlen(q->line)) / 8] = '\0';
      } else {
        sstrncpy(pad, "\n", sizeof(pad));
      }

      if(sendline("%s%s", q->line, pad) < 0)
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
  return 0;
}


static
void discard_output()
{
  if(fpool)
    destroy_pool(fpool);
  fpool = NULL;

  head = tail = NULL;
  colwidth = 0;
  filenames = 0;
}


static int cmp(const void *a, const void *b)
{
  return strcmp(*(const char **)a, *(const char **)b);
}

static
char **sreaddir(pool *workp, const char *dirname, const int sort)
{
  DIR 		*d;
  struct	dirent *de;
  struct	stat st;
  int		i;
  char		**p;
  char		*s, *s_end;
  int		dsize, ssize;

  if(fs_stat(dirname, &st) < 0) 
    return NULL;

  if(!S_ISDIR(st.st_mode)) {
    errno = ENOTDIR;
    return NULL;
  }

  if((d = opendir(dirname)) == NULL)
    return NULL;

  /* It doesn't matter if the following guesses are wrong, but it slows
   * the system a bit and wastes some memory if they are wrong, so
   * don't guess *too* naiively!
   *
   * 'dsize' must be greater than zero or we loop forever.
   * 'ssize' must be at least big enough to hold a maximum-length name.
   */
  dsize = (st.st_size / 4) + 10;	 /* Guess number of entries in dir */

  /*
  ** Guess number of bytes total needed to store all filenames in dir.
  ** Any OS supporting multple file system types cannot define NAME_MAX
  ** (POSIX 1003.1a, section 2.9.5) since this value will not be constant.
  ** The directory has been opened already, but portably accessing the file
  ** descriptor inside the DIR struct is difficult.  Some systems use "dd_fd"
  ** or "__dd_fd" rather than "d_fd", and others work really hard at opacity.
  ** So, with a loss of efficiency, use pathconf() rather than fpathconf(),
  ** unless "d->d_fd" happens to work.
  */
#ifdef NAME_MAX
# define MOD_LS_NAME_MAX_GUESS NAME_MAX
#else
# define MOD_LS_NAME_MAX_GUESS 255
#endif
#define MOD_LS_DQSTR(x)	(#x)
#if defined(HAVE_FPATHCONF) && defined(HAVE_STRUCT_DIR_D_FD)
  if ( (ssize = fpathconf(d->d_fd, _PC_NAME_MAX)) < 1 ) {
    log_debug(DEBUG1, "fpathconf(%s, _PC_NAME_MAX) = %d, using %s",
    		dirname, ssize, MOD_LS_DQSTR(MOD_LS_NAME_MAX_GUESS));
    ssize = MOD_LS_NAME_MAX_GUESS;
  }
#elif defined(HAVE_PATHCONF)
  if ( (ssize = pathconf(dirname, _PC_NAME_MAX)) < 1 ) {
    log_debug(DEBUG1, "pathconf(%s, _PC_NAME_MAX) = %d, using %s",
    		dirname, ssize, MOD_LS_DQSTR(MOD_LS_NAME_MAX_GUESS));
    ssize = MOD_LS_NAME_MAX_GUESS;
  }
#elif defined(NAME_MAX)
  ssize = NAME_MAX;
#elif defined(MAXNAMELEN)
  ssize = MAXNAMELEN - 1;
#else
  ssize = MOD_LS_NAME_MAX_GUESS;
#endif
  ssize *= ((dsize / 4) + 1);

  /* Allocate array for pointers to filenames */
  p = (char **) palloc(workp, dsize * sizeof(char *));
  
  /* Allocate first block for holding filenames themselves */
  s = (char *) palloc(workp, ssize * sizeof(char));
  s_end = s + (ssize * sizeof(char));

  i = 0;
  
  while((de = readdir(d)) != NULL) {
    if(i >= dsize - 1) {
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
    
    if(s + strlen(de->d_name) + 1 >= s_end) {
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
  
  closedir(d);

  /* This is correct, since the above is off by one element.
   */
  p[i] = NULL;

  if(sort)
    qsort(p, i, sizeof(char *), cmp);
  
  return p;
}

/* Return true iff S is ".", "./", "../", or "..". */
static int is_dotdir(char *s)
{
  if(!strcmp(s, ".")  ||
     !strcmp(s, "./") ||
     !strcmp(s, "..") ||
     !strcmp(s, "../"))
    return 1;
  
  return 0;
}

/* listdir required chdir first */
static int listdir(cmd_rec *cmd, pool *workp, const char *name)
{
  char **dir;
  int dest_workp = 0;

  if(XFER_ABORTED)
	return -1;

  if(!workp) {
    workp = make_sub_pool(cmd->tmp_pool);
    dest_workp++;
  } else {
    workp = make_sub_pool(workp);
    dest_workp++;
  }

  dir = sreaddir(workp,".",TRUE);

  if(dir) {
    char **s;
    char **r;

    int d = 0;

#if 0
    if(opt_l) {
      if(opt_STAT)
        add_response(R_211,"total 0");
      else if(sendline("total 0\n") < 0)
        return -1;
    }
#endif
    
    s = dir;
    while(*s) {
      if (**s == '.'
	  && !opt_a
	  && (!opt_A || is_dotdir(*s))) {
	d = 0;
      } else {
        d = listfile(cmd,workp,*s);
      }

      if(!d)
	*s = NULL;
      s++;
    }

    if(outputfiles(cmd) < 0) {
      if(dest_workp)
        destroy_pool(workp);
      return -1;
    }

    r = dir;
    while(opt_R && r != s) {
      char cwd[MAXPATHLEN + 1] = {'\0'};
      int symhold;

      if(*r && (strcmp(*r,".") == 0 || strcmp(*r,"..") == 0)) {
        r++;
        continue;
      }
      
      push_cwd(cwd,&symhold);
     
      if(*r && ls_perms_full(workp,cmd,(char*)*r,NULL) 
	    && !fs_chdir_canon(*r, !opt_L && showsymlinks)) {
        char *subdir;

	if(strcmp(name,".") == 0)
          subdir = *r;
        else
          subdir = pdircat(workp,name,*r,NULL);

	if(opt_STAT) {
	  add_response(R_211,"");
          add_response(R_211,"%s:",subdir);
	} else if(sendline("\n%s:\n",subdir) < 0) {
          pop_cwd(cwd,&symhold);
          if(dest_workp)
            destroy_pool(workp);
          return -1;
        }

        if(listdir(cmd,workp,subdir) < 0) {
          pop_cwd(cwd,&symhold);
          if(dest_workp)
            destroy_pool(workp);
          return -1;
        }

        pop_cwd(cwd,&symhold);
      }
      r++;
    }
  }

  if(dest_workp)
    destroy_pool(workp);

  return 0;
}

static
void ls_terminate()
{
  if(!opt_STAT) {
    discard_output();
    if(!XFER_ABORTED) {  /* an error has occured, other than client ABOR */
      if(ls_errno)
        data_abort(ls_errno,FALSE);
      else
        data_abort((session.d && session.d->outf ? 
                   session.d->outf->xerrno : errno),FALSE);
    }
    ls_errno = 0;
  } else if(ls_errno) {
    add_response(R_211,"ERROR: %s",strerror(ls_errno));
    ls_errno = 0;
  }
}

static
void _parse_options(char **opt, int *glob_flags)
{
  while(isspace((UCHAR)**opt))
    (*opt)++;

  while(*opt && **opt == '-') {
    while((*opt)++ && isalnum((UCHAR)**opt)) {
      switch(**opt) {
      case 'a':
        opt_a = 1;
        break;
      case 'A':
        opt_A = 1;
        break;
      case 'l':
        opt_l = 1;
        opt_C = 0;
        break;
      case 'L':
        opt_L++;
        break;
      case '1':
        opt_l = opt_C = 0;
        break;
      case 'C':
        opt_l = 0;
        opt_C = 1;
        break;
      case 'F':
        opt_F = 1;
        break;
      case 'r':
        opt_r = 1;
        break;
      case 'R':
        opt_R = 1;
        break;
      case 'd':
        opt_d = 1;
        break;
      case 't':
        opt_t = 1;
        if(glob_flags)
          *glob_flags |= GLOB_NOSORT;;
        break;
      }
    }
    while(isspace((UCHAR)**opt)) 
      (*opt)++;

  }
}

/* The main work for LIST and STAT (not NLST).
   Return -1 on error, 0 if successful.  */
static
int dolist(cmd_rec *cmd, const char *opt, int clearflags)
{
  int skiparg = 0;
  int glob_flags = GLOB_PERIOD;
  char *arg = (char*)opt;

  matches = 0;
  ls_curtime = time(NULL);

  if(clearflags)
    opt_a = opt_C = opt_d = opt_F = opt_r = opt_R = opt_t = opt_STAT = 0;
    opt_L = 0;

  if(default_options)
    _parse_options(&default_options,&glob_flags);
  _parse_options(&arg,&glob_flags);

  /* open data connection */
  if(!opt_STAT) {
    session.flags |= SF_ASCII_OVERRIDE;
    if(data_open(NULL,"file list",IO_WRITE,0) < 0)
      return -1;
  }
  
  if(arg && *arg) {
    int justone;
    
    justone = 1;
    while(arg) {
      glob_t g;
      int    a;
      char   pbuffer[MAXPATHLEN + 1];
      
      char   *endarg = strchr(arg,' ');
      
      if(endarg) {
        *endarg++ = '\0';
        justone = 0;
      }
      
      if(*arg == '~') {
        struct passwd *pw;
	int i;
        const char *p;

	for(i = 0, p = arg + 1;
	    (i < sizeof(pbuffer) - 1) && p && *p && *p != '/';
	    pbuffer[i++] = *p++);
	
        pbuffer[i] = '\0';
	
        if((pw = auth_getpwnam(cmd->tmp_pool,i ? pbuffer : session.user))) {
          snprintf(pbuffer, sizeof(pbuffer), "%s%s", pw->pw_dir, p);
	} else {
          *pbuffer = '\0';
	}
      } else {
        *pbuffer = '\0';
      }
      
      /* check perms on the directory/file we are about to scan */
      if(!ls_perms_full(cmd->tmp_pool, cmd,
			(*pbuffer ? (char *) pbuffer : (char *) arg), NULL)) {
        a = -1;
	skiparg = 1;
      } else {
        skiparg = 0;
        a = fs_glob(*pbuffer ? pbuffer : arg, glob_flags, NULL, &g);
      }
      
      if(!a) {
        char **path;
	
        path = g.gl_pathv;
        if(path && path[0] && path[1])
          justone = 0;
	
        while(path && *path) {
          struct stat st;

	  /* If we have a leading '.', two conditions must be true for us to
	   * invalidate it:
	   *
	   * - opt_a is not set
	   * - We don't have '.' or '..'.
	   */
	  if(**path == '.' && !opt_a && !is_dotdir(*path)) {
            **path = '\0';
            path++;
            continue;
          }
	  
          if(fs_lstat(*path,&st) == 0) {
            mode_t target_mode,lmode;
	    target_mode = st.st_mode;

            if(S_ISLNK(st.st_mode) && (lmode = file_mode((char*)*path)) != 0) {
              if(opt_L || !showsymlinks)
                st.st_mode = lmode;
              target_mode = lmode;
            }

            if(opt_d || !(S_ISDIR(target_mode))) {
              if(listfile(cmd,NULL,*path) < 0) {
                ls_terminate();
		fs_globfree(&g);
                return -1;
              }
              **path = '\0';
            }
          } else {
            **path = '\0';
          }
          path++;
        }

	if(outputfiles(cmd) < 0) {
          ls_terminate();
          fs_globfree(&g);
	  return -1;
        }

        path = g.gl_pathv;
        while(path && *path) {
          if(**path && ls_perms_full(cmd->tmp_pool,cmd,*path,NULL)) {
            char cwd[MAXPATHLEN + 1] = {'\0'};
            int symhold;

            if(!justone) {
              if(opt_STAT) {
		add_response(R_211, "");
		add_response(R_211, "%s:", *path);
	      } else
                sendline("\n%s:\n", *path);
            }

            push_cwd(cwd,&symhold);

            if(!fs_chdir_canon(*path, !opt_L && showsymlinks)) {
              int ret = listdir(cmd, NULL, *path);
              pop_cwd(cwd, &symhold);

              if(ret < 0) {
                ls_terminate();
		fs_globfree(&g);
                return -1;
              }
            }
          }
          if(XFER_ABORTED) {
	    discard_output();
            fs_globfree(&g);
	    return -1;
	  }
          path++;
        }

      } else if(!skiparg) {
        if(a == GLOB_NOSPACE) {
          add_response(R_226,"Out of memory during globbing of %s", arg);
        } else if(a == GLOB_ABORTED) {
          add_response(R_226,"Read error during globbing of %s", arg);
        } else if(a != GLOB_NOMATCH) {
          add_response(R_226,"Unknown error during globbing of %s", arg);
        }
      }

      if(!skiparg)
        fs_globfree(&g);
      arg = endarg;

      if(XFER_ABORTED) {
	discard_output();
        return -1;
      }
    }
  } else {
    if(ls_perms_full(cmd->tmp_pool,cmd,".",NULL)) {
      if(opt_d) {
        if(listfile(cmd,NULL,".") < 0) {
          ls_terminate();
          return -1;
        }
      } else {
        if(listdir(cmd,NULL,".") < 0) {
          ls_terminate(); 
	  return -1;
        }
      }
    }

    if(outputfiles(cmd) < 0) {
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

static
int nlstfile(cmd_rec *cmd, const char *file)
{
	int err;

	/* If the data connection isn't open, open it now. */
	if((session.flags & SF_XFER) == 0) {
		if(data_open(NULL,"file list",IO_WRITE,0) < 0) {
			data_reset();
			return -1;
		}
		session.flags |= SF_ASCII_OVERRIDE;
	}

	if((err = sendline("%s\n",file)) < 0)
		return err;
	
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
  int curdir = 0, i, symhold, count = 0;
  mode_t mode;
  
  workp = make_sub_pool(cmd->tmp_pool);
  
  if(!*dir || (*dir == '.' && !dir[1]) || strcmp(dir, "./") == 0) {
    curdir = 1;
    dir = "";
  } else {
    push_cwd(cwd,&symhold);
  }
  
  if(fs_chdir_canon(dir, !opt_L && showsymlinks)) {
    destroy_pool(workp);
    return 0;
  }
  
  if((list = sreaddir(workp,".",FALSE)) == NULL) {
    if(!curdir)
      pop_cwd(cwd,&symhold);
    destroy_pool(workp);
    return 0;
  }
  
  while(*list && count >= 0) {
    p = *list; list++;
    
    if(*p == '.' && (!opt_A || is_dotdir(p)))
      continue;
    
    if((i = fs_readlink(p, file, sizeof(file))) > 0) {
      file[i] = '\0';
      f = file;
    } else {
      f = p;
    }
    
    if(ls_perms(workp,cmd,f,NULL)) {
      /* If the data connection isn't open, open it now. */
      if((session.flags & SF_XFER) == 0) {
	if(data_open(NULL,"file list",IO_WRITE,0) < 0) {
	  data_reset();
	  count = -1;
	  continue;
	}
	session.flags |= SF_ASCII_OVERRIDE;
      }
      
      if((mode = file_mode(f)) == 0)
	continue;
      
      if(!curdir) {
	if(sendline("%s/%s\n",dir,p) < 0)
	  count = -1;
	else count++;
      } else {
	if(sendline("%s\n",p) < 0)
	  count = -1;
	else count++;
      }
    }
  }
  
  if(!curdir)
    pop_cwd(cwd,&symhold);
  
  destroy_pool(workp);
  
  return count;
}

/* The LIST command.  */
MODRET genericlist(cmd_rec *cmd)
{
  int err;
  long _fakemode;

  showsymlinks = get_param_int(TOPLEVEL_CONF,"ShowSymlinks",FALSE);

  if(showsymlinks == -1)
    showsymlinks = 1;

  default_options = get_param_ptr(TOPLEVEL_CONF,"LsDefaultOptions",FALSE);
  fakeuser = get_param_ptr(TOPLEVEL_CONF,"DirFakeUser",FALSE);
  fakegroup = get_param_ptr(TOPLEVEL_CONF,"DirFakeGroup",FALSE);
  _fakemode = (long)get_param_int(TOPLEVEL_CONF,"DirFakeMode",FALSE);
  timesgmt = get_param_int(TOPLEVEL_CONF, "TimesGMT", FALSE);
  
  if((opt_A = get_param_int(TOPLEVEL_CONF,"ShowDotFiles",FALSE)) < 0)
    opt_A = 0;
  
  if(_fakemode != -1) {
    fakemode = (umode_t)_fakemode;
    fakemodep = 1;
  } else
    fakemodep = 0;

  err = dolist(cmd,cmd->arg,TRUE);
  if(XFER_ABORTED) {
    data_abort(0,0);
    err = -1;
  } else if(session.flags & SF_XFER)
    ls_done(cmd);

  opt_l = 0;
  return (err == -1 ? ERROR(cmd) : HANDLED(cmd));
}

MODRET fini_nlst(cmd_rec *cmd)
{
  data_cleanup();
  return DECLINED(cmd);
}

MODRET cmd_stat(cmd_rec *cmd)
{
  char *arg = cmd->arg;
  long _fakemode;

  if(cmd->argc < 2) {
    add_response_err(R_500,"'%s' not understood.",get_full_cmd(cmd));
    return ERROR(cmd);
  }

  /* Get to the actual argument.
   */
  if(*arg == '-')
    while(arg && *arg && !isspace((UCHAR)*arg)) arg++;
  
  while(arg && *arg && isspace((UCHAR)*arg)) arg++;
  
  showsymlinks = get_param_int(TOPLEVEL_CONF,"ShowSymlinks",FALSE);

  if(showsymlinks == -1)
    showsymlinks = 1;

  default_options = get_param_ptr(TOPLEVEL_CONF,"LsDefaultOptions",FALSE);
  fakeuser = get_param_ptr(TOPLEVEL_CONF,"DirFakeUser",FALSE);
  fakegroup = get_param_ptr(TOPLEVEL_CONF,"DirFakeGroup",FALSE);
  _fakemode = (long)get_param_int(TOPLEVEL_CONF,"DirFakeMode",FALSE);
  timesgmt = get_param_int(TOPLEVEL_CONF, "TimesGMT", FALSE);
  
  /* No need to check ShowDotFiles since we force opt_a below.
   */
  if(_fakemode != -1) {
    fakemode = (umode_t)_fakemode;
    fakemodep = 1;
  } else
    fakemodep = 0;

  opt_C = opt_d = opt_F = opt_R;
  opt_a = opt_l = opt_STAT = 1;

  add_response(R_211,"status of %s:", arg && *arg ? arg : ".");
  dolist(cmd,cmd->arg,FALSE);
  add_response(R_211,"End of Status");
  return HANDLED(cmd);
}

MODRET cmd_list(cmd_rec *cmd)
{
  MODRET ret;
  
  opt_l = 1;
  ret = genericlist(cmd);
  return ret;
}

/* NLST is a very simplistic directory listing, unlike LIST (which
 * emululates ls), it only sends a list of all files/directories
 * matching the glob(s).
 */

MODRET cmd_nlst(cmd_rec *cmd)
{
	char	*target,line[MAXPATHLEN + 1] = {'\0'};
	int	count = 0;
	int	ret = 0;

	/* In case the client used NLST instead of LIST
	 */

	if(cmd->argc > 1 && cmd->argv[1][0] == '-')
		return genericlist(cmd);

	showsymlinks = get_param_int(TOPLEVEL_CONF,"ShowSymlinks",FALSE);

	if(showsymlinks == -1)
		showsymlinks = 1;
	if((opt_A = get_param_int(TOPLEVEL_CONF,"ShowDotFiles",FALSE)) < 0)
	  opt_A = 0;
	
	if(cmd->argc == 1)
		target = ".";
	else
		target = cmd->arg;
	
	/* If the target starts with '~' ... */
	if(*target == '~') {
		char pb[MAXPATHLEN + 1] = {'\0'};
		struct passwd *pw;
		int i;
		const char *p;

		i = 0;
		p = target;
		p++;

		while(*p && *p !='/' && i<MAXPATHLEN)
			pb[i++] = *p++;
		pb[i] = '\0';

		if((pw = auth_getpwnam(cmd->tmp_pool,i ? pb : session.user))) {
		  snprintf(pb, sizeof(pb), "%s%s",pw->pw_dir,p);
		  sstrncpy(line, pb, sizeof(line));
		  target = line;
		}
	}
	
	/* If the target is a glob, get the listing of files/dirs to send
	 */

	if(strpbrk(target,"{[*?") != NULL) {
		glob_t g;
		char **path,*p;
		
		if(fs_glob(target,GLOB_PERIOD,NULL,&g) != 0) {
			add_response_err(R_550,"No files found.");
			return ERROR(cmd);
		}

		/* Iterate through each matching entry */
		path = g.gl_pathv;
		while(path && *path && ret >= 0) {
			struct stat st;

			p = *path; path++;

			if(*p == '.' && (!opt_A || is_dotdir(p)))
				continue;

			if(fs_stat(p,&st) == 0) {
				/* If it's a directory, hand off to nlstdir */
				if(S_ISDIR(st.st_mode))
					ret = nlstdir(cmd,p);
				else if(S_ISREG(st.st_mode) &&
						ls_perms(cmd->tmp_pool,cmd,p,NULL))
					ret = nlstfile(cmd,p);
				if(ret > 0)
					count += ret;
			}
		}
		fs_globfree(&g);
	} else {
		/* A single target, if it's a directory, list the contents,
		 * if it's a file, just list the file.
		 */
		int hidden;
		struct stat st;
		
		if(!ls_perms(cmd->tmp_pool,cmd,target,&hidden)) {
			if(hidden)
				add_response_err(R_550,"%s: No such file or directory",cmd->arg);
			else
				add_response_err(R_550,"%s: Permission denied",cmd->arg);
			return ERROR(cmd);
		}

		/* Make sure the target is a file or directory,
		 * and that we have access to it.
		 */
		if(fs_stat(target,&st) < 0) {
			add_response_err(R_550,"%s: %s",
					cmd->arg,strerror(errno));
			return ERROR(cmd);
		}

		if(S_ISREG(st.st_mode))
			ret = nlstfile(cmd,target);
		else if(S_ISDIR(st.st_mode)) {
			if(access_check(target,R_OK) != 0) {
				add_response_err(R_550,"%s: %s",
						cmd->arg,strerror(errno));
				return ERROR(cmd);
			}
			ret = nlstdir(cmd,target);
		} else {
			add_response_err(R_550,"%s: Not a regular file",
					cmd->arg,strerror(errno));
			return ERROR(cmd);
		}
		
		if(ret > 0)
			count += ret;
	}
	
	if(XFER_ABORTED) {
		data_abort(0,0);
		ret = -1;
	} else {
		if(ret == 0 && !count && (session.flags & SF_XFER) == 0) {
			add_response_err(R_550,"No files found.");
			ret = -1;
		} else if(session.flags & SF_XFER)
			ls_done(cmd);

		/* Note that the data connection is NOT cleared here,
		 * as an error in NLST still leaves data ready for
		 * another command
		 */
	}

	return (ret < 0 ? ERROR(cmd) : HANDLED(cmd));
}

MODRET _sethide(cmd_rec *cmd, const char *param)
{
  int bool;
  char *as = "ftp";

  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);

  if(cmd->argc < 2 || cmd->argc > 3)
    CONF_ERROR(cmd,pstrcat(cmd->tmp_pool,"syntax: ",
                   param," On|Off [<id to display>]",NULL));

  bool = get_boolean(cmd,1);
  if(bool > 0) {
    if(cmd->argc > 2)
      as = cmd->argv[2];

    add_config_param_str(param,1,as);
  } else if(!bool)
    add_config_param_str(param,0);

  return HANDLED(cmd);
}

MODRET set_dirfakeuser(cmd_rec *cmd)
{
  return _sethide(cmd,"DirFakeUser");
}

MODRET set_dirfakegroup(cmd_rec *cmd)
{
  return _sethide(cmd,"DirFakeGroup");
}

MODRET set_dirfakemode(cmd_rec *cmd)
{
  config_rec *c;
  unsigned long fake;
  char *endp;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL|CONF_DIR);

  fake = (unsigned long)strtol(cmd->argv[1],&endp,8);

  if(endp && *endp)
    CONF_ERROR(cmd,"argument must be an octal number.");

  c = add_config_param("DirFakeMode",1,(void*)fake);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_lsdefaultoptions(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);

  add_config_param_str("LsDefaultOptions",1,cmd->argv[1]);

  return HANDLED(cmd);
}

MODRET set_showdotfiles(cmd_rec *cmd)
{
  int b;
  
  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);

  if((b = get_boolean(cmd,1)) == -1)
    CONF_ERROR(cmd,"expected boolean argument.");

  add_config_param("ShowDotFiles",1,(void*)b);
  return HANDLED(cmd);
}

static conftable ls_config[] = {
  { "DirFakeUser",	set_dirfakeuser,			NULL },
  { "DirFakeGroup",	set_dirfakegroup,			NULL },
  { "DirFakeMode",	set_dirfakemode,			NULL },
  { "LsDefaultOptions",	set_lsdefaultoptions,			NULL },
  { "ShowDotFiles",	set_showdotfiles,			NULL },
  { NULL,		NULL,					NULL }
};

static cmdtable ls_commands[] = {
  { CMD,  	C_NLST,	G_DIRS,	cmd_nlst,	TRUE, FALSE, CL_DIRS },
  { CMD,	C_LIST,	G_DIRS,	cmd_list,	TRUE, FALSE, CL_DIRS },
  { CMD, 	C_STAT,	G_DIRS,	cmd_stat,	TRUE, FALSE, CL_DIRS },
  { LOG_CMD,	C_LIST,	G_NONE,	fini_nlst,	FALSE, FALSE },
  { LOG_CMD,	C_NLST, G_NONE,	fini_nlst,	FALSE, FALSE },
  { 0, NULL }
};

module ls_module = {
  NULL,NULL,			/* Always NULL */
  0x20,				/* API version */
  "ls",				/* Module name */
  ls_config,
  ls_commands,
  NULL,
  NULL,NULL
};
