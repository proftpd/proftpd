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
 * Directory listing module for proftpd
 * $Id: mod_ls.c,v 1.1 1998-10-18 02:24:41 flood Exp $
 */

#include "conf.h"

#ifndef GLOB_ABORTED
#define GLOB_ABORTED GLOB_ABEND
#endif

#define MAP_UID(x)	(fakeuser ? fakeuser : auth_uid_name(cmd->tmp_pool,(x)))
#define MAP_GID(x)	(fakegroup ? fakegroup : auth_gid_name(cmd->tmp_pool,(x)))

static void addfile(cmd_rec*,const char *, const char *, time_t);
static int outputfiles(cmd_rec*);

static int listfile(cmd_rec*,const char *name);
static int listdir(cmd_rec*,const char *name,int list_dotdirs);

static int matches = 0;
static char *default_options;
static int showsymlinks,showsymlinks_hold;
static int cmp(const void *a, const void *b);
static char *fakeuser,*fakegroup;
static umode_t fakemode;
static int fakemodep;
static int ls_errno = 0;
static time_t ls_curtime = 0;

/* ls options */
int opt_a = 0,
    opt_C = 0,
    opt_d = 0,
    opt_F = 0,
    opt_l = 0,
    opt_R = 0,
    opt_t = 0,
    opt_STAT = 0;

static char cwd[MAXPATHLEN+1] = "";

static void push_cwd(char *_cwd, int *symhold)
{
  if(!_cwd) _cwd = cwd;
  if(!symhold) symhold = &showsymlinks_hold;

  strncpy(_cwd,fs_getcwd(),MAXPATHLEN);
  *symhold = showsymlinks;
}

static void pop_cwd(char *_cwd, int *symhold)
{
  if(!_cwd) _cwd = cwd;
  if(!symhold) symhold = &showsymlinks_hold;

  fs_chdir(_cwd,*symhold);
  showsymlinks = *symhold;
}

static int ls_perms(pool *p, cmd_rec *cmd, const char *path)
{
  int ret,hidden;
  char *fullpath;

  fullpath = pdircat(p,fs_getcwd(),path,NULL);
  fullpath = dir_canonical_path(p,fullpath);
  
  ret = dir_check(p,cmd->argv[0],cmd->group,fullpath,&hidden);

  if(hidden)
    return 0;

  if(session.dir_config) {
    showsymlinks = get_param_int(session.dir_config->subset,
                                 "ShowSymlinks",FALSE);

    if(showsymlinks == -1)
      showsymlinks = 1;
  }

  return ret;
}

static int ls_perms_full(pool *p, cmd_rec *cmd, const char *path)
{
  int ret,hidden,canon = 0;
  char *fullpath;

  fullpath = dir_realpath(p,path);
  if(!fullpath) {
    fullpath = dir_canonical_path(p,path);
    canon = 1;
  } if(!fullpath)
    fullpath = pstrdup(p,path);
  
  if(canon)
    ret = dir_check_canon(p,cmd->argv[0],cmd->group,fullpath,&hidden);
  else
    ret = dir_check(p,cmd->argv[0],cmd->group,fullpath,&hidden);

  if(hidden)
    return 0;

  if(session.dir_config) {
    showsymlinks = get_param_int(session.dir_config->subset,
                                 "ShowSymlinks",FALSE);

    if(showsymlinks == -1)
      showsymlinks = 1;
  }

  return ret;
}

static
int sendline(char *fmt, ...)
{
  va_list msg;
  char buf[1025];
  int ret;

  va_start(msg,fmt);
  vsnprintf(buf,sizeof(buf),fmt,msg);
  va_end(msg);

  buf[1024] = '\0';

  ret = data_xfer(buf,strlen(buf));
  if(ret < 0) {
    log_debug(DEBUG3,"data_xfer returned %d, error = %s",
              ret,strerror(session.d->outf->xerrno));
  }
  return ret;
}

static
void ls_done(cmd_rec *cmd)
{
  data_close(FALSE);
}

static
int listfile(cmd_rec *cmd, const char *name)
{
  int		rval = 0;
  time_t	mtime;
  char		m[1024],l[1024];
  struct	stat st;
  char		months[12][4] =
  { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

  struct	tm *t;
  char		suffix[2];

  if(fs_lstat(name,&st) == 0) {
    suffix[0] = suffix[1] = '\0';

    if(S_ISLNK(st.st_mode) && !showsymlinks) {
      /* attempt to fully dereference symlink */
      struct stat l_st;

      if(fs_stat(name,&l_st) != -1) {
        memcpy(&st,&l_st,sizeof(st));
        m[fs_readlink(name,m,sizeof(m))] = '\0';
        if(!ls_perms_full(cmd->tmp_pool,cmd,m))
          return 0;
      } else
        return 0;
    } else if(S_ISLNK(st.st_mode)) {
      l[fs_readlink(name,l,sizeof(l))] = '\0';
      if(!ls_perms_full(cmd->tmp_pool,cmd,l))
        return 0;
    } else if(!ls_perms(cmd->tmp_pool,cmd,name))
      return 0;

    mtime = st.st_mtime;
    t = localtime((time_t*)&mtime);
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
      } else if(st.st_mode & 010101 )
        suffix[0] = '*';
    }

    if(opt_l) {
      strcpy(m," ---------");
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
        char nameline[MAXPATHLEN + MAXPATHLEN + 128];
        char timeline[6];
        umode_t mode = st.st_mode;

        if(fakemodep)
          mode = fakemode;

        if(mode & 256)
          m[1] = 'r';
        if(mode & 128)
          m[2] = 'w';
        if(mode & 64)
          m[3] = 'x';
        if(mode & 32)
          m[4] = 'r';
        if(mode & 16)
          m[5] = 'w';
        if(mode & 8)
          m[6] = 'x';
        if(mode & 4)
          m[7] = 'r';
        if(mode & 2)
          m[8] = 'w';
        if(mode & 1)
          m[9] = 'x';

        if(ls_curtime - mtime > 180 * 24 * 60 * 60)
          sprintf(timeline,"%5d",t->tm_year+1900);
        else
          sprintf(timeline,"%02d:%02d",t->tm_hour,t->tm_min);

        sprintf(nameline,"%s %3d %-8s %-8s %8d %s %2d %s %s", m,
                (int)st.st_nlink, MAP_UID((int)st.st_uid), 
                MAP_GID((int)st.st_gid),
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
            else if(S_ISDIR(st.st_mode & 010101))
              suffix[0] = '*';
          }

          sprintf(p," -> %s", l);
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
 
void addfile(cmd_rec *cmd, const char *name, const char *suffix, time_t mtime)
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
      sort_arr = make_array(fpool,20,sizeof(struct sort_filename));

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

  p = (struct filename*)pcalloc(fpool,sizeof(struct filename) + l + 1);
#if 0
  log_debug(DEBUG4,"alloc: %d\n",sizeof(struct filename) + l + 1);
#endif

  sprintf(p->line, "%s%s", name, suffix);
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
void sortfiles(cmd_rec *cmd)
{
  struct sort_filename *s;
  int i;

  if(opt_t && sort_arr) {
    qsort(sort_arr->elts, sort_arr->nelts, sizeof(struct sort_filename),
          (int (*)(const void*,const void*))_compare_file_mtime);

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

  if(opt_l)
    if(sendline("total 0\n") < 0)
      return -1;

  p = head;
  while(p) {
    q = p;
    p = p->down;
    while(q) {
      char pad[6];

      if(q->right) {
        strcpy(pad,"\t\t\t\t\t");
        pad[(colwidth + 7 - strlen(q->line)) / 8] = '\0';
      } else
        strcpy(pad,"\n");

      if(sendline("%s%s",q->line,pad) < 0)
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
char **sreaddir(pool *workp, const char *dirname)
{
  DIR 		*d;
  struct	dirent *de;
  struct	stat st;
  int		i;
  char		**p;
  char		*s;
  int		dsize;

  if(fs_stat(dirname,&st) < 0) 
    return NULL;

  if(!S_ISDIR(st.st_mode)) {
    errno = ENOTDIR;
    return NULL;
  }

  if((d = opendir(dirname)) == NULL)
    return NULL;

  dsize = st.st_size + 100;

realloc_buf:
  p = (char**)palloc(workp,dsize);

  s = dsize + (char*)p;
  i = 0;

  while((de = readdir(d)) != NULL) {
    if((unsigned int)p + (i+1)*sizeof(char*) + strlen(de->d_name) + 1
         > (unsigned int)s) {
      dsize *= 2;
      rewinddir(d);
      goto realloc_buf;
    }
    s -= strlen(de->d_name) + 1;
    strcpy(s,de->d_name);
    p[i++] = s;
  }

  closedir(d);
  p[i] = NULL;

  qsort(p,i,sizeof(char*),cmp);
  return p;
}

/* listdir required chdir first */
int listdir(cmd_rec *cmd, const char *name, int list_dotdirs)
{
  char **dir;
  pool *workp;

  if(XFER_ABORTED)
	return -1;

  workp = make_sub_pool(cmd->tmp_pool);
  dir = sreaddir(workp,".");

  if(dir) {
    char **s;
    char **r;

    int d = 0;

    /* CODENOTE: print total here */

    s = dir;
    while(*s) {
      if(**s != '.') {
        d = listfile(cmd,*s);
      } else if(!opt_a && list_dotdirs) {
        if( (((*s)[1] == '\0') ||
            (((*s)[1] == '.') &&
             ((*s)[2] == '\0')))) {
          d = listfile(cmd,*s);
          if(d > 0)
            d = 0;
        }
      } else if(opt_a) {
        d = listfile(cmd,*s);
        if(d && (((*s)[1] == '\0') ||
           (((*s)[1] == '.') &&
            ((*s)[2] == '\0'))))
          d = 0;
      } else {
        d = 0;
      }
      if(!d)
        *s = NULL;
      s++;
    }

    if(outputfiles(cmd) < 0) {
      destroy_pool(workp);
      return -1;
    }

    r = dir;
    while(opt_R && r != s) {
      char cwd[MAXPATHLEN];
      int symhold;

      push_cwd(cwd,&symhold);
      
      if(*r && ls_perms_full(workp,cmd,(char*)*r) && !fs_chdir_canon(*r,showsymlinks)) {
        char *subdir;

	if(strcmp(name,".") == 0)
          subdir = *r;
        else
          subdir = pdircat(workp,name,*r,NULL);

	if(opt_STAT)
          add_response(R_211,"\r\n%s:\r\n",subdir);
	else if(sendline("\n%s:\n",subdir) < 0) {
          pop_cwd(cwd,&symhold);
          destroy_pool(workp);
          return -1;
        }

        if(listdir(cmd,subdir,list_dotdirs) < 0) {
          pop_cwd(cwd,&symhold);
          destroy_pool(workp);
          return -1;
        }

        pop_cwd(cwd,&symhold);
      }
      r++;
    }
  }

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
    opt++;

  while(*opt && **opt == '-') {
    while((*opt)++ && isalnum((UCHAR)**opt)) {
      switch(**opt) {
      case 'a':
        opt_a++;
        break;
      case 'l':
        opt_l++;
        opt_C = 0;
        break;
      case '1':
        opt_l = opt_C = 0;
        break;
      case 'C':
        opt_l = 0;
        opt_C++;
        break;
      case 'F':
        opt_F++;
        break;
      case 'R':
        opt_R++;
        break;
      case 'd':
        opt_d++;
        break;
      case 't':
        opt_t++;
        if(glob_flags)
          *glob_flags |= GLOB_NOSORT;;
        break;
      }
    }
    while(isspace((UCHAR)**opt)) 
      (*opt)++;

  }
}

static
int donlist(cmd_rec *cmd, const char *opt, int clearflags)
{
  int skiparg = 0;
  int glob_flags = GLOB_PERIOD;
  char *arg = (char*)opt;

  matches = 0;
  ls_curtime = time(NULL);

  if(clearflags)
    opt_a = opt_C = opt_d = opt_F = opt_R = opt_t = opt_STAT = 0;

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
      char   pbuffer[MAXPATHLEN];

      char   *endarg = strchr(arg,' ');

      if(endarg) {
        *endarg++ = '\0';
        justone = 0;
      }

      if(*arg == '~') {
        struct passwd *pw;
	int i;
        const char *p;

        i = 0;
        p = arg;
        p++;

        while(*p && *p != '/')
          pbuffer[i++] = *p++;
        pbuffer[i] = '\0';

        if((pw = auth_getpwnam(cmd->tmp_pool,i ? pbuffer : session.user)))
          sprintf(pbuffer,"%s%s",pw->pw_dir,p);
        else
          *pbuffer = '\0';
      } else
        *pbuffer = '\0';

      /* check perms on the directory/file we are about to scan */
      if(!ls_perms_full(cmd->tmp_pool,cmd,(*pbuffer ? (char*)pbuffer:(char*)arg))) {
        a = -1; skiparg = 1;
      } else {
        skiparg = 0;
        a = fs_glob(*pbuffer ? pbuffer:arg, glob_flags,
                 NULL, &g);
      }

      if(!a) {
        char **path;

        path = g.gl_pathv;
        if(path && path[0] && path[1])
          justone = 0;

        while(path && *path) {
          struct stat st;

          /* if opt_a is not set, don't display dot files, except for
           * ./ and ../
           */

          if(**path == '.' && !opt_a && strcmp(*path,".") && strcmp(*path,"..")) {
            **path = '\0';
            path++;
            continue;
          }

          if(fs_lstat(*path,&st) == 0) {
            mode_t target_mode,lmode;
	    target_mode = st.st_mode;

            if(S_ISLNK(st.st_mode) && (lmode = file_mode((char*)*path)) != 0) {
              if(!showsymlinks)
                st.st_mode = lmode;
              target_mode = lmode;
            }

            if(opt_d || !(S_ISDIR(target_mode))) {
              if(listfile(cmd,*path) < 0) {
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
          if(**path && ls_perms_full(cmd->tmp_pool,cmd,*path)) {
            char cwd[MAXPATHLEN];
            int symhold;

            if(!justone) {
              if(opt_STAT)
	        add_response(R_211,"\r\n%s:\r\n",*path);
              else
                sendline("\n%s:\n",*path);
            }

            push_cwd(cwd,&symhold);

            if(!fs_chdir_canon(*path,showsymlinks)) {
              int ret = listdir(cmd,*path,FALSE);
              pop_cwd(cwd,&symhold);

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
    if(ls_perms_full(cmd->tmp_pool,cmd,".")) {
      if(opt_d) {
        if(listfile(cmd,".") < 0) {
          ls_terminate();
          return -1;
        }
      } else {
        if(listdir(cmd,".",FALSE) < 0) {
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

MODRET cmd_nlst(cmd_rec *cmd)
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

  if(_fakemode != -1) {
    fakemode = (umode_t)_fakemode;
    fakemodep = 1;
  } else
    fakemodep = 0;

  err = donlist(cmd,cmd->arg,TRUE);
  if(XFER_ABORTED) {
    data_abort(0,0);
    err = -1;
  } else if(session.flags & SF_XFER)
    ls_done(cmd);

  opt_l = 0;
  return (err == -1 ? ERROR(cmd) : HANDLED(cmd));
}

MODRET cmd_list(cmd_rec *cmd)
{
  opt_l = 1;
  return cmd_nlst(cmd);
}

MODRET fini_nlst(cmd_rec *cmd)
{
  data_cleanup();
  return DECLINED(cmd);
}

MODRET cmd_stat(cmd_rec *cmd)
{
  struct stat sbuf;
  char *arg = cmd->arg;
  long _fakemode;

  if(cmd->argc < 2) {
    add_response_err(R_500,"'%s' not understood.",get_full_cmd(cmd));
    return ERROR(cmd);
  }

  if(*arg == '-')
    while(!isspace((UCHAR)*arg)) arg++;
  while(isspace((UCHAR)*arg)) arg++;

  showsymlinks = get_param_int(TOPLEVEL_CONF,"ShowSymlinks",FALSE);

  if(showsymlinks == -1)
    showsymlinks = 1;

  default_options = get_param_ptr(TOPLEVEL_CONF,"LsDefaultOptions",FALSE);
  fakeuser = get_param_ptr(TOPLEVEL_CONF,"DirFakeUser",FALSE);
  fakegroup = get_param_ptr(TOPLEVEL_CONF,"DirFakeGroup",FALSE);
  _fakemode = (long)get_param_int(TOPLEVEL_CONF,"DirFakeMode",FALSE);

  if(_fakemode != -1) {
    fakemode = (umode_t)_fakemode;
    fakemodep = 1;
  } else
    fakemodep = 0;

  opt_C = opt_d = opt_F = opt_R;
  opt_a = opt_l = opt_STAT = 1;

  if(fs_stat(arg,&sbuf) == -1) {
    add_response_err(R_550,"%s: %s",arg,strerror(errno));
    return ERROR(cmd);
  }

  add_response(R_211,"status of %s:",arg);
  donlist(cmd,cmd->arg,FALSE);
  add_response(R_211,"End of Status");
  return HANDLED(cmd);
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
  unsigned long fake;
  char *endp;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);

  fake = (unsigned long)strtol(cmd->argv[1],&endp,8);

  if(endp && *endp)
    CONF_ERROR(cmd,"argument must be an octal number.");

  add_config_param("DirFakeMode",1,(void*)fake);

  return HANDLED(cmd);
}

MODRET set_lsdefaultoptions(cmd_rec *cmd)
{
  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);

  add_config_param_str("LsDefaultOptions",1,cmd->argv[1]);

  return HANDLED(cmd);
}

conftable ls_config[] = {
  { "DirFakeUser",	set_dirfakeuser,			NULL },
  { "DirFakeGroup",	set_dirfakegroup,			NULL },
  { "DirFakeMode",	set_dirfakemode,			NULL },
  { "LsDefaultOptions",	set_lsdefaultoptions,			NULL },
  { NULL,		NULL,					NULL }
};

cmdtable ls_commands[] = {
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
