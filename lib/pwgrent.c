/* Copyright (C) 1991, 1992, 1993 Free Software Foundation, Inc.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU Library General Public
License along with this library; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite
330, Boston, MA  02111-1307, USA.  */

/* Required to tell conf.h not to include the standard ProFTPD
 * header files
 */

#define __PROFTPD_SUPPORT_LIBRARY

#include <conf.h>

/* From log.c */
extern void log_pri(int, char *, ...);

/* From utils.c */
extern char *sstrncpy(char *dest, const char *src, size_t n);

#define NPWDFIELDS 	7
#define NGRPFIELDS 	4

#ifndef BUFSIZ
#define BUFSIZ		1024
#endif

/* provides fgetpwent()/fgetgrent() functions.  Note that the
 * format of the files is probably NOT platform dependant, so
 * use of these functions will require a strict format
 * "username:password:uid:gid:gecos:home:default_shell"
 */

#ifndef HAVE_FGETPWENT

static char pwdbuf[BUFSIZ];
static char *pwdfields[NPWDFIELDS];
static struct passwd pwent;

static struct passwd *_pgetpwent(const char *buf)
{
  register	int	i;
  register	char	*cp;
  char			*ep;
  char			**fields;
  char			*buffer;
  struct	passwd	*pwd;

  fields = pwdfields;
  buffer = pwdbuf;
  pwd = &pwent;

  strncpy(buffer,buf,BUFSIZ-1);
  buffer[BUFSIZ-1] = '\0';

  for(cp = buffer, i = 0; i < NPWDFIELDS && cp; i++) {
    fields[i] = cp;
    while(*cp && *cp != ':')
      ++cp;
    if(*cp)
      *cp++ = '\0';
    else
      cp = 0;
  }

  if(i != NPWDFIELDS || *fields[2] == '\0' || *fields[3] == '\0')
    return 0;

  pwd->pw_name = fields[0];
  pwd->pw_passwd = fields[1];
  if(fields[2][0] == '\0' ||
     ((pwd->pw_uid = strtol(fields[2], &ep, 10)) == 0 && *ep))
       return 0;

  if(fields[3][0] == '\0' ||
     ((pwd->pw_gid = strtol(fields[3], &ep, 10)) == 0 && *ep))
       return 0;

  pwd->pw_gecos = fields[4];
  pwd->pw_dir = fields[5];
  pwd->pw_shell = fields[6];

  return pwd;  
}

struct passwd *fgetpwent(FILE *fp)
{
  char buf[BUFSIZ] = {'\0'};

  while (fgets(buf, sizeof(buf), fp) != (char*) 0) {

    /* ignore empty and comment lines */
    if (buf[0] == '\0' || buf[0] == '#')
      continue;

    buf[strlen(buf) - 1] = '\0';
    return _pgetpwent(buf);
  }

  return NULL;
}
#endif /* HAVE_FGETPWENT */

#ifndef HAVE_FGETGRENT


#define MAXMEMBERS 4096

static char *grpbuf = NULL;
static struct group grent;
static char *grpfields[NGRPFIELDS];
static char *members[MAXMEMBERS+1];

static char *fgetbufline(char **buf, int *size, FILE *fp)
{
  char *rbuf = NULL,*cp;

  if(!*size || !*buf) {
    *size = BUFSIZ;
    *buf = rbuf = malloc(*size);
    if(!rbuf)
      return 0;
  }

  cp = rbuf;

  while(fgets(cp,(*size) - (cp - rbuf), fp) != (char *)0) {
    if(strchr(cp,'\n'))
      return rbuf;

    *size += *size;
    *buf = realloc(rbuf,*size);

    if(!*buf)
      break;

    cp = *buf + (cp - rbuf);
    rbuf = *buf;
    cp = strchr(cp,'\0');
  }

  free(rbuf);
  *buf = NULL; *size = 0;
  return 0;
}

static char **_grlist(char *s)
{
  int nmembers = 0;

  while(s && *s && nmembers < MAXMEMBERS) {
    members[nmembers++] = s;
    while(*s && *s != ',')
      s++;
    if(*s)
      *s++ = '\0';
  }

  members[nmembers] = (char*)0;
  return members;
}

static struct group *
_pgetgrent(const char *buf)
{
  int i;
  char *cp;

  i = strlen(buf) + 1;
  
  if(!grpbuf)
    grpbuf = malloc(i);
  else
    grpbuf = realloc(grpbuf, i);
  
  if(!grpbuf)
    return NULL;
  
  sstrncpy(grpbuf, buf, i);
  
  if((cp = strrchr(grpbuf,'\n')))
    *cp = '\0';

  for(cp = grpbuf, i = 0; i < NGRPFIELDS && cp; i++) {
    grpfields[i] = cp;
    if((cp = strchr(cp,':')))
      *cp++ = 0;
  }

  if(i < (NGRPFIELDS - 1)) {
    log_pri(LOG_ERR, "Malformed entry in group file: %s", buf);
    return 0;
  }
  
  if(*grpfields[2] == '\0')
    return 0;

  grent.gr_name = grpfields[0];
  grent.gr_passwd = grpfields[1];
  grent.gr_gid = atoi(grpfields[2]);
  grent.gr_mem = _grlist(grpfields[3]);

  return &grent;
}

struct group *fgetgrent(FILE *fp)
{
  char *buf = NULL;
  int size = 0;
  char *cp;
  struct group *g;

  while (fgetbufline(&buf,&size,fp) != (char*)0) {

    /* ignore comment and empty lines */
    if (buf[0] == '\0' || buf[0] == '#')
      continue;

    if ((cp = strchr(buf,'\n')) != (char*)0)
      *cp = '\0';

    g = _pgetgrent(buf);
    free(buf);
    return g;
  }

  return 0;
}

#endif /* HAVE_FGETGRENT */
