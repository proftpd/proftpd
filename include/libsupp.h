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
not, write to the Free Software Foundation, Inc., 59 Temple Place, 
Suite 330, Boston, MA  02111-1307, USA.  */

#if !defined HAVE_GLOB && !defined __PROFTPD_SUPPORT_LIBRARY

#ifndef __P
#define __P(x)	x
#endif

/* Bits set in the FLAGS argument to `glob'.  */
#define GLOB_ERR        (1 << 0)/* Return on read errors.  */
#define GLOB_MARK       (1 << 1)/* Append a slash to each name.  */
#define GLOB_NOSORT     (1 << 2)/* Don't sort the names.  */
#define GLOB_DOOFFS     (1 << 3)/* Insert PGLOB->gl_offs NULLs.  */
#define GLOB_NOCHECK    (1 << 4)/* If nothing matches, return the pattern.  */ 
#define GLOB_APPEND     (1 << 5)/* Append to results of a previous call.  */   
#define GLOB_NOESCAPE   (1 << 6)/* Backslashes don't quote metacharacters.  */
#define GLOB_PERIOD     (1 << 7)/* Leading `.' can be matched by metachars.  */
# define GLOB_MAGCHAR    (1 << 8)/* Set in gl_flags if any metachars seen.  */
# define GLOB_ALTDIRFUNC (1 << 9)/* Use gl_opendir et al functions.  */
# define GLOB_BRACE      (1 << 10)/* Expand "{a,b}" to "a" "b".  */
# define GLOB_NOMAGIC    (1 << 11)/* If no magic chars, return the pattern.  */
# define GLOB_TILDE      (1 << 12)/* Expand ~user and ~ to home directories. */
# define GLOB_ONLYDIR    (1 << 13)/* Match only directories.  */
# define __GLOB_FLAGS   (GLOB_ERR|GLOB_MARK|GLOB_NOSORT|GLOB_DOOFFS| \
                         GLOB_NOESCAPE|GLOB_NOCHECK|GLOB_APPEND|     \
                         GLOB_PERIOD|GLOB_ALTDIRFUNC|GLOB_BRACE|     \
                         GLOB_NOMAGIC|GLOB_TILDE|GLOB_ONLYDIR)
#define GLOB_NOSPACE    1       /* Ran out of memory.  */
#define GLOB_ABORTED    2       /* Read error.  */
#define GLOB_NOMATCH    3       /* No matches found.  */

/* Structure describing a globbing run.  */
#if !defined _AMIGA && !defined VMS /* Buggy compiler.   */
struct stat;
#endif
typedef struct
  {
    int gl_pathc;               /* Count of paths matched by the pattern.  */
    char **gl_pathv;            /* List of matched pathnames.  */
    int gl_offs;                /* Slots to reserve in `gl_pathv'.  */
    int gl_flags;               /* Set to FLAGS, maybe | GLOB_MAGCHAR.  */

    /* If the GLOB_ALTDIRFUNC flag is set, the following functions
       are used instead of the normal file access functions.  */  
    void (*gl_closedir) __P ((void *));
    struct dirent *(*gl_readdir) __P ((void *));
    void *(*gl_opendir) __P ((const char *));
    int (*gl_lstat) __P ((const char *, struct stat *));
    int (*gl_stat) __P ((const char *, struct stat *));
  } glob_t;

extern int glob (const char *__pattern, int __flags,
                      int (*__errfunc)(const char *, int),
                      glob_t *__pglob);
extern void globfree (glob_t *__pglob);
extern int __glob_pattern_p (const char *__pattern, int __quote);
extern int glob_pattern_p (const char *__pattern, int __quote);

#endif /* HAVE_GLOB */

#ifndef HAVE_FNMATCH

/* Bits set in the FLAGS argument to `fnmatch'.  */
#define	FNM_PATHNAME	(1 << 0) /* No wildcard can ever match `/'.  */
#define	FNM_NOESCAPE	(1 << 1) /* Backslashes don't quote special chars.  */
#define	FNM_PERIOD	(1 << 2) /* Leading `.' is matched only explicitly.  */

#define	FNM_FILE_NAME	FNM_PATHNAME /* Preferred GNU name.  */
#define	FNM_LEADING_DIR	(1 << 3) /* Ignore `/...' after a match.  */
#define	FNM_CASEFOLD	(1 << 4) /* Compare without regard to case.  */

/* Value returned by `fnmatch' if STRING does not match PATTERN.  */
#define	FNM_NOMATCH	1

int fnmatch(const char *pattern, const char *strings, int flags);

#endif /* HAVE_FNMATCH */

#ifndef HAVE_STRSEP

char *strsep(char **stringp, const char *delim);

#endif /* HAVE_STRSEP */

#ifndef HAVE_VSNPRINTF

int vsnprintf(char *,size_t,const char*,va_list);

#endif /* HAVE_VSNPRINTF */

#ifndef HAVE_SNPRINTF

int snprintf(char *,size_t,const char*,...);

#endif

#ifndef HAVE_FGETPWENT
struct passwd *fgetpwent(FILE*);
#endif /* HAVE_FGETPWENT */

#ifndef HAVE_FGETGRENT
struct group *fgetgrent(FILE*);
#endif /* HAVE_FGETGRENT */
