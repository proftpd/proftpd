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

/* Non-specific support functions.
 * $Id: support.h,v 1.5 2000-10-08 22:24:46 macgyver Exp $
 */

#ifndef __SUPPORT_H
#define __SUPPORT_H

#define CHOP(s)		strip_end((s),"\r\n")

#if defined(NAME_MAX)
# define NAME_MAX_GUESS		(NAME_MAX)
#elif defined(MAXNAMELEN)
# define NAME_MAX_GUESS		(MAXNAMELEN - 1)
#else
# define NAME_MAX_GUESS		(255)
#endif

/* Functions [optionally] provided by libsupp.a */
#ifndef HAVE_GETOPT
int getopt(int argc, char * const argv[], const char *optstring);
extern char *optarg;
extern int optind,opterr,optopt;
#endif

#ifndef HAVE_GETOPT_LONG
struct option {
  const char *name;
  int has_arg;
  int *flag;
  int val;
};

int getopt_long(int argc, char * const argv[],
                const char *optstring,
                const struct option *longopts, int *longindex);
#endif

void block_signals();
void unblock_signals();

char *dir_interpolate(pool*,const char*);
char *dir_abs_path(pool*,const char*,int);
char *dir_realpath(pool*,const char*);
char *dir_canonical_path(pool*,const char*);
char *dir_best_path(pool*,const char*);
char *dir_virtual_chdir(pool*,const char*);

void add_exit_handler(void (*f)());
void run_exit_handlers();

void schedule(void (*f)(void*,void*,void*,void*),int nloops,
              void*,void*,void*,void*);
void run_schedule();
int schedulep();

int get_name_max(char*, int);

mode_t file_mode(char*);
int file_exists(char*);
int dir_exists(char*);
int exists(char*);
int access_check(char *, int);
char *make_arg_str(pool*,int,char**);

char *strip_end(char*,char*);
char *get_token(char**,char*);
char *safe_token(char**);
int check_shutmsg(time_t*,time_t*,time_t*,char*,size_t);

char *sstrcat(char *dest, const char *src, size_t n);
char *sstrncpy(char *dest, const char *src, size_t n);
char *sreplace(pool*,char*,...);

#if defined(HAVE_SYS_STATVFS_H) || defined(HAVE_SYS_VFS_H)
unsigned long get_fs_size(char*);
#endif
#endif /* __SUPPORT_H */
