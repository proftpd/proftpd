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

/* Non-specific support functions.
 * $Id: support.h,v 1.14 2002-12-05 21:16:48 castaglia Exp $
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
int getopt(int, char * const [], const char *);
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

int getopt_long(int, char * const [], const char *, const struct option *,
  int *);
#endif

void block_signals(void);
void unblock_signals(void);

char *dir_interpolate(pool *, const char *);
char *dir_abs_path(pool *, const char *, int);
char *dir_realpath(pool *, const char *);
char *dir_canonical_path(pool *, const char *);
char *dir_best_path(pool *, const char *);
char *dir_virtual_chdir(pool *, const char *);

void add_exit_handler(void (*f)());
void remove_exit_handlers(void);
void run_exit_handlers(void);

void schedule(void (*f)(void *, void *, void *, void *), int, void *, void *,
  void *, void *);
void run_schedule(void);

int get_name_max(char *, int);

mode_t file_mode(char *);
int file_exists(char *);
int dir_exists(char *);
int exists(char *);
int access_check(char *, int);
char *make_arg_str(pool *, int, char **);

char *strip_end(char *, char *);
char *get_token(char **, char *);
char *safe_token(char **);
int check_shutmsg(time_t *, time_t *, time_t *, char *, size_t);

void pr_memscrub(void *, size_t);
char *sstrcat(char *, const char *, size_t);
char *sstrncpy(char *, const char *, size_t);
char *sreplace(pool *, char *, ...);

#endif /* __SUPPORT_H */
