/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2001-2011 The ProFTPD Project team
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
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* Regular expression management
 * $Id: regexp.h,v 1.7 2011-03-03 21:38:54 castaglia Exp $
 */

#ifndef PR_REGEXP_H
#define PR_REGEXP_H

/* We define our own wrapper struct, pr_regex_t, in order to abstract the
 * differences between POSIX regexes and PCRE regexes from the calling
 * code.
 */

#ifdef PR_USE_PCRE
# include <pcre.h>
# include <pcreposix.h>
# define PR_USE_REGEX		1
#else
# ifdef HAVE_REGEX_H
# include <regex.h>
#   ifdef HAVE_REGCOMP
#     define PR_USE_REGEX	1
#   endif /* HAVE_REGCOMP */
# endif /* HAVE_REGEX_H */
#endif /* !PR_USE_PCRE */

typedef struct regexp_rec pr_regex_t;

pr_regex_t *pr_regexp_alloc(module *m);
void pr_regexp_free(module *m, pr_regex_t *pre);

/* Callers wishing to explicitly use POSIX regular expressions, regardless
 * of PCRE support, should use this function.
 */
int pr_regexp_compile_posix(pr_regex_t *pre, const char *pattern, int flags);

/* If PCRE support is enabled, the given pattern will be compiled as a
 * PCRE regular expression, otherwise it will be compiled as a POSIX
 * regular expression.
 */
int pr_regexp_compile(pr_regex_t *pre, const char *pattern, int flags);

size_t pr_regexp_error(int res, const pr_regex_t *pre, char *buf, size_t bufsz);

/* Returns the original pattern used to compile the regular expression, if
 * present.
 */
const char *pr_regexp_get_pattern(const pr_regex_t *pre);

int pr_regexp_exec(pr_regex_t *pre, const char *str, size_t nmatches,
  regmatch_t *matches, int flags, unsigned long match_limit,
  unsigned long match_limit_recursion);

/* Used to set default limits on the matching, if no such limits are
 * explicitly provided by the calling code.  These limits can be set e.g.
 * for the entire vhost/daemon.
 *
 * NOTE: The match limits are only properly honored when PCRE support is
 * enabled.
 */
int pr_regexp_set_limits(unsigned long match_limit,
  unsigned long match_limit_recursion);

/* For internal use only */
void init_regexp(void);

#endif /* PR_REGEXP_H */
