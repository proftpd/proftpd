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
 * $Id: regexp.h,v 1.6 2011-02-25 20:15:25 castaglia Exp $
 */

#ifndef PR_REGEXP_H
#define PR_REGEXP_H

#ifdef PR_USE_PCRE
# include <pcreposix.h>
#else
# ifdef HAVE_REGEX_H
# include <regex.h>
# endif /* HAVE_REGEX_H */
#endif /* !PR_USE_PCRE */

regex_t *pr_regexp_alloc(void);
void pr_regexp_free(regex_t *);

int pr_regexp_compile(regex_t *, const char *, int);
size_t pr_regexp_error(int, const regex_t *, char *, size_t);
int pr_regexp_exec(const regex_t *, const char *, size_t, regmatch_t *, int);

/* For internal use only */
void init_regexp(void);

#endif /* PR_REGEXP_H */
