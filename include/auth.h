/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2004 The ProFTPD Project team
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
 * As a special exemption, the ProFTPD Project and other respective copyright
 * holders give permission to link this program with OpenSSL, and distribute
 * the resulting executable, without including the source code for OpenSSL in
 * the source distribution.
 */

/* ProFTPD Auth API
 *
 * $Id: auth.h,v 1.1 2004-09-26 20:11:59 castaglia Exp $
 */

#ifndef PR_AUTH_H
#define PR_AUTH_H

/* Possible return codes for auth handlers
 */

/* Account authenticated by RFC2228 security data exchange */
#define PR_AUTH_RFC2228_OK		2

/* Account authenticated normally */
#define PR_AUTH_OK			0

/* Error occurred in auth handler */
#define PR_AUTH_ERROR			-1

/* Account does not exist */
#define PR_AUTH_NOPWD			-2

/* Password mismatch */
#define PR_AUTH_BADPWD			-3

/* Password hasn't been changed recently enough */
#define PR_AUTH_AGEPWD			-4

/* Account has been disabled */
#define PR_AUTH_DISABLEDPWD		-5

void pr_auth_setpwent(pool *);
void pr_auth_endpwent(pool *);
void pr_auth_setgrent(pool *);
void pr_auth_endgrent(pool *);
struct passwd *pr_auth_getpwent(pool *);
struct group *pr_auth_getgrent(pool *);
struct passwd *pr_auth_getpwnam(pool *, const char *);
struct passwd *pr_auth_getpwuid(pool *, uid_t);
struct group *pr_auth_getgrnam(pool *, const char *);
struct group *pr_auth_getgrgid(pool *, gid_t);
int pr_auth_authenticate(pool *, const char *, const char *);
int pr_auth_check(pool *, const char *, const char *, const char *);
const char *pr_auth_uid2name(pool *, uid_t);
const char *pr_auth_gid2name(pool *, gid_t);
uid_t pr_auth_name2uid(pool *, const char *);
gid_t pr_auth_name2gid(pool *, const char *);
int pr_auth_getgroups(pool *, const char *, array_header **, array_header **);

/* Legacy redefines, for compatibility (for now). */
#define auth_setpwent		pr_auth_setpwent
#define auth_endpwent		pr_auth_endpwent
#define auth_setgrent		pr_auth_setgrent
#define auth_endgrent		pr_auth_endgrent
#define auth_getpwent		pr_auth_getpwent
#define auth_getgrent		pr_auth_getgrent
#define auth_getpwnam		pr_auth_getpwnam
#define auth_getpwuid		pr_auth_getpwuid
#define auth_getgrnam		pr_auth_getgrnam
#define auth_getgrgid		pr_auth_getgrgid
#define auth_authenticate	pr_auth_authenticate
#define auth_check		pr_auth_check
#define auth_uid2name		pr_auth_uid2name
#define auth_gid2name		pr_auth_gid2name
#define auth_name2uid		pr_auth_name2uid
#define auth_name2gid		pr_auth_name2gid
#define auth_getgroups		pr_auth_getgroups

/* For internal use only. */
int set_groups(pool *, gid_t, array_header *);

#endif /* PR_MODULES_H */
