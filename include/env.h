/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2007 The ProFTPD Project team
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

/* Environment handling
 * $Id: env.h,v 1.1 2007-01-12 01:30:55 castaglia Exp $
 */

#ifndef PR_ENV_H
#define PR_ENV_H

char *pr_env_get(pool *, const char *);
int pr_env_set(pool *, const char *, const char *);
int pr_env_unset(pool *, const char *);

#endif /* PR_ENV_H */
