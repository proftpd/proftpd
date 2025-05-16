/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2005-2025 The ProFTPD Project team
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
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* Compatibility macros */

#ifndef PR_COMPAT_H
#define PR_COMPAT_H

/* Legacy redefines, for compatibility (for a while). */

/* The following macros first appeared in 1.3.6rc2. */
#define _sql_make_cmd			sql_make_cmd

/* the following macro used to be governed by Autoconf, but was hardcoded
 * (per autoupdate recommendations) in 1.3.10rc1.
 */
#define RETSIGTYPE			void

#endif /* PR_COMPAT_H */
