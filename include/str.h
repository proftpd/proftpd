/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2008 The ProFTPD Project team
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

/* String manipulation functions
 * $Id: str.h,v 1.1 2008-02-11 04:37:49 castaglia Exp $
 */

#ifndef PR_STR_H
#define PR_STR_H

char *sstrcat(char *, const char *, size_t);
char *sreplace(pool *, char *, ...);

char *pdircat(pool *, ...);
char *pstrcat(pool *, ...);
char *pstrdup(pool *, const char *);
char *pstrndup(pool *, const char *, size_t);

#endif /* PR_STR_H */
