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

/* Data connection management prototypes
 * $Id: data.h,v 1.10 2002-06-23 19:03:21 castaglia Exp $
 */

#ifndef __DATACONN_H
#define __DATACONN_H

void data_init(char *, int);
void data_cleanup(void);
int data_open(char *, char *, int, off_t);
void data_close(int);
void data_abort(int, int);
int data_xfer(char *, int);
void data_reset(void);

#ifdef HAVE_SENDFILE
typedef

#if defined(HAVE_LINUX_SENDFILE) || defined(HAVE_HPUX_SENDFILE)
ssize_t
#elif defined(HAVE_BSD_SENDFILE)
off_t
#else
#error "You have an unknown sendfile implementation."
#endif /* HAVE_LINUX_SENDFILE || HAVE_HPUX_SENDFILE */

pr_sendfile_t;

pr_sendfile_t data_sendfile(int retr_fd, off_t *offset, size_t count);
#endif /* HAVE_SENDFILE */

#endif /* __DATACONN_H */
