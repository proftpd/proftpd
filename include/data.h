/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
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

/* Data connection management prototypes
 * $Id: data.h,v 1.4 1999-10-05 05:37:21 macgyver Exp $
 */

#ifndef __DATACONN_H
#define __DATACONN_H

void data_init(char*,int);
void data_cleanup();
int data_open(char*,char*,int,unsigned long);
void data_close(int);
void data_abort(int,int);
int data_xfer(char*,int);
void data_reset();

#ifdef HAVE_SENDFILE
#if defined(HAVE_LINUX_SENDFILE)
ssize_t
#elif defined(HAVE_BSD_SENDFILE)
off_t
#else
#error "You have an unknown sendfile implementation."
#endif /* HAVE_LINUX_SENDFILE */
data_sendfile(int retr_fd, off_t *offset, size_t count);
#endif /* HAVE_SENDFILE */

#endif /* __DATACONN_H */
