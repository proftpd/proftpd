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
 * $Id: data.h,v 1.1 1998-10-18 02:24:41 flood Exp $
 */

#ifndef __DATACONN_H
#define __DATACONN_H

void data_init(char*,int);
void data_cleanup();
int data_open(char*,char*,int,unsigned long);
void data_close(int);
void data_abort(int,int);
int data_xfer(char*,int);

#endif /* __DATACONN_H */
