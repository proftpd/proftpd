/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (C) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
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

/* User configurable defaults and tunable parameters.
 *
 * $Id: options.h,v 1.3 2000-08-02 05:25:24 macgyver Exp $
 */

#ifndef __OPTIONS_H
#define __OPTIONS_H

/* Define the next option if your libc needs persistant /etc/passwd
 * and /etc/group functions.  Some libcs occasionally close these files
 * which can not be re-opened after a chroot().  Symptoms of this
 * include the inability to see user/group names when doing a 'ls -l' from
 * an anon. ftp login (you see only uid/gid numbers).
 */

/* If we have setpassent(), NEED_PERSISTENT_PASSWD is not enabled
 * by default.  This option controls the DEFAULT value of the
 * PersistentPasswd directive.  You can always override this in
 * the configuration file.
 */

#if ! (defined (HAVE_SETPASSENT) || defined (HAVE__PW_STAYOPEN))
# define NEED_PERSISTENT_PASSWD
#endif

/* Tunable parameters */

/* "Backlog" is the number of connections that can be received at one
 * burst before the kernel rejects.  This can be configured by the
 * "tcpBackLog" configuration directive, this value is just the default.
 */

#define TUNABLE_DEFAULT_BACKLOG 5

/* The next two define the default receive/send tcp windows (and
 * internal ProFTPD buffer sizes.  These can be configured per server
 * or per virtual-server via the tcpReceiveWindow and tcpSendWindow
 * directives.
 */

#define TUNABLE_DEFAULT_RWIN    8192
#define TUNABLE_DEFAULT_SWIN    8192

/* Default timeouts, if not explicitly configured via
 * the TimeoutLogin, TimeoutIdle, etc directives.
 */

#define TUNABLE_TIMEOUTLOGIN	300
#define TUNABLE_TIMEOUTIDLE	600
#define TUNABLE_TIMEOUTNOXFER	300
#define TUNABLE_TIMEOUTIDENT	10
#define TUNABLE_TIMEOUTSTALLED	3600

/* Number of bytes in a new memory pool.  During file transfers,
 * quite a few pools can be created, which eat up a lot of memory.
 * Tune this if ProFTPD seems too memory hungry (warning! too low
 * can negatively impact performance)
 */

#define TUNABLE_NEW_POOL_SIZE   512

/* Loopback network, this should generally not need to be changed,
 * although you can set a specific address by setting it to say
 * "127.0.0.1" and the netmask to "255.255.255.255".
 */

#define LOOPBACK_NET            "127.0.0.0"
#define LOOPBACK_MASK           "255.255.255.0"

#endif /* __OPTIONS_H */
