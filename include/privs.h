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

/* $Id: privs.h,v 1.1 1998-10-18 02:24:41 flood Exp $
 */

#ifndef __PRIVS_H
#define __PRIVS_H

/* Macros for manipulating saved, real and effective uid for easy 
 * switching from/to root.
 *
 * Note: In version 1.1.5, all of this changed.  We USED to play games
 * with the saved-uid/gid _and_ setreuid()/setregid(), however this
 * appears to be slightly non-portable (i.e. w/ BSDs).  However, since
 * POSIX.1 saved-uids are pretty much useless without setre* (in the
 * case of root), so we now use basic uid swapping if we have seteuid(),
 * and setreuid() swapping if not.
 */

/* Porters, please put the most reasonable and secure method of
 * doing this in here:
 */

#if !defined(HAVE_SETEUID)
 
/* Use setreuid() to perform uid swapping.
 */

#define PRIVS_SETUP(u,g)	{ if(getuid()) { \
				  session.ouid = session.uid = (int)getuid(); \
				  session.gid = (int)getgid(); \
                                  setgid(session.gid); \
                                  setreuid(session.uid,session.uid); \
				} else {  \
                                  session.ouid = (int)getuid(); \
                                  session.uid = (u); session.gid = (g); \
                                  setgid(session.gid); \
				  setreuid(0,session.uid); \
				} }

#define PRIVS_ROOT		if(!session.disable_id_switching) \
				{ setreuid(session.uid,0); }

#define PRIVS_RELINQUISH	if(!session.disable_id_switching) \
				{ setreuid(0,session.uid); }

#define PRIVS_REVOKE		{ setreuid(0,0); \
				  setgid(session.gid); \
                                  setuid(session.uid); }
#else /* HAVE_SETEUID */

/* Set the saved uid/gid using setuid/seteuid().  setreuid() is
 * no longer used as it is considered obsolete on many systems.
 * gids are also no longer swapped, as they are unnecessary.
 * If run as root, proftpd now normally runs as:
 *   real user            : root
 *   effective user       : <user>
 *   saved user           : root
 *   real/eff/saved group : <group>
 */

#define PRIVS_SETUP(u,g)	{ if(getuid()) { \
                                  session.ouid = session.uid = (int)getuid(); \
                                  session.gid = (int)getgid(); \
                                  setgid(session.gid); \
                                  setuid(session.uid); \
				  seteuid(session.uid); \
                                } else { \
				  session.ouid = (int)getuid(); \
                                  session.uid = (u); session.gid = (g); \
                                  setuid(0); \
                                  setgid((g)); seteuid((u)); \
                                } }


/* Switch back to root */

#define PRIVS_ROOT		if(!session.disable_id_switching) \
				{ seteuid(0); }

/* Relinquish privs granted by PRIVS_ROOT */

#define PRIVS_RELINQUISH	if(!session.disable_id_switching) \
				{ seteuid(session.uid); }

/* Revoke all privs */

#define PRIVS_REVOKE		{ seteuid(0); \
				  setgid(session.gid); \
				  setuid(session.uid); }

#endif /* HAVE_SETEUID */

#endif /* __PRIVS_H */
