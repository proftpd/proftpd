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

/* Generic configuration and standard header file includes.
 * $Id: conf.h,v 1.21 2002-10-28 16:19:26 castaglia Exp $
 */

#ifndef __CONF_H
#define __CONF_H

#define _GNU_SOURCE

#include "version.h"
#include "config.h"

#include "default_paths.h"

/* This is no longer used, autoconf provides us with a top level
 * config.h
 */
/* #include "platform.h" */
#include "options.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <pwd.h>
#include <grp.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_LIMITS_H
# include <limits.h>
#endif

#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#ifdef HAVE_SYS_FILE_H
# include <sys/file.h>
#endif

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif

#ifndef WEXITSTATUS
# define WEXITSTATUS(stat_val) ((unsigned)(stat_val)>>8)
#endif
#ifndef WIFEXITED
# define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif

#ifdef HAVE_MEMORY_H
# include <memory.h>
#endif

#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif

#ifdef STDC_HEADERS
# include <string.h>
#else
# ifndef HAVE_STRCHR
#  define strchr index
#  define strrchr rindex
# endif
char *strchr(),*strrchr();
# ifndef HAVE_MEMCPY
#  define memcpy(d,s,n) bcopy((s),(d),(n))
#  define memmove(d,s,n) bcopy((s),(d),(n))
# endif
#endif

#ifdef HAVE_BSTRING_H
# include <bstring.h>
#endif

#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif

#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_TCP_H
# include <netinet/tcp.h>
#endif

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

#if (defined(HAVE_SHADOW_H) && defined(USESHADOW))
# include <shadow.h>
#endif

#ifndef TM_IN_SYS_TIME
# include <time.h>
#endif

#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif

#ifdef HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) ((dirent)->d_namlen)
# ifdef HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# ifdef HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# ifdef HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifdef HAVE_CTYPE_H
# include <ctype.h>
#endif

#ifdef HAVE_FNMATCH
# include <fnmatch.h>
#endif

#ifdef HAVE_UTMP_H
# include <utmp.h>
#endif

#ifdef HAVE_UTMPX_H
# include <utmpx.h>
#endif

/* Solaris 2.5 needs sys/termios.h for TIOCNOTTY.  Due to complications
 * with termio.h/termios.h, prefer to include termios.h.  If not found,
 * then try termio.h
 */

#ifdef HAVE_SYS_TERMIOS_H
# include <sys/termios.h>
#else
# ifdef HAVE_SYS_TERMIO_H
#  include <sys/termio.h>
# endif /* HAVE_SYS_TERMIO_H */
#endif /* HAVE_SYS_TERMIOS_H */

/* Solaris 2.5 seems to already have a typedef for 'timer_t', so
 * #define timer_t to something else as a workaround.
 */

#ifdef HAVE_TIMER_T
# define timer_t p_timer_t
#endif

/* AIX, when compiled using -D_NO_PROTO, lacks some prototypes without
 * which ProFTPD may do some funny (and not good) things.  Provide the
 * prototypes as necessary here.
 */

#if defined(AIX4) && defined(_NO_PROTO)
off_t lseek(int, off_t, int);
#endif

/* See if we have bcopy, if not define them to use the memcpy functions */

#ifndef HAVE_BCOPY
# define bcopy(s,d,n)	memcpy((d),(s),(n))
# define bzero(d,n)	memset((d),0,(n))
#endif

/* Solaris has __vsnprintf, but no vsnprintf */
#if ! defined(HAVE_VSNPRINTF) && defined(HAVE___VSNPRINTF)
# undef vsnprintf
# define vsnprintf	__vsnprintf
# define HAVE_VSNPRINTF 1
#endif

#if ! defined(HAVE_SNPRINTF) && defined(HAVE___SNPRINTF)
# undef snprintf
# define snprintf	__snprintf
# define HAVE_SNPRINTF
#endif

/* If we are BSD, make minor adjustments */

#if defined(BSD) && !defined(O_APPEND)
# define O_APPEND	F_APPEND
#endif

#ifndef O_NONBLOCK
#define	O_NONBLOCK	O_NDELAY
#endif

#ifndef O_NDELAY
#define	O_NDELAY	O_NONBLOCK
#endif

#if defined(HAVE_GETOPT) && defined(AIX3)
/* AIX 3.2.5 libc exports symbol optopt but is forgotten in includes */
extern int optopt;
#endif

/* GNU HURD (and maybe others) do not define MAXPATHLEN */
#ifndef MAXPATHLEN
#define MAXPATHLEN      1024
#endif

/* Necessary for alloca to work */
#if !defined(__alloca) && !defined(__GNU_LIBRARY__)
# ifdef __GNUC__
#  undef alloca
#  define alloca(n)		__builtin_alloca(n)
# else /* Not GCC */
#  ifdef HAVE_ALLOCA_H
#   include <alloca.h>
#  else /* No HAVE_ALLOCA_H */
#   ifndef _AIX
#    ifdef WINDOWS32
#     include <malloc.h>
#    else
extern char *alloca();
#    endif /* WINDOWS32 */
#   endif /* Not _AIX */
#  endif /* sparc or HAVE_ALLOCA_H */
# endif /* GCC */

# define __alloca	alloca

#endif

#if defined(_FILE_OFFSET_BITS) || defined(_LARGE_FILES) || SIZEOF_UNSIGNED_LONG_LONG == 8
# define PR_LU	"llu"
#else
# define PR_LU	"lu"
#endif

/********************************************************************
 * This is NOT the user configurable section.  Look in options.h
 * for tunable parameters.
 ********************************************************************/

#ifndef __PROFTPD_SUPPORT_LIBRARY

/* This section is only needed for modules and the core source files,
 * not for the support library.
 */

/* Generic typedefs */

typedef struct in_addr p_in_addr_t;

#include "pool.h"
#include "regexp.h"
#include "proftpd.h"
#include "support.h"
#include "sets.h"
#include "dirtree.h"
#include "netio.h"
#include "modules.h"
#include "timers.h"
#include "inet.h"
#include "ident.h"
#include "ftp.h"
#include "log.h"
#include "scoreboard.h"
#include "data.h"
#include "libsupp.h"
#include "fs.h"
#include "pr-syslog.h"

# ifdef HAVE_SETPASSENT
#  define setpwent()	setpassent(1)
# endif /* HAVE_SETPASSENT */

# ifdef HAVE_SETGROUPENT
#  define setgrent()	setgroupent(1)
# endif /* HAVE_SETGROUPENT */

#endif /* __PROFTPD_SUPPORT_LIBRARY */

#endif /* __CONF_H */
