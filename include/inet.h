/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001, 2002, 2003 The ProFTPD Project team
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

/* BSD socket manipulation tools.
 * $Id: inet.h,v 1.19 2003-08-06 22:03:32 castaglia Exp $
 */

#ifndef PR_INET_H
#define PR_INET_H

#include "conf.h"

#ifndef AF_INET6
# define AF_INET6	AF_UNSPEC
#endif /* AF_INET6 */

#ifndef INET_ADDRSTRLEN
# define INET_ADDRSTRLEN	16
#endif /* INET_ADDRSTRLEN */

#ifndef INET6_ADDRSTRLEN
# define INET6_ADDRSTRLEN	46
#endif /* INET6_ADDRSTRLEN */

#ifndef INADDR_ANY
# define INADDR_ANY	((unsigned long int) 0x00000000)
#endif /* INADDR_ANY */

#ifndef INADDR_LOOPBACK
# define INADDR_LOOPBACK	((unsigned long int) 0x7f000001)
#endif /* INADDR_LOOPBACK */

#ifndef INADDR_NONE
# define INADDR_NONE	0xffffffff
#endif /* INADDR_NONE */

#ifndef INPORT_ANY
# define INPORT_ANY	0
#endif

#ifndef IN6_IS_ADDR_UNSPECIFIED
# define IN6_IS_ADDR_UNSPECIFIED(a)	0
#endif

#ifndef IN6_IS_ADDR_LOOPBACK
# define IN6_IS_ADDR_LOOPBACK(a)	0
#endif

#ifndef IN6_IS_ADDR_MULTICAST
# define IN6_IS_ADDR_MULTICAST(a)	0
#endif

#ifndef IN6_IS_ADDR_LINKLOCAL
# define IN6_IS_ADDR_LINKLOCAL(a)	0
#endif

#ifndef IN6_IS_ADDR_SITELOCAL
# define IN6_IS_ADDR_SITELOCAL(a)	0
#endif

#ifndef IN6_IS_ADDR_V4MAPPED
# define IN6_IS_ADDR_V4MAPPED(a)	0
#endif

#ifndef IN6_IS_ADDR_V4COMPAT
# define IN6_IS_ADDR_V4COMPAT(a)	0
#endif

#ifndef IN6_ARE_ADDR_EQUAL
# define IN6_ARE_ADDR_EQUAL(a, b)	0
#endif

#ifndef U32BITS
# define U32BITS	0xffffffff
#endif

/* Much of the following is for handling IPv4-stack hosts. */

#ifndef HAVE_STRUCT_ADDRINFO
struct addrinfo {

  /* AI_PASSIVE, AI_CANONNAME */
  int ai_flags;

  /* AF/PF_xxx */
  int ai_family;

  /* SOCK_xxx */
  int ai_socktype;

  /* IPPROTO_xxx for IPv4/v6 */
  int ai_protocol;

  /* Length of ai_addr */
  int ai_addrlen;

  /* Canonical name for host */
  char *ai_canonname;

  /* Binary address */
  struct sockaddr *ai_addr;

  /* Next structure in the linked list */
  struct addrinfo *ai_next;
};
#endif /* HAVE_STRUCT_ADDRINFO */

/* These AI_ defines are for use by getaddrinfo(3). */

#if defined(HAVE_GETADDRINFO) && !defined(USE_GETADDRINFO)
# define pr_getaddrinfo    	getaddrinfo
# define pr_freeaddrinfo	freeaddrinfo
#else
int pr_getaddrinfo(const char *, const char *, const struct addrinfo *,
  struct addrinfo **);
void pr_freeaddrinfo(struct addrinfo *);
#endif /* HAVE_GETNAMEINFO and !USE_GETNAMEINFO */

/* Indicates that the socket is intended for bind()+listen(). */
#ifndef AI_PASSIVE
# define AI_PASSIVE	1
#endif /* AI_PASSIVE */

/* Return the canonical name. */
#ifndef AI_CANONNAME
# define AI_CANONNAME	2
#endif /* AI_CANONNAME */

/* These NI_ defines are for use by getnameinfo(3). */

#if defined(HAVE_GETNAMEINFO) && !defined(USE_GETNAMEINFO)
# define pr_getnameinfo    	getnameinfo
#else
int pr_getnameinfo(const struct sockaddr *, socklen_t, char *, size_t,
  char *, size_t, int);
#endif /* HAVE_GETNAMEINFO and !USE_GETNAMEINFO */

/* Max hostname length returned. */
#ifndef NI_MAXHOST
# define NI_MAXHOST	1025
#endif /* NI_MAXHOST */

/* Max service name length returned. */
#ifndef NI_MAXSERV
# define NI_MAXSERV	32
#endif /* NI_MAXSERV */

/* Do not return FQDNs. */
#ifndef NI_NOFQDN
# define NI_NOFQDN	1
#endif /* NI_NOFQDN */

/* Return the numeric form of the hostname. */
#ifndef NI_NUMERICHOST
# define NI_NUMERICHOST	2
#endif /* NI_NUMERICHOST */

/* Return an error if hostname is not found. */
#ifndef NI_NAMEREQD
# define NI_NAMEREQD	4
#endif /* NI_NAMEREQD */

/* Return the numeric form of the service name. */
#ifndef NI_NUMERICSERV
# define NI_NUMERICSERV	8
#endif /* NI_NUMERICSERV */

/* Datagram service for getservbyname(). */
#ifndef NI_DGRAM
# define NI_DGRAM	16
#endif /* NI_DGRAM */

/* The following EAI_ defines are for errors. */

/* Host address family not supported. */
#ifndef EAI_ADDRFAMILY
# define EAI_ADDRFAMILY	-1
#endif /* EAI_ADDRFAMILY */

/* Temporary failure in name resolution. */
#ifndef EAI_AGAIN
# define EAI_AGAIN	-2
#endif /* EAI_AGAIN */

/* Invalid value for ai_flags. */
#ifndef EAI_BADFLAGS
# define EAI_BADFLAGS	-3
#endif /* EAI_BADFLAGS */

/* Non-recoverable failure in name resolution. */
#ifndef EAI_FAIL
# define EAI_FAIL	-4
#endif /* EAI_FAIL */

/* ai_family not supported. */
#ifndef EAI_FAMILY
# define EAI_FAMILY	-5
#endif /* EAI_FAMILY */

/* Memory allocation failure. */
#ifndef EAI_MEMORY
# define EAI_MEMORY	-6
#endif /* EAI_MEMORY */

/* No address associated with host. */
#ifndef EAI_NODATA
# define EAI_NODATA	-7
#endif /* EAI_NODATA */

/* Host nor service not provided, or not known. */
#ifndef EAI_NONAME
# define EAI_NONAME	-8
#endif /* EAI_NONAME */

/* Service not supported for ai_socktype. */
#ifndef EAI_SERVICE
# define EAI_SERVICE	-9
#endif /* EAI_SERVICE */

/* ai_socktype not supported. */
#ifndef EAI_SOCKTYPE
# define EAI_SOCKTYPE	-10
#endif /* EAI_SOCKTYPE */

/* System error contained in errno. */
#ifndef EAI_SYSTEM
# define EAI_SYSTEM	-11
#endif /* EAI_SYSTEM */

/* Connection modes */
#define CM_NONE         0
#define CM_LISTEN       1
#define CM_OPEN         2
#define CM_ACCEPT       3
#define CM_CONNECT      4
#define CM_CLOSED       5
#define CM_ERROR        6

/* connection structure */
typedef struct conn_struc {
  struct conn_struc *next;
  pool *pool;
  int mode;				/* Current connection mode */
  int listen_fd;			/* Listening file descriptor */
  int rcvbuf,sndbuf;			/* Socket recv and send sizes */

  int xerrno;				/* Set to error if mode == CM_ERROR */

  array_header *iplist;
  int niplist;				/* IPs we are listening to */

  int rfd,wfd;				/* Read and write fds */
  pr_netio_stream_t *instrm, *outstrm;	/* Input/Output streams */

  /* Remote address of the connection. */
  pr_netaddr_t *remote_addr;

  /* Remote port of the connection. */
  int remote_port;

  /* Remote FQDN of the connection. */
  const char *remote_name;

  /* Local address of the connection. */
  pr_netaddr_t *local_addr;

  /* Local port of the connection. */
  int local_port;

} conn_t;


/* Prototypes */
void pr_init_inet(void);
void pr_inet_clear(void);
int pr_inet_reverse_dns(pool *, int);
int pr_inet_getservport(pool *, char *, char *);
char *pr_inet_validate(char *);
char *pr_inet_fqdn(pool *, const char *);
pr_netaddr_t *pr_inet_getaddr(pool *, const char *, array_header **);
conn_t *pr_inet_copy_connection(pool *, conn_t*);
conn_t *pr_inet_create_dup_connection(pool *, xaset_t *, int, pr_netaddr_t *);
conn_t *pr_inet_create_connection(pool *, xaset_t *, int, pr_netaddr_t *, int,
  int);
conn_t *pr_inet_create_connection_portrange(pool *, xaset_t *, pr_netaddr_t *,
  int, int);
void pr_inet_close(pool *, conn_t *);
void pr_inet_lingering_close(pool *, conn_t *, long);
int pr_inet_set_default_family(pool *, int);
int pr_inet_set_async(pool *, conn_t *);
int pr_inet_set_block(pool *, conn_t *);
int pr_inet_set_nonblock(pool *, conn_t *);
int pr_inet_set_proto_opts(pool *, conn_t *, int, int, int, int, int);
int pr_inet_set_socket_opts(pool *, conn_t *, int, int);
int pr_inet_listen(pool *, conn_t *, int);
int pr_inet_resetlisten(pool *, conn_t *);
int pr_inet_accept_nowait(pool *, conn_t *);
int pr_inet_connect(pool *, conn_t *, pr_netaddr_t *, int);
int pr_inet_connect_nowait(pool *, conn_t *, pr_netaddr_t *, int);
int pr_inet_get_conn_info(conn_t *, int);
conn_t *pr_inet_accept(pool *, conn_t *, conn_t *, int, int, unsigned char);
conn_t *pr_inet_associate(pool *, conn_t *, pr_netaddr_t *,
  pr_netio_stream_t *, pr_netio_stream_t *, int);
conn_t *pr_inet_openrw(pool *, conn_t *, pr_netaddr_t *, int, int, int,
  int, int);

#endif /* PR_INET_H */
