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
 *
 * As a special exemption, Public Flood Software/MacGyver aka Habeeb J. Dihu
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

/*
 * Inet support functions, many wrappers for netdb functions
 */


#include "conf.h"
#include "privs.h"

#if 0
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#include <netinet/ip.h>
#include <netinet/tcp.h>
#endif

#define CHECK_INET_POOL	 if(!inet_pool) _create_inet_pool()

extern server_rec *main_server;

/* A private work pool for all inet_ functions to use
 */

static pool *inet_pool = NULL;
static int tcp_proto = 6;		/* Generally, this is "tcp" */
static int reverse_dns = 1;		/* Use reverse dns? */
static int inet_errno = 0;		/* Holds errno */

/* Cleanup for inet_pool
 */

static void _inet_pool_cleanup(void *ignore)
{
  inet_pool = NULL;
}

/* Create the private inet pool
 */

static void _create_inet_pool(void)
{
  inet_pool = make_sub_pool(permanent_pool);

  /* Necessary to register a cleanup, in case the whole process
   * execs and we lose our pool.
   */

  register_cleanup(inet_pool,NULL,_inet_pool_cleanup,_inet_pool_cleanup);
}

/*
 * Called by others after running a number of inet_ functions in order
 * to free up memory.
 */

void clear_inet_pool(void)
{
  if(!inet_pool)		/* Sanity check */
    return;

  kill_cleanup(inet_pool,NULL,_inet_pool_cleanup);
  destroy_pool(inet_pool);
  inet_pool = NULL;
}


/* All inet_ interface functions take a pool as the first arg, which
 * is where any returned allocated memory is taken from.  For purposes
 * of uniformity the pool is included in all calls, even those that
 * don't need to return allocated memory.
 */

/* Enable or disable reverse dns lookups */
int inet_reverse_dns(pool *pool, int enable)
{
  int old;

  old = reverse_dns;
  reverse_dns = enable;
  return old;
}

/* Find a service and return it's port number
 */

int inet_getservport(pool *pool, char *serv, char *proto)
{
  struct servent *servent;

  servent = getservbyname(serv,proto);

  /* getservbyname returns the port in network byte order */

  return (servent ? ntohs(servent->s_port) : -1);
}

/* Validate anything returned from the 'outside', since it's untrusted
 * information.
 */
char *inet_validate(char *buf) {
  char *p;
  
  /* Validate anything returned from a DNS.
   */
  for(p = buf; p && *p; p++) {
    /* Per RFC requirements, these are all that are valid from a DNS.
     */
    if(!isalnum(*p) && *p != '.' && *p != '-') {
      /* We set it to _ because we know that's an invalid, yet safe, option
       * for a DNS entry.
       */
      *p = '_';
    }
  }
  
  return buf;
}

/* Return the hostname (wrapper for gethostname(), except returns FQDN)
 */
char *inet_gethostname(pool *pool)
{
  char buf[256] = {'\0'};
  struct hostent *host;

  if(gethostname(buf,sizeof(buf)-1) != -1) {
    buf[sizeof(buf)-1] = '\0';
    host = gethostbyname(buf);
    if(host)
      return inet_validate(pstrdup(pool,host->h_name));

    return inet_validate(pstrdup(pool,buf));
  }

  return NULL;
}

/* Return the FQDN of an address
 */

char *inet_fqdn(pool *pool, const char *addr)
{
  struct hostent *host;

  if((host = gethostbyname(addr)) != NULL)
    return inet_validate(pstrdup(pool,host->h_name));

  return NULL;
}

/* DNS/hosts lookup for a particular name
 */
p_in_addr_t *inet_getaddr(pool *pool, char *name)
{
  struct hostent *host;
  p_in_addr_t *res;

  res = (p_in_addr_t*)pcalloc(pool,sizeof(p_in_addr_t));

  /* Try dotted quad notation first */
#ifdef HAVE_INET_ATON
  if(inet_aton(name,res))
    return res;
#else
  /* This is a bit unclean, because inet_addr() is obsolete, and
   * returns -1 (255.255.255.255) if the input is invalid.  The caller
   * _might_ just be trying to resolve "255.255.255.255", in which case
   * this entire function will fail.  Hopefully, you have inet_aton().
   * <grin>
   */
  if((res->s_addr = inet_addr(name)) != -1)
    return res;
#endif

  host = gethostbyname(name);
  if(host) {
    memcpy(res, host->h_addr_list[0], sizeof(p_in_addr_t));
    return res;
  }
    

  return NULL;
}

/* Wrapper for inet_ntoa, except stores result in dynamically allocated
 * memory.
 */

char *inet_ascii(pool *pool, p_in_addr_t *addr)
{
  char *res = NULL;

  if((res = inet_ntoa(*addr)) != NULL)
    res = pstrdup(pool,res);

  return res;
}

/* Given an ip addresses, return the FQDN */
char *inet_getname(pool *pool, p_in_addr_t *addr)
{
  char *res = NULL;
  char **checkaddr;
  struct hostent *hptr_rev = NULL, *hptr_forw = NULL;
  static char *res_cache = NULL;
  static p_in_addr_t *addr_cache = NULL;

  if(reverse_dns) {
    if(res_cache && addr_cache && addr_cache->s_addr == addr->s_addr) {
      res = pstrdup(pool, res_cache);
      return inet_validate(res);
    }
    
    if((hptr_rev = gethostbyaddr((const char *)addr,
                                 sizeof(p_in_addr_t), AF_INET)) != NULL) {
      if((hptr_forw = gethostbyname(hptr_rev->h_name)) != NULL) {
        for(checkaddr = hptr_forw->h_addr_list; *checkaddr; ++checkaddr) {
          if(((p_in_addr_t*)(*checkaddr))->s_addr == addr->s_addr) {
            res = pstrdup(pool, hptr_rev->h_name);
            break;
          }
        }
      }
    }
  }
  
  if(!res)
    res = pstrdup(pool, inet_ntoa(*addr));
 
  if(reverse_dns) {
    /* cache the result */
    if(!addr_cache)
      addr_cache = malloc(sizeof(p_in_addr_t));

    if(addr_cache)
      memcpy(addr_cache, addr, sizeof(p_in_addr_t));

    if(res_cache)
      free(res_cache);

    res_cache = strdup(res);
  }
  
  return inet_validate(res);
}

static void _conn_cleanup(void *cv) { 
  conn_t *c = (conn_t*)cv;

  if(c->inf)
    io_close(c->inf);
  if(c->outf && c->outf != c->inf)
    io_close(c->outf);

  if(c->listen_fd != -1)
    close(c->listen_fd);

  if(c->rfd != -1)
    close(c->rfd);

  if(c->wfd != -1)
    close(c->wfd);
}

/*
 * Copy a connection structure, also creates a sub pool for the new
 * connection.
 */

conn_t *inet_copy_connection(pool *p, conn_t *c)
{
  conn_t *res;
  pool *subpool;

  subpool = make_sub_pool(p);
  res = (conn_t*)palloc(subpool,sizeof(conn_t));

  memcpy(res,c,sizeof(conn_t));
  res->pool = subpool;
  res->inf = res->outf = NULL;

  if(c->local_ipaddr) {
    res->local_ipaddr = (p_in_addr_t*)palloc(res->pool,sizeof(p_in_addr_t));
    *res->local_ipaddr = *c->local_ipaddr;
  }

  if(c->remote_ipaddr) {
    res->remote_ipaddr = (p_in_addr_t*)palloc(res->pool,sizeof(p_in_addr_t));
    *res->remote_ipaddr = *c->remote_ipaddr;
  }

  if(c->remote_name)
    res->remote_name = pstrdup(res->pool,c->remote_name);

  if(c->iplist)
    res->iplist = copy_array(subpool,c->iplist);

  register_cleanup(res->pool,(void*)res,_conn_cleanup,_conn_cleanup);
  return res;
}

#if 0 /* This code is unused right now.  -- MacGyver */

/* Pre-bind a socket to a port, use to bind to a low-numbered port
 */
int inet_prebind_socket(pool *p, p_in_addr_t *bind_addr, int port)
{
  int save_errno,res = -1,s,on = 1,tries;
  struct sockaddr_in servaddr;

#ifdef SOLARIS2
  if(port != INPORT_ANY && port < 1024) {
    block_signals();
    PRIVS_ROOT
  }
#endif
  s = socket(AF_INET, SOCK_STREAM, 0);
#ifdef SOLARIS2
  if(port != INPORT_ANY && port < 1024) {
    PRIVS_RELINQUISH
    unblock_signals();
  }
#endif

  if(s < 0)
    return -1;

  setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(void*)&on,sizeof(on));
  servaddr.sin_family = AF_INET;
  if(!bind_addr)
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  else
    servaddr.sin_addr = *bind_addr;

  servaddr.sin_port = htons(port);
  
  if(port != INPORT_ANY && port < 1024) {
    block_signals();
    PRIVS_ROOT
  }

  for(tries = 1; tries < 10; tries++) {
    if(bind(s,(struct sockaddr *)&servaddr,sizeof(servaddr)) >= 0)
    { res = s; break; }
    if(errno != EADDRINUSE) break;

    if(port != INPORT_ANY && port < 1024) {
      PRIVS_RELINQUISH
      unblock_signals();
    }
    timer_sleep(tries);
    if(port != INPORT_ANY && port < 1024) {
      block_signals();
      PRIVS_ROOT
    }
  }

  save_errno = errno;

  if(port != INPORT_ANY && port < 1024) {
    PRIVS_RELINQUISH
    unblock_signals();
  }

  errno = save_errno;
  return res;
}
#endif /* Unused code. -- MacGyver */

/* Initialize a new connection record, also creates a new subpool
 * just for the new connection.
 */
static conn_t *inet_initialize_connection(pool *p, xaset_t *servers, int fd,
					  p_in_addr_t *bind_addr, int port,
					  int retry_bind, int reporting)
{
  pool *subpool;
  conn_t *c;
  array_header *tmp;
  server_rec *s;
  struct sockaddr_in servaddr;
  int i,res = 0, len, one = 1, hold_errno;
  
  CHECK_INET_POOL;
  
  if((!servers || !servers->xas_list) && !main_server)
    return NULL;
  
  /* Build the accept IPs dynamically using the inet work pool,
   * once built, move into the conn struc.
   */
  tmp = make_array(inet_pool, 5, sizeof(p_in_addr_t));
  subpool = make_sub_pool(p);
  c = (conn_t *) pcalloc(subpool, sizeof(conn_t));
  c->pool = subpool;
  
  if(servers && servers->xas_list) {
    for(s = (server_rec *) servers->xas_list; s; s = s->next)
      if(s->ipaddr)
        *((p_in_addr_t *) push_array(tmp)) = *s->ipaddr;
  } else {
    *((p_in_addr_t *) push_array(tmp)) = *main_server->ipaddr;
  }
  
  c->local_port = port;
  c->iplist = copy_array(c->pool, tmp);
  c->niplist = c->iplist->nelts;
  c->rfd = c->wfd = -1;
  
  /* If fd == -1, there is no currently open socket, so create one.
   */
  if(fd == -1) {
    
    /* Certain versions of Solaris apparently require us to be root
     * in order to create a socket inside a chroot ??
     */

    /* FreeBSD 2.2.6 (possibly other versions as well), has a security
     * "feature" which disallows SO_REUSEADDR from working if the socket
     * owners don't match.  The easiest thing to do is simply make sure
     * the socket is created as root.
     *
     * Note: this "feature" seems to apply to ALL bsds -jss 2/28/2001
     */
    
#if defined(SOLARIS2) || defined(FREEBSD2) || defined(FREEBSD3) || \
    defined(FREEBSD4) || defined(__OpenBSD__) || defined(__NetBSD__) || \
    defined(SYSV4_2MP)
# ifdef SOLARIS2
    if(port != INPORT_ANY && port < 1024) {
# endif
      block_signals();
      PRIVS_ROOT
# ifdef SOLARIS2
    }
# endif
#endif

    fd = socket(AF_INET, SOCK_STREAM, tcp_proto);

#if defined(SOLARIS2) || defined(FREEBSD2) || defined(FREEBSD3) || \
    defined(FREEBSD4) || defined(__OpenBSD__) || defined(__NetBSD__) || \
    defined(SYSV4_2MP)
# ifdef SOLARIS2
    if(port != INPORT_ANY && port < 1024) {
# endif
      PRIVS_RELINQUISH
      unblock_signals();
# ifdef SOLARIS2
    }
# endif
#endif
    
    if(fd == -1) {
      /* on failure, destroy the connection and return NULL
       */

      inet_errno = errno;
      if(reporting)
        log_pri(LOG_ERR,"socket() failed in inet_initialize_connection(): %s",
			strerror(inet_errno));
      destroy_pool(c->pool);
      return NULL;
    }
    
    /* Allow address reuse.
     */
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *) &one, sizeof(one));
    
    memset(&servaddr, 0, sizeof(servaddr));
    
    servaddr.sin_family = AF_INET;
    
    if(bind_addr)
      memcpy(&servaddr.sin_addr, bind_addr, sizeof(servaddr.sin_addr));
    else
      servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    servaddr.sin_port = htons(port);
    
    if(port != INPORT_ANY && port < 1024) {
      block_signals();
      PRIVS_ROOT
    }
    
    /* According to one expert, the very nature of the FTP protocol,
     * and it's multiple data-connections creates problems with
     * "rapid-fire" connections (transfering lots of files) causing
     * an eventual "Address already in use" error.  As a result, this
     * nasty kludge retries ten times (once per second) if the
     * port being bound to is INPORT_ANY)
     */
    for(i = 10; i; i--) {
      res = bind(fd, (struct sockaddr *) &servaddr, sizeof(servaddr));
      hold_errno = errno;

      if(res == -1 && errno == EINTR) {
	i++;
	continue;
      }

      if(res != -1 || errno != EADDRINUSE ||
	 (port != INPORT_ANY && !retry_bind))
        break;
      
      if(port != INPORT_ANY && port < 1024) {
        PRIVS_RELINQUISH
        unblock_signals();
      }
      
      timer_sleep(1);
      
      if(port != INPORT_ANY && port < 1024) {
        block_signals();
        PRIVS_ROOT
      }
    }
    
    if(res == -1) {
      if(port != INPORT_ANY && port < 1024) {
        PRIVS_RELINQUISH
        unblock_signals();
      }

      if(reporting) {
        log_pri(LOG_ERR, "Failed binding to %s, port %d: %s",
                inet_ntoa(servaddr.sin_addr), port, strerror(hold_errno));
        log_pri(LOG_ERR, "Check the ServerType directive "
	                 "to ensure you are configured correctly.");
      }
      
      inet_errno = hold_errno;
      destroy_pool(c->pool);
      close(fd);
      return NULL;
    }
    
    if(port != INPORT_ANY && port < 1024) {
      PRIVS_RELINQUISH
      unblock_signals();
    }
    
    /* We use getsockname here because the caller might be binding
     * to INPORT_ANY (0), in which case our port number will be
     * dynamic.
     */
    len = sizeof(servaddr);
    if(fd >= 0 && getsockname(fd, (struct sockaddr *) &servaddr, &len) != -1) {
      if(!c->local_ipaddr)
        c->local_ipaddr = (p_in_addr_t *) pcalloc(c->pool,
						  sizeof(p_in_addr_t));
      *c->local_ipaddr = servaddr.sin_addr;
      c->local_port = ntohs(servaddr.sin_port);
    }
  }
  
  c->listen_fd = fd;
  register_cleanup(c->pool, (void *) c, _conn_cleanup, _conn_cleanup);
  
  return c;
}

conn_t *inet_create_connection(pool *p, xaset_t *servers, int fd,
                               p_in_addr_t *bind_addr, int port,
			       int retry_bind)
{
  conn_t *c = inet_initialize_connection(p, servers, fd, bind_addr,
		  		         port, retry_bind, TRUE);

  /* This code is somewhat of a kludge, because error handling should
   * NOT occur in inet.c, it should be handled by the caller.
   */
  
  if(!c)
    end_login(1);

  return c;
}

/* Attempt to create a connection bound to a given port range, returns NULL
 * if unable to bind to any port in the range.
 */

conn_t *inet_create_connection_portrange(pool *p, xaset_t *servers,
				p_in_addr_t *bind_addr, int low_port, int high_port)
{
  int range_len, index;
  int *range, *ports;
  int attempt, random_index;
  conn_t *c = NULL;

  /* Make sure the temporary inet work pool exists. */
  CHECK_INET_POOL;
  
  range_len = high_port - low_port + 1;
  range = (int*)pcalloc(inet_pool, (range_len*sizeof(int)));
  ports = (int*)pcalloc(inet_pool, (range_len*sizeof(int)));
  
  index = range_len;
  while(index--)
    range[index] = low_port + index;
  
  for(attempt = 3; attempt > 0 && !c; attempt--) {
    for(index = range_len - 1; index >= 0 && !c; index--) {

      /* If this is the first attempt through the range, randomize
       * the order of the port numbers used.
       */

      if(attempt == 3) {
	/* obtain a random index into the port array range
	 */
	random_index = (int) ((1.0 * index * rand()) / (RAND_MAX+1.0));

	/* copy the port at that index into the array from which port
	 * numbers will be selected when calling inet_initialize_connection()
	 */
	ports[index] = range[random_index];

	/* Move non-selected numbers down so that the next randomly chosen
	 * port will be from the range of as-yet untried ports
	 */

	while(++random_index < index)
	  range[random_index-1] = range[random_index];
      }

      c = inet_initialize_connection(p, servers, -1, bind_addr,
				     ports[index], FALSE, FALSE);
    
      if(!c && inet_errno != EADDRINUSE) {
        log_pri(LOG_ERR,"inet_initialize_connection(): %s",
  		        strerror(inet_errno));
        end_login(1);
      }
    }
  }

  return c;
}

void inet_close(pool *pool, conn_t *c)
{
  /* It's not necessary to close the fds or schedule IOFILEs for
   * removal, because the creator of the connection (either
   * inet_create_connection() or inet_copy_connection() will
   * have registered a pool cleanup handler (_conn_cleanup())
   * which will do all this for us.  Simply destroy the pool
   * and all the dirty work gets done. :-)
   */

  destroy_pool(c->pool);
}

int inet_set_proto_options(pool *pool, conn_t *c,
			int nodelay,
			int lowdelay,
			int throughput,
			int nopush)
{
  int tos = 0;

#ifdef TCP_NODELAY
  if(get_param_int(main_server->conf,"tcpNoDelay",FALSE) != 0) {
    if(c->wfd != -1)
      setsockopt(c->wfd,IPPROTO_TCP,TCP_NODELAY,(void*)&nodelay,sizeof(nodelay));
    if(c->rfd != -1)
      setsockopt(c->rfd,IPPROTO_TCP,TCP_NODELAY,(void*)&nodelay,sizeof(nodelay));
  }
#endif

#ifdef IPTOS_LOWDELAY
  if(lowdelay)
    tos = IPTOS_LOWDELAY;
#endif

#ifdef IPTOS_THROUGHPUT
  if(throughput)
    tos |= IPTOS_THROUGHPUT;
#endif

#ifdef IP_TOS
  if(c->wfd != -1)
    setsockopt(c->wfd,IPPROTO_IP,IP_TOS,(void*)&tos,sizeof(tos));
  if(c->rfd != -1)
    setsockopt(c->rfd,IPPROTO_IP,IP_TOS,(void*)&tos,sizeof(tos));
#endif

#ifdef TCP_NOPUSH
  if(c->wfd != -1)
    setsockopt(c->wfd,IPPROTO_TCP,TCP_NOPUSH,(void*)&nopush,sizeof(nopush));
  if(c->rfd != -1)
    setsockopt(c->rfd,IPPROTO_TCP,TCP_NOPUSH,(void*)&nopush,sizeof(nopush));
#endif

  return 0;
}

/*
 * Set socket options on a connection. If set_buffers is non-zero the
 * socket snd/rcv buffers will be set according the the server
 * information.
 */

int inet_setoptions(pool *pool, conn_t *c, int rcvbuf, int sndbuf)
{
  int no_keep_alive = 0;
  struct linger li;
  int len,crcvbuf,csndbuf;

  li.l_onoff = 0;
  li.l_linger = 0;

  if(c->wfd != -1) {
    setsockopt(c->wfd,SOL_SOCKET,SO_KEEPALIVE,(void*)&no_keep_alive,sizeof(int));
    setsockopt(c->wfd,SOL_SOCKET,SO_LINGER,(void*)&li,sizeof(li));

    /* Linux and "most" newer networking OSes probably use a highly
     * adaptive window size system, which generally wouldn't require
     * user-space modification at all.  Thus, check the current
     * sndbuf and rcvbuf sizes before changing them, and only change
     * them if we are making them larger than their current size.
     */

    len = sizeof(csndbuf);
    getsockopt(c->wfd,SOL_SOCKET,SO_SNDBUF,(void*)&csndbuf,&len);

    if(sndbuf && sndbuf > csndbuf)
      setsockopt(c->wfd,SOL_SOCKET,SO_SNDBUF,(void*)&sndbuf,sizeof(sndbuf));

    c->sndbuf = (sndbuf ? sndbuf : csndbuf);
  }

  if(c->rfd != -1) {
    setsockopt(c->rfd,SOL_SOCKET,SO_KEEPALIVE,(void*)&no_keep_alive,sizeof(int));
    setsockopt(c->wfd,SOL_SOCKET,SO_LINGER,(void*)&li,sizeof(li));

    len = sizeof(crcvbuf);
    getsockopt(c->rfd,SOL_SOCKET,SO_RCVBUF,(void*)&crcvbuf,&len);

    if(rcvbuf && rcvbuf > crcvbuf)
      setsockopt(c->rfd,SOL_SOCKET,SO_RCVBUF,(void*)&rcvbuf,sizeof(rcvbuf));

    c->rcvbuf = (rcvbuf ? rcvbuf : crcvbuf);
  }
 
  return 0;
}

#ifdef SO_OOBINLINE
static
void _set_oobinline(int fd)
{
  int on = 1;
  if(fd != -1)
    setsockopt(fd, SOL_SOCKET, SO_OOBINLINE, (void*)&on, sizeof(on));
}
#endif

#ifdef F_SETOWN
static
void _set_owner(int fd)
{ 
  if(fd != -1)
    fcntl(fd, F_SETOWN, getpid());
}
#endif

/* Put a socket in async mode (so SIGURG is raised on OOB)
 */

int inet_setasync(pool *pool, conn_t *c)
{

#ifdef SO_OOBINLINE
  _set_oobinline(c->listen_fd);
  _set_oobinline(c->rfd);
  _set_oobinline(c->wfd);
#endif

#ifdef F_SETOWN
  _set_owner(c->listen_fd);
  _set_owner(c->rfd);
  _set_owner(c->wfd);
#endif

  return 0;
}

/*
 * Put a socket in nonblocking mode.
 */

int inet_setnonblock(pool *pool, conn_t *c)
{
  int flags;
  int res = -1;

  errno = EBADF;		/* Default */

  if(c->mode == CM_LISTEN) {
    flags = fcntl(c->listen_fd,F_GETFL);
    res = fcntl(c->listen_fd,F_SETFL,flags | O_NONBLOCK);
  } else {
    if(c->rfd != -1) {
      flags = fcntl(c->rfd,F_GETFL);
      res = fcntl(c->rfd,F_SETFL,flags | O_NONBLOCK);
    }

    if(c->wfd != -1) {
      flags = fcntl(c->wfd,F_GETFL);
      res = fcntl(c->wfd,F_GETFL,flags | O_NONBLOCK);
    }
  }

  return res;
}

int inet_setblock(pool *pool, conn_t *c)
{
  int flags;
  int res = -1;

  errno = EBADF;		/* Default */

  if(c->mode == CM_LISTEN) {
    flags = fcntl(c->listen_fd,F_GETFL);
    res = fcntl(c->listen_fd,F_SETFL,flags & (U32BITS ^ O_NONBLOCK));
  } else {
    if(c->rfd != -1) {
      flags = fcntl(c->rfd,F_GETFL);
      res = fcntl(c->rfd,F_SETFL,flags & (U32BITS ^ O_NONBLOCK));
    }

    if(c->wfd != -1) {
      flags = fcntl(c->wfd,F_GETFL);
      res = fcntl(c->wfd,F_SETFL,flags & (U32BITS ^ O_NONBLOCK));
    }
  }

  return res;
}

/*
 * Put a connection in listen mode
 */

int inet_listen(pool *pool, conn_t *c, int backlog)
{
  if(!c || c->mode == CM_LISTEN)
    return -1;

  while(1)
    if(listen(c->listen_fd,backlog) == -1) {
      if(errno == EINTR)
        continue; 
      log_pri(LOG_ERR,"listen() failed in inet_listen(): %s",
              strerror(errno));
      end_login(1);
    } else
      break;
  
  c->mode = CM_LISTEN;  
  return 0;
}

/*
 * Reset a connection back to listen mode.  Enables blocking mode
 * for safety.
 */

int inet_resetlisten(pool *pool, conn_t *c)
{
  c->mode = CM_LISTEN;
  inet_setblock(c->pool,c);

  return 0;
}

int inet_connect(pool *pool, conn_t *c, p_in_addr_t *addr, int port)
{
  struct sockaddr_in remaddr;
  int ret;

  inet_setblock(pool,c);
  remaddr.sin_family = AF_INET;
  remaddr.sin_addr = *addr;
  remaddr.sin_port = htons(port);

  c->mode = CM_CONNECT;

  while( (ret = connect(c->listen_fd,(struct sockaddr*)&remaddr,sizeof(remaddr))) == -1 &&
         errno == EINTR ) ;

  if(ret == -1) {
    c->mode = CM_ERROR;
    c->xerrno = errno;
    return -1;
  }

  c->mode = CM_OPEN;

  if (inet_get_conn_info(c, c->listen_fd) < 0)
    return -1;

  inet_setblock(c->pool,c);
  return 1;
}

/* attempt to connection a connection, returning immediately with
 * 1 if connected, 0 if not connected, or -1 if error.  Only needs to be
 * called once, and can then be selected for writing.
 */

int inet_connect_nowait(pool *pool, conn_t *c, p_in_addr_t *addr, int port)
{
  struct sockaddr_in remaddr;

  inet_setnonblock(pool,c);

  remaddr.sin_family = AF_INET;
  remaddr.sin_addr = *addr;
  remaddr.sin_port = htons(port);

  c->mode = CM_CONNECT;
  if(connect(c->listen_fd,(struct sockaddr*)&remaddr,sizeof(remaddr)) == -1) {
    if(errno != EINPROGRESS && errno != EALREADY) {
      c->mode = CM_ERROR;
      c->xerrno = errno;
      return -1;
    }

    return 0;
  }

  c->mode = CM_OPEN;

  if (inet_get_conn_info(c, c->listen_fd) < 0)
    return -1;

  inet_setblock(c->pool,c);
  return 1;
}

/*
 * Accepts a new connection, returning immediately with -1 if
 * no connection is available.  If a connection is accepted,
 * creating a new conn_t and potential resolving is deferred,
 * and a normal socket fd is returned for the new connection, which
 * can later be used in inet_openrw to fully open and resolve
 * addresses.
 */
int inet_accept_nowait(pool *pool, conn_t *c)
{
  int fd;
  struct sockaddr_in servaddr;
  int len = sizeof(servaddr);

  if(c->mode == CM_LISTEN)
    inet_setnonblock(c->pool,c);

  c->mode = CM_ACCEPT;
  if((fd = accept(c->listen_fd,(struct sockaddr*)&servaddr,&len)) == -1) {
    if(errno != EWOULDBLOCK) {
      c->mode = CM_ERROR;
      c->xerrno = errno;
      return -1;
    }

    c->mode = CM_LISTEN;
    c->xerrno = 0;
    return -1;
  }

  /* Leave the connection in CM_ACCEPT mode, so others can see
   * our state.  Re-enable blocking mode, however.
   */

  inet_setblock(c->pool,c);

  return fd;
}

/* Accepts a new connection, cloning the existing conn_t and returning
 * it, or NULL upon error.
 */
conn_t *inet_accept(pool *pool, conn_t *d, conn_t *c, int rfd, int wfd,
		    int resolve) {
  conn_t *res = NULL;
  int newfd = -1, allow_foreign_addr = -1;
  struct sockaddr_in addr;
  int addrlen = sizeof(addr);
  
  d->mode = CM_ACCEPT;
  allow_foreign_addr = get_param_int(TOPLEVEL_CONF, "AllowForeignAddress",
				     FALSE);
  
  for(;;) {
    if((newfd = accept(d->listen_fd, (struct sockaddr *) &addr,
		       &addrlen)) != -1) {
      if((allow_foreign_addr != 1) &&
	 (getpeername(newfd, (struct sockaddr *) &addr, &addrlen) != -1)) {
	if(addr.sin_addr.s_addr != c->remote_ipaddr->s_addr) {
	  log_pri(LOG_NOTICE,
		  "SECURITY VIOLATION: Passive connection from %s rejected.",
		  inet_ntoa(addr.sin_addr));
	  close(newfd);
	  continue;
	}
      }
      d->mode = CM_OPEN;
      res = inet_openrw(pool, d, NULL, newfd, rfd, wfd, resolve);
    } else {
      d->mode = CM_ERROR;
      d->xerrno = errno;
    }
    
    break;
  }

  return res;
}

int inet_get_conn_info(conn_t *c, int fd) {
  static struct sockaddr_in servaddr;
  int len = sizeof(servaddr);
  
  /* Sanity check.
   */
  if (fd < 0) {
    errno = EBADF;
    return -1;
  }
 
  if (getsockname(fd, (struct sockaddr *) &servaddr, &len) != -1) {
    if (!c->local_ipaddr)
      c->local_ipaddr = (p_in_addr_t *) pcalloc(c->pool, sizeof(p_in_addr_t));     
    *c->local_ipaddr = servaddr.sin_addr;
    c->local_port = ntohs(servaddr.sin_port);

  } else
    return -1;
  
  len = sizeof(servaddr);

  if (getpeername(fd, (struct sockaddr *) &servaddr, &len) != -1) {
    c->remote_ipaddr = (p_in_addr_t *) pcalloc(c->pool, sizeof(p_in_addr_t));
    *c->remote_ipaddr = servaddr.sin_addr;
    c->remote_port = ntohs(servaddr.sin_port);

  } else
    return -1;

  return 0;
}

/*
 * Associate already open streams with the connection,
 * returns NULL if either stream points to a non-socket descriptor.
 * If addr is non-NULL, remote address discovery is attempted.
 * If resolve is non-zero, the remote address is reverse resolved.
 */

conn_t *inet_associate(pool *pool, conn_t *c, p_in_addr_t *addr, 
                       IOFILE *inf, IOFILE *outf, int resolve)
{
  int rfd,wfd;
  int socktype;
  int socktype_len = sizeof(socktype);
  conn_t *res;

  rfd = inf->fd;
  wfd = outf->fd;

  if(getsockopt(rfd,SOL_SOCKET,SO_TYPE,(void*)&socktype,&socktype_len) == -1 ||
     socktype != SOCK_STREAM)
    return NULL;

  if(getsockopt(wfd,SOL_SOCKET,SO_TYPE,(void*)&socktype,&socktype_len) == -1 ||
     socktype != SOCK_STREAM)
    return NULL;

  res = inet_copy_connection(pool,c);

  res->rfd = rfd;
  res->wfd = wfd;
  res->inf = inf;
  res->outf = outf;
  res->mode = CM_OPEN;

  if (inet_get_conn_info(res, wfd) < 0)
    return NULL;

  /* Get the remote address */

  if(addr) {
    if(!res->remote_ipaddr)
      res->remote_ipaddr = (p_in_addr_t*)palloc(res->pool,sizeof(p_in_addr_t));
    *res->remote_ipaddr = *addr;
  }

  if(resolve && res->remote_ipaddr)
    res->remote_name = inet_getname(res->pool,res->remote_ipaddr);

  if(!res->remote_name)
    res->remote_name = pstrdup(res->pool,inet_ntoa(*res->remote_ipaddr));

  inet_setoptions(res->pool,res,0,0);
  /* inet_setnonblock(res->pool,res); */
  return res;
}
    
/*
 * Open streams for a new socket, if rfd and wfd != -1,
 * two new fds are duped to the respective read/write fds.
 * If the fds specified correspond to the normal stdin and stdout,
 * the streams opened will be assigned to stdin and stdout in
 * an intuitive fashion (so that they may be later be used by
 * printf/fgets type libc functions).  If inaddr is non-NULL,
 * the address is assigned to the connection (as the *source* of
 * the connection).  If it is NULL, remote address discovery will
 * be attempted.  The connection structure appropriate fields are filled
 * in, including the *destination* address.  Finally, if resolve is
 * non-ZERO, inet_openrw will attempt to reverse resolve the remote
 * address.  A new connection structure is created in the specified pool.
 *
 * Important, do not call any log_* functions from inside of inet_openrw()
 * or any functions it calls, as the possibility for fd overwriting occurs.
 */
conn_t *inet_openrw(pool *pool, conn_t *c, p_in_addr_t *addr, int fd,
                    int rfd,int wfd, int resolve)
{
  conn_t *res = NULL;
  int close_fd = TRUE;

  res = inet_copy_connection(pool,c);

  res->listen_fd = -1;

  /* Note: there are some cases where the given file descriptor will
   * intentionally be bad (e.g. in get_ident() lookups).  In this case,
   * errno will have a value of EBADF; this is an "acceptable" error.  Any
   * other errno value constitutes an unacceptable error.
   */
  if (inet_get_conn_info(res, fd) < 0 && errno != EBADF)
    return NULL;

  if (addr) {
    if (!res->remote_ipaddr)
      res->remote_ipaddr = (p_in_addr_t*)palloc(res->pool,sizeof(p_in_addr_t));
    *res->remote_ipaddr = *addr;
  }

  if (resolve && res->remote_ipaddr)
    res->remote_name = inet_getname(res->pool,res->remote_ipaddr);

  if (!res->remote_name)
    res->remote_name = pstrdup(res->pool,inet_ntoa(*res->remote_ipaddr));

  if (fd == -1 && c->listen_fd != -1)
    fd = c->listen_fd;

  if (rfd != -1) {
    if (fd != rfd)
      dup2(fd, rfd);
    else
      close_fd = FALSE;

  } else
    rfd = dup(fd);

  if (wfd != -1) {
    if (fd != wfd) {
      if (wfd == STDOUT_FILENO)
        fflush(stdout);
      dup2(fd, wfd);

    } else
      close_fd = FALSE;

  } else
    wfd = dup(fd);

  /* Now discard the original socket */
  if (rfd != -1 && wfd != -1 && close_fd)
    close(fd);

  res->rfd = rfd;
  res->wfd = wfd;

  res->inf = io_open(res->pool,res->rfd,IO_READ);
  res->outf = io_open(res->pool,res->wfd,IO_WRITE);

  /* Set options on the sockets. */
  inet_setoptions(res->pool,res,0,0);
  inet_setblock(res->pool,res);

  res->mode = CM_OPEN;
  return res;
}

/* Perform reverse ip dns resolution on an existing
 * connection.
 */

void inet_resolve_ip(pool *pool, conn_t *c)
{
  if(c->remote_ipaddr) {
    c->remote_name = inet_getname(c->pool,c->remote_ipaddr);

    if(!c->remote_name)
      c->remote_name = pstrdup(c->pool,inet_ntoa(*c->remote_ipaddr));

  }
}

void init_inet(void)
{
  struct protoent *pr;

  setprotoent(FALSE);
  if((pr = getprotobyname("tcp")) != NULL)
    tcp_proto = pr->p_proto;
  endprotoent();
}
