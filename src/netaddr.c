/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2003 The ProFTPD Project team
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
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* Network address routines
 * $Id: netaddr.c,v 1.2 2003-08-06 22:31:37 castaglia Exp $
 */

#include "conf.h"

/* Define an IPv4 equivalent of the IN6_IS_ADDR_LOOPBACK macro. */
#undef IN_IS_ADDR_LOOPBACK
#define IN_IS_ADDR_LOOPBACK(a) \
  ((((long int) (a)->s_addr) & 0xff000000) == 0x7f000000)

/* Do reverse DNS lookups? */
static int reverse_dns = 1;

int pr_netaddr_reverse_dns(int enable) {
  int old_enable = reverse_dns;
  reverse_dns = enable;
  return old_enable;
}

pr_netaddr_t *pr_netaddr_get_addr(pool *p, const char *name,
    array_header **addrs) {

  struct sockaddr_in sin;
#ifdef USE_IPV6
  struct sockaddr_in6 sin6;
#endif /* USE_IPV6 */
  pr_netaddr_t *na = NULL;
  int res;

  if (p == NULL || name == NULL) {
    errno = EINVAL;
    return NULL;
  }

  /* Attempt to translate the given name into a pr_netaddr_t using inet_pton()
   * first.
   *
   * First, if IPv6 support is enabled, we try to translate the name using
   * inet_pton(AF_INET6) on the hopes that the given string is a valid
   * representation of an IPv6 address.  If that fails, or if IPv6 support
   * is not enabled, we try with inet_pton(AF_INET).  If that fails, we
   * assume that the given name is a DNS name, and we call getaddrinfo().
   */

  na = (pr_netaddr_t *) pcalloc(p, sizeof(pr_netaddr_t));

#ifdef USE_IPV6
  sin6.sin6_family = AF_INET6;
  res = inet_pton(AF_INET6, name, &sin6.sin6_addr);
  if (res > 0) {
    pr_netaddr_set_family(na, AF_INET6);
    pr_netaddr_set_sockaddr(na, (struct sockaddr *) &sin6);
    if (addrs)
      *addrs = NULL;

    return na;
  }
#endif

  sin.sin_family = AF_INET;
  res = inet_pton(AF_INET, name, &sin.sin_addr);
  if (res > 0) {
    pr_netaddr_set_family(na, AF_INET);
    pr_netaddr_set_sockaddr(na, (struct sockaddr *) &sin);
    if (addrs)
      *addrs = NULL;

    return na;

  } else if (res == 0) {

    /* If inet_pton(3) returns 0, it means that name does not represent a
     * valid network address in the specified address family.  Usually,
     * this means that name is actually a DNS name, not an IP address
     * string.  So we treat it as a DNS name, and use getaddrinfo(3) to
     * resolve that name to its IP address(es).
     */

    struct addrinfo hints, *info = NULL;
    int res = 0;

    memset(&hints, 0, sizeof(hints));

#ifdef USE_IPV6
    /* This looks up both IPv4 (as IPv6-mapped) and IPv6 addresses. */
    hints.ai_family = AF_UNSPEC;
#else
    hints.ai_family = AF_INET;
#endif /* USE_IPV6 */
    hints.ai_socktype = SOCK_STREAM;

    res = pr_getaddrinfo(name, NULL, &hints, &info);
    if (res != 0) {
      log_pri(PR_LOG_INFO, "getaddrinfo '%s' error: %s", name,
        res != EAI_SYSTEM ? gai_strerror(res) : strerror(errno));
      return NULL;
    }

    if (info) {
      /* Copy the first returned addr into na, as the return value. */
      pr_netaddr_set_family(na, info->ai_family);
      pr_netaddr_set_sockaddr(na, info->ai_addr);

      /* If the caller provided a pointer for any additional addresses,
       * then we cycle through the rest of getaddrinfo(3)'s results and
       * build a list to return to the caller.
       */
      if (addrs) {
        struct addrinfo *ai;
        *addrs = make_array(p, 0, sizeof(pr_netaddr_t *));

        for (ai = info->ai_next; ai; ai = ai->ai_next) {
          pr_netaddr_t **elt = push_array(*addrs);

          *elt = palloc(p, sizeof(pr_netaddr_t));
          pr_netaddr_set_family(*elt, ai->ai_family);
          pr_netaddr_set_sockaddr(*elt, ai->ai_addr);
        }
      }

      pr_freeaddrinfo(info);
      return na;
    }
  }

  return NULL;
}

int pr_netaddr_get_family(const pr_netaddr_t *na) {
  if (!na) {
    errno = EINVAL;
    return -1;
  }

  return na->na_family;
}

int pr_netaddr_set_family(pr_netaddr_t *na, int family) {
  if (!na) {
    errno = EINVAL;
    return -1;
  }

  na->na_family = family;
  return 0;
}

int pr_netaddr_get_addrlen(const pr_netaddr_t *na) {
  if (!na) {
    errno = EINVAL;
    return -1;
  }

  switch (pr_netaddr_get_family(na)) {
    case AF_INET:
      return sizeof(struct sockaddr_in);
 
#ifdef USE_IPV6
    case AF_INET6:
      return sizeof(struct sockaddr_in6);
#endif /* USE_IPV6 */   
  }

  errno = EPERM;
  return -1;
}

struct sockaddr *pr_netaddr_get_sockaddr(const pr_netaddr_t *na) {
  if (!na) {
    errno = EINVAL;
    return NULL;
  }

  switch (pr_netaddr_get_family(na)) {
    case AF_INET:
      return (struct sockaddr *) &na->na_addr.v4;

#ifdef USE_IPV6
    case AF_INET6:
      return (struct sockaddr *) &na->na_addr.v6;
#endif /* USE_IPV6 */
  }

  errno = EPERM;
  return NULL;
}

int pr_netaddr_set_sockaddr(pr_netaddr_t *na, struct sockaddr *addr) {
  if (!na || !addr) {
    errno = EINVAL;
    return -1;
  }

  memset(&na->na_addr, 0, sizeof(na->na_addr));
  switch (na->na_family) {
    case AF_INET:
      memcpy(&(na->na_addr.v4), addr, sizeof(struct sockaddr_in));
      return 0;

#ifdef USE_IPV6
    case AF_INET6:
      memcpy(&(na->na_addr.v6), addr, sizeof(struct sockaddr_in6));
      return 0;
#endif /* USE_IPV6 */
  }

  errno = EPERM;
  return -1;
}

int pr_netaddr_set_sockaddr_any(pr_netaddr_t *na) {
  if (!na) {
    errno = EINVAL;
    return -1;
  }

  switch (pr_netaddr_get_family(na)) {
    case AF_INET: {
      struct in_addr in4addr_any;
      in4addr_any.s_addr = htonl(INADDR_ANY);
      memcpy(&na->na_addr.v4.sin_addr, &in4addr_any, sizeof(struct in_addr));
      return 0;
    }

#ifdef USE_IPV6
    case AF_INET6:
      memcpy(&na->na_addr.v6.sin6_addr, &in6addr_any, sizeof(struct in6_addr));
      return 0;
#endif /* USE_IPV6 */
  }

  errno = EPERM;
  return -1;
}

void *pr_netaddr_get_inaddr(const pr_netaddr_t *na) {
  if (!na) {
    errno = EINVAL;
    return NULL;
  }

  switch (pr_netaddr_get_family(na)) {
    case AF_INET:
      return (void *) &na->na_addr.v4.sin_addr;

#ifdef USE_IPV6
    case AF_INET6:
      return (void *) &na->na_addr.v6.sin6_addr;
#endif /* USE_IPV6 */
  }

  errno = EPERM;
  return NULL;
}

unsigned int pr_netaddr_get_port(const pr_netaddr_t *na) {
  if (!na) {
    errno = EINVAL;
    return 0;
  }

  switch (pr_netaddr_get_family(na)) {
    case AF_INET:
      return na->na_addr.v4.sin_port;

#ifdef USE_IPV6
    case AF_INET6:
      return na->na_addr.v6.sin6_port;
#endif /* USE_IPV6 */
  }

  errno = EPERM;
  return 0;
}

int pr_netaddr_set_port(pr_netaddr_t *na, unsigned int port) {
  if (!na) {
    errno = EINVAL;
    return -1;
  }

  switch (pr_netaddr_get_family(na)) {
    case AF_INET:
      na->na_addr.v4.sin_port = port;
      return 0;

#ifdef USE_IPV6
    case AF_INET6:
      na->na_addr.v6.sin6_port = port;
      return 0;
#endif /* USE_IPV6 */
  }

  errno = EPERM;
  return 0;
}

int pr_netaddr_cmp(const pr_netaddr_t *na1, const pr_netaddr_t *na2) {
  if (na1 && !na2)
    return 1;

  if (!na1 && na2)
    return -1;

  if (!na1 && !na2)
    return 0;

  if (pr_netaddr_get_family(na1) != pr_netaddr_get_family(na2)) {
    /* Cannot compare addresses from different families. */
    errno = EINVAL;
    return -1;
  }

  switch (pr_netaddr_get_family(na1)) {
    case AF_INET:
      return memcmp(&na1->na_addr.v4.sin_addr, &na2->na_addr.v4.sin_addr,
        sizeof(struct in_addr));

#ifdef USE_IPV6
    case AF_INET6:
      return memcmp(&na1->na_addr.v6.sin6_addr, &na2->na_addr.v6.sin6_addr,
        sizeof(struct in6_addr));
#endif /* USE_IPV6 */
  }

  errno = EPERM;
  return -1;
}

const char *pr_netaddr_get_ipstr(pr_netaddr_t *na) {
#ifdef USE_IPV6
  char buf[INET6_ADDRSTRLEN];
#else
  char buf[INET_ADDRSTRLEN];
#endif /* USE_IPV6 */
  int res = 0;
  
  if (!na) {
    errno = EINVAL;
    return NULL;
  }

  /* If this pr_netaddr_t has already been resolved to an IP string, return the
   * cached string.
   */
  if (na->na_have_ipstr)
    return na->na_ipstr;

  memset(buf, '\0', sizeof(buf));
  res = pr_getnameinfo(pr_netaddr_get_sockaddr(na), pr_netaddr_get_addrlen(na),
    buf, sizeof(buf), NULL, 0, NI_NUMERICHOST);
  if (res != 0) {
    log_pri(PR_LOG_NOTICE, "getnameinfo error: %s",
      res != EAI_SYSTEM ? gai_strerror(res) : strerror(errno));
    return NULL;
  }

  /* Copy the string into the pr_netaddr_t cache as well, so we only
   * have to do this once for this pr_netaddr_t.
   */
  memset(na->na_ipstr, '\0', sizeof(na->na_ipstr));
  sstrncpy(na->na_ipstr, buf, sizeof(na->na_ipstr));
  na->na_have_ipstr = TRUE;

  return na->na_ipstr;
}

/* This differs from pr_netaddr_get_ipstr() in that pr_netaddr_get_ipstr()
 * returns a string of the numeric form of the given network address, whereas
 * this function returns a string of the DNS name (if present).
 */
const char *pr_netaddr_get_dnsstr(pr_netaddr_t *na) {
  char *name = NULL;

  if (!na) {
    errno = EINVAL;
    return NULL;
  }

  /* If this pr_netaddr_t has already been resolved to an DNS string, return the
   * cached string.
   */
  if (na->na_have_dnsstr)
    return na->na_dnsstr;

  if (reverse_dns) {
    char buf[256];
    int res = 0;

    memset(buf, '\0', sizeof(buf));
    res = pr_getnameinfo(pr_netaddr_get_sockaddr(na),
      pr_netaddr_get_addrlen(na), buf, sizeof(buf), NULL, 0, NI_NAMEREQD);

    if (res == 0) {
      char **checkaddr;
      struct hostent *hent = NULL;
      unsigned char ok = FALSE;

       /* Note: here, gethostbyname() is fine, as it returns both IPv4 and IPv6
        * entries (ideally).  However, gethostbyname(2) has been marked
        * (in some literature) as a legacy interface, and use of the newer
        * getipnodebyname(2) is recommended.  Not every platform provides
        * getipnodebyname(2), though, which means we'll stick with
        * gethostbyname(2) for now.
        *
        * XXX other places in this file use gethostbyname(2) as well, so don't
        * forget them when we change to using a newer function.
        * entries.
        */

      hent = gethostbyname(buf);
      if (hent != NULL) {
        switch (hent->h_addrtype) {
          case AF_INET:
            if (pr_netaddr_get_family(na) == AF_INET) {
              for (checkaddr = hent->h_addr_list; *checkaddr; ++checkaddr) {
                if (memcmp(*checkaddr, pr_netaddr_get_inaddr(na),
                    hent->h_length) == 0) {

                  ok = TRUE;
                  break;
                }
              }
            } 
            break;

#ifdef USE_IPV6
          case AF_INET6:
            if (pr_netaddr_get_family(na) == AF_INET6) {
              for (checkaddr = hent->h_addr_list; *checkaddr; ++checkaddr) {
                if (memcmp(*checkaddr, pr_netaddr_get_inaddr(na),
                    hent->h_length) == 0) {

                  ok = TRUE;
                  break;
                }
              }
            } 
            break;
#endif /* USE_IPV6 */
        }

        if (!ok)
          name = NULL;
      }
    }
  }

  if (!name)
    name = (char *) pr_netaddr_get_ipstr(na);

  name = pr_inet_validate(name);

  /* Copy the string into the pr_netaddr_t cache as well, so we only
   * have to do this once for this pr_netaddr_t.
   */
  memset(na->na_dnsstr, '\0', sizeof(na->na_dnsstr));
  sstrncpy(na->na_dnsstr, name, sizeof(na->na_dnsstr));
  na->na_have_dnsstr = TRUE;

  return na->na_dnsstr;
}

/* Return the FQDN for a given string. */
const char *pr_netaddr_get_fqdn(pool *p, const char *name) {
  struct hostent *host;

  if ((host = gethostbyname(name)) != NULL)
    return pr_inet_validate(pstrdup(p, host->h_name));

  return NULL;
}

/* Return the hostname (wrapper for gethostname(2), except returns FQDN). */
const char *pr_netaddr_get_localaddr_str(pool *p) {
  char buf[256] = {'\0'};
  struct hostent *host;

  if (gethostname(buf, sizeof(buf)-1) != -1) {
    buf[sizeof(buf)-1] = '\0';
    host = gethostbyname(buf);
    if (host)
      return pr_inet_validate(pstrdup(p, host->h_name));

    return pr_inet_validate(pstrdup(p, buf));
  }

  return NULL;
}

int pr_netaddr_loopback(const pr_netaddr_t *na) {
  if (!na) {
    errno = EINVAL;
    return -1;
  }

  switch (pr_netaddr_get_family(na)) {
    case AF_INET:
      return IN_IS_ADDR_LOOPBACK(
        (struct in_addr *) pr_netaddr_get_inaddr(na));

#ifdef USE_IPV6
    case AF_INET6:

      /* XXX *sigh* Different platforms implement the IN6_IS_ADDR macros
       * differently.  For example, on Linux, those macros expect to operate
       * on s6_addr32, while on Solaris, the macros operate on struct in6_addr.
       * Certain Drafts define the macros to work on struct in6_addr *, as
       * Solaris does, so Linux may have it wrong.  Tentative research on
       * Google shows some BSD netinet6/in6.h headers that define these
       * macros in terms of struct in6_addr *, so I'll go with that for now.
       * Joy. =P
       */
# ifndef LINUX
      return IN6_IS_ADDR_LOOPBACK(
        (struct in6_addr *) pr_netaddr_get_inaddr(na));
# else
      return IN6_IS_ADDR_LOOPBACK(
        ((struct in6_addr *) pr_netaddr_get_inaddr(na))->s6_addr32);
# endif
#endif /* USE_IPV6 */
  }

  return FALSE;
}

/* A slightly naughty function that should go away. It relies too much on
 * knowledge of the internal structures of struct in_addr, struct in6_addr.
 */
unsigned int pr_netaddr_get_addrno(const pr_netaddr_t *na) {
  if (!na) {
    errno = EINVAL;
    return -1;
  }

  switch (pr_netaddr_get_family(na)) {
    case AF_INET:
      return na->na_addr.v4.sin_addr.s_addr;

#ifdef USE_IPV6
    case AF_INET6: {

      /* Linux defines s6_addr32 in its netinet/in.h header.
       * FreeBSD defines s6_addr32 in KAME's netinet6/in6.h header.
       * Solaris defines s6_addr32 in its netinet/in.h header, but only
       * for kernel builds.
       */
#if 0
      int *addrs = ((struct sockaddr_in6 *) pr_netaddr_get_inaddr(na))->s6_addr32;
      return addrs[0];
#else
      return 0;
#endif
    }
#endif /* USE_IPV6 */
  }

  errno = EPERM;
  return -1;
}

int pr_netaddr_v4mappedv6(const pr_netaddr_t *na) {
  if (!na) {
    errno = EINVAL;
    return -1;
  }

  switch (pr_netaddr_get_family(na)) {
    case AF_INET:

      /* This function tests only IPv6 addresses, not IPv4 addresses. */
      errno = EINVAL;
      return -1;

#ifdef USE_IPV6
    case AF_INET6:

# ifndef LINUX
      return IN6_IS_ADDR_V4MAPPED(
        (struct in6_addr *) pr_netaddr_get_inaddr(na));
# else
      return IN6_IS_ADDR_V4MAPPED(
        ((struct in6_addr *) pr_netaddr_get_inaddr(na))->s6_addr32);
# endif
#endif /* USE_IPV6 */
  }

  errno = EPERM;
  return -1;
}

