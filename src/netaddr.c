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
 * $Id: netaddr.c,v 1.25 2003-10-10 06:36:57 castaglia Exp $
 */

#include "conf.h"

/* Define an IPv4 equivalent of the IN6_IS_ADDR_LOOPBACK macro. */
#undef IN_IS_ADDR_LOOPBACK
#define IN_IS_ADDR_LOOPBACK(a) \
  ((((long int) (a)->s_addr) & 0xff000000) == 0x7f000000)

/* Do reverse DNS lookups? */
static int reverse_dns = 1;

int pr_netaddr_set_reverse_dns(int enable) {
  int old_enable = reverse_dns;
  reverse_dns = enable;
  return old_enable;
}

pr_netaddr_t *pr_netaddr_alloc(pool *p) {
  if (!p) {
    errno = EINVAL;
    return NULL;
  }

  return pcalloc(p, sizeof(pr_netaddr_t));
}

void pr_netaddr_clear(pr_netaddr_t *na) {
  if (!na)
    return;

  memset(na, 0, sizeof(pr_netaddr_t));
}

pr_netaddr_t *pr_netaddr_get_addr(pool *p, const char *name,
    array_header **addrs) {

  struct sockaddr_in v4;
#ifdef USE_IPV6
  struct sockaddr_in6 v6;
#endif /* USE_IPV6 */
  pr_netaddr_t *na = NULL;
  int res;

  if (p == NULL || name == NULL) {
    errno = EINVAL;
    return NULL;
  }

  /* Attempt to translate the given name into a pr_netaddr_t using
   * pr_inet_pton() first.
   *
   * First, if IPv6 support is enabled, we try to translate the name using
   * pr_inet_pton(AF_INET6) on the hopes that the given string is a valid
   * representation of an IPv6 address.  If that fails, or if IPv6 support
   * is not enabled, we try with pr_inet_pton(AF_INET).  If that fails, we
   * assume that the given name is a DNS name, and we call pr_getaddrinfo().
   */

  na = (pr_netaddr_t *) pcalloc(p, sizeof(pr_netaddr_t));

#ifdef USE_IPV6
  memset(&v6, 0, sizeof(v6));
  v6.sin6_family = AF_INET6;

# ifdef SIN6_LEN
  v6.sin6_len = sizeof(struct sockaddr_in6);
# endif /* SIN6_LEN */

  res = pr_inet_pton(AF_INET6, name, &v6.sin6_addr);
  if (res > 0) {
    pr_netaddr_set_family(na, AF_INET6);
    pr_netaddr_set_sockaddr(na, (struct sockaddr *) &v6);
    if (addrs)
      *addrs = NULL;

    return na;
  }
#endif

  memset(&v4, 0, sizeof(v4));
  v4.sin_family = AF_INET;

# ifdef SIN_LEN
  v4.sin_len = sizeof(struct sockaddr_in);
# endif /* SIN_LEN */

  res = pr_inet_pton(AF_INET, name, &v4.sin_addr);
  if (res > 0) {
    pr_netaddr_set_family(na, AF_INET);
    pr_netaddr_set_sockaddr(na, (struct sockaddr *) &v4);
    if (addrs)
      *addrs = NULL;

    return na;

  } else if (res == 0) {

    /* If pr_inet_pton() returns 0, it means that name does not represent a
     * valid network address in the specified address family.  Usually,
     * this means that name is actually a DNS name, not an IP address
     * string.  So we treat it as a DNS name, and use getaddrinfo(3) to
     * resolve that name to its IP address(es).
     */

    struct addrinfo hints, *info = NULL;
    int gai_res = 0;

    memset(&hints, 0, sizeof(hints));

#ifdef USE_IPV6
    /* This looks up both IPv4 (as IPv6-mapped) and IPv6 addresses. */
    hints.ai_family = AF_UNSPEC;
#else
    hints.ai_family = AF_INET;
#endif /* USE_IPV6 */
    hints.ai_socktype = SOCK_STREAM;

    gai_res = pr_getaddrinfo(name, NULL, &hints, &info);
    if (gai_res != 0) {
      log_pri(PR_LOG_INFO, "getaddrinfo '%s' error: %s", name,
        res != EAI_SYSTEM ? pr_gai_strerror(gai_res) : strerror(errno));
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

  /* Set the family member of the appropriate sockaddr struct. */
  switch (family) {
    case AF_INET:
      na->na_addr.v4.sin_family = AF_INET;
      break;

#ifdef USE_IPV6
    case AF_INET6:
      na->na_addr.v6.sin6_family = AF_INET6;
      break;
#endif /* USE_IPV6 */

    default:
#ifdef EAFNOSUPPORT
      errno = EAFNOSUPPORT;
#else
      errno = EINVAL;
#endif
      return -1;
  }

  na->na_family = family;
  return 0;
}

size_t pr_netaddr_get_sockaddr_len(const pr_netaddr_t *na) {
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

size_t pr_netaddr_get_inaddr_len(const pr_netaddr_t *na) {
  if (!na) {
    errno = EINVAL;
    return -1;
  }

  switch (pr_netaddr_get_family(na)) {
    case AF_INET:
      return sizeof(struct in_addr);

#ifdef USE_IPV6
    case AF_INET6:
      return sizeof(struct in6_addr);
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
      na->na_addr.v4.sin_family = AF_INET;
#ifdef SIN_LEN
      na->na_addr.v4.sin_len = sizeof(struct sockaddr_in);
#endif /* SIN_LEN */
      memcpy(&na->na_addr.v4.sin_addr, &in4addr_any, sizeof(struct in_addr));
      return 0;
    }

#ifdef USE_IPV6
    case AF_INET6:
      na->na_addr.v6.sin6_family = AF_INET6;
#ifdef SIN6_LEN
      na->na_addr.v6.sin6_len = sizeof(struct sockaddr_in6);
#endif /* SIN6_LEN */
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

int pr_netaddr_ncmp(const pr_netaddr_t *na1, const pr_netaddr_t *na2,
    unsigned int bitlen) {
  unsigned int nbytes, nbits;
  const unsigned char *in1, *in2;

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
    case AF_INET: {
      /* Make sure that the given number of bits is not more than supported
       * for IPv4 addresses (32).
       */
      if (bitlen > 32) {
        errno = EINVAL;
        return -1;
      }

      break;
    }

#ifdef USE_IPV6
    case AF_INET6: {
      /* Make sure that the given number of bits is not more than supported
       * for IPv6 addresses (128).
       */
      if (bitlen > 128) {
        errno = EINVAL;
        return -1;
      }

      break;
    }
#endif /* USE_IPV6 */

    default:
      errno = EPERM;
      return -1;
  }

  /* Retrieve pointers to the contained in_addrs. */
  in1 = (const unsigned char *) pr_netaddr_get_inaddr(na1);
  in2 = (const unsigned char *) pr_netaddr_get_inaddr(na2);

  /* Determine the number of bytes, and leftover bits, in the given
   * bit length.
   */
  nbytes = bitlen / 8;
  nbits = bitlen % 8;

  /* Compare bytes, using memcmp(3), first. */
  if (nbytes > 0) {
    int res = memcmp(in1, in2, nbytes);

    /* No need to continue comparing the addresses if they differ already. */
    if (res != 0)
      return res;
  }

  /* Next, compare the remaining bits in the addresses. */
  if (nbits > 0) {
    unsigned int mask;

    /* Get the bytes in the addresses that have not yet been compared. */
    unsigned int in1byte = in1[nbytes];
    unsigned int in2byte = in2[nbytes];

    /* Build up a mask covering the bits left to be checked. */
    mask = (0xff << (8 - nbits)) & 0xff;

    if ((in1byte & mask) > (in2byte & mask))
      return 1;

    if ((in1byte & mask) < (in2byte & mask))
      return -1;
  }

  /* If we've made it this far, the addresses match, for the given bit
   * length.
   */
  return 0;
}

int pr_netaddr_fnmatch(pr_netaddr_t *na, const char *pattern) {

  /* NOTE: I'm still not sure why proftpd bundles an fnmatch(3)
   * implementation rather than using the system library's implementation.
   * Needs looking into.
   *
   * The FNM_CASEFOLD flag is a GNU extension; perhaps the bundled
   * implementation was added to make that flag available on other platforms.
   */
  int flags = PR_FNM_NOESCAPE|PR_FNM_CASEFOLD;
  const char *dnsstr, *ipstr;

  if (!na || !pattern) {
    errno = EINVAL;
    return -1;
  }

  dnsstr = pr_netaddr_get_dnsstr(na);
  if (pr_fnmatch(pattern, dnsstr, flags) == 0)
    return TRUE;

  ipstr = pr_netaddr_get_ipstr(na);
  if (pr_fnmatch(pattern, ipstr, flags) == 0)
    return TRUE;

  return FALSE;
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
  res = pr_getnameinfo(pr_netaddr_get_sockaddr(na),
    pr_netaddr_get_sockaddr_len(na), buf, sizeof(buf), NULL, 0, NI_NUMERICHOST);

  if (res != 0) {
    log_pri(PR_LOG_NOTICE, "getnameinfo error: %s",
      res != EAI_SYSTEM ? pr_gai_strerror(res) : strerror(errno));
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
  char buf[256];

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
    int res = 0;

    memset(buf, '\0', sizeof(buf));
    res = pr_getnameinfo(pr_netaddr_get_sockaddr(na),
      pr_netaddr_get_sockaddr_len(na), buf, sizeof(buf), NULL, 0, NI_NAMEREQD);

    if (res == 0) {
      char **checkaddr;
      struct hostent *hent = NULL;
      unsigned char ok = FALSE;

#ifdef HAVE_GETHOSTBYNAME2
      /* On *BSD platforms, gethostbyname2() is provided as the function to
       * handle names with AF_INET6 addresses.
       */
      hent = gethostbyname2(buf, pr_netaddr_get_family(na));
#else
      hent = gethostbyname(buf);
#endif /* HAVE_GETHOSTBYNAME2 */

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

        name = ok ? buf : NULL;

      } else
        log_debug(DEBUG1, "notice: unable to resolve '%s': %s", buf,
          hstrerror(errno));
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

/* Return the hostname (wrapper for gethostname(2), except returns FQDN). */
const char *pr_netaddr_get_localaddr_str(pool *p) {
  char buf[256] = {'\0'};
  struct hostent *host;

  if (gethostname(buf, sizeof(buf)-1) != -1) {
    buf[sizeof(buf)-1] = '\0';

    /* Note: this may need to be gethostbyname2() on systems that provide
     * that function, for it is possible that the configured hostname for
     * a machine only resolves to an IPv6 address.
     */
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

