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

/* Network address API
 * $Id: netaddr.h,v 1.1 2003-08-06 22:03:32 castaglia Exp $
 */

#ifndef PR_NETADDR_H
#define PR_NETADDR_H

#include "conf.h"

pr_netaddr_t *pr_netaddr_get_addr(pool *, const char *, array_header **);
int pr_netaddr_cmp(const pr_netaddr_t *s, const pr_netaddr_t *);
int pr_netaddr_get_addrlen(const pr_netaddr_t *);
int pr_netaddr_get_family(const pr_netaddr_t *);
int pr_netaddr_set_family(pr_netaddr_t *, int);
void *pr_netaddr_get_inaddr(const pr_netaddr_t *);
struct sockaddr *pr_netaddr_get_sockaddr(const pr_netaddr_t *);
int pr_netaddr_set_sockaddr(pr_netaddr_t *, struct sockaddr *);
int pr_netaddr_set_sockaddr_any(pr_netaddr_t *);
unsigned int pr_netaddr_get_port(const pr_netaddr_t *);
int pr_netaddr_set_port(pr_netaddr_t *, unsigned int);
int pr_netaddr_reverse_dns(int);
const char *pr_netaddr_get_dnsstr(pr_netaddr_t *);
const char *pr_netaddr_get_fqdn(pool *, const char *);
const char *pr_netaddr_get_ipstr(pr_netaddr_t *);
const char *pr_netaddr_get_localaddr_str(pool *);
unsigned int pr_netaddr_get_addrno(const pr_netaddr_t *);
int pr_netaddr_loopback(const pr_netaddr_t *);
int pr_netaddr_v4mappedv6(const pr_netaddr_t *);

#endif /* PR_NETADDR_H */
