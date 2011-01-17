/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2011 The ProFTPD Project team
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

/* Memcache support
 * $Id: memcache.h,v 1.5 2011-01-17 21:17:39 castaglia Exp $
 */

#ifndef PR_MEMCACHE_H
#define PR_MEMCACHE_H

#include "conf.h"

typedef struct mcache_rec pr_memcache_t;

/* Core API for use by modules et al */
pr_memcache_t *pr_memcache_conn_get(pool *p, time_t expires);
pr_memcache_t *pr_memcache_conn_new(pool *p, time_t expires);
int pr_memcache_conn_close(pr_memcache_t *mcache);

int pr_memcache_add(pr_memcache_t *mcache, const char *key, void *value,
  size_t valuesz, uint32_t flags);
void *pr_memcache_get(pr_memcache_t *mcache, const char *key, size_t *valuesz,
  uint32_t *flags);
char *pr_memcache_get_str(pr_memcache_t *mcache, const char *key,
  uint32_t *flags);
int pr_memcache_remove(pr_memcache_t *mcache, const char *key);
int pr_memcache_set(pr_memcache_t *mcache, const char *key, void *value,
  size_t valuesz, uint32_t flags);

/* Variants of the above, where the key values are arbitrary bits rather
 * than being assumed to be strings.
 */
int pr_memcache_kadd(pr_memcache_t *mcache, const char *key, size_t keysz,
  void *value, size_t valuesz, uint32_t flags);
void *pr_memcache_kget(pr_memcache_t *mcache, const char *key, size_t keysz,
  size_t *valuesz, uint32_t *flags);
char *pr_memcache_kget_str(pr_memcache_t *mcache, const char *key,
  size_t keysz, uint32_t *flags);
int pr_memcache_kremove(pr_memcache_t *mcache, const char *key, size_t keysz);
int pr_memcache_kset(pr_memcache_t *mcache, const char *key, size_t keysz,
  void *value, size_t valuesz, uint32_t flags);

/* For internal use only */
unsigned long memcache_get_flags(void);
#define PR_MEMCACHE_FL_NO_BINARY_PROTOCOL	0x001
#define PR_MEMCACHE_FL_BLOCKING			0x002

int memcache_set_flags(unsigned long flags);
int memcache_set_logfd(int logfd);
int memcache_set_replicas(uint64_t count);
int memcache_set_servers(void *server_list);

#endif /* PR_MEMCACHE_H */
