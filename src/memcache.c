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

/* Memcache management
 * $Id: memcache.c,v 1.5 2011-01-17 21:17:39 castaglia Exp $
 */

#include "conf.h"

#ifdef PR_USE_MEMCACHE

#include <libmemcached/memcached.h>

struct mcache_rec {
  pool *pool;
  memcached_st *mc;
  time_t expires;
};

static memcached_server_st *servers = NULL;
static int memcache_logfd = -1;
static pr_memcache_t *sess_mcache = NULL;

static unsigned long memcache_flags = 0;
static uint64_t memcache_nreplicas = 0;

static const char *trace_channel = "memcache";

pr_memcache_t *pr_memcache_conn_get(pool *p, time_t expires) {
  if (sess_mcache != NULL) {
    return sess_mcache;
  }

  return pr_memcache_conn_new(p, expires);
}

pr_memcache_t *pr_memcache_conn_new(pool *p, time_t expires) {
  pr_memcache_t *mcache;
  pool *sub_pool;
  memcached_st *mc;
  memcached_return res;
  uint64_t nreplicas = 0;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (servers == NULL) {
    errno = EPERM;
    return NULL;
  }

  mc = memcached_create(NULL);
  if (mc == NULL) {
    errno = ENOMEM;
    return NULL;
  }

  res = memcached_server_push(mc, servers); 
  if (res != MEMCACHED_SUCCESS) {
    (void) pr_log_writefile(memcache_logfd, trace_channel,
      "error adding memcache servers to connection: %s",
      memcached_strerror(mc, res));
    memcached_free(mc);

    errno = EPERM;
    return NULL;
  }

  sub_pool = pr_pool_create_sz(p, 128);
  pr_pool_tag(sub_pool, "Memcache connection pool");

  mcache = palloc(sub_pool, sizeof(pr_memcache_t));
  mcache->pool = sub_pool;
  mcache->mc = mc;
  mcache->expires = expires;

  /* Set some of the desired behavior flags on the connection */
  if (memcached_behavior_get(mc, MEMCACHED_BEHAVIOR_TCP_NODELAY) != 1) {
    res = memcached_behavior_set(mc, MEMCACHED_BEHAVIOR_TCP_NODELAY, 1);
    if (res != MEMCACHED_SUCCESS) {
      (void) pr_log_writefile(memcache_logfd, trace_channel,
        "error setting TCP_NODELAY behavior on connection: %s",
        memcached_strerror(mc, res));
    }
  }

  /* Enable caching of DNS lookups. */
  if (memcached_behavior_get(mc, MEMCACHED_BEHAVIOR_CACHE_LOOKUPS) != 1) {
    res = memcached_behavior_set(mc, MEMCACHED_BEHAVIOR_CACHE_LOOKUPS, 1);
    if (res != MEMCACHED_SUCCESS) {
      (void) pr_log_writefile(memcache_logfd, trace_channel,
        "error setting CACHE_LOOKUPS behavior on connection: %s",
        memcached_strerror(mc, res));
    }
  }

  /* We always want consistent hashing, to minimize cache churn when
   * servers are added/removed from the list.  */
  if (memcached_behavior_get(mc, MEMCACHED_BEHAVIOR_DISTRIBUTION) != MEMCACHED_DISTRIBUTION_CONSISTENT) {
    res = memcached_behavior_set(mc, MEMCACHED_BEHAVIOR_DISTRIBUTION,
      MEMCACHED_DISTRIBUTION_CONSISTENT);
    if (res != MEMCACHED_SUCCESS) {
      (void) pr_log_writefile(memcache_logfd, trace_channel,
        "error setting DISTRIBUTION_CONSISTENT behavior on connection: %s",
        memcached_strerror(mc, res));
    }
  }

  /* Use nonblocking IO, unless explicitly requested not to. */
  if (memcached_behavior_get(mc, MEMCACHED_BEHAVIOR_NO_BLOCK) != 1) {
    if (!(memcache_flags & PR_MEMCACHE_FL_BLOCKING)) {
      res = memcached_behavior_set(mc, MEMCACHED_BEHAVIOR_NO_BLOCK, 1);
      if (res != MEMCACHED_SUCCESS) {
        (void) pr_log_writefile(memcache_logfd, trace_channel,
          "error setting NO_BLOCK behavior on connection: %s",
          memcached_strerror(mc, res));
      }
    }
  }

  /* Use the binary protocol by default, unless explicitly requested not to. */
  if (memcached_behavior_get(mc, MEMCACHED_BEHAVIOR_BINARY_PROTOCOL) != 1) {
    if (!(memcache_flags & PR_MEMCACHE_FL_NO_BINARY_PROTOCOL)) {
      res = memcached_behavior_set(mc, MEMCACHED_BEHAVIOR_BINARY_PROTOCOL, 1);
      if (res != MEMCACHED_SUCCESS) {
        (void) pr_log_writefile(memcache_logfd, trace_channel,
          "error setting BINARY_PROTOCOL behavior on connection: %s",
          memcached_strerror(mc, res));
      }
    }
  }

  /* Make sure that the requested number of replicas does not exceed the
   * server count.
   */
  nreplicas = memcache_nreplicas;
  if (nreplicas > memcached_server_count(mc)) {
    nreplicas = memcached_server_count(mc);
  }

  /* XXX Some caveats about libmemcached replication:
   *
   *  1.  Replication is enabled only if the binary protocol is used.
   *  2.  Replication occurs only for 'delete' or 'set' operations, NOT
   *      'add', 'cas', 'incr', 'decr', etc.
   */

  if (nreplicas > 0) {
    res = memcached_behavior_set(mc, MEMCACHED_BEHAVIOR_NUMBER_OF_REPLICAS,
      nreplicas);
    if (res != MEMCACHED_SUCCESS) {
      (void) pr_log_writefile(memcache_logfd, trace_channel,
        "error setting NUMBER_OF_REPLICAS behavior on connection: %s",
        memcached_strerror(mc, res));

    } else {
      (void) pr_log_writefile(memcache_logfd, trace_channel,
        "storing %lu replicas", (unsigned long) nreplicas);
    }
  }

  /* XXX Other behavior to play with:
   *  MEMCACHED_BEHAVIOR_RANDOMIZE_REPLICA_READ
   */

  if (sess_mcache == NULL) {
    sess_mcache = mcache;
  }

  return mcache;
}

int pr_memcache_conn_close(pr_memcache_t *mcache) {
  if (mcache == NULL) {
    errno = EINVAL;
    return -1;
  }

  memcached_free(mcache->mc);
  return 0;
}

int pr_memcache_add(pr_memcache_t *mcache, const char *key, void *value,
    size_t valuesz, uint32_t flags) {
  int res;

  /* XXX Should we allow null values to be added, thus allowing use of keys
   * as sentinels?
   */
  if (mcache == NULL ||
      key == NULL ||
      value == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_memcache_kadd(mcache, key, strlen(key), value, valuesz, flags); 
  if (res < 0) {
    (void) pr_log_writefile(memcache_logfd, trace_channel,
      "error adding key '%s', value (%lu bytes): %s", key,
      (unsigned long) valuesz, strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

void *pr_memcache_get(pr_memcache_t *mcache, const char *key, size_t *valuesz,
    uint32_t *flags) {
  void *ptr = NULL;

  if (mcache == NULL ||
      key == NULL ||
      valuesz == NULL ||
      flags == NULL) {
    errno = EINVAL;
    return NULL;
  }

  ptr = pr_memcache_kget(mcache, key, strlen(key), valuesz, flags);
  if (ptr == NULL) {
    (void) pr_log_writefile(memcache_logfd, trace_channel,
      "error getting data for key '%s': %s", key, strerror(errno));
    errno = EPERM;
    return NULL;
  }

  return ptr;
}

char *pr_memcache_get_str(pr_memcache_t *mcache, const char *key,
    uint32_t *flags) {
  char *ptr = NULL;

  if (mcache == NULL ||
      key == NULL ||
      flags == NULL) {
    errno = EINVAL;
    return NULL;
  }

  ptr = pr_memcache_kget_str(mcache, key, strlen(key), flags);
  if (ptr == NULL) {
    (void) pr_log_writefile(memcache_logfd, trace_channel,
      "error getting data for key '%s': %s", key, strerror(errno));
    errno = EPERM;
    return NULL;
  }

  return ptr;
}

int pr_memcache_remove(pr_memcache_t *mcache, const char *key) {
  int res;

  if (mcache == NULL ||
      key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_memcache_kremove(mcache, key, strlen(key));
  if (res < 0) {
    (void) pr_log_writefile(memcache_logfd, trace_channel,
      "error removing key '%s': %s", key, strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

int pr_memcache_set(pr_memcache_t *mcache, const char *key, void *value,
    size_t valuesz, uint32_t flags) {
  int res;

  /* XXX Should we allow null values to be added, thus allowing use of keys
   * as sentinels?
   */
  if (mcache == NULL ||
      key == NULL ||
      value == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_memcache_kset(mcache, key, strlen(key), value, valuesz, flags);
  if (res < 0) {
    (void) pr_log_writefile(memcache_logfd, trace_channel,
      "error setting key '%s', value (%lu bytes): %s", key,
      (unsigned long) valuesz, strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

int pr_memcache_kadd(pr_memcache_t *mcache, const char *key, size_t keysz,
    void *value, size_t valuesz, uint32_t flags) {
  memcached_return res;

  /* XXX Should we allow null values to be added, thus allowing use of keys
   * as sentinels?
   */
  if (mcache == NULL ||
      key == NULL ||
      value == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = memcached_add(mcache->mc, key, keysz, value, valuesz,
    mcache->expires, flags); 
  if (res != MEMCACHED_SUCCESS) {
    (void) pr_log_writefile(memcache_logfd, trace_channel,
      "error adding key (%lu bytes), value (%lu bytes): %s",
      (unsigned long) keysz, (unsigned long) valuesz,
      memcached_strerror(mcache->mc, res));
    errno = EPERM;
    return -1;
  }

  return 0;
}

void *pr_memcache_kget(pr_memcache_t *mcache, const char *key, size_t keysz,
    size_t *valuesz, uint32_t *flags) {
  char *data = NULL;
  void *ptr = NULL;
  memcached_return res;

  if (mcache == NULL ||
      key == NULL ||
      valuesz == NULL ||
      flags == NULL) {
    errno = EINVAL;
    return NULL;
  }

  data = memcached_get(mcache->mc, key, keysz, valuesz, flags, &res);
  if (data == NULL) {
    (void) pr_log_writefile(memcache_logfd, trace_channel,
      "error getting data for key (%lu bytes): %s", (unsigned long) keysz,
      memcached_strerror(mcache->mc, res));
    errno = EPERM;
    return NULL;
  }

  /* Create a duplicate of the returned data from the mcache's pool, so that
   * we can call free(3) on the data returned by libmemcached.
   */

  ptr = palloc(mcache->pool, *valuesz);
  memcpy(ptr, data, *valuesz);
  free(data);

  return ptr;
}

char *pr_memcache_kget_str(pr_memcache_t *mcache, const char *key,
    size_t keysz, uint32_t *flags) {
  char *data = NULL, *ptr = NULL;
  size_t valuesz = 0;
  memcached_return res;

  if (mcache == NULL ||
      key == NULL ||
      flags == NULL) {
    errno = EINVAL;
    return NULL;
  }

  data = memcached_get(mcache->mc, key, keysz, &valuesz, flags, &res);
  if (data == NULL) {
    (void) pr_log_writefile(memcache_logfd, trace_channel,
      "error getting data for key (%lu bytes): %s", (unsigned long) keysz,
      memcached_strerror(mcache->mc, res));
    errno = EPERM;
    return NULL;
  }

  /* Create a duplicate of the returned data from the mcache's pool, so that
   * we can call free(3) on the data returned by libmemcached.
   */

  ptr = pcalloc(mcache->pool, valuesz + 1);
  memcpy(ptr, data, valuesz);
  free(data);

  return ptr;
}

int pr_memcache_kremove(pr_memcache_t *mcache, const char *key, size_t keysz) {
  memcached_return res;

  if (mcache == NULL ||
      key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = memcached_delete(mcache->mc, key, keysz, mcache->expires);
  if (res != MEMCACHED_SUCCESS) {
    (void) pr_log_writefile(memcache_logfd, trace_channel,
      "error removing key (%lu bytes): %s", (unsigned long) keysz,
      memcached_strerror(mcache->mc, res));
    errno = EPERM;
    return -1;
  }

  return 0;
}

int pr_memcache_kset(pr_memcache_t *mcache, const char *key, size_t keysz,
    void *value, size_t valuesz, uint32_t flags) {
  memcached_return res;

  /* XXX Should we allow null values to be added, thus allowing use of keys
   * as sentinels?
   */
  if (mcache == NULL ||
      key == NULL ||
      value == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = memcached_set(mcache->mc, key, keysz, value, valuesz,
    mcache->expires, flags); 
  if (res != MEMCACHED_SUCCESS) {
    (void) pr_log_writefile(memcache_logfd, trace_channel,
      "error setting key (%lu bytes), value (%lu bytes): %s",
      (unsigned long) keysz, (unsigned long) valuesz,
      memcached_strerror(mcache->mc, res));
    errno = EPERM;
    return -1;
  }

  return 0;
}

unsigned long memcache_get_flags(void) {
  return memcache_flags;
}

int memcache_set_flags(unsigned long flags) {
  memcache_flags = flags;
  return 0;
}

int memcache_set_logfd(int fd) {
  if (fd < 0) {
    errno = EINVAL;
    return -1;
  }

  memcache_logfd = fd;
  return 0;
}

int memcache_set_replicas(uint64_t count) {
  if (count < 1) {
    errno = EINVAL;
    return -1;
  }

  memcache_nreplicas = count;
  return 0;
}

int memcache_set_servers(void *server_list) {
  if (server_list == NULL) {
    errno = EINVAL;
    return -1;
  }

  servers = server_list;
  return 0;
}

#else

pr_memcache_t *pr_memcache_conn_get(pool *p, time_t expires) {
  errno = ENOSYS;
  return NULL;
}

pr_memcache_t *pr_memcache_conn_new(pool *p, time_t expires) {
  errno = ENOSYS;
  return NULL;
}

int pr_memcache_conn_close(pr_memcache_t *mcache) {
  errno = ENOSYS;
  return -1;
}

int pr_memcache_add(pr_memcache_t *mcache, const char *key, void *value,
    size_t valuesz, uint32_t flags) {
  errno = ENOSYS;
  return -1;
}

void *pr_memcache_get(pr_memcache_t *mcache, const char *key, size_t *valuesz,
    uint32_t *flags) {
  errno = ENOSYS;
  return NULL;
}

char *pr_memcache_get_str(pr_memcache_t *mcache, const char *key,
    uint32_t *flags) {
  errno = ENOSYS;
  return NULL;
}

int pr_memcache_remove(pr_memcache_t *mcache, const char *key) {
  errno = ENOSYS;
  return -1;
}

int pr_memcache_set(pr_memcache_t *mcache, const char *key, void *value,
    size_t valuesz, uint32_t flags) {
  errno = ENOSYS;
  return -1;
}

int pr_memcache_kadd(pr_memcache_t *mcache, const char *key, size_t keysz,
    void *value, size_t valuesz, uint32_t flags) {
  errno = ENOSYS;
  return -1;
}

void *pr_memcache_kget(pr_memcache_t *mcache, const char *key, size_t keysz,
    size_t *valuesz, uint32_t *flags) {
  errno = ENOSYS;
  return NULL;
}

char *pr_memcache_kget_str(pr_memcache_t *mcache, const char *key, size_t keysz,
    uint32_t *flags) {
  errno = ENOSYS;
  return NULL;
}

int pr_memcache_kremove(pr_memcache_t *mcache, const char *key, size_t keysz) {
  errno = ENOSYS;
  return -1;
}

int pr_memcache_kset(pr_memcache_t *mcache, const char *key, size_t keysz,
    void *value, size_t valuesz, uint32_t flags) {
  errno = ENOSYS;
  return -1;
}

unsigned long memcache_get_flags(void) {
  return 0;
}

int memcache_set_flags(unsigned long flags) {
  errno = ENOSYS;
  return -1;
}

int memcache_set_logfd(int fd) {
  errno = ENOSYS;
  return -1;
}

int memcache_set_replicas(uint64_t count) {
  errno = ENOSYS;
  return -1;
}

int memcache_set_servers(void *server_list) {
  errno = ENOSYS;
  return -1;
}

#endif /* PR_USE_MEMCACHE */

