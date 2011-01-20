/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2010-2011 The ProFTPD Project team
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
 * $Id: memcache.c,v 1.8 2011-01-20 02:04:45 castaglia Exp $
 */

#include "conf.h"

#ifdef PR_USE_MEMCACHE

#include <libmemcached/memcached.h>

#if defined(LIBMEMCACHED_VERSION_HEX)
# if LIBMEMCACHED_VERSION_HEX < 0x00037000
#  error "libmemcached-0.37 or later required"
# endif /* LIBMEMCACHED_VERSION_HEX too old */
#else
# error "Unable to determine libmemcached version"
#endif /* LIBMEMCACHED_VERSION_HEX */

extern tpl_hook_t tpl_hook;

struct mcache_rec {
  pool *pool;
  module *owner;
  memcached_st *mc;
};

static memcached_server_st *servers = NULL;
static pr_memcache_t *sess_mcache = NULL;

static unsigned long memcache_sess_flags = 0;
static uint64_t memcache_sess_nreplicas = 0;

static unsigned long memcache_conn_ms = 500;
static unsigned long memcache_rcv_ms = 500;
static unsigned long memcache_snd_ms = 500;

static const char *trace_channel = "memcache";

pr_memcache_t *pr_memcache_conn_get(void) {
  if (sess_mcache != NULL) {
    return sess_mcache;
  }

  return pr_memcache_conn_new(session.pool, NULL, memcache_sess_flags,
    memcache_sess_nreplicas);
}

pr_memcache_t *pr_memcache_conn_new(pool *p, module *m, unsigned long flags,
    uint64_t nreplicas) {
  pr_memcache_t *mcache;
  pool *sub_pool;
  memcached_st *mc;
  memcached_stat_st *mst;
  memcached_return res;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (servers == NULL) {
    pr_trace_msg(trace_channel, 9, "%s",
      "unable to create new memcache connection: No servers configured");
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
    pr_trace_msg(trace_channel, 2,
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
  mcache->owner = m;
  mcache->mc = mc;

  /* Set some of the desired behavior flags on the connection */
  if (memcached_behavior_get(mc, MEMCACHED_BEHAVIOR_TCP_NODELAY) != 1) {
    res = memcached_behavior_set(mc, MEMCACHED_BEHAVIOR_TCP_NODELAY, 1);
    if (res != MEMCACHED_SUCCESS) {
      pr_trace_msg(trace_channel, 4,
        "error setting TCP_NODELAY behavior on connection: %s",
        memcached_strerror(mc, res));
    }
  }

  /* Enable caching of DNS lookups. */
  if (memcached_behavior_get(mc, MEMCACHED_BEHAVIOR_CACHE_LOOKUPS) != 1) {
    res = memcached_behavior_set(mc, MEMCACHED_BEHAVIOR_CACHE_LOOKUPS, 1);
    if (res != MEMCACHED_SUCCESS) {
      pr_trace_msg(trace_channel, 4,
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
      pr_trace_msg(trace_channel, 4,
        "error setting DISTRIBUTION_CONSISTENT behavior on connection: %s",
        memcached_strerror(mc, res));
    }
  }

  /* Use blocking IO */
  if (memcached_behavior_get(mc, MEMCACHED_BEHAVIOR_NO_BLOCK) != 0) {
    res = memcached_behavior_set(mc, MEMCACHED_BEHAVIOR_NO_BLOCK, 0);
    if (res != MEMCACHED_SUCCESS) {
      pr_trace_msg(trace_channel, 4,
        "error setting NO_BLOCK behavior on connection: %s",
        memcached_strerror(mc, res));
    }
  }

  /* Use the binary protocol by default, unless explicitly requested not to. */
  if (memcached_behavior_get(mc, MEMCACHED_BEHAVIOR_BINARY_PROTOCOL) != 1) {
    if (!(flags & PR_MEMCACHE_FL_NO_BINARY_PROTOCOL)) {
      res = memcached_behavior_set(mc, MEMCACHED_BEHAVIOR_BINARY_PROTOCOL, 1);
      if (res != MEMCACHED_SUCCESS) {
        pr_trace_msg(trace_channel, 4,
          "error setting BINARY_PROTOCOL behavior on connection: %s",
          memcached_strerror(mc, res));
      }
    }
  }

  /* Configure the timeouts. */
  res = memcached_behavior_set(mc, MEMCACHED_BEHAVIOR_CONNECT_TIMEOUT,
    memcache_conn_ms * 1000);
  if (res != MEMCACHED_SUCCESS) {
    pr_trace_msg(trace_channel, 4,
      "error setting CONNECT_TIMEOUT behavior on connection to %lu ms: %s",
      memcache_conn_ms, memcached_strerror(mc, res));
  }

  res = memcached_behavior_set(mc, MEMCACHED_BEHAVIOR_RCV_TIMEOUT,
    memcache_rcv_ms * 1000);
  if (res != MEMCACHED_SUCCESS) {
    pr_trace_msg(trace_channel, 4,
      "error setting RCV_TIMEOUT behavior on connection to %lu ms: %s",
      memcache_rcv_ms, memcached_strerror(mc, res));
  }

  res = memcached_behavior_set(mc, MEMCACHED_BEHAVIOR_SND_TIMEOUT,
    memcache_snd_ms * 1000);
  if (res != MEMCACHED_SUCCESS) {
    pr_trace_msg(trace_channel, 4,
      "error setting SND_TIMEOUT behavior on connection to %lu ms: %s",
      memcache_snd_ms, memcached_strerror(mc, res));
  }

  /* Make sure that the requested number of replicas does not exceed the
   * server count.
   */
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
      pr_trace_msg(trace_channel, 4,
        "error setting NUMBER_OF_REPLICAS behavior on connection: %s",
        memcached_strerror(mc, res));

    } else {
      pr_trace_msg(trace_channel, 9, "storing %lu replicas",
        (unsigned long) nreplicas);
    }
  }

  /* XXX Other behavior to play with:
   *  MEMCACHED_BEHAVIOR_RANDOMIZE_REPLICA_READ
   */

  /* Make sure we are connected to the configured servers by querying
   * some stats/info from them.
   */
  mst = memcached_stat(mc, NULL, &res);
  if (mst != NULL) {
    if (res == MEMCACHED_SUCCESS) {
      register unsigned int i;
      const char *stat_keys[] = {
        "version",
        "uptime",
        "curr_connections",
        "curr_items",
        "bytes",
        "limit_maxbytes",
        NULL
      };

      /* Log some of the stats about the memcached servers to which we just
       * connected.
       */  

      for (i = 0; stat_keys[i] != NULL; i++) {
        char *val;

        val = memcached_stat_get_value(mc, mst, "uptime", &res);
        if (val != NULL) {
          pr_trace_msg(trace_channel, 9,
            "memcached servers stats: %s = %s", stat_keys[i], val);
          free(val);

        } else {
          pr_trace_msg(trace_channel, 6,
            "unable to obtain '%s' stat: %s", stat_keys[i],
            memcached_strerror(mc, res));
        }
      }

    } else {
      switch (res) {
        case MEMCACHED_ERRNO:
          if (errno != EINPROGRESS) {
            pr_trace_msg(trace_channel, 3,
              "error requesting memcached stats: system error: %s",
              strerror(errno));
            break;

          } else {
            /* We know that we're not using nonblocking IO; this value usually
             * means that libmemcached could not connect to the configured
             * memcached servers.  So set the value to something more
             * indicative, and fall through.
             */
            res = MEMCACHED_CONNECTION_FAILURE;
          }

        default:
          pr_trace_msg(trace_channel, 6,
            "error requesting memcached stats: %s",
            memcached_strerror(mc, res));
          break;
      }
    }

    memcached_stat_free(mc, mst);
  }

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
    size_t valuesz, time_t expires, uint32_t flags) {
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

  res = pr_memcache_kadd(mcache, key, strlen(key), value, valuesz, expires,
    flags); 
  if (res < 0) {
    pr_trace_msg(trace_channel, 2,
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
    pr_trace_msg(trace_channel, 2,
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
    pr_trace_msg(trace_channel, 2,
      "error getting data for key '%s': %s", key, strerror(errno));
    errno = EPERM;
    return NULL;
  }

  return ptr;
}

int pr_memcache_remove(pr_memcache_t *mcache, const char *key, time_t expires) {
  int res;

  if (mcache == NULL ||
      key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_memcache_kremove(mcache, key, strlen(key), expires);
  if (res < 0) {
    pr_trace_msg(trace_channel, 2,
      "error removing key '%s': %s", key, strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

int pr_memcache_set(pr_memcache_t *mcache, const char *key, void *value,
    size_t valuesz, time_t expires, uint32_t flags) {
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

  res = pr_memcache_kset(mcache, key, strlen(key), value, valuesz, expires,
    flags);
  if (res < 0) {
    pr_trace_msg(trace_channel, 2,
      "error setting key '%s', value (%lu bytes): %s", key,
      (unsigned long) valuesz, strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

int pr_memcache_kadd(pr_memcache_t *mcache, const char *key, size_t keysz,
    void *value, size_t valuesz, time_t expires, uint32_t flags) {
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

  res = memcached_add(mcache->mc, key, keysz, value, valuesz, expires, flags); 
  switch (res) {
    case MEMCACHED_SUCCESS:
      return 0;

    case MEMCACHED_ERRNO:
      if (errno != EINPROGRESS) {
        pr_trace_msg(trace_channel, 3,
          "error adding key (%lu bytes), value (%lu bytes): system error: %s",
          (unsigned long) keysz, (unsigned long) valuesz, strerror(errno));
        break;

      } else {
        /* We know that we're not using nonblocking IO; this value usually
         * means that libmemcached could not connect to the configured
         * memcached servers.  So set the value to something more
         * indicative, and fall through.
         */
        res = MEMCACHED_CONNECTION_FAILURE;
      }

    default:
      pr_trace_msg(trace_channel, 2,
        "error adding key (%lu bytes), value (%lu bytes): %s",
        (unsigned long) keysz, (unsigned long) valuesz,
        memcached_strerror(mcache->mc, res));
      errno = EPERM;
  }

  return -1;
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
    switch (res) {
      case MEMCACHED_NOTFOUND:
        pr_trace_msg(trace_channel, 8,
          "no data found for key (%lu bytes)", (unsigned long) keysz);
        errno = ENOENT;
        break;

      case MEMCACHED_ERRNO:
        if (errno != EINPROGRESS) {
          pr_trace_msg(trace_channel, 3,
            "no data found for key (%lu bytes): system error: %s",
            (unsigned long) keysz, strerror(errno));
          break;

        } else {
          /* We know that we're not using nonblocking IO; this value usually
           * means that libmemcached could not connect to the configured
           * memcached servers.  So set the value to something more
           * indicative, and fall through.
           */
          res = MEMCACHED_CONNECTION_FAILURE;
        }

      default:
        pr_trace_msg(trace_channel, 6,
          "error getting data for key (%lu bytes): [%d] %s",
          (unsigned long) keysz, res, memcached_strerror(mcache->mc, res));
        errno = EPERM;
        break;
    }

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
    switch (res) {
      case MEMCACHED_NOTFOUND:
        pr_trace_msg(trace_channel, 8,
          "no data found for key (%lu bytes)", (unsigned long) keysz);
        errno = ENOENT;
        break;

      case MEMCACHED_ERRNO:
        if (errno != EINPROGRESS) {
          pr_trace_msg(trace_channel, 3,
            "no data found for key (%lu bytes): system error: %s",
            (unsigned long) keysz, strerror(errno));
          break;

        } else {
          /* We know that we're not using nonblocking IO; this value usually
           * means that libmemcached could not connect to the configured
           * memcached servers.  So set the value to something more
           * indicative, and fall through.
           */
          res = MEMCACHED_CONNECTION_FAILURE;
        }

      default:
        pr_trace_msg(trace_channel, 6,
          "error getting data for key (%lu bytes): [%d] %s",
          (unsigned long) keysz, res, memcached_strerror(mcache->mc, res));
        errno = EPERM;
        break;
    }

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

int pr_memcache_kremove(pr_memcache_t *mcache, const char *key, size_t keysz,
    time_t expires) {
  memcached_return res;

  if (mcache == NULL ||
      key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = memcached_delete(mcache->mc, key, keysz, expires);
  switch (res) {
    case MEMCACHED_SUCCESS:
      return 0;

    case MEMCACHED_ERRNO:
      if (errno != EINPROGRESS) {
        pr_trace_msg(trace_channel, 3,
          "error removing key (%lu bytes): system error: %s",
          (unsigned long) keysz, strerror(errno));
        break;

      } else {
        /* We know that we're not using nonblocking IO; this value usually
         * means that libmemcached could not connect to the configured
         * memcached servers.  So set the value to something more
         * indicative, and fall through.
         */
        res = MEMCACHED_CONNECTION_FAILURE;
      }

    default:
      pr_trace_msg(trace_channel, 2,
        "error removing key (%lu bytes): %s", (unsigned long) keysz,
        memcached_strerror(mcache->mc, res));
      errno = EPERM;
  }

  return -1;
}

int pr_memcache_kset(pr_memcache_t *mcache, const char *key, size_t keysz,
    void *value, size_t valuesz, time_t expires, uint32_t flags) {
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

  res = memcached_set(mcache->mc, key, keysz, value, valuesz, expires, flags); 
  switch (res) {
    case MEMCACHED_SUCCESS:
      return 0;

    case MEMCACHED_ERRNO:
      if (errno != EINPROGRESS) {
        pr_trace_msg(trace_channel, 3,
          "error setting key (%lu bytes), value (%lu bytes): system error: %s",
          (unsigned long) keysz, (unsigned long) valuesz, strerror(errno));
        break;

      } else {
        /* We know that we're not using nonblocking IO; this value usually
         * means that libmemcached could not connect to the configured
         * memcached servers.  So set the value to something more
         * indicative, and fall through.
         */
        res = MEMCACHED_CONNECTION_FAILURE;
      }

    default:
      pr_trace_msg(trace_channel, 2,
        "error setting key (%lu bytes), value (%lu bytes): %s",
        (unsigned long) keysz, (unsigned long) valuesz,
        memcached_strerror(mcache->mc, res));
      errno = EPERM;
  }

  return -1;
}

unsigned long memcache_get_sess_flags(void) {
  return memcache_sess_flags;
}

int memcache_set_sess_flags(unsigned long flags) {
  memcache_sess_flags = flags;
  return 0;
}

int memcache_set_sess_replicas(uint64_t count) {
  if (count < 1) {
    errno = EINVAL;
    return -1;
  }

  memcache_sess_nreplicas = count;
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

int memcache_set_timeouts(unsigned long conn_ms, unsigned long read_ms,
    unsigned long write_ms) {
  memcache_conn_ms = conn_ms;
  memcache_rcv_ms = read_ms;
  memcache_snd_ms = write_ms;

  return 0;
}

static int memcache_tpl_oops(const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  pr_trace_vmsg(trace_channel, 1, fmt, ap);
  va_end(ap);

  /* XXX Does tpl check the return value of its oops() hook? */
  return 0;
}

static void memcache_tpl_fatal(char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  pr_trace_vmsg(trace_channel, 1, fmt, ap);
  va_end(ap);

  _exit(1);
}

int memcache_init(void) {

  /* Set the tpl callbacks */
  tpl_hook.oops = memcache_tpl_oops;
  tpl_hook.fatal = memcache_tpl_fatal;

  return 0;
}

#else

pr_memcache_t *pr_memcache_conn_get(void) {
  errno = ENOSYS;
  return NULL;
}

pr_memcache_t *pr_memcache_conn_new(pool *p, module *m, unsigned long flags,
    uint64_t nreplicas) {
  errno = ENOSYS;
  return NULL;
}

int pr_memcache_conn_close(pr_memcache_t *mcache) {
  errno = ENOSYS;
  return -1;
}

int pr_memcache_add(pr_memcache_t *mcache, const char *key, void *value,
    size_t valuesz, time_t expires, uint32_t flags) {
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

int pr_memcache_remove(pr_memcache_t *mcache, const char *key, time_t expires) {
  errno = ENOSYS;
  return -1;
}

int pr_memcache_set(pr_memcache_t *mcache, const char *key, void *value,
    size_t valuesz, time_t expires, uint32_t flags) {
  errno = ENOSYS;
  return -1;
}

int pr_memcache_kadd(pr_memcache_t *mcache, const char *key, size_t keysz,
    void *value, size_t valuesz, time_t expires, uint32_t flags) {
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

int pr_memcache_kremove(pr_memcache_t *mcache, const char *key, size_t keysz,
    time_t expires) {
  errno = ENOSYS;
  return -1;
}

int pr_memcache_kset(pr_memcache_t *mcache, const char *key, size_t keysz,
    void *value, size_t valuesz, time_t expires, uint32_t flags) {
  errno = ENOSYS;
  return -1;
}

unsigned long memcache_get_sess_flags(void) {
  return 0;
}

int memcache_set_sess_flags(unsigned long flags) {
  errno = ENOSYS;
  return -1;
}

int memcache_set_sess_replicas(uint64_t count) {
  errno = ENOSYS;
  return -1;
}

int memcache_set_servers(void *server_list) {
  errno = ENOSYS;
  return -1;
}

int memcache_set_timeouts(unsigned long conn_ms, unsigned long read_ms,
    unsigned long write_ms) {
  errno = ENOSYS;
  return -1;
}

int memcache_init(void) {
  errno = ENOSYS;
  return -1;
}

#endif /* PR_USE_MEMCACHE */

