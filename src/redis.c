/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2017 The ProFTPD Project team
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
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* Redis management */

#include "conf.h"

#ifdef PR_USE_REDIS

#include <hiredis/hiredis.h>

struct redis_rec {
  pool *pool;
  module *owner;
  redisContext *ctx;

  /* For tracking the number of "opens"/"closes" on a shared redis_rec,
   * as the same struct might be used by multiple modules in the same
   * session, each module doing a conn_get()/conn_close().
   */
  unsigned int refcount;

  /* Table mapping modules to their namespaces */
  pr_table_t *namespace_tab;
};

static const char *redis_server = NULL;
static int redis_port = -1;

static pr_redis_t *sess_redis = NULL;

static unsigned long redis_connect_millis = 500;
static unsigned long redis_io_millis = 500;

static const char *trace_channel = "redis";

static void millis2timeval(struct timeval *tv, unsigned long millis) {
  tv->tv_sec = (millis / 1000);
  tv->tv_usec = (millis - (tv->tv_sec * 1000)) * 1000;
}

static const char *redis_strerror(pool *p, pr_redis_t *redis, int rerrno) {
  const char *err;

  switch (redis->ctx->err) {
    case REDIS_ERR_IO:
      err = pstrcat(p, "[io] ", strerror(rerrno), NULL);
      break;

    case REDIS_ERR_EOF:
      err = pstrcat(p, "[eof] ", redis->ctx->errstr, NULL);
      break;

    case REDIS_ERR_PROTOCOL:
      err = pstrcat(p, "[protocol] ", redis->ctx->errstr, NULL);
      break;

    case REDIS_ERR_OOM:
      err = pstrcat(p, "[oom] ", redis->ctx->errstr, NULL);
      break;

    case REDIS_ERR_OTHER:
      err = pstrcat(p, "[other] ", redis->ctx->errstr, NULL);
      break;

    case REDIS_OK:
    default:
      err = "OK";
      break;
  }

  return err;
}

static int ping_server(pr_redis_t *redis) {
  const char *cmd;
  redisReply *reply;

  cmd = "PING";
  reply = redisCommand(redis->ctx, "%s", cmd);
  if (reply == NULL) {
    int xerrno;
    pool *tmp_pool;

    xerrno = errno;
    tmp_pool = make_sub_pool(redis->pool);
    pr_trace_msg(trace_channel, 2, "error sending %s command: %s", cmd,
      redis_strerror(tmp_pool, redis, xerrno));

    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  /* We COULD assert a "PONG" response here, but really, anything is OK. */
  pr_trace_msg(trace_channel, 7, "%s reply: %s", cmd, reply->str);
  freeReplyObject(reply);
  return 0;
}

static int stat_server(pr_redis_t *redis) {
  const char *cmd;
  redisReply *reply;

  cmd = "INFO";
  reply = redisCommand(redis->ctx, "%s", cmd);
  if (reply == NULL) {
    int xerrno;
    pool *tmp_pool;

    xerrno = errno;
    tmp_pool = make_sub_pool(redis->pool);
    pr_trace_msg(trace_channel, 2, "error sending %s command: %s", cmd,
      redis_strerror(tmp_pool, redis, xerrno));

    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %s", cmd, reply->str);
  freeReplyObject(reply);
  return 0;
}

pr_redis_t *pr_redis_conn_get(pool *p) {
  if (sess_redis != NULL) {
    sess_redis->refcount++;
    return sess_redis;
  }

  return pr_redis_conn_new(p, NULL, 0UL);
}

static int set_conn_options(pr_redis_t *redis, unsigned long flags) {
  int res, xerrno;
  struct timeval tv;
  pool *tmp_pool;

  tmp_pool = make_sub_pool(redis->pool);

  millis2timeval(&tv, redis_io_millis);
  res = redisSetTimeout(redis->ctx, tv);
  if (res == REDIS_ERR) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 4,
      "error setting %lu ms timeout: %s", redis_io_millis,
      redis_strerror(tmp_pool, redis, xerrno));
  }

  res = redisEnableKeepAlive(redis->ctx);
  if (res == REDIS_ERR) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 4,
      "error setting keepalive: %s", redis_strerror(tmp_pool, redis, xerrno));
  }

  destroy_pool(tmp_pool);
  return 0;
}

pr_redis_t *pr_redis_conn_new(pool *p, module *m, unsigned long flags) {
  int res, xerrno;
  pr_redis_t *redis;
  pool *sub_pool;
  redisContext *ctx;
  struct timeval tv;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (redis_server == NULL) {
    pr_trace_msg(trace_channel, 9, "%s",
      "unable to create new Redis connection: No server configured");
    errno = EPERM;
    return NULL;
  }

  millis2timeval(&tv, redis_connect_millis); 
  ctx = redisConnectWithTimeout(redis_server, redis_port, tv);
  xerrno = errno;

  if (ctx == NULL) {
    errno = ENOMEM;
    return NULL;
  }

  if (ctx->err != 0) {
    const char *err_type, *err_msg;

    switch (ctx->err) {
      case REDIS_ERR_IO:
        err_type = "io";
        err_msg = strerror(xerrno);
        break;

      case REDIS_ERR_EOF:
        err_type = "eof";
        err_msg = ctx->errstr;
        break;

      case REDIS_ERR_PROTOCOL:
        err_type = "protocol";
        err_msg = ctx->errstr;
        break;

      case REDIS_ERR_OOM:
        err_type = "oom";
        err_msg = ctx->errstr;
        break;

      case REDIS_ERR_OTHER:
        err_type = "other";
        err_msg = ctx->errstr;
        break;

      default:
        err_type = "unknown";
        err_msg = ctx->errstr;
        break;
    }

    pr_trace_msg(trace_channel, 3,
      "error connecting to %s#%d: [%s] %s", redis_server, redis_port, err_type,
      err_msg);
    redisFree(ctx);
    errno = EIO;
    return NULL;
  }

  sub_pool = make_sub_pool(p);
  pr_pool_tag(sub_pool, "Redis connection pool");

  redis = pcalloc(sub_pool, sizeof(pr_redis_t));
  redis->pool = sub_pool;
  redis->owner = m;
  redis->ctx = ctx;
  redis->refcount = 1;

  /* The namespace table is null; it will be created if/when callers
   * configure namespace prefixes.
   */
  redis->namespace_tab = NULL;

  /* Set some of the desired behavior flags on the connection */
  res = set_conn_options(redis, flags);
  if (res < 0) {
    xerrno = errno;

    pr_redis_conn_close(redis);
    errno = xerrno;
    return NULL;    
  }

  res = ping_server(redis);
  if (res < 0) {
    xerrno = errno;

    pr_redis_conn_close(redis);
    errno = xerrno;
    return NULL;
  }

  /* Make sure we are connected to the configured server by querying
   * some stats/info from it.
   */
  res = stat_server(redis);
  if (res < 0) {
    xerrno = errno;

    pr_redis_conn_close(redis);
    errno = xerrno;
    return NULL;    
  }

  if (sess_redis == NULL) {
    sess_redis = redis;
  }

  return redis;
}

int pr_redis_conn_close(pr_redis_t *redis) {
  if (redis == NULL) {
    errno = EINVAL;
    return -1;
  }

  redis->refcount--;

  if (redis->refcount == 0) {
    redisFree(redis->ctx);
    redis->ctx = NULL;

    if (redis->namespace_tab != NULL) {
      (void) pr_table_empty(redis->namespace_tab);
      (void) pr_table_free(redis->namespace_tab);
      redis->namespace_tab = NULL;
    }
  }

  destroy_pool(redis->pool);
  return 0;
}

int pr_redis_conn_clone(pool *p, pr_redis_t *redis) {
  errno = ENOSYS;
  return -1;
}

static int modptr_cmp_cb(const void *k1, size_t ksz1, const void *k2,
    size_t ksz2) {

  /* Return zero to indicate a match, non-zero otherwise. */
  return (((module *) k1) == ((module *) k2) ? 0 : 1);
}

static unsigned int modptr_hash_cb(const void *k, size_t ksz) {
  unsigned int key = 0;

  /* XXX Yes, this is a bit hacky for "hashing" a pointer value. */

  memcpy(&key, k, sizeof(key));
  key ^= (key >> 16);

  return key;
}

int pr_redis_conn_set_namespace(pr_redis_t *redis, module *m,
    const char *prefix) {

  if (redis == NULL ||
      m == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (redis->namespace_tab == NULL) {
    pr_table_t *tab;

    tab = pr_table_alloc(redis->pool, 0);

    if (pr_table_ctl(tab, PR_TABLE_CTL_SET_KEY_CMP, modptr_cmp_cb) < 0) {
      pr_trace_msg(trace_channel, 4,
        "error setting key comparison callback for namespace table: %s",
        strerror(errno));
    }

    if (pr_table_ctl(tab, PR_TABLE_CTL_SET_KEY_HASH, modptr_hash_cb) < 0) {
      pr_trace_msg(trace_channel, 4,
        "error setting key hash callback for namespace table: %s",
        strerror(errno));
    }

    redis->namespace_tab = tab;
  }

  if (prefix != NULL) {
    int count;
    size_t prefix_len;

    prefix_len = strlen(prefix);

    count = pr_table_kexists(redis->namespace_tab, m, sizeof(module *));
    if (count <= 0) {
      if (pr_table_kadd(redis->namespace_tab, m, sizeof(module *),
          pstrndup(redis->pool, prefix, prefix_len), prefix_len) < 0) {
        pr_trace_msg(trace_channel, 7,
          "error adding namespace prefix '%s' for module 'mod_%s.c': %s",
          prefix, m->name, strerror(errno));
      }

    } else {
      if (pr_table_kset(redis->namespace_tab, m, sizeof(module *),
          pstrndup(redis->pool, prefix, prefix_len), prefix_len) < 0) {
        pr_trace_msg(trace_channel, 7,
          "error setting namespace prefix '%s' for module 'mod_%s.c': %s",
          prefix, m->name, strerror(errno));
      }
    }

  } else {
    /* A NULL prefix means the caller is removing their namespace maping. */
    (void) pr_table_kremove(redis->namespace_tab, m, sizeof(module *), NULL);
  }

  return 0;
}

int pr_redis_add(pr_redis_t *redis, module *m, const char *key, void *value,
    size_t valuesz, time_t expires) {
  int res;

  /* XXX Should we allow null values to be added, thus allowing use of keys
   * as sentinels?
   */
  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      value == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_kadd(redis, m, key, strlen(key), value, valuesz, expires);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error adding key '%s', value (%lu bytes): %s", key,
      (unsigned long) valuesz, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_decr(pr_redis_t *redis, module *m, const char *key, uint32_t decr,
    uint64_t *value) {
  int res;

  /* XXX Should we allow null values to be added, thus allowing use of keys
   * as sentinels?
   */
  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      decr == 0) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_kdecr(redis, m, key, strlen(key), decr, value);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error decrementing key '%s' by %lu: %s", key,
      (unsigned long) decr, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

void *pr_redis_get(pool *p, pr_redis_t *redis, module *m, const char *key,
    size_t *valuesz) {
  void *ptr = NULL;

  if (p == NULL ||
      redis == NULL ||
      m == NULL ||
      key == NULL ||
      valuesz == NULL) {
    errno = EINVAL;
    return NULL;
  }

  ptr = pr_redis_kget(p, redis, m, key, strlen(key), valuesz);
  if (ptr == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error getting data for key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  return ptr;
}

char *pr_redis_get_str(pool *p, pr_redis_t *redis, module *m, const char *key) {
  char *ptr = NULL;

  if (p == NULL ||
      redis == NULL ||
      m == NULL ||
      key == NULL) {
    errno = EINVAL;
    return NULL;
  }

  ptr = pr_redis_kget_str(p, redis, m, key, strlen(key));
  if (ptr == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error getting data for key '%s': %s", key, strerror(xerrno));

    errno = xerrno; 
    return NULL;
  }

  return ptr;
}

int pr_redis_incr(pr_redis_t *redis, module *m, const char *key, uint32_t incr,
    uint64_t *value) {
  int res;

  /* XXX Should we allow null values to be added, thus allowing use of keys
   * as sentinels?
   */
  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      incr == 0) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_kincr(redis, m, key, strlen(key), incr, value);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error incrementing key '%s' by %lu: %s", key,
      (unsigned long) incr, strerror(xerrno));
 
    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_remove(pr_redis_t *redis, module *m, const char *key) {
  int res;

  if (redis == NULL ||
      m == NULL ||
      key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_kremove(redis, m, key, strlen(key));
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error removing key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_set(pr_redis_t *redis, module *m, const char *key, void *value,
    size_t valuesz, time_t expires) {
  int res;

  /* XXX Should we allow null values to be added, thus allowing use of keys
   * as sentinels?
   */
  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      value == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_kset(redis, m, key, strlen(key), value, valuesz, expires);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error setting key '%s', value (%lu bytes): %s", key,
      (unsigned long) valuesz, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

static const char *get_namespace_prefix(pr_redis_t *redis, module *m) {
  const char *prefix = NULL;

  if (m != NULL &&
      redis->namespace_tab != NULL) {
    const char *v;

    v = pr_table_kget(redis->namespace_tab, m, sizeof(module *), NULL);
    if (v != NULL) {
      pr_trace_msg(trace_channel, 25,
        "using namespace prefix '%s' for module 'mod_%s.c'", v, m->name);

      prefix = v;
    }
  }

  return prefix;
}

static const char *get_reply_type(redisReply *reply) {
  const char *type_name;

  switch (reply->type) {
    case REDIS_REPLY_STRING:
      type_name = "STRING";
      break;

    case REDIS_REPLY_ARRAY:
      type_name = "ARRAY";
      break;

    case REDIS_REPLY_INTEGER:
      type_name = "INTEGER";
      break;

    case REDIS_REPLY_NIL:
      type_name = "NIL";
      break;

    case REDIS_REPLY_STATUS:
      type_name = "STATUS";
      break;

    case REDIS_REPLY_ERROR:
      type_name = "ERROR";
      break;

    default:
      type_name = "unknown";
  }

  return type_name;
}

int pr_redis_kadd(pr_redis_t *redis, module *m, const char *key, size_t keysz,
    void *value, size_t valuesz, time_t expires) {
  return pr_redis_kset(redis, m, key, keysz, value, valuesz, expires);
}

int pr_redis_kdecr(pr_redis_t *redis, module *m, const char *key, size_t keysz,
    uint32_t decr, uint64_t *value) {
  int xerrno;
  pool *tmp_pool = NULL;
  const char *cmd = NULL, *namespace_prefix;
  redisReply *reply;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      decr == 0) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis DECRBY pool");

  namespace_prefix = get_namespace_prefix(redis, m);
  if (namespace_prefix != NULL) {
    key = pstrcat(tmp_pool, namespace_prefix, key, NULL);
  }

  cmd = "DECRBY";
  reply = redisCommand(redis->ctx, "%s %b %lu", cmd, key, keysz,
    (unsigned long) decr);
  xerrno = errno;

  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error decrementing key (%lu bytes) by %lu using %s: %s",
      (unsigned long) keysz, (unsigned long) decr, cmd,
      redis_strerror(tmp_pool, redis, xerrno));
    destroy_pool(tmp_pool);
    errno = EIO;
    return -1;
  }

  if (reply->type != REDIS_REPLY_INTEGER) {
    pr_trace_msg(trace_channel, 2,
      "expected INTEGER reply for %s, got %s", cmd, get_reply_type(reply));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  /* Note: DECRBY will automatically set the key value to zero if it does
   * not already exist.  To detect a nonexistent key, then, we look to
   * see if the return value is exactly our requested decrement.  If so,
   * REMOVE the auto-created key, and return ENOENT.
   */
  if ((decr * -1) == (uint32_t) reply->integer) {
    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    (void) pr_redis_kremove(redis, m, key, keysz);
    errno = ENOENT;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %lld", cmd, reply->integer);

  if (value != NULL) {
    *value = (uint64_t) reply->integer;
  }

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return 0;
}

void *pr_redis_kget(pool *p, pr_redis_t *redis, module *m, const char *key,
    size_t keysz, size_t *valuesz) {
  int xerrno = 0;
  const char *cmd, *namespace_prefix;
  pool *tmp_pool;
  redisReply *reply;
  char *data = NULL;

  if (p == NULL ||
      redis == NULL ||
      m == NULL ||
      key == NULL ||
      valuesz == NULL) {
    errno = EINVAL;
    return NULL;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis GET pool");

  namespace_prefix = get_namespace_prefix(redis, m);
  if (namespace_prefix != NULL) {
    key = pstrcat(tmp_pool, namespace_prefix, key, NULL);
  }

  cmd = "GET";
  reply = redisCommand(redis->ctx, "%s %b", cmd, key, keysz);
  xerrno = errno;

  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error getting data for key (%lu bytes) using %s: %s",
      (unsigned long) keysz, cmd, redis_strerror(tmp_pool, redis, xerrno));
    destroy_pool(tmp_pool);
    errno = EIO;
    return NULL;
  }

  if (reply->type == REDIS_REPLY_NIL) {
    pr_trace_msg(trace_channel, 7, "%s reply: Nil", cmd);
    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = ENOENT;
    return NULL;
  }

  if (reply->type != REDIS_REPLY_STRING) {
    pr_trace_msg(trace_channel, 2,
      "expected STRING reply for %s, got %s", cmd, get_reply_type(reply));
    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return NULL;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %.*s", cmd, (int) reply->len,
    reply->str);

  if (valuesz != NULL) {
    *valuesz = (uint64_t) reply->len;
  }

  data = palloc(p, reply->len);
  memcpy(data, reply->str, reply->len);

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return data;
}

char *pr_redis_kget_str(pool *p, pr_redis_t *redis, module *m, const char *key,
    size_t keysz) {
  int xerrno = 0;
  const char *cmd, *namespace_prefix;
  pool *tmp_pool;
  redisReply *reply;
  char *data = NULL;

  if (p == NULL ||
      redis == NULL ||
      m == NULL ||
      key == NULL) {
    errno = EINVAL;
    return NULL;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis GET pool");

  namespace_prefix = get_namespace_prefix(redis, m);
  if (namespace_prefix != NULL) {
    key = pstrcat(tmp_pool, namespace_prefix, key, NULL);
  }

  cmd = "GET";
  reply = redisCommand(redis->ctx, "%s %b", cmd, key, keysz);
  xerrno = errno;

  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error getting data for key (%lu bytes) using %s: %s",
      (unsigned long) keysz, cmd, redis_strerror(tmp_pool, redis, xerrno));
    destroy_pool(tmp_pool);
    errno = EIO;
    return NULL;
  }

  if (reply->type == REDIS_REPLY_NIL) {
    pr_trace_msg(trace_channel, 7, "%s reply: Nil", cmd);
    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = ENOENT;
    return NULL;
  }

  if (reply->type != REDIS_REPLY_STRING) {
    pr_trace_msg(trace_channel, 2,
      "expected STRING reply for %s, got %s", cmd, get_reply_type(reply));
    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return NULL;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %.*s", cmd, (int) reply->len,
    reply->str);

  data = pstrndup(p, reply->str, reply->len);

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return data;
}

int pr_redis_kincr(pr_redis_t *redis, module *m, const char *key, size_t keysz,
    uint32_t incr, uint64_t *value) {
  int xerrno;
  pool *tmp_pool = NULL;
  const char *cmd = NULL, *namespace_prefix;
  redisReply *reply;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      incr == 0) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis INCRRBY pool");

  namespace_prefix = get_namespace_prefix(redis, m);
  if (namespace_prefix != NULL) {
    key = pstrcat(tmp_pool, namespace_prefix, key, NULL);
  }

  cmd = "INCRBY";
  reply = redisCommand(redis->ctx, "%s %b %lu", cmd, key, keysz,
    (unsigned long) incr);
  xerrno = errno;

  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error incrementing key (%lu bytes) by %lu using %s: %s",
      (unsigned long) keysz, (unsigned long) incr, cmd,
      redis_strerror(tmp_pool, redis, xerrno));
    destroy_pool(tmp_pool);
    errno = EIO;
    return -1;
  }

  if (reply->type != REDIS_REPLY_INTEGER) {
    pr_trace_msg(trace_channel, 2,
      "expected INTEGER reply for %s, got %s", cmd, get_reply_type(reply));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  /* Note: INCRBY will automatically set the key value to zero if it does
   * not already exist.  To detect a nonexistent key, then, we look to
   * see if the return value is exactly our requested increment.  If so,
   * REMOVE the auto-created key, and return ENOENT.
   */
  if (incr == (uint32_t) reply->integer) {
    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    (void) pr_redis_kremove(redis, m, key, keysz);
    errno = ENOENT;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %lld", cmd, reply->integer);

  if (value != NULL) {
    *value = (uint64_t) reply->integer;
  }

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return 0;
}

int pr_redis_kremove(pr_redis_t *redis, module *m, const char *key,
    size_t keysz) {
  int xerrno = 0;
  pool *tmp_pool = NULL;
  const char *cmd = NULL, *namespace_prefix;
  redisReply *reply;
  long long count;

  if (redis == NULL ||
      m == NULL ||
      key == NULL) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis DEL pool");

  namespace_prefix = get_namespace_prefix(redis, m);
  if (namespace_prefix != NULL) {
    key = pstrcat(tmp_pool, namespace_prefix, key, NULL);
  }

  cmd = "DEL";
  reply = redisCommand(redis->ctx, "%s %b", cmd, key, keysz);
  xerrno = errno;

  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error removing key (%lu bytes): %s", (unsigned long) keysz,
      redis_strerror(tmp_pool, redis, xerrno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_INTEGER) {
    pr_trace_msg(trace_channel, 2,
      "expected INTEGER reply for %s, got %s", cmd, get_reply_type(reply));
    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %lld", cmd, reply->integer);
  count = reply->integer;

  freeReplyObject(reply);
  destroy_pool(tmp_pool);

  if (count == 0) {
    /* No keys removed. */
    errno = ENOENT;
    return -1;
  }

  return 0;
}

int pr_redis_kset(pr_redis_t *redis, module *m, const char *key, size_t keysz,
    void *value, size_t valuesz, time_t expires) {
  int xerrno = 0;
  pool *tmp_pool = NULL;
  const char *cmd = NULL, *namespace_prefix;
  redisReply *reply;

  /* XXX Should we allow null values to be added, thus allowing use of keys
   * as sentinels?
   */
  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      value == NULL) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis SET pool");

  namespace_prefix = get_namespace_prefix(redis, m);
  if (namespace_prefix != NULL) {
    key = pstrcat(tmp_pool, namespace_prefix, key, NULL);
  }

  if (expires > 0) {
    cmd = "SETEX";
    reply = redisCommand(redis->ctx, "%s %b %lu %b", cmd, key, keysz,
      (unsigned long) expires, value, valuesz);

  } else {
    cmd = "SET";
    reply = redisCommand(redis->ctx, "%s %b %b", cmd, key, keysz, value,
      valuesz);
  }

  xerrno = errno;

  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error adding key (%lu bytes), value (%lu bytes) using %s: %s",
      (unsigned long) keysz, (unsigned long) valuesz, cmd,
      redis_strerror(tmp_pool, redis, xerrno));
    destroy_pool(tmp_pool);
    errno = EIO;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %s", cmd, reply->str);
  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return 0;
}

int redis_set_server(const char *server, int port) {
  if (server == NULL ||
      port < 1) {
    errno = EINVAL;
    return -1;
  }

  redis_server = server;
  redis_port = port;
  return 0;
}

int redis_set_timeouts(unsigned long connect_millis, unsigned long io_millis) {
  redis_connect_millis = connect_millis;
  redis_io_millis = io_millis;

  return 0;
}

int redis_clear(void) {
  if (sess_redis != NULL) {
    pr_redis_conn_close(sess_redis);
    sess_redis = NULL;
  }

  return 0;
}

int redis_init(void) {
  return 0;
}

#else

pr_redis_t *pr_redis_conn_get(pool *p) {
  errno = ENOSYS;
  return NULL;
}

pr_redis_t *pr_redis_conn_new(pool *p, module *m, unsigned long flags) {
  errno = ENOSYS;
  return NULL;
}

int pr_redis_conn_close(pr_redis_t *redis) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_conn_clone(pool *p, pr_redis_t *redis) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_conn_set_namespace(pr_redis_t *redis, module *m,
    const char *prefix) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_add(pr_redis_t *redis, module *m, const char *key, void *value,
    size_t valuesz, time_t expires) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_decr(pr_redis_t *redis, module *m, const char *key, uint32_t decr,
    uint64_t *value) {
  errno = ENOSYS;
  return -1;
}

void *pr_redis_get(pool *p, pr_redis_t *redis, module *m, const char *key,
    size_t *valuesz) {
  errno = ENOSYS;
  return NULL;
}

char *pr_redis_get_str(pool *p, pr_redis_t *redis, module *m, const char *key) {
  errno = ENOSYS;
  return NULL;
}

int pr_redis_incr(pr_redis_t *redis, module *m, const char *key, uint32_t incr,
    uint64_t *value) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_remove(pr_redis_t *redis, module *m, const char *key) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_set(pr_redis_t *redis, module *m, const char *key, void *value,
    size_t valuesz, time_t expires) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_kadd(pr_redis_t *redis, module *m, const char *key, size_t keysz,
    void *value, size_t valuesz, time_t expires) {
  errno = ENOSYS;
  return -1;
}

void *pr_redis_kget(pool *p, pr_redis_t *redis, module *m, const char *key,
    size_t keysz, size_t *valuesz) {
  errno = ENOSYS;
  return NULL;
}

char *pr_redis_kget_str(pool *p, pr_redis_t *redis, module *m, const char *key,
    size_t keysz) {
  errno = ENOSYS;
  return NULL;
}

int pr_redis_kremove(pr_redis_t *redis, module *m, const char *key,
    size_t keysz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_kset(pr_redis_t *redis, module *m, const char *key, size_t keysz,
    void *value, size_t valuesz, time_t expires) {
  errno = ENOSYS;
  return -1;
}

int redis_set_server(const char *server, int port) {
  errno = ENOSYS;
  return -1;
}

int redis_set_timeouts(unsigned long conn_millis, unsigned long io_millis) {
  errno = ENOSYS;
  return -1;
}

int redis_clear(void) {
  errno = ENOSYS;
  return -1;
}

int redis_init(void) {
  errno = ENOSYS;
  return -1;
}

#endif /* PR_USE_REDIS */
