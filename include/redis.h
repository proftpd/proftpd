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

/* Redis support */

#ifndef PR_REDIS_H
#define PR_REDIS_H

#include "conf.h"

typedef struct redis_rec pr_redis_t;

/* Core API for use by modules et al */

/* This function returns the pr_redis_t for the current session; if one
 * does not exist, it will be allocated.
 */
pr_redis_t *pr_redis_conn_get(pool *p);
pr_redis_t *pr_redis_conn_new(pool *p, module *owner, unsigned long flags);
int pr_redis_conn_close(pr_redis_t *redis);

/* Given an existing handle, quit that handle, and clone the internal
 * structures.  This is to be used by modules which need to get their own
 * process-specific handle, using a handle inherited from their parent process.
 */
int pr_redis_conn_clone(pool *p, pr_redis_t *redis);

/* Set a namespace key prefix, to be used by this connection for all of the
 * operations involving items.  In practice, the key prefix should always
 * be a string which does contain any space characters.
 *
 * Different modules can use different namespace prefixes for their keys.
 * Setting NULL for the namespace prefix clears it.
 */
int pr_redis_conn_set_namespace(pr_redis_t *redis, module *m,
  const char *prefix);

int pr_redis_add(pr_redis_t *redis, module *m, const char *key,
  void *value, size_t valuesz, time_t expires);
int pr_redis_decr(pr_redis_t *redis, module *m, const char *key, uint32_t decr,
  uint64_t *value);
void *pr_redis_get(pool *p, pr_redis_t *redis, module *m, const char *key,
  size_t *valuesz);
char *pr_redis_get_str(pool *p, pr_redis_t *redis, module *m, const char *key);
int pr_redis_incr(pr_redis_t *redis, module *m, const char *key, uint32_t incr,
  uint64_t *value);
int pr_redis_remove(pr_redis_t *redis, module *m, const char *key);
int pr_redis_set(pr_redis_t *redis, module *m, const char *key, void *value,
  size_t valuesz, time_t expires);

/* Variants of the above, where the key values are arbitrary bits rather
 * than being assumed to be strings.
 */
int pr_redis_kadd(pr_redis_t *redis, module *m, const char *key, size_t keysz,
  void *value, size_t valuesz, time_t expires);
int pr_redis_kdecr(pr_redis_t *redis, module *m, const char *key, size_t keysz,
  uint32_t decr, uint64_t *value);
void *pr_redis_kget(pool *p, pr_redis_t *redis, module *m, const char *key,
  size_t keysz, size_t *valuesz);
char *pr_redis_kget_str(pool *p, pr_redis_t *redis, module *m, const char *key,
  size_t keysz);
int pr_redis_kincr(pr_redis_t *redis, module *m, const char *key, size_t keysz,
  uint32_t incr, uint64_t *value);
int pr_redis_kremove(pr_redis_t *redis, module *m, const char *key,
  size_t keysz);
int pr_redis_kset(pr_redis_t *redis, module *m, const char *key, size_t keysz,
  void *value, size_t valuesz, time_t expires);

/* For internal use only */

int redis_set_server(const char *server, int port);
int redis_set_timeouts(unsigned long connect_millis, unsigned long io_millis);

int redis_clear(void);
int redis_init(void);

#endif /* PR_REDIS_H */
