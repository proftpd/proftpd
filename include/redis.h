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
int pr_redis_conn_destroy(pr_redis_t *redis);

/* Set a namespace key prefix, to be used by this connection for all of the
 * operations involving items.  In practice, the key prefix should always
 * be a string which does contain any space characters.
 *
 * Different modules can use different namespace prefixes for their keys.
 * Setting NULL for the namespace prefix clears it.
 */
int pr_redis_conn_set_namespace(pr_redis_t *redis, module *m,
  const char *prefix);

int pr_redis_add(pr_redis_t *redis, module *m, const char *key, void *value,
  size_t valuesz, time_t expires);
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

/* Hash operations */
int pr_redis_hash_count(pr_redis_t *redis, module *m, const char *key,
  uint64_t *count);
int pr_redis_hash_delete(pr_redis_t *redis, module *m, const char *key,
  const char *field);
int pr_redis_hash_exists(pr_redis_t *redis, module *m, const char *key,
  const char *field);
int pr_redis_hash_get(pool *p, pr_redis_t *redis, module *m, const char *key,
  const char *field, void **value, size_t *valuesz);
int pr_redis_hash_getall(pool *p, pr_redis_t *redis, module *m,
  const char *key, pr_table_t **hash);
int pr_redis_hash_incr(pr_redis_t *redis, module *m, const char *key,
  const char *field, int32_t incr, int64_t *value);
int pr_redis_hash_keys(pool *p, pr_redis_t *redis, module *m, const char *key,
  array_header **fields);
int pr_redis_hash_remove(pr_redis_t *redis, module *m, const char *key);
int pr_redis_hash_set(pr_redis_t *redis, module *m, const char *key,
  const char *field, void *value, size_t valuesz);
int pr_redis_hash_setall(pr_redis_t *redis, module *m, const char *key,
  pr_table_t *hash);
int pr_redis_hash_values(pool *p, pr_redis_t *redis, module *m,
  const char *key, array_header **values);

/* List operations */
int pr_redis_list_append(pr_redis_t *redis, module *m, const char *key,
  void *value, size_t valuesz);
int pr_redis_list_count(pr_redis_t *redis, module *m, const char *key,
  uint64_t *count);
int pr_redis_list_delete(pr_redis_t *redis, module *m, const char *key,
  void *value, size_t valuesz);
int pr_redis_list_exists(pr_redis_t *redis, module *m, const char *key,
  unsigned int idx);
int pr_redis_list_remove(pr_redis_t *redis, module *m, const char *key);
int pr_redis_list_set(pr_redis_t *redis, module *m, const char *key,
  unsigned int idx, void *value, size_t valuesz);

/* Set operations */
int pr_redis_set_add(pr_redis_t *redis, module *m, const char *key,
  void *value, size_t valuesz);
int pr_redis_set_count(pr_redis_t *redis, module *m, const char *key,
  uint64_t *count);
int pr_redis_set_delete(pr_redis_t *redis, module *m, const char *key,
  void *value, size_t valuesz);
int pr_redis_set_exists(pr_redis_t *redis, module *m, const char *key,
  void *value, size_t valuesz);
int pr_redis_set_remove(pr_redis_t *redis, module *m, const char *key);

/* Variants of the above, where the key values are arbitrary bits rather than
 * being assumed to be strings.
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

int pr_redis_hash_kcount(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, uint64_t *count);
int pr_redis_hash_kdelete(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, const char *field, size_t fieldsz);
int pr_redis_hash_kexists(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, const char *field, size_t fieldsz);
int pr_redis_hash_kget(pool *p, pr_redis_t *redis, module *m, const char *key,
  size_t keysz, const char *field, size_t fieldsz, void **value,
  size_t *valuesz);
int pr_redis_hash_kgetall(pool *p, pr_redis_t *redis, module *m,
  const char *key, size_t keysz, pr_table_t **hash);
int pr_redis_hash_kincr(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, const char *field, size_t fieldsz, int32_t incr,
  int64_t *value);
int pr_redis_hash_kkeys(pool *p, pr_redis_t *redis, module *m, const char *key,
  size_t keysz, array_header **fields);
int pr_redis_hash_kremove(pr_redis_t *redis, module *m, const char *key,
  size_t keysz);
int pr_redis_hash_kset(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, const char *field, size_t fieldsz, void *value, size_t valuesz);
int pr_redis_hash_ksetall(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, pr_table_t *hash);
int pr_redis_hash_kvalues(pool *p, pr_redis_t *redis, module *m,
  const char *key, size_t keysz, array_header **values);

int pr_redis_list_kappend(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, void *value, size_t valuesz);
int pr_redis_list_kcount(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, uint64_t *count);
int pr_redis_list_kdelete(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, void *value, size_t valuesz);
int pr_redis_list_kexists(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, unsigned int idx);
int pr_redis_list_kremove(pr_redis_t *redis, module *m, const char *key,
  size_t keysz);
int pr_redis_list_kset(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, unsigned int idx, void *value, size_t valuesz);

int pr_redis_set_kadd(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, void *value, size_t valuesz);
int pr_redis_set_kcount(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, uint64_t *count);
int pr_redis_set_kdelete(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, void *value, size_t valuesz);
int pr_redis_set_kexists(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, void *value, size_t valuesz);
int pr_redis_set_kremove(pr_redis_t *redis, module *m, const char *key,
  size_t keysz);

/* For internal use only */

int redis_set_server(const char *server, int port);
int redis_set_timeouts(unsigned long connect_millis, unsigned long io_millis);

int redis_clear(void);
int redis_init(void);

#endif /* PR_REDIS_H */
