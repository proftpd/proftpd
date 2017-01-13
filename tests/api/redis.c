/*
 * ProFTPD - FTP server testsuite
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

/* Redis API tests. */

#include "tests.h"

#ifdef PR_USE_REDIS

static pool *p = NULL;
static const char *redis_server = "127.0.0.1";
static int redis_port = 6379;

/* Fixtures */

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  redis_init();
  redis_set_server(redis_server, redis_port);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("redis", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("redis", 0, 0);
  }

  redis_clear();

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }
}

/* Tests */

START_TEST (redis_conn_close_test) {
  int res;

  mark_point();
  res = pr_redis_conn_close(NULL);
  fail_unless(res < 0, "Failed to handle null redis");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (redis_conn_new_test) {
  int res;
  pr_redis_t *redis;

  mark_point();
  redis = pr_redis_conn_new(NULL, NULL, 0);
  fail_unless(redis == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  redis = pr_redis_conn_new(p, NULL, 0);
  fail_unless(redis != NULL, "Failed to open connection to Redis: %s",
    strerror(errno));

  mark_point();
  res = pr_redis_conn_close(redis);
  fail_unless(res == 0, "Failed to close redis: %s", strerror(errno));
}
END_TEST

START_TEST (redis_conn_set_namespace_test) {
  int res;
  pr_redis_t *redis;
  module m;
  const char *prefix;

  mark_point();
  res = pr_redis_conn_set_namespace(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null redis");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  redis = pr_redis_conn_new(p, NULL, 0);
  fail_unless(redis != NULL, "Failed to open connection to Redis: %s",
    strerror(errno));

  mark_point();
  res = pr_redis_conn_set_namespace(redis, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null module");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_redis_conn_set_namespace(redis, &m, NULL);
  fail_unless(res == 0, "Failed to set null namespace prefix: %s",
    strerror(errno));

  prefix = "test.";
  res = pr_redis_conn_set_namespace(redis, &m, prefix);
  fail_unless(res == 0, "Failed to set namespace prefix '%s': %s", prefix,
    strerror(errno));

  mark_point();
  res = pr_redis_conn_set_namespace(redis, &m, NULL);
  fail_unless(res == 0, "Failed to set null namespace prefix: %s",
    strerror(errno));

  mark_point();
  res = pr_redis_conn_close(redis);
  fail_unless(res == 0, "Failed to close redis: %s", strerror(errno));
}
END_TEST

START_TEST (redis_remove_test) {
  int res;
  pr_redis_t *redis;
  module m;
  const char *key;

  mark_point();
  res = pr_redis_remove(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null redis");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  redis = pr_redis_conn_new(p, NULL, 0);
  fail_unless(redis != NULL, "Failed to open connection to Redis: %s",
    strerror(errno));

  mark_point();
  res = pr_redis_remove(redis, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null module");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_redis_remove(redis, &m, NULL);
  fail_unless(res < 0, "Failed to handle null key");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  key = "testkey";

  mark_point();
  res = pr_redis_remove(redis, &m, key);
  fail_unless(res < 0, "Unexpectedly removed key '%s'", key);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  mark_point();
  res = pr_redis_conn_close(redis);
  fail_unless(res == 0, "Failed to close redis: %s", strerror(errno));
}
END_TEST

START_TEST (redis_add_test) {
  int res;
  pr_redis_t *redis;
  module m;
  const char *key;
  char *val;
  size_t valsz;
  time_t expires;

  mark_point();
  res = pr_redis_add(NULL, NULL, NULL, NULL, 0, 0);
  fail_unless(res < 0, "Failed to handle null redis");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  redis = pr_redis_conn_new(p, NULL, 0);
  fail_unless(redis != NULL, "Failed to open connection to Redis: %s",
    strerror(errno));

  mark_point();
  res = pr_redis_add(redis, NULL, NULL, NULL, 0, 0);
  fail_unless(res < 0, "Failed to handle null module");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_redis_add(redis, &m, NULL, NULL, 0, 0);
  fail_unless(res < 0, "Failed to handle null key");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  key = "testkey";

  mark_point();
  res = pr_redis_add(redis, &m, key, NULL, 0, 0);
  fail_unless(res < 0, "Failed to handle null value");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  val = "testval";
  valsz = strlen(val);
  expires = 0;

  mark_point();
  res = pr_redis_add(redis, &m, key, val, valsz, expires);
  fail_unless(res == 0, "Failed to add key '%s', val '%s': %s", key, val,
    strerror(errno));

  mark_point();
  res = pr_redis_remove(redis, &m, key);
  fail_unless(res == 0, "Failed to remove key '%s': %s", key, strerror(errno));

  expires = 3;

  mark_point();
  res = pr_redis_add(redis, &m, key, val, valsz, expires);
  fail_unless(res == 0, "Failed to add key '%s', val '%s': %s", key, val,
    strerror(errno));

  mark_point();
  res = pr_redis_remove(redis, &m, key);
  fail_unless(res == 0, "Failed to remove key '%s': %s", key, strerror(errno));

  mark_point();
  res = pr_redis_conn_close(redis);
  fail_unless(res == 0, "Failed to close redis: %s", strerror(errno));
}
END_TEST

START_TEST (redis_add_with_namespace_test) {
  int res;
  pr_redis_t *redis;
  module m;
  const char *prefix, *key;
  char *val;
  size_t valsz;
  time_t expires;

  mark_point();
  redis = pr_redis_conn_new(p, NULL, 0);
  fail_unless(redis != NULL, "Failed to open connection to Redis: %s",
    strerror(errno));

  prefix = "test.";

  mark_point();
  res = pr_redis_conn_set_namespace(redis, &m, prefix);
  fail_unless(res == 0, "Failed to set namespace prefix '%s': %s", prefix,
    strerror(errno));

  key = "key";
  val = "val";
  valsz = strlen(val);
  expires = 0;

  mark_point();
  res = pr_redis_add(redis, &m, key, val, valsz, expires);
  fail_unless(res == 0, "Failed to add key '%s', val '%s': %s", key, val,
    strerror(errno));

  mark_point();
  res = pr_redis_remove(redis, &m, key);
  fail_unless(res == 0, "Failed to remove key '%s': %s", key, strerror(errno));

  mark_point();
  res = pr_redis_conn_set_namespace(redis, &m, NULL);
  fail_unless(res == 0, "Failed to set null namespace prefix: %s",
    strerror(errno));

  mark_point();
  res = pr_redis_conn_close(redis);
  fail_unless(res == 0, "Failed to close redis: %s", strerror(errno));
}
END_TEST

START_TEST (redis_get_test) {
  int res;
  pr_redis_t *redis;
  module m;
  const char *key;
  char *val;
  size_t valsz;
  time_t expires;
  void *data;

  mark_point();
  data = pr_redis_get(NULL, NULL, NULL, NULL, NULL);
  fail_unless(data == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  data = pr_redis_get(p, NULL, NULL, NULL, NULL);
  fail_unless(data == NULL, "Failed to handle null redis");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  redis = pr_redis_conn_new(p, NULL, 0);
  fail_unless(redis != NULL, "Failed to open connection to Redis: %s",
    strerror(errno));

  mark_point();
  data = pr_redis_get(p, redis, NULL, NULL, NULL);
  fail_unless(data == NULL, "Failed to handle null module");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  data = pr_redis_get(p, redis, &m, NULL, NULL);
  fail_unless(data == NULL, "Failed to handle null key");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  key = "testkey";
  (void) pr_redis_remove(redis, &m, key);

  mark_point();
  data = pr_redis_get(p, redis, &m, key, NULL);
  fail_unless(data == NULL, "Failed to handle null valuesz");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  data = pr_redis_get(p, redis, &m, key, &valsz);
  fail_unless(data == NULL, "Failed to handle nonexistent key");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  val = "Hello, World!";
  valsz = strlen(val);
  expires = 0;

  mark_point();
  res = pr_redis_set(redis, &m, key, val, valsz, expires);
  fail_unless(res == 0, "Failed to set key '%s', val '%s': %s", key, val,
    strerror(errno));

  valsz = 0;

  mark_point();
  data = pr_redis_get(p, redis, &m, key, &valsz);
  fail_unless(data != NULL, "Failed to get data for key '%s': %s", key,
    strerror(errno));
  fail_unless(valsz == strlen(val), "Expected %lu, got %lu",
    (unsigned long) strlen(val), (unsigned long) valsz);

  mark_point();
  res = pr_redis_remove(redis, &m, key);
  fail_unless(res == 0, "Failed to remove key '%s': %s", key, strerror(errno));

  mark_point();
  data = pr_redis_get(p, redis, &m, key, &valsz);
  fail_unless(data == NULL, "Failed to handle nonexistent key");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  mark_point();
  res = pr_redis_conn_close(redis);
  fail_unless(res == 0, "Failed to close redis: %s", strerror(errno));
}
END_TEST

START_TEST (redis_get_str_test) {
  int res;
  pr_redis_t *redis;
  module m;
  const char *key;
  size_t valsz;
  time_t expires;
  char *val, *str;

  mark_point();
  str = pr_redis_get_str(NULL, NULL, NULL, NULL);
  fail_unless(str == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  str = pr_redis_get_str(p, NULL, NULL, NULL);
  fail_unless(str == NULL, "Failed to handle null redis");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  redis = pr_redis_conn_new(p, NULL, 0);
  fail_unless(redis != NULL, "Failed to open connection to Redis: %s",
    strerror(errno));

  mark_point();
  str = pr_redis_get_str(p, redis, NULL, NULL);
  fail_unless(str == NULL, "Failed to handle null module");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  str = pr_redis_get_str(p, redis, &m, NULL);
  fail_unless(str == NULL, "Failed to handle null key");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  key = "test_string";
  (void) pr_redis_remove(redis, &m, key);

  mark_point();
  str = pr_redis_get_str(p, redis, &m, key);
  fail_unless(str == NULL, "Failed to handle nonexistent key");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  val = "Hello, World!";
  valsz = strlen(val);
  expires = 0;

  mark_point();
  res = pr_redis_set(redis, &m, key, val, valsz, expires);
  fail_unless(res == 0, "Failed to set key '%s', val '%s': %s", key, val,
    strerror(errno));

  mark_point();
  str = pr_redis_get_str(p, redis, &m, key);
  fail_unless(str != NULL, "Failed to get string for key '%s': %s", key,
    strerror(errno));
  fail_unless(strlen(str) == strlen(val), "Expected %lu, got %lu",
    (unsigned long) strlen(val), (unsigned long) strlen(str));

  mark_point();
  res = pr_redis_remove(redis, &m, key);
  fail_unless(res == 0, "Failed to remove key '%s': %s", key, strerror(errno));

  mark_point();
  str = pr_redis_get_str(p, redis, &m, key);
  fail_unless(str == NULL, "Failed to handle nonexistent key");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  mark_point();
  res = pr_redis_conn_close(redis);
  fail_unless(res == 0, "Failed to close redis: %s", strerror(errno));
}
END_TEST

START_TEST (redis_incr_test) {
  int res;
  pr_redis_t *redis;
  module m;
  const char *key;
  char *value;
  uint32_t incr;
  uint64_t val = 0;
  size_t valsz;
  time_t expires;

  mark_point();
  res = pr_redis_incr(NULL, NULL, NULL, 0, NULL);
  fail_unless(res < 0, "Failed to handle null redis");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  redis = pr_redis_conn_new(p, NULL, 0);
  fail_unless(redis != NULL, "Failed to open connection to Redis: %s",
    strerror(errno));

  mark_point();
  res = pr_redis_incr(redis, NULL, NULL, 0, NULL);
  fail_unless(res < 0, "Failed to handle null module");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_redis_incr(redis, &m, NULL, 0, NULL);
  fail_unless(res < 0, "Failed to handle null key");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  key = "testval";
  (void) pr_redis_remove(redis, &m, key);

  mark_point();
  res = pr_redis_incr(redis, &m, key, 0, NULL);
  fail_unless(res < 0, "Failed to handle zero incr");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  incr = 2;

  mark_point();
  res = pr_redis_incr(redis, &m, key, incr, NULL);
  fail_unless(res < 0, "Failed to handle nonexistent key");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  /* Note: Yes, Redis wants a string, NOT the actual bytes.  Makes sense,
   * I guess, given its text-based protocol.
   */
  value = "31";
  valsz = strlen(value);
  expires = 0;

  mark_point();
  res = pr_redis_set(redis, &m, key, value, valsz, expires);
  fail_unless(res == 0, "Failed to set key '%s', val '%s': %s", key, val,
    strerror(errno));

  mark_point();
  res = pr_redis_incr(redis, &m, key, incr, NULL);
  fail_unless(res == 0, "Failed to increment key '%s' by %lu: %s", key,
    (unsigned long) incr, strerror(errno));

  val = 0;

  mark_point();
  res = pr_redis_incr(redis, &m, key, incr, &val);
  fail_unless(res == 0, "Failed to increment key '%s' by %lu: %s", key,
    (unsigned long) incr, strerror(errno));
  fail_unless(val == 35, "Expected %lu, got %lu", 35, (unsigned long) val);

  mark_point();
  res = pr_redis_remove(redis, &m, key);
  fail_unless(res == 0, "Failed to remove key '%s': %s", key, strerror(errno));

  /* Now, let's try incrementing a non-numeric value. */
  value = "Hello, World!";
  valsz = strlen(value);
  expires = 0;

  mark_point();
  res = pr_redis_set(redis, &m, key, value, valsz, expires);
  fail_unless(res == 0, "Failed to set key '%s', val '%s': %s", key, val,
    strerror(errno));

  mark_point();
  res = pr_redis_incr(redis, &m, key, incr, &val);
  fail_unless(res < 0, "Failed to handle non-numeric key value");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  (void) pr_redis_remove(redis, &m, key);

  mark_point();
  res = pr_redis_conn_close(redis);
  fail_unless(res == 0, "Failed to close redis: %s", strerror(errno));
}
END_TEST

START_TEST (redis_decr_test) {
  int res;
  pr_redis_t *redis;
  module m;
  const char *key;
  char *value;
  uint32_t decr;
  uint64_t val = 0;
  size_t valsz;
  time_t expires;

  mark_point();
  res = pr_redis_decr(NULL, NULL, NULL, 0, NULL);
  fail_unless(res < 0, "Failed to handle null redis");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  redis = pr_redis_conn_new(p, NULL, 0);
  fail_unless(redis != NULL, "Failed to open connection to Redis: %s",
    strerror(errno));

  mark_point();
  res = pr_redis_decr(redis, NULL, NULL, 0, NULL);
  fail_unless(res < 0, "Failed to handle null module");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_redis_decr(redis, &m, NULL, 0, NULL);
  fail_unless(res < 0, "Failed to handle null key");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  key = "testval";
  (void) pr_redis_remove(redis, &m, key);

  mark_point();
  res = pr_redis_decr(redis, &m, key, 0, NULL);
  fail_unless(res < 0, "Failed to handle zero decr");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  decr = 5;

  mark_point();
  res = pr_redis_decr(redis, &m, key, decr, NULL);
  fail_unless(res < 0, "Failed to handle nonexistent key");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  /* Note: Yes, Redis wants a string, NOT the actual bytes.  Makes sense,
   * I guess, given its text-based protocol.
   */
  value = "31";
  valsz = strlen(value);
  expires = 0;

  mark_point();
  res = pr_redis_set(redis, &m, key, value, valsz, expires);
  fail_unless(res == 0, "Failed to set key '%s', val '%s': %s", key, val,
    strerror(errno));

  mark_point();
  res = pr_redis_decr(redis, &m, key, decr, NULL);
  fail_unless(res == 0, "Failed to decrement key '%s' by %lu: %s", key,
    (unsigned long) decr, strerror(errno));

  val = 0;

  mark_point();
  res = pr_redis_decr(redis, &m, key, decr, &val);
  fail_unless(res == 0, "Failed to decrement key '%s' by %lu: %s", key,
    (unsigned long) decr, strerror(errno));
  fail_unless(val == 21, "Expected %lu, got %lu", 21, (unsigned long) val);

  mark_point();
  res = pr_redis_remove(redis, &m, key);
  fail_unless(res == 0, "Failed to remove key '%s': %s", key, strerror(errno));

  /* Now, let's try decrementing a non-numeric value. */
  value = "Hello, World!";
  valsz = strlen(value);
  expires = 0;

  mark_point();
  res = pr_redis_set(redis, &m, key, value, valsz, expires);
  fail_unless(res == 0, "Failed to set key '%s', val '%s': %s", key, val,
    strerror(errno));

  mark_point();
  res = pr_redis_decr(redis, &m, key, decr, &val);
  fail_unless(res < 0, "Failed to handle non-numeric key value");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  (void) pr_redis_remove(redis, &m, key);

  mark_point();
  res = pr_redis_conn_close(redis);
  fail_unless(res == 0, "Failed to close redis: %s", strerror(errno));
}
END_TEST

START_TEST (redis_set_test) {
  int res;
  pr_redis_t *redis;
  module m;
  const char *key;
  char *val;
  size_t valsz;
  time_t expires;

  mark_point();
  res = pr_redis_set(NULL, NULL, NULL, NULL, 0, 0);
  fail_unless(res < 0, "Failed to handle null redis");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  redis = pr_redis_conn_new(p, NULL, 0);
  fail_unless(redis != NULL, "Failed to open connection to Redis: %s",
    strerror(errno));

  mark_point();
  res = pr_redis_set(redis, NULL, NULL, NULL, 0, 0);
  fail_unless(res < 0, "Failed to handle null module");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_redis_set(redis, &m, NULL, NULL, 0, 0);
  fail_unless(res < 0, "Failed to handle null key");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  key = "testkey";

  mark_point();
  res = pr_redis_set(redis, &m, key, NULL, 0, 0);
  fail_unless(res < 0, "Failed to handle null value");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  val = "testval";
  valsz = strlen(val);
  expires = 0;

  mark_point();
  res = pr_redis_set(redis, &m, key, val, valsz, expires);
  fail_unless(res == 0, "Failed to set key '%s', val '%s': %s", key, val,
    strerror(errno));

  mark_point();
  res = pr_redis_remove(redis, &m, key);
  fail_unless(res == 0, "Failed to remove key '%s': %s", key, strerror(errno));

  expires = 3;

  mark_point();
  res = pr_redis_set(redis, &m, key, val, valsz, expires);
  fail_unless(res == 0, "Failed to set key '%s', val '%s': %s", key, val,
    strerror(errno));

  mark_point();
  res = pr_redis_remove(redis, &m, key);
  fail_unless(res == 0, "Failed to remove key '%s': %s", key, strerror(errno));

  mark_point();
  res = pr_redis_conn_close(redis);
  fail_unless(res == 0, "Failed to close redis: %s", strerror(errno));
}
END_TEST

#endif /* PR_USE_REDIS */

Suite *tests_get_redis_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("redis");
  testcase = tcase_create("base");

#ifdef PR_USE_REDIS
  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, redis_conn_close_test);
  tcase_add_test(testcase, redis_conn_new_test);
  tcase_add_test(testcase, redis_conn_set_namespace_test);

  tcase_add_test(testcase, redis_remove_test);
  tcase_add_test(testcase, redis_add_test);
  tcase_add_test(testcase, redis_add_with_namespace_test);
  tcase_add_test(testcase, redis_get_test);
  tcase_add_test(testcase, redis_get_str_test);
  tcase_add_test(testcase, redis_incr_test);
  tcase_add_test(testcase, redis_decr_test);
  tcase_add_test(testcase, redis_set_test);

  suite_add_tcase(suite, testcase);
#endif /* PR_USE_REDIS */

  return suite;
}
