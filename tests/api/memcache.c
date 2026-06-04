/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2026 The ProFTPD Project team
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 *
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* Memcache API tests. */

#include "tests.h"

#if defined(PR_USE_MEMCACHE)

#include <libmemcached/memcached.h>

static pool *p = NULL;
static const char *memcached_server = "127.0.0.1";
static int memcached_port = 11211;

static int memcache_set_server(const char *host, int port) {
  char buf[1024];
  memcached_server_st *memcache_servers = NULL;

  memset(buf, 0, sizeof(buf));
  snprintf(buf, sizeof(buf)-1, "%s:%d", host, port);
  memcache_servers = memcached_servers_parse(buf);
  if (memcache_servers == NULL) {
    errno = EINVAL;
    return -1;
  }

  memcache_set_servers(memcache_servers);
  return 0;
}

/* Fixtures */

static void set_up(void) {
  const char *key, *val;

  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  memcache_init();

  key = "MEMCACHED_HOST";
  val = getenv(key);
  if (val != NULL) {
    memcached_server = val;
  }

  key = "MEMCACHED_PORT";
  val = getenv(key);
  if (val != NULL) {
    memcached_port = atoi(val);
  }

  memcache_set_server(memcached_server, memcached_port);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("memcache", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("memcache", 0, 0);
  }

  memcache_clear();

  if (p != NULL) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }
}

/* Tests */

START_TEST (memcache_conn_destroy_test) {
  int res;

  mark_point();
  res = pr_memcache_conn_destroy(NULL);
  ck_assert_msg(res < 0, "Failed to handle null mcache");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (memcache_conn_close_test) {
  int res;

  mark_point();
  res = pr_memcache_conn_close(NULL);
  ck_assert_msg(res < 0, "Failed to handle null mcache");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (memcache_conn_new_test) {
  int res;
  pr_memcache_t *mcache;

  mark_point();
  mcache = pr_memcache_conn_new(NULL, NULL, 0, 0);
  ck_assert_msg(mcache == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  mcache = pr_memcache_conn_new(p, NULL, 0, 0);
  ck_assert_msg(mcache != NULL, "Failed to open connection to Memcached: %s",
    strerror(errno));

  mark_point();
  res = pr_memcache_conn_destroy(mcache);
  ck_assert_msg(res == TRUE, "Failed to close mcache: %s", strerror(errno));

  if (getenv("CI") == NULL &&
      getenv("CIRRUS_CLONE_DEPTH") == NULL) {
    /* Now deliberately set the wrong server and port. */
    memcache_set_server("127.1.2.3", memcached_port);

    mark_point();
    mcache = pr_memcache_conn_new(p, NULL, 0, 0);
    ck_assert_msg(mcache == NULL, "Failed to handle invalid address");
    ck_assert_msg(errno == EIO, "Expected EIO (%d), got %s (%d)", EIO,
      strerror(errno), errno);
  }

  memcache_set_server(memcached_server, 1020);

  mark_point();
  mcache = pr_memcache_conn_new(p, NULL, 0, 0);
  ck_assert_msg(mcache == NULL, "Failed to handle invalid port");
  ck_assert_msg(errno == EIO, "Expected EIO (%d), got %s (%d)", EIO,
    strerror(errno), errno);

  /* Restore our testing server/port. */
  memcache_set_server(memcached_server, memcached_port);
}
END_TEST

START_TEST (memcache_conn_get_test) {
  int res;
  pr_memcache_t *mcache, *mcache2;

  mark_point();
  mcache = pr_memcache_conn_get(NULL);
  ck_assert_msg(mcache == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  mcache = pr_memcache_conn_get(p);
  ck_assert_msg(mcache != NULL, "Failed to open connection to Memcached: %s",
    strerror(errno));

  mark_point();
  res = pr_memcache_conn_destroy(mcache);
  ck_assert_msg(res == TRUE, "Failed to close mcache: %s", strerror(errno));

  mark_point();
  mcache = pr_memcache_conn_get(p);
  ck_assert_msg(mcache != NULL, "Failed to open connection to Memcached: %s",
    strerror(errno));

  mark_point();
  mcache2 = pr_memcache_conn_get(p);
  ck_assert_msg(mcache2 != NULL, "Failed to open connection to Memcached: %s",
    strerror(errno));
  ck_assert_msg(mcache == mcache2, "Expected %p, got %p", mcache, mcache2);

  mark_point();
  res = pr_memcache_conn_destroy(mcache);
  ck_assert_msg(res == FALSE, "Expected FALSE, got TRUE");

  mark_point();
  res = pr_memcache_conn_destroy(mcache);
  ck_assert_msg(res == TRUE, "Failed to close mcache: %s", strerror(errno));
}
END_TEST

START_TEST (memcache_conn_clone_test) {
  int res;
  pr_memcache_t *mcache;

  mark_point();
  res = pr_memcache_conn_clone(NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_memcache_conn_clone(p, NULL);
  ck_assert_msg(res < 0, "Failed to handle null mcache");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  mcache = pr_memcache_conn_new(p, NULL, 0, 0);
  ck_assert_msg(mcache != NULL, "Failed to open connection to Memcached: %s",
    strerror(errno));

  mark_point();
  res = pr_memcache_conn_clone(p, mcache);
  ck_assert_msg(res == 0, "Failed to clone connection: %s",
    strerror(errno));

  mark_point();
  res = pr_memcache_conn_destroy(mcache);
  ck_assert_msg(res == TRUE, "Failed to close mcache: %s", strerror(errno));
}
END_TEST

START_TEST (memcache_conn_set_namespace_test) {
  int res;
  pr_memcache_t *mcache;
  module m;
  const char *prefix;

  mark_point();
  res = pr_memcache_conn_set_namespace(NULL, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null mcache");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  mcache = pr_memcache_conn_new(p, NULL, 0, 0);
  ck_assert_msg(mcache != NULL, "Failed to open connection to Memcached: %s",
    strerror(errno));

  mark_point();
  res = pr_memcache_conn_set_namespace(mcache, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null module");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_memcache_conn_set_namespace(mcache, &m, NULL);
  ck_assert_msg(res == 0, "Failed to set null namespace prefix: %s",
    strerror(errno));

  prefix = "test.";

  res = pr_memcache_conn_set_namespace(mcache, &m, prefix);
  ck_assert_msg(res == 0, "Failed to handle namespace prefix '%s': %s", prefix,
    strerror(errno));

  mark_point();
  res = pr_memcache_conn_set_namespace(mcache, &m, NULL);
  ck_assert_msg(res == 0, "Failed to set null namespace prefix: %s",
    strerror(errno));

  mark_point();
  res = pr_memcache_conn_destroy(mcache);
  ck_assert_msg(res == TRUE, "Failed to close mcache: %s", strerror(errno));
}
END_TEST

START_TEST (memcache_remove_test) {
  int res;
  pr_memcache_t *mcache;
  module m;
  const char *key;

  mark_point();
  res = pr_memcache_remove(NULL, NULL, NULL, 0);
  ck_assert_msg(res < 0, "Failed to handle null mcache");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  mcache = pr_memcache_conn_new(p, NULL, 0, 0);
  ck_assert_msg(mcache != NULL, "Failed to open connection to Memcached: %s",
    strerror(errno));

  mark_point();
  res = pr_memcache_remove(mcache, NULL, NULL, 0);
  ck_assert_msg(res < 0, "Failed to handle null module");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_memcache_remove(mcache, &m, NULL, 0);
  ck_assert_msg(res < 0, "Failed to handle null key");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  key = "testkey";

  mark_point();
  res = pr_memcache_remove(mcache, &m, key, 0);
  ck_assert_msg(res < 0, "Unexpectedly removed key '%s'", key);
  ck_assert_msg(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  mark_point();
  res = pr_memcache_conn_destroy(mcache);
  ck_assert_msg(res == TRUE, "Failed to close mcache: %s", strerror(errno));
}
END_TEST

START_TEST (memcache_add_test) {
  int res;
  pr_memcache_t *mcache;
  module m;
  const char *key;
  char *val;
  size_t valsz;
  time_t expires;

  mark_point();
  res = pr_memcache_add(NULL, NULL, NULL, NULL, 0, 0, 0);
  ck_assert_msg(res < 0, "Failed to handle null mcache");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  mcache = pr_memcache_conn_new(p, NULL, 0, 0);
  ck_assert_msg(mcache != NULL, "Failed to open connection to Memcached: %s",
    strerror(errno));

  mark_point();
  res = pr_memcache_add(mcache, NULL, NULL, NULL, 0, 0, 0);
  ck_assert_msg(res < 0, "Failed to handle null module");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_memcache_add(mcache, &m, NULL, NULL, 0, 0, 0);
  ck_assert_msg(res < 0, "Failed to handle null key");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  key = "testkey";

  mark_point();
  res = pr_memcache_add(mcache, &m, key, NULL, 0, 0, 0);
  ck_assert_msg(res < 0, "Failed to handle null value");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  val = "testval";
  valsz = strlen(val);
  expires = 0;

  mark_point();
  res = pr_memcache_add(mcache, &m, key, val, valsz, expires, 0);
  ck_assert_msg(res == 0, "Failed to add key '%s', val '%s': %s", key, val,
    strerror(errno));

  mark_point();
  res = pr_memcache_remove(mcache, &m, key, 0);
  ck_assert_msg(res == 0, "Failed to remove key '%s': %s", key,
    strerror(errno));

  expires = 3;

  mark_point();
  res = pr_memcache_add(mcache, &m, key, val, valsz, expires, 0);
  ck_assert_msg(res == 0, "Failed to add key '%s', val '%s': %s", key, val,
    strerror(errno));

  mark_point();
  res = pr_memcache_remove(mcache, &m, key, 0);
  ck_assert_msg(res == 0, "Failed to remove key '%s': %s", key,
    strerror(errno));

  mark_point();
  res = pr_memcache_conn_destroy(mcache);
  ck_assert_msg(res == TRUE, "Failed to close mcache: %s", strerror(errno));
}
END_TEST

START_TEST (memcache_add_with_namespace_test) {
  int res;
  pr_memcache_t *mcache;
  module m;
  const char *prefix, *key;
  char *val;
  size_t valsz;
  time_t expires;

  mark_point();
  mcache = pr_memcache_conn_new(p, NULL, 0, 0);
  ck_assert_msg(mcache != NULL, "Failed to open connection to Memcached: %s",
    strerror(errno));

  prefix = "test.";

  mark_point();
  res = pr_memcache_conn_set_namespace(mcache, &m, prefix);
  ck_assert_msg(res == 0, "Failed to set namespace prefix '%s': %s", prefix,
    strerror(errno));

  key = "key";
  val = "val";
  valsz = strlen(val);
  expires = 0;

  mark_point();
  res = pr_memcache_add(mcache, &m, key, val, valsz, expires, 0);
  ck_assert_msg(res == 0, "Failed to add key '%s', val '%s': %s", key, val,
    strerror(errno));

  mark_point();
  res = pr_memcache_remove(mcache, &m, key, 0);
  ck_assert_msg(res == 0, "Failed to remove key '%s': %s", key,
    strerror(errno));

  mark_point();
  res = pr_memcache_conn_set_namespace(mcache, &m, NULL);
  ck_assert_msg(res == 0, "Failed to set null namespace prefix: %s",
    strerror(errno));

  mark_point();
  res = pr_memcache_conn_destroy(mcache);
  ck_assert_msg(res == TRUE, "Failed to close mcache: %s", strerror(errno));
}
END_TEST

START_TEST (memcache_get_test) {
  int res;
  pr_memcache_t *mcache;
  module m;
  const char *key;
  char *val;
  size_t valsz;
  time_t expires;
  uint32_t flags;
  void *data;

  mark_point();
  data = pr_memcache_get(NULL, NULL, NULL, NULL, NULL);
  ck_assert_msg(data == NULL, "Failed to handle null mcache");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  mcache = pr_memcache_conn_new(p, NULL, 0, 0);
  ck_assert_msg(mcache != NULL, "Failed to open connection to Memcached: %s",
    strerror(errno));

  mark_point();
  data = pr_memcache_get(mcache, NULL, NULL, NULL, NULL);
  ck_assert_msg(data == NULL, "Failed to handle null module");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  data = pr_memcache_get(mcache, &m, NULL, NULL, NULL);
  ck_assert_msg(data == NULL, "Failed to handle null key");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  key = "testkey";
  (void) pr_memcache_remove(mcache, &m, key, 0);

  mark_point();
  data = pr_memcache_get(mcache, &m, key, NULL, NULL);
  ck_assert_msg(data == NULL, "Failed to handle null valuesz");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  data = pr_memcache_get(mcache, &m, key, &valsz, NULL);
  ck_assert_msg(data == NULL, "Failed to handle null flags");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  data = pr_memcache_get(mcache, &m, key, &valsz, &flags);
  ck_assert_msg(data == NULL, "Failed to handle nonexistent key");
  ck_assert_msg(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  val = "Hello, World!";
  valsz = strlen(val);
  expires = 0;

  mark_point();
  res = pr_memcache_set(mcache, &m, key, val, valsz, expires, 0);
  ck_assert_msg(res == 0, "Failed to set key '%s', val '%s': %s", key, val,
    strerror(errno));

  valsz = 0;

  mark_point();
  data = pr_memcache_get(mcache, &m, key, &valsz, &flags);
  ck_assert_msg(data != NULL, "Failed to get data for key '%s': %s", key,
    strerror(errno));
  ck_assert_msg(valsz == strlen(val), "Expected %lu, got %lu",
    (unsigned long) strlen(val), (unsigned long) valsz);

  mark_point();
  res = pr_memcache_remove(mcache, &m, key, 0);
  ck_assert_msg(res == 0, "Failed to remove key '%s': %s", key,
    strerror(errno));

  mark_point();
  data = pr_memcache_get(mcache, &m, key, &valsz, &flags);
  ck_assert_msg(data == NULL, "Failed to handle nonexistent key");
  ck_assert_msg(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  mark_point();
  res = pr_memcache_conn_destroy(mcache);
  ck_assert_msg(res == TRUE, "Failed to close mcache: %s", strerror(errno));
}
END_TEST

START_TEST (memcache_get_with_namespace_test) {
  int res;
  pr_memcache_t *mcache;
  module m;
  const char *prefix, *key;
  char *val;
  size_t valsz;
  time_t expires;
  uint32_t flags;
  void *data;

  /* set a value, set the namespace, get it. */

  mark_point();
  mcache = pr_memcache_conn_new(p, NULL, 0, 0);
  ck_assert_msg(mcache != NULL, "Failed to open connection to Memcached: %s",
    strerror(errno));

  prefix = "prefix.";

  key = "prefix.testkey";
  (void) pr_memcache_remove(mcache, &m, key, 0);

  val = "Hello, World!";
  valsz = strlen(val);
  expires = 0;

  mark_point();
  res = pr_memcache_set(mcache, &m, key, val, valsz, expires, 0);
  ck_assert_msg(res == 0, "Failed to set key '%s', val '%s': %s", key, val,
    strerror(errno));

  mark_point();
  res = pr_memcache_conn_set_namespace(mcache, &m, prefix);
  ck_assert_msg(res == 0, "Failed to set namespace prefix '%s': %s", prefix,
    strerror(errno));

  key = "testkey";
  valsz = 0;

  mark_point();
  data = pr_memcache_get(mcache, &m, key, &valsz, &flags);
  ck_assert_msg(data != NULL, "Failed to get data for key '%s': %s", key,
    strerror(errno));
  ck_assert_msg(valsz == strlen(val), "Expected %lu, got %lu",
    (unsigned long) strlen(val), (unsigned long) valsz);
  ck_assert_msg(memcmp(data, val, valsz) == 0, "Expected '%s', got '%.*s'",
    val, (int) valsz, (char *) data);

  mark_point();
  res = pr_memcache_conn_destroy(mcache);
  ck_assert_msg(res == TRUE, "Failed to close mcache: %s", strerror(errno));
}
END_TEST

START_TEST (memcache_get_str_test) {
  int res;
  pr_memcache_t *mcache;
  module m;
  const char *key;
  size_t valsz;
  time_t expires;
  uint32_t flags;
  char *val, *str;

  mark_point();
  str = pr_memcache_get_str(NULL, NULL, NULL, NULL);
  ck_assert_msg(str == NULL, "Failed to handle null mcache");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  mcache = pr_memcache_conn_new(p, NULL, 0, 0);
  ck_assert_msg(mcache != NULL, "Failed to open connection to Memcached: %s",
    strerror(errno));

  mark_point();
  str = pr_memcache_get_str(mcache, NULL, NULL, NULL);
  ck_assert_msg(str == NULL, "Failed to handle null module");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  str = pr_memcache_get_str(mcache, &m, NULL, NULL);
  ck_assert_msg(str == NULL, "Failed to handle null key");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  key = "test_string";
  (void) pr_memcache_remove(mcache, &m, key, 0);

  mark_point();
  str = pr_memcache_get_str(mcache, &m, key, NULL);
  ck_assert_msg(str == NULL, "Failed to handle null flags");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  str = pr_memcache_get_str(mcache, &m, key, &flags);
  ck_assert_msg(str == NULL, "Failed to handle nonexistent key");
  ck_assert_msg(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  val = "Hello, World!";
  valsz = strlen(val);
  expires = 0;

  mark_point();
  res = pr_memcache_set(mcache, &m, key, val, valsz, expires, 0);
  ck_assert_msg(res == 0, "Failed to set key '%s', val '%s': %s", key, val,
    strerror(errno));

  mark_point();
  str = pr_memcache_get_str(mcache, &m, key, &flags);
  ck_assert_msg(str != NULL, "Failed to get string for key '%s': %s", key,
    strerror(errno));
  ck_assert_msg(strlen(str) == strlen(val), "Expected %lu, got %lu",
    (unsigned long) strlen(val), (unsigned long) strlen(str));

  mark_point();
  res = pr_memcache_remove(mcache, &m, key, 0);
  ck_assert_msg(res == 0, "Failed to remove key '%s': %s", key,
    strerror(errno));

  mark_point();
  str = pr_memcache_get_str(mcache, &m, key, &flags);
  ck_assert_msg(str == NULL, "Failed to handle nonexistent key");
  ck_assert_msg(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  mark_point();
  res = pr_memcache_conn_destroy(mcache);
  ck_assert_msg(res == TRUE, "Failed to close mcache: %s", strerror(errno));
}
END_TEST

START_TEST (memcache_incr_test) {
  int res;
  pr_memcache_t *mcache;
  module m;
  const char *key;
  char *value;
  uint32_t incr;
  uint64_t val = 0;
  size_t valsz;
  time_t expires;

  mark_point();
  res = pr_memcache_incr(NULL, NULL, NULL, 0, NULL);
  ck_assert_msg(res < 0, "Failed to handle null mcache");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  mcache = pr_memcache_conn_new(p, NULL, 0, 0);
  ck_assert_msg(mcache != NULL, "Failed to open connection to Memcached: %s",
    strerror(errno));

  mark_point();
  res = pr_memcache_incr(mcache, NULL, NULL, 0, NULL);
  ck_assert_msg(res < 0, "Failed to handle null module");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_memcache_incr(mcache, &m, NULL, 0, NULL);
  ck_assert_msg(res < 0, "Failed to handle null key");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  key = "testval";
  (void) pr_memcache_remove(mcache, &m, key, 0);

  mark_point();
  res = pr_memcache_incr(mcache, &m, key, 0, NULL);
  ck_assert_msg(res < 0, "Failed to handle zero incr");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  incr = 2;

  mark_point();
  res = pr_memcache_incr(mcache, &m, key, incr, NULL);
  ck_assert_msg(res == 0, "Failed to handle nonexistent val: %s",
    strerror(errno));

  value = "31";
  valsz = strlen(value);

  mark_point();
  res = pr_memcache_set(mcache, &m, key, value, valsz, 0, 0);
  ck_assert_msg(res == 0, "Failed to set key '%s', val '%s': %s", key,
    value, strerror(errno));

  mark_point();
  res = pr_memcache_incr(mcache, &m, key, incr, NULL);
  ck_assert_msg(res == 0, "Failed to increment key '%s' by %lu: %s", key,
    (unsigned long) incr, strerror(errno));

  val = 0;

  mark_point();
  res = pr_memcache_incr(mcache, &m, key, incr, &val);
  ck_assert_msg(res == 0, "Failed to increment key '%s' by %lu: %s", key,
    (unsigned long) incr, strerror(errno));
  ck_assert_msg(val == 35, "Expected %lu, got %lu", (unsigned long) 35,
    (unsigned long) val);

  mark_point();
  res = pr_memcache_remove(mcache, &m, key, 0);
  ck_assert_msg(res == 0, "Failed to remove key '%s': %s", key,
    strerror(errno));

  /* Now, let's try incrementing a non-numeric value. */
  value = "Hello, World!";
  valsz = strlen(value);
  expires = 0;

  mark_point();
  res = pr_memcache_set(mcache, &m, key, value, valsz, expires, 0);
  ck_assert_msg(res == 0, "Failed to set key '%s', val '%s': %s", key, value,
    strerror(errno));

  mark_point();
  res = pr_memcache_incr(mcache, &m, key, incr, &val);
  ck_assert_msg(res < 0, "Failed to handle non-numeric key value");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  (void) pr_memcache_remove(mcache, &m, key, 0);

  mark_point();
  res = pr_memcache_conn_destroy(mcache);
  ck_assert_msg(res == TRUE, "Failed to close mcache: %s", strerror(errno));
}
END_TEST

START_TEST (memcache_decr_test) {
  int res;
  pr_memcache_t *mcache;
  module m;
  const char *key;
  char *value;
  uint32_t decr;
  uint64_t val = 0;
  size_t valsz;
  time_t expires;

  mark_point();
  res = pr_memcache_decr(NULL, NULL, NULL, 0, NULL);
  ck_assert_msg(res < 0, "Failed to handle null mcache");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  mcache = pr_memcache_conn_new(p, NULL, 0, 0);
  ck_assert_msg(mcache != NULL, "Failed to open connection to Memcached: %s",
    strerror(errno));

  mark_point();
  res = pr_memcache_decr(mcache, NULL, NULL, 0, NULL);
  ck_assert_msg(res < 0, "Failed to handle null module");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_memcache_decr(mcache, &m, NULL, 0, NULL);
  ck_assert_msg(res < 0, "Failed to handle null key");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  key = "testval";
  (void) pr_memcache_remove(mcache, &m, key, 0);

  mark_point();
  res = pr_memcache_decr(mcache, &m, key, 0, NULL);
  ck_assert_msg(res < 0, "Failed to handle zero decr");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  decr = 5;

  mark_point();
  res = pr_memcache_decr(mcache, &m, key, decr, NULL);
  ck_assert_msg(res < 0, "Failed to handle nonexistent key");
  ck_assert_msg(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  /* While libmemcached automatically creates a value for incrementing,
   * it does NOT do so for decrementing.  Yay asymmetry.
   */

  value = "31";
  valsz = strlen(value); 
  expires = 0;

  mark_point();
  res = pr_memcache_set(mcache, &m, key, value, valsz, expires, 0);
  ck_assert_msg(res == 0, "Failed to set key '%s', val '%s': %s", key, value,
    strerror(errno));

  mark_point();
  res = pr_memcache_decr(mcache, &m, key, decr, NULL);
  ck_assert_msg(res == 0, "Failed to decrement key '%s' by %lu: %s", key,
    (unsigned long) decr, strerror(errno));

  val = 0;

  mark_point();
  res = pr_memcache_decr(mcache, &m, key, decr, &val);
  ck_assert_msg(res == 0, "Failed to decrement key '%s' by %lu: %s", key,
    (unsigned long) decr, strerror(errno));
  ck_assert_msg(val == 21, "Expected %lu, got %lu", (unsigned long) 21,
    (unsigned long) val);

  mark_point();
  res = pr_memcache_remove(mcache, &m, key, 0);
  ck_assert_msg(res == 0, "Failed to remove key '%s': %s", key,
    strerror(errno));

  /* Now, let's try decrementing a non-numeric value. */
  value = "Hello, World!";
  valsz = strlen(value);
  expires = 0;

  mark_point();
  res = pr_memcache_set(mcache, &m, key, value, valsz, expires, 0);
  ck_assert_msg(res == 0, "Failed to set key '%s', val '%s': %s", key, value,
    strerror(errno));

  mark_point();
  res = pr_memcache_decr(mcache, &m, key, decr, &val);
  ck_assert_msg(res < 0, "Failed to handle non-numeric key value");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  (void) pr_memcache_remove(mcache, &m, key, 0);

  mark_point();
  res = pr_memcache_conn_destroy(mcache);
  ck_assert_msg(res == TRUE, "Failed to close mcache: %s", strerror(errno));
}
END_TEST

START_TEST (memcache_set_test) {
  int res;
  pr_memcache_t *mcache;
  module m;
  const char *key;
  char *val;
  size_t valsz;
  time_t expires;

  mark_point();
  res = pr_memcache_set(NULL, NULL, NULL, NULL, 0, 0, 0);
  ck_assert_msg(res < 0, "Failed to handle null mcache");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  mcache = pr_memcache_conn_new(p, NULL, 0, 0);
  ck_assert_msg(mcache != NULL, "Failed to open connection to Memcached: %s",
    strerror(errno));

  mark_point();
  res = pr_memcache_set(mcache, NULL, NULL, NULL, 0, 0, 0);
  ck_assert_msg(res < 0, "Failed to handle null module");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_memcache_set(mcache, &m, NULL, NULL, 0, 0, 0);
  ck_assert_msg(res < 0, "Failed to handle null key");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  key = "testkey";

  mark_point();
  res = pr_memcache_set(mcache, &m, key, NULL, 0, 0, 0);
  ck_assert_msg(res < 0, "Failed to handle null value");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  val = "testval";
  valsz = strlen(val);
  expires = 0;

  mark_point();
  res = pr_memcache_set(mcache, &m, key, val, valsz, expires, 0);
  ck_assert_msg(res == 0, "Failed to set key '%s', val '%s': %s", key, val,
    strerror(errno));

  mark_point();
  res = pr_memcache_remove(mcache, &m, key, 0);
  ck_assert_msg(res == 0, "Failed to remove key '%s': %s", key,
    strerror(errno));

  expires = 3;

  mark_point();
  res = pr_memcache_set(mcache, &m, key, val, valsz, expires, 0);
  ck_assert_msg(res == 0, "Failed to set key '%s', val '%s': %s", key, val,
    strerror(errno));

  mark_point();
  res = pr_memcache_remove(mcache, &m, key, 0);
  ck_assert_msg(res == 0, "Failed to remove key '%s': %s", key,
    strerror(errno));

  mark_point();
  res = pr_memcache_conn_destroy(mcache);
  ck_assert_msg(res == TRUE, "Failed to close mcache: %s", strerror(errno));
}
END_TEST

START_TEST (memcache_kremove_test) {
  int res;
  pr_memcache_t *mcache;
  module m;
  const char *key;

  mark_point();
  res = pr_memcache_kremove(NULL, NULL, NULL, 0, 0);
  ck_assert_msg(res < 0, "Failed to handle null mcache");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  mcache = pr_memcache_conn_new(p, NULL, 0, 0);
  ck_assert_msg(mcache != NULL, "Failed to open connection to Memcached: %s",
    strerror(errno));

  mark_point();
  res = pr_memcache_kremove(mcache, NULL, NULL, 0, 0);
  ck_assert_msg(res < 0, "Failed to handle null module");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_memcache_kremove(mcache, &m, NULL, 0, 0);
  ck_assert_msg(res < 0, "Failed to handle null key");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  key = "testkey";

  mark_point();
  res = pr_memcache_kremove(mcache, &m, key, 0, 0);
  ck_assert_msg(res < 0, "Unexpectedly removed key '%s'", key);
  ck_assert_msg(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  mark_point();
  res = pr_memcache_conn_destroy(mcache);
  ck_assert_msg(res == TRUE, "Failed to close mcache: %s", strerror(errno));
}
END_TEST

START_TEST (memcache_kadd_test) {
  int res;
  pr_memcache_t *mcache;
  module m;
  const char *key;
  char *val;
  size_t valsz;
  time_t expires;

  mark_point();
  res = pr_memcache_kadd(NULL, NULL, NULL, 0, NULL, 0, 0, 0);
  ck_assert_msg(res < 0, "Failed to handle null mcache");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  mcache = pr_memcache_conn_new(p, NULL, 0, 0);
  ck_assert_msg(mcache != NULL, "Failed to open connection to Memcached: %s",
    strerror(errno));

  mark_point();
  res = pr_memcache_kadd(mcache, NULL, NULL, 0, NULL, 0, 0, 0);
  ck_assert_msg(res < 0, "Failed to handle null module");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_memcache_kadd(mcache, &m, NULL, 0, NULL, 0, 0, 0);
  ck_assert_msg(res < 0, "Failed to handle null key");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  key = "testkey";

  mark_point();
  res = pr_memcache_kadd(mcache, &m, key, strlen(key), NULL, 0, 0, 0);
  ck_assert_msg(res < 0, "Failed to handle null value");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  val = "testval";
  valsz = strlen(val);
  expires = 0;

  mark_point();
  res = pr_memcache_kadd(mcache, &m, key, strlen(key), val, valsz, expires, 0);
  ck_assert_msg(res == 0, "Failed to add key '%s', val '%s': %s", key, val,
    strerror(errno));

  mark_point();
  res = pr_memcache_remove(mcache, &m, key, 0);
  ck_assert_msg(res == 0, "Failed to remove key '%s': %s", key,
    strerror(errno));

  expires = 3;

  mark_point();
  res = pr_memcache_kadd(mcache, &m, key, strlen(key), val, valsz, expires, 0);
  ck_assert_msg(res == 0, "Failed to add key '%s', val '%s': %s", key, val,
    strerror(errno));

  mark_point();
  res = pr_memcache_remove(mcache, &m, key, 0);
  ck_assert_msg(res == 0, "Failed to remove key '%s': %s", key,
    strerror(errno));

  mark_point();
  res = pr_memcache_conn_destroy(mcache);
  ck_assert_msg(res == TRUE, "Failed to close mcache: %s", strerror(errno));
}
END_TEST

START_TEST (memcache_kget_test) {
  int res;
  pr_memcache_t *mcache;
  module m;
  const char *key;
  char *val;
  size_t valsz;
  time_t expires;
  uint32_t flags;
  void *data;

  mark_point();
  data = pr_memcache_kget(NULL, NULL, NULL, 0, NULL, NULL);
  ck_assert_msg(data == NULL, "Failed to handle null mcache");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  mcache = pr_memcache_conn_new(p, NULL, 0, 0);
  ck_assert_msg(mcache != NULL, "Failed to open connection to Memcached: %s",
    strerror(errno));

  mark_point();
  data = pr_memcache_kget(mcache, NULL, NULL, 0, NULL, NULL);
  ck_assert_msg(data == NULL, "Failed to handle null module");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  data = pr_memcache_kget(mcache, &m, NULL, 0, NULL, NULL);
  ck_assert_msg(data == NULL, "Failed to handle null key");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  key = "testkey";
  (void) pr_memcache_remove(mcache, &m, key, 0);

  mark_point();
  data = pr_memcache_kget(mcache, &m, key, strlen(key), NULL, NULL);
  ck_assert_msg(data == NULL, "Failed to handle null valuesz");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  data = pr_memcache_kget(mcache, &m, key, strlen(key), &valsz, NULL);
  ck_assert_msg(data == NULL, "Failed to handle null flags");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  data = pr_memcache_kget(mcache, &m, key, strlen(key), &valsz, &flags);
  ck_assert_msg(data == NULL, "Failed to handle nonexistent key");
  ck_assert_msg(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  val = "Hello, World!";
  valsz = strlen(val);
  expires = 0;

  mark_point();
  res = pr_memcache_set(mcache, &m, key, val, valsz, expires, 0);
  ck_assert_msg(res == 0, "Failed to set key '%s', val '%s': %s", key, val,
    strerror(errno));

  valsz = 0;

  mark_point();
  data = pr_memcache_kget(mcache, &m, key, strlen(key), &valsz, &flags);
  ck_assert_msg(data != NULL, "Failed to get data for key '%s': %s", key,
    strerror(errno));
  ck_assert_msg(valsz == strlen(val), "Expected %lu, got %lu",
    (unsigned long) strlen(val), (unsigned long) valsz);

  mark_point();
  res = pr_memcache_remove(mcache, &m, key, 0);
  ck_assert_msg(res == 0, "Failed to remove key '%s': %s", key,
    strerror(errno));

  mark_point();
  data = pr_memcache_kget(mcache, &m, key, strlen(key), &valsz, &flags);
  ck_assert_msg(data == NULL, "Failed to handle nonexistent key");
  ck_assert_msg(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  mark_point();
  res = pr_memcache_conn_destroy(mcache);
  ck_assert_msg(res == TRUE, "Failed to close mcache: %s", strerror(errno));
}
END_TEST

START_TEST (memcache_kget_str_test) {
  int res;
  pr_memcache_t *mcache;
  module m;
  const char *key;
  size_t valsz;
  time_t expires;
  uint32_t flags;
  char *val, *str;

  mark_point();
  str = pr_memcache_kget_str(NULL, NULL, NULL, 0, NULL);
  ck_assert_msg(str == NULL, "Failed to handle null mcache");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  mcache = pr_memcache_conn_new(p, NULL, 0, 0);
  ck_assert_msg(mcache != NULL, "Failed to open connection to Memcached: %s",
    strerror(errno));

  mark_point();
  str = pr_memcache_kget_str(mcache, NULL, NULL, 0, NULL);
  ck_assert_msg(str == NULL, "Failed to handle null module");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  str = pr_memcache_kget_str(mcache, &m, NULL, 0, NULL);
  ck_assert_msg(str == NULL, "Failed to handle null key");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  key = "test_string";
  (void) pr_memcache_remove(mcache, &m, key, 0);

  mark_point();
  str = pr_memcache_kget_str(mcache, &m, key, strlen(key), NULL);
  ck_assert_msg(str == NULL, "Failed to handle null flags");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  str = pr_memcache_kget_str(mcache, &m, key, strlen(key), &flags);
  ck_assert_msg(str == NULL, "Failed to handle nonexistent key");
  ck_assert_msg(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  val = "Hello, World!";
  valsz = strlen(val);
  expires = 0;

  mark_point();
  res = pr_memcache_set(mcache, &m, key, val, valsz, expires, 0);
  ck_assert_msg(res == 0, "Failed to set key '%s', val '%s': %s", key, val,
    strerror(errno));

  mark_point();
  str = pr_memcache_kget_str(mcache, &m, key, strlen(key), &flags);
  ck_assert_msg(str != NULL, "Failed to get string for key '%s': %s", key,
    strerror(errno));
  ck_assert_msg(strlen(str) == strlen(val), "Expected %lu, got %lu",
    (unsigned long) strlen(val), (unsigned long) strlen(str));

  mark_point();
  res = pr_memcache_remove(mcache, &m, key, 0);
  ck_assert_msg(res == 0, "Failed to remove key '%s': %s", key,
    strerror(errno));

  mark_point();
  str = pr_memcache_kget_str(mcache, &m, key, strlen(key), &flags);
  ck_assert_msg(str == NULL, "Failed to handle nonexistent key");
  ck_assert_msg(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  mark_point();
  res = pr_memcache_conn_destroy(mcache);
  ck_assert_msg(res == TRUE, "Failed to close mcache: %s", strerror(errno));
}
END_TEST

START_TEST (memcache_kincr_test) {
  int res;
  pr_memcache_t *mcache;
  module m;
  const char *key;
  char *value;
  uint32_t incr;
  uint64_t val = 0;
  size_t valsz;
  time_t expires;

  mark_point();
  res = pr_memcache_kincr(NULL, NULL, NULL, 0, 0, NULL);
  ck_assert_msg(res < 0, "Failed to handle null mcache");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  mcache = pr_memcache_conn_new(p, NULL, 0, 0);
  ck_assert_msg(mcache != NULL, "Failed to open connection to Memcached: %s",
    strerror(errno));

  mark_point();
  res = pr_memcache_kincr(mcache, NULL, NULL, 0, 0, NULL);
  ck_assert_msg(res < 0, "Failed to handle null module");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_memcache_kincr(mcache, &m, NULL, 0, 0, NULL);
  ck_assert_msg(res < 0, "Failed to handle null key");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  key = "testval";
  (void) pr_memcache_remove(mcache, &m, key, 0);

  mark_point();
  res = pr_memcache_kincr(mcache, &m, key, strlen(key), 0, NULL);
  ck_assert_msg(res < 0, "Failed to handle zero kincr");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  incr = 2;

  mark_point();
  res = pr_memcache_kincr(mcache, &m, key, strlen(key), incr, NULL);
  ck_assert_msg(res == 0, "Failed to handle nonexistent val: %s",
    strerror(errno));

  value = "31";
  valsz = strlen(value);

  mark_point();
  res = pr_memcache_set(mcache, &m, key, value, valsz, 0, 0);
  ck_assert_msg(res == 0, "Failed to set key '%s', val '%s': %s", key,
    value, strerror(errno));

  mark_point();
  res = pr_memcache_kincr(mcache, &m, key, strlen(key), incr, NULL);
  ck_assert_msg(res == 0, "Failed to increment key '%s' by %lu: %s", key,
    (unsigned long) incr, strerror(errno));

  val = 0;

  mark_point();
  res = pr_memcache_kincr(mcache, &m, key, strlen(key), incr, &val);
  ck_assert_msg(res == 0, "Failed to increment key '%s' by %lu: %s", key,
    (unsigned long) incr, strerror(errno));
  ck_assert_msg(val == 35, "Expected %lu, got %lu", (unsigned long) 35,
    (unsigned long) val);

  mark_point();
  res = pr_memcache_remove(mcache, &m, key, 0);
  ck_assert_msg(res == 0, "Failed to remove key '%s': %s", key,
    strerror(errno));

  /* Now, let's try incrementing a non-numeric value. */
  value = "Hello, World!";
  valsz = strlen(value);
  expires = 0;

  mark_point();
  res = pr_memcache_set(mcache, &m, key, value, valsz, expires, 0);
  ck_assert_msg(res == 0, "Failed to set key '%s', val '%s': %s", key, value,
    strerror(errno));

  mark_point();
  res = pr_memcache_kincr(mcache, &m, key, strlen(key), incr, &val);
  ck_assert_msg(res < 0, "Failed to handle non-numeric key value");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  (void) pr_memcache_remove(mcache, &m, key, 0);

  mark_point();
  res = pr_memcache_conn_destroy(mcache);
  ck_assert_msg(res == TRUE, "Failed to close mcache: %s", strerror(errno));
}
END_TEST

START_TEST (memcache_kdecr_test) {
  int res;
  pr_memcache_t *mcache;
  module m;
  const char *key;
  char *value;
  uint32_t decr;
  uint64_t val = 0;
  size_t valsz;
  time_t expires;

  mark_point();
  res = pr_memcache_kdecr(NULL, NULL, NULL, 0, 0, NULL);
  ck_assert_msg(res < 0, "Failed to handle null mcache");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  mcache = pr_memcache_conn_new(p, NULL, 0, 0);
  ck_assert_msg(mcache != NULL, "Failed to open connection to Memcached: %s",
    strerror(errno));

  mark_point();
  res = pr_memcache_kdecr(mcache, NULL, NULL, 0, 0, NULL);
  ck_assert_msg(res < 0, "Failed to handle null module");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_memcache_kdecr(mcache, &m, NULL, 0, 0, NULL);
  ck_assert_msg(res < 0, "Failed to handle null key");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  key = "testval";
  (void) pr_memcache_remove(mcache, &m, key, 0);

  mark_point();
  res = pr_memcache_kdecr(mcache, &m, key, strlen(key), 0, NULL);
  ck_assert_msg(res < 0, "Failed to handle zero kdecr");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  decr = 5;

  mark_point();
  res = pr_memcache_kdecr(mcache, &m, key, strlen(key), decr, NULL);
  ck_assert_msg(res < 0, "Failed to handle nonexistent key");
  ck_assert_msg(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  /* While libmemcached automatically creates a value for incrementing,
   * it does NOT do so for decrementing.  Yay asymmetry.
   */

  value = "31";
  valsz = strlen(value);
  expires = 0;

  mark_point();
  res = pr_memcache_set(mcache, &m, key, value, valsz, expires, 0);
  ck_assert_msg(res == 0, "Failed to set key '%s', val '%s': %s", key, value,
    strerror(errno));

  mark_point();
  res = pr_memcache_kdecr(mcache, &m, key, strlen(key), decr, NULL);
  ck_assert_msg(res == 0, "Failed to decrement key '%s' by %lu: %s", key,
    (unsigned long) decr, strerror(errno));

  val = 0;

  mark_point();
  res = pr_memcache_kdecr(mcache, &m, key, strlen(key), decr, &val);
  ck_assert_msg(res == 0, "Failed to decrement key '%s' by %lu: %s", key,
    (unsigned long) decr, strerror(errno));
  ck_assert_msg(val == 21, "Expected %lu, got %lu", (unsigned long) 21,
    (unsigned long) val);

  mark_point();
  res = pr_memcache_remove(mcache, &m, key, 0);
  ck_assert_msg(res == 0, "Failed to remove key '%s': %s", key,
    strerror(errno));

  /* Now, let's try decrementing a non-numeric value. */
  value = "Hello, World!";
  valsz = strlen(value);
  expires = 0;

  mark_point();
  res = pr_memcache_set(mcache, &m, key, value, valsz, expires, 0);
  ck_assert_msg(res == 0, "Failed to set key '%s', val '%s': %s", key, value,
    strerror(errno));

  mark_point();
  res = pr_memcache_kdecr(mcache, &m, key, strlen(key), decr, &val);
  ck_assert_msg(res < 0, "Failed to handle non-numeric key value");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  (void) pr_memcache_remove(mcache, &m, key, 0);

  mark_point();
  res = pr_memcache_conn_destroy(mcache);
  ck_assert_msg(res == TRUE, "Failed to close mcache: %s", strerror(errno));
}
END_TEST

START_TEST (memcache_kset_test) {
  int res;
  pr_memcache_t *mcache;
  module m;
  const char *key;
  char *val;
  size_t valsz;
  time_t expires;

  mark_point();
  res = pr_memcache_kset(NULL, NULL, NULL, 0, NULL, 0, 0, 0);
  ck_assert_msg(res < 0, "Failed to handle null mcache");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  mcache = pr_memcache_conn_new(p, NULL, 0, 0);
  ck_assert_msg(mcache != NULL, "Failed to open connection to Memcached: %s",
    strerror(errno));

  mark_point();
  res = pr_memcache_kset(mcache, NULL, NULL, 0, NULL, 0, 0, 0);
  ck_assert_msg(res < 0, "Failed to handle null module");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_memcache_kset(mcache, &m, NULL, 0, NULL, 0, 0, 0);
  ck_assert_msg(res < 0, "Failed to handle null key");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  key = "testkey";

  mark_point();
  res = pr_memcache_kset(mcache, &m, key, strlen(key), NULL, 0, 0, 0);
  ck_assert_msg(res < 0, "Failed to handle null value");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  val = "testval";
  valsz = strlen(val);
  expires = 0;

  mark_point();
  res = pr_memcache_kset(mcache, &m, key, strlen(key), val, valsz, expires, 0);
  ck_assert_msg(res == 0, "Failed to set key '%s', val '%s': %s", key, val,
    strerror(errno));

  mark_point();
  res = pr_memcache_remove(mcache, &m, key, 0);
  ck_assert_msg(res == 0, "Failed to remove key '%s': %s", key,
    strerror(errno));

  expires = 3;

  mark_point();
  res = pr_memcache_kset(mcache, &m, key, strlen(key), val, valsz, expires, 0);
  ck_assert_msg(res == 0, "Failed to set key '%s', val '%s': %s", key, val,
    strerror(errno));

  mark_point();
  res = pr_memcache_remove(mcache, &m, key, 0);
  ck_assert_msg(res == 0, "Failed to remove key '%s': %s", key,
    strerror(errno));

  mark_point();
  res = pr_memcache_conn_destroy(mcache);
  ck_assert_msg(res == TRUE, "Failed to close mcache: %s", strerror(errno));
}
END_TEST
#endif /* PR_USE_MEMCACHE */

Suite *tests_get_memcache_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("memcache");
  testcase = tcase_create("base");

#if defined(PR_USE_MEMCACHE)
  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, memcache_conn_destroy_test);
  tcase_add_test(testcase, memcache_conn_close_test);
  tcase_add_test(testcase, memcache_conn_new_test);
  tcase_add_test(testcase, memcache_conn_get_test);
  tcase_add_test(testcase, memcache_conn_clone_test);
  tcase_add_test(testcase, memcache_conn_set_namespace_test);

  tcase_add_test(testcase, memcache_remove_test);
  tcase_add_test(testcase, memcache_add_test);
  tcase_add_test(testcase, memcache_add_with_namespace_test);
  tcase_add_test(testcase, memcache_get_test);
  tcase_add_test(testcase, memcache_get_with_namespace_test);
  tcase_add_test(testcase, memcache_get_str_test);
  tcase_add_test(testcase, memcache_incr_test);
  tcase_add_test(testcase, memcache_decr_test);
  tcase_add_test(testcase, memcache_set_test);

  tcase_add_test(testcase, memcache_kremove_test);
  tcase_add_test(testcase, memcache_kadd_test);
  tcase_add_test(testcase, memcache_kget_test);
  tcase_add_test(testcase, memcache_kget_str_test);
  tcase_add_test(testcase, memcache_kincr_test);
  tcase_add_test(testcase, memcache_kdecr_test);
  tcase_add_test(testcase, memcache_kset_test);

  /* Some of the Memcache tests may take a little longer. */
  tcase_set_timeout(testcase, 30);
#endif /* PR_USE_MEMCACHE */

  suite_add_tcase(suite, testcase);
  return suite;
}
