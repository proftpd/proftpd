/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2016 The ProFTPD Project team
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

/* Hiding API tests */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = make_sub_pool(NULL);
  }

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("hiding", 1, 20);
  }

  hiding_init();
}

static void tear_down(void) {
  hiding_finish();

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("hiding", 0, 0);
  }

  if (p) {
    destroy_pool(p);
    p = NULL;
  }
}

static int hider1(pool *hp, const char *path, const char *abs_path,
    void *user_data) {
  return 0;
}

static int hider2(pool *hp, const char *path, const char *abs_path,
    void *user_data) {
  return 0;
}

START_TEST (hiding_register_unregister_test) {
  int res;
  const char *handler_name = NULL;

  res = pr_hiding_register(NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  handler_name = "foo";
  res = pr_hiding_register(NULL, handler_name, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  hiding_finish();
  res = pr_hiding_register(NULL, handler_name, hider1, NULL);
  fail_unless(res < 0, "Failed to handle uninitialized API");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  hiding_init();
  res = pr_hiding_register(NULL, handler_name, hider1, NULL);
  fail_unless(res == 0, "Failed to register handler '%s': %s", handler_name,
    strerror(errno));

  res = pr_hiding_register(NULL, handler_name, hider2, NULL);
  fail_unless(res < 0, "Failed to handle duplicate handler names");
  fail_unless(errno == EEXIST, "Expected EEXIST (%d), got %s (%d)", EEXIST,
    strerror(errno), errno);

  handler_name = "bar";
  res = pr_hiding_register(NULL, handler_name, hider2, NULL);
  fail_unless(res == 0, "Failed to register handler '%s': %s", handler_name,
    strerror(errno));

  handler_name = "foo";
  res = pr_hiding_unregister(NULL, handler_name);
  fail_unless(res == 0, "Failed to unregister handler '%s': %s", handler_name,
    strerror(errno));

  res = pr_hiding_unregister(NULL, handler_name);
  fail_unless(res < 0, "Failed to handle absent handlers");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  handler_name = "bar";
  res = pr_hiding_unregister(NULL, handler_name);
  fail_unless(res == 0, "Failed to unregister handler '%s': %s", handler_name,
    strerror(errno));

  mark_point();

  handler_name = "foo";
  res = pr_hiding_register(NULL, handler_name, hider1, NULL);
  fail_unless(res == 0, "Failed to register handler '%s': %s", handler_name,
    strerror(errno));

  handler_name = "bar";
  res = pr_hiding_register(NULL, handler_name, hider2, NULL);
  fail_unless(res == 0, "Failed to register handler '%s': %s", handler_name,
    strerror(errno));

  res = pr_hiding_unregister(NULL, NULL);
  fail_unless(res == 0, "Failed to unregister all handlers: %s",
    strerror(errno));

  /* Already unregistered everything, right? */
  res = pr_hiding_unregister(NULL, NULL);
  fail_unless(res < 0, "Unregistered all handlers unexpectedly");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
}
END_TEST

static int erroring_hider(pool *hp, const char *path, const char *abs_path,
    void *user_data) {
  errno = ENOSYS;
  return -1;
}

static int ignoring_hider(pool *hp, const char *path, const char *abs_path,
    void *user_data) {
  return 0;
}

static int hiding_hider(pool *hp, const char *path, const char *abs_path,
    void *user_data) {
  return 1;
}

START_TEST (hiding_hide_path_test) {
  int res;
  const char *handler_name, *path;

  res = pr_hiding_hide_path(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_hiding_hide_path(p, NULL);
  fail_unless(res < 0, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* No handlers registered */
  (void) pr_hiding_unregister(NULL, NULL);
  path = "/tmp/foo";
  res = pr_hiding_hide_path(p, path);
  fail_unless(res == 0, "Expected 0 for path '%s', got %d (%s)", path, res,
    res < 0 ? strerror(errno) : "OK");

  /* Erroring handler */
  (void) pr_hiding_unregister(NULL, NULL);
  handler_name = "errorer";
  res = pr_hiding_register(NULL, handler_name, erroring_hider, NULL);
  fail_unless(res == 0, "Failed to register handler '%s': %s", handler_name,
    strerror(errno));

  res = pr_hiding_hide_path(p, path);
  fail_unless(res == 0, "Expected 0 for path '%s', got %d (%s)", path, res,
    res < 0 ? strerror(errno) : "OK");

  /* Ignoring handler */
  (void) pr_hiding_unregister(NULL, NULL);
  handler_name = "ignorer";
  res = pr_hiding_register(NULL, handler_name, ignoring_hider, NULL);
  fail_unless(res == 0, "Failed to register handler '%s': %s", handler_name,
    strerror(errno));
  
  res = pr_hiding_hide_path(p, path);
  fail_unless(res == 0, "Expected 0 for path '%s', got %d (%s)", path, res,
    res < 0 ? strerror(errno) : "OK");

  /* Hiding handler FIRST */
  (void) pr_hiding_unregister(NULL, NULL);
  handler_name = "hider";
  res = pr_hiding_register(NULL, handler_name, hiding_hider, NULL);
  fail_unless(res == 0, "Failed to register handler '%s': %s", handler_name,
    strerror(errno));
 
  res = pr_hiding_hide_path(p, path);
  fail_unless(res == 1, "Expected 1 for path '%s', got %d (%s)", path, res,
    res < 0 ? strerror(errno) : "OK");

  /* Hiding handler LAST */
  handler_name = "ignorer";
  res = pr_hiding_register(NULL, handler_name, ignoring_hider, NULL);
  fail_unless(res == 0, "Failed to register handler '%s': %s", handler_name,
    strerror(errno));

  handler_name = "errorer";
  res = pr_hiding_register(NULL, handler_name, erroring_hider, NULL);
  fail_unless(res == 0, "Failed to register handler '%s': %s", handler_name,
    strerror(errno));

  res = pr_hiding_hide_path(p, path);
  fail_unless(res == 1, "Expected 1 for path '%s', got %d (%s)", path, res,
    res < 0 ? strerror(errno) : "OK");

  (void) pr_hiding_unregister(NULL, NULL);
}
END_TEST

static void hiding_dump(const char *fmt, ...) {
  va_list msg;

  va_start(msg, fmt);
  pr_trace_vmsg("hiding", 9, fmt, msg);
  va_end(msg);
}

START_TEST (hiding_dump_test) {
  int res;
  const char *handler_name;

  mark_point();
  pr_hiding_dump(NULL);

  mark_point();
  pr_hiding_dump(hiding_dump);

  handler_name = "foo";
  res = pr_hiding_register(NULL, handler_name, hider1, NULL);
  fail_unless(res == 0, "Failed to register handler '%s': %s", handler_name,
    strerror(errno));

  handler_name = "bar";
  res = pr_hiding_register(NULL, handler_name, hider2, NULL);
  fail_unless(res == 0, "Failed to register handler '%s': %s", handler_name,
    strerror(errno));

  pr_hiding_dump(hiding_dump);

  res = pr_hiding_unregister(NULL, NULL);
  fail_unless(res == 0, "Failed to unregister all handlers: %s",
    strerror(errno));
}
END_TEST

Suite *tests_get_hiding_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("hiding");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, hiding_register_unregister_test);
  tcase_add_test(testcase, hiding_hide_path_test);
  tcase_add_test(testcase, hiding_dump_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
