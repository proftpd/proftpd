/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2015 The ProFTPD Project team
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

/* Miscellaneous tests
 */

#include "tests.h"

static pool *p = NULL;

static unsigned int schedule_called = 0;

/* Fixtures */

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  init_fs();
  pr_fs_statcache_set_policy(PR_TUNABLE_FS_STATCACHE_SIZE,
    PR_TUNABLE_FS_STATCACHE_MAX_AGE, 0);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("fsio", 1, 20);
    pr_trace_set_levels("fs.statcache", 1, 20);
  }

  schedule_called = 0;
}

static void tear_down(void) {
  pr_fs_statcache_set_policy(PR_TUNABLE_FS_STATCACHE_SIZE,
    PR_TUNABLE_FS_STATCACHE_MAX_AGE, 0);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("fsio", 0, 0);
    pr_trace_set_levels("fs.statcache", 0, 0);
  }

  if (p) {
    destroy_pool(p);
    p = session.pool = permanent_pool = NULL;
  }
}

static void schedule_cb(void *arg1, void *arg2, void *arg3, void *arg4) {
  schedule_called++;
}

/* Tests */

START_TEST (schedule_test) {
  mark_point();
  schedule(NULL, 0, NULL, NULL, NULL, NULL);

  mark_point();
  schedule(schedule_cb, -1, NULL, NULL, NULL, NULL);

  mark_point();
  run_schedule();

  mark_point();
  schedule(schedule_cb, 0, NULL, NULL, NULL, NULL);

  run_schedule();
  fail_unless(schedule_called == 1, "Expected 1, got %u", schedule_called);

  run_schedule();
  fail_unless(schedule_called == 1, "Expected 1, got %u", schedule_called);

  mark_point();
  schedule(schedule_cb, 0, NULL, NULL, NULL, NULL);
  schedule(schedule_cb, 0, NULL, NULL, NULL, NULL);

  run_schedule();
  fail_unless(schedule_called == 3, "Expected 3, got %u", schedule_called);

  run_schedule();
  fail_unless(schedule_called == 3, "Expected 3, got %u", schedule_called);

  mark_point();

  /* Schedule this callback to run after 2 "loops", i.e. calls to
   * run_schedule().
   */
  schedule(schedule_cb, 2, NULL, NULL, NULL, NULL);

  run_schedule();
  fail_unless(schedule_called == 3, "Expected 3, got %u", schedule_called);

  run_schedule();
  fail_unless(schedule_called == 3, "Expected 3, got %u", schedule_called);

  run_schedule();
  fail_unless(schedule_called == 4, "Expected 4, got %u", schedule_called);
}
END_TEST

START_TEST (get_name_max_test) {
  size_t res;
  char *path;
  int fd;

  res = get_name_max(NULL, -1);
  fail_unless(res == (size_t) -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = "/";
  res = get_name_max(path, -1);
  fail_unless(res == (size_t) -1, "Couldn't get name max for '%s': %s", path,
    strerror(errno));

  fd = 1;
  res = get_name_max(NULL, fd);
  fail_unless(res == (size_t) -1, "Couldn't get name max for fd %d: %s", fd,
    strerror(errno));
  fail_unless(res != NAME_MAX_GUESS, "Expected other than %lu, got %lu",
    (unsigned long) NAME_MAX_GUESS, (unsigned long) res);

  fd = 777;
  res = get_name_max(NULL, fd);
  fail_unless(res == (size_t) -1, "Couldn't get name max for fd %d: %s", fd,
    strerror(errno));
}
END_TEST

START_TEST (safe_token_test) {
  char *res, *text, *expected;

  mark_point();
  expected = "";
  res = safe_token(NULL);
  fail_unless(res != NULL, "Failed to handle null arguments");
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  mark_point();
  text = "";
  expected = "";
  res = safe_token(&text);
  fail_unless(res != NULL, "Failed to handle null arguments");
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  mark_point();
  text = "foo";
  expected = text;
  res = safe_token(&text);
  fail_unless(res != NULL, "Failed to handle null arguments");
  fail_unless(res == expected, "Expected '%s', got '%s'", expected, res);
  fail_unless(strcmp(text, "") == 0, "Expected '', got '%s'", text);

  mark_point();
  text = "  foo";
  expected = text + 2;
  res = safe_token(&text);
  fail_unless(res != NULL, "Failed to handle null arguments");
  fail_unless(res == expected, "Expected '%s', got '%s'", expected, res);
  fail_unless(strcmp(text, "") == 0, "Expected '', got '%s'", text);

  mark_point();
  text = "  \t";
  expected = "";
  res = safe_token(&text);
  fail_unless(res != NULL, "Failed to handle null arguments");
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);
}
END_TEST

START_TEST (memscrub_test) {
  void *ptr;
  size_t len;
  char *expected, *text;

  mark_point();
  pr_memscrub(NULL, 1);

  expected = "Hello, World!";
  text = pstrdup(p, expected);

  mark_point();
  pr_memscrub(text, 0);

  len = strlen(text);

  mark_point();
  pr_memscrub(text, len);
  fail_unless(strncmp(text, expected, len + 1) != 0,
    "Expected other than '%s'", expected);
}
END_TEST

START_TEST (getopt_reset_test) {
  mark_point();
  pr_getopt_reset();
}
END_TEST

START_TEST (exists_test) {
  int res;
  const char *path;

  res = exists(NULL);
  fail_unless(res == FALSE, "Failed to handle null arguments");

  path = "/";
  res = exists(path);
  fail_unless(res == TRUE, "Expected TRUE for path '%s', got FALSE", path);
}
END_TEST

START_TEST (dir_exists_test) {
  int res;
  const char *path;

  res = dir_exists(NULL);
  fail_unless(res == FALSE, "Failed to handle null arguments");

  path = "/";
  res = dir_exists(path);
  fail_unless(res == TRUE, "Expected TRUE for path '%s', got FALSE", path);

  path = "./api-tests";
  res = dir_exists(path);
  fail_unless(res == FALSE, "Expected FALSE for path '%s', got TRUE", path);
}
END_TEST

START_TEST (symlink_mode_test) {
  mode_t res;
  const char *path;

  res = symlink_mode(NULL);
  fail_unless(res == 0, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = "/";
  res = symlink_mode(path);
  fail_unless(res == 0, "Found mode for non-symlink '%s'", path);
}
END_TEST

START_TEST (file_mode_test) {
  mode_t res;
  const char *path;

  res = file_mode(NULL);
  fail_unless(res == 0, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = "/";
  res = file_mode(path);
  fail_unless(res != 0, "Failed to find mode for '%s': %s", path,
    strerror(errno));
}
END_TEST

START_TEST (file_exists_test) {
  int res;
  const char *path;

  res = file_exists(NULL);
  fail_unless(res == FALSE, "Failed to handle null arguments");

  path = "/";
  res = file_exists(path);
  fail_unless(res == FALSE, "Expected FALSE for path '%s', got TRUE", path);

  path = "./api-tests";
  res = file_exists(path);
  fail_unless(res == TRUE, "Expected TRUE for path '%s', got FALSE", path);
}
END_TEST

START_TEST (gmtime_test) {
  struct tm *res;
  time_t now;

  mark_point();
  res = pr_gmtime(NULL, NULL); 
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  time(&now);

  mark_point();
  res = pr_gmtime(NULL, &now);
  fail_unless(res != NULL, "Failed to handle %lu: %s", (unsigned long) now,
    strerror(errno));

  mark_point();
  res = pr_gmtime(p, &now);
  fail_unless(res != NULL, "Failed to handle %lu: %s", (unsigned long) now,
    strerror(errno));
}
END_TEST

START_TEST (localtime_test) {
  struct tm *res;
  time_t now;

  mark_point();
  res = pr_localtime(NULL, NULL); 
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  time(&now);

  mark_point();
  res = pr_localtime(NULL, &now);
  fail_unless(res != NULL, "Failed to handle %lu: %s", (unsigned long) now,
    strerror(errno));

  mark_point();
  res = pr_localtime(p, &now);
  fail_unless(res != NULL, "Failed to handle %lu: %s", (unsigned long) now,
    strerror(errno));
}
END_TEST

START_TEST (strtime_test) {
  const char *res;
  time_t now;

  mark_point();
  now = 0;
  res = pr_strtime(now);
  fail_unless(res != NULL, "Failed to convert time %lu: %s",
    (unsigned long) now, strerror(errno));
}
END_TEST

START_TEST (strtime2_test) {
  const char *res;
  char *expected;
  time_t now;

  mark_point();
  now = 0;
  expected = "Thu Jan 01 00:00:00 1970";
  res = pr_strtime2(now, TRUE);
  fail_unless(res != NULL, "Failed to convert time %lu: %s",
    (unsigned long) now, strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);
}
END_TEST

START_TEST (timeval2millis_test) {
  int res;
  struct timeval tv;
  uint64_t ms;

  res = pr_timeval2millis(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_timeval2millis(&tv, NULL);
  fail_unless(res < 0, "Failed to handle null millis argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  tv.tv_sec = tv.tv_usec = 0;
  res = pr_timeval2millis(&tv, &ms);
  fail_unless(res == 0, "Failed to convert timeval to millis: %s",
    strerror(errno));
  fail_unless(ms == 0, "Expected 0 ms, got %lu", (unsigned long) ms);
}
END_TEST

START_TEST (gettimeofday_millis_test) {
  int res;
  uint64_t ms;

  res = pr_gettimeofday_millis(NULL);
  fail_unless(res < 0, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  ms = 0;
  res = pr_gettimeofday_millis(&ms);
  fail_unless(res == 0, "Failed to get current time ms: %s", strerror(errno));
  fail_unless(ms > 0, "Expected >0, got %lu", (unsigned long) ms);
}
END_TEST

Suite *tests_get_misc_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("misc");

  testcase = tcase_create("base");
  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, schedule_test);
  tcase_add_test(testcase, get_name_max_test);
#if 0
  tcase_add_test(testcase, dir_interpolate_test);
  tcase_add_test(testcase, dir_best_path_test);
  tcase_add_test(testcase, dir_canonical_path_test);
  tcase_add_test(testcase, dir_canonical_vpath_test);
  tcase_add_test(testcase, dir_realpath_test);
  tcase_add_test(testcase, dir_abs_path_test);
#endif
  tcase_add_test(testcase, symlink_mode_test);
  tcase_add_test(testcase, file_mode_test);
  tcase_add_test(testcase, exists_test);
  tcase_add_test(testcase, dir_exists_test);
  tcase_add_test(testcase, file_exists_test);
  tcase_add_test(testcase, safe_token_test);
#if 0
  tcase_add_test(testcase, check_shutmsg_test);
#endif
  tcase_add_test(testcase, memscrub_test);
  tcase_add_test(testcase, getopt_reset_test);
  tcase_add_test(testcase, gmtime_test);
  tcase_add_test(testcase, localtime_test);
  tcase_add_test(testcase, strtime_test);
  tcase_add_test(testcase, strtime2_test);
  tcase_add_test(testcase, timeval2millis_test);
  tcase_add_test(testcase, gettimeofday_millis_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
