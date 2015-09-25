/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2008-2015 The ProFTPD Project team
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

/* Regexp API tests */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  init_regexp();

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_use_stderr(TRUE);
    pr_trace_set_levels("regexp", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_use_stderr(FALSE);
    pr_trace_set_levels("regexp", 0, 0);
  }

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }
}

START_TEST (regexp_alloc_test) {
  pr_regex_t *res;

  res = pr_regexp_alloc(NULL);
  fail_unless(res != NULL, "Failed to allocate regex: %s", strerror(errno));
  pr_regexp_free(NULL, res);
}
END_TEST

START_TEST (regexp_free_test) {
  mark_point();
  pr_regexp_free(NULL, NULL);
}
END_TEST

START_TEST (regexp_compile_test) {
  pr_regex_t *pre = NULL;
  int res;
  char errstr[256], *pattern;
  size_t errstrlen;

  res = pr_regexp_compile(NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  pre = pr_regexp_alloc(NULL);

  res = pr_regexp_compile(pre, NULL, 0);
  fail_unless(res < 0, "Failed to handle null pattern");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  pattern = "[=foo";
  res = pr_regexp_compile(pre, pattern, 0); 
  fail_unless(res != 0, "Successfully compiled pattern unexpectedly"); 

  errstrlen = pr_regexp_error(res, pre, errstr, sizeof(errstr));
  fail_unless(errstrlen > 0, "Failed to get regex compilation error string");

  pattern = "foo";
  res = pr_regexp_compile(pre, pattern, 0);
  fail_unless(res == 0, "Failed to compile regex pattern");

  pr_regexp_free(NULL, pre);
}
END_TEST

START_TEST (regexp_compile_posix_test) {
  pr_regex_t *pre = NULL;
  int res;
  char *pattern;

  res = pr_regexp_compile_posix(NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  pre = pr_regexp_alloc(NULL);

  res = pr_regexp_compile_posix(pre, NULL, 0);
  fail_unless(res < 0, "Failed to handle null pattern");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  pattern = "[=foo";
  res = pr_regexp_compile_posix(pre, pattern, 0);
  fail_unless(res != 0, "Successfully compiled pattern unexpectedly");

  pattern = "foo";
  res = pr_regexp_compile_posix(pre, pattern, 0);
  fail_unless(res == 0, "Failed to compile regex pattern");

  pr_regexp_free(NULL, pre);
}
END_TEST

START_TEST (regexp_get_pattern_test) {
  pr_regex_t *pre = NULL;
  int res;
  const char *str;
  char *pattern;

  str = pr_regexp_get_pattern(NULL);
  fail_unless(str == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  pre = pr_regexp_alloc(NULL);
  pattern = "^foo";
  res = pr_regexp_compile(pre, pattern, 0);
  fail_unless(res == 0, "Failed to compile regex pattern '%s'", pattern);

  str = pr_regexp_get_pattern(pre);
  fail_unless(str != NULL, "Failed to get regex pattern: %s", strerror(errno));
  fail_unless(strcmp(str, pattern) == 0, "Expected '%s', got '%s'", pattern,
    str);

  pr_regexp_free(NULL, pre);
}
END_TEST

START_TEST (regexp_set_limits_test) {
  int res;

  res = pr_regexp_set_limits(0, 0);
  fail_unless(res == 0, "Failed to set limits: %s", strerror(errno));
}
END_TEST

START_TEST (regexp_exec_test) {
  pr_regex_t *pre = NULL;
  int res;
  char *pattern, *str;

  res = pr_regexp_exec(NULL, NULL, 0, NULL, 0, 0, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  pre = pr_regexp_alloc(NULL);

  pattern = "^foo";
  res = pr_regexp_compile(pre, pattern, 0);
  fail_unless(res == 0, "Failed to compile regex pattern");

  res = pr_regexp_exec(pre, NULL, 0, NULL, 0, 0, 0);
  fail_unless(res != 0, "Failed to handle null string");

  str = "bar";
  res = pr_regexp_exec(pre, str, 0, NULL, 0, 0, 0);
  fail_unless(res != 0, "Matched string unexpectedly");

  str = "foobar";
  res = pr_regexp_exec(pre, str, 0, NULL, 0, 0, 0);
  fail_unless(res == 0, "Failed to match string");

  pr_regexp_free(NULL, pre);
}
END_TEST

START_TEST (regexp_cleanup_test) {
  pr_regex_t *pre, *pre2;

  pre = pr_regexp_alloc(NULL);
  pre2 = pr_regexp_alloc(NULL);

  mark_point();
  pr_event_generate("core.restart", NULL);

  mark_point();
  pr_event_generate("core.exit", NULL);

  mark_point();
  pr_regexp_free(NULL, pre);

  mark_point();
  pr_regexp_free(NULL, pre2);
}
END_TEST

Suite *tests_get_regexp_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("regexp");

  testcase = tcase_create("base");
  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, regexp_alloc_test);
  tcase_add_test(testcase, regexp_free_test);
  tcase_add_test(testcase, regexp_compile_test);
  tcase_add_test(testcase, regexp_compile_posix_test);
  tcase_add_test(testcase, regexp_exec_test);
  tcase_add_test(testcase, regexp_get_pattern_test);
  tcase_add_test(testcase, regexp_set_limits_test);
  tcase_add_test(testcase, regexp_cleanup_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
