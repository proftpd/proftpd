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

/* Fixtures */

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }
}

static void tear_down(void) {
  if (p) {
    destroy_pool(p);
    p = session.pool = permanent_pool = NULL;
  }
}

/* Tests */

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

  tcase_add_test(testcase, timeval2millis_test);
  tcase_add_test(testcase, gettimeofday_millis_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
