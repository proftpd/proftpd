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

/* Data API tests */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = session.pool = make_sub_pool(NULL);
  }

  init_netio();
}

static void tear_down(void) {
  if (p) {
    destroy_pool(p);
    p = session.pool = session.xfer.p = NULL;
  } 
}

START_TEST (data_open_test) {
  int res;

  /* TODO:
   *  data.c#data_active_open: needs session.c != NULL
   */
#if 0
  res = pr_data_open(NULL, NULL, 0, 0);
  fail_unless(res == 0, "Failed to open data channel: %s", strerror(errno));
#endif
}
END_TEST

START_TEST (data_xfer_ascii_read_test) {
  /* TODO:
   *  data.c#data_active_open: needs session.c != NULL
   *  data.c#pr_data_xfer: needs session.d != NULL
   */
}
END_TEST

START_TEST (data_xfer_ascii_write_test) {
  /* TODO:
   *  data.c#data_active_open: needs session.c != NULL
   *  data.c#pr_data_xfer: needs session.d != NULL
   */
}
END_TEST

Suite *tests_get_data_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("data");

  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, data_open_test);
  tcase_add_test(testcase, data_xfer_ascii_read_test);
  tcase_add_test(testcase, data_xfer_ascii_write_test);

  suite_add_tcase(suite, testcase);

  return suite;
}
