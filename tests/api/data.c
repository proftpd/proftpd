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

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_use_stderr(TRUE);
    pr_trace_set_levels("data", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_use_stderr(FALSE);
    pr_trace_set_levels("data", 0, 0);
  }

  if (p) {
    destroy_pool(p);
    p = session.pool = session.xfer.p = NULL;
  } 
}

START_TEST (data_get_timeout_test) {
  int res;

  res = pr_data_get_timeout(-1);
  fail_unless(res < 0, "Failed to handle invalid timeout ID");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_data_get_timeout(PR_DATA_TIMEOUT_IDLE);
  fail_unless(res == PR_TUNABLE_TIMEOUTIDLE, "Expected %d, got %d",
    PR_TUNABLE_TIMEOUTIDLE, res);

  res = pr_data_get_timeout(PR_DATA_TIMEOUT_NO_TRANSFER);
  fail_unless(res == PR_TUNABLE_TIMEOUTNOXFER, "Expected %d, got %d",
    PR_TUNABLE_TIMEOUTNOXFER, res);

  res = pr_data_get_timeout(PR_DATA_TIMEOUT_STALLED);
  fail_unless(res == PR_TUNABLE_TIMEOUTSTALLED, "Expected %d, got %d",
    PR_TUNABLE_TIMEOUTSTALLED, res);
}
END_TEST

START_TEST (data_set_timeout_test) {
  int res, timeout = 7;

  pr_data_set_timeout(PR_DATA_TIMEOUT_IDLE, timeout);
  res = pr_data_get_timeout(PR_DATA_TIMEOUT_IDLE);
  fail_unless(res == timeout, "Expected %d, got %d", timeout, res);

  pr_data_set_timeout(PR_DATA_TIMEOUT_NO_TRANSFER, timeout);
  res = pr_data_get_timeout(PR_DATA_TIMEOUT_NO_TRANSFER);
  fail_unless(res == timeout, "Expected %d, got %d", timeout, res);

  pr_data_set_timeout(PR_DATA_TIMEOUT_STALLED, timeout);
  res = pr_data_get_timeout(PR_DATA_TIMEOUT_STALLED);
  fail_unless(res == timeout, "Expected %d, got %d", timeout, res);

  /* Interestingly, the linger timeout has its own function. */
  pr_data_set_linger(7L);
}
END_TEST

START_TEST (data_ignore_ascii_test) {
  int res;

  res = pr_data_ignore_ascii(-1);
  fail_unless(res < 0, "Failed to handle invalid argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_data_ignore_ascii(TRUE);
  fail_unless(res == FALSE, "Expected FALSE (%d), got %d", FALSE, res);

  res = pr_data_ignore_ascii(TRUE);
  fail_unless(res == TRUE, "Expected TRUE (%d), got %d", TRUE, res);

  res = pr_data_ignore_ascii(FALSE);
  fail_unless(res == TRUE, "Expected TRUE (%d), got %d", TRUE, res);

  res = pr_data_ignore_ascii(FALSE);
  fail_unless(res == FALSE, "Expected FALSE (%d), got %d", FALSE, res);
}
END_TEST

START_TEST (data_sendfile_test) {
  int fd = -1, res;

  session.xfer.direction = PR_NETIO_IO_RD;
  res = pr_data_sendfile(fd, NULL, 1);
  fail_unless(res < 0, "Failed to handle invalid transfer direction");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  session.xfer.direction = PR_NETIO_IO_WR;
  res = pr_data_sendfile(fd, NULL, 1);
  fail_unless(res < 0, "Failed to handle lack of data connection");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
}
END_TEST

Suite *tests_get_data_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("data");

  testcase = tcase_create("base");
  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, data_get_timeout_test);
  tcase_add_test(testcase, data_set_timeout_test);
  tcase_add_test(testcase, data_ignore_ascii_test);

#if 0
  tcase_add_test(testcase, data_init_test);
  tcase_add_test(testcase, data_open_test);
  tcase_add_test(testcase, data_close_test);
  tcase_add_test(testcase, data_abort_test);
  tcase_add_test(testcase, data_reset_test);
  tcase_add_test(testcase, data_cleanup_test);

  /* This is the big one! */
  tcase_add_test(testcase, data_xfer_test);
#endif

  tcase_add_test(testcase, data_sendfile_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
