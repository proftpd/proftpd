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
    p = session.pool = permanent_pool = make_sub_pool(NULL);
  }

  init_netio();
  init_dirtree();
  pr_response_set_pool(p);

  session.sf_flags = 0;

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

  if (session.c != NULL) {
    (void) pr_inet_close(p, session.c);
    session.c = NULL;
  }

  pr_response_set_pool(NULL);

  if (p) {
    destroy_pool(p);
    p = session.pool = session.xfer.p = permanent_pool = NULL;
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

START_TEST (data_init_test) {
  int rd = PR_NETIO_IO_RD, wr = PR_NETIO_IO_WR;
  char *filename = NULL;

  mark_point();
  pr_data_init(filename, 0);
  fail_unless(session.xfer.direction == 0, "Expected xfer direction %d, got %d",
    0, session.xfer.direction);
  fail_unless(session.xfer.p != NULL, "Transfer pool not created as expected");
  fail_unless(session.xfer.filename == NULL, "Expected null filename, got %s",
    session.xfer.filename);

  filename = "test.dat";
  pr_data_clear_xfer_pool();

  mark_point();
  pr_data_init(filename, rd);
  fail_unless(session.xfer.direction == rd,
    "Expected xfer direction %d, got %d", rd, session.xfer.direction);
  fail_unless(session.xfer.p != NULL, "Transfer pool not created as expected");
  fail_unless(session.xfer.filename != NULL, "Missing transfer filename");
  fail_unless(strcmp(session.xfer.filename, filename) == 0,
    "Expected '%s', got '%s'", filename, session.xfer.filename);

  mark_point();
  pr_data_init("test2.dat", wr);
  fail_unless(session.xfer.direction == wr,
    "Expected xfer direction %d, got %d", wr, session.xfer.direction);
  fail_unless(session.xfer.p != NULL, "Transfer pool not created as expected");
  fail_unless(session.xfer.filename != NULL, "Missing transfer filename");

  /* Even though we opened with a new filename, the previous filename should
   * still be there, as we didn't actually clear/reset this transfer.
   */
  fail_unless(strcmp(session.xfer.filename, filename) == 0,
    "Expected '%s', got '%s'", filename, session.xfer.filename);
}
END_TEST

START_TEST (data_open_active_test) {
  int dir = PR_NETIO_IO_RD, port = INPORT_ANY, sockfd = -1, res;
  conn_t *conn;

  mark_point();
  res = pr_data_open(NULL, NULL, dir, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  /* Note: these tests REQUIRE that session.c be non-NULL */
  session.c = conn;

  /* Open a READing data transfer connection...*/

  mark_point();
  res = pr_data_open(NULL, NULL, dir, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Note: we also need session.c to have valid local/remote_addr, too! */
  session.c->local_addr = session.c->remote_addr = pr_netaddr_get_addr(p, "127.0.0.1", NULL);
  fail_unless(session.c->remote_addr != NULL, "Failed to get address: %s",
    strerror(errno));

  mark_point();
  res = pr_data_open(NULL, NULL, dir, 0);
  fail_unless(res < 0, "Opened active READ data connection unexpectedly");
  fail_unless(errno == EADDRNOTAVAIL || errno == ECONNREFUSED,
    "Expected EADDRNOTAVAIL (%d) or ECONNREFUSED (%d), got %s (%d)",
    EADDRNOTAVAIL, ECONNREFUSED, strerror(errno), errno);

  /* Open a WRITing data transfer connection...*/
  dir = PR_NETIO_IO_WR;

  mark_point();
  res = pr_data_open(NULL, NULL, dir, 0);
  fail_unless(res < 0, "Opened active READ data connection unexpectedly");
  fail_unless(errno == EADDRNOTAVAIL || errno == ECONNREFUSED,
    "Expected EADDRNOTAVAIL (%d) or ECONNREFUSED (%d), got %s (%d)",
    EADDRNOTAVAIL, ECONNREFUSED, strerror(errno), errno);

  (void) pr_inet_close(p, session.c);
  session.c = NULL;
  if (session.d != NULL) {
    (void) pr_inet_close(p, session.d);
    session.d = NULL;
  }
}
END_TEST

START_TEST (data_open_passive_test) {
  int dir = PR_NETIO_IO_RD, port = INPORT_ANY, sockfd = -1, res;

  /* Set the session flags for a passive transfer data connection. */
  session.sf_flags |= SF_PASSIVE;

  mark_point();
  res = pr_data_open(NULL, NULL, dir, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Note: these tests REQUIRE that session.c be non-NULL, AND that session.d
   * be non-NULL.
   */
  session.c = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(session.c != NULL, "Failed to create conn: %s", strerror(errno));

  session.d = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(session.d != NULL, "Failed to create conn: %s", strerror(errno));

  /* Open a READing data transfer connection...*/

  mark_point();
  res = pr_data_open(NULL, NULL, dir, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Note: we also need session.c to have valid local/remote_addr, too! */
  session.c->local_addr = session.c->remote_addr = pr_netaddr_get_addr(p, "127.0.0.1", NULL);
  fail_unless(session.c->remote_addr != NULL, "Failed to get address: %s",
    strerror(errno));

  mark_point();
  res = pr_data_open(NULL, NULL, dir, 0);
  fail_unless(res < 0, "Opened passive READ data connection unexpectedly");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Open a WRITing data transfer connection...*/
  dir = PR_NETIO_IO_WR;

  mark_point();
  res = pr_data_open(NULL, NULL, dir, 0);
  fail_unless(res < 0, "Opened passive READ data connection unexpectedly");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  (void) pr_inet_close(p, session.c);
  session.c = NULL;
  if (session.d != NULL) {
    (void) pr_inet_close(p, session.d);
    session.d = NULL;
  }
}
END_TEST

START_TEST (data_close_test) {
  session.sf_flags |= SF_PASSIVE;
  pr_data_close(TRUE);
  fail_unless(!(session.sf_flags & SF_PASSIVE),
    "Failed to clear SF_PASSIVE session flag");

  session.sf_flags |= SF_PASSIVE;
  pr_data_close(FALSE);
  fail_unless(!(session.sf_flags & SF_PASSIVE),
    "Failed to clear SF_PASSIVE session flag");
}
END_TEST

START_TEST (data_abort_test) {
  session.sf_flags |= SF_PASSIVE;
  pr_data_abort(EPERM, TRUE);
  fail_unless(!(session.sf_flags & SF_PASSIVE),
    "Failed to clear SF_PASSIVE session flag");

  session.sf_flags |= SF_PASSIVE;
  pr_data_abort(EPERM, FALSE);
  fail_unless(!(session.sf_flags & SF_PASSIVE),
    "Failed to clear SF_PASSIVE session flag");
}
END_TEST

START_TEST (data_reset_test) {
  mark_point();

  /* Set a session flag, make sure it's cleared properly. */
  session.sf_flags |= SF_PASSIVE;
  pr_data_reset();
  fail_unless(session.d == NULL, "Expected NULL session.d, got %p", session.d);
  fail_unless(!(session.sf_flags & SF_PASSIVE),
    "SF_PASSIVE session flag not cleared");
}
END_TEST

START_TEST (data_cleanup_test) {
  mark_point();

  /* Set a session flag, make sure it's cleared properly. */
  session.sf_flags |= SF_PASSIVE;
  pr_data_cleanup();
  fail_unless(session.d == NULL, "Expected NULL session.d, got %p", session.d);
  fail_unless(session.sf_flags & SF_PASSIVE,
    "SF_PASSIVE session flag not preserved");
  fail_unless(session.xfer.xfer_type == STOR_DEFAULT, "Expected %d, got %d",
    STOR_DEFAULT, session.xfer.xfer_type);
}
END_TEST

START_TEST (data_clear_xfer_pool_test) {
  int xfer_type = 7;

  mark_point();
  pr_data_clear_xfer_pool();
  fail_unless(session.xfer.p == NULL, "Failed to clear session.xfer.p");

  session.xfer.xfer_type = xfer_type; 
  session.xfer.p = make_sub_pool(p);

  mark_point();
  pr_data_clear_xfer_pool();
  fail_unless(session.xfer.p == NULL, "Failed to clear session.xfer.p");
  fail_unless(session.xfer.xfer_type == xfer_type, "Expected %d, got %d",
    xfer_type, session.xfer.xfer_type);
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
  tcase_add_test(testcase, data_sendfile_test);

  tcase_add_test(testcase, data_init_test);
  tcase_add_test(testcase, data_open_active_test);
  tcase_add_test(testcase, data_open_passive_test);
  tcase_add_test(testcase, data_close_test);
  tcase_add_test(testcase, data_abort_test);
  tcase_add_test(testcase, data_reset_test);
  tcase_add_test(testcase, data_cleanup_test);
  tcase_add_test(testcase, data_clear_xfer_pool_test);

#if 0
  /* This is the big one! */
  tcase_add_test(testcase, data_xfer_test);
#endif

  suite_add_tcase(suite, testcase);
  return suite;
}
