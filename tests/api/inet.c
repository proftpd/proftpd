/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2014 The ProFTPD Project team
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

/* Inet API tests
 */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = make_sub_pool(NULL);
  }

  init_inet();
}

static void tear_down(void) {
  if (p) {
    destroy_pool(p);
    p = NULL;
  } 
}

START_TEST (inet_create_conn_test) {
  int sockfd = -2, port = INPORT_ANY;
  conn_t *conn;

  conn = pr_inet_create_conn(NULL, sockfd, NULL, port, FALSE);
  fail_unless(conn == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL,
    "Failed to set errno to EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));
  fail_unless(conn->listen_fd == sockfd, "Expected listen_fd %d, got %d",
    sockfd, conn->listen_fd);
  pr_inet_close(p, conn);

  sockfd = -1;
  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));
  fail_unless(conn->listen_fd != sockfd,
    "Expected listen_fd other than %d, got %d",
    sockfd, conn->listen_fd);
  pr_inet_close(p, conn);
}
END_TEST

START_TEST (inet_set_async_test) {
  int res;
  conn_t *conn = NULL;

  res = pr_inet_set_async(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected errno EINVAL (%d), got '%s' (%d)",
    EINVAL, strerror(errno), errno);

}
END_TEST

START_TEST (inet_set_block_test) {
  int res;
  conn_t *conn = NULL;

  res = pr_inet_set_block(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected errno EINVAL (%d), got '%s' (%d)",
    EINVAL, strerror(errno), errno);

}
END_TEST

START_TEST (inet_set_nonblock_test) {
  int res;
  conn_t *conn = NULL;

  res = pr_inet_set_nonblock(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected errno EINVAL (%d), got '%s' (%d)",
    EINVAL, strerror(errno), errno);

}
END_TEST

START_TEST (inet_set_proto_cork_test) {
  int res, sockfd = -1;

  res = pr_inet_set_proto_cork(sockfd, TRUE);
  fail_unless(res < 0, "Failed to handle bad socket descriptor");
  fail_unless(errno == EBADF,
    "Failed to set errno to EBADF (%d), got '%s' (%d)", EBADF, strerror(errno),
    errno);
}
END_TEST

Suite *tests_get_inet_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("inet");

  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, inet_create_conn_test);
  tcase_add_test(testcase, inet_set_async_test);
  tcase_add_test(testcase, inet_set_block_test);
  tcase_add_test(testcase, inet_set_nonblock_test);
  tcase_add_test(testcase, inet_set_proto_cork_test);

  suite_add_tcase(suite, testcase);

  return suite;
}
