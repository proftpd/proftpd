/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2014-2015 The ProFTPD Project team
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

/* Inet API tests */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  init_inet();

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_use_stderr(TRUE);
    pr_trace_set_levels("inet", 1, 20);
  }
}

static void tear_down(void) {
  pr_inet_clear();

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  } 

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_use_stderr(FALSE);
    pr_trace_set_levels("inet", 0, 0);
  }
}

START_TEST (inet_family_test) {
  int res;

  res = pr_inet_set_default_family(p, AF_INET);
  fail_unless(res == 0, "Expected previous family 0, got %d", res);

  res = pr_inet_set_default_family(p, 0);
  fail_unless(res == AF_INET, "Expected previous family %d, got %d", AF_INET,
    res);
}
END_TEST

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

START_TEST (inet_create_conn_portrange_test) {
  conn_t *conn;

  conn = pr_inet_create_conn_portrange(NULL, NULL, -1, -1);
  fail_unless(conn == NULL, "Failed to handle negative ports");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn_portrange(NULL, NULL, 10, 1);
  fail_unless(conn == NULL, "Failed to handle bad ports");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  conn = pr_inet_create_conn_portrange(p, NULL, 49152, 65534);
  fail_unless(conn != NULL, "Failed to create conn in portrange: %s",
    strerror(errno));
  pr_inet_lingering_close(p, conn, 0L);
}
END_TEST

START_TEST (inet_copy_conn_test) {
  int sockfd = -1, port = INPORT_ANY;
  conn_t *conn, *conn2;

  conn = pr_inet_copy_conn(NULL, NULL);
  fail_unless(conn == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_copy_conn(p, NULL);
  fail_unless(conn == NULL, "Failed to handle null conn argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  conn2 = pr_inet_copy_conn(p, conn);
  fail_unless(conn2 != NULL, "Failed to copy conn: %s", strerror(errno));

  pr_inet_close(p, conn);
  pr_inet_close(p, conn2);
}
END_TEST

START_TEST (inet_set_async_test) {
  int sockfd = -1, port = INPORT_ANY, res;
  conn_t *conn;

  res = pr_inet_set_async(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected errno EINVAL (%d), got '%s' (%d)",
    EINVAL, strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  res = pr_inet_set_async(p, conn);
  fail_unless(res == 0, "Failed to set conn %p async: %s", conn,
    strerror(errno));

  pr_inet_close(p, conn);
}
END_TEST

START_TEST (inet_set_block_test) {
  int sockfd = -1, port = INPORT_ANY, res;
  conn_t *conn; 

  res = pr_inet_set_block(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected errno EINVAL (%d), got '%s' (%d)",
    EINVAL, strerror(errno), errno);

  res = pr_inet_set_nonblock(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected errno EINVAL (%d), got '%s' (%d)",
    EINVAL, strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  res = pr_inet_set_nonblock(p, conn);
  fail_unless(res < 0, "Failed to handle bad socket");
  fail_unless(errno == EBADF, "Expected EBADF (%d), got %s (%d)", EBADF,
    strerror(errno), errno);

  res = pr_inet_set_block(p, conn);
  fail_unless(res < 0, "Failed to handle bad socket");
  fail_unless(errno == EBADF, "Expected EBADF (%d), got %s (%d)", EBADF,
    strerror(errno), errno);

  pr_inet_close(p, conn);
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

START_TEST (inet_set_proto_nodelay_test) {
  int fd, sockfd = -1, port = INPORT_ANY, res;
  conn_t *conn;

  res = pr_inet_set_proto_nodelay(NULL, NULL, 1);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  res = pr_inet_set_proto_nodelay(p, conn, 1);
  fail_unless(res == 0, "Failed to enable nodelay: %s", strerror(errno));

  res = pr_inet_set_proto_nodelay(p, conn, 0);
  fail_unless(res == 0, "Failed to disable nodelay: %s", strerror(errno));

  fd = conn->rfd;
  conn->rfd = 8;
  res = pr_inet_set_proto_nodelay(p, conn, 0);
  fail_unless(res == 0, "Failed to disable nodelay: %s", strerror(errno));
  conn->rfd = fd;

  fd = conn->wfd;
  conn->rfd = 9;
  res = pr_inet_set_proto_nodelay(p, conn, 0);
  fail_unless(res == 0, "Failed to disable nodelay: %s", strerror(errno));
  conn->wfd = fd;

  pr_inet_close(p, conn);
}
END_TEST

START_TEST (inet_set_proto_opts_test) {
  int fd, sockfd = -1, port = INPORT_ANY, res;
  conn_t *conn;

  mark_point();
  res = pr_inet_set_proto_opts(NULL, NULL, 1, 1, 1, 1);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  mark_point();
  res = pr_inet_set_proto_opts(p, conn, 1, 1, 1, 1);
  fail_unless(res == 0, "Failed to set proto opts: %s", strerror(errno));

  mark_point();
  fd = conn->rfd;
  conn->rfd = 8;
  res = pr_inet_set_proto_opts(p, conn, 1, 1, 1, 1);
  fail_unless(res == 0, "Failed to set proto opts: %s", strerror(errno));
  conn->rfd = fd;

  mark_point();
  fd = conn->wfd;
  conn->wfd = 9;
  res = pr_inet_set_proto_opts(p, conn, 1, 1, 1, 1);
  fail_unless(res == 0, "Failed to set proto opts: %s", strerror(errno));
  conn->wfd = fd;

  mark_point();
  fd = conn->listen_fd;
  conn->listen_fd = 10;
  res = pr_inet_set_proto_opts(p, conn, 1, 1, 1, 1);
  fail_unless(res == 0, "Failed to set proto opts: %s", strerror(errno));
  conn->listen_fd = fd;

  pr_inet_close(p, conn);
}
END_TEST

START_TEST (inet_set_socket_opts_test) {
  int sockfd = -1, port = INPORT_ANY, res;
  conn_t *conn;

  res = pr_inet_set_socket_opts(NULL, NULL, 1, 2, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  res = pr_inet_set_socket_opts(p, conn, 1, 2, NULL);
  fail_unless(res == 0, "Failed to set socket opts: %s", strerror(errno));

  pr_inet_close(p, conn);
}
END_TEST

START_TEST (inet_listen_test) {
  int fd, sockfd = -1, port = INPORT_ANY, res;
  conn_t *conn;

  res = pr_inet_listen(NULL, NULL, 5, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_inet_resetlisten(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  fd = conn->listen_fd;
  conn->listen_fd = 777;
  res = pr_inet_listen(p, conn, 5, 0);
  fail_unless(res < 0, "Succeeded in listening on conn unexpectedly");
  fail_unless(errno == EBADF, "Expected EBADF (%d), got %s (%d)", EBADF,
    strerror(errno), errno);
  conn->listen_fd = fd;

  res = pr_inet_listen(p, conn, 5, 0);
  fail_unless(res == 0, "Failed to listen on conn: %s", strerror(errno));

  res = pr_inet_resetlisten(p, conn);
  fail_unless(res == 0, "Failed to reset listen mode: %s", strerror(errno));

  res = pr_inet_listen(p, conn, 5, 0);
  fail_unless(res < 0, "Failed to handle already-listening socket");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  pr_inet_close(p, conn);
}
END_TEST

START_TEST (inet_connect_test) {
  int sockfd = -1, port = INPORT_ANY, res;
  conn_t *conn;
  pr_netaddr_t *addr;

  res = pr_inet_connect(NULL, NULL, NULL, port);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  res = pr_inet_connect(p, conn, NULL, 80);
  fail_unless(res < 0, "Failed to handle null connection");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  addr = pr_netaddr_get_addr(p, "127.0.0.1", NULL);
  fail_unless(addr != NULL, "Failed to resolve '127.0.0.1': %s",
    strerror(errno));

  res = pr_inet_connect(p, conn, addr, 80);
  fail_unless(res < 0, "Connected to 127.0.0.1#80 unexpectedly");

  pr_inet_close(p, conn);
}
END_TEST

START_TEST (inet_connect_nowait_test) {
  int sockfd = -1, port = INPORT_ANY, res;
  conn_t *conn;
  pr_netaddr_t *addr;

  res = pr_inet_connect_nowait(NULL, NULL, NULL, port);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  res = pr_inet_connect_nowait(p, conn, NULL, 80);
  fail_unless(res < 0, "Failed to handle null connection");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  addr = pr_netaddr_get_addr(p, "127.0.0.1", NULL);
  fail_unless(addr != NULL, "Failed to resolve '127.0.0.1': %s",
    strerror(errno));

  res = pr_inet_connect_nowait(p, conn, addr, 80);
  fail_unless(res < 0, "Connected to 127.0.0.1#80 unexpectedly");

  pr_inet_close(p, conn);
}
END_TEST

START_TEST (inet_accept_test) {
  conn_t *conn;

  conn = pr_inet_accept(NULL, NULL, NULL, 0, 2, FALSE);
  fail_unless(conn == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (inet_accept_nowait_test) {
  int sockfd = -1, port = INPORT_ANY, res;
  conn_t *conn;

  res = pr_inet_accept_nowait(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  res = pr_inet_accept_nowait(p, conn);
  fail_unless(res < 0, "Accepted connection unexpectedly");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  pr_inet_close(p, conn);
}
END_TEST

START_TEST (inet_conn_info_test) {
  int sockfd = -1, port = INPORT_ANY, res;
  conn_t *conn;

  res = pr_inet_get_conn_info(NULL, -1);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  res = pr_inet_get_conn_info(conn, -1);
  fail_unless(res < 0, "Failed to handle bad file descriptor");
  fail_unless(errno == EBADF, "Expected EBADF (%d), got %s (%d)", EBADF,
    strerror(errno), errno);

  res = pr_inet_get_conn_info(conn, 1);
  fail_unless(res < 0, "Failed to handle bad file descriptor");
  fail_unless(errno == ENOTSOCK, "Expected ENOTSOCK (%d), got %s (%d)",
    ENOTSOCK, strerror(errno), errno);

  pr_inet_close(p, conn);
}
END_TEST

Suite *tests_get_inet_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("inet");

  testcase = tcase_create("base");
  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, inet_family_test);
  tcase_add_test(testcase, inet_create_conn_test);
  tcase_add_test(testcase, inet_create_conn_portrange_test);
  tcase_add_test(testcase, inet_copy_conn_test);
  tcase_add_test(testcase, inet_set_async_test);
  tcase_add_test(testcase, inet_set_block_test);
  tcase_add_test(testcase, inet_set_proto_cork_test);
  tcase_add_test(testcase, inet_set_proto_nodelay_test);
  tcase_add_test(testcase, inet_set_proto_opts_test);
  tcase_add_test(testcase, inet_set_socket_opts_test);
  tcase_add_test(testcase, inet_listen_test);
  tcase_add_test(testcase, inet_connect_test);
  tcase_add_test(testcase, inet_connect_nowait_test);
  tcase_add_test(testcase, inet_accept_test);
  tcase_add_test(testcase, inet_accept_nowait_test);
  tcase_add_test(testcase, inet_conn_info_test);

  suite_add_tcase(suite, testcase);

  return suite;
}
