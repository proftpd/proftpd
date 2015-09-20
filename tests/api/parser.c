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

/* Parser API tests. */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = make_sub_pool(NULL);
  }
}

static void tear_down(void) {
  pr_parser_cleanup();

  if (p) {
    destroy_pool(p);
    p = NULL;
  } 
}

START_TEST (parser_prepare_test) {
  int res;
  xaset_t *parsed_servers = NULL;

  res = pr_parser_prepare(NULL, NULL);
  fail_unless(res == 0, "Failed to handle null arguments: %s", strerror(errno));

  res = pr_parser_prepare(p, NULL);
  fail_unless(res == 0, "Failed to handle null parsed_servers: %s",
    strerror(errno));

  res = pr_parser_prepare(NULL, &parsed_servers);
  fail_unless(res == 0, "Failed to handle null pool: %s", strerror(errno));
}
END_TEST

START_TEST (parser_server_ctxt_test) {
  server_rec *ctx, *res;

  pr_parser_prepare(p, NULL);

  mark_point();
  res = pr_parser_server_ctxt_open("127.0.0.1");
  fail_unless(res != NULL, "Failed to open server context: %s",
    strerror(errno));

  mark_point();
  ctx = pr_parser_server_ctxt_get();
  fail_unless(ctx != NULL, "Failed to get current server context: %s",
    strerror(errno));
  fail_unless(ctx == res, "Expected server context %p, got %p", res, ctx);

  mark_point();
  (void) pr_parser_server_ctxt_close();
}
END_TEST

Suite *tests_get_parser_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("parser");

  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, parser_prepare_test);
  tcase_add_test(testcase, parser_server_ctxt_test);
#if 0
  tcase_add_test(testcase, parser_read_line_test);
  tcase_add_test(testcase, parser_parse_file_test);
  tcase_add_test(testcase, parser_get_lineno_test);
#endif

  suite_add_tcase(suite, testcase);

  return suite;
}
