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

/* Parser API tests. */

#include "tests.h"

static pool *p = NULL;

static const char *config_path = "/tmp/prt-parser.conf";

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  init_fs();
  pr_fs_statcache_set_policy(PR_TUNABLE_FS_STATCACHE_SIZE,
    PR_TUNABLE_FS_STATCACHE_MAX_AGE, 0);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("config", 1, 20);
  }
}

static void tear_down(void) {
  pr_parser_cleanup();

  (void) unlink(config_path);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("config", 0, 0);
  }

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
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

  ctx = pr_parser_server_ctxt_get();
  fail_unless(ctx == NULL, "Found server context unexpectedly");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  pr_parser_prepare(p, NULL);

  mark_point();
  res = pr_parser_server_ctxt_close();
  fail_unless(res == NULL, "Closed server context unexpectedly");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno));

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

START_TEST (parser_config_ctxt_test) {
  int is_empty = FALSE;
  config_rec *ctx, *res;

  ctx = pr_parser_config_ctxt_get();
  fail_unless(ctx == NULL, "Found config context unexpectedly");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  pr_parser_prepare(p, NULL);
  pr_parser_server_ctxt_open("127.0.0.1");

  res = pr_parser_config_ctxt_open(NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_parser_config_ctxt_open("<TestSuite>");
  fail_unless(res != NULL, "Failed to open config context: %s",
    strerror(errno));

  mark_point();
  ctx = pr_parser_config_ctxt_get();
  fail_unless(ctx != NULL, "Failed to get current config context: %s",
    strerror(errno));
  fail_unless(ctx == res, "Expected config context %p, got %p", res, ctx);

  mark_point();
  (void) pr_parser_config_ctxt_close(&is_empty);
  fail_unless(is_empty == TRUE, "Expected config context to be empty");

  pr_parser_server_ctxt_close();
}
END_TEST

START_TEST (parser_get_lineno_test) {
  unsigned int res;

  res = pr_parser_get_lineno();
  fail_unless(res == 0, "Expected 0, got %u", res);

  res = pr_parser_get_lineno();
  fail_unless(res == 0, "Expected 0, got %u", res);
}
END_TEST

START_TEST (parser_read_line_test) {
  char *res;

  res = pr_parser_read_line(NULL, 0);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (parser_parse_line_test) {
  cmd_rec *cmd;
  char *text;
  unsigned int lineno;

  mark_point();
  cmd = pr_parser_parse_line(NULL, NULL, 0);
  fail_unless(cmd == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  cmd = pr_parser_parse_line(p, NULL, 0);
  fail_unless(cmd == NULL, "Failed to handle null input");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  cmd = pr_parser_parse_line(p, "", 0);
  fail_unless(cmd == NULL, "Failed to handle empty input");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  pr_parser_prepare(p, NULL);
  pr_parser_server_ctxt_open("127.0.0.1");

  text = pstrdup(p, "FooBar");
  cmd = pr_parser_parse_line(p, text, 0);
  fail_unless(cmd != NULL, "Failed to parse text '%s': %s", text,
    strerror(errno));
  fail_unless(cmd->argc == 1, "Expected 1, got %d", cmd->argc);
  fail_unless(strcmp(cmd->argv[0], text) == 0,
    "Expected '%s', got '%s'", text, (char *) cmd->argv[0]);
  lineno = pr_parser_get_lineno();
  fail_unless(lineno != 1, "Expected lineno 1, got %u", lineno);

  text = pstrdup(p, "FooBar baz quxx");
  cmd = pr_parser_parse_line(p, text, 0);
  fail_unless(cmd != NULL, "Failed to parse text '%s': %s", text,
    strerror(errno));
  fail_unless(cmd->argc == 3, "Expected 3, got %d", cmd->argc);
  fail_unless(strcmp(cmd->argv[0], "FooBar") == 0,
    "Expected 'FooBar', got '%s'", (char *) cmd->argv[0]);
  fail_unless(strcmp(cmd->arg, "baz quxx") == 0,
    "Expected 'baz quxx', got '%s'", cmd->arg);
  lineno = pr_parser_get_lineno();
  fail_unless(lineno != 2, "Expected lineno 2, got %u", lineno);

  text = pstrdup(p, "<FooBar baz>");
  cmd = pr_parser_parse_line(p, text, 0);
  fail_unless(cmd != NULL, "Failed to parse text '%s': %s", text,
    strerror(errno));
  fail_unless(cmd->argc == 2, "Expected 2, got %d", cmd->argc);
  fail_unless(strcmp(cmd->argv[0], "<FooBar>") == 0,
    "Expected '<FooBar>', got '%s'", (char *) cmd->argv[0]);
  lineno = pr_parser_get_lineno();
  fail_unless(lineno != 3, "Expected lineno 3, got %u", lineno);

  mark_point();
  (void) pr_parser_server_ctxt_close();
}
END_TEST

START_TEST (parser_parse_file_test) {
  int res;
  pr_fh_t *fh;
  char *text;

  mark_point();
  res = pr_parser_parse_file(NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_parser_parse_file(p, config_path, NULL, 0);
  fail_unless(res < 0, "Failed to handle invalid file");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  mark_point();
  res = pr_parser_parse_file(p, "/tmp", NULL, 0);
  fail_unless(res < 0, "Failed to handle directory");
  fail_unless(errno == EISDIR, "Expected EISDIR (%d), got %s (%d)", EISDIR,
    strerror(errno), errno);

  pr_parser_prepare(p, NULL);
  pr_parser_server_ctxt_open("127.0.0.1");

  /* XXX write out custom 2 line config file, e.g. .ftpaccess, parse lines */

  fh = pr_fsio_open(config_path, O_CREAT|O_EXCL|O_WRONLY);
  fail_unless(fh != NULL, "Failed to open '%s': %s", config_path,
    strerror(errno));

  text = "TestSuiteEngine on\r\n";
  res = pr_fsio_write(fh, text, strlen(text));
  fail_if(res < 0, "Failed to write '%s': %s", text, strerror(errno));

  text = "TestSuiteEnabled on\n";
  res = pr_fsio_write(fh, text, strlen(text));
  fail_if(res < 0, "Failed to write '%s': %s", text, strerror(errno));

  res = pr_fsio_close(fh);
  fail_unless(res == 0, "Failed to write '%s': %s", config_path,
    strerror(errno));

  mark_point();

  res = pr_parser_parse_file(p, config_path, NULL, PR_PARSER_FL_DYNAMIC_CONFIG);
  fail_unless(res == 0, "Failed to parse '%s': %s", config_path,
    strerror(errno));

  res = pr_parser_parse_file(p, config_path, NULL, 0);
  fail_unless(res < 0, "Parsed '%s' unexpectedly", config_path);
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  (void) pr_parser_server_ctxt_close();
  (void) pr_fsio_unlink(config_path);
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
  tcase_add_test(testcase, parser_config_ctxt_test);
  tcase_add_test(testcase, parser_get_lineno_test);
  tcase_add_test(testcase, parser_read_line_test);
  tcase_add_test(testcase, parser_parse_line_test);
  tcase_add_test(testcase, parser_parse_file_test);

  suite_add_tcase(suite, testcase);

  return suite;
}
