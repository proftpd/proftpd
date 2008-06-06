/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2008 The ProFTPD Project team
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 *
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* Scoreboard API tests
 * $Id: scoreboard.c,v 1.1 2008-06-06 00:46:25 castaglia Exp $
 */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }
}

static void tear_down(void) {
  if (p) {
    destroy_pool(p);
    p = NULL;
    permanent_pool = NULL;
  } 
}

START_TEST (scoreboard_get_test) {
  const char *ok, *res;

  ok = PR_RUN_DIR "/proftpd.scoreboard";

  res = pr_get_scoreboard();
  fail_unless(res != NULL, "Failed to get scoreboard path");
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);
}
END_TEST

START_TEST (scoreboard_set_test) {
  int res;

  res = pr_set_scoreboard(NULL);
  fail_unless(res == -1, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_set_scoreboard("foo");
  fail_unless(res == -1, "Failed to handle non-path argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_set_scoreboard("foo/");
  fail_unless(res == -1, "Failed to handle relative path argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_set_scoreboard("/foo/");
  fail_unless(res == -1, "Failed to handle nonexistent path argument");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT");
}
END_TEST

START_TEST (scoreboard_open_test) {
}
END_TEST

START_TEST (scoreboard_close_test) {
}
END_TEST

START_TEST (scoreboard_delete_test) {
}
END_TEST

START_TEST (scoreboard_restore_test) {
}
END_TEST

START_TEST (scoreboard_rewind_test) {
}
END_TEST

START_TEST (scoreboard_scrub_test) {
}
END_TEST

START_TEST (scoreboard_get_daemon_pid_test) {
}
END_TEST

START_TEST (scoreboard_get_daemon_uptime_test) {
}
END_TEST

START_TEST (scoreboard_entry_add_test) {
}
END_TEST

START_TEST (scoreboard_entry_del_test) {
}
END_TEST

START_TEST (scoreboard_entry_read_test) {
}
END_TEST

START_TEST (scoreboard_entry_get_test) {
}
END_TEST

START_TEST (scoreboard_entry_update_test) {
}
END_TEST

Suite *tests_get_scoreboard_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("scoreboard");

  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, scoreboard_get_test);
  tcase_add_test(testcase, scoreboard_set_test);
  tcase_add_test(testcase, scoreboard_open_test);
  tcase_add_test(testcase, scoreboard_close_test);
  tcase_add_test(testcase, scoreboard_delete_test);
  tcase_add_test(testcase, scoreboard_restore_test);
  tcase_add_test(testcase, scoreboard_rewind_test);
  tcase_add_test(testcase, scoreboard_scrub_test);
  tcase_add_test(testcase, scoreboard_get_daemon_pid_test);
  tcase_add_test(testcase, scoreboard_get_daemon_uptime_test);
  tcase_add_test(testcase, scoreboard_entry_add_test);
  tcase_add_test(testcase, scoreboard_entry_del_test);
  tcase_add_test(testcase, scoreboard_entry_read_test);
  tcase_add_test(testcase, scoreboard_entry_get_test);
  tcase_add_test(testcase, scoreboard_entry_update_test);

  suite_add_tcase(suite, testcase);

  return suite;
}
