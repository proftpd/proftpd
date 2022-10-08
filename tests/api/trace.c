/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2014-2022 The ProFTPD Project team
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

/* Trace API tests */

#include "tests.h"

static pool *p = NULL;

static const char *trace_path = "/tmp/prt-trace.log";

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  init_inet();
}

static void tear_down(void) {
  (void) unlink(trace_path);

  pr_inet_clear();
  pr_trace_set_options(PR_TRACE_OPT_DEFAULT);

  if (p != NULL) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  } 
}

#if defined(PR_USE_TRACE)

START_TEST (trace_set_levels_test) {
  int min_level, max_level, res;
  const char *channel;

  mark_point();
  res = pr_trace_set_levels(NULL, 0, 0);
  ck_assert_msg(res < 0, "Failed to handle null channel, no table");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  mark_point();
  channel = "foo";
  min_level = 3;
  max_level = 1;
  res = pr_trace_set_levels(channel, min_level, max_level);
  ck_assert_msg(res < 0, "Failed to handle min level > max level");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  mark_point();
  min_level = 1;
  max_level = 2; 
  res = pr_trace_set_levels(channel, min_level, max_level);
  ck_assert_msg(res == 0, "Failed to handle valid channel and levels: %s",
    strerror(errno));

  mark_point();
  res = pr_trace_set_levels(PR_TRACE_DEFAULT_CHANNEL, 1, 5);
  ck_assert_msg(res == 0, "Failed to set default channels: %s", strerror(errno));

  mark_point();
  res = pr_trace_set_levels(PR_TRACE_DEFAULT_CHANNEL, 0, 0);
  ck_assert_msg(res == 0, "Failed to set default channels: %s", strerror(errno));
}
END_TEST

START_TEST (trace_get_table_test) {
  pr_table_t *res;

  mark_point();
  res = pr_trace_get_table();
  ck_assert_msg(res == NULL, "Failed to handle uninitialized Trace API");
  ck_assert_msg(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));

  mark_point();
  pr_trace_set_levels("foo", 1, 2);

  mark_point();
  res = pr_trace_get_table();
  ck_assert_msg(res != NULL, "Did not get Trace API table as expected: %s",
    strerror(errno));
}
END_TEST

START_TEST (trace_get_max_level_test) {
  int min_level, max_level, res;
  const char *channel;

  channel = "foo";
  min_level = 1;
  max_level = 2;

  mark_point();
  res = pr_trace_get_max_level(NULL);
  ck_assert_msg(res < 0, "Failed to handle null channel");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  mark_point();
  res = pr_trace_get_max_level("bar");
  ck_assert_msg(res < 0, "Failed to handle unset channels/levels");
  ck_assert_msg(errno == EPERM, "Failed to set errno to EPERM, got %d (%s)",
    errno, strerror(errno));

  mark_point();
  res = pr_trace_set_levels(channel, min_level, max_level);
  ck_assert_msg(res == 0, "Failed to set '%s:%d-%d': %s", channel, min_level,
    max_level, strerror(errno));

  mark_point();
  res = pr_trace_get_max_level("bar");
  ck_assert_msg(res < 0, "Failed to handle unknown channel");
  ck_assert_msg(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));

  mark_point();
  res = pr_trace_get_max_level(channel);
  ck_assert_msg(res == max_level, "Failed to get level %d for channel '%s': %s",
    max_level, channel, strerror(errno));
}
END_TEST

START_TEST (trace_get_min_level_test) {
  int min_level, max_level, res;
  const char *channel;

  channel = "foo";
  min_level = 1;
  max_level = 2;

  mark_point();
  res = pr_trace_get_min_level(NULL);
  ck_assert_msg(res < 0, "Failed to handle null channel");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  mark_point();
  res = pr_trace_get_min_level("bar");
  ck_assert_msg(res < 0, "Failed to handle unset channels/levels");
  ck_assert_msg(errno == EPERM, "Failed to set errno to EPERM, got %d (%s)",
    errno, strerror(errno));

  mark_point();
  res = pr_trace_set_levels(channel, min_level, max_level);
  ck_assert_msg(res == 0, "Failed to set '%s:%d-%d': %s", channel, min_level,
    max_level, strerror(errno));

  mark_point();
  res = pr_trace_get_min_level("bar");
  ck_assert_msg(res < 0, "Failed to handle unknown channel");
  ck_assert_msg(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));

  mark_point();
  res = pr_trace_get_min_level(channel);
  ck_assert_msg(res == min_level, "Failed to get level %d for channel '%s': %s",
    min_level, channel, strerror(errno));
}
END_TEST

START_TEST (trace_get_level_test) {
  int min_level, max_level, res;
  const char *channel;

  channel = "foo";
  min_level = 1;
  max_level = 2;

  mark_point();
  res = pr_trace_get_level(NULL);
  ck_assert_msg(res < 0, "Failed to handle null channel");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  mark_point();
  res = pr_trace_get_level("bar");
  ck_assert_msg(res < 0, "Failed to handle unset channels/levels");
  ck_assert_msg(errno == EPERM, "Failed to set errno to EPERM, got %d (%s)",
    errno, strerror(errno));

  mark_point();
  res = pr_trace_set_levels(channel, min_level, max_level);
  ck_assert_msg(res == 0, "Failed to set '%s:%d-%d': %s", channel, min_level,
    max_level, strerror(errno));

  mark_point();
  res = pr_trace_get_level("bar");
  ck_assert_msg(res < 0, "Failed to handle unknown channel");
  ck_assert_msg(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));

  mark_point();
  res = pr_trace_get_level(channel);
  ck_assert_msg(res == max_level, "Failed to get level %d for channel '%s': %s",
    max_level, channel, strerror(errno));
}
END_TEST

START_TEST (trace_parse_levels_test) {
  int min_level, max_level, res;
  char *level_str;

  mark_point();
  res = pr_trace_parse_levels(NULL, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null arguments");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  mark_point();
  res = pr_trace_parse_levels("", &min_level, &max_level);
  ck_assert_msg(res < 0, "Failed to handle empty string");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  mark_point();
  level_str = "foo";
  res = pr_trace_parse_levels(level_str, &min_level, &max_level);
  ck_assert_msg(res < 0, "Failed to handle invalid levels string");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  mark_point();
  level_str = pstrdup(p, "-7");
  res = pr_trace_parse_levels(level_str, &min_level, &max_level);
  ck_assert_msg(res < 0, "Failed to handle negative levels string");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  /* Overflow the int data type, in order to get a negative number without
   * using the dash.
   */
  mark_point();
  level_str = pstrdup(p, "2147483653");
  res = pr_trace_parse_levels(level_str, &min_level, &max_level);
  ck_assert_msg(res < 0, "Failed to handle negative levels string");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  mark_point();
  level_str = pstrdup(p, "0");
  res = pr_trace_parse_levels(level_str, &min_level, &max_level);
  ck_assert_msg(res == 0, "Failed to handle single level zero string");
  ck_assert_msg(min_level == 0, "Expected min level 0, got %d", max_level);
  ck_assert_msg(max_level == 0, "Expected max level 0, got %d", max_level);

  mark_point();
  level_str = pstrdup(p, "7");
  res = pr_trace_parse_levels(level_str, &min_level, &max_level);
  ck_assert_msg(res == 0, "Failed to handle single level string");
  ck_assert_msg(min_level == 1, "Expected min level 1, got %d", max_level);
  ck_assert_msg(max_level == 7, "Expected max level 7, got %d", max_level);

  mark_point();
  level_str = pstrdup(p, "abc-def");
  res = pr_trace_parse_levels(level_str, &min_level, &max_level);
  ck_assert_msg(res < 0, "Failed to handle invalid levels string");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  mark_point();
  level_str = pstrdup(p, "1-def");
  res = pr_trace_parse_levels(level_str, &min_level, &max_level);
  ck_assert_msg(res < 0, "Failed to handle invalid levels string");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  /* Overflow the int data type, in order to get a negative number without
   * using the dash.
   */
  mark_point();
  level_str = pstrdup(p, "2147483653-10");
  res = pr_trace_parse_levels(level_str, &min_level, &max_level);
  ck_assert_msg(res < 0, "Failed to handle negative levels string");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  mark_point();
  level_str = pstrdup(p, "10-2147483653");
  res = pr_trace_parse_levels(level_str, &min_level, &max_level);
  ck_assert_msg(res < 0, "Failed to handle negative levels string");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  mark_point();
  level_str = pstrdup(p, "-7-5");
  res = pr_trace_parse_levels(level_str, &min_level, &max_level);
  ck_assert_msg(res < 0, "Failed to handle negative levels string");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  mark_point();
  level_str = pstrdup(p, "0--1");
  res = pr_trace_parse_levels(level_str, &min_level, &max_level);
  ck_assert_msg(res < 0, "Failed to handle single level zero string");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  mark_point();
  level_str = pstrdup(p, "8-7");
  res = pr_trace_parse_levels(level_str, &min_level, &max_level);
  ck_assert_msg(res < 0, "Failed to handle max level < min level");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  mark_point();
  level_str = pstrdup(p, "1-7");
  res = pr_trace_parse_levels(level_str, &min_level, &max_level);
  ck_assert_msg(res == 0, "Failed to handle levels string");
  ck_assert_msg(min_level == 1, "Expected min level 1, got %d", max_level);
  ck_assert_msg(max_level == 7, "Expected max level 7, got %d", max_level);
}
END_TEST

START_TEST (trace_msg_test) {
  int res;
  char *channel, msg[16384];

  mark_point();
  res = pr_trace_msg(NULL, -1, NULL);
  ck_assert_msg(res < 0, "Failed to handle null arguments");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  channel = "testsuite";

  mark_point();
  res = pr_trace_msg(channel, -1, NULL);
  ck_assert_msg(res < 0, "Failed to handle bad level");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_trace_msg(channel, 1, NULL);
  ck_assert_msg(res < 0, "Failed to handle null message");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  pr_trace_set_levels(channel, 1, 10);

  mark_point();
  memset(msg, 'A', sizeof(msg)-1);
  msg[sizeof(msg)-1] = '\0';
  pr_trace_msg(channel, 5, "%s", msg);

  mark_point();
  session.c = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  ck_assert_msg(session.c != NULL, "Failed to create conn: %s", strerror(errno));
  session.c->local_addr = session.c->remote_addr =
    pr_netaddr_get_addr(p, "127.0.0.1", NULL);

  mark_point();
  res = pr_trace_set_options(PR_TRACE_OPT_LOG_CONN_IPS|PR_TRACE_OPT_USE_TIMESTAMP_MILLIS);
  ck_assert_msg(res == 0, "Failed to set options: %s", strerror(errno));
  pr_trace_msg(channel, 5, "%s", "alef bet vet?");

  res = pr_trace_set_options(0);
  ck_assert_msg(res == 0, "Failed to set options: %s", strerror(errno));
  pr_trace_msg(channel, 5, "%s", "alef bet vet?");

  pr_inet_close(p, session.c);
  session.c = NULL;

  pr_trace_set_levels(channel, 0, 0);
}
END_TEST

START_TEST (trace_set_file_test) {
  int res;
  const char *path;

  mark_point();
  path = "/";
  res = pr_trace_set_file(path);
  ck_assert_msg(res < 0, "Failed to handle path '%s'", path);
  ck_assert_msg(errno == EISDIR, "Expected EISDIR (%d), got %s (%d)", EISDIR,
    strerror(errno), errno);

  mark_point();
  path = "/tmp";
  res = pr_trace_set_file(path);
  ck_assert_msg(res < 0, "Failed to handle path '%s'", path);
  ck_assert_msg(errno == EISDIR, "Expected EISDIR (%d), got %s (%d)", EISDIR,
    strerror(errno), errno);

  mark_point();
  path = trace_path;
  res = pr_trace_set_file(path);
  ck_assert_msg(res == 0, "Failed to set trace file '%s': %s", path,
    strerror(errno));
  pr_trace_set_levels("foo", 1, 20);

  mark_point();
  pr_trace_msg("foo", 1, "bar?");
  pr_trace_msg("foo", 1, "baz!");

  mark_point();
  res = pr_trace_set_options(PR_TRACE_OPT_LOG_CONN_IPS|PR_TRACE_OPT_USE_TIMESTAMP_MILLIS);
  ck_assert_msg(res == 0, "Failed to set options: %s", strerror(errno));

  pr_trace_msg("foo", 1, "quxx?");
  pr_trace_msg("foo", 1, "QUZZ!");

  res = pr_trace_set_options(PR_TRACE_OPT_DEFAULT);
  ck_assert_msg(res == 0, "Failed to set default options: %s", strerror(errno));

  pr_trace_set_levels("foo", 0, 0);
  res = pr_trace_set_file(NULL);
  ck_assert_msg(res == 0, "Failed to reset trace file: %s", strerror(errno));

  (void) unlink(trace_path);
}
END_TEST

START_TEST (trace_restart_test) {
  pr_trace_set_levels("testsuite", 1, 10);
  pr_event_generate("core.restart", NULL);
}
END_TEST
#endif /* PR_USE_TRACE */

Suite *tests_get_trace_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("trace");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

#if defined(PR_USE_TRACE)
  tcase_add_test(testcase, trace_set_levels_test);
  tcase_add_test(testcase, trace_get_table_test);
  tcase_add_test(testcase, trace_get_max_level_test);
  tcase_add_test(testcase, trace_get_min_level_test);
  tcase_add_test(testcase, trace_get_level_test);
  tcase_add_test(testcase, trace_parse_levels_test);
  tcase_add_test(testcase, trace_msg_test);
  tcase_add_test(testcase, trace_set_file_test);
  tcase_add_test(testcase, trace_restart_test);
#endif /* PR_USE_TRACE */

  suite_add_tcase(suite, testcase);
  return suite;
}
