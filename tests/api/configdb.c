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

/* Configuration API tests
 */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  init_config();
  pr_parser_prepare(p, NULL);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_use_stderr(TRUE);
    pr_trace_set_levels("config", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_use_stderr(FALSE);
    pr_trace_set_levels("config", 0, 0);
  }

  pr_parser_cleanup();

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  } 
}

START_TEST (add_remove_config_test) {
  int res;
  const char *name = NULL;
  config_rec *c = NULL;
  server_rec *s = NULL;

  s = pr_parser_server_ctxt_open("127.0.0.1");
  fail_unless(s != NULL, "Failed to open server context: %s", strerror(errno));

  name = "foo";

  mark_point();
  c = add_config(NULL, name);
  fail_unless(c != NULL, "Failed to add config '%s': %s", name,
    strerror(errno));
  fail_unless(c->config_type == 0, "Expected config_type 0, got %d",
    c->config_type);

  mark_point();
  res = remove_config(s->conf, name, FALSE);
  fail_unless(res > 0, "Failed to remove config '%s': %s", name,
    strerror(errno));

  mark_point();
  pr_config_dump(NULL, s->conf, " ");
}
END_TEST

START_TEST (add_remove_config_set_test) {
  int res;
  xaset_t *set = NULL;
  const char *name = NULL;
  config_rec *c = NULL;

  res = remove_config(NULL, NULL, FALSE);
  fail_unless(res == 0, "Failed to handle null arguments: %s", strerror(errno));

  name = "foo";

  c = add_config_set(NULL, name);
  fail_unless(c == NULL, "Failed to handle null set argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  c = add_config_set(&set, name);
  fail_unless(c != NULL, "Failed to add config '%s' to set: %s", name,
    strerror(errno));
  fail_unless(c->config_type == 0, "Expected config_type 0, got %d",
    c->config_type);

  res = remove_config(set, name, FALSE);
  fail_unless(res > 0, "Failed to remove config '%s': %s", name,
    strerror(errno));

  name = "bar";
  res = remove_config(set, name, FALSE);
  fail_unless(res == 0, "Removed config '%s' unexpectedly", name,
    strerror(errno));
}
END_TEST

START_TEST (add_config_param_set_test) {
  xaset_t *set = NULL;
  const char *name = NULL;
  config_rec *c = NULL;

  name = "foo";

  c = add_config_param_set(NULL, name, 0);
  fail_unless(c == NULL, "Failed to handle null set argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  c = add_config_param_set(&set, name, 0);
  fail_unless(c != NULL, "Failed to add config '%s' to set: %s", name,
    strerror(errno));
  fail_unless(c->config_type == CONF_PARAM, "Expected config_type %d, got %d",
    CONF_PARAM, c->config_type);
  fail_unless(c->argc == 0, "Expected argc 0, got %d", c->argc);

  c = add_config_param_set(&set, name, 2, "bar", "baz");
  fail_unless(c != NULL, "Failed to add config '%s' to set: %s", name,
    strerror(errno));
  fail_unless(c->config_type == CONF_PARAM, "Expected config_type %d, got %d",
    CONF_PARAM, c->config_type);
  fail_unless(c->argc == 2, "Expected argc 2, got %d", c->argc);
  fail_unless(strcmp("bar", (char *) c->argv[0]) == 0,
    "Expected argv[0] to be 'bar', got '%s'", (char *) c->argv[0]);
  fail_unless(strcmp("baz", (char *) c->argv[1]) == 0,
    "Expected argv[1] to be 'baz', got '%s'", (char *) c->argv[1]);
  fail_unless(c->argv[2] == NULL, "Expected argv[2] to be null");
}
END_TEST

START_TEST (find_config_test) {
  int res;
  config_rec *c;
  xaset_t *set = NULL;
  const char *name;

  c = find_config(NULL, -1, NULL, FALSE);
  fail_unless(c == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  mark_point();

  name = "foo";
  c = add_config_param_set(&set, name, 0);
  fail_unless(c != NULL, "Failed to add config '%s': %s", name,
    strerror(errno));

  name = "bar";
  c = find_config(set, -1, name, FALSE);
  fail_unless(c == NULL, "Failed to handle null arguments");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));

  mark_point();

  /* We expect to find "foo", but a 'next' should be empty. */
  name = "foo";
  c = find_config(set, -1, name, FALSE);
  fail_unless(c != NULL, "Failed to find config '%s': %s", name,
    strerror(errno));

  mark_point();

  c = find_config_next(c, c->next, -1, name, FALSE);
  fail_unless(c == NULL, "Found next config unexpectedly");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));

  /* Now add another config, find "foo" again; this time, a 'next' should
   * NOT be empty; it should find the 2nd config we added.
   */

  name = "foo2";
  c = add_config_param_set(&set, name, 0);
  fail_unless(c != NULL, "Failed to add config '%s': %s", name,
    strerror(errno));

  name = NULL;
  c = find_config(set, -1, name, FALSE);
  fail_unless(c != NULL, "Failed to find any config: %s", strerror(errno));

  mark_point();

  c = find_config_next(c, c->next, -1, name, FALSE);
  fail_unless(c != NULL, "Expected to find another config");

  mark_point();

  name = "foo";
  res = remove_config(set, name, FALSE);
  fail_unless(res > 0, "Failed to remove config '%s': %s", name,
    strerror(errno));

  mark_point();

  c = find_config(set, -1, name, FALSE);
  fail_unless(c == NULL, "Found config '%s' unexpectedly", name);
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));
}
END_TEST

START_TEST (find_config2_test) {
  int res;
  config_rec *c;
  xaset_t *set = NULL;
  const char *name;
  unsigned long flags = 0;

  c = find_config2(NULL, -1, NULL, FALSE, flags);
  fail_unless(c == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  mark_point();

  name = "foo";
  c = add_config_param_set(&set, name, 0);
  fail_unless(c != NULL, "Failed to add config '%s': %s", name,
    strerror(errno));

  name = "bar";
  c = find_config2(set, -1, name, FALSE, flags);
  fail_unless(c == NULL, "Failed to handle null arguments");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));

  mark_point();

  /* We expect to find "foo", but a 'next' should be empty. */
  name = "foo";
  c = find_config2(set, -1, name, FALSE, flags);
  fail_unless(c != NULL, "Failed to find config '%s': %s", name,
    strerror(errno));

  mark_point();

  c = find_config_next2(c, c->next, -1, name, FALSE, flags);
  fail_unless(c == NULL, "Found next config unexpectedly");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));

  /* Now add another config, find "foo" again; this time, a 'next' should
   * NOT be empty; it should find the 2nd config we added.
   */

  name = "foo2";
  c = add_config_param_set(&set, name, 0);
  fail_unless(c != NULL, "Failed to add config '%s': %s", name,
    strerror(errno));

  name = NULL;
  c = find_config2(set, -1, name, FALSE, flags);
  fail_unless(c != NULL, "Failed to find any config: %s", strerror(errno));

  mark_point();

  c = find_config_next2(c, c->next, -1, name, FALSE, flags);
  fail_unless(c != NULL, "Expected to find another config");

  mark_point();

  name = "foo";
  res = remove_config(set, name, FALSE);
  fail_unless(res > 0, "Failed to remove config '%s': %s", name,
    strerror(errno));

  mark_point();

  c = find_config2(set, -1, name, FALSE, flags);
  fail_unless(c == NULL, "Found config '%s' unexpectedly", name);
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));
}
END_TEST

START_TEST (get_param_ptr_test) {
  void *res;
  int count;
  xaset_t *set = NULL;
  config_rec *c;
  const char *name = NULL;

  res = get_param_ptr(NULL, NULL, FALSE);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));

  mark_point();

  name = "foo";
  c = add_config_param_set(&set, name, 1, "bar");
  fail_unless(c != NULL, "Failed to add config '%s': %s", name,
    strerror(errno));

  name = "bar";
  res = get_param_ptr(set, name, FALSE);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));

  mark_point();

  /* We expect to find "foo", but a 'next' should be empty. Note that we
   * need to reset the get_param_ptr tree.
   */
  get_param_ptr(NULL, NULL, FALSE);

  name = "foo";
  res = get_param_ptr(set, name, FALSE);
  fail_unless(res != NULL, "Failed to find config '%s': %s", name,
    strerror(errno));

  mark_point();

  res = get_param_ptr_next(name, FALSE);
  fail_unless(res == NULL, "Found next config unexpectedly");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));

  /* Now add another config, find "foo" again; this time, a 'next' should
   * NOT be empty; it should find the 2nd config we added.
   */

  name = "foo2";
  c = add_config_param_set(&set, name, 1, "baz");
  fail_unless(c != NULL, "Failed to add config '%s': %s", name,
    strerror(errno));

  get_param_ptr(NULL, NULL, FALSE);

  name = NULL;
  res = get_param_ptr(set, name, FALSE);
  fail_unless(res != NULL, "Failed to find any config: %s", strerror(errno));

  mark_point();

  res = get_param_ptr_next(name, FALSE);
  fail_unless(res != NULL, "Expected to find another config");

  mark_point();

  name = "foo";
  count = remove_config(set, name, FALSE);
  fail_unless(count > 0, "Failed to remove config '%s': %s", name,
    strerror(errno));

  mark_point();

  res = get_param_ptr(set, name, FALSE);
  fail_unless(res == NULL, "Found config '%s' unexpectedly", name);
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));
}
END_TEST

START_TEST (config_set_get_id_test) {
  unsigned int id, res;
  const char *name;

  res = pr_config_get_id(NULL);
  fail_unless(res == 0, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  res = pr_config_set_id(NULL);
  fail_unless(res == 0, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  name = "foo";

  id = pr_config_set_id(name);
  fail_unless(id > 0, "Failed to set ID for config '%s': %s", name,
    strerror(errno));

  res = pr_config_get_id(name);
  fail_unless(res == id, "Expected ID %u for config '%s', found %u", id,
    name, res);
}
END_TEST

Suite *tests_get_config_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("config");

  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, add_remove_config_test);
  tcase_add_test(testcase, add_remove_config_set_test);
  tcase_add_test(testcase, add_config_param_set_test);
  tcase_add_test(testcase, find_config_test);
  tcase_add_test(testcase, find_config2_test);
  tcase_add_test(testcase, get_param_ptr_test);
  tcase_add_test(testcase, config_set_get_id_test);

  suite_add_tcase(suite, testcase);

  return suite;
}
