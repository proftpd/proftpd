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

/* Modules API tests
 * $Id: modules.c,v 1.1 2008-06-13 01:30:43 castaglia Exp $
 */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  init_stash();
  modules_init();
}

static void tear_down(void) {
  if (p) {
    destroy_pool(p);
    p = NULL;
    permanent_pool = NULL;
  } 
}

START_TEST (stash_add_symbol_test) {
}
END_TEST

START_TEST (stash_get_symbol_test) {
}
END_TEST

START_TEST (stash_remove_symbol_test) {
}
END_TEST

START_TEST (module_exists_test) {
}
END_TEST

START_TEST (module_get_test) {
}
END_TEST

START_TEST (module_load_test) {
}
END_TEST

START_TEST (module_unload_test) {
}
END_TEST

START_TEST (module_call_test) {
}
END_TEST

Suite *tests_get_modules_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("modules");

  testcase = tcase_create("stash");
  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, stash_add_symbol_test);
  tcase_add_test(testcase, stash_get_symbol_test);
  tcase_add_test(testcase, stash_remove_symbol_test);

  suite_add_tcase(suite, testcase);

  testcase = tcase_create("module");
  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, module_exists_test);
  tcase_add_test(testcase, module_get_test);
  tcase_add_test(testcase, module_load_test);
  tcase_add_test(testcase, module_unload_test);
  tcase_add_test(testcase, module_call_test);

  suite_add_tcase(suite, testcase);

  return suite;
}
