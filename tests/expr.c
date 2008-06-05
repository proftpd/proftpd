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

/*
 * Expression API tests
 * $Id: expr.c,v 1.1 2008-06-05 07:42:55 castaglia Exp $
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

START_TEST (expr_create_test) {
}
END_TEST

START_TEST (expr_eval_class_and_test) {
}
END_TEST

START_TEST (expr_eval_class_or_test) {
}
END_TEST

START_TEST (expr_eval_group_and_test) {
}
END_TEST

START_TEST (expr_eval_group_or_test) {
}
END_TEST

START_TEST (expr_eval_user_and_test) {
}
END_TEST

START_TEST (expr_eval_user_or_test) {
}
END_TEST

Suite *tests_get_expr_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("expr");

  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, expr_create_test);
  tcase_add_test(testcase, expr_eval_class_and_test);
  tcase_add_test(testcase, expr_eval_class_or_test);
  tcase_add_test(testcase, expr_eval_group_and_test);
  tcase_add_test(testcase, expr_eval_group_or_test);
  tcase_add_test(testcase, expr_eval_user_and_test);
  tcase_add_test(testcase, expr_eval_user_or_test);

  suite_add_tcase(suite, testcase);

  return suite;
}
