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
 * String API tests
 * $Id: str.c,v 1.1 2008-02-11 04:44:28 castaglia Exp $
 */

#include "tests.h"

START_TEST (sstrncpy_test) {
}
END_TEST

START_TEST (sstrcat_test) {
  register unsigned int i;
  char c = 'A', src[1024], dst[1024], *res;

  res = sstrcat(dst, src, 0);
  fail_unless(res == NULL, "Non-null result for zero-length strcat");

  src[0] = 'f';
  src[1] = '\0';
  dst[0] = 'e';
  dst[1] = '\0';
  res = sstrcat(dst, src, 1);
  fail_unless(res == dst, "Returned wrong destination buffer");

  /* In this case, we told sstrcat() that dst is len 1, which means that
   * sstrcat() should set dst[0] to NUL.
   */
  fail_unless(dst[0] == 0, "Failed to terminate destination buffer");

  src[0] = 'f';
  src[1] = '\0';
  dst[0] = 'e';
  dst[1] = '\0';
  res = sstrcat(dst, src, 2);
  fail_unless(res == dst, "Returned wrong destination buffer");

  /* In this case, we told sstrcat() that dst is len 2, which means that
   * sstrcat() should preserve the value at 0, and set dst[1] to NUL.
   */
  fail_unless(dst[0] == 'e',
    "Failed to preserve destination buffer (expected '%c' at index 0, "
    "got '%c')", 'e', dst[0]);

  fail_unless(dst[1] == 0, "Failed to terminate destination buffer");

  src[0] = 'f';
  src[1] = '\0';
  dst[0] = 'e';
  dst[1] = '\0';
  res = sstrcat(dst, src, 3);
  fail_unless(res == dst, "Returned wrong destination buffer");

  fail_unless(dst[0] == 'e',
    "Failed to preserve destination buffer (expected '%c' at index 0, "
    "got '%c')", 'e', dst[0]);

  fail_unless(dst[1] == 'f',
    "Failed to copy source buffer (expected '%c' at index 1, got '%c')",
    'f', dst[1]);

  fail_unless(dst[2] == 0, "Failed to terminate destination buffer");

  memset(src, c, sizeof(src));

  dst[0] = '\0';
  res = sstrcat(dst, src, sizeof(dst));
  fail_unless(res == dst, "Returned wrong destination buffer");
  fail_unless(dst[sizeof(dst)-1] == 0,
    "Failed to terminate destination buffer");

  fail_unless(strlen(dst) == (sizeof(dst)-1),
    "Failed to copy all the data (expected len %u, got len %u)",
    sizeof(dst)-1, strlen(dst));

  for (i = 0; i < sizeof(dst)-1; i++) {
    fail_unless(dst[i] == c, "Copied wrong value (expected '%c', got '%c')",
      c, dst[i]);
  }
}
END_TEST

START_TEST (sreplace_test) {
}
END_TEST

START_TEST (pdircat_test) {
}
END_TEST

START_TEST (pstrcat_test) {
}
END_TEST

START_TEST (pstrdup_test) {
}
END_TEST

START_TEST (pstrndup_test) {
}
END_TEST

Suite *tests_get_str_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("str");

  testcase = tcase_create("base");

  tcase_add_test(testcase, sstrncpy_test);
  tcase_add_test(testcase, sstrcat_test);
  tcase_add_test(testcase, sreplace_test);
  tcase_add_test(testcase, pdircat_test);
  tcase_add_test(testcase, pstrcat_test);
  tcase_add_test(testcase, pstrdup_test);
  tcase_add_test(testcase, pstrndup_test);

  suite_add_tcase(suite, testcase);

  return suite;
}
