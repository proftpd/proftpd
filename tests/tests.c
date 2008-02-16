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

#include "tests.h"

static const char *suites[] = {
  "pool",
  "array",
  "str",
  "env",

  NULL
};

static Suite *tests_get_suite(const char *suite) { 
  if (strcmp(suite, "pool") == 0) { 
    return tests_get_pool_suite();
 
  } else if (strcmp(suite, "array") == 0) {
    return tests_get_array_suite(); 

  } else if (strcmp(suite, "str") == 0) {
    return tests_get_str_suite(); 

  } else if (strcmp(suite, "env") == 0) {
    return tests_get_env_suite(); 
  }
 
  return NULL;
}

int main(int argc, char *argv[]) {
  register unsigned int i;
  int nfailed = 0;
  SRunner *runner = NULL;

  runner = srunner_create(NULL);

  srunner_set_log(runner, "tests.log");

  for (i = 0; suites[i]; i++) {
    Suite *suite;

    suite = tests_get_suite(suites[i]);
    if (suite) {
      srunner_add_suite(runner, suite);
    }
  }

  srunner_run_all(runner, CK_NORMAL);

  nfailed = srunner_ntests_failed(runner);

  if (runner)
    srunner_free(runner);

  if (nfailed != 0)
    return EXIT_FAILURE;

  return EXIT_SUCCESS;
}
