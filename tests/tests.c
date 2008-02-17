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
  "sets",
  "timers",
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

  } else if (strcmp(suite, "sets") == 0) {
    return tests_get_sets_suite(); 

  } else if (strcmp(suite, "timers") == 0) {
    return tests_get_timers_suite(); 

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

  if (nfailed != 0) {
    fprintf(stderr, "-------------------------------------------------\n");
    fprintf(stderr, " FAILED %d %s\n\n", nfailed,
      nfailed != 1 ? "tests" : "test");
    fprintf(stderr, " Please send email to:\n\n");
    fprintf(stderr, "   proftp-devel@lists.sourceforge.net\n\n");
    fprintf(stderr, " containing the `tests.log' file and the output\n");
    fprintf(stderr, " from running `proftpd -V'\n");
    fprintf(stderr, "-------------------------------------------------\n");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
