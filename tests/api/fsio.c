/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2008-2015 The ProFTPD Project team
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

/* FSIO API tests */

#include "tests.h"

static pool *p = NULL;

static const char *fsio_link_path = "/tmp/prt-fsio-symlink.lnk";
static const char *fsio_access_dir_path = "/tmp/prt-fsio-access.d";

/* Fixtures */

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  init_fs();
  pr_fs_statcache_set_policy(PR_TUNABLE_FS_STATCACHE_SIZE,
    PR_TUNABLE_FS_STATCACHE_MAX_AGE, 0);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("fs.statcache", 1, 20);
  }
}

static void tear_down(void) {
  if (p) {
    destroy_pool(p);
    p = NULL;
    permanent_pool = NULL;
  }

  pr_fs_statcache_set_policy(PR_TUNABLE_FS_STATCACHE_SIZE,
    PR_TUNABLE_FS_STATCACHE_MAX_AGE, 0);
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("fs.statcache", 0, 0);
  }

  (void) unlink(fsio_link_path);
  (void) rmdir(fsio_access_dir_path);
}

/* Tests */

START_TEST (fs_clean_path_test) {
  char res[PR_TUNABLE_PATH_MAX+1], *path, *expected;

  res[sizeof(res)-1] = '\0';
  path = "/test.txt";
  pr_fs_clean_path(path, res, sizeof(res)-1);
  fail_unless(strcmp(res, path) == 0, "Expected cleaned path '%s', got '%s'",
    path, res);

  res[sizeof(res)-1] = '\0';
  path = "/./test.txt";
  pr_fs_clean_path(path, res, sizeof(res)-1);

  expected = "/test.txt";
  fail_unless(strcmp(res, expected) == 0,
    "Expected cleaned path '%s', got '%s'", expected, res);

  res[sizeof(res)-1] = '\0';
  path = "test.txt";
  pr_fs_clean_path(path, res, sizeof(res)-1);

  expected = "/test.txt";
  fail_unless(strcmp(res, expected) == 0,
    "Expected cleaned path '%s', got '%s'", path, res);
}
END_TEST

START_TEST (fs_clean_path2_test) {
  char res[PR_TUNABLE_PATH_MAX+1], *path, *expected;

  res[sizeof(res)-1] = '\0';
  path = "test.txt";
  pr_fs_clean_path2(path, res, sizeof(res)-1, 0);
  fail_unless(strcmp(res, path) == 0, "Expected cleaned path '%s', got '%s'",
    path, res);

  res[sizeof(res)-1] = '\0';
  path = "/./test.txt";
  pr_fs_clean_path2(path, res, sizeof(res)-1, 0);

  expected = "/test.txt";
  fail_unless(strcmp(res, expected) == 0,
    "Expected cleaned path '%s', got '%s'", expected, res);

  res[sizeof(res)-1] = '\0';
  path = "test.d///test.txt";
  pr_fs_clean_path2(path, res, sizeof(res)-1, 0);

  expected = "test.d/test.txt";
  fail_unless(strcmp(res, expected) == 0,
    "Expected cleaned path '%s', got '%s'", expected, res);

  res[sizeof(res)-1] = '\0';
  path = "/test.d///test.txt";
  pr_fs_clean_path2(path, res, sizeof(res)-1,
    PR_FSIO_CLEAN_PATH_FL_MAKE_ABS_PATH);

  expected = "/test.d/test.txt";
  fail_unless(strcmp(res, expected) == 0,
    "Expected cleaned path '%s', got '%s'", expected, res);

}
END_TEST

START_TEST (fs_dircat_test) {
  char buf[PR_TUNABLE_PATH_MAX+1], *a, *b, *ok;
  int res;

  res = pr_fs_dircat(NULL, 0, NULL, NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL,
    "Failed to set errno to EINVAL for null arguments");

  res = pr_fs_dircat(buf, 0, "foo", "bar");
  fail_unless(res == -1, "Failed to handle zero-length buffer");
  fail_unless(errno == EINVAL,
    "Failed to set errno to EINVAL for zero-length buffer");

  res = pr_fs_dircat(buf, -1, "foo", "bar");
  fail_unless(res == -1, "Failed to handle negative-length buffer");
  fail_unless(errno == EINVAL,
    "Failed to set errno to EINVAL for negative-length buffer");

  a = pcalloc(p, PR_TUNABLE_PATH_MAX);
  memset(a, 'A', PR_TUNABLE_PATH_MAX-1);

  b = "foo";

  res = pr_fs_dircat(buf, sizeof(buf)-1, a, b);
  fail_unless(res == -1, "Failed to handle too-long paths");
  fail_unless(errno == ENAMETOOLONG,
    "Failed to set errno to ENAMETOOLONG for too-long paths");

  a = "foo";
  b = "/bar";
  ok = b;
  res = pr_fs_dircat(buf, sizeof(buf)-1, a, b);
  fail_unless(res == 0, "Failed to concatenate abs-path path second dir");
  fail_unless(strcmp(buf, ok) == 0, "Expected concatenated dir '%s', got '%s'",
    ok, buf);
 
  a = "foo";
  b = "bar";
  ok = "foo/bar";
  res = pr_fs_dircat(buf, sizeof(buf)-1, a, b);
  fail_unless(res == 0, "Failed to concatenate two normal paths");
  fail_unless(strcmp(buf, ok) == 0, "Expected concatenated dir '%s', got '%s'",
    ok, buf);
 
  a = "foo/";
  b = "bar";
  ok = "foo/bar";
  res = pr_fs_dircat(buf, sizeof(buf)-1, a, b);
  fail_unless(res == 0, "Failed to concatenate first dir with trailing slash");
  fail_unless(strcmp(buf, ok) == 0, "Expected concatenated dir '%s', got '%s'",
    ok, buf);

  a = "";
  b = "";
  ok = "/";
  res = pr_fs_dircat(buf, sizeof(buf)-1, a, b);
  fail_unless(res == 0, "Failed to concatenate two empty paths");
  fail_unless(strcmp(buf, ok) == 0, "Expected concatenated dir '%s', got '%s'",
    ok, buf);
}
END_TEST

START_TEST (fs_setcwd_test) {
  int res;

  /* Make sure that we don't segfault if we call pr_fs_setcwd() on the
   * buffer that it is already using.
   */
  res = pr_fs_setcwd(pr_fs_getcwd());
  fail_unless(res == 0, "Failed to set cwd to '%s': %s", pr_fs_getcwd(),
    strerror(errno));
}
END_TEST

START_TEST (fsio_symlink_test) {
  int res;
  const char *target_path, *link_path;

  target_path = link_path = NULL;
  res = pr_fsio_symlink(target_path, link_path);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL, got %s (%d)", strerror(errno),
    errno);

  target_path = "/tmp";
  link_path = NULL;
  res = pr_fsio_symlink(target_path, link_path);
  fail_unless(res < 0, "Failed to handle null link_path argument");
  fail_unless(errno == EINVAL, "Expected EINVAL, got %s (%d)", strerror(errno),
    errno);

  target_path = NULL;
  link_path = fsio_link_path;
  res = pr_fsio_symlink(target_path, link_path);
  fail_unless(res < 0, "Failed to handle null target_path argument");
  fail_unless(errno == EINVAL, "Expected EINVAL, got %s (%d)", strerror(errno),
    errno);

  /* Symlink a file (that exists) to itself */
  link_path = target_path = "/tmp";
  res = pr_fsio_symlink(target_path, link_path);
  fail_unless(res < 0, "Failed to handle same existing source/destination");
  fail_unless(errno == EEXIST, "Expected EEXIST, got %s (%d)", strerror(errno),
    errno);

  /* Create expected symlink */
  link_path = fsio_link_path;
  target_path = "/tmp";
  res = pr_fsio_symlink(target_path, link_path);
  fail_unless(res == 0, "Failed to create symlink from '%s' to '%s': %s",
    link_path, target_path, strerror(errno));
  (void) unlink(link_path);
}
END_TEST

START_TEST (fsio_readlink_test) {
  int res;
  char buf[PR_TUNABLE_BUFFER_SIZE];
  const char *link_path, *target_path, *path;

  res = pr_fsio_readlink(NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL, got %s (%d)", strerror(errno),
    errno);

  /* Read a non-symlink file */
  path = "/";
  res = pr_fsio_readlink(path, buf, sizeof(buf)-1);
  fail_unless(res < 0, "Failed to handle non-symlink path");
  fail_unless(errno == EINVAL, "Expected EINVAL, got %s (%d)", strerror(errno),
    errno);

  /* Read a symlink file */
  target_path = "/tmp";
  link_path = fsio_link_path;
  res = pr_fsio_symlink(target_path, link_path);
  fail_unless(res == 0, "Failed to create symlink from '%s' to '%s': %s",
    link_path, target_path, strerror(errno));

  memset(buf, '\0', sizeof(buf));
  res = pr_fsio_readlink(link_path, buf, sizeof(buf)-1);
  fail_unless(res > 0, "Failed to read symlink '%s': %s", link_path,
    strerror(errno));
  buf[res] = '\0';
  fail_unless(strcmp(buf, target_path) == 0, "Expected '%s', got '%s'",
    target_path, buf);

  /* Read a symlink file using a zero-length buffer */
  res = pr_fsio_readlink(link_path, buf, 0);
  fail_unless(res <= 0, "Expected length <= 0, got %d", res);

  (void) unlink(link_path);
}
END_TEST

START_TEST (fsio_access_dir_test) {
  int res;
  uid_t uid = getuid(), other_uid = 1000;
  gid_t gid = getgid(), other_gid = 1000;
  mode_t perms;

  res = pr_fsio_access(NULL, X_OK, uid, gid, NULL);
  fail_unless(res < 0, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL, got %s (%d)", strerror(errno),
    errno);

  /* Make the directory to check; we want it to have perms 771.*/
  perms = (mode_t) 0771;
  if (mkdir(fsio_access_dir_path, perms) < 0) {
    fail("unable to create directory '%s': %s", fsio_access_dir_path,
      strerror(errno));
  }

  /* Use chmod(2) to ensure that the directory has the perms we want,
   * regardless of any umask settings.
   */
  if (chmod(fsio_access_dir_path, perms) < 0) {
    fail("unable to set perms %04o on directory '%s': %s", perms,
      fsio_access_dir_path, strerror(errno));
  }

  /* First, check that we ourselves can access our own directory. */

  pr_fs_clear_cache2(fsio_access_dir_path);
  res = pr_fsio_access(fsio_access_dir_path, F_OK, uid, gid, NULL);
  fail_unless(res == 0, "Failed to check for file access on directory: %s",
    strerror(errno));

  pr_fs_clear_cache2(fsio_access_dir_path);
  res = pr_fsio_access(fsio_access_dir_path, R_OK, uid, gid, NULL);
  fail_unless(res == 0, "Failed to check for read access on directory: %s",
    strerror(errno));

  pr_fs_clear_cache2(fsio_access_dir_path);
  res = pr_fsio_access(fsio_access_dir_path, W_OK, uid, gid, NULL);
  fail_unless(res == 0, "Failed to check for read access on directory: %s",
    strerror(errno));

  pr_fs_clear_cache2(fsio_access_dir_path);
  res = pr_fsio_access(fsio_access_dir_path, X_OK, uid, gid, NULL);
  fail_unless(res == 0, "Failed to check for execute access on directory: %s",
    strerror(errno));

  if (getenv("TRAVIS_CI") == NULL) {
    /* Next, check that others can access the directory. */
    pr_fs_clear_cache2(fsio_access_dir_path);
    res = pr_fsio_access(fsio_access_dir_path, F_OK, other_uid, other_gid,
      NULL);
    fail_unless(res == 0,
      "Failed to check for other file access on directory: %s",
      strerror(errno));

    pr_fs_clear_cache2(fsio_access_dir_path);
    res = pr_fsio_access(fsio_access_dir_path, R_OK, other_uid, other_gid,
      NULL);
    fail_unless(res < 0,
      "other read access on directory succeeded unexpectedly");
    fail_unless(errno == EACCES, "Expected EACCES, got %s (%d)",
      strerror(errno), errno);

    pr_fs_clear_cache2(fsio_access_dir_path);
    res = pr_fsio_access(fsio_access_dir_path, W_OK, other_uid, other_gid,
      NULL);
    fail_unless(res < 0,
      "other write access on directory succeeded unexpectedly");
    fail_unless(errno == EACCES, "Expected EACCES, got %s (%d)",
      strerror(errno), errno);

    pr_fs_clear_cache2(fsio_access_dir_path);
    res = pr_fsio_access(fsio_access_dir_path, X_OK, other_uid, other_gid,
      NULL);
    fail_unless(res == 0, "Failed to check for execute access on directory: %s",
      strerror(errno));
  }

  (void) rmdir(fsio_access_dir_path);
}
END_TEST

START_TEST (fsio_stat_test) {
  int res;
  struct stat st;
  unsigned int cache_size = 3, max_age = 1, policy_flags = 0;

  res = pr_fsio_stat(NULL, &st);
  fail_unless(res < 0, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL, got %s (%d)", strerror(errno),
    errno);

  res = pr_fsio_stat("/", NULL);
  fail_unless(res < 0, "Failed to handle null struct stat");
  fail_unless(errno == EINVAL, "Expected EINVAL, got %s (%d)", strerror(errno),
    errno);

  res = pr_fsio_stat("/", &st);
  fail_unless(res == 0, "Unexpected stat(2) error on '/': %s",
    strerror(errno));
  fail_unless(S_ISDIR(st.st_mode), "'/' is not a directory as expected");

  /* Now, do the stat(2) again, and make sure we get the same information
   * from the cache.
   */
  res = pr_fsio_stat("/", &st);
  fail_unless(res == 0, "Unexpected stat(2) error on '/': %s",
    strerror(errno));
  fail_unless(S_ISDIR(st.st_mode), "'/' is not a directory as expected");

  pr_fs_statcache_reset();
  res = pr_fs_statcache_set_policy(cache_size, max_age, policy_flags);
  fail_unless(res == 0, "Failed to set statcache policy: %s", strerror(errno));

  res = pr_fsio_stat("/foo/bar/baz/quxx", &st);
  fail_unless(res < 0, "Failed to handle nonexistent path");
  fail_unless(errno == ENOENT, "Expected ENOENT, got %s (%d)", strerror(errno),
    errno);

  res = pr_fsio_stat("/foo/bar/baz/quxx", &st);
  fail_unless(res < 0, "Failed to handle nonexistent path");
  fail_unless(errno == ENOENT, "Expected ENOENT, got %s (%d)", strerror(errno),
    errno);

  /* Now wait for longer than 1 second (our configured max age) */
  sleep(max_age + 1);

  res = pr_fsio_stat("/foo/bar/baz/quxx", &st);
  fail_unless(res < 0, "Failed to handle nonexistent path");
  fail_unless(errno == ENOENT, "Expected ENOENT, got %s (%d)", strerror(errno),
    errno);
}
END_TEST

START_TEST (fsio_lstat_test) {
  int res;
  struct stat st;
  unsigned int cache_size = 3, max_age = 1, policy_flags = 0;

  res = pr_fsio_lstat(NULL, &st);
  fail_unless(res < 0, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL, got %s (%d)", strerror(errno),
    errno);

  res = pr_fsio_lstat("/", NULL);
  fail_unless(res < 0, "Failed to handle null struct stat");
  fail_unless(errno == EINVAL, "Expected EINVAL, got %s (%d)", strerror(errno),
    errno);

  res = pr_fsio_lstat("/", &st);
  fail_unless(res == 0, "Unexpected lstat(2) error on '/': %s",
    strerror(errno));
  fail_unless(S_ISDIR(st.st_mode), "'/' is not a directory as expected");

  /* Now, do the lstat(2) again, and make sure we get the same information
   * from the cache.
   */
  res = pr_fsio_lstat("/", &st);
  fail_unless(res == 0, "Unexpected lstat(2) error on '/': %s",
    strerror(errno));
  fail_unless(S_ISDIR(st.st_mode), "'/' is not a directory as expected");

  pr_fs_statcache_reset();
  res = pr_fs_statcache_set_policy(cache_size, max_age, policy_flags);
  fail_unless(res == 0, "Failed to set statcache policy: %s", strerror(errno));

  res = pr_fsio_lstat("/foo/bar/baz/quxx", &st);
  fail_unless(res < 0, "Failed to handle nonexistent path");
  fail_unless(errno == ENOENT, "Expected ENOENT, got %s (%d)", strerror(errno),
    errno);

  res = pr_fsio_lstat("/foo/bar/baz/quxx", &st);
  fail_unless(res < 0, "Failed to handle nonexistent path");
  fail_unless(errno == ENOENT, "Expected ENOENT, got %s (%d)", strerror(errno),
    errno);

  /* Now wait for longer than 1 second (our configured max age) */
  sleep(max_age + 1);

  res = pr_fsio_lstat("/foo/bar/baz/quxx", &st);
  fail_unless(res < 0, "Failed to handle nonexistent path");
  fail_unless(errno == ENOENT, "Expected ENOENT, got %s (%d)", strerror(errno),
    errno);
}
END_TEST

Suite *tests_get_fsio_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("fsio");

  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, fs_clean_path_test);
  tcase_add_test(testcase, fs_clean_path2_test);
  tcase_add_test(testcase, fs_dircat_test);
  tcase_add_test(testcase, fs_setcwd_test);

  tcase_add_test(testcase, fsio_symlink_test);
  tcase_add_test(testcase, fsio_readlink_test);
  tcase_add_test(testcase, fsio_access_dir_test);

  tcase_add_test(testcase, fsio_stat_test);
  tcase_add_test(testcase, fsio_lstat_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
