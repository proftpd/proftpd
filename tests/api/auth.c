/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2014 The ProFTPD Project team
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

/* Auth API tests */

#include "tests.h"

#define PR_TEST_AUTH_NAME	"unit_test"
#define PR_TEST_AUTH_UID	500
#define PR_TEST_AUTH_UID_STR	"500"
#define PR_TEST_AUTH_GID	500
#define PR_TEST_AUTH_GID_STR	"500"
#define PR_TEST_AUTH_HOME	"/tmp"
#define PR_TEST_AUTH_SHELL	"/bin/bash"

static pool *p = NULL;

static struct passwd test_pwd;
static struct group test_grp;

static unsigned int setpwent_count = 0;
static unsigned int endpwent_count = 0;
static unsigned int getpwent_count = 0;
static unsigned int getpwnam_count = 0;
static unsigned int getpwuid_count = 0;
static unsigned int name2uid_count = 0;
static unsigned int uid2name_count = 0;

static unsigned int setgrent_count = 0;
static unsigned int endgrent_count = 0;
static unsigned int getgrent_count = 0;
static unsigned int getgrnam_count = 0;
static unsigned int getgrgid_count = 0;
static unsigned int name2gid_count = 0;
static unsigned int gid2name_count = 0;
static unsigned int getgroups_count = 0;

static module unit_tests_module = {
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "unit_tests",

  /* Module configuration directive table */
  NULL,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  NULL,

  /* Session initialization function */
  NULL
};

MODRET handle_setpwent(cmd_rec *cmd) {
  setpwent_count++;
  return PR_HANDLED(cmd);
}

MODRET handle_endpwent(cmd_rec *cmd) {
  endpwent_count++;
  return PR_HANDLED(cmd);
}

MODRET handle_getpwent(cmd_rec *cmd) {
  getpwent_count++;
  return mod_create_data(cmd, &test_pwd);
}

MODRET handle_getpwnam(cmd_rec *cmd) {
  const char *name;

  name = cmd->argv[0];
  getpwnam_count++;

  if (strcmp(name, PR_TEST_AUTH_NAME) != 0) {
    return PR_DECLINED(cmd);
  }

  return mod_create_data(cmd, &test_pwd);
}

MODRET handle_getpwuid(cmd_rec *cmd) {
  uid_t uid;

  uid = *((uid_t *) cmd->argv[0]);
  getpwuid_count++;

  if (uid != PR_TEST_AUTH_UID) {
    return PR_DECLINED(cmd);
  }
  
  return mod_create_data(cmd, &test_pwd);
}

MODRET decline_name2uid(cmd_rec *cmd) {
  name2uid_count++;
  return PR_DECLINED(cmd);
}

MODRET handle_name2uid(cmd_rec *cmd) {
  const char *name;

  name = cmd->argv[0];
  name2uid_count++;

  if (strcmp(name, PR_TEST_AUTH_NAME) != 0) {
    return PR_DECLINED(cmd);
  }

  return mod_create_data(cmd, (void *) &(test_pwd.pw_uid));
}

MODRET decline_uid2name(cmd_rec *cmd) {
  uid2name_count++;
  return PR_DECLINED(cmd);
}

MODRET handle_uid2name(cmd_rec *cmd) {
  uid_t uid;

  uid = *((uid_t *) cmd->argv[0]);
  uid2name_count++;

  if (uid != PR_TEST_AUTH_UID) {
    return PR_DECLINED(cmd);
  }

  return mod_create_data(cmd, test_pwd.pw_name);
}

MODRET handle_setgrent(cmd_rec *cmd) {
  setgrent_count++;
  return PR_HANDLED(cmd);
}

MODRET handle_endgrent(cmd_rec *cmd) {
  endgrent_count++;
  return PR_HANDLED(cmd);
}

MODRET handle_getgrent(cmd_rec *cmd) {
  getgrent_count++;
  return mod_create_data(cmd, &test_grp);
}

MODRET handle_getgrnam(cmd_rec *cmd) {
  const char *name;

  name = cmd->argv[0];
  getgrnam_count++;

  if (strcmp(name, PR_TEST_AUTH_NAME) != 0) {
    return PR_DECLINED(cmd);
  }

  return mod_create_data(cmd, &test_grp);
}

MODRET handle_getgrgid(cmd_rec *cmd) {
  gid_t gid;

  gid = *((gid_t *) cmd->argv[0]);
  getgrgid_count++;

  if (gid != PR_TEST_AUTH_GID) {
    return PR_DECLINED(cmd);
  }
  
  return mod_create_data(cmd, &test_grp);
}

MODRET decline_name2gid(cmd_rec *cmd) {
  name2gid_count++;
  return PR_DECLINED(cmd);
}

MODRET handle_name2gid(cmd_rec *cmd) {
  const char *name;

  name = cmd->argv[0];
  name2gid_count++;

  if (strcmp(name, PR_TEST_AUTH_NAME) != 0) {
    return PR_DECLINED(cmd);
  }

  return mod_create_data(cmd, (void *) &(test_grp.gr_gid));
}

MODRET decline_gid2name(cmd_rec *cmd) {
  gid2name_count++;
  return PR_DECLINED(cmd);
}

MODRET handle_gid2name(cmd_rec *cmd) {
  gid_t gid;

  gid = *((gid_t *) cmd->argv[0]);
  gid2name_count++;

  if (gid != PR_TEST_AUTH_GID) {
    return PR_DECLINED(cmd);
  }

  return mod_create_data(cmd, test_grp.gr_name);
}

MODRET handle_getgroups(cmd_rec *cmd) {
  const char *name;
  array_header *gids;

  name = (char *) cmd->argv[0];

  if (cmd->argv[1]) {
    gids = (array_header *) cmd->argv[1];
  }

  getgroups_count++;

  if (strcmp(name, PR_TEST_AUTH_NAME) != 0) {
    return PR_DECLINED(cmd);
  }

  *((gid_t *) push_array(gids)) = PR_TEST_AUTH_GID;
  return mod_create_data(cmd, (void *) &gids->nelts);
}

/* Fixtures */

static void set_up(void) {
  server_rec *s = NULL;

  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  pr_trace_use_stderr(TRUE);
  init_stash();
  init_auth();

  s = pcalloc(p, sizeof(server_rec));
  tests_stubs_set_main_server(s);

  test_pwd.pw_name = PR_TEST_AUTH_NAME;
  test_pwd.pw_uid = PR_TEST_AUTH_UID;
  test_pwd.pw_gid = PR_TEST_AUTH_GID;
  test_pwd.pw_dir = PR_TEST_AUTH_HOME;
  test_pwd.pw_shell = PR_TEST_AUTH_SHELL;

  test_grp.gr_name = PR_TEST_AUTH_NAME;
  test_grp.gr_gid = PR_TEST_AUTH_GID;

  /* Reset counters. */
  setpwent_count = 0;
  endpwent_count = 0;
  getpwent_count = 0;
  getpwnam_count = 0;
  getpwuid_count = 0;
  name2uid_count = 0;
  uid2name_count = 0;

  setgrent_count = 0;
  endgrent_count = 0;
  getgrent_count = 0;
  getgrnam_count = 0;
  getgrgid_count = 0;
  name2gid_count = 0;
  gid2name_count = 0;
  getgroups_count = 0;

  pr_auth_cache_clear();
}

static void tear_down(void) {
  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  } 

  tests_stubs_set_main_server(NULL);
}

/* Tests */

START_TEST (auth_setpwent_test) {
  int res;
  authtable authtab;
  char *sym_name = "setpwent";

  pr_auth_setpwent(p);
  fail_unless(setpwent_count == 0, "Expected call count 0, got %u",
    setpwent_count);
  mark_point();
  
  /* Load the appropriate AUTH symbol, and call it. */

  memset(&authtab, 0, sizeof(authtab));
  authtab.name = sym_name;
  authtab.handler = handle_setpwent;
  authtab.m = &unit_tests_module;
  res = pr_stash_add_symbol(PR_SYM_AUTH, &authtab);
  fail_unless(res == 0, "Failed to add '%s' AUTH symbol: %s", sym_name,
    strerror(errno));

  pr_auth_setpwent(p);
  fail_unless(setpwent_count == 1, "Expected call count 1, got %u",
    setpwent_count);

  pr_stash_remove_symbol(PR_SYM_AUTH, sym_name, &unit_tests_module);
}
END_TEST

START_TEST (auth_endpwent_test) {
  int res;
  authtable authtab;
  char *sym_name = "endpwent";

  pr_auth_endpwent(p);
  fail_unless(endpwent_count == 0, "Expected call count 0, got %u",
    endpwent_count);
  mark_point();
  
  /* Load the appropriate AUTH symbol, and call it. */

  memset(&authtab, 0, sizeof(authtab));
  authtab.name = sym_name;
  authtab.handler = handle_endpwent;
  authtab.m = &unit_tests_module;
  res = pr_stash_add_symbol(PR_SYM_AUTH, &authtab);
  fail_unless(res == 0, "Failed to add '%s' AUTH symbol: %s", sym_name,
    strerror(errno));

  pr_auth_endpwent(p);
  fail_unless(endpwent_count == 1, "Expected call count 1, got %u",
    endpwent_count);

  pr_stash_remove_symbol(PR_SYM_AUTH, sym_name, &unit_tests_module);
}
END_TEST

START_TEST (auth_getpwent_test) {
  int res;
  struct passwd *pw;
  authtable authtab;
  char *sym_name = "getpwent";

  pw = pr_auth_getpwent(NULL);
  fail_unless(pw == NULL, "Found pwent unexpectedly");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  pw = pr_auth_getpwent(p);
  fail_unless(pw == NULL, "Found pwent unexpectedly");
  fail_unless(getpwent_count == 0, "Expected call count 0, got %u",
    getpwent_count);
  mark_point();
  
  /* Load the appropriate AUTH symbol, and call it. */

  memset(&authtab, 0, sizeof(authtab));
  authtab.name = sym_name;
  authtab.handler = handle_getpwent;
  authtab.m = &unit_tests_module;
  res = pr_stash_add_symbol(PR_SYM_AUTH, &authtab);
  fail_unless(res == 0, "Failed to add '%s' AUTH symbol: %s", sym_name,
    strerror(errno));

  pw = pr_auth_getpwent(p);
  fail_unless(pw != NULL, "Failed to find pwent: %s", strerror(errno));
  fail_unless(getpwent_count == 1, "Expected call count 1, got %u",
    getpwent_count);

  pr_stash_remove_symbol(PR_SYM_AUTH, sym_name, &unit_tests_module);
}
END_TEST

START_TEST (auth_getpwnam_test) {
  int res;
  struct passwd *pw;
  authtable authtab;
  char *sym_name = "getpwnam";

  pw = pr_auth_getpwnam(NULL, NULL);
  fail_unless(pw == NULL, "Found pwnam unexpectedly");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  pw = pr_auth_getpwnam(p, PR_TEST_AUTH_NAME);
  fail_unless(pw == NULL, "Found pwnam unexpectedly");
  fail_unless(getpwnam_count == 0, "Expected call count 0, got %u",
    getpwnam_count);
  mark_point();
  
  /* Load the appropriate AUTH symbol, and call it. */

  memset(&authtab, 0, sizeof(authtab));
  authtab.name = sym_name;
  authtab.handler = handle_getpwnam;
  authtab.m = &unit_tests_module;
  res = pr_stash_add_symbol(PR_SYM_AUTH, &authtab);
  fail_unless(res == 0, "Failed to add '%s' AUTH symbol: %s", sym_name,
    strerror(errno));

  mark_point();

  pw = pr_auth_getpwnam(p, PR_TEST_AUTH_NAME);
  fail_unless(pw != NULL, "Failed to find pwnam: %s", strerror(errno));
  fail_unless(getpwnam_count == 1, "Expected call count 1, got %u",
    getpwnam_count);

  mark_point();

  pw = pr_auth_getpwnam(p, "other");
  fail_unless(pw == NULL, "Found pwnam for user 'other' unexpectedly");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));
  fail_unless(getpwnam_count == 2, "Expected call count 2, got %u",
    getpwnam_count);

  pr_stash_remove_symbol(PR_SYM_AUTH, sym_name, &unit_tests_module);
}
END_TEST

START_TEST (auth_getpwuid_test) {
  int res;
  struct passwd *pw;
  authtable authtab;
  char *sym_name = "getpwuid";

  pw = pr_auth_getpwuid(NULL, -1);
  fail_unless(pw == NULL, "Found pwuid unexpectedly");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  pw = pr_auth_getpwuid(p, PR_TEST_AUTH_UID);
  fail_unless(pw == NULL, "Found pwuid unexpectedly");
  fail_unless(getpwuid_count == 0, "Expected call count 0, got %u",
    getpwuid_count);
  mark_point();
  
  /* Load the appropriate AUTH symbol, and call it. */

  memset(&authtab, 0, sizeof(authtab));
  authtab.name = sym_name;
  authtab.handler = handle_getpwuid;
  authtab.m = &unit_tests_module;
  res = pr_stash_add_symbol(PR_SYM_AUTH, &authtab);
  fail_unless(res == 0, "Failed to add '%s' AUTH symbol: %s", sym_name,
    strerror(errno));

  mark_point();

  pw = pr_auth_getpwuid(p, PR_TEST_AUTH_UID);
  fail_unless(pw != NULL, "Failed to find pwuid: %s", strerror(errno));
  fail_unless(getpwuid_count == 1, "Expected call count 1, got %u",
    getpwuid_count);

  mark_point();

  pw = pr_auth_getpwuid(p, 5);
  fail_unless(pw == NULL, "Found pwuid for UID 5 unexpectedly");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));
  fail_unless(getpwuid_count == 2, "Expected call count 2, got %u",
    getpwuid_count);

  pr_stash_remove_symbol(PR_SYM_AUTH, sym_name, &unit_tests_module);
}
END_TEST

START_TEST (auth_name2uid_test) {
  int res;
  uid_t uid;
  authtable authtab;
  char *sym_name = "name2uid";

  pr_auth_cache_set(FALSE, PR_AUTH_CACHE_FL_BAD_NAME2UID);

  uid = pr_auth_name2uid(NULL, NULL);
  fail_unless(uid == (uid_t) -1, "Found UID unexpectedly");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  uid = pr_auth_name2uid(p, PR_TEST_AUTH_NAME);
  fail_unless(uid == (uid_t) -1, "Found UID unexpectedly");
  fail_unless(name2uid_count == 0, "Expected call count 0, got %u",
    name2uid_count);
  mark_point();
  
  /* Load the appropriate AUTH symbol, and call it. */

  memset(&authtab, 0, sizeof(authtab));
  authtab.name = sym_name;
  authtab.handler = handle_name2uid;
  authtab.m = &unit_tests_module;
  res = pr_stash_add_symbol(PR_SYM_AUTH, &authtab);
  fail_unless(res == 0, "Failed to add '%s' AUTH symbol: %s", sym_name,
    strerror(errno));

  mark_point();

  uid = pr_auth_name2uid(p, PR_TEST_AUTH_NAME);
  fail_unless(uid == PR_TEST_AUTH_UID, "Expected UID %lu, got %lu",
    (unsigned long) PR_TEST_AUTH_UID, (unsigned long) uid);
  fail_unless(name2uid_count == 1, "Expected call count 1, got %u",
    name2uid_count);

  mark_point();

  /* Call again; the call counter should NOT increment due to caching. */

  uid = pr_auth_name2uid(p, PR_TEST_AUTH_NAME);
  fail_unless(uid == PR_TEST_AUTH_UID, "Expected UID %lu, got %lu",
    (unsigned long) PR_TEST_AUTH_UID, (unsigned long) uid);
  fail_unless(name2uid_count == 1, "Expected call count 1, got %u",
    name2uid_count);

  pr_stash_remove_symbol(PR_SYM_AUTH, sym_name, &unit_tests_module);
}
END_TEST

START_TEST (auth_uid2name_test) {
  int res;
  const char *name; 
  authtable authtab;
  char *sym_name = "uid2name";

  pr_auth_cache_set(FALSE, PR_AUTH_CACHE_FL_BAD_UID2NAME);

  name = pr_auth_uid2name(NULL, -1);
  fail_unless(name == NULL, "Found name unexpectedly: %s", name);
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));
  mark_point();

  name = pr_auth_uid2name(p, PR_TEST_AUTH_UID);
  fail_unless(name != NULL, "Failed to find name for UID %lu: %s",
    (unsigned long) PR_TEST_AUTH_UID, strerror(errno));
  fail_unless(strcmp(name, PR_TEST_AUTH_UID_STR) == 0,
     "Expected name '%s', got '%s'", PR_TEST_AUTH_UID_STR, name);
  fail_unless(uid2name_count == 0, "Expected call count 0, got %u",
    uid2name_count);
  mark_point();
  
  /* Load the appropriate AUTH symbol, and call it. */

  memset(&authtab, 0, sizeof(authtab));
  authtab.name = sym_name;
  authtab.handler = handle_uid2name;
  authtab.m = &unit_tests_module;
  res = pr_stash_add_symbol(PR_SYM_AUTH, &authtab);
  fail_unless(res == 0, "Failed to add '%s' AUTH symbol: %s", sym_name,
    strerror(errno));

  mark_point();

  name = pr_auth_uid2name(p, PR_TEST_AUTH_UID);
  fail_unless(name != NULL, "Expected name, got null");
  fail_unless(strcmp(name, PR_TEST_AUTH_NAME) == 0,
    "Expected name '%s', got '%s'", PR_TEST_AUTH_NAME, name);
  fail_unless(uid2name_count == 1, "Expected call count 1, got %u",
    uid2name_count);

  pr_stash_remove_symbol(PR_SYM_AUTH, sym_name, &unit_tests_module);
}
END_TEST

START_TEST (auth_setgrent_test) {
  int res;
  authtable authtab;
  char *sym_name = "setgrent";

  pr_auth_setgrent(p);
  fail_unless(setgrent_count == 0, "Expected call count 0, got %u",
    setgrent_count);
  mark_point();
  
  /* Load the appropriate AUTH symbol, and call it. */

  memset(&authtab, 0, sizeof(authtab));
  authtab.name = sym_name;
  authtab.handler = handle_setgrent;
  authtab.m = &unit_tests_module;
  res = pr_stash_add_symbol(PR_SYM_AUTH, &authtab);
  fail_unless(res == 0, "Failed to add '%s' AUTH symbol: %s", sym_name,
    strerror(errno));

  pr_auth_setgrent(p);
  fail_unless(setgrent_count == 1, "Expected call count 1, got %u",
    setgrent_count);

  pr_stash_remove_symbol(PR_SYM_AUTH, sym_name, &unit_tests_module);
}
END_TEST

START_TEST (auth_endgrent_test) {
  int res;
  authtable authtab;
  char *sym_name = "endgrent";

  pr_auth_endgrent(p);
  fail_unless(endgrent_count == 0, "Expected call count 0, got %u",
    endgrent_count);
  mark_point();
  
  /* Load the appropriate AUTH symbol, and call it. */

  memset(&authtab, 0, sizeof(authtab));
  authtab.name = sym_name;
  authtab.handler = handle_endgrent;
  authtab.m = &unit_tests_module;
  res = pr_stash_add_symbol(PR_SYM_AUTH, &authtab);
  fail_unless(res == 0, "Failed to add '%s' AUTH symbol: %s", sym_name,
    strerror(errno));

  pr_auth_endgrent(p);
  fail_unless(endgrent_count == 1, "Expected call count 1, got %u",
    endgrent_count);

  pr_stash_remove_symbol(PR_SYM_AUTH, sym_name, &unit_tests_module);
}
END_TEST

START_TEST (auth_getgrent_test) {
  int res;
  struct group *gr;
  authtable authtab;
  char *sym_name = "getgrent";

  gr = pr_auth_getgrent(NULL);
  fail_unless(gr == NULL, "Found grent unexpectedly");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  gr = pr_auth_getgrent(p);
  fail_unless(gr == NULL, "Found grent unexpectedly");
  fail_unless(getgrent_count == 0, "Expected call count 0, got %u",
    getgrent_count);
  mark_point();
  
  /* Load the appropriate AUTH symbol, and call it. */

  memset(&authtab, 0, sizeof(authtab));
  authtab.name = sym_name;
  authtab.handler = handle_getgrent;
  authtab.m = &unit_tests_module;
  res = pr_stash_add_symbol(PR_SYM_AUTH, &authtab);
  fail_unless(res == 0, "Failed to add '%s' AUTH symbol: %s", sym_name,
    strerror(errno));

  gr = pr_auth_getgrent(p);
  fail_unless(gr != NULL, "Failed to find grent: %s", strerror(errno));
  fail_unless(getgrent_count == 1, "Expected call count 1, got %u",
    getgrent_count);

  pr_stash_remove_symbol(PR_SYM_AUTH, sym_name, &unit_tests_module);
}
END_TEST

START_TEST (auth_getgrnam_test) {
  int res;
  struct group *gr;
  authtable authtab;
  char *sym_name = "getgrnam";

  gr = pr_auth_getgrnam(NULL, NULL);
  fail_unless(gr == NULL, "Found grnam unexpectedly");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  gr = pr_auth_getgrnam(p, PR_TEST_AUTH_NAME);
  fail_unless(gr == NULL, "Found grnam unexpectedly");
  fail_unless(getgrnam_count == 0, "Expected call count 0, got %u",
    getgrnam_count);
  mark_point();
  
  /* Load the appropriate AUTH symbol, and call it. */

  memset(&authtab, 0, sizeof(authtab));
  authtab.name = sym_name;
  authtab.handler = handle_getgrnam;
  authtab.m = &unit_tests_module;
  res = pr_stash_add_symbol(PR_SYM_AUTH, &authtab);
  fail_unless(res == 0, "Failed to add '%s' AUTH symbol: %s", sym_name,
    strerror(errno));

  mark_point();

  gr = pr_auth_getgrnam(p, PR_TEST_AUTH_NAME);
  fail_unless(gr != NULL, "Failed to find grnam: %s", strerror(errno));
  fail_unless(getgrnam_count == 1, "Expected call count 1, got %u",
    getgrnam_count);

  mark_point();

  gr = pr_auth_getgrnam(p, "other");
  fail_unless(gr == NULL, "Found grnam for user 'other' unexpectedly");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));
  fail_unless(getgrnam_count == 2, "Expected call count 2, got %u",
    getgrnam_count);

  pr_stash_remove_symbol(PR_SYM_AUTH, sym_name, &unit_tests_module);
}
END_TEST

START_TEST (auth_getgrgid_test) {
  int res;
  struct group *gr;
  authtable authtab;
  char *sym_name = "getgrgid";

  gr = pr_auth_getgrgid(NULL, -1);
  fail_unless(gr == NULL, "Found grgid unexpectedly");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  gr = pr_auth_getgrgid(p, PR_TEST_AUTH_GID);
  fail_unless(gr == NULL, "Found grgid unexpectedly");
  fail_unless(getgrgid_count == 0, "Expected call count 0, got %u",
    getgrgid_count);
  mark_point();
  
  /* Load the appropriate AUTH symbol, and call it. */

  memset(&authtab, 0, sizeof(authtab));
  authtab.name = sym_name;
  authtab.handler = handle_getgrgid;
  authtab.m = &unit_tests_module;
  res = pr_stash_add_symbol(PR_SYM_AUTH, &authtab);
  fail_unless(res == 0, "Failed to add '%s' AUTH symbol: %s", sym_name,
    strerror(errno));

  mark_point();

  gr = pr_auth_getgrgid(p, PR_TEST_AUTH_GID);
  fail_unless(gr != NULL, "Failed to find grgid: %s", strerror(errno));
  fail_unless(getgrgid_count == 1, "Expected call count 1, got %u",
    getgrgid_count);

  mark_point();

  gr = pr_auth_getgrgid(p, 5);
  fail_unless(gr == NULL, "Found grgid for GID 5 unexpectedly");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));
  fail_unless(getgrgid_count == 2, "Expected call count 2, got %u",
    getgrgid_count);

  pr_stash_remove_symbol(PR_SYM_AUTH, sym_name, &unit_tests_module);
}
END_TEST

START_TEST (auth_name2gid_test) {
  int res;
  gid_t gid;
  authtable authtab;
  char *sym_name = "name2gid";

  pr_auth_cache_set(FALSE, PR_AUTH_CACHE_FL_BAD_NAME2GID);

  gid = pr_auth_name2gid(NULL, NULL);
  fail_unless(gid == (gid_t) -1, "Found GID unexpectedly");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  gid = pr_auth_name2gid(p, PR_TEST_AUTH_NAME);
  fail_unless(gid == (gid_t) -1, "Found GID unexpectedly");
  fail_unless(name2gid_count == 0, "Expected call count 0, got %u",
    name2gid_count);
  mark_point();
  
  /* Load the appropriate AUTH symbol, and call it. */

  memset(&authtab, 0, sizeof(authtab));
  authtab.name = sym_name;
  authtab.handler = handle_name2gid;
  authtab.m = &unit_tests_module;
  res = pr_stash_add_symbol(PR_SYM_AUTH, &authtab);
  fail_unless(res == 0, "Failed to add '%s' AUTH symbol: %s", sym_name,
    strerror(errno));

  mark_point();

  gid = pr_auth_name2gid(p, PR_TEST_AUTH_NAME);
  fail_unless(gid == PR_TEST_AUTH_GID, "Expected GID %lu, got %lu",
    (unsigned long) PR_TEST_AUTH_GID, (unsigned long) gid);
  fail_unless(name2gid_count == 1, "Expected call count 1, got %u",
    name2gid_count);

  mark_point();

  /* Call again; the call counter should NOT increment due to caching. */

  gid = pr_auth_name2gid(p, PR_TEST_AUTH_NAME);
  fail_unless(gid == PR_TEST_AUTH_GID, "Expected GID %lu, got %lu",
    (unsigned long) PR_TEST_AUTH_GID, (unsigned long) gid);
  fail_unless(name2gid_count == 1, "Expected call count 1, got %u",
    name2gid_count);

  pr_stash_remove_symbol(PR_SYM_AUTH, sym_name, &unit_tests_module);
}
END_TEST

START_TEST (auth_gid2name_test) {
  int res;
  const char *name; 
  authtable authtab;
  char *sym_name = "gid2name";

  pr_auth_cache_set(FALSE, PR_AUTH_CACHE_FL_BAD_GID2NAME);

  name = pr_auth_gid2name(NULL, -1);
  fail_unless(name == NULL, "Found name unexpectedly: %s", name);
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));
  mark_point();

  name = pr_auth_gid2name(p, PR_TEST_AUTH_GID);
  fail_unless(name != NULL, "Failed to find name for GID %lu: %s",
    (unsigned long) PR_TEST_AUTH_GID, strerror(errno));
  fail_unless(strcmp(name, PR_TEST_AUTH_GID_STR) == 0,
     "Expected name '%s', got '%s'", PR_TEST_AUTH_GID_STR, name);
  fail_unless(gid2name_count == 0, "Expected call count 0, got %u",
    gid2name_count);
  mark_point();
  
  /* Load the appropriate AUTH symbol, and call it. */

  memset(&authtab, 0, sizeof(authtab));
  authtab.name = sym_name;
  authtab.handler = handle_gid2name;
  authtab.m = &unit_tests_module;
  res = pr_stash_add_symbol(PR_SYM_AUTH, &authtab);
  fail_unless(res == 0, "Failed to add '%s' AUTH symbol: %s", sym_name,
    strerror(errno));

  mark_point();

  name = pr_auth_gid2name(p, PR_TEST_AUTH_GID);
  fail_unless(name != NULL, "Expected name, got null");
  fail_unless(strcmp(name, PR_TEST_AUTH_NAME) == 0,
    "Expected name '%s', got '%s'", PR_TEST_AUTH_NAME, name);
  fail_unless(gid2name_count == 1, "Expected call count 1, got %u",
    gid2name_count);

  pr_stash_remove_symbol(PR_SYM_AUTH, sym_name, &unit_tests_module);
}
END_TEST

START_TEST (auth_getgroups_test) {
  int res;
  array_header *gids = NULL;
  authtable authtab;
  char *sym_name = "getgroups";

  res = pr_auth_getgroups(NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  res = pr_auth_getgroups(p, PR_TEST_AUTH_NAME, &gids, NULL);
  fail_unless(res < 0, "Found groups for '%s' unexpectedly", PR_TEST_AUTH_NAME);
  fail_unless(getgroups_count == 0, "Expected call count 0, got %u",
    getgroups_count);
  mark_point();
  
  /* Load the appropriate AUTH symbol, and call it. */

  memset(&authtab, 0, sizeof(authtab));
  authtab.name = sym_name;
  authtab.handler = handle_getgroups;
  authtab.m = &unit_tests_module;
  res = pr_stash_add_symbol(PR_SYM_AUTH, &authtab);
  fail_unless(res == 0, "Failed to add '%s' AUTH symbol: %s", sym_name,
    strerror(errno));

  mark_point();

  res = pr_auth_getgroups(p, PR_TEST_AUTH_NAME, &gids, NULL);
  fail_unless(res > 0, "Expected group count 1 for '%s', got %d: %s",
    PR_TEST_AUTH_NAME, res, strerror(errno));
  fail_unless(getgroups_count == 1, "Expected call count 1, got %u",
    getgroups_count);

  res = pr_auth_getgroups(p, "other", &gids, NULL);
  fail_unless(res < 0, "Found groups for 'other' unexpectedly");
  fail_unless(getgroups_count == 2, "Expected call count 2, got %u",
    getgroups_count);

  pr_stash_remove_symbol(PR_SYM_AUTH, sym_name, &unit_tests_module);
}
END_TEST

START_TEST (auth_cache_uid2name_test) {
  int res;
  const char *name; 
  authtable authtab;
  char *sym_name = "uid2name";

  /* Load the appropriate AUTH symbol, and call it. */

  memset(&authtab, 0, sizeof(authtab));
  authtab.name = sym_name;
  authtab.handler = handle_uid2name;
  authtab.m = &unit_tests_module;
  res = pr_stash_add_symbol(PR_SYM_AUTH, &authtab);
  fail_unless(res == 0, "Failed to add '%s' AUTH symbol: %s", sym_name,
    strerror(errno));

  mark_point();

  name = pr_auth_uid2name(p, PR_TEST_AUTH_UID);
  fail_unless(name != NULL, "Expected name, got null");
  fail_unless(strcmp(name, PR_TEST_AUTH_NAME) == 0,
    "Expected name '%s', got '%s'", PR_TEST_AUTH_NAME, name);
  fail_unless(uid2name_count == 1, "Expected call count 1, got %u",
    uid2name_count);

  /* Call again; the call counter should NOT increment due to caching. */

  name = pr_auth_uid2name(p, PR_TEST_AUTH_UID);
  fail_unless(name != NULL, "Expected name, got null");
  fail_unless(strcmp(name, PR_TEST_AUTH_NAME) == 0,
    "Expected name '%s', got '%s'", PR_TEST_AUTH_NAME, name);
  fail_unless(uid2name_count == 1, "Expected call count 1, got %u",
    uid2name_count);

  pr_stash_remove_symbol(PR_SYM_AUTH, sym_name, &unit_tests_module);
}
END_TEST

START_TEST (auth_cache_gid2name_test) {
  int res;
  const char *name; 
  authtable authtab;
  char *sym_name = "gid2name";

  /* Load the appropriate AUTH symbol, and call it. */

  memset(&authtab, 0, sizeof(authtab));
  authtab.name = sym_name;
  authtab.handler = handle_gid2name;
  authtab.m = &unit_tests_module;
  res = pr_stash_add_symbol(PR_SYM_AUTH, &authtab);
  fail_unless(res == 0, "Failed to add '%s' AUTH symbol: %s", sym_name,
    strerror(errno));

  mark_point();

  name = pr_auth_gid2name(p, PR_TEST_AUTH_GID);
  fail_unless(name != NULL, "Expected name, got null");
  fail_unless(strcmp(name, PR_TEST_AUTH_NAME) == 0,
    "Expected name '%s', got '%s'", PR_TEST_AUTH_NAME, name);
  fail_unless(gid2name_count == 1, "Expected call count 1, got %u",
    gid2name_count);

  /* Call again; the call counter should NOT increment due to caching. */

  name = pr_auth_gid2name(p, PR_TEST_AUTH_GID);
  fail_unless(name != NULL, "Expected name, got null");
  fail_unless(strcmp(name, PR_TEST_AUTH_NAME) == 0,
    "Expected name '%s', got '%s'", PR_TEST_AUTH_NAME, name);
  fail_unless(gid2name_count == 1, "Expected call count 1, got %u",
    gid2name_count);

  pr_stash_remove_symbol(PR_SYM_AUTH, sym_name, &unit_tests_module);
}
END_TEST

START_TEST (auth_cache_uid2name_failed_test) {
  int res;
  const char *name; 
  authtable authtab;
  char *sym_name = "uid2name";

  /* Load the appropriate AUTH symbol, and call it. */

  memset(&authtab, 0, sizeof(authtab));
  authtab.name = sym_name;
  authtab.handler = decline_uid2name;
  authtab.m = &unit_tests_module;
  res = pr_stash_add_symbol(PR_SYM_AUTH, &authtab);
  fail_unless(res == 0, "Failed to add '%s' AUTH symbol: %s", sym_name,
    strerror(errno));

  mark_point();

  name = pr_auth_uid2name(p, PR_TEST_AUTH_UID);
  fail_unless(name != NULL, "Expected name, got null");
  fail_unless(strcmp(name, PR_TEST_AUTH_UID_STR) == 0,
    "Expected name '%s', got '%s'", PR_TEST_AUTH_UID_STR, name);
  fail_unless(uid2name_count == 1, "Expected call count 1, got %u",
    uid2name_count);

  /* Call again; the call counter should NOT increment due to caching. */

  name = pr_auth_uid2name(p, PR_TEST_AUTH_UID);
  fail_unless(name != NULL, "Expected name, got null");
  fail_unless(strcmp(name, PR_TEST_AUTH_UID_STR) == 0,
    "Expected name '%s', got '%s'", PR_TEST_AUTH_UID_STR, name);
  fail_unless(uid2name_count == 1, "Expected call count 1, got %u",
    uid2name_count);

  pr_stash_remove_symbol(PR_SYM_AUTH, sym_name, &unit_tests_module);
}
END_TEST

START_TEST (auth_cache_gid2name_failed_test) {
  int res;
  const char *name; 
  authtable authtab;
  char *sym_name = "gid2name";

  /* Load the appropriate AUTH symbol, and call it. */

  memset(&authtab, 0, sizeof(authtab));
  authtab.name = sym_name;
  authtab.handler = decline_gid2name;
  authtab.m = &unit_tests_module;
  res = pr_stash_add_symbol(PR_SYM_AUTH, &authtab);
  fail_unless(res == 0, "Failed to add '%s' AUTH symbol: %s", sym_name,
    strerror(errno));

  mark_point();

  name = pr_auth_gid2name(p, PR_TEST_AUTH_GID);
  fail_unless(name != NULL, "Expected name, got null");
  fail_unless(strcmp(name, PR_TEST_AUTH_GID_STR) == 0,
    "Expected name '%s', got '%s'", PR_TEST_AUTH_GID_STR, name);
  fail_unless(gid2name_count == 1, "Expected call count 1, got %u",
    gid2name_count);

  /* Call again; the call counter should NOT increment due to caching. */

  name = pr_auth_gid2name(p, PR_TEST_AUTH_GID);
  fail_unless(name != NULL, "Expected name, got null");
  fail_unless(strcmp(name, PR_TEST_AUTH_GID_STR) == 0,
    "Expected name '%s', got '%s'", PR_TEST_AUTH_GID_STR, name);
  fail_unless(gid2name_count == 1, "Expected call count 1, got %u",
    gid2name_count);

  pr_stash_remove_symbol(PR_SYM_AUTH, sym_name, &unit_tests_module);
}
END_TEST

START_TEST (auth_cache_name2uid_failed_test) {
  int res;
  uid_t uid;
  authtable authtab;
  char *sym_name = "name2uid";

  /* Load the appropriate AUTH symbol, and call it. */

  memset(&authtab, 0, sizeof(authtab));
  authtab.name = sym_name;
  authtab.handler = decline_name2uid;
  authtab.m = &unit_tests_module;
  res = pr_stash_add_symbol(PR_SYM_AUTH, &authtab);
  fail_unless(res == 0, "Failed to add '%s' AUTH symbol: %s", sym_name,
    strerror(errno));

  mark_point();

  uid = pr_auth_name2uid(p, PR_TEST_AUTH_NAME);
  fail_unless(uid == (uid_t) -1, "Expected -1, got %lu", (unsigned long) uid);
  fail_unless(name2uid_count == 1, "Expected call count 1, got %u",
    name2uid_count);

  /* Call again; the call counter should NOT increment due to caching. */

  uid = pr_auth_name2uid(p, PR_TEST_AUTH_NAME);
  fail_unless(uid == (uid_t) -1, "Expected -1, got %lu", (unsigned long) uid);
  fail_unless(name2uid_count == 1, "Expected call count 1, got %u",
    name2uid_count);

  pr_stash_remove_symbol(PR_SYM_AUTH, sym_name, &unit_tests_module);
}
END_TEST

START_TEST (auth_cache_name2gid_failed_test) {
  int res;
  gid_t gid;
  authtable authtab;
  char *sym_name = "name2gid";

  /* Load the appropriate AUTH symbol, and call it. */

  memset(&authtab, 0, sizeof(authtab));
  authtab.name = sym_name;
  authtab.handler = decline_name2gid;
  authtab.m = &unit_tests_module;
  res = pr_stash_add_symbol(PR_SYM_AUTH, &authtab);
  fail_unless(res == 0, "Failed to add '%s' AUTH symbol: %s", sym_name,
    strerror(errno));

  mark_point();

  gid = pr_auth_name2gid(p, PR_TEST_AUTH_NAME);
  fail_unless(gid == (gid_t) -1, "Expected -1, got %lu", (unsigned long) gid);
  fail_unless(name2gid_count == 1, "Expected call count 1, got %u",
    name2gid_count);

  /* Call again; the call counter should NOT increment due to caching. */

  gid = pr_auth_name2gid(p, PR_TEST_AUTH_NAME);
  fail_unless(gid == (gid_t) -1, "Expected -1, got %lu", (unsigned long) gid);
  fail_unless(name2gid_count == 1, "Expected call count 1, got %u",
    name2gid_count);

  pr_stash_remove_symbol(PR_SYM_AUTH, sym_name, &unit_tests_module);
}
END_TEST

Suite *tests_get_auth_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("auth");

  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  /* pwent* et al */
  tcase_add_test(testcase, auth_setpwent_test);
  tcase_add_test(testcase, auth_endpwent_test);
  tcase_add_test(testcase, auth_getpwent_test);
  tcase_add_test(testcase, auth_getpwnam_test);
  tcase_add_test(testcase, auth_getpwuid_test);
  tcase_add_test(testcase, auth_name2uid_test);
  tcase_add_test(testcase, auth_uid2name_test);

  /* grent* et al */
  tcase_add_test(testcase, auth_setgrent_test);
  tcase_add_test(testcase, auth_endgrent_test);
  tcase_add_test(testcase, auth_getgrent_test);
  tcase_add_test(testcase, auth_getgrnam_test);
  tcase_add_test(testcase, auth_getgrgid_test);
  tcase_add_test(testcase, auth_gid2name_test);
  tcase_add_test(testcase, auth_name2gid_test);
  tcase_add_test(testcase, auth_getgroups_test);

  /* Caching tests */
  tcase_add_test(testcase, auth_cache_uid2name_test);
  tcase_add_test(testcase, auth_cache_gid2name_test);
  tcase_add_test(testcase, auth_cache_uid2name_failed_test);
  tcase_add_test(testcase, auth_cache_gid2name_failed_test);
  tcase_add_test(testcase, auth_cache_name2uid_failed_test);
  tcase_add_test(testcase, auth_cache_name2gid_failed_test);

#if 0
  /* Authorization */
  tcase_add_test(testcase, auth_authenticate_test);
  tcase_add_test(testcase, auth_authorize_test);
  tcase_add_test(testcase, auth_check_test);
  tcase_add_test(testcase, auth_requires_pass_test);

  /* Auth modules */
  tcase_add_test(testcase, auth_add_auth_only_module_test);
  tcase_add_test(testcase, auth_remove_auth_only_module_test);
  tcase_add_test(testcase, auth_clear_auth_only_modules_test);
#endif

  suite_add_tcase(suite, testcase);

  return suite;
}
