/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2020 The ProFTPD Project team
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

/* Controls API tests */

#include "tests.h"
#include "mod_ctrls.h"

#if defined(PR_USE_CTRLS)
static pool *p = NULL;

static const char *tmpfile_path = "/tmp/prt-ctrls.dat";

static void set_up(void) {
  (void) unlink(tmpfile_path);

  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("ctrls", 1, 20);
  }

  init_ctrls2("/tmp/test.sock");
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("ctrls", 0, 0);
  }

  if (p != NULL) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }

  (void) unlink(tmpfile_path);
}

static int devnull_fd(void) {
  int fd;

  fd = open("/dev/null", O_RDWR);
  if (fd < 0) {
    fprintf(stderr, "Error opening /dev/null: %s\n", strerror(errno));
    return -1;
  }

  return fd;
}

static int tmpfile_fd(void) {
  int fd;

  fd = open(tmpfile_path, O_CREAT|O_RDWR, 0600);
  if (fd < 0) {
    fprintf(stderr, "Error opening %s: %s\n", tmpfile_path, strerror(errno));
    return -1;
  }

  (void) unlink(tmpfile_path);
  return fd;
}

static int reset_fd(int fd) {
  (void) close(fd);
  return tmpfile_fd();
}

static int rewind_fd(int fd) {
  if (lseek(fd, 0, SEEK_SET) == (off_t) -1) {
    return -1;
  }

  return 0;
}

/* Largely copied from mod_ctrls. */
static int listen_unix(const char *path) {
  int fd = -1, socklen = 0;
  struct sockaddr_un sock;
#if !defined(SO_PEERCRED) && !defined(HAVE_GETPEEREID) && \
    !defined(HAVE_GETPEERUCRED) && defined(LOCAL_CREDS)
  int opt = 1;
  socklen_t optlen = sizeof(opt);
#endif /* !LOCAL_CREDS */

  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    fprintf(stderr, "error creating local socket: %s\n", strerror(errno));
    return -1;
  }

  (void) unlink(path);
  memset(&sock, 0, sizeof(sock));
  sock.sun_family = AF_UNIX;
  sstrncpy(sock.sun_path, path, sizeof(sock.sun_path));

  socklen = sizeof(sock);
  if (bind(fd, (struct sockaddr *) &sock, socklen) < 0) {
    fprintf(stderr, "error binding local socket to path '%s': %s\n", path,
      strerror(errno));
    (void) close(fd);
    return -1;
  }

  if (listen(fd, 5) < 0) {
    fprintf(stderr, "error listening on local socket: %s\n", strerror(errno));
    (void) close(fd);
    return -1;
  }

#if !defined(SO_PEERCRED) && !defined(HAVE_GETPEEREID) && \
    !defined(HAVE_GETPEERUCRED) && defined(LOCAL_CREDS)
  /* Set the LOCAL_CREDS socket option. */
  if (setsockopt(fd, 0, LOCAL_CREDS, &opt, optlen) < 0) {
    fprintf(stderr, "error enabling LOCAL_CREDS: %s\n", strerror(errno));
  }
#endif /* !LOCAL_CREDS */

  return fd;
}

/* Tests */

START_TEST (ctrls_alloc_free_test) {
  int res;
  pr_ctrls_t *ctrl, *ctrl2, *ctrl3;

  mark_point();
  res = pr_ctrls_free(NULL);
  fail_unless(res < 0, "Failed to handle null ctrl");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  ctrl = pr_ctrls_alloc();
  fail_unless(ctrl != NULL, "Failed to allocate ctrl: %s", strerror(errno));
  res = pr_ctrls_free(ctrl);
  fail_unless(res == 0, "Failed to free ctrl: %s", strerror(errno));

  mark_point();
  ctrl = pr_ctrls_alloc();
  fail_unless(ctrl != NULL, "Failed to allocate ctrl: %s", strerror(errno));
  res = pr_ctrls_free(ctrl);
  fail_unless(res == 0, "Failed to free ctrl: %s", strerror(errno));

  /* LIFO order */
  mark_point();
  ctrl = pr_ctrls_alloc();
  ctrl2 = pr_ctrls_alloc();
  fail_unless(ctrl2 != NULL, "Failed to allocate ctrl2: %s", strerror(errno));
  ctrl2->ctrls_tmp_pool = make_sub_pool(p);
  ctrl3 = pr_ctrls_alloc();
  fail_unless(ctrl3 != NULL, "Failed to allocate ctrl3: %s", strerror(errno));
  ctrl3->ctrls_tmp_pool = make_sub_pool(p);

  res = pr_ctrls_free(ctrl3);
  fail_unless(res == 0, "Failed to free ctrl3 %s", strerror(errno));
  res = pr_ctrls_free(ctrl2);
  fail_unless(res == 0, "Failed to free ctrl2: %s", strerror(errno));
  res = pr_ctrls_free(ctrl);
  fail_unless(res == 0, "Failed to free ctrl: %s", strerror(errno));

  /* FIFO order */
  mark_point();
  ctrl = pr_ctrls_alloc();
  ctrl2 = pr_ctrls_alloc();
  fail_unless(ctrl2 != NULL, "Failed to allocate ctrl2: %s", strerror(errno));
  ctrl2->ctrls_tmp_pool = make_sub_pool(p);
  ctrl3 = pr_ctrls_alloc();
  fail_unless(ctrl3 != NULL, "Failed to allocate ctrl3: %s", strerror(errno));
  ctrl3->ctrls_tmp_pool = make_sub_pool(p);

  res = pr_ctrls_free(ctrl);
  fail_unless(res == 0, "Failed to free ctrl: %s", strerror(errno));
  res = pr_ctrls_free(ctrl2);
  fail_unless(res == 0, "Failed to free ctrl2: %s", strerror(errno));
  res = pr_ctrls_free(ctrl3);
  fail_unless(res == 0, "Failed to free ctrl3 %s", strerror(errno));
}
END_TEST

START_TEST (ctrls_unregister_test) {
  int res;

  mark_point();
  res = pr_ctrls_unregister(NULL, NULL);
  fail_unless(res < 0, "Failed to handle lack of registered actions");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);
}
END_TEST

static int ctrls_test_cb(pr_ctrls_t *ctrl, int reqargc, char **reqargv) {
  return 0;
}

static int ctrls_test2_cb(pr_ctrls_t *ctrl, int reqargc, char **reqargv) {
  return 0;
}

START_TEST (ctrls_register_test) {
  int res;
  const char *action = NULL, *desc = NULL;
  module m;

  mark_point();
  res = pr_ctrls_register(NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null action");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  action = "test";
  res = pr_ctrls_register(NULL, action, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null desc");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  desc = "desc";
  res = pr_ctrls_register(NULL, action, desc, NULL);
  fail_unless(res < 0, "Failed to handle null callback");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_ctrls_register(NULL, action, desc, ctrls_test_cb);
  fail_unless(res >= 0, "Failed to register ctrls action: %s", strerror(errno));

  mark_point();
  res = pr_ctrls_unregister(NULL, action);
  fail_unless(res == 0, "Failed to unregister ctrls action: %s",
    strerror(errno));

  mark_point();
  res = pr_ctrls_register(NULL, action, desc, ctrls_test_cb);
  fail_unless(res >= 0, "Failed to register ctrls action: %s", strerror(errno));

  m.name = "test";
  res = pr_ctrls_register(&m, action, desc, ctrls_test_cb);
  fail_unless(res >= 0, "Failed to register ctrls action: %s", strerror(errno));

  mark_point();
  res = pr_ctrls_unregister(NULL, action);
  fail_unless(res == 0, "Failed to unregister ctrls action: %s",
    strerror(errno));
}
END_TEST

START_TEST (ctrls_add_arg_test) {
  int res;
  pr_ctrls_t *ctrl;
  char buf[4];
  size_t buflen;

  mark_point();
  res = pr_ctrls_add_arg(NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null ctrl");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  ctrl = pr_ctrls_alloc();
  res = pr_ctrls_add_arg(ctrl, NULL, 0);
  fail_unless(res < 0, "Failed to handle null arg");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  ctrl = pr_ctrls_alloc();

  /* Provide an arg that uses unprintable ASCII. */
  buf[0] = 'a';
  buf[1] = 'b';
  buf[2] = -120;
  buflen = 3;

  res = pr_ctrls_add_arg(ctrl, buf, buflen);
  fail_unless(res < 0, "Failed to handle bad arg");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  mark_point();
  buf[0] = 'a';
  buf[1] = 'B';
  buf[2] = '1';
  buflen = 3;

  res = pr_ctrls_add_arg(ctrl, buf, buflen);
  fail_unless(res == 0, "Failed to add ctrl arg: %s", strerror(errno));
}
END_TEST

START_TEST (ctrls_add_response_test) {
  int res;
  pr_ctrls_t *ctrl;

  mark_point();
  res = pr_ctrls_add_response(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null ctrl");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  ctrl = pr_ctrls_alloc();
  res = pr_ctrls_add_response(ctrl, NULL);
  fail_unless(res < 0, "Failed to handle null fmt");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_ctrls_add_response(ctrl, "%s", "foo");
  fail_unless(res == 0, "Failed to add ctrl response: %s", strerror(errno));
}
END_TEST

START_TEST (ctrls_copy_args_test) {
  int res;
  pr_ctrls_t *src_ctrl, *dst_ctrl;

  mark_point();
  res = pr_ctrls_copy_args(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null src ctrl");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  src_ctrl = pr_ctrls_alloc();
  res = pr_ctrls_copy_args(src_ctrl, NULL);
  fail_unless(res < 0, "Failed to handle null dst ctrl");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_ctrls_copy_args(src_ctrl, src_ctrl);
  fail_unless(res < 0, "Failed to handle same src/dst ctrl");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  dst_ctrl = pr_ctrls_alloc();
  res = pr_ctrls_copy_args(src_ctrl, dst_ctrl);
  fail_unless(res == 0, "Failed to copy ctrl args: %s", strerror(errno));

  mark_point();
  res = pr_ctrls_add_arg(src_ctrl, "foo", 3);
  fail_unless(res == 0, "Failed to add src ctrl arg: %s", strerror(errno));

  res = pr_ctrls_add_arg(src_ctrl, "bar", 3);
  fail_unless(res == 0, "Failed to add src ctrl arg: %s", strerror(errno));

  res = pr_ctrls_add_arg(src_ctrl, "baz", 3);
  fail_unless(res == 0, "Failed to add src ctrl arg: %s", strerror(errno));

  res = pr_ctrls_copy_args(src_ctrl, dst_ctrl);
  fail_unless(res == 0, "Failed to copy ctrl args: %s", strerror(errno));
}
END_TEST

START_TEST (ctrls_copy_resps_test) {
  int res;
  pr_ctrls_t *src_ctrl, *dst_ctrl;

  mark_point();
  res = pr_ctrls_copy_resps(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null src ctrl");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  src_ctrl = pr_ctrls_alloc();
  res = pr_ctrls_copy_resps(src_ctrl, NULL);
  fail_unless(res < 0, "Failed to handle null dst ctrl");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_ctrls_copy_resps(src_ctrl, src_ctrl);
  fail_unless(res < 0, "Failed to handle same src/dst ctrl");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  dst_ctrl = pr_ctrls_alloc();
  res = pr_ctrls_copy_resps(src_ctrl, dst_ctrl);
  fail_unless(res < 0, "Failed to handle src ctrl with no responses");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  mark_point();
  res = pr_ctrls_add_response(src_ctrl, "%s", "foo");
  fail_unless(res == 0, "Failed to add src ctrl response: %s", strerror(errno));

  res = pr_ctrls_add_response(dst_ctrl, "%s", "bar");
  fail_unless(res == 0, "Failed to add dst ctrl response: %s", strerror(errno));

  res = pr_ctrls_copy_resps(src_ctrl, dst_ctrl);
  fail_unless(res < 0, "Failed to handle dst ctrl with responses");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  mark_point();
  src_ctrl = pr_ctrls_alloc();
  res = pr_ctrls_add_response(src_ctrl, "%s", "foo");
  fail_unless(res == 0, "Failed to add src ctrl response: %s", strerror(errno));

  dst_ctrl = pr_ctrls_alloc();
  res = pr_ctrls_copy_resps(src_ctrl, dst_ctrl);
  fail_unless(res == 0, "Failed to copy ctrl responses: %s", strerror(errno));
}
END_TEST

START_TEST (ctrls_send_msg_test) {
  int fd, res, status;
  unsigned int msgargc = 1;
  char *msgargv[] = { "foo", NULL };

  mark_point();
  res = pr_ctrls_send_msg(-1, 0, 0, NULL);
  fail_unless(res < 0, "Failed to handle invalid fd");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  fd = 7;
  res = pr_ctrls_send_msg(fd, 0, 0, NULL);
  fail_unless(res == 0, "Failed to send zero ctrl messages: %s",
    strerror(errno));

  mark_point();
  fd = 7;
  res = pr_ctrls_send_msg(fd, 0, msgargc, NULL);
  fail_unless(res == 0, "Failed to send zero ctrl messages: %s",
    strerror(errno));

  mark_point();
  fd = 7777;
  status = -24;
  res = pr_ctrls_send_msg(fd, status, msgargc, msgargv);
  fail_unless(res < 0, "Failed to handle invalid fd");
  fail_unless(errno == EBADF, "Expected EBADF (%d), got %s (%d)", EBADF,
    strerror(errno), errno);

  fd = devnull_fd();
  if (fd < 0) {
    return;
  }

  mark_point();
  status = -24;
  res = pr_ctrls_send_msg(fd, status, msgargc, msgargv);
  fail_unless(res == 0, "Failed to send ctrl message: %s", strerror(errno));

  (void) close(fd);
}
END_TEST

START_TEST (ctrls_flush_response_test) {
  int res;
  pr_ctrls_t *ctrl;
  pr_ctrls_cl_t *cl;

  mark_point();
  res = pr_ctrls_flush_response(NULL);
  fail_unless(res < 0, "Failed to handle null ctrl");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  ctrl = pr_ctrls_alloc();
  res = pr_ctrls_flush_response(ctrl);
  fail_unless(res == 0, "Failed to flush ctrl with no responses: %s",
    strerror(errno));

  mark_point();
  res = pr_ctrls_add_response(ctrl, "%s", "foo");
  fail_unless(res == 0, "Failed to add ctrl response: %s", strerror(errno));
  res = pr_ctrls_flush_response(ctrl);
  fail_unless(res < 0, "Failed to handle ctrl with no client");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  mark_point();
  cl = pcalloc(p, sizeof(pr_ctrls_cl_t));
  cl->cl_fd = devnull_fd();
  if (cl->cl_fd < 0) {
    return;
  }

  ctrl->ctrls_cl = cl;
  res = pr_ctrls_flush_response(ctrl);
  fail_unless(res == 0, "Failed to flush ctrl responses: %s", strerror(errno));

  mark_point();
  (void) close(cl->cl_fd);
  res = pr_ctrls_flush_response(ctrl);
  fail_unless(res < 0, "Failed to handle bad fd");
  fail_unless(errno == EBADF, "Expected EBADF (%d), got %s (%d)", EBADF,
    strerror(errno), errno);
}
END_TEST

START_TEST (ctrls_parse_msg_test) {
  int res;
  char *msg, **msgargv = NULL;
  unsigned int msgargc = 0;

  mark_point();
  res = pr_ctrls_parse_msg(NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_ctrls_parse_msg(p, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null msg");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  msg = "foo 'bar' baz";
  res = pr_ctrls_parse_msg(p, msg, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null msgargc");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  msg = "foo 'bar' baz";
  res = pr_ctrls_parse_msg(p, msg, &msgargc, NULL);
  fail_unless(res < 0, "Failed to handle null msgargv");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  msg = pstrdup(p, "foo 'Bar' BAZ");
  res = pr_ctrls_parse_msg(p, msg, &msgargc, &msgargv);
  fail_unless(res == 0, "Failed to parse msg '%s': %s", msg, strerror(errno));
  fail_unless(msgargc == 3, "Expected msgargc 3, got %u", msgargc);
  fail_unless(msgargv != NULL, "Expected msgargv, got null");
  fail_unless(strcmp(msgargv[0], "foo") == 0,
    "Expected 'foo', got '%s'", msgargv[0]);
  fail_unless(strcmp(msgargv[1], "'Bar'") == 0,
    "Expected 'Bar', got '%s'", msgargv[1]);
  fail_unless(strcmp(msgargv[2], "BAZ") == 0,
    "Expected 'BAZ', got '%s'", msgargv[2]);
  mark_point();
  msg = pstrdup(p, "foo\'s 'Bar\\\'s' BAZ");
  res = pr_ctrls_parse_msg(p, msg, &msgargc, &msgargv);
  fail_unless(res == 0, "Failed to parse msg '%s': %s", msg, strerror(errno));
  fail_unless(msgargc == 3, "Expected msgargc 3, got %u", msgargc);
  fail_unless(msgargv != NULL, "Expected msgargv, got null");
  fail_unless(strcmp(msgargv[0], "foo's") == 0,
    "Expected 'foo's', got '%s'", msgargv[0]);
  fail_unless(strcmp(msgargv[1], "'Bar\\\'s'") == 0,
    "Expected 'Bar\\\'s', got '%s'", msgargv[1]);
  fail_unless(strcmp(msgargv[2], "BAZ") == 0,
    "Expected 'BAZ', got '%s'", msgargv[2]);

  mark_point();
  msg = pstrdup(p, "foo 'Bar' BAZ");
  res = pr_ctrls_parse_msg(p, msg, &msgargc, &msgargv);
  fail_unless(res == 0, "Failed to parse msg '%s': %s", msg, strerror(errno));
  fail_unless(msgargc == 3, "Expected msgargc 3, got %u", msgargc);
  fail_unless(msgargv != NULL, "Expected msgargv, got null");
  fail_unless(strcmp(msgargv[0], "foo") == 0,
    "Expected 'foo', got '%s'", msgargv[0]);
  fail_unless(strcmp(msgargv[1], "'Bar'") == 0,
    "Expected 'Bar', got '%s'", msgargv[1]);
  fail_unless(strcmp(msgargv[2], "BAZ") == 0,
    "Expected 'BAZ', got '%s'", msgargv[2]);

  mark_point();
  msg = pstrdup(p, "foo \"Bar\\\'s\" BAZ");
  res = pr_ctrls_parse_msg(p, msg, &msgargc, &msgargv);
  fail_unless(res == 0, "Failed to parse msg '%s': %s", msg, strerror(errno));
  fail_unless(msgargc == 3, "Expected msgargc 3, got %u", msgargc);
  fail_unless(msgargv != NULL, "Expected msgargv, got null");
  fail_unless(strcmp(msgargv[0], "foo") == 0,
    "Expected 'foo', got '%s'", msgargv[0]);
  fail_unless(strcmp(msgargv[1], "Bar's") == 0,
    "Expected 'Bar's', got '%s'", msgargv[1]);
  fail_unless(strcmp(msgargv[2], "BAZ") == 0,
    "Expected 'BAZ', got '%s'", msgargv[2]);
}
END_TEST

START_TEST (ctrls_recv_request_invalid_test) {
  int fd, res, status;
  unsigned int nreqargs, actionlen;
  char *action;
  pr_ctrls_cl_t *cl;

  mark_point();
  res = pr_ctrls_recv_request(NULL);
  fail_unless(res < 0, "Failed to handle null client");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  cl = pcalloc(p, sizeof(pr_ctrls_cl_t));
  res = pr_ctrls_recv_request(cl);
  fail_unless(res < 0, "Failed to handle client without ctrls list");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  cl->cl_ctrls = make_array(p, 0, sizeof(pr_ctrls_t *));
  cl->cl_fd = -1;
  res = pr_ctrls_recv_request(cl);
  fail_unless(res < 0, "Failed to handle client without fd");
  fail_unless(errno == EBADF, "Expected EBADF (%d), got %s (%d)", EBADF,
    strerror(errno), errno);

  mark_point();
  fd = tmpfile_fd();
  if (fd < 0) {
    return;
  }

  cl->cl_fd = fd;
  (void) close(cl->cl_fd);
  res = pr_ctrls_recv_request(cl);
  fail_unless(res < 0, "Failed to handle client with bad fd");
  fail_unless(errno == EBADF, "Expected EBADF (%d), got %s (%d)", EBADF,
    strerror(errno), errno);

  mark_point();
  fd = tmpfile_fd();
  if (fd < 0) {
    return;
  }

  cl->cl_fd = fd;
  write(fd, "a", 1);
  rewind_fd(fd);
  res = pr_ctrls_recv_request(cl);
  fail_unless(res < 0, "Failed to handle invalid status (too short)");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  fd = reset_fd(fd);
  if (fd < 0) {
    return;
  }
  cl->cl_fd = fd;

  mark_point();
  status = 0;
  write(fd, &status, sizeof(status));
  write(fd, "a", 1);
  rewind_fd(fd);
  res = pr_ctrls_recv_request(cl);
  fail_unless(res < 0, "Failed to handle invalid nreqargs (too short)");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  fd = reset_fd(fd);
  if (fd < 0) {
    return;
  }
  cl->cl_fd = fd;

  mark_point();
  nreqargs = 100;
  write(fd, &status, sizeof(status));
  write(fd, &nreqargs, sizeof(nreqargs));
  rewind_fd(fd);
  res = pr_ctrls_recv_request(cl);
  fail_unless(res < 0, "Failed to handle invalid nreqargs (too many)");
  fail_unless(errno == ENOMEM, "Expected ENOMEM (%d), got %s (%d)", ENOMEM,
    strerror(errno), errno);

  fd = reset_fd(fd);
  if (fd < 0) {
    return;
  }
  cl->cl_fd = fd;

  mark_point();
  nreqargs = 1;
  write(fd, &status, sizeof(status));
  write(fd, &nreqargs, sizeof(nreqargs));
  write(fd, "a", 1);
  rewind_fd(fd);
  res = pr_ctrls_recv_request(cl);
  fail_unless(res < 0, "Failed to handle invalid actionlen (too short)");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  fd = reset_fd(fd);
  if (fd < 0) {
    return;
  }
  cl->cl_fd = fd;

  mark_point();
  actionlen = 256;
  write(fd, &status, sizeof(status));
  write(fd, &nreqargs, sizeof(nreqargs));
  write(fd, &actionlen, sizeof(actionlen));
  rewind_fd(fd);
  res = pr_ctrls_recv_request(cl);
  fail_unless(res < 0, "Failed to handle invalid actionlen (too long)");
  fail_unless(errno == ENOMEM, "Expected ENOMEM (%d), got %s (%d)", ENOMEM,
    strerror(errno), errno);

  fd = reset_fd(fd);
  if (fd < 0) {
    return;
  }
  cl->cl_fd = fd;

  mark_point();
  actionlen = 4;
  write(fd, &status, sizeof(status));
  write(fd, &nreqargs, sizeof(nreqargs));
  write(fd, &actionlen, sizeof(actionlen));
  write(fd, "a", 1);
  rewind_fd(fd);
  res = pr_ctrls_recv_request(cl);
  fail_unless(res < 0, "Failed to handle invalid reqarg (too short)");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  fd = reset_fd(fd);
  if (fd < 0) {
    return;
  }
  cl->cl_fd = fd;

  mark_point();
  action = "test";
  actionlen = strlen(action);
  write(fd, &status, sizeof(status));
  write(fd, &nreqargs, sizeof(nreqargs));
  write(fd, &actionlen, sizeof(actionlen));
  write(fd, action, actionlen);
  rewind_fd(fd);
  res = pr_ctrls_recv_request(cl);
  fail_unless(res < 0, "Failed to handle unknown action");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  (void) close(fd);
}
END_TEST

START_TEST (ctrls_recv_request_actions_test) {
  int fd, res, status;
  unsigned int nreqargs, actionlen, reqarglen;
  const char *action, *desc, *reqarg;
  pr_ctrls_cl_t *cl;
  pr_ctrls_t *ctrl;
  module m;

  mark_point();
  m.name = "test";
  action = "test";
  desc = "desc";
  res = pr_ctrls_register(&m, action, desc, ctrls_test_cb);
  fail_unless(res >= 0, "Failed to register ctrls action: %s", strerror(errno));

  mark_point();
  fd = tmpfile_fd();
  if (fd < 0) {
    return;
  }

  cl = pcalloc(p, sizeof(pr_ctrls_cl_t));
  cl->cl_ctrls = make_array(p, 0, sizeof(pr_ctrls_t *));
  cl->cl_fd = fd;

  status = 0;
  nreqargs = 1;
  actionlen = strlen(action);
  write(fd, &status, sizeof(status));
  write(fd, &nreqargs, sizeof(nreqargs));
  write(fd, &actionlen, sizeof(actionlen));
  write(fd, action, actionlen);
  rewind_fd(fd);
  res = pr_ctrls_recv_request(cl);
  fail_unless(res == 0, "Failed to handle known action: %s", strerror(errno));
  fail_unless(cl->cl_ctrls->nelts == 1, "Expected 1 ctrl, got %d",
    cl->cl_ctrls->nelts);
  ctrl = ((pr_ctrls_t **) cl->cl_ctrls->elts)[0];
  fail_unless(ctrl->ctrls_flags & PR_CTRLS_REQUESTED,
    "Expected PR_CTRLS_REQUESTED flag, got %lu", ctrl->ctrls_flags);
  fail_unless(ctrl->ctrls_cb_args == NULL,
    "Expected no callback args, got %p", ctrl->ctrls_cb_args);

  mark_point();
  fd = reset_fd(fd);
  if (fd < 0) {
    return;
  }
  clear_array(cl->cl_ctrls);
  cl->cl_fd = fd;

  nreqargs = 2;
  write(fd, &status, sizeof(status));
  write(fd, &nreqargs, sizeof(nreqargs));
  write(fd, &actionlen, sizeof(actionlen));
  write(fd, action, actionlen);
  write(fd, "a", 1);
  rewind_fd(fd);
  res = pr_ctrls_recv_request(cl);
  fail_unless(res == 0, "Failed to handle too-short reqarglen: %s",
    strerror(errno));
  fail_unless(cl->cl_ctrls->nelts == 1, "Expected 1 ctrl, got %d",
    cl->cl_ctrls->nelts);
  ctrl = ((pr_ctrls_t **) cl->cl_ctrls->elts)[0];
  fail_unless(ctrl->ctrls_flags & PR_CTRLS_REQUESTED,
    "Expected PR_CTRLS_REQUESTED flag, got %lu", ctrl->ctrls_flags);
  fail_unless(ctrl->ctrls_cb_args == NULL,
    "Expected no callback args, got %p", ctrl->ctrls_cb_args);

  mark_point();
  fd = reset_fd(fd);
  if (fd < 0) {
    return;
  }
  clear_array(cl->cl_ctrls);
  cl->cl_fd = fd;

  reqarglen = 0;
  write(fd, &status, sizeof(status));
  write(fd, &nreqargs, sizeof(nreqargs));
  write(fd, &actionlen, sizeof(actionlen));
  write(fd, action, actionlen);
  write(fd, &reqarglen, sizeof(reqarglen));
  rewind_fd(fd);
  res = pr_ctrls_recv_request(cl);
  fail_unless(res == 0, "Failed to handle zero-length reqarg: %s",
    strerror(errno));
  fail_unless(cl->cl_ctrls->nelts == 1, "Expected 1 ctrl, got %d",
    cl->cl_ctrls->nelts);
  ctrl = ((pr_ctrls_t **) cl->cl_ctrls->elts)[0];
  fail_unless(ctrl->ctrls_flags & PR_CTRLS_REQUESTED,
    "Expected PR_CTRLS_REQUESTED flag, got %lu", ctrl->ctrls_flags);
  fail_unless(ctrl->ctrls_cb_args == NULL,
    "Expected no callback args, got %p", ctrl->ctrls_cb_args);

  mark_point();
  fd = reset_fd(fd);
  if (fd < 0) {
    return;
  }
  clear_array(cl->cl_ctrls);
  cl->cl_fd = fd;

  reqarglen = 500;
  write(fd, &status, sizeof(status));
  write(fd, &nreqargs, sizeof(nreqargs));
  write(fd, &actionlen, sizeof(actionlen));
  write(fd, action, actionlen);
  write(fd, &reqarglen, sizeof(reqarglen));
  rewind_fd(fd);
  res = pr_ctrls_recv_request(cl);
  fail_unless(res < 0, "Failed to handle too-long reqarg");
  fail_unless(errno == ENOMEM, "Expected ENOMEM (%d), got %s (%d)", ENOMEM,
    strerror(errno), errno);
  fail_unless(cl->cl_ctrls->nelts == 0, "Expected 0 ctrl, got %d",
    cl->cl_ctrls->nelts);

  mark_point();
  fd = reset_fd(fd);
  if (fd < 0) {
    return;
  }
  clear_array(cl->cl_ctrls);
  cl->cl_fd = fd;

  reqarglen = 4;
  write(fd, &status, sizeof(status));
  write(fd, &nreqargs, sizeof(nreqargs));
  write(fd, &actionlen, sizeof(actionlen));
  write(fd, action, actionlen);
  write(fd, &reqarglen, sizeof(reqarglen));
  write(fd, "a", 1);
  rewind_fd(fd);
  res = pr_ctrls_recv_request(cl);
  fail_unless(res == 0, "Failed to handle truncated reqarg: %s",
    strerror(errno));
  fail_unless(cl->cl_ctrls->nelts == 1, "Expected 1 ctrl, got %d",
    cl->cl_ctrls->nelts);
  ctrl = ((pr_ctrls_t **) cl->cl_ctrls->elts)[0];
  fail_unless(ctrl->ctrls_flags & PR_CTRLS_REQUESTED,
    "Expected PR_CTRLS_REQUESTED flag, got %lu", ctrl->ctrls_flags);
  fail_unless(ctrl->ctrls_cb_args == NULL,
    "Expected no callback args, got %p", ctrl->ctrls_cb_args);

  mark_point();
  fd = reset_fd(fd);
  if (fd < 0) {
    return;
  }
  clear_array(cl->cl_ctrls);
  cl->cl_fd = fd;

  reqarg = "next";
  reqarglen = strlen(reqarg);
  write(fd, &status, sizeof(status));
  write(fd, &nreqargs, sizeof(nreqargs));
  write(fd, &actionlen, sizeof(actionlen));
  write(fd, action, actionlen);
  write(fd, &reqarglen, sizeof(reqarglen));
  write(fd, reqarg, reqarglen);
  rewind_fd(fd);
  res = pr_ctrls_recv_request(cl);
  fail_unless(res == 0, "Failed to handle truncated reqarg: %s",
    strerror(errno));
  fail_unless(cl->cl_ctrls->nelts == 1, "Expected 1 ctrl, got %d",
    cl->cl_ctrls->nelts);
  ctrl = ((pr_ctrls_t **) cl->cl_ctrls->elts)[0];
  fail_unless(ctrl->ctrls_flags & PR_CTRLS_REQUESTED,
    "Expected PR_CTRLS_REQUESTED flag, got %lu", ctrl->ctrls_flags);
  fail_unless(ctrl->ctrls_cb_args != NULL, "Expected callback args, got NULL");
  fail_unless(ctrl->ctrls_cb_args->nelts == 1,
    "Expected 1 callback arg, got %d", ctrl->ctrls_cb_args->nelts);

  /* next_action present */

  mark_point();
  res = pr_ctrls_register(&m, action, desc, ctrls_test2_cb);
  fail_unless(res >= 0, "Failed to register ctrls action: %s", strerror(errno));

  mark_point();
  fd = reset_fd(fd);
  if (fd < 0) {
    return;
  }
  clear_array(cl->cl_ctrls);
  cl->cl_fd = fd;

  reqarg = "next";
  reqarglen = strlen(reqarg);
  write(fd, &status, sizeof(status));
  write(fd, &nreqargs, sizeof(nreqargs));
  write(fd, &actionlen, sizeof(actionlen));
  write(fd, action, actionlen);
  write(fd, &reqarglen, sizeof(reqarglen));
  write(fd, reqarg, reqarglen);
  rewind_fd(fd);
  res = pr_ctrls_recv_request(cl);
  fail_unless(res == 0, "Failed to handle truncated reqarg: %s",
    strerror(errno));
  fail_unless(cl->cl_ctrls->nelts == 2, "Expected 2 ctrl, got %d",
    cl->cl_ctrls->nelts);

  ctrl = ((pr_ctrls_t **) cl->cl_ctrls->elts)[0];
  fail_unless(ctrl->ctrls_flags & PR_CTRLS_REQUESTED,
    "Expected PR_CTRLS_REQUESTED flag, got %lu", ctrl->ctrls_flags);
  fail_unless(ctrl->ctrls_cb_args != NULL, "Expected callback args, got NULL");
  fail_unless(ctrl->ctrls_cb_args->nelts == 1,
    "Expected 1 callback arg, got %d", ctrl->ctrls_cb_args->nelts);

  ctrl = ((pr_ctrls_t **) cl->cl_ctrls->elts)[1];
  fail_unless(ctrl->ctrls_flags & PR_CTRLS_REQUESTED,
    "Expected PR_CTRLS_REQUESTED flag, got %lu", ctrl->ctrls_flags);
  fail_unless(ctrl->ctrls_cb_args != NULL, "Expected callback args, got NULL");
  fail_unless(ctrl->ctrls_cb_args->nelts == 1,
    "Expected 1 callback arg, got %d", ctrl->ctrls_cb_args->nelts);

  (void) pr_ctrls_unregister(&m, action);
  (void) close(fd);
}
END_TEST

START_TEST (ctrls_recv_response_test) {
  int fd, res, retval, status;
  unsigned int respargc, resparglen;
  char *resparg, **respargv = NULL, *resp;

  mark_point();
  res = pr_ctrls_recv_response(NULL, -1, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_ctrls_recv_response(p, -1, NULL, NULL);
  fail_unless(res < 0, "Failed to handle invalid fd");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_ctrls_recv_response(p, 0, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null status");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  fd = devnull_fd();
  if (fd < 0) {
    return;
  }

  errno = 0;
  res = pr_ctrls_recv_response(p, fd, &status, &respargv);
  fail_unless(res < 0, "Failed to handle no response");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
  (void) close(fd);

  mark_point();
  fd = tmpfile_fd();
  if (fd < 0) {
    return;
  }

  write(fd, "a", 1);
  rewind_fd(fd);
  res = pr_ctrls_recv_response(p, fd, &status, &respargv);
  fail_unless(res < 0, "Failed to handle truncated status");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  mark_point();
  fd = reset_fd(fd);
  if (fd < 0) {
    return;
  }

  retval = 1;
  write(fd, &retval, sizeof(retval));
  write(fd, "a", 1);
  rewind_fd(fd);
  res = pr_ctrls_recv_response(p, fd, &status, &respargv);
  fail_unless(res < 0, "Failed to handle truncated nrespargc");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  mark_point();
  fd = reset_fd(fd);
  if (fd < 0) {
    return;
  }

  respargc = 2000;
  write(fd, &retval, sizeof(retval));
  write(fd, &respargc, sizeof(respargc));
  rewind_fd(fd);
  res = pr_ctrls_recv_response(p, fd, &status, &respargv);
  fail_unless(res < 0, "Failed to handle too-many respargc");
  fail_unless(errno == ENOMEM, "Expected ENOMEM (%d), got %s (%d)", ENOMEM,
    strerror(errno), errno);

  mark_point();
  fd = reset_fd(fd);
  if (fd < 0) {
    return;
  }

  respargc = 1;
  write(fd, &retval, sizeof(retval));
  write(fd, &respargc, sizeof(respargc));
  write(fd, "a", 1);
  rewind_fd(fd);
  res = pr_ctrls_recv_response(p, fd, &status, &respargv);
  fail_unless(res < 0, "Failed to handle truncated resparglen");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  mark_point();
  fd = reset_fd(fd);
  if (fd < 0) {
    return;
  }

  resparglen = (PR_TUNABLE_BUFFER_SIZE * 10);
  write(fd, &retval, sizeof(retval));
  write(fd, &respargc, sizeof(respargc));
  write(fd, &resparglen, sizeof(resparglen));
  rewind_fd(fd);
  res = pr_ctrls_recv_response(p, fd, &status, &respargv);
  fail_unless(res < 0, "Failed to handle too-long resparglen");
  fail_unless(errno == ENOMEM, "Expected ENOMEM (%d), got %s (%d)", ENOMEM,
    strerror(errno), errno);

  mark_point();
  fd = reset_fd(fd);
  if (fd < 0) {
    return;
  }

  resparglen = 4;
  write(fd, &retval, sizeof(retval));
  write(fd, &respargc, sizeof(respargc));
  write(fd, &resparglen, sizeof(resparglen));
  write(fd, "a", 1);
  rewind_fd(fd);
  res = pr_ctrls_recv_response(p, fd, &status, &respargv);
  fail_unless(res < 0, "Failed to handle truncated resparg");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  mark_point();
  fd = reset_fd(fd);
  if (fd < 0) {
    return;
  }

  resparg = "foobarbaz";
  resparglen = strlen(resparg);
  write(fd, &retval, sizeof(retval));
  write(fd, &respargc, sizeof(respargc));
  write(fd, &resparglen, sizeof(resparglen));
  write(fd, resparg, resparglen);
  rewind_fd(fd);
  res = pr_ctrls_recv_response(p, fd, &status, &respargv);
  fail_unless((unsigned int) res == respargc, "Failed to receive response: %s",
    strerror(errno));
  fail_unless(status == retval, "Expected %d, got %d", retval, status);
  fail_unless(respargv != NULL, "Expected respargv, got NULL");
  resp = respargv[0];
  fail_unless(strcmp(resp, resparg) == 0, "Expected '%s', got '%s'",
    resparg, resp);

  (void) close(fd);
}
END_TEST

START_TEST (ctrls_issock_unix_test) {
  int res;
  mode_t mode;

  mark_point();
  mode = 0;
  res = pr_ctrls_issock_unix(mode);
  fail_unless(res < 0, "Failed to handle invalid mode");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

#if defined(S_ISFIFO)
  mark_point();
  mode = 0;
  mode |= S_IFIFO;
  res = pr_ctrls_issock_unix(mode);
  if (res < 0) {
    fail_if(errno != ENOSYS, "Did not expect ENOSYS (%d)", ENOSYS);
  }
#endif /* S_ISFIFO */

#if defined(S_ISSOCK)
  mark_point();
  mode = 0;
  mode |= S_IFSOCK;
  res = pr_ctrls_issock_unix(mode);
  if (res < 0) {
    fail_if(errno != ENOSYS, "Did not expect ENOSYS (%d)", ENOSYS);
  }
#endif /* S_ISSOCK */
}
END_TEST

START_TEST (ctrls_get_registered_actions_test) {
  int res;
  pr_ctrls_t *ctrl;
  const char *action, *desc;
  module m;

  mark_point();
  res = pr_get_registered_actions(NULL, 0);
  fail_unless(res < 0, "Failed to handle null ctrl");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  ctrl = pr_ctrls_alloc();
  res = pr_get_registered_actions(ctrl, 0);
  fail_unless(res == 0, "Failed to handle lack of registered actions: %s",
    strerror(errno));

  mark_point();
  pr_block_ctrls();
  res = pr_get_registered_actions(ctrl, 0);
  fail_unless(res < 0, "Failed to handle blocked actions");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
  pr_unblock_ctrls();

  mark_point();
  action = "test";
  desc = "desc";
  res = pr_ctrls_register(NULL, action, desc, ctrls_test_cb);
  fail_unless(res >= 0, "Failed to register ctrls action: %s", strerror(errno));

  m.name = "test";
  res = pr_ctrls_register(&m, action, desc, ctrls_test_cb);
  fail_unless(res >= 0, "Failed to register ctrls action: %s", strerror(errno));

  mark_point();
  res = pr_get_registered_actions(ctrl, 0);
  fail_unless(res == 0, "Failed to handle invalid flags: %s", strerror(errno));

  mark_point();
  res = pr_get_registered_actions(ctrl, CTRLS_GET_ACTION_ALL);
  fail_unless(res == 2, "Failed to handle GET_ACTION_ALL flag: %s",
    strerror(errno));

  mark_point();
  res = pr_get_registered_actions(ctrl, CTRLS_GET_ACTION_ENABLED);
  fail_unless(res == 2, "Failed to handle GET_ACTION_ENABLED flag: %s",
    strerror(errno));

  mark_point();
  res = pr_get_registered_actions(ctrl, CTRLS_GET_DESC);
  fail_unless(res == 2, "Failed to handle GET_DESC flag: %s", strerror(errno));

  mark_point();
  res = pr_ctrls_unregister(NULL, action);
  fail_unless(res == 0, "Failed to unregister ctrls action: %s",
    strerror(errno));
}
END_TEST

START_TEST (ctrls_set_registered_actions_test) {
  int res;
  const char *action, *desc;

  mark_point();
  res = pr_set_registered_actions(NULL, NULL, FALSE, 0);
  fail_unless(res < 0, "Failed to handle no registered actions");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  mark_point();
  res = pr_set_registered_actions(NULL, NULL, FALSE, 24);
  fail_unless(res < 0, "Failed to handle invalid flag");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  action = "test";
  desc = "desc";
  res = pr_ctrls_register(NULL, action, desc, ctrls_test_cb);
  fail_unless(res >= 0, "Failed to register ctrls action: %s", strerror(errno));

  mark_point();
  res = pr_set_registered_actions(NULL, NULL, FALSE, 0);
  fail_unless(res == 0, "Failed to handle no registered actions: %s",
    strerror(errno));

  mark_point();
  pr_block_ctrls();
  res = pr_set_registered_actions(NULL, NULL, FALSE, 0);
  fail_unless(res < 0, "Failed to handle blocked actions");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
  pr_unblock_ctrls();

  mark_point();
  res = pr_set_registered_actions(NULL, action, FALSE, 0);
  fail_unless(res == 0, "Failed to handle action '%s': %s", action,
    strerror(errno));

  mark_point();
  res = pr_set_registered_actions(NULL, "all", FALSE, 0);
  fail_unless(res == 0, "Failed to handle action 'all': %s", strerror(errno));

  mark_point();
  res = pr_ctrls_unregister(NULL, action);
  fail_unless(res == 0, "Failed to unregister ctrls action: %s",
    strerror(errno));
}
END_TEST

START_TEST (ctrls_check_actions_test) {
  int res;
  const char *action, *desc;

  mark_point();
  res = pr_ctrls_check_actions();
  fail_unless(res == 0, "Failed to handle no registered actions: %s",
    strerror(errno));

  mark_point();
  action = "test";
  desc = "desc";
  res = pr_ctrls_register(NULL, action, desc, ctrls_test_cb);
  fail_unless(res >= 0, "Failed to register ctrls action: %s", strerror(errno));

  mark_point();
  res = pr_ctrls_check_actions();
  fail_unless(res == 0, "Failed to handle no registered actions: %s",
    strerror(errno));

  /* Register a duplicate action name, then check. */

  mark_point();
  res = pr_ctrls_register(NULL, action, desc, ctrls_test_cb);
  fail_unless(res >= 0, "Failed to register ctrls action: %s", strerror(errno));

  mark_point();
  res = pr_ctrls_check_actions();
  fail_unless(res == 0, "Failed to handle registered actions: %s",
    strerror(errno));

  mark_point();
  res = pr_set_registered_actions(NULL, action, FALSE, PR_CTRLS_ACT_SOLITARY);
  fail_unless(res == 0, "Failed to set SOLITARY action flag: %s",
    strerror(errno));

  mark_point();
  res = pr_ctrls_check_actions();
  fail_unless(res < 0, "Failed to handle duplicate SOLITARY actions");
  fail_unless(errno == EEXIST, "Expected EEXIST (%d), got %s (%d)", EEXIST,
    strerror(errno), errno);

  mark_point();
  res = pr_ctrls_unregister(NULL, action);
  fail_unless(res == 0, "Failed to unregister ctrls action: %s",
    strerror(errno));
}
END_TEST

START_TEST (ctrls_run_ctrls_test) {
  int fd, res, status;
  unsigned int nreqargs, actionlen, reqarglen;
  const char *action, *desc, *reqarg;
  pr_ctrls_cl_t *cl;
  pr_ctrls_t *ctrl;
  module m, m2;
  time_t now;

  mark_point();
  res = pr_run_ctrls(NULL, NULL);
  fail_unless(res == 0, "Failed to run ctrls: %s", strerror(errno));

  mark_point();
  pr_block_ctrls();
  res = pr_run_ctrls(NULL, NULL);
  fail_unless(res < 0, "Failed to handle blocked ctrls");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
  pr_unblock_ctrls();

  mark_point();
  action = "test";
  desc = "desc";
  m.name = "test";
  m2.name = "test2";
  res = pr_ctrls_register(&m, action, desc, ctrls_test_cb);
  fail_unless(res >= 0, "Failed to register ctrls action: %s", strerror(errno));

  mark_point();
  res = pr_run_ctrls(NULL, NULL);
  fail_unless(res == 0, "Failed to run ctrls: %s", strerror(errno));

  mark_point();
  res = pr_run_ctrls(&m2, NULL);
  fail_unless(res == 0, "Failed to run ctrls: %s", strerror(errno));

  mark_point();
  res = pr_run_ctrls(&m, NULL);
  fail_unless(res == 0, "Failed to run ctrls: %s", strerror(errno));

  /* XXX TODO More test cases to fill in here. */
  /* Note that pr_run_ctrls() makes a lot of assumptions about recv_response,
   * recv_request having been called previously.  Not great.  How to deal
   * with that?
   */

  mark_point();
  fd = tmpfile_fd();
  if (fd < 0) {
    return;
  }

  cl = pcalloc(p, sizeof(pr_ctrls_cl_t));
  cl->cl_ctrls = make_array(p, 0, sizeof(pr_ctrls_t *));
  cl->cl_fd = fd;

  status = 0;
  nreqargs = 2;
  actionlen = strlen(action);
  reqarg = "FOO";
  reqarglen = strlen(reqarg);
  write(fd, &status, sizeof(status));
  write(fd, &nreqargs, sizeof(nreqargs));
  write(fd, &actionlen, sizeof(actionlen));
  write(fd, action, actionlen);
  write(fd, &reqarglen, sizeof(reqarglen));
  write(fd, reqarg, reqarglen);
  rewind_fd(fd);
  res = pr_ctrls_recv_request(cl);
  fail_unless(res == 0, "Failed to handle known action: %s", strerror(errno));
  fail_unless(cl->cl_ctrls->nelts == 1, "Expected 1 ctrl, got %d",
    cl->cl_ctrls->nelts);
  ctrl = ((pr_ctrls_t **) cl->cl_ctrls->elts)[0];

  mark_point();
  res = pr_run_ctrls(&m2, NULL);
  fail_unless(res == 0, "Failed to run ctrls: %s", strerror(errno));

  mark_point();
  res = pr_run_ctrls(&m, NULL);
  fail_unless(res == 0, "Failed to run ctrls: %s", strerror(errno));

  mark_point();
  cl->cl_flags = PR_CTRLS_CL_HAVEREQ;
  ctrl->ctrls_flags |= PR_CTRLS_ACT_DISABLED;
  res = pr_run_ctrls(&m, NULL);
  fail_unless(res == 0, "Failed to run ctrls: %s", strerror(errno));

  mark_point();
  cl->cl_flags = PR_CTRLS_CL_HAVEREQ;
  ctrl->ctrls_flags &= ~PR_CTRLS_ACT_DISABLED;
  ctrl->ctrls_flags &= ~PR_CTRLS_REQUESTED;
  res = pr_run_ctrls(&m, NULL);
  fail_unless(res == 0, "Failed to run ctrls: %s", strerror(errno));

  mark_point();
  cl->cl_flags = PR_CTRLS_CL_HAVEREQ;
  ctrl->ctrls_flags |= PR_CTRLS_REQUESTED;
  now = time(NULL);
  ctrl->ctrls_when = now + 10;
  res = pr_run_ctrls(&m, NULL);
  fail_unless(res == 0, "Failed to run ctrls: %s", strerror(errno));

  mark_point();
  cl->cl_flags = PR_CTRLS_CL_HAVEREQ;
  ctrl->ctrls_flags &= PR_CTRLS_PENDING;
  ctrl->ctrls_flags |= PR_CTRLS_REQUESTED;
  ctrl->ctrls_when = now - 10;
  res = pr_run_ctrls(&m, "test2");
  fail_unless(res == 0, "Failed to run ctrls: %s", strerror(errno));

  mark_point();
  cl->cl_flags = PR_CTRLS_CL_HAVEREQ;
  ctrl->ctrls_flags |= PR_CTRLS_REQUESTED;
  res = pr_run_ctrls(&m, "test");
  fail_unless(res == 0, "Failed to run ctrls: %s", strerror(errno));

  mark_point();
  res = pr_ctrls_unregister(NULL, action);
  fail_unless(res == 0, "Failed to unregister ctrls action: %s",
    strerror(errno));

  (void) close(fd);
}
END_TEST

START_TEST (ctrls_reset_ctrls_test) {
  int res;
  const char *action, *desc;

  mark_point();
  res = pr_ctrls_reset();
  fail_unless(res == 0, "Failed to reset ctrls: %s", strerror(errno));

  mark_point();
  action = "test";
  desc = "desc";
  res = pr_ctrls_register(NULL, action, desc, ctrls_test_cb);
  fail_unless(res >= 0, "Failed to register ctrls action: %s", strerror(errno));

  mark_point();
  res = pr_ctrls_reset();
  fail_unless(res == 0, "Failed to reset ctrls: %s", strerror(errno));

  mark_point();
  res = pr_ctrls_unregister(NULL, action);
  fail_unless(res == 0, "Failed to unregister ctrls action: %s",
    strerror(errno));
}
END_TEST

START_TEST (ctrls_accept_test) {
  int fd, res;

  mark_point();
  res = pr_ctrls_accept(-1, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle bad fd");
  fail_unless(errno == EBADF, "Expected EBADF (%d), got %s (%d)", EBADF,
    strerror(errno), errno);

  mark_point();
  fd = devnull_fd();
  if (fd < 0) {
    return;
  }

  res = pr_ctrls_accept(fd, NULL, NULL, NULL, 5);
  fail_unless(res < 0, "Failed to handle no clients");
  fail_unless(errno = ENOENT, "Expected ENOENT (%d), got %d (%d)", ENOENT,
    strerror(errno), errno);

  (void) close(fd);
}
END_TEST

START_TEST (ctrls_connect_test) {
  int fd, res;
  const char *socket_path;

  mark_point();
  res = pr_ctrls_connect(NULL);
  fail_unless(res < 0, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  socket_path = "/tmp/foo.sock";
  res = pr_ctrls_connect(socket_path);
  fail_unless(res < 0, "Failed to handle nonexistent socket path");
  fail_unless(errno == ECONNREFUSED || errno == ENOENT,
    "Expected ECONNREFUSED (%d) or ENOENT (%d), got %s (%d)", ECONNREFUSED,
    ENOENT, strerror(errno), errno);

  mark_point();
  fd = listen_unix(socket_path);
  if (fd < 0) {
    return;
  }

  res = pr_ctrls_connect(socket_path);
  fail_unless(res >= 0, "Failed to connect to local socket: %s",
    strerror(errno));

  (void) close(res);
  (void) close(fd);
  (void) unlink(socket_path);
}
END_TEST

START_TEST (ctrls_check_group_acl_test) {
  int res;
  gid_t gid;
  ctrls_group_acl_t *group_acl;

  mark_point();
  res = pr_ctrls_check_group_acl(0, NULL);
  fail_unless(res < 0, "Failed to handle null acl");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  group_acl = pcalloc(p, sizeof(ctrls_group_acl_t));
  res = pr_ctrls_check_group_acl(0, group_acl);
  fail_unless(res == TRUE, "Expected TRUE, got %d", res);

  mark_point();
  group_acl->allow = TRUE;
  res = pr_ctrls_check_group_acl(0, group_acl);
  fail_unless(res == FALSE, "Expected FALSE, got %d", res);

  mark_point();
  group_acl->ngids = 1;
  res = pr_ctrls_check_group_acl(0, group_acl);
  fail_unless(res == group_acl->allow, "Expected %d, got %d",
    group_acl->allow, res);

  group_acl->allow = FALSE;
  res = pr_ctrls_check_group_acl(0, group_acl);
  fail_unless(res == group_acl->allow, "Expected %d, got %d",
    group_acl->allow, res);

  mark_point();
  gid = 1;
  group_acl->allow = TRUE;
  group_acl->gids = palloc(p, sizeof(gid_t) * 2);
  ((gid_t *) group_acl->gids)[0] = gid;
  res = pr_ctrls_check_group_acl(0, group_acl);
  fail_unless(res == FALSE, "Expected FALSE, got %d", res);

  res = pr_ctrls_check_group_acl(gid, group_acl);
  fail_unless(res == TRUE, "Expected TRUE, got %d", res);
}
END_TEST

START_TEST (ctrls_check_user_acl_test) {
  int res;
  uid_t uid;
  ctrls_user_acl_t *user_acl;

  mark_point();
  res = pr_ctrls_check_user_acl(0, NULL);
  fail_unless(res < 0, "Failed to handle null acl");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  user_acl = pcalloc(p, sizeof(ctrls_user_acl_t));
  res = pr_ctrls_check_user_acl(0, user_acl);
  fail_unless(res == TRUE, "Expected TRUE, got %d", res);

  mark_point();
  user_acl->allow = TRUE;
  res = pr_ctrls_check_user_acl(0, user_acl);
  fail_unless(res == FALSE, "Expected FALSE, got %d", res);

  mark_point();
  user_acl->nuids = 1;
  res = pr_ctrls_check_user_acl(0, user_acl);
  fail_unless(res == user_acl->allow, "Expected %d, got %d",
    user_acl->allow, res);

  user_acl->allow = FALSE;
  res = pr_ctrls_check_user_acl(0, user_acl);
  fail_unless(res == user_acl->allow, "Expected %d, got %d",
    user_acl->allow, res);

  mark_point();
  uid = 1;
  user_acl->allow = TRUE;
  user_acl->uids = palloc(p, sizeof(uid_t) * 2);
  ((uid_t *) user_acl->uids)[0] = uid;
  res = pr_ctrls_check_user_acl(0, user_acl);
  fail_unless(res == FALSE, "Expected FALSE, got %d", res);

  res = pr_ctrls_check_user_acl(uid, user_acl);
  fail_unless(res == TRUE, "Expected TRUE, got %d", res);
}
END_TEST

START_TEST (ctrls_init_acl_test) {
  int res;
  ctrls_acl_t *acl;

  mark_point();
  res = pr_ctrls_init_acl(NULL);
  fail_unless(res < 0, "Failed to handle null acl");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  acl = pcalloc(p, sizeof(ctrls_acl_t));
  res = pr_ctrls_init_acl(acl);
  fail_unless(res == 0, "Failed to init acl: %s", strerror(errno));
}
END_TEST

static int test_action_cb(pr_ctrls_t *ctl, int reqargc, char **reqargv) {
  return 0;
}

START_TEST (ctrls_check_acl_test) {
  int res;
  pr_ctrls_t *ctrl;
  pr_ctrls_cl_t *cl;
  ctrls_acl_t *acl;
  const char *action;
  ctrls_acttab_t acttab[] = {
    { "test", "desc", NULL, test_action_cb },
    { NULL, NULL, NULL, NULL }
  };

  mark_point();
  res = pr_ctrls_check_acl(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null ctrl");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  ctrl = pr_ctrls_alloc();
  res = pr_ctrls_check_acl(ctrl, NULL, NULL);
  fail_unless(res < 0, "Failed to handle ctrl without client");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  cl = pcalloc(p, sizeof(pr_ctrls_cl_t));
  cl->cl_uid = cl->cl_gid = 1;
  ctrl->ctrls_cl = cl;
  res = pr_ctrls_check_acl(ctrl, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null acttab");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_ctrls_check_acl(ctrl, acttab, NULL);
  fail_unless(res < 0, "Failed to handle null action");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  action = "foobar";
  res = pr_ctrls_check_acl(ctrl, acttab, action);
  fail_unless(res == TRUE, "Expected TRUE, got %d", res);

  mark_point();
  action = "test";
  res = pr_ctrls_check_acl(ctrl, acttab, action);
  fail_unless(res == FALSE, "Expected FALSE, got %d", res);

  mark_point();
  acl = pcalloc(p, sizeof(ctrls_acl_t));
  res = pr_ctrls_init_acl(acl);
  acttab[0].act_acl = acl;
  res = pr_ctrls_check_acl(ctrl, acttab, action);
  fail_unless(res == FALSE, "Expected FALSE, got %d", res);

  mark_point();
  acl->acl_groups.ngids = 1;
  res = pr_ctrls_check_acl(ctrl, acttab, action);
  fail_unless(res == TRUE, "Expected TRUE, got %d", res);

  acl->acl_users.nuids = 1;
  res = pr_ctrls_check_acl(ctrl, acttab, action);
  fail_unless(res == TRUE, "Expected TRUE, got %d", res);
}
END_TEST

START_TEST (ctrls_parse_acl_test) {
  char **res;
  const char *names;

  mark_point();
  res = pr_ctrls_parse_acl(NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_ctrls_parse_acl(p, NULL);
  fail_unless(res == NULL, "Failed to handle null ACL text");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  names = "foo";
  res = pr_ctrls_parse_acl(p, names);
  fail_unless(res != NULL, "Failed to parse ACL '%s': %s", names,
    strerror(errno));
  fail_unless(strcmp(res[0], "foo") == 0, "Expected 'foo', got '%s'", res[0]);
  fail_unless(res[1] == NULL, "Expected NULL, got %p", res[1]);

  mark_point();
  names = "foo,'Bar',BAZ";
  res = pr_ctrls_parse_acl(p, names);
  fail_unless(res != NULL, "Failed to parse ACL '%s': %s", names,
    strerror(errno));
  fail_unless(strcmp(res[0], "foo") == 0, "Expected 'foo', got '%s'", res[0]);
  fail_unless(strcmp(res[1], "'Bar'") == 0, "Expected 'Bar', got '%s'", res[1]);
  fail_unless(strcmp(res[2], "BAZ") == 0, "Expected 'BAZ', got '%s'", res[2]);
  fail_unless(res[3] == NULL, "Expected NULL, got %p", res[3]);
}
END_TEST

START_TEST (ctrls_set_group_acl_test) {
  int res;
  ctrls_group_acl_t *group_acl;
  const char *allow;
  char *grouplist;

  mark_point();
  res = pr_ctrls_set_group_acl(NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_ctrls_set_group_acl(p, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null group_acl");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  group_acl = pcalloc(p, sizeof(ctrls_group_acl_t));
  res = pr_ctrls_set_group_acl(p, group_acl, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null allow");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  allow = "allow";
  res = pr_ctrls_set_group_acl(p, group_acl, allow, NULL);
  fail_unless(res < 0, "Failed to handle null grouplist");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  grouplist = "foo,bar,baz,wheel";
  res = pr_ctrls_set_group_acl(p, group_acl, allow, grouplist);
  fail_unless(res == 0, "Failed to set group acl: %s", strerror(errno));
  fail_unless(group_acl->allow == TRUE, "Expected TRUE, got %d",
    group_acl->allow);
  /* Note that we expect zero here, because of name/GID lookup failures. */
  fail_unless(group_acl->ngids == 0, "Expected 0, got %d",
    group_acl->ngids);
  fail_unless(group_acl->gids != NULL, "Got NULL unexpectedly");

  mark_point();
  group_acl = pcalloc(p, sizeof(ctrls_group_acl_t));
  allow = "deny";
  grouplist = "foo,*";
  res = pr_ctrls_set_group_acl(p, group_acl, allow, grouplist);
  fail_unless(res == 0, "Failed to set group acl: %s", strerror(errno));
  fail_unless(group_acl->allow == FALSE, "Expected FALSE, got %d",
    group_acl->allow);
  fail_unless(group_acl->ngids == 1, "Expected 1, got %d",
    group_acl->ngids);
  fail_unless(group_acl->gids == NULL, "Expected NULL, got %p",
    group_acl->gids);
}
END_TEST

START_TEST (ctrls_set_user_acl_test) {
  int res;
  ctrls_user_acl_t *user_acl;
  const char *allow;
  char *userlist;

  mark_point();
  res = pr_ctrls_set_user_acl(NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_ctrls_set_user_acl(p, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null user_acl");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  user_acl = pcalloc(p, sizeof(ctrls_user_acl_t));
  res = pr_ctrls_set_user_acl(p, user_acl, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null allow");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  allow = "allow";
  res = pr_ctrls_set_user_acl(p, user_acl, allow, NULL);
  fail_unless(res < 0, "Failed to handle null userlist");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  userlist = "foo,bar,baz,root";
  res = pr_ctrls_set_user_acl(p, user_acl, allow, userlist);
  fail_unless(res == 0, "Failed to set user acl: %s", strerror(errno));
  fail_unless(user_acl->allow == TRUE, "Expected TRUE, got %d",
    user_acl->allow);
  /* Note that we expect zero here, because of name/UID lookup failures. */
  fail_unless(user_acl->nuids == 0, "Expected 0, got %d", user_acl->nuids);
  fail_unless(user_acl->uids != NULL, "Got NULL unexpectedly");

  mark_point();
  user_acl = pcalloc(p, sizeof(ctrls_user_acl_t));
  allow = "deny";
  userlist = "foo,*";
  res = pr_ctrls_set_user_acl(p, user_acl, allow, userlist);
  fail_unless(res == 0, "Failed to set user acl: %s", strerror(errno));
  fail_unless(user_acl->allow == FALSE, "Expected FALSE, got %d",
    user_acl->allow);
  fail_unless(user_acl->nuids == 1, "Expected 1, got %d", user_acl->nuids);
  fail_unless(user_acl->uids == NULL, "Expected NULL, got %p",
    user_acl->uids);
}
END_TEST

START_TEST (ctrls_set_module_acls_test) {
  char *res, *list;
  const char *allow, *type;
  ctrls_acl_t *acl;
  char *good_actions[] = { "test", NULL };
  char *bad_actions[] = { "bar", "baz", NULL };
  char *all_actions[] = { "all", NULL };
  ctrls_acttab_t acttab[] = {
    { "test", "desc", NULL, test_action_cb },
    { NULL, NULL, NULL, NULL }
  };

  mark_point();
  res = pr_ctrls_set_module_acls(NULL, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null acttab");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_ctrls_set_module_acls(acttab, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null acl_pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_ctrls_set_module_acls(acttab, p, NULL, NULL, NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null actions");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_ctrls_set_module_acls(acttab, p, good_actions, NULL, NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null allow");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  allow = "allow";
  res = pr_ctrls_set_module_acls(acttab, p, good_actions, allow, NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null type");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  type = "test";
  res = pr_ctrls_set_module_acls(acttab, p, good_actions, allow, type, NULL);
  fail_unless(res == NULL, "Failed to handle null list");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  list = "foo,bar,baz";
  res = pr_ctrls_set_module_acls(acttab, p, bad_actions, allow, type, list);
  fail_unless(res == NULL, "Failed to handle invalid type '%s'", type);
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  type = "user";
  res = pr_ctrls_set_module_acls(acttab, p, bad_actions, allow, type, list);
  fail_unless(res != NULL, "Failed to handle invalid action");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
  fail_unless(strcmp(res, "bar") == 0, "Expected 'bar', got '%s'", res);

  mark_point();
  acl = pcalloc(p, sizeof(ctrls_acl_t));
  fail_unless(pr_ctrls_init_acl(acl) == 0,
    "Failed to initialize acl: %s", strerror(errno));

  acttab[0].act_acl = acl;
  type = "group";
  res = pr_ctrls_set_module_acls(acttab, p, good_actions, allow, type, list);
  fail_unless(res == NULL, "Failed to handle good action: %s", strerror(errno));

  mark_point();
  type = "user";
  res = pr_ctrls_set_module_acls(acttab, p, good_actions, allow, type, list);
  fail_unless(res == NULL, "Failed to handle good action: %s", strerror(errno));

  mark_point();
  res = pr_ctrls_set_module_acls(acttab, p, all_actions, allow, type, list);
  fail_unless(res == NULL, "Failed to handle all actions: %s", strerror(errno));
}
END_TEST

START_TEST (ctrls_set_module_acls2_test) {
  int res;
  char *list;
  const char *allow, *type, *bad_action = NULL;
  ctrls_acl_t *acl;
  char *good_actions[] = { "test", NULL };
  char *bad_actions[] = { "bar", "baz", NULL };
  char *all_actions[] = { "all", NULL };
  ctrls_acttab_t acttab[] = {
    { "test", "desc", NULL, test_action_cb },
    { NULL, NULL, NULL, NULL }
  };

  mark_point();
  res = pr_ctrls_set_module_acls2(NULL, NULL, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null acttab");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_ctrls_set_module_acls2(acttab, NULL, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null acl_pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_ctrls_set_module_acls2(acttab, p, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null actions");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_ctrls_set_module_acls2(acttab, p, good_actions, NULL, NULL, NULL,
    NULL);
  fail_unless(res < 0, "Failed to handle null allow");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  allow = "allow";
  res = pr_ctrls_set_module_acls2(acttab, p, good_actions, allow, NULL, NULL,
    NULL);
  fail_unless(res < 0, "Failed to handle null type");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  type = "test";
  res = pr_ctrls_set_module_acls2(acttab, p, good_actions, allow, type, NULL,
    NULL);
  fail_unless(res < 0, "Failed to handle null list");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  list = "foo,bar,baz";
  res = pr_ctrls_set_module_acls2(acttab, p, bad_actions, allow, type, list,
    NULL);
  fail_unless(res < 0, "Failed to handle null bad_action");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_ctrls_set_module_acls2(acttab, p, bad_actions, allow, type, list,
    &bad_action);
  fail_unless(res < 0, "Failed to handle invalid type '%s'", type);
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  type = "user";
  res = pr_ctrls_set_module_acls2(acttab, p, bad_actions, allow, type, list,
    &bad_action);
  fail_unless(res < 0, "Failed to handle invalid action");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
  fail_unless(strcmp(bad_action, "bar") == 0,
    "Expected 'bar', got '%s'", bad_action);

  mark_point();
  acl = pcalloc(p, sizeof(ctrls_acl_t));
  fail_unless(pr_ctrls_init_acl(acl) == 0,
    "Failed to initialize acl: %s", strerror(errno));

  acttab[0].act_acl = acl;
  type = "group";
  res = pr_ctrls_set_module_acls2(acttab, p, good_actions, allow, type, list,
    &bad_action);
  fail_unless(res == 0, "Failed to handle good action: %s", strerror(errno));

  mark_point();
  type = "user";
  res = pr_ctrls_set_module_acls2(acttab, p, good_actions, allow, type, list,
    &bad_action);
  fail_unless(res == 0, "Failed to handle good action: %s", strerror(errno));

  mark_point();
  res = pr_ctrls_set_module_acls2(acttab, p, all_actions, allow, type, list,
    &bad_action);
  fail_unless(res == 0, "Failed to handle all actions: %s", strerror(errno));
}
END_TEST

START_TEST (ctrls_unregister_module_actions_test) {
  char *res;
  char *good_actions[] = { "test", NULL };
  char *bad_actions[] = { "bar", "baz", NULL };
  ctrls_acl_t *acl;
  ctrls_acttab_t acttab[] = {
    { "test", "desc", NULL, test_action_cb },
    { NULL, NULL, NULL, NULL }
  };
  module m;

  mark_point();
  res = pr_ctrls_unregister_module_actions(NULL, NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null acttab");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_ctrls_unregister_module_actions(acttab, NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null actions");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_ctrls_unregister_module_actions(acttab, good_actions, NULL);
  fail_unless(res == NULL, "Failed to handle null module");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  m.name = "test";
  res = pr_ctrls_unregister_module_actions(acttab, bad_actions, &m);
  fail_unless(res != NULL, "Failed to handle invalid action");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
  fail_unless(strcmp(res, "bar") == 0, "Expected 'bar', got '%s'", res);

  mark_point();
  acl = pcalloc(p, sizeof(ctrls_acl_t));
  fail_unless(pr_ctrls_init_acl(acl) == 0,
    "Failed to initialize acl: %s", strerror(errno));
  acttab[0].act_acl = acl;
  res = pr_ctrls_unregister_module_actions(acttab, good_actions, &m);
  fail_unless(res == NULL, "Failed to handle valid action: %s",
    strerror(errno));
}
END_TEST

START_TEST (ctrls_unregister_module_actions2_test) {
  int res;
  const char *bad_action = NULL;
  char *good_actions[] = { "test", NULL };
  char *bad_actions[] = { "bar", "baz", NULL };
  ctrls_acl_t *acl;
  ctrls_acttab_t acttab[] = {
    { "test", "desc", NULL, test_action_cb },
    { NULL, NULL, NULL, NULL }
  };
  module m;

  mark_point();
  res = pr_ctrls_unregister_module_actions2(NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null acttab");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_ctrls_unregister_module_actions2(acttab, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null actions");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_ctrls_unregister_module_actions2(acttab, good_actions, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null module");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  m.name = "test";
  res = pr_ctrls_unregister_module_actions2(acttab, bad_actions, &m, NULL);
  fail_unless(res < 0, "Failed to handle null bad_action");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_ctrls_unregister_module_actions2(acttab, bad_actions, &m,
    &bad_action);
  fail_unless(res < 0, "Failed to handle invalid action");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
  fail_unless(bad_action != NULL, "Expected bad_action, got NULL");
  fail_unless(strcmp(bad_action, "bar") == 0,
    "Expected 'bar', got '%s'", bad_action);

  mark_point();
  acl = pcalloc(p, sizeof(ctrls_acl_t));
  fail_unless(pr_ctrls_init_acl(acl) == 0,
    "Failed to initialize acl: %s", strerror(errno));
  acttab[0].act_acl = acl;
  res = pr_ctrls_unregister_module_actions2(acttab, good_actions, &m,
    &bad_action);
  fail_unless(res == 0, "Failed to handle valid action: %s", strerror(errno));
}
END_TEST

START_TEST (ctrls_set_logfd_test) {
  int fd, res;

  mark_point();
  fd = 0;
  res = pr_ctrls_set_logfd(fd);
  fail_unless(res == 0, "Failed to set ctrls log fd %d: %s", fd,
     strerror(errno));

  mark_point();
  fd = -1;
  res = pr_ctrls_set_logfd(fd);
  fail_unless(res == 0, "Failed to set ctrls log fd %d: %s", fd,
     strerror(errno));
}
END_TEST

START_TEST (ctrls_log_test) {
  int fd, res;

  mark_point();
  fd = -1;
  pr_ctrls_set_logfd(fd);
  res = pr_ctrls_log(NULL, NULL);
  fail_unless(res == 0, "Failed to handle bad logfd: %s", strerror(errno));

  mark_point();
  fd = devnull_fd();
  if (fd < 0) {
    return;
  }

  pr_ctrls_set_logfd(fd);
  res = pr_ctrls_log(NULL, NULL);
  fail_unless(res == 0, "Failed to handle bad module_version: %s",
    strerror(errno));

  mark_point();
  res = pr_ctrls_log("test", NULL);
  fail_unless(res == 0, "Failed to handle null fmt: %s", strerror(errno));

  mark_point();
  res = pr_ctrls_log("test", "%s", "foo bar baz");
  fail_unless(res == 0, "Failed to handle valid fmt: %s", strerror(errno));

  (void) close(fd);
}
END_TEST

#endif /* PR_USE_CTRLS */

Suite *tests_get_ctrls_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("ctrls");
  testcase = tcase_create("base");

#if defined(PR_USE_CTRLS)
  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, ctrls_alloc_free_test);
  tcase_add_test(testcase, ctrls_unregister_test);
  tcase_add_test(testcase, ctrls_register_test);
  tcase_add_test(testcase, ctrls_add_arg_test);
  tcase_add_test(testcase, ctrls_add_response_test);
  tcase_add_test(testcase, ctrls_copy_args_test);
  tcase_add_test(testcase, ctrls_copy_resps_test);
  tcase_add_test(testcase, ctrls_send_msg_test);
  tcase_add_test(testcase, ctrls_flush_response_test);
  tcase_add_test(testcase, ctrls_parse_msg_test);
  tcase_add_test(testcase, ctrls_recv_request_invalid_test);
  tcase_add_test(testcase, ctrls_recv_request_actions_test);
  tcase_add_test(testcase, ctrls_recv_response_test);
  tcase_add_test(testcase, ctrls_issock_unix_test);
  tcase_add_test(testcase, ctrls_get_registered_actions_test);
  tcase_add_test(testcase, ctrls_set_registered_actions_test);
  tcase_add_test(testcase, ctrls_check_actions_test);
  tcase_add_test(testcase, ctrls_run_ctrls_test);
  tcase_add_test(testcase, ctrls_reset_ctrls_test);
  tcase_add_test(testcase, ctrls_accept_test);
  tcase_add_test(testcase, ctrls_connect_test);

  /* mod_ctrls */
  tcase_add_test(testcase, ctrls_check_group_acl_test);
  tcase_add_test(testcase, ctrls_check_user_acl_test);
  tcase_add_test(testcase, ctrls_init_acl_test);
  tcase_add_test(testcase, ctrls_check_acl_test);
  tcase_add_test(testcase, ctrls_parse_acl_test);
  tcase_add_test(testcase, ctrls_set_group_acl_test);
  tcase_add_test(testcase, ctrls_set_user_acl_test);
  tcase_add_test(testcase, ctrls_set_module_acls_test);
  tcase_add_test(testcase, ctrls_set_module_acls2_test);
  tcase_add_test(testcase, ctrls_unregister_module_actions_test);
  tcase_add_test(testcase, ctrls_unregister_module_actions2_test);
  tcase_add_test(testcase, ctrls_set_logfd_test);
  tcase_add_test(testcase, ctrls_log_test);
#endif /* PR_USE_CTRLS */

  suite_add_tcase(suite, testcase);
  return suite;
}
