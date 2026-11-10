/*
 * ProFTPD - FTP server fuzzing testsuite
 * Copyright (c) 2026 The ProFTPD Project team
 *
 * Fuzz the Controls API request parser (src/ctrls.c): a framed JSON
 * message (uint32 length + text) is received over the local control
 * socket and parsed by pr_ctrls_recv_request(), which decodes the JSON,
 * looks up the requested action and copies the request arguments into
 * the matching control objects. The socket data is untrusted input for
 * any local client allowed to connect to the Controls socket.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL,
 * and to distribute the resulting executable, without including the
 * source code for OpenSSL in the source distribution.
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

#include "pool.h"
#include "ctrls.h"

static int fuzz_ctrls_cb(pr_ctrls_t *ctrl, int reqargc, char **reqargv) {
  (void) reqargv;
  pr_ctrls_add_response(ctrl, "fuzz callback invoked (argc %d)", reqargc);
  return 0;
}

static int ctrls_initialized = 0;

static void ensure_ctrls_init(void) {
  if (ctrls_initialized != 0) {
    return;
  }

  /* Initializes the Controls pools/lists and the (unused) listening socket;
   * the socket path is only touched once. */
  init_ctrls2("/tmp/proftpd-ctrls-fuzz.sock");
  pr_ctrls_register(NULL, "fuzzaction", "fuzz target action", fuzz_ctrls_cb);
  pr_ctrls_register(NULL, "get", "get all actions", fuzz_ctrls_cb);
  pr_ctrls_register(NULL, "dump", "dump state", fuzz_ctrls_cb);

  ctrls_initialized = 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  pool *cl_pool = NULL;
  pr_ctrls_cl_t *cl = NULL;
  uint32_t msglen;
  int sp[2] = { -1, -1 };

  /* CTRLS_MAX_REQ_SIZE cap in ctrls.c; longer inputs are rejected before
   * any parsing happens, so do not waste the fuzzer's time on them.
   * (Harness cap, not a product change.) */
  if (size > 1024) {
    size = 1024;
  }

  ensure_ctrls_init();

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) < 0) {
    return 0;
  }

  cl_pool = make_sub_pool(NULL);
  if (cl_pool == NULL) {
    close(sp[0]);
    close(sp[1]);
    return 0;
  }

  cl = pcalloc(cl_pool, sizeof(pr_ctrls_cl_t));
  cl->cl_pool = cl_pool;
  cl->cl_fd = sp[0];
  cl->cl_ctrls = make_array(cl_pool, 2, sizeof(pr_ctrls_t *));

  /* Frame the fuzz data exactly as a Controls client would: uint32 message
   * length followed by the JSON text. */
  msglen = (uint32_t) size;
  if (write(sp[1], &msglen, sizeof(msglen)) == sizeof(msglen) &&
      (size == 0 || write(sp[1], data, size) == (ssize_t) size)) {
    pr_ctrls_recv_request(cl);
  }

  close(sp[1]);
  close(sp[0]);
  destroy_pool(cl_pool);

  /* Clear any request state accumulated on the persistent action objects. */
  pr_ctrls_reset();

  return 0;
}
