/*
 * ProFTPD - FTP server fuzzing testsuite
 * Copyright (c) 2026 The ProFTPD Project team
 *
 * Fuzz the bundled fnmatch(3) implementation (lib/pr_fnmatch.c,
 * lib/pr_fnmatch_loop.c) used for glob-style matching of user-supplied
 * paths and patterns (LIST/NLST arguments, PermissionMatch and
 * HideFiles directives, .ftpaccess-driven matching).
 *
 * Threat model: the *pattern* side comes from server configuration
 * (including per-directory .ftpaccess files writable by FTP users) and
 * the *string* side is fully attacker-controlled (paths sent in FTP
 * commands). Both sides reach pr_fnmatch() verbatim, so the matcher
 * must be robust against arbitrary bytes and bracket/escape/extmatch
 * constructs on either side.
 *
 * Input layout: byte 0 selects a combination of PR_FNM_* flags,
 * followed by the NUL-terminated pattern, followed by the string
 * (rest of the input, NUL-bounded).
 */

#include <stdint.h>
#include <string.h>
#include "conf.h"
#include "base.h"

#define FUZZ_MAX_LEN 2048

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char pattern[FUZZ_MAX_LEN + 1], string[FUZZ_MAX_LEN + 1];
  size_t pattern_len, string_len;
  int flags;

  if (size < 4 || size > 2 * FUZZ_MAX_LEN) {
    return 0;
  }

  /* Flag matrix over the documented PR_FNM_* bits. */
  flags = 0;
  if (data[0] & (1 << 0)) {
    flags |= PR_FNM_PATHNAME;
  }
  if (data[0] & (1 << 1)) {
    flags |= PR_FNM_NOESCAPE;
  }
  if (data[0] & (1 << 2)) {
    flags |= PR_FNM_PERIOD;
  }
  if (data[0] & (1 << 3)) {
    flags |= PR_FNM_LEADING_DIR;
  }
  if (data[0] & (1 << 4)) {
    flags |= PR_FNM_CASEFOLD;
  }
  if (data[0] & (1 << 5)) {
    flags |= PR_FNM_EXTMATCH;
  }

  /* NUL-bounded pattern followed by the string; both are copied so
   * NUL-less inputs can never run past the buffer.
   */
  pattern_len = strnlen((const char *) &data[1], size - 1);
  if (pattern_len > FUZZ_MAX_LEN) {
    return 0;
  }
  memcpy(pattern, &data[1], pattern_len);
  pattern[pattern_len] = '\0';

  if (1 + pattern_len + 1 > size) {
    return 0;
  }
  string_len = size - (1 + pattern_len + 1);
  if (string_len > FUZZ_MAX_LEN) {
    string_len = FUZZ_MAX_LEN;
  }
  memcpy(string, &data[1 + pattern_len + 1], string_len);
  string[string_len] = '\0';

  (void) pr_fnmatch(pattern, string, flags);

  return 0;
}
