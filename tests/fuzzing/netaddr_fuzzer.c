/*
 * ProFTPD - FTP server fuzzing testsuite
 * Copyright (c) 2026 The ProFTPD Project team
 *
 * Fuzz the network address and network ACL parsing used by the FTP
 * control connection (PORT/EPRT arguments), <Directory>/<Limit> and
 * <Class> access control (Allow/Deny/AllowClass), and the mod_ifsession
 * and mod_wrap evaluations:
 *
 *   - pr_netaddr_get_addr2() with PR_NETADDR_GET_ADDR_FL_EXCL_DNS (the
 *     no-DNS path used for IP literals; DNS lookups are deliberately
 *     excluded so the harness stays hermetic),
 *   - pr_netaddr_is_v4()/pr_netaddr_is_v6() dotted-quad and IPv6
 *     literal validation (including the non-canonical forms proftpd
 *     accepts),
 *   - pr_netacl_create()/pr_netacl_match() ACL string parsing and
 *     matching (negated, wildcard, CIDR and v4-mapped-v6 forms),
 *   - formatting round-trips via pr_netaddr_get_ipstr().
 *
 * Threat model: ACL/address strings are attacker-influenceable via
 * server configuration, per-directory .ftpaccess files and (for the
 * address side) FTP command arguments; a parsing or matching bug here
 * is an ACL-bypass or memory-safety issue.
 *
 * Input layout: byte 0 selects lookup flags, followed by two
 * NUL-bounded strings; each string is resolved, validated and turned
 * into an ACL, and each ACL is matched against both resolved
 * addresses (cross-matching covers mixed v4/v6 decisions).
 */

#include <stdint.h>
#include <string.h>
#include "conf.h"
#include "netaddr.h"
#include "netacl.h"

#define FUZZ_MAX_STR 512

static pool *fuzz_pool = NULL;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  pool *p;
  char s1[FUZZ_MAX_STR + 1], s2[FUZZ_MAX_STR + 1];
  const pr_netaddr_t *a1, *a2;
  pr_netacl_t *acl1, *acl2;
  size_t len1, len2;
  unsigned int flags;

  if (size < 4) {
    return 0;
  }

  if (fuzz_pool == NULL) {
    fuzz_pool = permanent_pool = make_sub_pool(NULL);
    init_netaddr();
  }

  /* DNS-free lookups; the cache is bypassed so that long fuzzing runs
   * cannot grow the (daemon-lifetime) netaddr cache unboundedly.
   */
  flags = PR_NETADDR_GET_ADDR_FL_EXCL_DNS|PR_NETADDR_GET_ADDR_FL_EXCL_CACHE;

  /* Two NUL-bounded strings; both copied to bound NUL-less inputs. */
  len1 = strnlen((const char *) &data[1], size - 1);
  if (len1 > FUZZ_MAX_STR || 1 + len1 + 1 > size) {
    return 0;
  }
  memcpy(s1, &data[1], len1);
  s1[len1] = '\0';

  len2 = strnlen((const char *) &data[1 + len1 + 1], size - (1 + len1 + 1));
  if (len2 > FUZZ_MAX_STR) {
    return 0;
  }
  memcpy(s2, &data[1 + len1 + 1], len2);
  s2[len2] = '\0';

  p = make_sub_pool(fuzz_pool);

  a1 = pr_netaddr_get_addr2(p, s1, NULL, flags);
  a2 = pr_netaddr_get_addr2(p, s2, NULL, flags);

  (void) pr_netaddr_is_v4(s1);
  (void) pr_netaddr_is_v6(s1);
  (void) pr_netaddr_is_v4(s2);
  (void) pr_netaddr_is_v6(s2);

  if (a1 != NULL) {
    (void) pr_netaddr_get_ipstr(a1);
    (void) pr_netaddr_get_family(a1);
    (void) pr_netaddr_is_v4mappedv6(a1);
  }
  if (a2 != NULL) {
    (void) pr_netaddr_get_ipstr(a2);
    (void) pr_netaddr_get_family(a2);
    (void) pr_netaddr_is_v4mappedv6(a2);
  }

  acl1 = pr_netacl_create(p, s1);
  acl2 = pr_netacl_create(p, s2);

  if (acl1 != NULL) {
    if (a1 != NULL) {
      (void) pr_netacl_match(acl1, a1);
    }
    if (a2 != NULL) {
      (void) pr_netacl_match(acl1, a2);
    }
  }
  if (acl2 != NULL) {
    if (a1 != NULL) {
      (void) pr_netacl_match(acl2, a1);
    }
    if (a2 != NULL) {
      (void) pr_netacl_match(acl2, a2);
    }
  }

  destroy_pool(p);
  return 0;
}
