/*
 * ProFTPD - mod_sftp SSH certs
 * Copyright (c) 2026 TJ Saunders
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 */

#include "mod_sftp.h"
#include "auth.h"
#include "msg.h"
#include "keys.h"
#include "certs.h"

#define SFTP_CERT_MAX_SIGN_DATA_SIZE	(1024 * 1024)
#define SFTP_CERT_MAX_PRINCIPALS	256

static const char *trace_channel = "ssh2";

uint32_t sftp_certs_read_nonce(pool *p, unsigned char *cert_data,
    uint32_t cert_datalen, const char *cert_algo, unsigned char **nonce) {
  uint32_t nonce_len = 0, res, len = 0;
  unsigned char *buf = NULL;

  if (p == NULL ||
      cert_data == NULL ||
      cert_datalen == 0 ||
      cert_algo == NULL) {
    errno = EINVAL;
    return 0;
  }
 
  res = sftp_msg_read_int2(p, &cert_data, &cert_datalen, &nonce_len);
  if (res == 0) {
    pr_trace_msg(trace_channel, 19,
      "error reading nonce length from %s certificate", cert_algo);
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error reading %s certificate: invalid/unsupported nonce format",
      cert_algo);
    return 0;
  }
  len += res;

  if (nonce_len < 16) {
    pr_trace_msg(trace_channel, 19,
      "nonce length (%lu bytes) from %s certificate is too short",
      (unsigned long) nonce_len, cert_algo);
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error reading %s certificate: invalid/unsupported nonce format",
      cert_algo);
    return 0;
  }

  if (nonce != NULL) {
    *nonce = palloc(p, nonce_len);
    buf = *nonce;

  } else {
    buf = palloc(p, nonce_len);
  }

  res = sftp_msg_read_data2(p, &cert_data, &cert_datalen, nonce_len, &buf);
  if (res == 0) {
    pr_trace_msg(trace_channel, 19,
      "error reading nonce data from %s certificate", cert_algo);
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error reading %s certificate: invalid/unsupported nonce format",
      cert_algo);
    return 0;
  }
  len += res;

  return len;
}

static const char *get_cert_role_text(unsigned int cert_role) {
  const char *text;

  switch (cert_role) {
    case SFTP_SSH_CERT_TYPE_USER:
      text = "USER";
      break;

    case SFTP_SSH_CERT_TYPE_HOST:
      text = "HOST";
      break;

    default:
      text = "(unknown/unsupported)";
  }

  return text;
}

static array_header *parse_principals(pool *p,
    unsigned char *principal_data, uint32_t principal_datalen) {
  array_header *principals;
  pool *tmp_pool;

  principals = make_array(p, 1, sizeof(char *));

  while (principal_datalen != 0) {
    char *name;
    uint32_t len;

    pr_signals_handle();

    len = sftp_msg_read_string2(p, &principal_data, &principal_datalen, &name);
    if (len == 0) {
      return NULL;
    }

    *((char **) push_array(principals)) = pstrdup(p, name);
  }

  tmp_pool = make_sub_pool(p);
  pr_trace_msg(trace_channel, 19, "parsed principals: '%s'",
    pr_str_array_to_text(tmp_pool, principals, ","));
  destroy_pool(tmp_pool);

  return principals;
}

static pr_table_t *parse_critical_options(pool *p,
    unsigned char *critical_data, uint32_t critical_datalen) {
  pr_table_t *critical_options;
  int count;

  critical_options = pr_table_nalloc(p, 0, 2);

  while (critical_datalen != 0) {
    char *key = NULL, *val = NULL;
    uint32_t len = 0;
    size_t valsz = 0;

    pr_signals_handle();

    len = sftp_msg_read_string2(p, &critical_data, &critical_datalen, &key);
    if (len == 0) {
      return NULL;
    }

    len = sftp_msg_read_string2(p, &critical_data, &critical_datalen, &val);
    if (len == 0) {
      return NULL;
    }

    /* Note that the value length could legitimately be zero. */
    valsz = strlen(val);
    if (pr_table_add(critical_options, key, val, valsz) < 0) {
      pr_trace_msg(trace_channel, 7,
        "error adding critical option '%s' value (%lu bytes): %s", key,
        (unsigned long) valsz, strerror(errno));
    }
  }

  count = pr_table_count(critical_options);
  pr_trace_msg(trace_channel, 19, "parsed %d critical %s", count,
    count != 1 ? "options" : "option");

  return critical_options;
}

static pr_table_t *parse_extensions(pool *p,
    unsigned char *extension_data, uint32_t extension_datalen) {
  pr_table_t *extensions;
  int count;

  extensions = pr_table_nalloc(p, 0, 2);

  while (extension_datalen != 0) {
    char *key = NULL, *val = NULL;
    uint32_t len = 0;
    size_t valsz = 0;

    pr_signals_handle();

    len = sftp_msg_read_string2(p, &extension_data, &extension_datalen, &key);
    if (len == 0) {
      return NULL;
    }

    len = sftp_msg_read_string2(p, &extension_data, &extension_datalen, &val);
    if (len == 0) {
      return NULL;
    }

    valsz = strlen(val);
    if (pr_table_add(extensions, key, val, valsz) < 0) {
      pr_trace_msg(trace_channel, 7,
        "error adding extension '%s' value (%lu bytes): %s", key,
        (unsigned long) valsz, strerror(errno));
    }
  }

  count = pr_table_count(extensions);
  pr_trace_msg(trace_channel, 19, "parsed %d %s", count,
    count != 1 ? "extensions" : "extension");

  return extensions;
}

static void fmt_cert_time(pool *p, uint64_t ts, char *buf, size_t buflen) {
  struct tm *tm;

  tm = pr_localtime(p, (time_t *) &ts);
  if (tm == NULL) {
    sstrncpy(buf, "UNKNOWN", buflen);
    return;
  }

  strftime(buf, buflen, "%Y-%m-%dT%H:%M:%S", tm);
}

static int trace_cert_table(const void *key_data, size_t key_datasz,
    const void *value_data, size_t value_datasz, void *user_data) {

  /* This interface treats table keys/values are binary blobs.  We know,
   * a priori, that the table keys/values in question use text.  Thus a
   * value size of 1 indicates that the value is the empty string, i.e. a
   * single NUL byte.  We have a value to be traced only if the value size
   * is longer than 1, then.
   */

  if (value_datasz > 1) {
    pr_trace_msg(trace_channel, 9, "  %.*s: '%.*s' (%lu)", (int) key_datasz,
      (char *) key_data, (int) value_datasz, (char *) value_data,
      (unsigned long) value_datasz);

  } else {
    pr_trace_msg(trace_channel, 9, "  %.*s", (int) key_datasz,
      (char *) key_data);
  }

  return 0;
}

static void trace_cert(pool *p, struct sftp_cert *cert) {
  pool *tmp_pool;
  int critical_option_count = 0, extension_count = 0;
  char before_text[32], after_text[32], *principals_text;

  tmp_pool = make_sub_pool(p);

  if (cert->principals != NULL) {
    principals_text = pr_str_array_to_text(tmp_pool, cert->principals, ",");

  } else {
    principals_text = pstrdup(tmp_pool, "");
  }

  if (cert->critical_options != NULL) {
    critical_option_count = pr_table_count(cert->critical_options);
  }

  if (cert->extensions != NULL) {
    extension_count = pr_table_count(cert->extensions);
  }

  fmt_cert_time(tmp_pool, cert->valid_after_ts, after_text, sizeof(after_text));

  if (cert->valid_before_ts != UINT64_MAX) {
    fmt_cert_time(tmp_pool, cert->valid_before_ts, before_text,
      sizeof(before_text));

  } else {
    sstrncpy(before_text, "forever", sizeof(before_text));
  }

  pr_trace_msg(trace_channel, 9,
    "%s certificate: role = %s, serial = %lu, ID = '%s', nonce = (%lu bytes), "
    "validity = %s to %s, principals = '%s', %d critical %s, %d %s",
    cert->cert_algo, get_cert_role_text(cert->cert_role),
    (unsigned long) cert->serialno, cert->cert_id,
    (unsigned long) cert->nonce_len, after_text, before_text, principals_text,
    critical_option_count, critical_option_count != 1 ? "options" : "option",
    extension_count, extension_count != 1 ? "extensions" : "extension");

  if (cert->critical_options != NULL) {
    pr_trace_msg(trace_channel, 9, "%s certificate critical options:",
      cert->cert_algo);
    (void) pr_table_do(cert->critical_options, trace_cert_table, NULL,
      PR_TABLE_DO_FL_ALL);
  }

  if (cert->extensions != NULL) {
    pr_trace_msg(trace_channel, 9, "%s certificate extensions:",
      cert->cert_algo);
    (void) pr_table_do(cert->extensions, trace_cert_table, NULL,
      PR_TABLE_DO_FL_ALL);
  }

  destroy_pool(tmp_pool);
}

int sftp_certs_parse_cert(pool *p, unsigned char *cert_data,
    uint32_t cert_datalen, struct sftp_cert **cert) {
  unsigned char *buf, *buf2, *principal_data, *critical_data, *extension_data,
    *reserved_data, *signature_data;
  uint32_t buflen, buflen2, len, principal_datalen, critical_datalen,
    extension_datalen, reserved_datalen, signature_datalen, signed_datalen;
  char *cert_algo = NULL;
  pool *cert_pool;
  struct sftp_cert *res;
  enum sftp_key_type_e signature_pubkey_type;

  if (p == NULL ||
      cert_data == NULL ||
      cert_datalen == 0 ||
      cert == NULL) {
    errno = EINVAL;
    return -1;
  }

  cert_pool = make_sub_pool(p);
  pr_pool_tag(cert_pool, "SFTP SSH Cert Pool");
  res = pcalloc(cert_pool, sizeof(struct sftp_cert));
  res->cert_pool = cert_pool;

  /* Keep copies of the provided cert data pointers/lens, for now. */
  buf = cert_data;
  buflen = cert_datalen;

  /* Certificate algorithm */
  len = sftp_msg_read_string2(cert_pool, &cert_data, &cert_datalen, &cert_algo);
  if (len == 0) {
    int xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error reading certificate: invalid/unsupported certificate format");

    destroy_pool(res->cert_pool);
    errno = xerrno;
    return -1;
  }
  res->cert_algo = cert_algo;

  /* Nonce */
  len = sftp_certs_read_nonce(cert_pool, cert_data, cert_datalen, cert_algo,
    &(res->nonce));
  if (len == 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 9,
      "error reading nonce from %s certificate", cert_algo);
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error reading %s certificate: invalid/unsupported nonce format",
      cert_algo);

    destroy_pool(res->cert_pool);
    errno = xerrno;
    return -1;
  }
  res->nonce_len = len;

  /* Skip past the algorithm-specific public key fields to get to the SSH
   * certificate fields.
   */
  cert_data = buf;
  cert_datalen = buflen;
  len = sftp_keys_skip_pubkey_data(p, cert_data, cert_datalen);
  if (len == 0) {
    int xerrno = errno;

    destroy_pool(res->cert_pool);
    errno = xerrno;
    return -1;
  }

  cert_data += len;
  cert_datalen -= len;

  /* Serial number */
  len = sftp_msg_read_long2(cert_pool, &cert_data, &cert_datalen,
    &(res->serialno));
  if (len == 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 9,
      "unable to read %s certificate serial number", cert_algo);
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error reading certificate: invalid/unsupported certificate format");

    destroy_pool(res->cert_pool);
    errno = xerrno;
    return -1;
  }

  /* Certificate role/type */
  len = sftp_msg_read_int2(cert_pool, &cert_data, &cert_datalen,
    &(res->cert_role));
  if (len == 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 9, "unable to read %s certificate role/type",
      cert_algo);
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error reading certificate: invalid/unsupported certificate format");

    destroy_pool(res->cert_pool);
    errno = xerrno;
    return -1;
  }

  /* Certificate ID */
  len = sftp_msg_read_string2(cert_pool, &cert_data, &cert_datalen,
    (char **) &(res->cert_id));
  if (len == 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 9, "unable to read %s certificate ID",
      cert_algo);
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error reading certificate: invalid/unsupported certificate format");

    destroy_pool(res->cert_pool);
    errno = xerrno;
    return -1;
  }

  /* Principals */
  len = sftp_msg_read_int2(cert_pool, &cert_data, &cert_datalen,
    &principal_datalen);
  if (len == 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 9, "unable to read %s certificate principals",
      cert_algo);
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error reading certificate: invalid/unsupported certificate format");

    destroy_pool(res->cert_pool);
    errno = xerrno;
    return -1;
  }

  if (principal_datalen > 0) {
    len = sftp_msg_read_data2(cert_pool, &cert_data, &cert_datalen,
      principal_datalen, &principal_data);
    if (len == 0) {
      int xerrno = errno;

      pr_trace_msg(trace_channel, 9, "unable to read %s certificate principals",
        cert_algo);
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error reading certificate: invalid/unsupported certificate format");

      destroy_pool(res->cert_pool);
      errno = xerrno;
      return -1;
    }

    res->principals = parse_principals(cert_pool, principal_data,
      principal_datalen);
    if (res->principals == NULL) {
      int xerrno = errno;

      pr_trace_msg(trace_channel, 9,
        "unable to parse %s certificate principals", cert_algo);
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error reading certificate: invalid/unsupported certificate format");

      destroy_pool(res->cert_pool);
      errno = xerrno;
      return -1;
    }

    if (res->principals->nelts >= SFTP_CERT_MAX_PRINCIPALS) {
      int xerrno = EINVAL;

      pr_trace_msg(trace_channel, 9,
        "parsed %s certificate principal count (%d) exceeds maximum (%d)",
        cert_algo, res->principals->nelts, SFTP_CERT_MAX_PRINCIPALS);
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error reading certificate: invalid/unsupported certificate format");

      destroy_pool(res->cert_pool);
      errno = xerrno;
      return -1;
    }
  }

  /* Valid after */
  len = sftp_msg_read_long2(cert_pool, &cert_data, &cert_datalen,
    &(res->valid_after_ts));
  if (len == 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 9, "unable to read %s certificate valid after",
      cert_algo);
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error reading certificate: invalid/unsupported certificate format");

    destroy_pool(res->cert_pool);
    errno = xerrno;
    return -1;
  }

  /* Valid before */
  len = sftp_msg_read_long2(cert_pool, &cert_data, &cert_datalen,
    &(res->valid_before_ts));
  if (len == 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 9, "unable to read %s certificate valid before",
      cert_algo);
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error reading certificate: invalid/unsupported certificate format");

    destroy_pool(res->cert_pool);
    errno = xerrno;
    return -1;
  }

  /* Critical options.  Note that there may be legitimately no critical
   * options in a valid certificate.
   */
  len = sftp_msg_read_int2(cert_pool, &cert_data, &cert_datalen,
    &critical_datalen);
  if (len == 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 9,
      "unable to read %s certificate critical options", cert_algo);
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error reading certificate: invalid/unsupported certificate format");

    destroy_pool(res->cert_pool);
    errno = xerrno;
    return -1;
  }

  if (critical_datalen > 0) {
    len = sftp_msg_read_data2(cert_pool, &cert_data, &cert_datalen,
      critical_datalen, &critical_data);
    if (len == 0) {
      int xerrno = errno;

      pr_trace_msg(trace_channel, 9,
        "unable to read %s certificate critical options (%lu bytes)",
        cert_algo, (unsigned long) critical_datalen);
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error reading certificate: invalid/unsupported certificate format");

      destroy_pool(res->cert_pool);
      errno = xerrno;
      return -1;
    }

    res->critical_options = parse_critical_options(cert_pool, critical_data,
      critical_datalen);
    if (res->critical_options == NULL) {
      int xerrno = errno;

      pr_trace_msg(trace_channel, 9,
        "unable to parse %s certificate critical options", cert_algo);
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error reading certificate: invalid/unsupported certificate format");

      destroy_pool(res->cert_pool);
      errno = xerrno;
      return -1;
    }
  }

  /* Extensions.  Note that there may legitimately be no extensions in a valid
   * certificate.
   */
  len = sftp_msg_read_int2(cert_pool, &cert_data, &cert_datalen,
    &extension_datalen);
  if (len == 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 9, "unable to read %s certificate extensions",
      cert_algo);
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error reading certificate: invalid/unsupported certificate format");

    destroy_pool(res->cert_pool);
    errno = xerrno;
    return -1;
  }

  if (extension_datalen > 0) {
    len = sftp_msg_read_data2(cert_pool, &cert_data, &cert_datalen,
      extension_datalen, &extension_data);
    if (len == 0) {
      int xerrno = errno;

      pr_trace_msg(trace_channel, 9,
        "unable to read %s certificate extensions (%lu bytes)", cert_algo,
        (unsigned long) extension_datalen);
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error reading certificate: invalid/unsupported certificate format");

      destroy_pool(res->cert_pool);
      errno = xerrno;
      return -1;
    }

    res->extensions = parse_extensions(cert_pool, extension_data,
      extension_datalen);
    if (res->extensions == NULL) {
      int xerrno = errno;

      pr_trace_msg(trace_channel, 9,
        "unable to parse %s certificate extensions", cert_algo);
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error reading certificate: invalid/unsupported certificate format");

      destroy_pool(res->cert_pool);
      errno = xerrno;
      return -1;
    }
  }

  /* Reserved.  Note that this might legitimately be zero for a valid
   * certificate.
   */
  len = sftp_msg_read_int2(cert_pool, &cert_data, &cert_datalen,
    &reserved_datalen);
  if (len == 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 9, "unable to read %s certificate reserved",
      cert_algo);
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error reading certificate: invalid/unsupported certificate format");

    destroy_pool(res->cert_pool);
    errno = xerrno;
    return -1;
  }

  if (reserved_datalen > 0) {
    len = sftp_msg_read_data2(cert_pool, &cert_data, &cert_datalen,
      reserved_datalen, &reserved_data);
    if (len == 0) {
      int xerrno = errno;

      pr_trace_msg(trace_channel, 9,
        "unable to read %s certificate reserved (%lu bytes)", cert_algo,
        (unsigned long) reserved_datalen);
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error reading certificate: invalid/unsupported certificate format");

      destroy_pool(res->cert_pool);
      errno = xerrno;
      return -1;
    }
  }

  /* Signature key */
  len = sftp_msg_read_int2(cert_pool, &cert_data, &cert_datalen,
    &(res->signature_pubkey_datalen));
  if (len == 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 9,
      "unable to read %s certificate signature key", cert_algo);
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error reading certificate: invalid/unsupported certificate format");

    destroy_pool(res->cert_pool);
    errno = xerrno;
    return -1;
  }

  len = sftp_msg_read_data2(cert_pool, &cert_data, &cert_datalen,
    res->signature_pubkey_datalen, &(res->signature_pubkey_data));
  if (len == 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 9,
      "unable to read %s certificate signature key", cert_algo);
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error reading certificate: invalid/unsupported certificate format");

    destroy_pool(res->cert_pool);
    errno = xerrno;
    return -1;
  }

  buf2 = res->signature_pubkey_data;
  buflen2 = res->signature_pubkey_datalen;
  res->signature_pubkey_algo = sftp_msg_read_string(cert_pool, &buf2, &buflen2);
  if (res->signature_pubkey_algo == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 9,
      "unable to read %s certificate signature key algorithm", cert_algo);
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error reading certificate: invalid/unsupported certificate format");

    destroy_pool(res->cert_pool);
    errno = xerrno;
    return -1;
  }

  /* If the signature key algorithm is a certificate algorithm, reject the
   * certificate; only non-certificate algorithms may act as CAs.
   */
  if (sftp_auth_certificate_algo_isvalid(res->signature_pubkey_algo,
      &signature_pubkey_type) == TRUE) {
    int xerrno = EINVAL;

    pr_trace_msg(trace_channel, 9,
      "%s certificate signature key algorithm '%s' is not recognized/supported",
      cert_algo, res->signature_pubkey_algo);
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error reading certificate: invalid/unsupported certificate format");

    destroy_pool(res->cert_pool);
    errno = xerrno;
    return -1;
  }

  if (sftp_keys_is_cert_type(signature_pubkey_type) == TRUE) {
    int xerrno = EINVAL;

    pr_trace_msg(trace_channel, 9,
      "%s certificate signature key algorithm '%s' cannot be used as a CA key",
      cert_algo, res->signature_pubkey_algo);
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error reading certificate: invalid/unsupported certificate format");

    destroy_pool(res->cert_pool);
    errno = xerrno;
    return -1;
  }

  /* Signature */
  len = sftp_msg_read_int2(cert_pool, &cert_data, &cert_datalen,
    &signature_datalen);
  if (len == 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 9, "unable to read %s certificate signature",
      cert_algo);
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error reading certificate: invalid/unsupported certificate format");

    destroy_pool(res->cert_pool);
    errno = xerrno;
    return -1;
  }

  if (signature_datalen == 0) {
    int xerrno = EPERM;

    pr_trace_msg(trace_channel, 9,
      "unable to read %s certificate signature of zero length", cert_algo);
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error reading certificate: invalid/unsupported certificate format");

    destroy_pool(res->cert_pool);
    errno = xerrno;
    return -1;
  }

  len = sftp_msg_read_data2(cert_pool, &cert_data, &cert_datalen,
    signature_datalen, &signature_data);
  if (len == 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 9, "unable to read %s certificate signature",
      cert_algo);
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error reading certificate: invalid/unsupported certificate format");

    destroy_pool(res->cert_pool);
    errno = xerrno;
    return -1;
  }

  cert_data = buf;
  cert_datalen = buflen;

  /* Make sure we omit the "signature" field from the data being verified,
   * which includes its uint32_t length prefix.
   */
  signed_datalen = cert_datalen - signature_datalen - sizeof(uint32_t);
  if (signed_datalen > SFTP_CERT_MAX_SIGN_DATA_SIZE) {
    int xerrno = EINVAL;

    pr_trace_msg(trace_channel, 9,
      "unable to verify %s certificate signature: signed data length "
      "(%lu bytes) exceeds maximum (%lu bytes)", cert_algo,
      (unsigned long) signed_datalen,
      (unsigned long) SFTP_CERT_MAX_SIGN_DATA_SIZE);
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error reading certificate: invalid/unsupported certificate format");

    destroy_pool(res->cert_pool);
    errno = xerrno;
    return -1;
  }

  if (sftp_keys_verify_signed_data(p, res->signature_pubkey_algo,
      res->signature_pubkey_data, res->signature_pubkey_datalen,
      signature_data, signature_datalen, cert_data, signed_datalen, NULL) < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 9,
      "error verifying %s certificate signature: %s", cert_algo,
      strerror(xerrno));
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error verifying certificate: invalid signature");

    destroy_pool(res->cert_pool);
    errno = xerrno;
    return -1;
  }

  trace_cert(p, res);

  *cert = res;
  return 0;
}

static int validate_critical_options(pool *p, struct sftp_cert *cert) {
  /* NOTE: Currently, we do not implement support for ANY critical options,
   * regardless of certificate type/role.
   */
  if (cert->critical_options != NULL) {
    return -1;
  }

  return 0;
}

int sftp_certs_validate_cert(pool *p, struct sftp_cert *cert,
    unsigned long cert_opts) {
  time_t now;
  uint64_t verify_ts;

  if (p == NULL ||
      cert == NULL) {
    errno = EINVAL;
    return -1;
  }

  now = time(NULL);
  verify_ts = now;

  if (verify_ts < cert->valid_after_ts) {
    pr_trace_msg(trace_channel, 3, "%s certificate is not yet valid",
      cert->cert_algo);
    errno = EPERM;
    return -1;
  }

  if (verify_ts >= cert->valid_before_ts) {
    pr_trace_msg(trace_channel, 3, "%s certificate is expired",
      cert->cert_algo);
    errno = EPERM;
    return -1;
  }

  if (cert->cert_role != SFTP_SSH_CERT_TYPE_USER &&
      cert->cert_role != SFTP_SSH_CERT_TYPE_HOST) {
    pr_trace_msg(trace_channel, 3, "%s certificate has unknown role (%u)",
      cert->cert_algo, cert->cert_role);
    errno = EPERM;
    return -1;
  }

  /* Note that the AllowEmptyPrincipals cert option only applies to host
   * certificates, not user certificates.
   */
  if (cert->principals == NULL) {
    if (cert->cert_role != SFTP_SSH_CERT_TYPE_HOST ||
        !(cert_opts & SFTP_CERT_OPT_ALLOW_EMPTY_PRINCIPALS)) {
      pr_trace_msg(trace_channel, 3, "%s certificate lacks required principals",
        cert->cert_algo);
      errno = EPERM;
      return -1;
    }
  }

  if (validate_critical_options(p, cert) < 0) {
    pr_trace_msg(trace_channel, 3,
      "%s certificate requires unsupported critical options", cert->cert_algo);
    errno = EPERM;
    return -1;
  }

  return 0;
}

