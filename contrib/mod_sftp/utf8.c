/*
 * ProFTPD - mod_sftp UTF8 encoding
 * Copyright (c) 2008-2009 TJ Saunders
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
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * $Id: utf8.c,v 1.4 2009-02-22 02:48:22 castaglia Exp $
 */

#include "mod_sftp.h"
#include "utf8.h"

#ifdef HAVE_ICONV_H
# include <iconv.h>
#endif

#ifdef HAVE_LANGINFO_H
# include <langinfo.h>
#endif

static const char *local_charset = NULL;

#if defined(PR_USE_NLS) && defined(HAVE_ICONV_H)
static iconv_t decode_conv = (iconv_t) -1;
static iconv_t encode_conv = (iconv_t) -1;

static int utf8_convert(iconv_t conv, char *inbuf, size_t *inbuflen,
    char *outbuf, size_t *outbuflen) {
# ifdef HAVE_ICONV
  char *start = inbuf;

  while (inbuflen > 0) {
    size_t nconv;

    pr_signals_handle();

    nconv = iconv(conv, &inbuf, inbuflen, &outbuf, outbuflen);
    if (nconv == (size_t) -1) {
      if (errno == EINVAL) {
        memmove(start, inbuf, *inbuflen);
        continue;

      } else
        return -1;
    }

    break;
  }
  return 0;
# else
  errno = ENOSYS;
  return -1;
# endif /* HAVE_ICONV */
}
#endif /* !PR_USE_NLS && !HAVE_ICONV_H */

int sftp_utf8_set_charset(const char *charset) {
  int res;

  if (charset == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (local_charset) {
    pr_trace_msg("sftp", 5,
      "attempting to switch local charset from %s to %s", local_charset,
      charset);

  } else {
    pr_trace_msg("sftp", 5, "attempting to use %s as local charset", charset);
  }

  (void) sftp_utf8_free();

  local_charset = pstrdup(permanent_pool, charset);

  res = sftp_utf8_init();
  if (res < 0) {
    pr_trace_msg("sftp", 1,
      "failed to initialize encoding for local charset %s", charset);
    local_charset = NULL;
    return -1;
  }

  return res;
}

int sftp_utf8_free(void) {
# if defined(PR_USE_NLS) && defined(HAVE_ICONV)
  int res = 0;

  /* Close the iconv handles. */
  if (encode_conv != (iconv_t) -1) {
    res = iconv_close(encode_conv);
    if (res < 0) {
      pr_trace_msg("sftp", 1,
        "error closing encoding conversion handle from '%s' to '%s': %s",
          local_charset, "UTF-8", strerror(errno));
      res = -1;
    }

    encode_conv = (iconv_t) -1;
  }

  if (decode_conv != (iconv_t) -1) {
    res = iconv_close(decode_conv);
    if (res < 0) {
      pr_trace_msg("sftp", 1,
        "error closing decoding conversion handle from '%s' to '%s': %s",
          "UTF-8", local_charset, strerror(errno));
      res = -1;
    }

    decode_conv = (iconv_t) -1;
  }

  return res;
# else
  errno = ENOSYS;
  return -1;
# endif
}

int sftp_utf8_init(void) {
#if defined(PR_USE_NLS) && defined(HAVE_ICONV)

  if (local_charset == NULL) {
# ifdef HAVE_NL_LANGINFO
    /* Look up the current charset.  If there's a problem, default to
     * UCS-2.
     */
    local_charset = nl_langinfo(CODESET);
    if (local_charset == NULL ||
        strlen(local_charset) == 0) {
      local_charset = "UTF-8";
      pr_trace_msg("sftp", 1,
        "unable to determine locale, defaulting to 'UTF-8' for "
        "UTF8 conversion");

    } else {

      /* Workaround a stupid bug in many implementations where nl_langinfo()
       * returns "646" to mean "US-ASCII".  The problem is that iconv_open(3)
       * doesn't accept "646" as an acceptable encoding.
       */
      if (strcmp(local_charset, "646") == 0) {
        local_charset = "US-ASCII";
      }

      pr_trace_msg("sftp", 1, "converting UTF8 to local character set '%s'",
        local_charset);
    }
# else
    local_charset = "UTF-8";
    pr_trace_msg("sftp", 1,
      "nl_langinfo(3) not supported, defaulting to using 'UTF-8' for UTF8 "
      "conversion");
# endif /* HAVE_NL_LANGINFO */
  } else {
    pr_trace_msg("sftp", 3,
      "using '%s' as local charset for UTF8 conversion", local_charset);
  }

  /* Get the iconv handles. */
  encode_conv = iconv_open("UTF-8", local_charset);
  if (encode_conv == (iconv_t) -1) {
    pr_trace_msg("sftp", 1, "error opening conversion handle from '%s' "
      "to '%s': %s", local_charset, "UTF-8", strerror(errno));
    return -1;
  }
 
  decode_conv = iconv_open(local_charset, "UTF-8");
  if (decode_conv == (iconv_t) -1) {
    int xerrno = errno;

    pr_trace_msg("sftp", 1, "error opening conversion handle from '%s' "
      "to '%s': %s", "UTF-8", local_charset, strerror(errno));

    (void) iconv_close(encode_conv);
    encode_conv = (iconv_t) -1;

    errno = xerrno;
    return -1;
  }

  return 0;
# else
  errno = ENOSYS;
  return -1;
#endif /* HAVE_ICONV */
}

char *sftp_utf8_decode_str(pool *p, const char *str) {
#if defined(PR_USE_NLS) && defined(HAVE_ICONV_H)
  size_t inlen, inbuflen, outlen, outbuflen;
  char *inbuf, outbuf[PR_TUNABLE_PATH_MAX*2], *res = NULL;

  if (p == NULL ||
      str == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (decode_conv == (iconv_t) -1) {
    pr_trace_msg("sftp", 1, "decoding conversion handle is invalid, unable to "
      "decode UTF8 string");
    return (char *) str;
  }

  inlen = strlen(str) + 1;
  inbuf = pcalloc(p, inlen);
  memcpy(inbuf, str, inlen);
  inbuflen = inlen;

  outbuflen = sizeof(outbuf);

  if (utf8_convert(decode_conv, inbuf, &inbuflen, outbuf, &outbuflen) < 0)
    return NULL;

  outlen = sizeof(outbuf) - outbuflen;
  res = pcalloc(p, outlen);
  memcpy(res, outbuf, outlen);

  return res;
#else
  return pstrdup(p, str);
#endif /* !PR_USE_NLS && !HAVE_ICONV_H */
}

char *sftp_utf8_encode_str(pool *p, const char *str) {
#if defined(PR_USE_NLS) && defined(HAVE_ICONV_H)
  size_t inlen, inbuflen, outlen, outbuflen;
  char *inbuf, outbuf[PR_TUNABLE_PATH_MAX*2], *res;

  if (p == NULL ||
      str == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (encode_conv == (iconv_t) -1) {
    pr_trace_msg("sftp", 1, "encoding conversion handle is invalid, unable to "
      "encode UTF8 string");
    return (char *) str;
  }

  inlen = strlen(str) + 1;
  inbuf = pcalloc(p, inlen);
  memcpy(inbuf, str, inlen);
  inbuflen = inlen;

  outbuflen = sizeof(outbuf);

  if (utf8_convert(encode_conv, inbuf, &inbuflen, outbuf, &outbuflen) < 0)
    return NULL;

  outlen = sizeof(outbuf) - outbuflen;
  res = pcalloc(p, outlen);
  memcpy(res, outbuf, outlen);

  return res;
#else
  return pstrdup(p, str);
#endif /* !PR_USE_NLS && !HAVE_ICONV_H */
}
