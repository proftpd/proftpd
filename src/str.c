/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2008-2016 The ProFTPD Project team
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
 * As a special exemption, Public Flood Software/MacGyver aka Habeeb J. Dihu
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

/* String manipulation functions. */

#include "conf.h"

/* Maximum number of matches that we will do in a given string. */
#define PR_STR_MAX_MATCHES			128

static char *str_vreplace(pool *p, unsigned int max_replaces, char *s,
    va_list args) {
  char *m, *r, *src, *cp;
  char *matches[PR_STR_MAX_MATCHES+1], *replaces[PR_STR_MAX_MATCHES+1];
  char buf[PR_TUNABLE_PATH_MAX] = {'\0'}, *pbuf = NULL;
  size_t nmatches = 0, rlen = 0;
  int blen = 0;

  src = s;
  cp = buf;
  *cp = '\0';

  memset(matches, 0, sizeof(matches));
  memset(replaces, 0, sizeof(replaces));

  blen = strlen(src) + 1;

  while ((m = va_arg(args, char *)) != NULL &&
         nmatches < PR_STR_MAX_MATCHES) {
    char *tmp = NULL;
    int count = 0;

    r = va_arg(args, char *);
    if (r == NULL) {
      break;
    }

    /* Increase the length of the needed buffer by the difference between
     * the given match and replacement strings, multiplied by the number
     * of times the match string occurs in the source string.
     */
    tmp = strstr(s, m);
    while (tmp) {
      pr_signals_handle();
      count++;
      if (count > max_replaces) {
        errno = E2BIG;
        return NULL;
      }

      /* Be sure to increment the pointer returned by strstr(3), to
       * advance past the beginning of the substring for which we are
       * looking.  Otherwise, we just loop endlessly, seeing the same
       * value for tmp over and over.
       */
      tmp += strlen(m);
      tmp = strstr(tmp, m);
    }

    /* We are only concerned about match/replacement strings that actually
     * occur in the given string.
     */
    if (count) {
      blen += count * (strlen(r) - strlen(m));
      if (blen < 0) {
        /* Integer overflow. In order to overflow this, somebody must be
         * doing something very strange. The possibility still exists that
         * we might not catch this overflow in extreme corner cases, but
         * massive amounts of data (gigabytes) would need to be in s to
         * trigger this, easily larger than any buffer we might use.
         */
        return s;
      }
      matches[nmatches] = m;
      replaces[nmatches++] = r;
    }
  }

  /* If there are no matches, then there is nothing to replace. */
  if (nmatches == 0) {
    return s;
  }

  /* Try to handle large buffer situations (i.e. escaping of PR_TUNABLE_PATH_MAX
   * (>2048) correctly, but do not allow very big buffer sizes, that may
   * be dangerous (BUFSIZ may be defined in stdio.h) in some library
   * functions.
   */
#ifndef BUFSIZ
# define BUFSIZ 8192
#endif

  if (blen >= BUFSIZ) {
    errno = ENOSPC;
    return NULL;
  }

  cp = pbuf = (char *) pcalloc(p, ++blen);

  while (*src) {
    char **mptr, **rptr;

    for (mptr = matches, rptr = replaces; *mptr; mptr++, rptr++) {
      size_t mlen;

      mlen = strlen(*mptr);
      rlen = strlen(*rptr);

      if (strncmp(src, *mptr, mlen) == 0) {
        sstrncpy(cp, *rptr, blen - strlen(pbuf));

        if (((cp + rlen) - pbuf + 1) > blen) {
          pr_log_pri(PR_LOG_ERR,
            "WARNING: attempt to overflow internal ProFTPD buffers");
          cp = pbuf;

          cp += (blen - 1);
          goto done;

        } else {
          cp += rlen;
        }
	
        src += mlen;
        break;
      }
    }

    if (!*mptr) {
      if ((cp - pbuf + 1) >= blen) {
        pr_log_pri(PR_LOG_ERR,
          "WARNING: attempt to overflow internal ProFTPD buffers");
        cp = pbuf;

        cp += (blen - 1);
        goto done;
      }

      *cp++ = *src++;
    }
  }

 done:
  *cp = '\0';

  return pbuf;
}

const char *quote_dir(pool *p, char *path) {
  if (p == NULL ||
      path == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return sreplace(p, path, "\"", "\"\"", NULL);
}

char *pr_str_replace(pool *p, unsigned int max_replaces, char *s, ...) {
  va_list args;
  char *res = NULL;

  if (p == NULL ||
      s == NULL ||
      max_replaces == 0) {
    errno = EINVAL;
    return NULL;
  }

  va_start(args, s);
  res = str_vreplace(p, max_replaces, s, args);
  va_end(args);

  return res;
}

char *sreplace(pool *p, char *s, ...) {
  va_list args;
  char *res = NULL;

  if (p == NULL ||
      s == NULL) {
    errno = EINVAL;
    return NULL;
  }

  va_start(args, s);
  res = str_vreplace(p, PR_STR_MAX_REPLACEMENTS, s, args);
  va_end(args);

  if (res == NULL &&
      errno == E2BIG) {
    /* For backward compatible behavior. */
    return s;
  }

  return res;
}

/* "safe" strcat, saves room for NUL at end of dst, and refuses to copy more
 * than "n" bytes.
 */
char *sstrcat(char *dst, const char *src, size_t n) {
  register char *d = dst;

  if (dst == NULL ||
      src == NULL ||
      n == 0) {
    errno = EINVAL;
    return NULL;
  }

  /* Edge case short ciruit; strlcat(3) doesn't do what I think it should
   * do for this particular case.
   */
  if (n > 1) {
#ifdef HAVE_STRLCAT
    strlcat(dst, src, n);
  
#else
    for (; *d && n > 1; d++, n--) ;

    while (n-- > 1 && *src) {
      *d++ = *src++;
    }

    *d = '\0';
#endif /* HAVE_STRLCAT */

  } else {
    *d = '\0';
  }

  return dst;
}

char *pstrdup(pool *p, const char *str) {
  char *res;
  size_t len;

  if (p == NULL ||
      str == NULL) {
    errno = EINVAL;
    return NULL;
  }

  len = strlen(str) + 1;

  res = palloc(p, len);
  if (res != NULL) {
    sstrncpy(res, str, len);
  }

  return res;
}

char *pstrndup(pool *p, const char *str, size_t n) {
  char *res;

  if (!p || !str) {
    errno = EINVAL;
    return NULL;
  }

  res = palloc(p, n + 1);
  sstrncpy(res, str, n + 1);
  return res;
}

char *pdircat(pool *p, ...) {
  char *argp, *ptr, *res;
  char last;
  int count = 0;
  size_t len = 0, res_len = 0;
  va_list ap;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  va_start(ap, p);

  last = 0;

  while ((res = va_arg(ap, char *)) != NULL) {
    /* If the first argument is "", we have to account for a leading /
     * which must be added.
     */
    if (!count++ && !*res) {
      len++;

    } else if (last && last != '/' && *res != '/') {
      len++;

    } else if (last && last == '/' && *res == '/') {
      len--;
    }

    res_len = strlen(res);
    len += res_len;
    last = (*res ? res[res_len-1] : 0);
  }

  va_end(ap);
  ptr = res = (char *) pcalloc(p, len + 1);

  va_start(ap, p);

  last = res_len = 0;

  while ((argp = va_arg(ap, char *)) != NULL) {
    size_t arglen;

    if (last && last == '/' && *argp == '/') {
      argp++;

    } else if (last && last != '/' && *argp != '/') {
      sstrcat(ptr, "/", len + 1);
      ptr += 1;
      res_len += 1;
    }

    arglen = strlen(argp);
    sstrcat(ptr, argp, len + 1);
    ptr += arglen;
    res_len += arglen;
 
    last = (*res ? res[res_len-1] : 0);
  }

  va_end(ap);

  return res;
}

char *pstrcat(pool *p, ...) {
  char *argp, *ptr, *res;
  size_t len = 0;
  va_list ap;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  va_start(ap, p);

  while ((res = va_arg(ap, char *)) != NULL) {
    len += strlen(res);
  }

  va_end(ap);

  ptr = res = pcalloc(p, len + 1);

  va_start(ap, p);

  while ((argp = va_arg(ap, char *)) != NULL) {
    size_t arglen;

    arglen = strlen(argp);
    sstrcat(ptr, argp, len + 1);
    ptr += arglen;
  }

  va_end(ap);

  return res;
}

int pr_strnrstr(const char *s, size_t slen, const char *suffix,
    size_t suffixlen, int flags) {
  int res = FALSE;

  if (s == NULL ||
      suffix == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (slen == 0) {
    slen = strlen(s);
  }

  if (suffixlen == 0) {
    suffixlen = strlen(suffix);
  }

  if (slen == 0 &&
      suffixlen == 0) {
    return TRUE;
  }

  if (slen == 0 ||
      suffixlen == 0) {
    return FALSE;
  }

  if (suffixlen > slen) {
    return FALSE;
  }

  if (flags & PR_STR_FL_IGNORE_CASE) {
    if (strncasecmp(s + (slen - suffixlen), suffix, suffixlen) == 0) {
      res = TRUE;
    }

  } else {
    if (strncmp(s + (slen - suffixlen), suffix, suffixlen) == 0) {
      res = TRUE;
    }
  }

  return res;
}

char *pr_str_strip(pool *p, char *str) {
  char c, *dupstr, *start, *finish;
 
  if (!p || !str) {
    errno = EINVAL;
    return NULL;
  }
 
  /* First, find the non-whitespace start of the given string */
  for (start = str; PR_ISSPACE(*start); start++);
 
  /* Now, find the non-whitespace end of the given string */
  for (finish = &str[strlen(str)-1]; PR_ISSPACE(*finish); finish--);

  /* finish is now pointing to a non-whitespace character.  So advance one
   * character forward, and set that to NUL.
   */
  c = *++finish;
  *finish = '\0';

  /* The space-stripped string is, then, everything from start to finish. */
  dupstr = pstrdup(p, start);

  /* Restore the given string buffer contents. */
  *finish = c;

  return dupstr;
}

char *pr_str_strip_end(char *s, char *ch) {
  size_t len;

  if (s == NULL ||
      ch == NULL) {
    errno = EINVAL;
    return NULL;
  }

  len = strlen(s);

  while (len && strchr(ch, *(s+len - 1))) {
    pr_signals_handle();

    *(s+len - 1) = '\0';
    len--;
  }

  return s;
}

#if defined(HAVE_STRTOULL) && \
  (SIZEOF_UID_T == SIZEOF_LONG_LONG && SIZEOF_GID_T == SIZEOF_LONG_LONG)
static int parse_ull(const char *val, unsigned long long *num) {
  char *endp = NULL;
  unsigned long long res;

  res = strtoull(val, &endp, 10);
  if (endp && *endp) {
    errno = EINVAL;
    return -1;
  }

  *num = res;
  return 0;
}
#endif /* HAVE_STRTOULL */

static int parse_ul(const char *val, unsigned long *num) {
  char *endp = NULL;
  unsigned long res;

  res = strtoul(val, &endp, 10);
  if (endp && *endp) {
    errno = EINVAL;
    return -1;
  }

  *num = res;
  return 0;
}

char *pr_str_bin2hex(pool *p, const unsigned char *buf, size_t len, int flags) {
  static const char *hex_lc = "0123456789abcdef", *hex_uc = "0123456789ABCDEF";
  register unsigned int i;
  const char *hex_vals;
  char *hex, *ptr;
  size_t hex_len;

  if (p == NULL ||
      buf == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (len == 0) {
    return pstrdup(p, "");
  }

  /* By default, we use lowercase hex values. */
  hex_vals = hex_lc;
  if (flags & PR_STR_FL_HEX_USE_UC) {
    hex_vals = hex_uc;
  }

  hex_len = (len * 2) + 1;
  hex = palloc(p, hex_len);

  ptr = hex;
  for (i = 0; i < len; i++) {
    *ptr++ = hex_vals[buf[i] >> 4];
    *ptr++ = hex_vals[buf[i] % 16];
  }
  *ptr = '\0';

  return hex;
}

static int c2h(char c, unsigned char *h) {
  if (c >= '0' &&
      c <= '9') {
    *h = c - '0';
    return TRUE;
  }

  if (c >= 'a' &&
      c <= 'f') {
    *h = c - 'a' + 10;
    return TRUE;
  }

  if (c >= 'A' &&
      c <= 'F') {
    *h = c - 'A' + 10;
    return TRUE;
  }

  return FALSE;
}

unsigned char *pr_str_hex2bin(pool *p, const unsigned char *hex, size_t hex_len,
    size_t *len) {
  register unsigned int i, j;
  unsigned char *data;
  size_t data_len;

  if (p == NULL ||
      hex == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (hex_len == 0) {
    hex_len = strlen((char *) hex);
  }

  if (hex_len == 0) {
    data = (unsigned char *) pstrdup(p, "");
    return data;
  }

  data_len = hex_len / 2;
  data = palloc(p, data_len);

  for (i = 0, j = 0; i < hex_len; i += 2) {
    unsigned char v1, v2;

    if (c2h(hex[i], &v1) == FALSE) {
      errno = ERANGE;
      return NULL;
    }

    if (c2h(hex[i+1], &v2) == FALSE) {
      errno = ERANGE;
      return NULL;
    }

    data[j++] = ((v1 << 4) | v2);
  }

  if (len != NULL) {
    *len = data_len;
  }

  return data;
}

int pr_str2uid(const char *val, uid_t *uid) {
#ifdef HAVE_STRTOULL
  unsigned long long ull = 0ULL;
#endif /* HAVE_STRTOULL */
  unsigned long ul = 0UL;

  if (val == NULL ||
      uid == NULL) {
    errno = EINVAL;
    return -1;
  }

#if SIZEOF_UID_T == SIZEOF_LONG_LONG
# ifdef HAVE_STRTOULL
  if (parse_ull(val, &ull) < 0) {
    return -1;
  }
  *uid = ull; 

# else
  if (parse_ul(val, &ul) < 0) {
    return -1;
  }
  *uid = ul;
# endif /* HAVE_STRTOULL */
#else
  (void) ull;
  if (parse_ul(val, &ul) < 0) {
    return -1;
  }
  *uid = ul;
#endif /* sizeof(uid_t) != sizeof(long long) */

  return 0;
}

int pr_str2gid(const char *val, gid_t *gid) {
#ifdef HAVE_STRTOULL
  unsigned long long ull = 0ULL;
#endif /* HAVE_STRTOULL */
  unsigned long ul = 0UL;

  if (val == NULL ||
      gid == NULL) {
    errno = EINVAL;
    return -1;
  }

#if SIZEOF_GID_T == SIZEOF_LONG_LONG
# ifdef HAVE_STRTOULL
  if (parse_ull(val, &ull) < 0) {
    return -1;
  }
  *gid = ull; 

# else
  if (parse_ul(val, &ul) < 0) {
    return -1;
  }
  *gid = ul;
# endif /* HAVE_STRTOULL */
#else
  (void) ull;
  if (parse_ul(val, &ul) < 0) {
    return -1;
  }
  *gid = ul;
#endif /* sizeof(gid_t) != sizeof(long long) */

  return 0;
}

const char *pr_uid2str(pool *p, uid_t uid) {
  static char buf[64];

  memset(&buf, 0, sizeof(buf));
  if (uid != (uid_t) -1) {
#if SIZEOF_UID_T == SIZEOF_LONG_LONG
    snprintf(buf, sizeof(buf)-1, "%llu", (unsigned long long) uid);
#else
    snprintf(buf, sizeof(buf)-1, "%lu", (unsigned long) uid);
#endif /* sizeof(uid_t) != sizeof(long long) */
  } else {
    snprintf(buf, sizeof(buf)-1, "%d", -1);
  }

  if (p != NULL) {
    return pstrdup(p, buf);
  }

  return buf;
}

const char *pr_gid2str(pool *p, gid_t gid) {
  static char buf[64];

  memset(&buf, 0, sizeof(buf));
  if (gid != (gid_t) -1) {
#if SIZEOF_GID_T == SIZEOF_LONG_LONG
    snprintf(buf, sizeof(buf)-1, "%llu", (unsigned long long) gid);
#else
    snprintf(buf, sizeof(buf)-1, "%lu", (unsigned long) gid);
#endif /* sizeof(gid_t) != sizeof(long long) */
  } else {
    snprintf(buf, sizeof(buf)-1, "%d", -1);
  }

  if (p != NULL) {
    return pstrdup(p, buf);
  }

  return buf;
}

/* NOTE: Update mod_ban's ban_parse_timestr() to use this function. */
int pr_str_get_duration(const char *str, int *duration) {
  int hours, mins, secs;
  int flags = PR_STR_FL_IGNORE_CASE, has_suffix = FALSE;
  size_t len;
  char *ptr = NULL;

  if (str == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (sscanf(str, "%2d:%2d:%2d", &hours, &mins, &secs) == 3) {
    if (hours < 0 ||
        mins < 0 ||
        secs < 0) {
      errno = ERANGE;
      return -1;
    }

    if (duration != NULL) {
      *duration = (hours * 60 * 60) + (mins * 60) + secs;
    }

    return 0;
  }

  len = strlen(str);
  if (len == 0) {
    errno = EINVAL;
    return -1;
  }

  /* Handle the "single component" formats:
   *
   * If ends with "S", "s", or "sec": parse secs
   * If ends with "M", "m", or "min": parse minutes
   * If ends with "H", "h", or "hr": parse hours
   *
   * Otherwise, try to parse as just a number of seconds.
   */

  has_suffix = pr_strnrstr(str, len, "s", 1, flags);
  if (has_suffix == FALSE) {
    has_suffix = pr_strnrstr(str, len, "sec", 3, flags);
  }
  if (has_suffix == TRUE) {
    /* Parse seconds */

    if (sscanf(str, "%d", &secs) == 1) {
      if (secs < 0) {
        errno = ERANGE;
        return -1;
      }

      if (duration != NULL) {
        *duration = secs;
      }

      return 0;
    }

    errno = EINVAL;
    return -1;
  }

  has_suffix = pr_strnrstr(str, len, "m", 1, flags);
  if (has_suffix == FALSE) {
    has_suffix = pr_strnrstr(str, len, "min", 3, flags);
  }
  if (has_suffix == TRUE) {
    /* Parse minutes */

    if (sscanf(str, "%d", &mins) == 1) {
      if (mins < 0) {
        errno = ERANGE;
        return -1;
      }

      if (duration != NULL) {
        *duration = (mins * 60);
      }
  
      return 0;
    }

    errno = EINVAL;
    return -1;
  }

  has_suffix = pr_strnrstr(str, len, "h", 1, flags);
  if (has_suffix == FALSE) {
    has_suffix = pr_strnrstr(str, len, "hr", 2, flags);
  }
  if (has_suffix == TRUE) {
    /* Parse hours */

    if (sscanf(str, "%d", &hours) == 1) {
      if (hours < 0) {
        errno = ERANGE;
        return -1;
      }

      if (duration != NULL) {
        *duration = (hours * 60 * 60);
      }
 
      return 0;
    }

    errno = EINVAL;
    return -1;
  }

  /* Use strtol(3) here, check for trailing garbage, etc. */
  secs = (int) strtol(str, &ptr, 10);
  if (ptr && *ptr) {
    /* Not a bare number, but a string with non-numeric characters. */
    errno = EINVAL;
    return -1;
  }

  if (secs < 0) {
    errno = ERANGE;
    return -1;
  }

  if (duration != NULL) {
    *duration = secs;
  }

  return 0;
}

int pr_str_get_nbytes(const char *str, const char *units, off_t *nbytes) {
  off_t sz;
  char *ptr = NULL;
  float factor = 0.0;

  if (str == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* No negative numbers. */
  if (*str == '-') {
    errno = EINVAL;
    return -1;
  }

  if (units == NULL ||
      *units == '\0') {
    factor = 1.0;

  } else if (strncasecmp(units, "KB", 3) == 0) {
    factor = 1024.0;

  } else if (strncasecmp(units, "MB", 3) == 0) {
    factor = 1024.0 * 1024.0;

  } else if (strncasecmp(units, "GB", 3) == 0) {
    factor = 1024.0 * 1024.0 * 1024.0;

  } else if (strncasecmp(units, "TB", 3) == 0) {
    factor = 1024.0 * 1024.0 * 1024.0 * 1024.0;
  
  } else if (strncasecmp(units, "B", 2) == 0) {
    factor = 1.0;

  } else {
    errno = EINVAL;
    return -1;
  }

  errno = 0;

#ifdef HAVE_STRTOULL
  sz = strtoull(str, &ptr, 10);
#else
  sz = strtoul(str, &ptr, 10);
#endif /* !HAVE_STRTOULL */

  if (errno == ERANGE) {
    return -1;
  }

  if (ptr != NULL && *ptr) {
    /* Error parsing the given string */
    errno = EINVAL;
    return -1;
  }

  /* Don't bother applying the factor if the result will overflow the result. */
#ifdef ULLONG_MAX
  if (sz > (ULLONG_MAX / factor)) {
#else
  if (sz > (ULONG_MAX / factor)) {
#endif /* !ULLONG_MAX */
    errno = ERANGE;
    return -1;
  }

  if (nbytes != NULL) {
    *nbytes = (off_t) (sz * factor);
  }

  return 0;
}

char *pr_str_get_word(char **cp, int flags) {
  char *res, *dst;
  char quote_mode = 0;

  if (cp == NULL ||
     !*cp ||
     !**cp) {
    errno = EINVAL;
    return NULL;
  }

  if (!(flags & PR_STR_FL_PRESERVE_WHITESPACE)) {
    while (**cp && PR_ISSPACE(**cp)) {
      pr_signals_handle();
      (*cp)++;
    }
  }

  if (!**cp) {
    return NULL;
  }

  res = dst = *cp;

  if (!(flags & PR_STR_FL_PRESERVE_COMMENTS)) {
    /* Stop processing at start of an inline comment. */
    if (**cp == '#') {
      return NULL;
    }
  }

  if (**cp == '\"') {
    quote_mode++;
    (*cp)++;
  }

  while (**cp && (quote_mode ? (**cp != '\"') : !PR_ISSPACE(**cp))) {
    pr_signals_handle();

    if (**cp == '\\' && quote_mode) {

      /* Escaped char */
      if (*((*cp)+1)) {
        *dst = *(++(*cp));
      }
    }

    *dst++ = **cp;
    ++(*cp);
  }

  if (**cp) {
    (*cp)++;
  }

  *dst = '\0';
  return res;
}

/* get_token tokenizes a string, increments the src pointer to the next
 * non-separator in the string.  If the src string is empty or NULL, the next
 * token returned is NULL.
 */
char *pr_str_get_token2(char **src, char *sep, size_t *token_len) {
  char *token;
  size_t len = 0;

  if (src == NULL ||
      *src == NULL ||
      **src == '\0' ||
      sep == NULL) {

    if (token_len != NULL) {
      *token_len = len;
    }

    errno = EINVAL;
    return NULL;
  }

  token = *src;

  while (**src && !strchr(sep, **src)) {
    (*src)++;
    len++;
  }

  if (**src) {
    *(*src)++ = '\0';
  }

  if (token_len != NULL) {
    *token_len = len;
  }

  return token;
}

char *pr_str_get_token(char **src, char *sep) {
  return pr_str_get_token2(src, sep, NULL);
}

int pr_str_is_boolean(const char *str) {
  if (str == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (strncasecmp(str, "on", 3) == 0) {
    return TRUE;
  }

  if (strncasecmp(str, "off", 4) == 0) {
    return FALSE;
  }

  if (strncasecmp(str, "yes", 4) == 0) {
    return TRUE;
  }
 
  if (strncasecmp(str, "no", 3) == 0) {
    return FALSE;
  }

  if (strncasecmp(str, "true", 5) == 0) {
    return TRUE;
  }

  if (strncasecmp(str, "false", 6) == 0) {
    return FALSE;
  }

  if (strncasecmp(str, "1", 2) == 0) {
    return TRUE;
  }

  if (strncasecmp(str, "0", 2) == 0) {
    return FALSE;
  }

  errno = EINVAL;
  return -1;
}

/* Return true if str contains any of the glob(7) characters. */
int pr_str_is_fnmatch(const char *str) {
  int have_bracket = 0;

  if (str == NULL) {
    return FALSE;
  }

  while (*str) {
    switch (*str) {
      case '?':
      case '*':
        return TRUE;

      case '\\':
        /* If the next character is NUL, we've reached the end of the string. */
        if (*(str+1) == '\0')
          return FALSE;

        /* Skip past the escaped character, i.e. the next character. */
        str++;
        break;

      case '[':
        have_bracket++;
        break;

      case ']':
        if (have_bracket)
          return TRUE;
        break;

      default:
        break;
    }

    str++;
  }

  return FALSE;
}

