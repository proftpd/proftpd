/*
 * ProFTPD: mod_tls_memcache -- a module which provides a shared SSL session
 *                              cache using memcached servers
 *
 * Copyright (c) 2011-2015 TJ Saunders
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
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * This is mod_tls_memcache, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "conf.h"
#include "privs.h"
#include "mod_tls.h"
#include "ccan-json.h"
#include "hanson-tpl.h"

#define MOD_TLS_MEMCACHE_VERSION		"mod_tls_memcache/0.2"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030602
# error "ProFTPD 1.3.6rc2 or later required"
#endif

module tls_memcache_module;

/* Assume a maximum SSL session (serialized) length of 10K.  Note that this
 * is different from the SSL_MAX_SSL_SESSION_ID_LENGTH provided by OpenSSL.
 * There is no limit imposed on the length of the ASN1 description of the
 * SSL session data.
 */
#ifndef TLS_MAX_SSL_SESSION_SIZE
# define TLS_MAX_SSL_SESSION_SIZE	1024 * 10
#endif

static unsigned long tls_mcache_opts = 0UL;
#define TLS_MCACHE_OPT_USE_JSON			0x0001

struct mcache_entry {
  uint32_t expires;
  unsigned int sess_datalen;
  unsigned char sess_data[TLS_MAX_SSL_SESSION_SIZE];
};

/* These are tpl format strings */
#define TLS_MCACHE_TPL_KEY_FMT			"s"
#define TLS_MCACHE_TPL_VALUE_FMT		"S(uic#)"

/* These are the JSON format field names */
#define TLS_MCACHE_JSON_KEY_EXPIRES		"expires"
#define TLS_MCACHE_JSON_KEY_DATA		"data"
#define TLS_MCACHE_JSON_KEY_DATA_LENGTH		"data_len"

/* The difference between mcache_entry and mcache_large_entry is that the
 * buffers in the latter are dynamically allocated from the heap, not
 * stored in memcached (given that memcached has limits on how much it can
 * store).  The large_entry struct is used for storing sessions which don't
 * fit into memcached; this also means that these large entries are NOT shared
 * across processes.
 */
struct mcache_large_entry {
  time_t expires;
  unsigned int sess_id_len;
  unsigned char *sess_id;
  unsigned int sess_datalen;
  unsigned char *sess_data;
};

/* These stats are stored in memcached as well, so that the status command can
 * be run on _any_ proftpd in the cluster.
 */

struct cache_key {
  const char *key;
  const char *desc;
};

static struct cache_key cache_keys[] = {
  { "cache_hits", "Cache lifetime hits" },
  { "cache_misses", "Cache lifetime misses" },
  { "cache_stores", "Cache lifetime sessions stored" },
  { "cache_deletes", "Cache lifetime sessions deleted" },
  { "cache_errors", "Cache lifetime errors handling sessions in cache" },
  { "cache_exceeds", "Cache lifetime sessions exceeding max entry size" },
  { "cache_max_sess_len", "Largest session exceeding max entry size" },
  { NULL, NULL }
};

/* Indexes into the cache_keys array */
#define CACHE_KEY_HITS		0
#define CACHE_KEY_MISSES	1
#define CACHE_KEY_STORES	2
#define CACHE_KEY_DELETES	3
#define CACHE_KEY_ERRORS	4
#define CACHE_KEY_EXCEEDS	5
#define CACHE_KEY_MAX_LEN	6

static tls_sess_cache_t tls_mcache;

static array_header *tls_mcache_sess_list = NULL;

/* For communicating with memcached servers for shared session data. */
static pr_memcache_t *mcache = NULL;

static const char *trace_channel = "tls.memcache";

static int tls_mcache_close(tls_sess_cache_t *);
static int tls_mcache_sess_init(void);

static const char *tls_mcache_get_crypto_errors(void) {
  unsigned int count = 0;
  unsigned long e = ERR_get_error();
  BIO *bio = NULL;
  char *data = NULL;
  long datalen;
  const char *str = "(unknown)";

  /* Use ERR_print_errors() and a memory BIO to build up a string with
   * all of the error messages from the error queue.
   */

  if (e)
    bio = BIO_new(BIO_s_mem());

  while (e) {
    pr_signals_handle();
    BIO_printf(bio, "\n  (%u) %s", ++count, ERR_error_string(e, NULL));
    e = ERR_get_error();
  }

  datalen = BIO_get_mem_data(bio, &data);
  if (data) {
    data[datalen] = '\0';
    str = pstrdup(permanent_pool, data);
  }

  if (bio)
    BIO_free(bio);

  return str;
}

/* Functions for marshalling key/value data to/from memcached. */

static int tls_mcache_get_tpl_key(pool *p, unsigned char *sess_id,
    unsigned int sess_id_len, void **key, size_t *keysz) {
  register unsigned int i;
  char *sess_id_hex;
  void *data = NULL;
  size_t datasz = 0, sess_id_hexlen;
  int res;

  sess_id_hexlen = (sess_id_len * 2) + 1;
  sess_id_hex = pcalloc(p, sess_id_hexlen);

  for (i = 0; i < sess_id_len; i++) {
    sprintf((char *) &(sess_id_hex[i*2]), "%02X", sess_id[i]);
  }

  res = tpl_jot(TPL_MEM, &data, &datasz, TLS_MCACHE_TPL_KEY_FMT, &sess_id_hex);
  if (res < 0) {
    return -1;
  }

  *keysz = datasz;
  *key = palloc(p, datasz);
  memcpy(*key, data, datasz);
  free(data);

  return 0;
}

static int tls_mcache_get_json_key(pool *p, unsigned char *sess_id,
    unsigned int sess_id_len, void **key, size_t *keysz) {
  register unsigned int i;
  char *sess_id_hex, *json_str;
  JsonNode *json;
  size_t sess_id_hexlen;

  sess_id_hexlen = (sess_id_len * 2) + 1;
  sess_id_hex = pcalloc(p, sess_id_hexlen);

  for (i = 0; i < sess_id_len; i++) {
    sprintf((char *) &(sess_id_hex[i*2]), "%02X", sess_id[i]);
  }

  json = json_mkobject();
  json_append_member(json, "id", json_mkstring(sess_id_hex));

  json_str = json_stringify(json, "");

  /* Include the terminating NUL in the key. */
  *keysz = strlen(json_str) + 1;
  *key = pstrndup(p, json_str, *keysz - 1);
  free(json_str);
  json_delete(json);

  return 0;
}

static int tls_mcache_get_key(pool *p, unsigned char *sess_id,
    unsigned int sess_id_len, void **key, size_t *keysz) {
  int res;
  const char *key_type = "unknown";

  if (tls_mcache_opts & TLS_MCACHE_OPT_USE_JSON) {
    key_type = "JSON";
    res = tls_mcache_get_json_key(p, sess_id, sess_id_len, key, keysz);

  } else {
    key_type = "TPL";
    res = tls_mcache_get_tpl_key(p, sess_id, sess_id_len, key, keysz);
  }

  if (res < 0) {
    pr_trace_msg(trace_channel, 3,
      "error constructing cache %s lookup key for session ID (%lu bytes)",
      key_type, (unsigned long) keysz);
    return -1;
  }

  return 0;
}

static int tls_mcache_entry_decode_tpl(pool *p, void *value, size_t valuesz,
    struct mcache_entry *me) {
  int res;
  tpl_node *tn;

  tn = tpl_map(TLS_MCACHE_TPL_VALUE_FMT, me, TLS_MAX_SSL_SESSION_SIZE);
  if (tn == NULL) {
    tls_log(MOD_TLS_MEMCACHE_VERSION
      ": error allocating tpl_map for format '%s'", TLS_MCACHE_TPL_VALUE_FMT);
    errno = ENOMEM;
    return -1;
  }

  res = tpl_load(tn, TPL_MEM, value, valuesz);
  if (res < 0) {
    pr_trace_msg(trace_channel, 3, "%s",
      "error loading TPL memcache session data");
    tpl_free(tn);
    errno = EINVAL;
    return -1;
  }

  res = tpl_unpack(tn, 0);
  if (res < 0) {
    pr_trace_msg(trace_channel, 3, "%s",
      "error unpacking TPL memcache session data");
    tpl_free(tn);
    errno = EINVAL;
    return -1;
  }

  tpl_free(tn);

  return 0;
}

static int tls_mcache_entry_decode_json(pool *p, void *value, size_t valuesz,
    struct mcache_entry *me) {
  JsonNode *field, *json;
  const char *json_str, *key;

  json_str = value;
  if (json_validate(json_str) == FALSE) {
    tls_log(MOD_TLS_MEMCACHE_VERSION
      ": unable to decode invalid JSON cache entry: '%s'", json_str);
    errno = EINVAL;
    return -1;
  }

  json = json_decode(json_str);

  key = TLS_MCACHE_JSON_KEY_EXPIRES;
  field = json_find_member(json, key);
  if (field != NULL) {
    if (field->tag == JSON_NUMBER) {
      me->expires = (uint32_t) field->number_;

    } else {
      pr_trace_msg(trace_channel, 3,
       "ignoring non-number '%s' JSON field in '%s'", key, json_str);
      json_delete(json);
      errno = EINVAL;
      return -1;
    }

  } else {
    tls_log(MOD_TLS_MEMCACHE_VERSION
      ": missing required '%s' JSON field in '%s'", key, json_str);
    json_delete(json);
    errno = EINVAL;
    return -1;
  }

  key = TLS_MCACHE_JSON_KEY_DATA;
  field = json_find_member(json, key);
  if (field != NULL) {
    if (field->tag == JSON_STRING) {
      int have_padding = FALSE, res;
      char *base64_data;
      size_t base64_datalen;
      unsigned char *data;

      base64_data = pstrdup(p, field->string_);
      if (base64_data == NULL) {
        tls_log(MOD_TLS_MEMCACHE_VERSION
          ": invalid/empty '%s' JSON key in '%s', rejecting cache entry",
          key, json_str);
        json_delete(json);
        errno = EINVAL;
        return -1;
      }

      base64_datalen = strlen(base64_data);

      /* Due to Base64's padding, we need to detect if the last block was
       * padded with zeros; we do this by looking for '=' characters at the
       * end of the text being decoded.  If we see these characters, then we
       * will "trim" off any trailing zero values in the decoded data, on the
       * ASSUMPTION that they are the auto-added padding bytes.
       */
      if (base64_data[base64_datalen-1] == '=') {
        have_padding = TRUE;
      }

      data = me->sess_data;
      res = EVP_DecodeBlock(data, (unsigned char *) base64_data,
        (int) base64_datalen);
      if (res <= 0) {
        /* Base64-decoding error. */
        pr_trace_msg(trace_channel, 5,
          "error base64-decoding session data in '%s', rejecting", json_str);
        errno = EINVAL;
        return -1;
      }

      if (have_padding) {
        /* Assume that only one or two zero bytes of padding were added. */
        if (data[res-1] == '\0') {
          res -= 1;

          if (data[res-1] == '\0') {
            res -= 1;
          }
        }
      }

    } else {
      pr_trace_msg(trace_channel, 3,
       "ignoring non-string '%s' JSON field in '%s'", key, json_str);
      json_delete(json);
      errno = EINVAL;
      return -1;
    }

  } else {
    tls_log(MOD_TLS_MEMCACHE_VERSION
      ": missing required '%s' JSON field in '%s'", key, json_str);
    json_delete(json);
    errno = EINVAL;
    return -1;
  }

  key = TLS_MCACHE_JSON_KEY_DATA_LENGTH;
  field = json_find_member(json, key);
  if (field != NULL) {
    if (field->tag == JSON_NUMBER) {
      me->sess_datalen = (unsigned int) field->number_;

    } else {
      pr_trace_msg(trace_channel, 3,
       "ignoring non-number '%s' JSON field in '%s'", key, json_str);
      json_delete(json);
      errno = EINVAL;
      return -1;
    }

  } else {
    tls_log(MOD_TLS_MEMCACHE_VERSION
      ": missing required '%s' JSON field in '%s'", key, json_str);
    json_delete(json);
    errno = EINVAL;
    return -1;
  }

  json_delete(json);
  return 0;
}

static int tls_mcache_entry_get(pool *p, unsigned char *sess_id,
    unsigned int sess_id_len, struct mcache_entry *me) {
  int res;
  void *key = NULL, *value = NULL;
  size_t keysz = 0, valuesz = 0;
  uint32_t flags = 0;

  res = tls_mcache_get_key(p, sess_id, sess_id_len, &key, &keysz);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1,
      "unable to get cache entry: error getting cache key: %s",
      strerror(errno));

    return -1;
  }

  value = pr_memcache_kget(mcache, &tls_memcache_module, (const char *) key,
    keysz, &valuesz, &flags);
  if (value == NULL) {
    pr_trace_msg(trace_channel, 3,
      "no matching memcache entry found for session ID (%lu bytes)",
      (unsigned long) keysz);
    errno = ENOENT;
    return -1;
  }

  /* Decode the cached session data. */
  if (tls_mcache_opts & TLS_MCACHE_OPT_USE_JSON) {
    res = tls_mcache_entry_decode_json(p, value, valuesz, me);

  } else {
    res = tls_mcache_entry_decode_tpl(p, value, valuesz, me);
  }

  if (res == 0) {
    time_t now;

    /* Check for expired cache entries. */
    time(&now);

    if (me->expires <= now) {
      pr_trace_msg(trace_channel, 4,
        "ignoring expired cached session data (expires %lu <= now %lu)",
        (unsigned long) me->expires, (unsigned long) now);
      errno = EPERM;
      return -1;
    }

    pr_trace_msg(trace_channel, 9, "retrieved session data from cache using %s",
      tls_mcache_opts & TLS_MCACHE_OPT_USE_JSON ? "JSON" : "TPL");
  }

  return 0;
}

static int tls_mcache_entry_delete(pool *p, unsigned char *sess_id,
    unsigned int sess_id_len) {
  int res;
  void *key = NULL;
  size_t keysz = 0;

  res = tls_mcache_get_key(p, sess_id, sess_id_len, &key, &keysz);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1,
      "unable to remove cache entry: error getting cache key: %s",
      strerror(errno));

    return -1;
  }

  res = pr_memcache_kremove(mcache, &tls_memcache_module, (const char *) key,
    keysz, 0);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "unable to remove memcache entry for session ID (%lu bytes): %s",
      (unsigned long) keysz, strerror(xerrno));

    errno = xerrno;
    return -1;
  }
 
  return 0; 
}

static int tls_mcache_entry_encode_tpl(pool *p, void **value, size_t *valuesz,
    struct mcache_entry *me) {
  int res;
  tpl_node *tn;
  void *ptr = NULL;

  tn = tpl_map(TLS_MCACHE_TPL_VALUE_FMT, me, TLS_MAX_SSL_SESSION_SIZE);
  if (tn == NULL) {
    pr_trace_msg(trace_channel, 1,
      "error allocating tpl_map for format '%s'", TLS_MCACHE_TPL_VALUE_FMT);
    return -1;
  }

  res = tpl_pack(tn, 0);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "%s",
      "error marshalling TPL memcache session data");
    return -1;
  }

  res = tpl_dump(tn, TPL_MEM, &ptr, valuesz);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "%s",
      "error dumping marshalled TPL memcache session data");
    return -1;
  }

  /* Duplicate the value using the given pool, so that we can free up the
   * memory allocated by tpl_dump().
   */
  *value = palloc(p, *valuesz);
  memcpy(*value, ptr, *valuesz);

  tpl_free(tn);
  free(ptr);

  return 0;
}

static int tls_mcache_entry_encode_json(pool *p, void **value, size_t *valuesz,
    struct mcache_entry *me) {
  JsonNode *json;
  pool *tmp_pool;
  char *base64_data = NULL, *json_str;

  json = json_mkobject();
  json_append_member(json, TLS_MCACHE_JSON_KEY_EXPIRES,
    json_mknumber((double) me->expires));

  /* Base64-encode the session data.  Note that EVP_EncodeBlock does
   * NUL-terminate the encoded data.
   */
  tmp_pool = make_sub_pool(p);
  base64_data = pcalloc(tmp_pool, me->sess_datalen * 2);

  EVP_EncodeBlock((unsigned char *) base64_data, me->sess_data,
    (int) me->sess_datalen);
  json_append_member(json, TLS_MCACHE_JSON_KEY_DATA,
    json_mkstring(base64_data));

  json_append_member(json, TLS_MCACHE_JSON_KEY_DATA_LENGTH,
    json_mknumber((double) me->sess_datalen));

  json_str = json_stringify(json, "");
  if (json_str == NULL) {
    destroy_pool(tmp_pool);
    json_delete(json);
    errno = ENOMEM;
    return -1;
  }

  /* Safety check */
  if (json_validate(json_str) == FALSE) {
    pr_trace_msg(trace_channel, 1, "invalid JSON emitted: '%s'", json_str);
    errno = EINVAL;
    return -1;
  }

  /* Include the terminating NUL in the value. */
  *valuesz = strlen(json_str) + 1;
  *value = pstrndup(p, json_str, *valuesz - 1);

  free(json_str);
  json_delete(json);
  destroy_pool(tmp_pool);

  return 0;
}

static int tls_mcache_entry_set(pool *p, unsigned char *sess_id,
    unsigned int sess_id_len, struct mcache_entry *me) {
  int res, xerrno = 0;
  void *key = NULL, *value = NULL;
  size_t keysz = 0, valuesz = 0;
  uint32_t flags = 0;

  /* Encode the SSL session data. */
  if (tls_mcache_opts & TLS_MCACHE_OPT_USE_JSON) {
    res = tls_mcache_entry_encode_json(p, &value, &valuesz, me);

  } else {
    res = tls_mcache_entry_encode_tpl(p, &value, &valuesz, me);
  }

  if (res < 0) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 4, "error %s encoding session data: %s",
      tls_mcache_opts & TLS_MCACHE_OPT_USE_JSON ? "JSON" : "TPL",
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  res = tls_mcache_get_key(p, sess_id, sess_id_len, &key, &keysz);
  xerrno = errno;
  if (res < 0) {
    pr_trace_msg(trace_channel, 1,
      "unable to set cache entry: error getting cache key: %s",
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  res = pr_memcache_kset(mcache, &tls_memcache_module, (const char *) key,
    keysz, value, valuesz, me->expires, flags);
  xerrno = errno;

  if (res < 0) {
    pr_trace_msg(trace_channel, 2,
      "unable to add memcache entry for session ID (%lu bytes): %s",
      (unsigned long) keysz, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  pr_trace_msg(trace_channel, 9, "stored session data in cache using %s",
    tls_mcache_opts & TLS_MCACHE_OPT_USE_JSON ? "JSON" : "TPL");
  return 0;
}

/* Cache implementation callbacks.
 */

static int tls_mcache_open(tls_sess_cache_t *cache, char *info, long timeout) {
  config_rec *c;

  pr_trace_msg(trace_channel, 9, "opening memcache cache %p (info '%s')",
    cache, info ? info : "(none)");

  /* This is a little messy, but necessary. The mod_memcache module does
   * not set the configured list of memcached servers until a connection
   * arrives.  But mod_tls opens its session cache prior to that, when the
   * server is starting up.  Thus we need to set the configured list of
   * memcached servers ourselves.
   */
  c = find_config(main_server->conf, CONF_PARAM, "MemcacheEngine", FALSE);
  if (c != NULL) {
    int engine;

    engine = *((int *) c->argv[0]);
    if (engine == FALSE) {
      pr_trace_msg(trace_channel, 2, "%s",
        "memcache support disabled (see MemcacheEngine directive)");
      errno = EPERM;
      return -1;
    }
  }

  mcache = pr_memcache_conn_new(cache->cache_pool, &tls_memcache_module, 0, 0);
  if (mcache == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error connecting to memcached: %s", strerror(errno));
    errno = EPERM;
    return -1;
  }

  /* Configure a namespace prefix for our memcached keys. */
  if (pr_memcache_conn_set_namespace(mcache, &tls_memcache_module,
      "mod_tls_memcache.sessions.") < 0) {
    pr_trace_msg(trace_channel, 2, 
      "error setting memcache namespace prefix: %s", strerror(errno));
  }

  cache->cache_pool = make_sub_pool(session.pool);
  pr_pool_tag(cache->cache_pool, MOD_TLS_MEMCACHE_VERSION);
  cache->cache_timeout = timeout;

  if (info != NULL &&
      strcasecmp(info, "/json") == 0) {
    tls_mcache_opts |= TLS_MCACHE_OPT_USE_JSON;
  }

  return 0;
}

static int tls_mcache_close(tls_sess_cache_t *cache) {
  pr_trace_msg(trace_channel, 9, "closing memcache cache %p", cache);

  if (cache != NULL &&
      cache->cache_pool != NULL) {

    /* We do NOT destroy the cache_pool here or close the mcache connection;
     * both were created at daemon startup, and should live as long as
     * the daemon lives.
     */

    if (tls_mcache_sess_list != NULL) {
      register unsigned int i;
      struct mcache_large_entry *entries;

      entries = tls_mcache_sess_list->elts;
      for (i = 0; i < tls_mcache_sess_list->nelts; i++) {
        struct mcache_large_entry *entry;

        entry = &(entries[i]);
        if (entry->expires > 0) {
          pr_memscrub(entry->sess_data, entry->sess_datalen);
        }
      }

      clear_array(tls_mcache_sess_list);
    }
  }

  return 0;
}

static int tls_mcache_add_large_sess(tls_sess_cache_t *cache,
    unsigned char *sess_id, unsigned int sess_id_len, time_t expires,
    SSL_SESSION *sess, int sess_len) {
  struct mcache_large_entry *entry = NULL;

  if (sess_len > TLS_MAX_SSL_SESSION_SIZE) {
    const char *exceeds_key = cache_keys[CACHE_KEY_EXCEEDS].key,
      *max_len_key = cache_keys[CACHE_KEY_MAX_LEN].key;
    void *value = NULL;
    size_t valuesz = 0;

    if (pr_memcache_incr(mcache, &tls_memcache_module, exceeds_key,
        1, NULL) < 0) {
      pr_trace_msg(trace_channel, 2,
        "error incrementing '%s' value: %s", exceeds_key, strerror(errno));
    }

    /* XXX Yes, this is subject to race conditions; other proftpd servers
     * might also be modifying this value in memcached.  Oh well.
     */

    value = pr_memcache_get(mcache, &tls_memcache_module, max_len_key,
      &valuesz, NULL);
    if (value != NULL) {
      uint64_t max_len;

      memcpy(&max_len, value, valuesz);
      if (sess_len > max_len) {
        if (pr_memcache_set(mcache, &tls_memcache_module, max_len_key, &max_len,
            sizeof(max_len), 0, 0) < 0) {
          pr_trace_msg(trace_channel, 2,
            "error setting '%s' value: %s", max_len_key, strerror(errno));
        }
      }

    } else {
      pr_trace_msg(trace_channel, 2,
        "error getting '%s' value: %s", max_len_key, strerror(errno));
    }
  }

  if (tls_mcache_sess_list != NULL) {
    register unsigned int i;
    struct mcache_large_entry *entries;
    time_t now;
    int ok = FALSE;

    /* Look for any expired sessions in the list to overwrite/reuse. */
    entries = tls_mcache_sess_list->elts;
    time(&now);
    for (i = 0; i < tls_mcache_sess_list->nelts; i++) {
      entry = &(entries[i]);

      if (entry->expires <= now) {
        /* This entry has expired; clear and reuse its slot. */
        entry->expires = 0;
        pr_memscrub(entry->sess_data, entry->sess_datalen);

        ok = TRUE;
        break;
      }
    }

    if (!ok) {
      /* We didn't find an open slot in the list.  Need to add one. */
      entry = push_array(tls_mcache_sess_list);
    }

  } else {
    tls_mcache_sess_list = make_array(cache->cache_pool, 1,
      sizeof(struct mcache_large_entry));
    entry = push_array(tls_mcache_sess_list);
  }

  entry->expires = expires;
  entry->sess_id_len = sess_id_len;
  entry->sess_id = palloc(cache->cache_pool, sess_id_len);
  memcpy(entry->sess_id, sess_id, sess_id_len);
  entry->sess_datalen = sess_len;
  entry->sess_data = palloc(cache->cache_pool, sess_len);
  i2d_SSL_SESSION(sess, &(entry->sess_data));

  return 0;
}

static int tls_mcache_add(tls_sess_cache_t *cache, unsigned char *sess_id,
    unsigned int sess_id_len, time_t expires, SSL_SESSION *sess) {
  struct mcache_entry entry;
  int sess_len;
  unsigned char *ptr;
  time_t now;

  time(&now);
  pr_trace_msg(trace_channel, 9,
    "adding session to memcache cache %p (expires = %lu, now = %lu)", cache,
    (unsigned long) expires, (unsigned long) now);

  /* First we need to find out how much space is needed for the serialized
   * session data.  There is no known maximum size for SSL session data;
   * this module is currently designed to allow only up to a certain size.
   */
  sess_len = i2d_SSL_SESSION(sess, NULL);
  if (sess_len > TLS_MAX_SSL_SESSION_SIZE) {
    pr_trace_msg(trace_channel, 2,
      "length of serialized SSL session data (%d) exceeds maximum size (%u), "
      "unable to add to shared memcache, adding to list", sess_len,
      TLS_MAX_SSL_SESSION_SIZE);

    /* Instead of rejecting the add here, we add the session to a "large
     * session" list.  Thus the large session would still be cached per process
     * and will not be lost.
     */

    return tls_mcache_add_large_sess(cache, sess_id, sess_id_len, expires,
      sess, sess_len);
  }

  entry.expires = expires;
  entry.sess_datalen = sess_len;
  ptr = entry.sess_data;
  i2d_SSL_SESSION(sess, &ptr);

  if (tls_mcache_entry_set(cache->cache_pool, sess_id, sess_id_len,
      &entry) < 0) {
    pr_trace_msg(trace_channel, 2,
      "error adding session to memcache: %s", strerror(errno));

    /* Add this session to the "large session" list instead as a fallback. */
    return tls_mcache_add_large_sess(cache, sess_id, sess_id_len, expires,
        sess, sess_len);

  } else {
    const char *key = cache_keys[CACHE_KEY_STORES].key;

    if (pr_memcache_incr(mcache, &tls_memcache_module, key, 1, NULL) < 0) {
      pr_trace_msg(trace_channel, 2,
        "error incrementing '%s' value: %s", key, strerror(errno));
    }
  }

  return 0;
}

static SSL_SESSION *tls_mcache_get(tls_sess_cache_t *cache,
    unsigned char *sess_id, unsigned int sess_id_len) {
  struct mcache_entry entry;
  time_t now;
  SSL_SESSION *sess = NULL;

  pr_trace_msg(trace_channel, 9, "getting session from memcache cache %p",
    cache); 

  /* Look for the requested session in the "large session" list first. */
  if (tls_mcache_sess_list != NULL) {
    register unsigned int i;
    struct mcache_large_entry *entries;

    entries = tls_mcache_sess_list->elts;
    for (i = 0; i < tls_mcache_sess_list->nelts; i++) {
      struct mcache_large_entry *large_entry;

      large_entry = &(entries[i]);
      if (large_entry->expires > 0 &&
          large_entry->sess_id_len == sess_id_len &&
          memcmp(large_entry->sess_id, sess_id,
            large_entry->sess_id_len) == 0) {

        now = time(NULL);
        if (large_entry->expires > now) {
          TLS_D2I_SSL_SESSION_CONST unsigned char *ptr;

          ptr = large_entry->sess_data;
          sess = d2i_SSL_SESSION(NULL, &ptr, large_entry->sess_datalen);
          if (sess == NULL) {
            pr_trace_msg(trace_channel, 2,
              "error retrieving session from cache: %s",
              tls_mcache_get_crypto_errors());

          } else {
            break;
          }
        }
      }
    }
  }

  if (sess) {
    return sess;
  }

  if (tls_mcache_entry_get(cache->cache_pool, sess_id, sess_id_len,
      &entry) < 0) {
    return NULL;
  }
 
  now = time(NULL);
  if (entry.expires > now) {
    TLS_D2I_SSL_SESSION_CONST unsigned char *ptr;

    ptr = entry.sess_data;
    sess = d2i_SSL_SESSION(NULL, &ptr, entry.sess_datalen);
    if (sess != NULL) {
      const char *key = cache_keys[CACHE_KEY_HITS].key;

      if (pr_memcache_incr(mcache, &tls_memcache_module, key, 1, NULL) < 0) {
        pr_trace_msg(trace_channel, 2,
          "error incrementing '%s' value: %s", key, strerror(errno));
      }

    } else {
      const char *key = cache_keys[CACHE_KEY_ERRORS].key;

      pr_trace_msg(trace_channel, 2,
        "error retrieving session from cache: %s",
        tls_mcache_get_crypto_errors());

      if (pr_memcache_incr(mcache, &tls_memcache_module, key, 1, NULL) < 0) {
        pr_trace_msg(trace_channel, 2,
          "error incrementing '%s' value: %s", key, strerror(errno));
      }
    }
  }

  if (sess == NULL) {
    const char *key = cache_keys[CACHE_KEY_MISSES].key;

    if (pr_memcache_incr(mcache, &tls_memcache_module, key, 1, NULL) < 0) {
      pr_trace_msg(trace_channel, 2,
        "error incrementing '%s' value: %s", key, strerror(errno));
    }

    errno = ENOENT;
  }

  return sess;
}

static int tls_mcache_delete(tls_sess_cache_t *cache,
    unsigned char *sess_id, unsigned int sess_id_len) {
  const char *key = cache_keys[CACHE_KEY_DELETES].key;
  int res;

  pr_trace_msg(trace_channel, 9, "removing session from memcache cache %p",
    cache);

  /* Look for the requested session in the "large session" list first. */
  if (tls_mcache_sess_list != NULL) {
    register unsigned int i;
    struct mcache_large_entry *entries;

    entries = tls_mcache_sess_list->elts;
    for (i = 0; i < tls_mcache_sess_list->nelts; i++) {
      struct mcache_large_entry *entry;

      entry = &(entries[i]);
      if (entry->sess_id_len == sess_id_len &&
          memcmp(entry->sess_id, sess_id, entry->sess_id_len) == 0) {

        pr_memscrub(entry->sess_data, entry->sess_datalen);
        entry->expires = 0;
        return 0;
      }
    }
  }

  res = tls_mcache_entry_delete(cache->cache_pool, sess_id, sess_id_len);
  if (res < 0) {
    return -1;
  }

  /* Don't forget to update the stats. */

  if (pr_memcache_incr(mcache, &tls_memcache_module, key, 1, NULL) < 0) {
    pr_trace_msg(trace_channel, 2,
      "error incrementing '%s' value: %s", key, strerror(errno));
  }

  return res;
}

static int tls_mcache_clear(tls_sess_cache_t *cache) {
  register unsigned int i;
  int res = 0;

  if (mcache == NULL) {
    pr_trace_msg(trace_channel, 9, "missing required memcached connection");
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 9, "clearing memcache cache %p", cache);

  if (tls_mcache_sess_list != NULL) {
    struct mcache_large_entry *entries;
    
    entries = tls_mcache_sess_list->elts;
    for (i = 0; i < tls_mcache_sess_list->nelts; i++) {
      struct mcache_large_entry *entry;

      entry = &(entries[i]);
      entry->expires = 0;
      pr_memscrub(entry->sess_data, entry->sess_datalen);
    }
  }

  /* XXX iterate through keys, kremoving any "mod_tls_memcache" prefixed keys */

  return res;
}

static int tls_mcache_remove(tls_sess_cache_t *cache) {
  int res;

  pr_trace_msg(trace_channel, 9, "clearing memcache");
  res = tls_mcache_clear(cache);
  /* XXX close memcache conn */

  return res;
}

static int tls_mcache_status(tls_sess_cache_t *cache,
    void (*statusf)(void *, const char *, ...), void *arg, int flags) {
  register unsigned int i;
  pool *tmp_pool;

  pr_trace_msg(trace_channel, 9, "checking memcache cache %p", cache); 

  tmp_pool = make_sub_pool(permanent_pool);

  statusf(arg, "%s", "Memcache SSL session cache provided by "
    MOD_TLS_MEMCACHE_VERSION);
  statusf(arg, "%s", "");
  statusf(arg, "Memcache servers: ");

  for (i = 0; cache_keys[i].key != NULL; i++) {
    const char *key, *desc;
    void *value = NULL;
    size_t valuesz = 0;
    uint32_t stat_flags = 0;

    key = cache_keys[i].key;
    desc = cache_keys[i].desc;

    value = pr_memcache_get(mcache, &tls_memcache_module, key, &valuesz,
      &stat_flags);
    if (value != NULL) {
      uint64_t num = 0;
      memcpy(&num, value, valuesz);
      statusf(arg, "%s: %lu", desc, (unsigned long) num);
    }
  }

  /* XXX run stats on memcached servers? */

#if 0
  if (flags & TLS_SESS_CACHE_STATUS_FL_SHOW_SESSIONS) {
    statusf(arg, "%s", "");
    statusf(arg, "%s", "Cached sessions:");

    /* XXX Get keys, looking for our namespace prefix, dump each one */

    /* We _could_ use SSL_SESSION_print(), which is what the sess_id
     * command-line tool does.  The problem is that SSL_SESSION_print() shows
     * too much (particularly, it shows the master secret).  And
     * SSL_SESSION_print() does not support a flags argument to use for
     * specifying which bits of the session we want to print.
     *
     * Instead, we get to do the more dangerous (compatibility-wise) approach
     * of rolling our own printing function.
     */

    for (i = 0; i < 0; i++) {
      struct mcache_entry *entry;

      pr_signals_handle();

      /* XXX Get entries */
      if (entry->expires > 0) {
        SSL_SESSION *sess;
        TLS_D2I_SSL_SESSION_CONST unsigned char *ptr;
        time_t ts;

        ptr = entry->sess_data;
        sess = d2i_SSL_SESSION(NULL, &ptr, entry->sess_datalen); 
        if (sess == NULL) {
          pr_log_pri(PR_LOG_NOTICE, MOD_TLS_MEMCACHE_VERSION
            ": error retrieving session from cache: %s",
            tls_mcache_get_crypto_errors());
          continue;
        }

        statusf(arg, "%s", "  -----BEGIN SSL SESSION PARAMETERS-----");

        /* XXX Directly accessing these fields cannot be a Good Thing. */
        if (sess->session_id_length > 0) {
          register unsigned int j;
          char *sess_id_str;

          sess_id_str = pcalloc(tmp_pool, (sess->session_id_length * 2) + 1);

          for (j = 0; j < sess->session_id_length; j++) {
            sprintf((char *) &(sess_id_str[j*2]), "%02X", sess->session_id[j]);
          }

          statusf(arg, "    Session ID: %s", sess_id_str);
        }

        if (sess->sid_ctx_length > 0) {
          register unsigned int j;
          char *sid_ctx_str;

          sid_ctx_str = pcalloc(tmp_pool, (sess->sid_ctx_length * 2) + 1);

          for (j = 0; j < sess->sid_ctx_length; j++) {
            sprintf((char *) &(sid_ctx_str[j*2]), "%02X", sess->sid_ctx[j]);
          }

          statusf(arg, "    Session ID Context: %s", sid_ctx_str);
        }

        switch (sess->ssl_version) {
          case SSL3_VERSION:
            statusf(arg, "    Protocol: %s", "SSLv3");
            break;

          case TLS1_VERSION:
            statusf(arg, "    Protocol: %s", "TLSv1");
            break;

          default:
            statusf(arg, "    Protocol: %s", "unknown");
        }

        ts = SSL_SESSION_get_time(sess);
        statusf(arg, "    Started: %s", pr_strtime(ts));
        ts = entry->expires;
        statusf(arg, "    Expires: %s (%u secs)", pr_strtime(ts),
          SSL_SESSION_get_timeout(sess));

        SSL_SESSION_free(sess);
        statusf(arg, "%s", "  -----END SSL SESSION PARAMETERS-----");
        statusf(arg, "%s", "");
      }
    }
  }
#endif

  destroy_pool(tmp_pool);
  return 0;
}

/* Event Handlers
 */

#if defined(PR_SHARED_MODULE)
static void tls_mcache_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_tls_memcache.c", (const char *) event_data) == 0) {
    pr_event_unregister(&tls_memcache_module, NULL, NULL);
    tls_sess_cache_unregister("memcache");
  }
}
#endif /* !PR_SHARED_MODULE */

/* Initialization functions
 */

static int tls_mcache_init(void) {
#if defined(PR_SHARED_MODULE)
  pr_event_register(&tls_memcache_module, "core.module-unload",
    tls_mcache_mod_unload_ev, NULL);
#endif /* !PR_SHARED_MODULE */

  /* Prepare our cache handler. */
  memset(&tls_mcache, 0, sizeof(tls_mcache));

  tls_mcache.cache_name = "memcache";
  tls_mcache.cache_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(tls_mcache.cache_pool, MOD_TLS_MEMCACHE_VERSION);

  tls_mcache.open = tls_mcache_open;
  tls_mcache.close = tls_mcache_close;
  tls_mcache.add = tls_mcache_add;
  tls_mcache.get = tls_mcache_get;
  tls_mcache.delete = tls_mcache_delete;
  tls_mcache.clear = tls_mcache_clear;
  tls_mcache.remove = tls_mcache_remove;
  tls_mcache.status = tls_mcache_status;

#ifdef SSL_SESS_CACHE_NO_INTERNAL
  /* Take a chance, and inform OpenSSL that it does not need to use its own
   * internal session cache lookups/storage; using the external session cache
   * (i.e. us) will be enough.
   */
  tls_mcache.cache_mode = SSL_SESS_CACHE_NO_INTERNAL;
#endif

#ifdef PR_USE_MEMCACHE
  /* Register ourselves with mod_tls. */
  if (tls_sess_cache_register("memcache", &tls_mcache) < 0) {
    pr_log_debug(DEBUG1, MOD_TLS_MEMCACHE_VERSION
      ": notice: error registering 'memcache' SSL session cache: %s",
      strerror(errno));
    return -1;
  }
#else
  pr_log_debug(DEBUG1, MOD_TLS_MEMCACHE_VERSION
    ": unable to register 'memcache' SSL session cache: Memcache support not enabled");
#endif /* PR_USE_MEMCACHE */

  return 0;
}

static int tls_mcache_sess_init(void) {
  if (mcache != NULL) {
    /* Reset our memcache handle. */
    if (pr_memcache_conn_clone(session.pool, mcache) < 0) {
      tls_log(MOD_TLS_MEMCACHE_VERSION
        ": error resetting memcache handle: %s", strerror(errno));
    }
  }

  return 0;
}

/* Module API tables
 */

module tls_memcache_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "tls_memcache",

  /* Module configuration handler table */
  NULL,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  tls_mcache_init,

  /* Session initialization function */
  tls_mcache_sess_init,

  /* Module version */
  MOD_TLS_MEMCACHE_VERSION
};
