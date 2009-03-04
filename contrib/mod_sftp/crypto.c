/*
 * ProFTPD - mod_sftp OpenSSL interface
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
 * $Id: crypto.c,v 1.3 2009-03-04 17:41:45 castaglia Exp $
 */

#include "mod_sftp.h"
#include "crypto.h"

#if OPENSSL_VERSION_NUMBER > 0x000907000L
static const char *crypto_engine = NULL;
#endif

struct sftp_cipher {
  const char *name;
  const char *openssl_name;

  /* Used mostly for the RC4/ArcFour algorithms, for mitigating attacks
   * based on the first N bytes of the keystream.
   */
  size_t discard_len;

#if OPENSSL_VERSION_NUMBER > 0x000907000L
  const EVP_CIPHER *(*get_type)(void);
#else
  EVP_CIPHER *(*get_type)(void);
#endif

  /* Is this cipher enabled by default?  (If FALSE, then this cipher must
   * be explicitly requested via SFTPCiphers.
   */
  int enabled;
};

/* Currently, OpenSSL does NOT support AES CTR modes (not sure why).
 * Until then, we have to provide our own CTR code, for some of the ciphers
 * recommended by RFC4344.
 *
 * And according to:
 *
 *   http://www.cpni.gov.uk/Docs/Vulnerability_Advisory_SSH.txt
 *
 * it is highly recommended to use CTR mode ciphers, rather than CBC mode,
 * in order to avoid leaking plaintext.
 */

static struct sftp_cipher ciphers[] = {
#if OPENSSL_VERSION_NUMBER > 0x000907000L
  /* XXX The handling of the openssl_name and get_type fields is done in
   * sftp_crypto_get_cipher(), as special cases.
   */
  { "aes256-ctr",	NULL,		0,	NULL,			TRUE },
  { "aes192-ctr",	NULL,		0,	NULL,			TRUE },
  { "aes128-ctr",	NULL,		0,	NULL,			TRUE },

  { "aes256-cbc",	"aes-256-cbc",	0,	EVP_aes_256_cbc,	TRUE },
  { "aes192-cbc",	"aes-192-cbc",	0,	EVP_aes_192_cbc,	TRUE },
  { "aes128-cbc",	"aes-128-cbc",	0,	EVP_aes_128_cbc,	TRUE },
#endif
  { "blowfish-cbc",	"bf-cbc",	0,	EVP_bf_cbc,		TRUE },
  { "cast128-cbc",	"cast5-cbc",	0,	EVP_cast5_cbc,		TRUE },
  { "arcfour256",	"rc4",		1536,	EVP_rc4,		TRUE },
  { "arcfour128",	"rc4",		1536,	EVP_rc4,		TRUE },

#if 0
  /* This cipher is explicitly NOT supported because it does not discard
   * the first N bytes of the keystream, unlike the other RC4 ciphers.
   *
   * If there is a hue and cry, I might add this to the code BUT it would
   * require explicit configuration via SFTPCiphers, and would generate
   * warnings about its unsafe use.
   */
  { "arcfour",		"rc4",		0,	EVP_rc4,		FALSE },
#endif

  { "3des-cbc",		"des-ede3-cbc",	0,	EVP_des_ede3_cbc,	TRUE },
  { "none",		"null",		0,	EVP_enc_null,		FALSE },
  { NULL, NULL, 0, NULL, FALSE }
};

struct sftp_digest {
  const char *name;
  const char *openssl_name;

#if OPENSSL_VERSION_NUMBER > 0x000907000L
  const EVP_MD *(*get_type)(void);
#else
  EVP_MD *(*get_type)(void);
#endif

  uint32_t mac_len;

  /* Is this MAC enabled by default?  (If FALSE, then this MAC must be
   * explicitly requested via SFTPDigests.
   */
  int enabled;
};

static struct sftp_digest digests[] = {
  { "hmac-sha1",	"sha1",		EVP_sha1,	0,	TRUE },
  { "hmac-sha1-96",	"sha1",		EVP_sha1,	12,	TRUE },
  { "hmac-md5",		"md5",		EVP_md5,	0,	TRUE },
  { "hmac-md5-96",	"md5",		EVP_md5,	12,	TRUE },
  { "hmac-ripemd160",	"rmd160",	EVP_ripemd160,	0,	TRUE },
  { "none",		"null",		EVP_md_null,	0,	FALSE },
  { NULL, NULL, NULL, 0, FALSE }
};

static const char *trace_channel = "ssh2";

#if OPENSSL_VERSION_NUMBER > 0x000907000L

struct aes_ex {
  AES_KEY key;
  unsigned char counter[AES_BLOCK_SIZE];
  unsigned char enc_counter[AES_BLOCK_SIZE];
  unsigned int num;
};

static int init_aes_ctr(EVP_CIPHER_CTX *ctx, const unsigned char *key,
    const unsigned char *iv, int enc) {
  struct aes_ex *ae;

  ae = EVP_CIPHER_CTX_get_app_data(ctx);
  if (ae == NULL) {

    /* Allocate our data structure. */
    ae = calloc(1, sizeof(struct aes_ex));
    if (ae == NULL) {
      pr_log_pri(PR_LOG_ERR, MOD_SFTP_VERSION ": Out of memory!");
      _exit(1);
    }

    EVP_CIPHER_CTX_set_app_data(ctx, ae);
  }

  if (key != NULL) {
    int nbits;

#if OPENSSL_VERSION_NUMBER == 0x0090805fL
    /* OpenSSL 0.9.8e had a bug where EVP_CIPHER_CTX_key_length() returned
     * the cipher key length rather than the context key length.
     */
    nbits = ctx->key_len * 8;
#else
    nbits = EVP_CIPHER_CTX_key_length(ctx) * 8;
#endif

    AES_set_encrypt_key(key, nbits, &(ae->key));
  }

  if (iv != NULL) {
    memcpy(ae->counter, iv, AES_BLOCK_SIZE);
  }

  return 1;
}

static int cleanup_aes_ctr(EVP_CIPHER_CTX *ctx) {
  struct aes_ex *ae;

  ae = EVP_CIPHER_CTX_get_app_data(ctx);
  if (ae != NULL) {
    pr_memscrub(ae, sizeof(struct aes_ex));
    free(ae);
    EVP_CIPHER_CTX_set_app_data(ctx, NULL);
  }

  return 1;
}

static int do_aes_ctr(EVP_CIPHER_CTX *ctx, unsigned char *dst,
    const unsigned char *src, unsigned int len) {
  struct aes_ex *ae;

  if (len == 0)
    return 1;

  /* Thin wrapper around AES_ctr128_encrypt(). */

  ae = EVP_CIPHER_CTX_get_app_data(ctx);
  if (ae == NULL)
    return 0;
 
  AES_ctr128_encrypt(src, dst, len, &(ae->key), ae->counter, ae->enc_counter,
    &(ae->num));

  return 1;
}

static const EVP_CIPHER *get_aes_cipher(int key_len) {
  static EVP_CIPHER aes_cipher;

  memset(&aes_cipher, 0, sizeof(EVP_CIPHER));

  aes_cipher.nid = NID_undef;
  aes_cipher.block_size = AES_BLOCK_SIZE;
  aes_cipher.iv_len = AES_BLOCK_SIZE;
  aes_cipher.key_len = key_len;
  aes_cipher.init = init_aes_ctr;
  aes_cipher.cleanup = cleanup_aes_ctr;
  aes_cipher.do_cipher = do_aes_ctr;

  aes_cipher.flags = EVP_CIPH_CBC_MODE|EVP_CIPH_VARIABLE_LENGTH|EVP_CIPH_ALWAYS_CALL_INIT|EVP_CIPH_CUSTOM_IV;

  return &aes_cipher;
}
#endif /* OpenSSL older than 0.9.7 */

const EVP_CIPHER *sftp_crypto_get_cipher(const char *name,
    size_t *discard_len) {
  register unsigned int i;

  for (i = 0; ciphers[i].name; i++) {
    if (strcmp(ciphers[i].name, name) == 0) {
      const EVP_CIPHER *cipher;

#if OPENSSL_VERSION_NUMBER > 0x000907000L
      if (strcmp(name, "aes256-ctr") == 0) {
        cipher = get_aes_cipher(32);

      } else if (strcmp(name, "aes192-ctr") == 0) {
        cipher = get_aes_cipher(24);

      } else if (strcmp(name, "aes128-ctr") == 0) {
        cipher = get_aes_cipher(16);

      } else {
        cipher = ciphers[i].get_type();
      }
#else
      cipher = ciphers[i].get_type();
#endif /* OpenSSL older than 0.9.7 */

      if (discard_len)
        *discard_len = ciphers[i].discard_len;

      return cipher;
    }
  }

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "no cipher matching '%s' found", name);
  return NULL;
}

const EVP_MD *sftp_crypto_get_digest(const char *name, uint32_t *mac_len) {
  register unsigned int i;

  for (i = 0; digests[i].name; i++) {
    if (strcmp(digests[i].name, name) == 0) {
      const EVP_MD *digest = digests[i].get_type();
      if (mac_len) {
        *mac_len = digests[i].mac_len;
      }

      return digest;
    }
  }

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "no digest matching '%s' found", name);
  return NULL;
}

const char *sftp_crypto_get_kexinit_cipher_list(pool *p) {
  char *res = "";
  config_rec *c;

  /* Make sure that OpenSSL can use these ciphers.  For example, in FIPS mode,
   * some ciphers cannot be used.  So we should not advertise ciphers that we
   * know we cannot use.
   */

  c = find_config(main_server->conf, CONF_PARAM, "SFTPCiphers", FALSE);
  if (c) {
    register unsigned int i;

    for (i = 0; i < c->argc; i++) {
      register unsigned int j;

      for (j = 0; ciphers[j].name; j++) {
        if (strcmp(c->argv[i], ciphers[j].name) == 0) {
          if (strcmp(c->argv[i], "none") != 0) {
            if (EVP_get_cipherbyname(ciphers[j].openssl_name) != NULL) {
              res = pstrcat(p, res, *res ? "," : "",
                pstrdup(p, ciphers[j].name), NULL);

            } else {
#if OPENSSL_VERSION_NUMBER > 0x000907000L
              /* XXX The AES CTR modes are special cases. */
              if (strcmp(ciphers[j].name, "aes256-ctr") == 0 ||
                  strcmp(ciphers[j].name, "aes192-ctr") == 0 ||
                  strcmp(ciphers[j].name, "aes128-ctr") == 0) {
                res = pstrcat(p, res, *res ? "," : "",
                  pstrdup(p, ciphers[j].name), NULL);
       
              } else {
#endif
                pr_trace_msg(trace_channel, 3,
                  "unable to use '%s' cipher: Unsupported by OpenSSL",
                  ciphers[j].name);

#if OPENSSL_VERSION_NUMBER > 0x000907000L
              }
#endif
            }

          } else {
            res = pstrcat(p, res, *res ? "," : "",
              pstrdup(p, ciphers[j].name), NULL);
          }
        }
      }
    }

  } else {
    register unsigned int i;

    for (i = 0; ciphers[i].name; i++) {
      if (ciphers[i].enabled) {
        if (strcmp(ciphers[i].name, "none") != 0) {
          if (EVP_get_cipherbyname(ciphers[i].openssl_name) != NULL) {
            res = pstrcat(p, res, *res ? "," : "",
              pstrdup(p, ciphers[i].name), NULL);

          } else {
#if OPENSSL_VERSION_NUMBER > 0x000907000L
            /* XXX The AES CTR modes are special cases. */
            if (strcmp(ciphers[i].name, "aes256-ctr") == 0 ||
                strcmp(ciphers[i].name, "aes192-ctr") == 0 ||
                strcmp(ciphers[i].name, "aes128-ctr") == 0) {
              res = pstrcat(p, res, *res ? "," : "",
                pstrdup(p, ciphers[i].name), NULL);

            } else {       
#endif
              pr_trace_msg(trace_channel, 3,
                "unable to use '%s' cipher: Unsupported by OpenSSL",
                ciphers[i].name);

#if OPENSSL_VERSION_NUMBER > 0x000907000L
            }
#endif
          }

        } else {
          res = pstrcat(p, res, *res ? "," : "",
            pstrdup(p, ciphers[i].name), NULL);
        }

      } else {
        pr_trace_msg(trace_channel, 3, "unable to use '%s' cipher: "
          "Must be explicitly requested via SFTPCiphers", ciphers[i].name);
      }
    }
  }

  return res;
}

const char *sftp_crypto_get_kexinit_digest_list(pool *p) {
  char *res = "";
  config_rec *c;

  /* Make sure that OpenSSL can use these digests.  For example, in FIPS
   * mode, some digests cannot be used.  So we should not advertise digests
   * that we know we cannot use.
   */

  c = find_config(main_server->conf, CONF_PARAM, "SFTPDigests", FALSE);
  if (c) {
    register unsigned int i;

    for (i = 0; i < c->argc; i++) {
      register unsigned int j;

      for (j = 0; digests[j].name; j++) {
        if (strcmp(c->argv[i], digests[j].name) == 0) {
          if (strcmp(c->argv[i], "none") != 0) {
            if (EVP_get_digestbyname(digests[j].openssl_name) != NULL) {
              res = pstrcat(p, res, *res ? "," : "",
                pstrdup(p, digests[j].name), NULL);

            } else {
              pr_trace_msg(trace_channel, 3,
                "unable to use '%s' digest: Unsupported by OpenSSL",
                digests[j].name);
            }

          } else {
            res = pstrcat(p, res, *res ? "," : "",
              pstrdup(p, digests[j].name), NULL);
          }
        }
      }
    }

  } else {
    register unsigned int i;

    for (i = 0; digests[i].name; i++) {
      if (digests[i].enabled) {
        if (strcmp(digests[i].name, "none") != 0) {
          if (EVP_get_digestbyname(digests[i].openssl_name) != NULL) {
            res = pstrcat(p, res, *res ? "," : "",
              pstrdup(p, digests[i].name), NULL);

          } else {
            pr_trace_msg(trace_channel, 3,
              "unable to use '%s' digest: Unsupported by OpenSSL",
              digests[i].name);
          }

        } else {
          res = pstrcat(p, res, *res ? "," : "",
            pstrdup(p, digests[i].name), NULL);
        }

      } else {
        pr_trace_msg(trace_channel, 3, "unable to use '%s' digest: "
          "Must be explicitly requested via SFTPDigests", digests[i].name);
      }
    }
  }

  return res;
}

const char *sftp_crypto_get_errors(void) {
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
    str = pstrdup(sftp_pool, data);
  }

  if (bio)
    BIO_free(bio);

  return str;
}

/* Try to find the best multiple/block size which accommodates the two given
 * sizes by rounding up.
 */
size_t sftp_crypto_get_size(size_t first, size_t second) {
#ifdef roundup
  return roundup(first, second);
#else
  return (((first + (second - 1)) / second) * second);
#endif /* !roundup */
}

void sftp_crypto_free(int flags) {
#if OPENSSL_VERSION_NUMBER > 0x000907000L
  if (crypto_engine) {
    ENGINE_cleanup();
    crypto_engine = NULL;
  }
#endif

  ERR_free_strings();
  ERR_remove_state(0);
  EVP_cleanup();
}

int sftp_crypto_set_driver(const char *driver) {
#if OPENSSL_VERSION_NUMBER > 0x000907000L
  if (driver == NULL) {
    errno = EINVAL;
    return -1;
  }

  crypto_engine = driver;

  if (strcasecmp(driver, "ALL") == 0) {
    /* Load all ENGINE implementations bundled with OpenSSL. */
    ENGINE_load_builtin_engines();
    ENGINE_register_all_complete();

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "enabled all builtin crypto devices");

  } else {
    ENGINE *e;

    /* Load all ENGINE implementations bundled with OpenSSL. */
    ENGINE_load_builtin_engines();

    e = ENGINE_by_id(driver);
    if (e) {
      if (ENGINE_init(e)) {
        if (ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
          ENGINE_finish(e);
          ENGINE_free(e);

          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "using SFTPCryptoDevice '%s'", driver);

        } else {
          /* The requested driver could not be used as the default for
           * some odd reason.
           */
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "unable to register SFTPCryptoDevice '%s' as the default: %s",
            driver, sftp_crypto_get_errors());

          ENGINE_finish(e);
          ENGINE_free(e);
          e = NULL;
          crypto_engine = NULL;

          errno = EPERM;
          return -1;
        }

      } else {
        /* The requested driver could not be initialized. */
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "unable to initialize SFTPCryptoDevice '%s': %s", driver,
          sftp_crypto_get_errors());

        ENGINE_free(e);
        e = NULL;
        crypto_engine = NULL;

        errno = EPERM;
        return -1;
      }

    } else {
      /* The requested driver is not available. */
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "SFTPCryptoDevice '%s' is not available", driver);

      crypto_engine = NULL;

      errno = EPERM;
      return -1;
    }
  }

  return 0;
#else
  errno = ENOSYS;
  return -1;
#endif
}

