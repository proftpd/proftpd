/*
 * mod_tls - an RFC2228 SSL/TLS module for ProFTPD
 *
 * Copyright (c) 2000-2002 Peter 'Luna' Runestig <peter@runestig.com>
 * Copyright (c) 2002 TJ Saunders <tj@castaglia.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modifi-
 * cation, are permitted provided that the following conditions are met:
 *
 *    o Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *    o Redistributions in binary form must reproduce the above copyright no-
 *      tice, this list of conditions and the following disclaimer in the do-
 *      cumentation and/or other materials provided with the distribution.
 *
 *    o The names of the contributors may not be used to endorse or promote
 *      products derived from this software without specific prior written
 *      permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LI-
 * ABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUEN-
 * TIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEV-
 * ER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABI-
 * LITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  --- DO NOT DELETE BELOW THIS LINE ----
 *  $Libraries: -lssl -lcrypto$
 */

#include "conf.h"
#include "privs.h"

#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define MOD_TLS_VERSION		"mod_tls/2.0.5"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001020801 
# error "ProFTPD 1.2.8rc1 or later required"
#endif

extern session_t session;

/* DH parameters */
static unsigned char dh512_p[] = {
  0xC0,0xC5,0x23,0x8D,0x3A,0xB3,0xA3,0x63,0x57,0xC0,0xD3,0xFE,
  0xD4,0xC2,0x8F,0x17,0x0E,0x7A,0xDB,0x8E,0x3B,0xB6,0xA5,0xC2,
  0x60,0x7D,0xE7,0x03,0xCC,0xA3,0x10,0xCC,0x82,0x39,0x3C,0x68,
  0xA0,0x82,0x9C,0x7A,0x4A,0x96,0x8C,0xB0,0x1A,0xB4,0xB8,0xA0,
  0x9E,0x64,0x9D,0x40,0x77,0x8A,0x9C,0x97,0x96,0x69,0x3D,0xCA,
  0xA8,0x25,0xAE,0xAB,
};

static unsigned char dh512_g[] = {
  0x02,
};

static DH *get_dh512(void) {
  DH *dh;

  if ((dh = DH_new()) == NULL)
    return NULL;

  dh->p = BN_bin2bn(dh512_p, sizeof(dh512_p), NULL);
  dh->g = BN_bin2bn(dh512_g, sizeof(dh512_g), NULL);

  if ((dh->p == NULL) || (dh->g == NULL))
    return NULL;

  return dh;
}

/*    
-----BEGIN DH PARAMETERS-----
MEYCQQDAxSONOrOjY1fA0/7Uwo8XDnrbjju2pcJgfecDzKMQzII5PGiggpx6SpaM
sBq0uKCeZJ1Ad4qcl5ZpPcqoJa6rAgEC
-----END DH PARAMETERS-----
*/

static unsigned char dh768_p[] = {
  0xB3,0x95,0x74,0xCE,0x0B,0xFD,0xAB,0xC3,0x53,0x9B,0x0B,0xFD,
  0x6E,0xB2,0x64,0x64,0x02,0xDD,0xFF,0x2E,0x77,0xEB,0x0D,0x6C,
  0xCE,0x04,0x2C,0x8E,0x5A,0xA7,0x96,0x45,0x54,0xA6,0x2F,0xBC,
  0xF9,0x77,0x1C,0x50,0x66,0x8E,0x48,0xA8,0x34,0xF0,0x81,0xDD,
  0x5B,0x5A,0xD4,0xA6,0x13,0x89,0x60,0x46,0x05,0x65,0x57,0x2C,
  0x1E,0x94,0x57,0x3C,0x3E,0x38,0xA6,0xFE,0x7B,0x03,0x7D,0x16,
  0x46,0xF6,0xB3,0x21,0x3C,0x44,0xF1,0xF1,0x90,0xCE,0x40,0x93,
  0x4B,0xE6,0xD6,0x0E,0x20,0x85,0xDA,0x9B,0x3F,0x5C,0x1F,0xDB,
};

static unsigned char dh768_g[] = {
  0x02,
};

static DH *get_dh768(void) {
  DH *dh;

  if ((dh = DH_new()) == NULL)
    return NULL;

  dh->p = BN_bin2bn(dh768_p, sizeof(dh768_p), NULL);
  dh->g = BN_bin2bn(dh768_g, sizeof(dh768_g), NULL);

  if ((dh->p == NULL) || (dh->g == NULL))
    return NULL;

  return dh;
}

/*
-----BEGIN DH PARAMETERS-----
MGYCYQCzlXTOC/2rw1ObC/1usmRkAt3/LnfrDWzOBCyOWqeWRVSmL7z5dxxQZo5I
qDTwgd1bWtSmE4lgRgVlVywelFc8Pjim/nsDfRZG9rMhPETx8ZDOQJNL5tYOIIXa
mz9cH9sCAQI=
-----END DH PARAMETERS-----
*/

static unsigned char dh1024_p[] = {
  0xC1,0xD8,0x9C,0x90,0xB1,0x58,0x7C,0xE1,0x56,0x70,0xD7,0x61,
  0x6C,0x00,0xE6,0xE7,0x99,0x04,0x9F,0x86,0xD9,0xB4,0x11,0x09,
  0x23,0x18,0xAA,0x19,0xCA,0x49,0x7C,0xA8,0x9D,0xF7,0x43,0x3A,
  0xAF,0xC3,0x1F,0x0E,0xAE,0xBB,0xF2,0xEA,0x5B,0x62,0xA1,0x5F,
  0x7C,0x26,0xA8,0xB4,0x5D,0x2A,0x25,0xAB,0x88,0x70,0x27,0x06,
  0xD0,0xF5,0x01,0xD9,0x6A,0x1F,0x48,0x2D,0x9C,0xEC,0xFE,0xA8,
  0x45,0x97,0x1D,0xC0,0x8A,0xFF,0xE5,0xE1,0x79,0xDF,0x85,0x31,
  0xFC,0x58,0x91,0x35,0xE8,0xC7,0xDA,0x55,0x7B,0xAA,0xDD,0xC2,
  0x0A,0x94,0x34,0xF7,0xB4,0x4A,0x91,0x3B,0x1E,0x16,0x89,0x2A,
  0x04,0x47,0x5D,0xE9,0x42,0x47,0x5E,0x30,0x61,0xE8,0x42,0xC1,
  0x23,0xC7,0x97,0x78,0x63,0x36,0x9D,0x3B,
};

static unsigned char dh1024_g[]={
  0x02,
};

static DH *get_dh1024(void) {
  DH *dh;

  if ((dh = DH_new()) == NULL)
    return NULL;

  dh->p = BN_bin2bn(dh1024_p, sizeof(dh1024_p), NULL);
  dh->g = BN_bin2bn(dh1024_g, sizeof(dh1024_g), NULL);

  if ((dh->p == NULL) || (dh->g == NULL))
    return NULL;

  return(dh);
}
/*
-----BEGIN DH PARAMETERS-----
MIGHAoGBAMHYnJCxWHzhVnDXYWwA5ueZBJ+G2bQRCSMYqhnKSXyonfdDOq/DHw6u
u/LqW2KhX3wmqLRdKiWriHAnBtD1AdlqH0gtnOz+qEWXHcCK/+Xhed+FMfxYkTXo
x9pVe6rdwgqUNPe0SpE7HhaJKgRHXelCR14wYehCwSPHl3hjNp07AgEC
-----END DH PARAMETERS-----
*/

static unsigned char dh1536_p[] = {
  0xDA,0x68,0x25,0x7F,0x9D,0xB5,0x3F,0x42,0x05,0xBC,0x79,0x65,
  0x6F,0x19,0x6A,0x6F,0x70,0x11,0x91,0xF2,0x08,0x48,0x2B,0xE2,
  0x0C,0x15,0xD9,0x31,0xE7,0x3A,0x50,0x32,0x9F,0xFB,0xD6,0x56,
  0xFA,0xB4,0xA9,0x5F,0x22,0x17,0x52,0x72,0x2C,0xE3,0x5D,0xA1,
  0xA8,0xEF,0x16,0x42,0x35,0xC6,0xD9,0x64,0xC1,0xB3,0xB3,0x4C,
  0x09,0x90,0xF4,0x49,0xEF,0xDE,0x64,0x99,0xFF,0x3C,0x37,0x0A,
  0x91,0xA4,0x9E,0x38,0x27,0xF2,0x96,0x13,0x1E,0x15,0xA2,0x52,
  0xF1,0x54,0x0C,0xED,0x5C,0x38,0xC4,0xEC,0xFF,0xE2,0xFA,0x0A,
  0x41,0xBB,0x48,0x5D,0xD3,0x54,0xA1,0xEB,0xBD,0x1F,0x68,0xED,
  0x2A,0x49,0x7F,0x68,0x52,0xB3,0xA0,0x77,0x3E,0x19,0xFB,0x44,
  0xCD,0x4B,0x21,0x3E,0x3B,0xBA,0xF6,0xA2,0x36,0x37,0xE5,0xFA,
  0x95,0xB0,0x7D,0x7B,0x58,0x96,0xC4,0xC9,0xC0,0xCF,0xD9,0x3F,
  0xA3,0x42,0x0B,0xD7,0xBE,0x1A,0xA8,0xB5,0x57,0x58,0xF4,0x04,
  0x97,0x54,0xB0,0x59,0x23,0x5F,0x98,0x09,0x90,0xC0,0x49,0x85,
  0x40,0x23,0x2D,0x21,0x3E,0xB0,0x07,0x06,0x07,0x32,0xFB,0xB9,
  0x91,0x40,0x92,0x09,0xED,0x07,0x80,0x05,0x14,0x5B,0xC1,0x9B,
};

static unsigned char dh1536_g[] = {
  0x02,
};

static DH *get_dh1536(void) {
  DH *dh;

  if ((dh = DH_new()) == NULL)
    return NULL;

  dh->p = BN_bin2bn(dh1536_p, sizeof(dh1536_p), NULL);
  dh->g = BN_bin2bn(dh1536_g, sizeof(dh1536_g), NULL);

  if ((dh->p == NULL) || (dh->g == NULL))
    return NULL;

  return dh;
}

/*
-----BEGIN DH PARAMETERS-----
MIHHAoHBANpoJX+dtT9CBbx5ZW8Zam9wEZHyCEgr4gwV2THnOlAyn/vWVvq0qV8i
F1JyLONdoajvFkI1xtlkwbOzTAmQ9Env3mSZ/zw3CpGknjgn8pYTHhWiUvFUDO1c
OMTs/+L6CkG7SF3TVKHrvR9o7SpJf2hSs6B3Phn7RM1LIT47uvaiNjfl+pWwfXtY
lsTJwM/ZP6NCC9e+Gqi1V1j0BJdUsFkjX5gJkMBJhUAjLSE+sAcGBzL7uZFAkgnt
B4AFFFvBmwIBAg==
-----END DH PARAMETERS-----
*/

static unsigned char dh2048_p[] = {
  0xD0,0xE6,0xFF,0x1F,0x39,0xE0,0xCC,0x85,0xAC,0xA4,0xE6,0xDD,
  0x06,0xE5,0x2D,0xBF,0xEA,0x64,0x2E,0xC7,0x99,0x8A,0x0F,0xCB,
  0x3C,0x9D,0xEE,0xAC,0x61,0xFF,0x69,0x31,0x71,0xFE,0x2F,0x7B,
  0x65,0x95,0xA0,0xA4,0x59,0xB8,0xE3,0x66,0x5B,0x3F,0xD8,0x42,
  0x99,0x4F,0x09,0x44,0xC5,0x8D,0x8B,0x5D,0x16,0xAA,0x05,0x6E,
  0x8B,0x11,0x59,0x1F,0xD7,0x11,0x84,0x87,0x4D,0xBE,0xBB,0xBA,
  0x9A,0xF0,0xC3,0xE2,0x0E,0xB8,0x0F,0xFD,0x08,0xB1,0x48,0x98,
  0xDE,0x89,0xDA,0x00,0x15,0x04,0xA4,0x51,0xBE,0x5B,0x60,0x0A,
  0x0E,0x20,0xAC,0xC5,0x83,0x5D,0xC4,0x0F,0xA3,0x8E,0x11,0x66,
  0x2C,0xD3,0x61,0x5F,0x16,0x83,0xAA,0xCF,0x52,0x9C,0x7D,0x75,
  0xEA,0xCA,0x67,0xA3,0xAB,0x58,0x9F,0x67,0x17,0xA0,0x54,0x3A,
  0x2B,0xCA,0xB5,0x03,0x7E,0x50,0xBD,0x99,0x1E,0xEF,0xB2,0x8F,
  0xB4,0xFB,0xD2,0x2D,0x6A,0xA9,0xA2,0xC0,0xD4,0xD2,0x68,0x6C,
  0x21,0x71,0x78,0x75,0x82,0x4C,0xD8,0xE8,0x2C,0x0B,0xC9,0x3F,
  0xF6,0xF0,0x64,0xD9,0x6E,0x76,0xCB,0xBB,0x99,0xFB,0xBC,0x15,
  0x54,0x7B,0x7F,0x97,0x36,0x8F,0x0B,0x1C,0xFF,0xDD,0x28,0x99,
  0xE5,0x3A,0xAD,0xCD,0x84,0xAB,0xA1,0xEF,0xB2,0x21,0xEA,0xD6,
  0x49,0x22,0x6A,0x30,0x6A,0x63,0x2E,0x52,0x79,0xCF,0xBC,0xC2,
  0xB6,0x2E,0xA5,0x5D,0xB3,0xDA,0xC2,0xDD,0x02,0xEA,0x26,0x2F,
  0x3B,0x0A,0x12,0xBB,0xA2,0xEF,0x2B,0xFA,0xCC,0x25,0x63,0x1B,
  0xC3,0x00,0x18,0x8F,0x36,0xB7,0x30,0x5A,0x55,0x1A,0xE0,0x12,
  0xA1,0xD2,0x9C,0x93,
};

static unsigned char dh2048_g[] = {
  0x02,
};

static DH *get_dh2048(void) {
  DH *dh;

  if ((dh = DH_new()) == NULL)
    return NULL;

  dh->p = BN_bin2bn(dh2048_p, sizeof(dh2048_p), NULL);
  dh->g = BN_bin2bn(dh2048_g, sizeof(dh2048_g), NULL);

  if ((dh->p == NULL) || (dh->g == NULL))
    return NULL;

  return dh;
}

/*
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA0Ob/HzngzIWspObdBuUtv+pkLseZig/LPJ3urGH/aTFx/i97ZZWg
pFm442ZbP9hCmU8JRMWNi10WqgVuixFZH9cRhIdNvru6mvDD4g64D/0IsUiY3ona
ABUEpFG+W2AKDiCsxYNdxA+jjhFmLNNhXxaDqs9SnH116spno6tYn2cXoFQ6K8q1
A35QvZke77KPtPvSLWqposDU0mhsIXF4dYJM2OgsC8k/9vBk2W52y7uZ+7wVVHt/
lzaPCxz/3SiZ5TqtzYSroe+yIerWSSJqMGpjLlJ5z7zCti6lXbPawt0C6iYvOwoS
u6LvK/rMJWMbwwAYjza3MFpVGuASodKckwIBAg==
-----END DH PARAMETERS-----
*/

/* ASN1_BIT_STRING_cmp was renamed in 0.9.5 */
#if OPENSSL_VERSION_NUMBER < 0x00905100L
# define M_ASN1_BIT_STRING_cmp ASN1_BIT_STRING_cmp
#endif

/* From src/dirtree.c */
extern int ServerUseReverseDNS;

module tls_module;

/* Module variables */
static unsigned char tls_engine = FALSE;
static unsigned long tls_flags = 0UL, tls_opts = 0UL;
static int tls_logfd = -1;
static char *tls_logname = NULL;
static char *tls_protocol = NULL;
static unsigned char tls_required_on_ctrl = FALSE;
static unsigned char tls_required_on_data = FALSE;

#define TLS_DEFAULT_CIPHER_SUITE	"ALL:!ADH"
#define TLS_DEFAULT_PROTOCOL		"SSLv23"

/* mod_tls session flags */
#define	TLS_SESS_ON_CTRL		0x0001
#define TLS_SESS_ON_DATA		0x0002
#define TLS_SESS_PBSZ_OK		0x0004
#define TLS_SESS_TLS_REQUIRED		0x0010
#define TLS_SESS_VERIFY_CLIENT		0x0020
#define TLS_SESS_NO_PASSWD_NEEDED	0x0040
#define TLS_SESS_NEED_DATA_PROT		0x0100
#define TLS_SESS_CTRL_RENEGOTIATING	0x0200
#define TLS_SESS_DATA_RENEGOTIATING	0x0400

/* mod_tls option flags */
#define TLS_OPT_NO_CERT_REQUEST		0x0001
#define TLS_OPT_VERIFY_CERT_FQDN	0x0002
#define TLS_OPT_VERIFY_CERT_IP_ADDR	0x0004
#define TLS_OPT_ALLOW_DOT_LOGIN		0x0010
#define TLS_OPT_EXPORT_CERT_DATA	0x0020
#define TLS_OPT_STD_ENV_VARS		0x0040

static char *tls_cipher_suite = NULL;
static char *tls_crl_file = NULL, *tls_crl_path = NULL;
static char *tls_dhparam_file = NULL;
static char *tls_dsa_cert_file = NULL, *tls_dsa_key_file = NULL;
static char *tls_rsa_cert_file = NULL, *tls_rsa_key_file = NULL;
static char *tls_rand_file = NULL;

/* Note: 9 is the default OpenSSL depth. */
static int tls_verify_depth = 9;

#if OPENSSL_VERSION_NUMBER > 0x000907000L
/* Renegotiate control channel SSL sessions after 4 hours, by default. */
static int tls_ctrl_renegotiate_timeout = 14400;

/* Renegotiate data channel SSL sessions after 1 gigabyte, by default. */
static off_t tls_data_renegotiate_limit = 1024 * 1024 * 1024;

/* Timeout given for renegotiations to occur before the SSL session is
 * shutdown.  The default is 30 seconds.
 */
static int tls_renegotiate_timeout = 30;

/* Is client acceptance of a requested renegotiation required? */
static unsigned char tls_renegotiate_required = TRUE;
#endif

static pr_netio_t *tls_ctrl_netio = NULL;
static pr_netio_stream_t *tls_ctrl_rd_nstrm = NULL;
static pr_netio_stream_t *tls_ctrl_wr_nstrm = NULL;

static pr_netio_t *tls_data_netio = NULL;
static pr_netio_stream_t *tls_data_rd_nstrm = NULL;
static pr_netio_stream_t *tls_data_wr_nstrm = NULL;

/* OpenSSL variables */
static SSL *ctrl_ssl = NULL;
static SSL_CTX *ssl_ctx = NULL;
static X509_STORE *crl_store = NULL;
static DH *tls_tmp_dh = NULL;
static RSA *tls_tmp_rsa = NULL;

/* SSL/TLS support functions */
static void tls_closelog(void);
static void tls_end_session(SSL *);
static char *tls_get_subj_name(void);

static int tls_log(const char *, ...)
#ifdef __GNUC__
       __attribute__ ((format (printf, 1, 2)));
#else
       ;
#endif

static int tls_openlog(void);
static RSA *tls_rsa_cb(SSL *, int, int);
static int tls_seed_prng(void);
static void tls_setup_environ(void);
static int tls_verify_cb(int, X509_STORE_CTX *);
static int tls_verify_crl(int, X509_STORE_CTX *);
static char *tls_x509_name_oneline(X509_NAME *);

static unsigned char tls_check_client_cert(SSL *ssl, conn_t *conn) {
  X509 *cert = NULL;
  int nexts = 0;
  unsigned char ok = FALSE, have_dns_ext = FALSE, have_ipaddr_ext = FALSE;

  /* Only perform these more stringent checks if asked to verify clients. */
  if (!(tls_flags & TLS_SESS_VERIFY_CLIENT))
    return TRUE;

  /* Only perform these checks is configured to do so. */
  if (!(tls_opts & TLS_OPT_VERIFY_CERT_FQDN) &&
      !(tls_opts & TLS_OPT_VERIFY_CERT_IP_ADDR))
    return TRUE;

  /* First, check the subjectAltName X509v3 extensions, as is proper, for
   * the IP address and FQDN.  If enough people clamor for backward
   * compatibility, I'll amend this to check commonName later.  Otherwise,
   * for now, only look in the extensions.
   */

  /* Note: this should _never_ return NULL in this case. */
  cert = SSL_get_peer_certificate(ssl);

  if ((nexts = X509_get_ext_count(cert)) > 0) {
    register unsigned int i = 0;

    for (i = 0; i < nexts; i++) {
      X509_EXTENSION *ext = X509_get_ext(cert, i);
      const char *extstr = OBJ_nid2sn(OBJ_obj2nid(
        X509_EXTENSION_get_object(ext)));

      if (!strcmp(extstr, "subjectAltName")) {
        register unsigned int j = 0;
        void *ext_str = NULL;
        STACK_OF(CONF_VALUE) *sk_vals = NULL;
        X509V3_EXT_METHOD *ext_meth = NULL;

        if ((ext_meth = X509V3_EXT_get(ext)) == NULL)
          break;

#if OPENSSL_VERSION_NUMBER > 0x000907000L
        if (ext_meth->it)
          ext_str = ASN1_item_d2i(NULL, &ext->value->data, ext->value->length,
            ASN1_ITEM_ptr(ext_meth->it));
        else
#endif
           ext_str = ext_meth->d2i(NULL, &ext->value->data, ext->value->length);

        sk_vals = ext_meth->i2v(ext_meth, ext_str, NULL);

        for (j = 0; j < sk_CONF_VALUE_num(sk_vals); j++) {
          CONF_VALUE *val = sk_CONF_VALUE_value(sk_vals, j);

          if (tls_opts & TLS_OPT_VERIFY_CERT_FQDN) {
            if (!strcmp(val->name, "DNS")) {
              have_dns_ext = TRUE;

              if (strcmp(val->value, conn->remote_name)) {
                X509_free(cert);
                tls_log("client cert dNSName value '%s' != client FQDN '%s'",
                  val->value, conn->remote_name);
                return FALSE;
              }

              tls_log("%s", "client cert dNSName matches client FQDN");
              ok = TRUE;
              continue;
            }
          }

          if (tls_opts & TLS_OPT_VERIFY_CERT_IP_ADDR) {
            if (!strcmp(val->name, "IP Address")) {
              have_ipaddr_ext = TRUE;

              if (strcmp(val->value, inet_ntoa(*conn->remote_ipaddr))) {
                X509_free(cert);
                tls_log("client cert iPAddress value '%s' != client IP '%s'",
                  val->value, inet_ntoa(*conn->remote_ipaddr));
                return FALSE;
              }

              tls_log("%s", "client cert iPAddress matches client IP"); 
              ok = TRUE;
              continue;
            }
          }
        }

        sk_CONF_VALUE_pop_free(sk_vals, X509V3_conf_free);

#if OPENSSL_VERSION_NUMBER > 0x000907000L
        if (ext_meth->it)
          ASN1_item_free(ext_str, ASN1_ITEM_ptr(ext_meth->it));
        else
#endif
          ext_meth->ext_free(ext_str);
      }
    }
  }

  if ((tls_opts & TLS_OPT_VERIFY_CERT_FQDN) && !have_dns_ext)
    tls_log("%s", "client cert missing required X509v3 subjectAltName dNSName");

  if ((tls_opts & TLS_OPT_VERIFY_CERT_IP_ADDR) && !have_ipaddr_ext)
    tls_log("%s", "client cert missing required X509v3 subjectAltName iPAddress");

  if (!ok)
    return FALSE;

  return TRUE;
}


#if OPENSSL_VERSION_NUMBER > 0x000907000L
static int tls_renegotiate_timeout_cb(CALLBACK_FRAME) {
  if ((tls_flags & TLS_SESS_ON_CTRL) &&
      (tls_flags & TLS_SESS_CTRL_RENEGOTIATING)) {

    if (!SSL_renegotiate_pending(ctrl_ssl)) {
      tls_log("%s", "control channel SSL session renegotiated");
      tls_flags &= ~TLS_SESS_CTRL_RENEGOTIATING;

    } else if (tls_renegotiate_required) {
      tls_log("%s", "requested SSL renegotiation timed out on control channel");
      tls_log("%s", "shutting down control channel SSL session");
      tls_end_session(ctrl_ssl);
      tls_ctrl_rd_nstrm->strm_data = tls_ctrl_wr_nstrm->strm_data =
        ctrl_ssl = NULL;
    }
  }

  if ((tls_flags & TLS_SESS_ON_DATA) &&
      (tls_flags & TLS_SESS_DATA_RENEGOTIATING)) {

    if (!SSL_renegotiate_pending((SSL *) tls_data_wr_nstrm->strm_data)) {
      tls_log("%s", "data channel SSL session renegotiated");
      tls_flags &= ~TLS_SESS_DATA_RENEGOTIATING;

    } else if (tls_renegotiate_required) {
      tls_log("%s", "requested SSL renegotiation timed out on data channel");
      tls_log("%s", "shutting down data channel SSL session");
      tls_end_session((SSL *) tls_data_wr_nstrm->strm_data);
      tls_data_rd_nstrm->strm_data = tls_data_wr_nstrm->strm_data = NULL;
    }
  }

  return 0;
}

static int tls_ctrl_renegotiate_cb(CALLBACK_FRAME) {
  if (tls_flags & TLS_SESS_ON_CTRL) {
    tls_log("%s", "requesting SSL renegotiation on control channel");
    SSL_renegotiate(ctrl_ssl);
    /* SSL_do_handshake(ctrl_ssl); */

    add_timer(tls_renegotiate_timeout, 0, &tls_module,
      tls_renegotiate_timeout_cb);

    tls_flags |= TLS_SESS_CTRL_RENEGOTIATING;

    /* Restart the timer. */
    return 1;
  }

  return 0;
}
#endif

static DH *tls_dh_cb(SSL *ssl, int is_export, int keylength) {
  FILE *fp = NULL;

  if (tls_tmp_dh)
    return tls_tmp_dh;

  if (tls_dhparam_file) {
    if ((fp = fopen(tls_dhparam_file, "r"))) {
      tls_tmp_dh = PEM_read_DHparams(fp, NULL, NULL, NULL);
      fclose(fp);

      if (tls_tmp_dh)
        return tls_tmp_dh;

    } else
      log_debug(DEBUG3, MOD_TLS_VERSION
        ": unable to open TLSDHParamFile '%s': %s", tls_dhparam_file,
          strerror(errno));
  }

  switch (keylength) {
    case 512:
      return (tls_tmp_dh = get_dh512());

    case 768:
      return (tls_tmp_dh = get_dh768());

     case 1024:
       return (tls_tmp_dh = get_dh1024());

     case 1536:
       return (tls_tmp_dh = get_dh1536());

     case 2048:
       return (tls_tmp_dh = get_dh2048());

     default:
       return (tls_tmp_dh = get_dh1024());
  }

  return NULL;
}

static int tls_init_ctxt(void) {
  SSL_load_error_strings();
  SSL_library_init();

#ifdef ZLIB
   {
     COMP_METHOD *cm = COMP_zlib();
     if (cm != NULL && cm->type != NID_undef) {
        SSL_COMP_add_compression_method(0xe0, cm); /* Eric Young's ZLIB ID */
     }
   }
#endif /* ZLIB */

  if ((ssl_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
    tls_log("error: SSL_CTX_new(): %s", ERR_error_string(ERR_get_error(),
      NULL));
    return -1;
  }

  /* Make sure that SSLv2 communications are disabled entirely.  If using
   * OpenSSL-0.9.7 or greater, revent session resumptions on renegotiations
   * as well (more secure).
   */
#if OPENSSL_VERSION_NUMBER > 0x000907000L
  SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2|
    SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
#else
  SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
#endif

  /* Set up session caching. */
  SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_SERVER);
  SSL_CTX_set_session_id_context(ssl_ctx, "1", 1);

  SSL_CTX_set_tmp_dh_callback(ssl_ctx, tls_dh_cb);

  if (tls_seed_prng())
    tls_log("%s", "unable to properly seed PRNG");

  return 0;
}

static int tls_init_server(void) {
#if OPENSSL_VERSION_NUMBER > 0x000907000L
  config_rec *c = NULL;
#endif
  char *tls_ca_cert = NULL, *tls_ca_path = NULL;

  if ((tls_protocol = get_param_ptr(main_server->conf,
      "TLSProtocol", FALSE)) == NULL)
    tls_protocol = TLS_DEFAULT_PROTOCOL;

  if (!strcasecmp(tls_protocol, "SSLv23"))
    /* This is the default, so there is no need to do anything. */
    ;

  else if (!strcasecmp(tls_protocol, "SSLv3"))
    SSL_CTX_set_ssl_version(ssl_ctx, SSLv3_server_method());

  else if (!strcasecmp(tls_protocol, "TLSv1"))
    SSL_CTX_set_ssl_version(ssl_ctx, TLSv1_server_method());

  tls_ca_cert = get_param_ptr(main_server->conf, "TLSCACertificateFile", FALSE);
  tls_ca_path = get_param_ptr(main_server->conf, "TLSCACertificatePath", FALSE);

  if (tls_ca_cert || tls_ca_path) {

    /* Set the locations used for verifying certificates. */
    PRIVS_ROOT
    if (!SSL_CTX_load_verify_locations(ssl_ctx, tls_ca_cert, tls_ca_path)) {
      PRIVS_RELINQUISH
      tls_log("unable to set CA verification locations '%s' or '%s': %s",
        tls_ca_cert, tls_ca_path, ERR_error_string(ERR_get_error(), NULL));
      return -1;
    }
    PRIVS_RELINQUISH

  } else {

    /* Default to using locations set in the OpenSSL config file. */
    SSL_CTX_set_default_verify_paths(ssl_ctx);
    tls_log("%s", "using default OpenSSL verification locations "
      "(see $SSL_CERT_DIR)");
  }

  if (!(tls_opts & TLS_OPT_NO_CERT_REQUEST)) {
    int verify_mode = SSL_VERIFY_PEER;
    char *tls_ca_chain = NULL;

    /* If we are verifying client, make sure the client sends a cert;
     * the protocol allows for the client to disregard a request for
     * its cert by the server.
     */
    if (tls_flags & TLS_SESS_VERIFY_CLIENT)
      verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;

    SSL_CTX_set_verify(ssl_ctx, verify_mode, tls_verify_cb);
    SSL_CTX_set_verify_depth(ssl_ctx, tls_verify_depth);

    /* Do not forget to configure the certs that the server will send to
     * the client when requesting a client cert.  Use the configured
     * TLSCertificateChainFile, if present; otherwise, construct the list
     * from all the certs in the TLSCACertificatePath.
     */
 
    if ((tls_ca_chain = get_param_ptr(main_server->conf,
        "TLSCACertificateChain", FALSE))) {
      SSL_CTX_set_client_CA_list(ssl_ctx,
        SSL_load_client_CA_file(tls_ca_chain));

    } else if (tls_ca_path) {
      DIR *cacertdir = NULL;

      PRIVS_ROOT
      cacertdir = opendir(tls_ca_path);
      PRIVS_RELINQUISH

      if (cacertdir) {
        struct dirent *cadent = NULL;
        pool *tmp_pool = make_sub_pool(permanent_pool);

        while ((cadent = readdir(cacertdir)) != NULL) {
          FILE *cacertf = NULL;
          char *cacertname = pdircat(tmp_pool, tls_ca_path, cadent->d_name,
             NULL);

          PRIVS_ROOT
          cacertf = fopen(cacertname, "r");
          PRIVS_RELINQUISH

          if (cacertf) {
            X509 *x509 = PEM_read_X509(cacertf, NULL, NULL, NULL);

            if (x509) {
              SSL_CTX_add_client_CA(ssl_ctx, x509);
              fclose(cacertf);

            } else
              tls_log("unable to add '%s' to client CA list: %s",
                cacertname, ERR_error_string(ERR_get_error(), NULL));

          } else
            tls_log("unable to add '%s' to client CA list: %s",
              cacertname, strerror(errno));
        }
        destroy_pool(tmp_pool);
        closedir(cacertdir);
 
      } else
        tls_log("unable to add CAs in '%s': %s", tls_ca_path,
          strerror(errno));
    }
  }

  /* Assume that, if no separate key files are configured, the keys are
   * in the same file as the corresponding certificate.
   */
  if (!tls_rsa_key_file)
     tls_rsa_key_file = tls_rsa_cert_file;

  if (!tls_dsa_key_file)
     tls_dsa_key_file = tls_dsa_cert_file;

  PRIVS_ROOT
  if (tls_rsa_cert_file) {
    int err = SSL_CTX_use_certificate_file(ssl_ctx, tls_rsa_cert_file,
      X509_FILETYPE_PEM);

    if (err <= 0) {
      PRIVS_RELINQUISH

      tls_log("error: '%s': %s", tls_rsa_cert_file,
        ERR_error_string(ERR_get_error(), NULL));
      return -1;
    }

    SSL_CTX_set_tmp_rsa_callback(ssl_ctx, tls_rsa_cb);
  }

  if (tls_rsa_key_file) {
    int err = SSL_CTX_use_PrivateKey_file(ssl_ctx, tls_rsa_key_file,
      X509_FILETYPE_PEM);

    if (err <= 0) {
      PRIVS_RELINQUISH

      tls_log("error: '%s': %s", tls_rsa_key_file,
        ERR_error_string(ERR_get_error(), NULL));
      return -1;
    }
  }

  if (tls_dsa_cert_file) {
    int err = SSL_CTX_use_certificate_file(ssl_ctx, tls_dsa_cert_file,
      X509_FILETYPE_PEM);

    if (err <= 0) {
      PRIVS_RELINQUISH

      tls_log("error: '%s' %s", tls_dsa_cert_file,
        ERR_error_string(ERR_get_error(), NULL));
      return -1;
    }
  }

  if (tls_dsa_key_file) {
    int err = SSL_CTX_use_PrivateKey_file(ssl_ctx, tls_dsa_key_file,
      X509_FILETYPE_PEM);

    if (err <= 0) {
      PRIVS_RELINQUISH

      tls_log("error: '%s': %s", tls_dsa_key_file,
        ERR_error_string(ERR_get_error(), NULL));
      return -1;
    }
  }
  PRIVS_RELINQUISH

  /* Set up the CRL. */
  if ((tls_crl_file || tls_crl_path) && (crl_store = X509_STORE_new()))
    X509_STORE_load_locations(crl_store, tls_crl_file, tls_crl_path);

  SSL_CTX_set_cipher_list(ssl_ctx, tls_cipher_suite);

#if OPENSSL_VERSION_NUMBER > 0x000907000L
  /* Lookup/process any configured TLSRenegotiate parameters. */
  if ((c = find_config(main_server->conf, CONF_PARAM, "TLSRenegotiate",
      FALSE)) != NULL) {

    if (c->argc == 0) {

      /* Disable all server-side requested renegotiations; clients can
       * still request renegotiations.
       */
      tls_ctrl_renegotiate_timeout = 0;
      tls_data_renegotiate_limit = 0;
      tls_renegotiate_timeout = 0;
      tls_renegotiate_required = FALSE;

    } else {
      int ctrl_timeout = *((int *) c->argv[0]);
      off_t data_limit = *((off_t *) c->argv[1]);
      int renegotiate_timeout = *((int *) c->argv[2]);
      unsigned char renegotiate_required = *((unsigned char *) c->argv[3]);

      if (data_limit)
        tls_data_renegotiate_limit = data_limit;
    
      if (renegotiate_timeout)
        tls_renegotiate_timeout = renegotiate_timeout;

      tls_renegotiate_required = renegotiate_required;
  
      /* Set any control channel renegotiation timers, if need be. */
      add_timer(ctrl_timeout ? ctrl_timeout : tls_ctrl_renegotiate_timeout,
        0, &tls_module, tls_ctrl_renegotiate_cb);
    }
  }
#endif

  return 0;
}

static int tls_accept(conn_t *conn, unsigned char on_data) {
  int res = 0;
  char *subj = NULL;
  static unsigned char logged_data = FALSE;
  SSL *ssl = NULL;

  if (!ssl_ctx) {
    tls_log("%s", "unable to start session: null SSL_CTX");
    return -1;
  }

  if ((ssl = SSL_new(ssl_ctx)) == NULL) {
    tls_log("error: unable to start session: %s",
      ERR_error_string(ERR_get_error(), NULL));
    return -2;
  }

  /* This works with either rfd or wfd (I hope) */
  SSL_set_fd(ssl, conn->rfd);

  retry:
  if ((res = SSL_accept(ssl)) < 1) {
    int err = SSL_get_error(ssl, res);

    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      pr_handle_signals();
      goto retry;
    }

    tls_log("unable to accept SSL connection: %s", ERR_error_string(err, NULL));
    tls_end_session(ssl);
    return -3;
  }

  /* Stash the SSL object in the pointers of the correct NetIO streams. */
  if (conn == session.c) {
    ctrl_ssl = ssl;
    tls_ctrl_rd_nstrm->strm_data = tls_ctrl_wr_nstrm->strm_data = (void *) ssl;

  } else if (conn == session.d)
    tls_data_rd_nstrm->strm_data = tls_data_wr_nstrm->strm_data = (void *) ssl;

  /* SSL handshake on the control channel... */
  if (!on_data) {
    tls_log("%s connection accepted, using cipher %s (%d bits)",
      SSL_get_cipher_version(ssl), SSL_get_cipher_name(ssl),
      SSL_get_cipher_bits(ssl, NULL));

    if ((subj = tls_get_subj_name()))
      tls_log("Client: %s", subj);

    if (!(tls_opts & TLS_OPT_NO_CERT_REQUEST)) {

      /* NOTE: should probably use SSL_get_verify_result() as a last
       * sanity check.
       */

      /* Now we can go on with our post-handshake, application level
       * requirement checks.
       */
      if (!tls_check_client_cert(ssl, conn))
        return -1;
    }

    /* Setup the TLS environment variables, if requested. */
    tls_setup_environ();

  /* SSL handshake on the data channel... */
  } else {

    /* Only be verbose with the first TLS data connection, otherwise there
     * might be too much noise.
     */
    if (!logged_data) {
      tls_log("%s data connection accepted, using cipher %s (%d bits)",
        SSL_get_cipher_version(ssl), SSL_get_cipher_name(ssl),
        SSL_get_cipher_bits(ssl, NULL));
      logged_data = TRUE;
    }
  }

  return 0;
}

static void tls_cleanup(void) {
  if (crl_store) {
    X509_STORE_free(crl_store);
    crl_store = NULL;
  }

  if (ssl_ctx) {
    SSL_CTX_free(ssl_ctx);
    ssl_ctx = NULL;
  }

  if (tls_tmp_dh) {
    DH_free(tls_tmp_dh);
    tls_tmp_dh = NULL;
  }

  if (tls_tmp_rsa) {
    RSA_free(tls_tmp_rsa);
    tls_tmp_rsa = NULL;
  }

  ERR_free_strings();
  ERR_remove_state(0);
  EVP_cleanup();
}

static void tls_end_session(SSL *ssl) {
  if (!ssl)
    return;

  if (SSL_shutdown(ssl) == 0)
    /* Call SSL_shutdown() again */
    SSL_shutdown(ssl);

  SSL_free(ssl);
}

static char *tls_get_subj_name(void) {
  X509 *cert = NULL;

  if ((cert = SSL_get_peer_certificate(ctrl_ssl))) {
    char *name = tls_x509_name_oneline(X509_get_subject_name(cert));
    X509_free(cert);
    return name;
  }

  return NULL;
}

static void tls_handle_error(int error) {
  char *errstr = ERR_error_string(error, NULL);

  switch (error) {
    case SSL_ERROR_NONE:
      return;

    case SSL_ERROR_SSL:
      tls_log("panic: SSL_ERROR_SSL on " __FILE__ ": %s", errstr);
      break;

    case SSL_ERROR_WANT_READ:
      tls_log("panic: SSL_ERROR_WANT_READ on " __FILE__ ": %s", errstr);
      break;

    case SSL_ERROR_WANT_WRITE:
      tls_log("panic: SSL_ERROR_WANT_WRITE on " __FILE__ ": %s", errstr);
      break;

    case SSL_ERROR_WANT_X509_LOOKUP:
      tls_log("panic: SSL_ERROR_WANT_X509_LOOKUP on " __FILE__ ": %s", errstr);
      break;

    case SSL_ERROR_SYSCALL:
      if (errno == ECONNRESET)
        return;

      tls_log("panic: SSL_ERROR_SYSCALL on " __FILE__ ": %s", errstr);
      break;

    case SSL_ERROR_ZERO_RETURN:
      tls_log("panic: SSL_ERROR_ZERO_RETURN on " __FILE__ ": %s", errstr);
      break;

    case SSL_ERROR_WANT_CONNECT:
      tls_log("panic: SSL_ERROR_WANT_CONNECT on " __FILE__ ": %s", errstr);
      break;

    default:
      tls_log("panic: SSL_ERROR %d (%s) on " __FILE__, error, errstr);
      break;
  }

  tls_log("%s", "unexpected OpenSSL error, disconnecting");
  log_pri(PR_LOG_ERR, "%s", MOD_TLS_VERSION
    ": unexpected OpenSSL error, disconnecting");

  end_login(1);
}

/* This function checks if the client's cert is in the ~/.tlslogin file
 * of the "user"
 */
static unsigned char tls_dotlogin_allow(const char *user) {
  char buf[512] = {'\0'}, *home = NULL;
  FILE *fp = NULL;
  X509 *client_cert = NULL, *file_cert = NULL;
  struct passwd *pwd = NULL;
  pool *tmp_pool = NULL;
  unsigned char allow_user = FALSE;

  if (!(tls_flags & TLS_SESS_ON_CTRL) || !ctrl_ssl || !user)
    return FALSE;

  tmp_pool = make_sub_pool(permanent_pool);

  PRIVS_ROOT
  if (!(pwd = auth_getpwnam(tmp_pool, user))) {
    PRIVS_RELINQUISH
    destroy_pool(tmp_pool);
    return FALSE;
  }
  PRIVS_RELINQUISH

  /* Handle the case where the user's home directory is a symlink. */
  PRIVS_USER
  home = dir_realpath(tmp_pool, pwd->pw_dir);
  PRIVS_RELINQUISH

  snprintf(buf, sizeof(buf), "%s/.tlslogin", home ? home : pwd->pw_dir);
  buf[sizeof(buf)-1] = '\0';

  /* No need for the temporary pool any more. */
  destroy_pool(tmp_pool);
  tmp_pool = NULL;

  PRIVS_ROOT
  if (!(fp = fopen(buf, "r"))) {
    PRIVS_RELINQUISH
    tls_log(".tlslogin check: unable to open '%s': %s", buf, strerror(errno));
    return FALSE;
  }

  if (!(client_cert = SSL_get_peer_certificate(ctrl_ssl))) {
    PRIVS_RELINQUISH
    fclose(fp);
    return FALSE;
  }

  while ((file_cert = PEM_read_X509(fp, NULL, NULL, NULL))) {
    if (!M_ASN1_BIT_STRING_cmp(client_cert->signature, file_cert->signature))
      allow_user = TRUE;

    X509_free(file_cert);
    if (allow_user)
      break;
  }
  PRIVS_RELINQUISH

  X509_free(client_cert);
  fclose(fp);

  return allow_user;
}

/* This is unused...for now. */
#if 0
static char *tls_cert_to_user(pool *cert_pool, X509 *cert) {
  if (!cert_pool || !cert)
    return FALSE;

  /* NOTE: insert cert->user translation code here.  Possibly add
   * TLSOptions that affect this mapping process.
   */

  return NULL;
}
#endif

static int tls_readmore(int rfd) {
  fd_set rfds;
  struct timeval tv;

  FD_ZERO(&rfds);
  FD_SET(rfd, &rfds);

  /* Use a timeout of 15 seconds */
  tv.tv_sec = 15;
  tv.tv_usec = 0;

  return select(rfd + 1, &rfds, NULL, NULL, &tv);
}

static ssize_t tls_read(SSL *ssl, void *buf, size_t len) {
  ssize_t count;

  retry:
  count = SSL_read(ssl, buf, len);

  if (count < 0) {
    int err = SSL_get_error(ssl, count);

    /* read(2) returns only the generic error number -1 */
    count = -1;

    switch (err) {
      case SSL_ERROR_WANT_READ:
        /* OpenSSL needs more data from the wire to finish the current block,
         * so we wait a little while for it.
         */
        if ((err = tls_readmore(SSL_get_fd(ssl))) > 0)
          goto retry;

        else if (err == 0)
          /* Still missing data after timeout. Simulate an EINTR and return.
           */
          errno = EINTR;

          /* If err < 0, i.e. some error from the select(), everything is
           * already in place; errno is properly set and this function
           * returns -1.
           */
          break;

      default:
        tls_handle_error(err);
        break;
    }
  }

  return count;
}

static RSA *tls_rsa_cb(SSL *ssl, int is_export, int keylength) {
  if (tls_tmp_rsa)
    return tls_tmp_rsa;

  tls_tmp_rsa = RSA_generate_key(keylength, RSA_F4, NULL, NULL);
  return tls_tmp_rsa;
}

static int tls_seed_prng(void) {
  char stackdata[1024];
  static char rand_file[300];
  FILE *fp = NULL;
  
  /* Lookup any configured TLSRandomSeed. */
  tls_rand_file = get_param_ptr(main_server->conf, "TLSRandomSeed", FALSE);

#if OPENSSL_VERSION_NUMBER >= 0x00905100L
  if (RAND_status())

    /* PRNG already well-seeded. */
    return 0;
#endif

  /* If the device '/dev/urandom' is present, OpenSSL uses it by default.
   * Check if it's present, else we have to make random data ourselves.
   */
  if ((fp = fopen("/dev/urandom", "r"))) {
    fclose(fp);
    return 0;
  }

  if (!tls_rand_file) {
    /* The ftpd's random file is (openssl-dir)/.rnd */
    snprintf(rand_file, sizeof(rand_file), "%s/.rnd",
      X509_get_default_cert_area());
    rand_file[sizeof(rand_file)-1] = '\0';
    tls_rand_file = rand_file;
  }

  if (!RAND_load_file(tls_rand_file, 1024)) {
    /* No random file found, create new seed. */
    unsigned int c = time(NULL);
    RAND_seed(&c, sizeof(c));
    c = getpid();
    RAND_seed(&c, sizeof(c));
    RAND_seed(stackdata, sizeof(stackdata));
  }

#if OPENSSL_VERSION_NUMBER >= 0x00905100L
  if (!RAND_status()) {
     /* PRNG still badly seeded. */
     return -1;
  }
#endif

  return 0;
}

/* Note: these mappings should probably be added to the mod_tls docs.
 */

static void tls_setup_cert_ext_environ(const char *env_prefix, X509 *cert) {

  /* NOTE: in the future, add ways of adding subjectAltName (and other
   * extensions?) to the environment.
   */

#if 0
  int nexts = 0;

  if ((nexts = X509_get_ext_count(cert)) > 0) {
    register unsigned int i = 0;

    for (i = 0; i < nexts; i++) {
      X509_EXTENSION *ext = X509_get_ext(cert, i);
      const char *extstr = OBJ_nid2sn(OBJ_obj2nid(
        X509_EXTENSION_get_object(ext)));
    }
  }
#endif

  return;
}

/* Note: these mappings should probably be added to the mod_tls docs.
 *
 *   Name                    Short Name    NID
 *   ----                    ----------    ---
 *   countryName             C             NID_countryName
 *   commonName              CN            NID_commonName
 *   description             D             NID_description
 *   givenName               G             NID_givenName
 *   initials                I             NID_initials
 *   localityName            L             NID_localityName
 *   organizationName        O             NID_organizationName
 *   organizationalUnitName  OU            NID_organizationalUnitName
 *   stateOrProvinceName     ST            NID_stateOrProvinceName
 *   surname                 S             NID_surname
 *   title                   T             NID_title
 *   uniqueIdentifer         UID           NID_x500UniqueIdentifier
 *                                         (or NID_uniqueIdentifier, depending
 *                                         on OpenSSL version)
 *   email                   Email         NID_pkcs9_emailAddress
 */

static void tls_setup_cert_dn_environ(const char *env_prefix, X509_NAME *name) {
  register unsigned int i = 0;

  for (i = 0; i < sk_X509_NAME_ENTRY_num(name->entries); i++) {
    X509_NAME_ENTRY *entry = sk_X509_NAME_ENTRY_value(name->entries, i);
    int nid = OBJ_obj2nid(entry->object);
   
    switch (nid) {
      case NID_countryName:
        putenv(pstrcat(main_server->pool, env_prefix, "C=",
          pstrndup(main_server->pool, entry->value->data,
          entry->value->length), NULL));
        break;

      case NID_commonName:
        putenv(pstrcat(main_server->pool, env_prefix, "CN=",
          pstrndup(main_server->pool, entry->value->data,
          entry->value->length), NULL));
        break;

      case NID_description:
        putenv(pstrcat(main_server->pool, env_prefix, "D=",
          pstrndup(main_server->pool, entry->value->data,
          entry->value->length), NULL));
        break;

      case NID_givenName:
        putenv(pstrcat(main_server->pool, env_prefix, "G=",
          pstrndup(main_server->pool, entry->value->data,
          entry->value->length), NULL));
        break;

      case NID_initials:
        putenv(pstrcat(main_server->pool, env_prefix, "I=",
          pstrndup(main_server->pool, entry->value->data,
          entry->value->length), NULL));
        break;

      case NID_localityName:
        putenv(pstrcat(main_server->pool, env_prefix, "L=",
          pstrndup(main_server->pool, entry->value->data,
          entry->value->length), NULL));
        break;

      case NID_organizationName:
        putenv(pstrcat(main_server->pool, env_prefix, "O=",
          pstrndup(main_server->pool, entry->value->data,
          entry->value->length), NULL));
        break;

      case NID_organizationalUnitName:
        putenv(pstrcat(main_server->pool, env_prefix, "OU=",
          pstrndup(main_server->pool, entry->value->data,
          entry->value->length), NULL));
        break;

      case NID_stateOrProvinceName:
        putenv(pstrcat(main_server->pool, env_prefix, "ST=",
          pstrndup(main_server->pool, entry->value->data,
          entry->value->length), NULL));
        break;

      case NID_surname:
        putenv(pstrcat(main_server->pool, env_prefix, "S=",
          pstrndup(main_server->pool, entry->value->data,
          entry->value->length), NULL));
        break;

      case NID_title:
        putenv(pstrcat(main_server->pool, env_prefix, "T=",
          pstrndup(main_server->pool, entry->value->data,
          entry->value->length), NULL));
        break;

#if OPENSSL_VERSION_NUMBER >= 0x00907000L
      case NID_x500UniqueIdentifier:
#else
      case NID_uniqueIdentifier:
#endif
        putenv(pstrcat(main_server->pool, env_prefix, "UID=",
          pstrndup(main_server->pool, entry->value->data,
          entry->value->length), NULL));
        break;

      case NID_pkcs9_emailAddress:
        putenv(pstrcat(main_server->pool, env_prefix, "Email=",
          pstrndup(main_server->pool, entry->value->data,
          entry->value->length), NULL));
        break;

      default:
        break;
    }
  }
}

static void tls_setup_cert_environ(const char *env_prefix, X509 *cert) {
  char *tmp = NULL;
  BIO *bio = NULL;

  if (tls_opts & TLS_OPT_STD_ENV_VARS) {
    char buf[80] = {'\0'};
    ASN1_INTEGER *serial = X509_get_serialNumber(cert);

    sprintf(buf, "%lu", X509_get_version(cert) + 1);
    buf[sizeof(buf)-1] = '\0';
    putenv(pstrcat(main_server->pool, env_prefix, "M_VERSION=", buf, NULL));

    if (serial->length < 4) {
      memset(buf, '\0', sizeof(buf));
      sprintf(buf, "%lu", ASN1_INTEGER_get(serial));
      buf[sizeof(buf)-1] = '\0';
      putenv(pstrcat(main_server->pool, env_prefix, "M_SERIAL=", buf, NULL));

    } else

      /* NOTE: actually, the number is printable, I'm just being lazy. This
       * case is much harder to deal with, and not really worth the effort.
       */
      tls_log("%s", "certificate serial number not printable");
    
    putenv(pstrcat(main_server->pool, env_prefix, "S_DN=",
      tls_x509_name_oneline(X509_get_subject_name(cert)), NULL));
    tls_setup_cert_dn_environ(pstrcat(main_server->pool, env_prefix, "S_DN_",
      NULL), X509_get_subject_name(cert));

    putenv(pstrcat(main_server->pool, env_prefix, "I_DN=",
      tls_x509_name_oneline(X509_get_issuer_name(cert)), NULL));
    tls_setup_cert_dn_environ(pstrcat(main_server->pool, env_prefix, "I_DN_",
      NULL), X509_get_issuer_name(cert));

    tls_setup_cert_ext_environ(pstrcat(main_server->pool, env_prefix, "EXT_",
      NULL), cert);

    bio = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bio, X509_get_notBefore(cert));
    BIO_get_mem_data(bio, &tmp);
    putenv(pstrcat(main_server->pool, env_prefix, "V_START=", tmp, NULL));
    BIO_free(bio);

    bio = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bio, X509_get_notAfter(cert));
    BIO_get_mem_data(bio, &tmp);
    putenv(pstrcat(main_server->pool, env_prefix, "V_END=", tmp, NULL));
    BIO_free(bio);

    bio = BIO_new(BIO_s_mem());
    i2a_ASN1_OBJECT(bio, cert->cert_info->signature->algorithm);
    BIO_get_mem_data(bio, &tmp);
    putenv(pstrcat(main_server->pool, env_prefix, "A_SIG=", tmp, NULL));
    BIO_free(bio);

    bio = BIO_new(BIO_s_mem());
    i2a_ASN1_OBJECT(bio, cert->cert_info->key->algor->algorithm);
    BIO_get_mem_data(bio, &tmp);
    putenv(pstrcat(main_server->pool, env_prefix, "A_KEY=", tmp, NULL));
    BIO_free(bio);
  }

  bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(bio, cert);
  BIO_get_mem_data(bio, &tmp);
  putenv(pstrcat(main_server->pool, env_prefix, "CERT=", tmp, NULL));
  BIO_free(bio);
}

static void tls_setup_environ(void) {
  X509 *cert = NULL;
  STACK_OF(X509) *sk_cert_chain = NULL;

  if (!(tls_opts & TLS_OPT_EXPORT_CERT_DATA) &&
      !(tls_opts & TLS_OPT_STD_ENV_VARS))
    return;

  if (tls_opts & TLS_OPT_STD_ENV_VARS) {
    SSL_CIPHER *cipher = NULL;
    SSL_SESSION *ssl_session = NULL;

    putenv(pstrdup(main_server->pool, "FTPS=1"));

    putenv(pstrcat(main_server->pool, "TLS_PROTOCOL=",
      SSL_get_cipher_version(ctrl_ssl), NULL));

    /* Process the SSL session-related environ variable. */
    if ((ssl_session = SSL_get_session(ctrl_ssl))) {
      char buf[SSL_MAX_SSL_SESSION_ID_LENGTH*2+1] = {'\0'};
      register unsigned int i = 0;

      /* Have to obtain a stringified session ID the hard way. */
      for (i = 0; i < ssl_session->session_id_length; i++)
        sprintf(&(buf[i*2]), "%02X", ssl_session->session_id[i]);
      buf[sizeof(buf)-1] = '\0';

      putenv(pstrcat(main_server->pool, "TLS_SESSION_ID=", buf, NULL));
    }

    /* Process the SSL cipher-related environ variables. */
    if ((cipher = SSL_get_current_cipher(ctrl_ssl))) {
      char buf[10] = {'\0'};
      int cipher_bits_used = 0, cipher_bits_possible = 0;

      putenv(pstrcat(main_server->pool, "TLS_CIPHER=",
        SSL_CIPHER_get_name(cipher), NULL));

      cipher_bits_used = SSL_CIPHER_get_bits(cipher, &cipher_bits_possible);

      if (cipher_bits_used < 56)
        putenv(pstrdup(main_server->pool, "TLS_CIPHER_EXPORT=1"));

      memset(buf, '\0', sizeof(buf));
      snprintf(buf, sizeof(buf), "%d", cipher_bits_possible);
      buf[sizeof(buf)-1] = '\0';

      putenv(pstrcat(main_server->pool, "TLS_CIPHER_KEYSIZE_POSSIBLE=",
        buf, NULL));

      memset(buf, '\0', sizeof(buf));
      snprintf(buf, sizeof(buf), "%d", cipher_bits_used);
      buf[sizeof(buf)-1] = '\0';

      putenv(pstrcat(main_server->pool, "TLS_CIPHER_KEYSIZE_USED=",
        buf, NULL));
    }

    if (putenv(pstrcat(main_server->pool, "TLS_LIBRARY_VERSION=",
       OPENSSL_VERSION_TEXT, NULL)) < 0)
     tls_log("error setting environ variable: %s", strerror(errno)); 
  }

  if ((sk_cert_chain = SSL_get_peer_cert_chain(ctrl_ssl))) {
    char *tmp = NULL;
    register unsigned int i = 0;
    BIO *bio = NULL;

    /* Adding TLS_CLIENT_CERT_CHAIN environ variables. */
    for (i = 0; i < sk_X509_num(sk_cert_chain); i++) {
      bio = BIO_new(BIO_s_mem());
      BIO_printf(bio, "TLS_CLIENT_CERT_CHAIN%u=", i);
      PEM_write_bio_X509(bio, sk_X509_value(sk_cert_chain, i));

      BIO_get_mem_data(bio, &tmp);
      if (putenv(pstrdup(main_server->pool, tmp)) < 0)
        tls_log("error setting environ variable: %s", strerror(errno));

      BIO_free(bio);
    } 
  }

  cert = SSL_get_certificate(ctrl_ssl);
  tls_setup_cert_environ("TLS_SERVER_", cert);
  X509_free(cert);

  cert = SSL_get_peer_certificate(ctrl_ssl);
  tls_setup_cert_environ("TLS_CLIENT_", cert);
  X509_free(cert);

  return;
}

static int tls_verify_cb(int ok, X509_STORE_CTX *ctx) {

  /* TODO: Make up my mind on what to accept or not.*/

  /* We can configure the server to skip the peer's cert verification */
  if (!(tls_flags & TLS_SESS_VERIFY_CLIENT))
     return 1;

  ok = tls_verify_crl(ok, ctx);

  if (!ok) {
    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    int depth = X509_STORE_CTX_get_error_depth(ctx);

    tls_log("error: unable to verify certificate at depth: %d", depth);
    tls_log("error: cert subject: %s", tls_x509_name_oneline(
      X509_get_subject_name(cert)));
    tls_log("error: cert issuer: %s", tls_x509_name_oneline(
      X509_get_issuer_name(cert)));

    switch (ctx->error) {
      case X509_V_ERR_CERT_HAS_EXPIRED:
      case X509_V_ERR_CERT_REVOKED:
      case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
      case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
      case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
        tls_log("%s", X509_verify_cert_error_string(ctx->error));
        ok = 0;
        break;

      case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
        /* XXX this is strange. we get this error for certain clients
         * (i.e. Jeff Altman's kftp) when all is ok. I think it's because the
         * client is actually sending the whole CA cert. This must be figured
         * out, but we let it pass for now. If the CA cert isn't available
         * locally, we will fail anyway.
         */
        tls_log("%s", X509_verify_cert_error_string(ctx->error));
        ok = 1;
        break;

      default:
        tls_log("unable to verify client's certificate: %s",
            ERR_error_string(ctx->error, NULL));
        ok = 0;
        break;
    }
  }

  return ok;
}

/* This routine is (very much!) based on the work by Ralf S. Engelschall
 * <rse@engelshall.com>.  Comments by Ralf.
 */
static int tls_verify_crl(int ok, X509_STORE_CTX *ctx) {
  X509_OBJECT obj;
  X509_NAME *subject = NULL, *issuer = NULL;
  X509 *xs = NULL;
  X509_CRL *crl = NULL;
  X509_REVOKED *revoked = NULL;
  X509_STORE_CTX store_ctx;
  int n, rc;
  register unsigned int i = 0;

  /* Unless a revocation store for CRLs was created we cannot do any
   * CRL-based verification, of course.
   */
  if (!crl_store)
    return ok;

  /* Determine certificate ingredients in advance.
   */
  xs = X509_STORE_CTX_get_current_cert(ctx);
  subject = X509_get_subject_name(xs);
  issuer = X509_get_issuer_name(xs);

  /* OpenSSL provides the general mechanism to deal with CRLs but does not
   * use them automatically when verifying certificates, so we do it
   * explicitly here. We will check the CRL for the currently checked
   * certificate, if there is such a CRL in the store.
   *
   * We come through this procedure for each certificate in the certificate
   * chain, starting with the root-CA's certificate. At each step we've to
   * both verify the signature on the CRL (to make sure it's a valid CRL)
   * and it's revocation list (to make sure the current certificate isn't
   * revoked).  But because to check the signature on the CRL we need the
   * public key of the issuing CA certificate (which was already processed
   * one round before), we've a little problem. But we can both solve it and
   * at the same time optimize the processing by using the following
   * verification scheme (idea and code snippets borrowed from the GLOBUS
   * project):
   *
   * 1. We'll check the signature of a CRL in each step when we find a CRL
   *    through the _subject_ name of the current certificate. This CRL
   *    itself will be needed the first time in the next round, of course.
   *    But we do the signature processing one round before this where the
   *    public key of the CA is available.
   *
   * 2. We'll check the revocation list of a CRL in each step when
   *    we find a CRL through the _issuer_ name of the current certificate.
   *    This CRLs signature was then already verified one round before.
   *
   * This verification scheme allows a CA to revoke its own certificate as
   * well, of course.
   */

  /* Try to retrieve a CRL corresponding to the _subject_ of
   * the current certificate in order to verify its integrity.
   */
  memset(&obj, 0, sizeof(obj));
  X509_STORE_CTX_init(&store_ctx, crl_store, NULL, NULL);
  rc = X509_STORE_get_by_subject(&store_ctx, X509_LU_CRL, subject, &obj);
  X509_STORE_CTX_cleanup(&store_ctx);
  crl = obj.data.crl;

  if (rc > 0 && crl != NULL) {
    /* Verify the signature on this CRL
     */
    if (X509_CRL_verify(crl, X509_get_pubkey(xs)) <= 0) {
      tls_log("%s", "invalid signature on CRL");
      X509_STORE_CTX_set_error(ctx, X509_V_ERR_CRL_SIGNATURE_FAILURE);
      X509_OBJECT_free_contents(&obj);
      return 0;
    }

    /* Check date of CRL to make sure it's not expired
     */
    i = X509_cmp_current_time(X509_CRL_get_nextUpdate(crl));

    if (i == 0) {
      tls_log("%s", "CRL has invalid nextUpdate field");
      X509_STORE_CTX_set_error(ctx, X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD);
      X509_OBJECT_free_contents(&obj);
      return 0;
    }

    if (i < 0) {
      tls_log("%s", "CRL is expired, revoking all certificates until an "
        "updated CRL is obtained");
      X509_STORE_CTX_set_error(ctx, X509_V_ERR_CRL_HAS_EXPIRED);
      X509_OBJECT_free_contents(&obj);
      return 0;
    }

    X509_OBJECT_free_contents(&obj);
  }

  /* Try to retrieve a CRL corresponding to the _issuer_ of
   * the current certificate in order to check for revocation.
   */
  memset(&obj, 0, sizeof(obj));
  X509_STORE_CTX_init(&store_ctx, crl_store, NULL, NULL);
  rc = X509_STORE_get_by_subject(&store_ctx, X509_LU_CRL, issuer, &obj);
  X509_STORE_CTX_cleanup(&store_ctx);
  crl = obj.data.crl;

  if (rc > 0 && crl != NULL) {

    /* Check if the current certificate is revoked by this CRL
     */
    n = sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl));

    for (i = 0; i < n; i++) {
      revoked = sk_X509_REVOKED_value(X509_CRL_get_REVOKED(crl), i);

      if (ASN1_INTEGER_cmp(revoked->serialNumber,
          X509_get_serialNumber(xs)) == 0) {
        long serial = ASN1_INTEGER_get(revoked->serialNumber);
        char *cp = tls_x509_name_oneline(issuer);

        tls_log("certificate with serial %ld (0x%lX) revoked per CRL from "
          "issuer %s", serial, serial, cp ? cp : "(ERROR)");

        X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REVOKED);
        X509_OBJECT_free_contents(&obj);
        return 0;
      }
    }

    X509_OBJECT_free_contents(&obj);
  }

  return ok;
}

static ssize_t tls_write(SSL *ssl, const void *buf, size_t len) {
  ssize_t count;

  count = SSL_write(ssl, buf, len);

  if (count < 0) {
    int err = SSL_get_error(ssl, count);

    /* write(2) returns only the generic error number -1 */
    count = -1;

    switch (err) {
      case SSL_ERROR_WANT_WRITE:
        /* Simulate an EINTR in case OpenSSL wants to write more. */
        errno = EINTR;
        break;

      default:
        tls_handle_error(err);
        break;
    }
  }

  return count;
}

static char *tls_x509_name_oneline(X509_NAME *x509_name) {
  static char buf[256] = {'\0'};

  /* If we are using OpenSSL 0.9.6 or newer, we want to use X509_NAME_print_ex()
   * instead of X509_NAME_oneline().
   */

#if OPENSSL_VERSION_NUMBER < 0x000906000L
  memset(&buf, '\0', sizeof(buf));
  return X509_NAME_oneline(x509_name, buf, sizeof(buf));
#else

  /* Sigh...do it the hard way. */
  BIO *mem = BIO_new(BIO_s_mem());
  char *data = NULL;
  int data_len = 0, ok;
   
  if ((ok = X509_NAME_print_ex(mem, x509_name, 0, XN_FLAG_ONELINE)))
     data_len = BIO_get_mem_data(mem, &data);

  if (data) {
    memset(&buf, '\0', sizeof(buf));
    memcpy(buf, data, data_len);
    buf[data_len] = '\0';
    buf[sizeof(buf)-1] = '\0';

    BIO_free(mem);
    return buf;
  }

  BIO_free(mem);
  return NULL;
#endif /* OPENSSL_VERSION_NUMBER >= 0x000906000 */
}

/* NetIO callbacks
 */

static void tls_netio_abort_cb(pr_netio_stream_t *nstrm) {
  nstrm->strm_flags |= PR_NETIO_SESS_ABORT;
}

static int tls_netio_close_cb(pr_netio_stream_t *nstrm) {
  int res = 0;

  if (nstrm->strm_data) {
    tls_end_session((SSL *) nstrm->strm_data);

    if (nstrm->strm_type == PR_NETIO_STRM_CTRL)
      tls_ctrl_rd_nstrm->strm_data = tls_ctrl_wr_nstrm->strm_data =
        nstrm->strm_data = NULL;

    if (nstrm->strm_type == PR_NETIO_STRM_DATA)
      tls_data_rd_nstrm->strm_data = tls_data_wr_nstrm->strm_data =
        nstrm->strm_data = NULL;
  }

  res = close(nstrm->strm_fd);
  nstrm->strm_fd = -1;

  return res;
}

static pr_netio_stream_t *tls_netio_open_cb(pr_netio_stream_t *nstrm, int fd,
    int mode) {
  nstrm->strm_fd = fd;
  nstrm->strm_mode = mode;

  /* Cache a pointer to this stream. */
  if (nstrm->strm_type == PR_NETIO_STRM_CTRL) {
    if (nstrm->strm_mode == PR_NETIO_IO_RD)
      tls_ctrl_rd_nstrm = nstrm;

    if (nstrm->strm_mode == PR_NETIO_IO_WR)
      tls_ctrl_wr_nstrm = nstrm;

  } else if (nstrm->strm_type == PR_NETIO_STRM_DATA) {
    if (nstrm->strm_mode == PR_NETIO_IO_RD)
      tls_data_rd_nstrm = nstrm;

    if (nstrm->strm_mode == PR_NETIO_IO_WR)
      tls_data_wr_nstrm = nstrm;

    /* Note: from the FTP-TLS Draft 9.2:
     * 
     *  It is quite reasonable for the server to insist that the data
     *  connection uses a TLS cached session.  This might be a cache of a
     *  previous data connection or of the control connection.  If this is
     *  the reason for the the refusal to allow the data transfer then the
     *  '522' reply should indicate this.
     * 
     * and, from 10.4:
     *   
     *   If a server needs to have the connection protected then it will
     *   reply to the STOR/RETR/NLST/... command with a '522' indicating
     *   that the current state of the data connection protection level is
     *   not sufficient for that data transfer at that time.
     *
     * This points out the need for a module to be able to influence
     * command response codes in a more flexible manner...
     */
  }

  return nstrm;
}

static int tls_netio_poll_cb(pr_netio_stream_t *nstrm) {
  fd_set rfds, wfds;
  struct timeval tval;

  FD_ZERO(&rfds);
  FD_ZERO(&wfds);

  if (nstrm->strm_mode == PR_NETIO_IO_RD)
    FD_SET(nstrm->strm_fd, &rfds);

  else
    FD_SET(nstrm->strm_fd, &wfds);

  tval.tv_sec = (nstrm->strm_flags & PR_NETIO_SESS_INTR) ?
    nstrm->strm_interval : 10;
  tval.tv_usec = 0;

  return select(nstrm->strm_fd + 1, &rfds, &wfds, NULL, &tval);
}

static int tls_netio_postopen_cb(pr_netio_stream_t *nstrm) {

  /* If this is a data stream, and it's for writing, and TLS is required,
   * then do an SSL handshake.
   */

  if (nstrm->strm_type == PR_NETIO_STRM_DATA &&
      nstrm->strm_mode == PR_NETIO_IO_WR) {

    /* Enforce the "data" part of TLSRequired, if configured. */
    if (tls_required_on_data || (tls_flags & TLS_SESS_NEED_DATA_PROT)) {
      X509 *ctrl_cert = NULL, *data_cert = NULL;

      if (tls_accept(session.d, TRUE) < 0) {
        tls_log("%s", "unable to open data connection: SSL handshake failure");
        session.d->xerrno = EPERM;
        return -1;
      }

      /* Make sure that the certificate used, if any, for this data channel
       * handshake is the same as that used for the control channel handshake.
       * This may be too strict of a requirement, though.
       */
      ctrl_cert = SSL_get_peer_certificate(ctrl_ssl);
      data_cert = SSL_get_peer_certificate((SSL *) nstrm->strm_data);

      if (ctrl_cert && data_cert) {
        if (X509_cmp(ctrl_cert, data_cert)) {

          /* Properly shutdown the SSL session. */
          tls_end_session((SSL *) nstrm->strm_data);

          tls_data_rd_nstrm->strm_data = tls_data_wr_nstrm->strm_data =
            nstrm->strm_data = NULL;

          X509_free(ctrl_cert);
          X509_free(data_cert);

          tls_log("%s", "unable to open data connection: control/data "
            "certificate mismatch");

          session.d->xerrno = EPERM;
          return -1;
        }
      }

      if (ctrl_cert)
        X509_free(ctrl_cert);

      if (data_cert)
        X509_free(data_cert);

      tls_flags |= TLS_SESS_ON_DATA;
    }
  }

  return 0;
}

static int tls_netio_read_cb(pr_netio_stream_t *nstrm, char *buf,
    size_t buflen) {

  if (nstrm->strm_data)
    return tls_read((SSL *) nstrm->strm_data, buf, buflen);

  return read(nstrm->strm_fd, buf, buflen);
}

static pr_netio_stream_t *tls_netio_reopen_cb(pr_netio_stream_t *nstrm, int fd,
    int mode) {

  if (nstrm->strm_fd != -1)
    close(nstrm->strm_fd);

  nstrm->strm_fd = fd;
  nstrm->strm_mode = mode;

  /* NOTE: a no-op? */
  return nstrm;
}

static int tls_netio_shutdown_cb(pr_netio_stream_t *nstrm, int how) {
  return shutdown(nstrm->strm_fd, how);
}

static int tls_netio_write_cb(pr_netio_stream_t *nstrm, char *buf,
    size_t buflen) {

  if (nstrm->strm_data) {

#if OPENSSL_VERSION_NUMBER > 0x000907000L
    if (tls_data_renegotiate_limit &&
        session.xfer.total_bytes >= tls_data_renegotiate_limit) {
      tls_log("%s", "requesting SSL renegotiation on data channel");
      SSL_renegotiate((SSL *) nstrm->strm_data);
      /* SSL_do_handshake((SSL *) nstrm->strm_data); */

      add_timer(tls_renegotiate_timeout, 0, &tls_module,
        tls_renegotiate_timeout_cb);

      tls_flags |= TLS_SESS_DATA_RENEGOTIATING;
    }
#endif

    return tls_write((SSL *) nstrm->strm_data, buf, buflen);
  }

  return write(nstrm->strm_fd, buf, buflen);
}

static void tls_netio_install_ctrl(void) {
  pr_netio_t *netio = tls_ctrl_netio ? tls_ctrl_netio :
    (tls_ctrl_netio = pr_alloc_netio(session.pool ? session.pool :
    permanent_pool));

  netio->abort = tls_netio_abort_cb;
  netio->close = tls_netio_close_cb;
  netio->open = tls_netio_open_cb;
  netio->poll = tls_netio_poll_cb;
  netio->postopen = tls_netio_postopen_cb;
  netio->read = tls_netio_read_cb;
  netio->reopen = tls_netio_reopen_cb;
  netio->shutdown = tls_netio_shutdown_cb;
  netio->write = tls_netio_write_cb;

  pr_unregister_netio(PR_NETIO_STRM_CTRL);

  if (pr_register_netio(netio, PR_NETIO_STRM_CTRL) < 0)
    log_pri(PR_LOG_INFO, MOD_TLS_VERSION ": error registering netio: %s",
      strerror(errno));
}

static void tls_netio_install_data(void) {
  pr_netio_t *netio = tls_data_netio ? tls_data_netio :
    (tls_data_netio = pr_alloc_netio(session.pool ? session.pool :
    permanent_pool));

  netio->abort = tls_netio_abort_cb;
  netio->close = tls_netio_close_cb;
  netio->open = tls_netio_open_cb;
  netio->poll = tls_netio_poll_cb;
  netio->postopen = tls_netio_postopen_cb;
  netio->read = tls_netio_read_cb;
  netio->reopen = tls_netio_reopen_cb;
  netio->shutdown = tls_netio_shutdown_cb;
  netio->write = tls_netio_write_cb;

  pr_unregister_netio(PR_NETIO_STRM_DATA);

  if (pr_register_netio(netio, PR_NETIO_STRM_DATA) < 0)
    log_pri(PR_LOG_INFO, MOD_TLS_VERSION ": error registering netio: %s",
      strerror(errno));
}

/* Logging functions
 */

static void tls_closelog(void) {

  /* Sanity check */
  if (tls_logfd != -1) {
    close(tls_logfd);
    tls_logfd = -1;
    tls_logname = NULL;
  }

  return;
}

static int tls_log(const char *fmt, ...) {
  char buf[PR_TUNABLE_BUFFER_SIZE] = {'\0'};
  time_t timestamp = time(NULL);
  struct tm *t = NULL;
  va_list msg;

  /* Sanity check */
  if (!tls_logname)
    return 0;

  t = localtime(&timestamp);

  /* Prepend the timestamp */
  strftime(buf, sizeof(buf), "%b %d %H:%M:%S ", t);
  buf[sizeof(buf)-1] = '\0';

  /* Prepend a small header */
  snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), MOD_TLS_VERSION
    "[%u]: ", (unsigned int) getpid());
  buf[sizeof(buf)-1] = '\0';

  /* Affix the message */
  va_start(msg, fmt);
  vsnprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), fmt, msg);
  va_end(msg);

  buf[strlen(buf)] = '\n';
  buf[sizeof(buf)-1] = '\0';

  if (write(tls_logfd, buf, strlen(buf)) < 0)
    return -1;

  return 0;
}

static int tls_openlog(void) {
  int res = 0;

  /* Sanity checks */
  if ((tls_logname = get_param_ptr(main_server->conf, "TLSLog",
      FALSE)) == NULL)
    return 0;

  if (!strcasecmp(tls_logname, "none")) {
    tls_logname = NULL;
    return 0;
  }

  block_signals();
  PRIVS_ROOT
  res = log_openfile(tls_logname, &tls_logfd, 0600);
  PRIVS_RELINQUISH
  unblock_signals();

  return res;
}

/* Authentication handlers
 */

/* This function does the main authentication work, and is called in the
 * normal course of events:
 *
 *   cmd->argv[0]: user name
 *   cmd->argv[1]: cleartext password
 */
MODRET tls_authenticate(cmd_rec *cmd) {
  if (!tls_engine)
    return DECLINED(cmd);

  /* Possible authentication combinations:
   *
   *  SSL handshake + passwd (default)
   *  SSL handshake + .tlslogin (passwd ignored)
   */

  if ((tls_flags & TLS_SESS_ON_CTRL) && (tls_opts & TLS_OPT_ALLOW_DOT_LOGIN)) {

    if (tls_dotlogin_allow(cmd->argv[0])) {
      tls_log("TLS/X509 .tlslogin check successful for user '%s'",
       cmd->argv[0]);
      log_auth(PR_LOG_NOTICE, "USER %s: TLS/X509 .tlslogin authentication "
        "successful", cmd->argv[0]);
      return mod_create_data(cmd, (void *) PR_AUTH_RFC2228_OK);

    } else
      tls_log("TLS/X509 .tlslogin check failed for user '%s'",
        cmd->argv[0]);
  }

  return DECLINED(cmd);
}


/* This function is called only when UserPassword is involved, used to
 * override the configured password for a user.  I don't know if we really
 * when this happens, but we have to be prepared for this case:
 *
 *  cmd->argv[0]: hashed password (from proftpd.conf)
 *  cmd->argv[1]: user name
 *  cmd->argv[2]: cleartext password
 */
MODRET tls_auth_check(cmd_rec *cmd) {
  if (!tls_engine)
    return DECLINED(cmd);

  /* Possible authentication combinations:
   *
   *  SSL handshake + passwd (default)
   *  SSL handshake + .tlslogin (passwd ignored)
   */

  if ((tls_flags & TLS_SESS_ON_CTRL) && (tls_opts & TLS_OPT_ALLOW_DOT_LOGIN)) {

    if (tls_dotlogin_allow(cmd->argv[1])) {
      tls_log("TLS/X509 .tlslogin check successful for user '%s'",
       cmd->argv[0]);
      log_auth(PR_LOG_NOTICE, "USER %s: TLS/X509 .tlslogin authentication "
        "successful", cmd->argv[1]);
      return mod_create_data(cmd, (void *) PR_AUTH_RFC2228_OK);

    } else
      tls_log("TLS/X509 .tlslogin check failed for user '%s'",
        cmd->argv[1]);
  }

  return DECLINED(cmd);
}

/* Command handlers
 */

MODRET tls_any(cmd_rec *cmd) {
  if (!tls_engine)
    return DECLINED(cmd);

  /* NOTE: possibly add checks of commands here in order to support the
   * ability of having TLSRequired in per-directory configurations.  This
   * would mean watching for directory change commands, file transfer
   * commands, and doing a context check in order to appropriately set
   * the value of tls_required_on_data.
   */

  /* Some commands need not be hindered. */
  if (!strcmp(cmd->argv[0], C_SYST) ||
      !strcmp(cmd->argv[0], C_AUTH) ||
      !strcmp(cmd->argv[0], C_QUIT))
    return DECLINED(cmd);

  if (tls_required_on_ctrl & !(tls_flags & TLS_SESS_ON_CTRL)) {
    pr_response_add_err(R_550, "SSL/TLS required on the control channel");
    return ERROR(cmd);
  }

#ifdef TLS
  if (tls_logged_in)
    reply_code = R_232;
#endif

  /* NOTE: in order for mod_tls to get the proper response code to
   * mod_auth's cmd_pass() (which cannot be circumvented, for it does the
   * setting up of the environment), I'll need to hack the core a little.
   * I'm thinking to have auth_authenticate handlers (and auth_check
   * handlers, I suppose) have the option of, if returning HANDLED, putting
   * the response code to use in the cmd_rec, and then having mod_auth
   * check for such a value.  If not given, do what it normally does
   * (this will allow mod_sql, mod_ldap, etc to continue to function without
   * needing to be modified).
   */

  return DECLINED(cmd);
}

MODRET tls_auth(cmd_rec *cmd) {
  register unsigned int i = 0;

  if (!tls_engine)
    return DECLINED(cmd);

  /* NOTE: need to make sure that AUTH cannot be used after USER has been
   * issued/processed (not without a REIN, anyway).
   */

  if (cmd->argc < 2) {
    pr_response_add_err(R_504, "AUTH requires at least one argument");
    return ERROR(cmd);
  }

  /* Convert the parameter to upper case */
  for (i = 0; i < strlen(cmd->argv[1]); i++)
    (cmd->argv[1])[i] = toupper((cmd->argv[1])[i]);

  if (!strcmp(cmd->argv[1], "TLS") ||
      !strcmp(cmd->argv[1], "TLS-C")) {
     pr_response_send(R_234, "AUTH %s successful", cmd->argv[1]);

     tls_log("%s", "TLS/TLS-C requested, starting TLS handshake");
     if (tls_accept(session.c, FALSE) < 0) {
       tls_log("%s", "TLS/TLS-C negotiation failed on control channel");

       if (tls_required_on_ctrl)
         end_login(1);

       pr_response_add_err(R_550, "TLS handshake failed");
       return ERROR(cmd);
     }
     tls_flags |= TLS_SESS_ON_CTRL;

  } else if (!strcmp(cmd->argv[1], "SSL") ||
     !strcmp(cmd->argv[1], "TLS-P")) {
    pr_response_send(R_234, "AUTH %s successful", cmd->argv[1]);

    tls_log("%s", "SSL/TLS-P requested, starting TLS handshake");
    if (tls_accept(session.c, FALSE) < 0) {
      tls_log("%s", "SSL/TLS-P negotiation failed on control channel");

      if (tls_required_on_ctrl)
        end_login(1);

      pr_response_add_err(R_550, "TLS handshake failed");
      return ERROR(cmd);
    }
    tls_flags |= TLS_SESS_ON_CTRL;
    tls_flags |= TLS_SESS_NEED_DATA_PROT;

  } else {
    pr_response_add_err(R_504, "AUTH %s unsupported", cmd->argv[1]);
    tls_log("AUTH %s unsupported, declining", cmd->argv[1]);

    /* Allow other RFC2228 modules a chance a handling this command. */
    return DECLINED(cmd);
  }

  return HANDLED(cmd);
}

MODRET tls_pbsz(cmd_rec *cmd) {

  if (!tls_engine)
    return DECLINED(cmd);

  CHECK_CMD_ARGS(cmd, 2);

  if (!(tls_flags & TLS_SESS_ON_CTRL)) {
    pr_response_add_err(R_503,
      "PBSZ not allowed on insecure control connection");

    /* Allow other RFC2228 modules a chance a handling this command. */
    return DECLINED(cmd);
  }

  /* We expect "PBSZ 0" */
  if (!strcmp(cmd->argv[1], "0"))
    pr_response_add(R_200, "PBSZ 0 successful");
  else
    pr_response_add(R_200, "PBSZ=0 successful");

  tls_flags |= TLS_SESS_PBSZ_OK;
  return HANDLED(cmd);
}

MODRET tls_prot(cmd_rec *cmd) {

  if (!tls_engine)
    return DECLINED(cmd);

  CHECK_CMD_ARGS(cmd, 2);

  if (!(tls_flags & TLS_SESS_PBSZ_OK)) {
    pr_response_add_err(R_503, "You must issue the PBSZ command prior to PROT");

    /* Allow other RFC2228 modules a chance a handling this command. */
    return DECLINED(cmd);
  }

  /* Only PROT C or PROT P is valid with respect to SSL/TLS. */
  if (!strcmp(cmd->argv[1], "C")) {
    char *mesg = "Protection set to Clear";

    if (!tls_required_on_data) {

      /* Only accept this if SSL/TLS is not required, by policy, on data
       * connections.
       */
      tls_flags &= ~TLS_SESS_NEED_DATA_PROT;
      pr_response_add(R_200, "%s", mesg);
      tls_log("%s", mesg);

    } else {
      pr_response_add_err(R_534, "Unwilling to accept security parameters");
      tls_log("%s: unwilling to accept security parameter (%s), declining",
        cmd->argv[0], cmd->argv[1]);
      return ERROR(cmd);
    }

  } else if (!strcmp(cmd->argv[1], "P")) {
    char *mesg = "Protection set to Private";

    tls_flags |= TLS_SESS_NEED_DATA_PROT;
    pr_response_add(R_200, "%s", mesg);
    tls_log("%s", mesg);

  } else if (!strcmp(cmd->argv[1], "S") || !strcmp(cmd->argv[1], "E")) {
    pr_response_add_err(R_536, "PROT %s unsupported", cmd->argv[1]);

    /* By the time the logic reaches this point, there must have been
     * an SSL/TLS session negotiated; other AUTH mechanisms will handle
     * things differently, and when they do, the logic of this handler
     * would not reach this point.  This means that it would not be impolite
     * to return ERROR here, rather than DECLINED: it shows that mod_tls
     * is handling the security mechanism, and that this module does not
     * allow for the unsupported PROT levels.
     */
    return ERROR(cmd);

  } else {
    pr_response_add_err(R_504, "PROT %s unsupported", cmd->argv[1]);
    return ERROR(cmd);
  }

  return HANDLED(cmd);
}

/* Configuration handlers
 */

/* usage: TLSCACertificateFile file */
MODRET set_tlscacertfile(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if (!file_exists(cmd->argv[1]))
    CONF_ERROR(cmd, "file does not exist");

  if (*cmd->argv[1] != '/')
    CONF_ERROR(cmd, "parameter must be an absolute path");

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return HANDLED(cmd);
}

/* usage: TLSCACertificatePath path */
MODRET set_tlscacertpath(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

   if (!dir_exists(cmd->argv[1]))
    CONF_ERROR(cmd, "parameter must be a directory path");

  if (*cmd->argv[1] != '/')
    CONF_ERROR(cmd, "parameter must be an absolute path");
 
  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]); 
  return HANDLED(cmd);
}

/* usage: TLSCARevocationFile file */
MODRET set_tlscacrlfile(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (!file_exists(cmd->argv[1]))
    CONF_ERROR(cmd, "file does not exist");

  if (*cmd->argv[1] != '/')
    CONF_ERROR(cmd, "parameter must be an absolute path");

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return HANDLED(cmd);
}

/* usage: TLSCARevocationPath path */
MODRET set_tlscacrlpath(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

   if (!dir_exists(cmd->argv[1]))
    CONF_ERROR(cmd, "parameter must be a directory path");

  if (*cmd->argv[1] != '/')
    CONF_ERROR(cmd, "parameter must be an absolute path");

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return HANDLED(cmd);
}

/* usage: TLSCertificateChainFile file */
MODRET set_tlscertchain(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (!file_exists(cmd->argv[1]))
    CONF_ERROR(cmd, "file does not exist");

  if (*cmd->argv[1] != '/')
    CONF_ERROR(cmd, "parameter must be an absolute path");

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return HANDLED(cmd);
}

/* usage: TLSCipherSuite string */
MODRET set_tlsciphersuite(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return HANDLED(cmd);
}

/* usage: TLSDHParamFile file */
MODRET set_tlsdhparamfile(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (!file_exists(cmd->argv[1]))
    CONF_ERROR(cmd, "file does not exist");

  if (*cmd->argv[1] != '/')
    CONF_ERROR(cmd, "parameter must be an absolute path");

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return HANDLED(cmd);
}

/* usage: TLSDSACertificateFile file */
MODRET set_tlsdsacertfile(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (!file_exists(cmd->argv[1]))
    CONF_ERROR(cmd, "file does not exist");

  if (*cmd->argv[1] != '/')
    CONF_ERROR(cmd, "parameter must be an absolute path");

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return HANDLED(cmd);
}

/* usage: TLSDSACertificateKeyFile file */
MODRET set_tlsdsakeyfile(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (!file_exists(cmd->argv[1]))
    CONF_ERROR(cmd, "file does not exist");

  if (*cmd->argv[1] != '/')
    CONF_ERROR(cmd, "parameter must be an absolute path");

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return HANDLED(cmd);
}

/* usage: TLSEngine on|off */
MODRET set_tlsengine(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((bool = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;

  return HANDLED(cmd);
}

/* usage: TLSLog file */
MODRET set_tlslog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return HANDLED(cmd);
}

/* usage: TLSOptions opt1 opt2 ... */
MODRET set_tlsoptions(cmd_rec *cmd) {
  config_rec *c = NULL;
  register unsigned int i = 0;
  unsigned long opts = 0UL;

  if (cmd->argc-1 == 0)
    CONF_ERROR(cmd, "wrong number of parameters");

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);

  for (i = 1; i < cmd->argc; i++) {
    if (!strcmp(cmd->argv[i], "AllowDotLogin"))
      opts |= TLS_OPT_ALLOW_DOT_LOGIN;

    else if (!strcmp(cmd->argv[i], "ExportCertData"))
      opts |= TLS_OPT_EXPORT_CERT_DATA;

    else if (!strcmp(cmd->argv[i], "NoCertRequest"))
      opts |= TLS_OPT_NO_CERT_REQUEST;

    else if (!strcmp(cmd->argv[i], "StdEnvVars"))
      opts |= TLS_OPT_STD_ENV_VARS;

    else if (!strcmp(cmd->argv[i], "dNSNameRequired"))
      opts |= TLS_OPT_VERIFY_CERT_FQDN;
 
    else if (!strcmp(cmd->argv[i], "iPAddressRequired"))
      opts |= TLS_OPT_VERIFY_CERT_IP_ADDR;

    else
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown TLSOption: '",
        cmd->argv[i], "'", NULL));
  }

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = opts;

  return HANDLED(cmd);
}

/* usage: TLSProtocol protocol */
MODRET set_tlsprotocol(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if (!strcasecmp(cmd->argv[1], "SSLv23"))
    tls_protocol = "SSLv23";

  else if (!strcasecmp(cmd->argv[1], "SSLv3"))
    tls_protocol = "SSLv3";

  else if (!strcasecmp(cmd->argv[1], "TLSv1"))
    tls_protocol = "TLSv1";

  else
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown protocol: '",
      cmd->argv[1], "'", NULL));

  return HANDLED(cmd);
}

/* usage: TLSRandomSeed file */
MODRET set_tlsrandseed(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  /* NOTE: not yet implemented/used */
  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return HANDLED(cmd);
}

/* usage: TLSRenegotiate [ctrl nsecs] [data nbytes] */
MODRET set_tlsrenegotiate(cmd_rec *cmd) {
#if OPENSSL_VERSION_NUMBER > 0x000907000L
  register unsigned int i = 0;
  config_rec *c = NULL;

  if (cmd->argc-1 < 1 || cmd->argc-1 > 8)
    CONF_ERROR(cmd, "wrong number of parameters");

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (!strcasecmp(cmd->argv[1], "none")) {
    add_config_param(cmd->argv[0], 0);
    return HANDLED(cmd);
  }

  c = add_config_param(cmd->argv[0], 4, NULL, NULL, NULL, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = 0;
  c->argv[1] = pcalloc(c->pool, sizeof(off_t));
  *((off_t *) c->argv[1]) = 0;
  c->argv[2] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[2]) = 0;
  c->argv[3] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[3]) = TRUE;

  for (i = 1; i < cmd->argc; i++) {
    if (!strcmp(cmd->argv[i], "ctrl")) {
      int secs = atoi(cmd->argv[i+1]);

      if (secs > 0)
        *((int *) c->argv[0]) = secs;

      else
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": ", 
          cmd->argv[i], " must be greater than zero: '", cmd->argv[i+1], "'",
          NULL));

      i += 2;
    }

    if (!strcmp(cmd->argv[i], "data")) {
      char *tmp = NULL;
      unsigned long kbytes = strtoul(cmd->argv[i+1], &tmp, 10);

      if (!(tmp && *tmp))
        *((off_t *) c->argv[1]) = (off_t) kbytes * 1024;

      else
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": ",
          cmd->argv[i], " must be greater than zero: '", cmd->argv[i+1], "'",
          NULL));

      i += 2;
    }

    if (!strcmp(cmd->argv[i], "required")) {
      int bool = get_boolean(cmd, i+1);

      if (bool != -1)
        *((unsigned char *) c->argv[3]) = bool;

      else
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": ",
          cmd->argv[i], " must be a Boolean value: '", cmd->argv[i+1], "'",
          NULL));

      i += 2;
    }

    if (!strcmp(cmd->argv[i], "timeout")) {
      int secs = atoi(cmd->argv[i+1]);
      
      if (secs > 0)
        *((int *) c->argv[2]) = secs;

      else
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": ", 
          cmd->argv[i], " must be greater than zero: '", cmd->argv[i+1], "'",
          NULL));

      i += 2;
    }
  }

  return HANDLED(cmd);
#else
  CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, " requires OpenSSL-0.9.7 or greater",
    NULL));
#endif
}

/* usage: TLSRequired on|off|both|ctrl|control|data */
MODRET set_tlsrequired(cmd_rec *cmd) {
  int bool = -1;
  unsigned char on_ctrl = FALSE, on_data = FALSE;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((bool = get_boolean(cmd, 1)) == -1) {

    if (!strcmp(cmd->argv[1], "control") || !strcmp(cmd->argv[1], "ctrl"))
      on_ctrl = TRUE;

    else if (!strcmp(cmd->argv[1], "data"))
      on_data = TRUE;

    else if (!strcmp(cmd->argv[1], "both")) {
      on_ctrl = TRUE;
      on_data = TRUE;
    
    } else
      CONF_ERROR(cmd, "bad parameter");

  } else {
    if (bool == TRUE) {
      on_ctrl = TRUE;
      on_data = TRUE;
    }
  }

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = on_ctrl;
  c->argv[1] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[1]) = on_data;

  return HANDLED(cmd);
}

/* usage: TLSRSACertificateFile file */
MODRET set_tlsrsacertfile(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (!file_exists(cmd->argv[1]))
    CONF_ERROR(cmd, "file does not exist");

  if (*cmd->argv[1] != '/')
    CONF_ERROR(cmd, "parameter must be an absolute path");

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return HANDLED(cmd);
}

/* usage: TLSRSACertificateKeyFile file */
MODRET set_tlsrsakeyfile(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (!file_exists(cmd->argv[1]))
    CONF_ERROR(cmd, "file does not exist");

  if (*cmd->argv[1] != '/')
    CONF_ERROR(cmd, "parameter must be an absolute path");

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return HANDLED(cmd);
}

/* usage: TLSVerifyClient on|off */
MODRET set_tlsverifyclient(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((bool = get_boolean(cmd, 1)) == -1)
     CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;

  return HANDLED(cmd);
}

/* usage: TLSVerifyDepth depth */
MODRET set_tlsverifydepth(cmd_rec *cmd) {
  int depth = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if ((depth = atoi(cmd->argv[1])) < 0)
    CONF_ERROR(cmd, "depth must be zero or greater");
 
  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = depth;
 
  return HANDLED(cmd);
}

/* Initialization routines
 */

static void tls_sess_exit(void) {

  /* OpenSSL cleanup */
  tls_cleanup();

  /* Write out a new RandomSeed file, for use later */
  if (tls_rand_file)
    RAND_write_file(tls_rand_file);

  /* Done with the NetIO objects */
  if (tls_ctrl_netio)
    destroy_pool(tls_ctrl_netio->pool);

  if (tls_data_netio)
    destroy_pool(tls_data_netio->pool);

  tls_closelog();
  return;
}

static int tls_init(void) {
  int res = 0;

  /* Install our control channel NetIO handlers. */
  tls_netio_install_ctrl();

  /* Initialize the OpenSSL context. */
  res = tls_init_ctxt();

  return 0;
}

static int tls_sess_init(void) {
  int res = 0;
  unsigned char *tmp = NULL;
  unsigned long *opts = NULL;
  config_rec *c = NULL;

  /* First, check to see whether mod_tls is even enabled. */
  if ((tmp = get_param_ptr(main_server->conf, "TLSEngine",
      FALSE)) != NULL && *tmp == TRUE)
    tls_engine = TRUE;

  else {

    /* No need for this modules's control channel NetIO handlers
     * anymore.
     */
    pr_unregister_netio(PR_NETIO_STRM_CTRL);

    /* No need for all the OpenSSL stuff in this process space, either.
     */
    tls_cleanup();

    return 0;
  }

  if ((tls_cipher_suite = get_param_ptr(main_server->conf,
      "TLSCipherSuite", FALSE)) == NULL)
    tls_cipher_suite = TLS_DEFAULT_CIPHER_SUITE;

  tls_crl_file = get_param_ptr(main_server->conf,
    "TLSRevocationFile", FALSE);
  tls_crl_path = get_param_ptr(main_server->conf, 
    "TLSRevocationPath", FALSE);

  tls_dhparam_file = get_param_ptr(main_server->conf,
    "TLSDHParamFile", FALSE);

  tls_dsa_cert_file = get_param_ptr(main_server->conf,
    "TLSDSACertificateFile", FALSE);
  tls_dsa_key_file = get_param_ptr(main_server->conf,
    "TLSDSACertificateKeyFile", FALSE);

  tls_rsa_cert_file = get_param_ptr(main_server->conf,
    "TLSRSACertificateFile", FALSE);
  tls_rsa_key_file = get_param_ptr(main_server->conf,
    "TLSRSACertificateKeyFile", FALSE);

  if ((opts = get_param_ptr(main_server->conf, "TLSOptions", FALSE)) != NULL)
    tls_opts = *opts;

  if ((tmp = get_param_ptr(main_server->conf, "TLSVerifyClient",
      FALSE)) != NULL && *tmp == TRUE) {
    int *depth = NULL;
    tls_flags |= TLS_SESS_VERIFY_CLIENT;

    if ((depth = get_param_ptr(main_server->conf, "TLSVerifyDepth",
        FALSE)) != NULL)
      tls_verify_depth = *depth;
  }

  if ((c = find_config(main_server->conf, CONF_PARAM, "TLSRequired",
      FALSE))) {
    tls_required_on_ctrl = *((unsigned char *) c->argv[0]);
    tls_required_on_data = *((unsigned char *) c->argv[1]);
  }

  /* Open the TLSLog, if configured */
  if ((res = tls_openlog()) < 0) {
    if (res == -1)
      log_pri(PR_LOG_NOTICE, MOD_TLS_VERSION
        ": notice: unable to open TLSLog: %s", strerror(errno));

    else if (res == LOG_WRITEABLE_DIR)
      log_pri(PR_LOG_NOTICE, "notice: unable to open TLSLog: "
        "parent directory is world writeable");

    else if (res == LOG_SYMLINK)
      log_pri(PR_LOG_NOTICE, "notice: unable to open TLSLog: "
          "cannot log to a symbolic link");
  }

  /* If UseReverseDNS is set to off, disable TLS_OPT_VERIFY_CERT_FQDN. */
  if ((tls_opts & TLS_OPT_VERIFY_CERT_FQDN) && !ServerUseReverseDNS) {
    tls_opts &= ~TLS_OPT_VERIFY_CERT_FQDN;
    tls_log("%s", "reverse DNS off, disabling TLSOption dNSNameRequired");
  }

  /* Install our data channel NetIO handlers. */
  tls_netio_install_data();

  add_exit_handler(tls_sess_exit);

  /* NOTE: fail session init if TLS server init fails (e.g. res < 0)? */
  /* Initialize the OpenSSL context for this server's configuration. */
  res = tls_init_server();

  return 0;
}

/* Module API tables
 */

static conftable tls_conftab[] = {
  { "TLSCACertificateFile",	set_tlscacertfile,	NULL },
  { "TLSCACertificatePath",	set_tlscacertpath,	NULL },
  { "TLSCARevocationFile",      set_tlscacrlfile,       NULL }, 
  { "TLSCARevocationPath",      set_tlscacrlpath,       NULL }, 
  { "TLSCertificateChainFile",	set_tlscertchain,	NULL },
  { "TLSCipherSuite",		set_tlsciphersuite,	NULL },
  { "TLSDHParamFile",		set_tlsdhparamfile,	NULL },
  { "TLSDSACertificateFile",	set_tlsdsacertfile,	NULL },
  { "TLSDSACertificateKeyFile",	set_tlsdsakeyfile,	NULL },
  { "TLSEngine",		set_tlsengine,		NULL },
  { "TLSLog",			set_tlslog,		NULL },
  { "TLSOptions",		set_tlsoptions,		NULL },
  { "TLSProtocol",		set_tlsprotocol,	NULL },
  { "TLSRandomSeed",		set_tlsrandseed,	NULL },
  { "TLSRenegotiate",		set_tlsrenegotiate,	NULL },
  { "TLSRequired",		set_tlsrequired,	NULL },
  { "TLSRSACertificateFile",	set_tlsrsacertfile,	NULL },
  { "TLSRSACertificateKeyFile",	set_tlsrsakeyfile,	NULL },
  { "TLSVerifyClient",		set_tlsverifyclient,	NULL },
  { "TLSVerifyDepth",		set_tlsverifydepth,	NULL },
  { NULL , NULL, NULL}
};

static cmdtable tls_cmdtab[] = {
  { PRE_CMD,	C_ANY,	G_NONE,	tls_any,	FALSE,	FALSE },
  { CMD,	C_AUTH,	G_NONE,	tls_auth,	FALSE,	FALSE },
  { CMD,	C_PBSZ,	G_NONE,	tls_pbsz,	FALSE,	FALSE },
  { CMD,	C_PROT,	G_NONE,	tls_prot,	FALSE,	FALSE },
  { 0,	NULL }
};

static authtable tls_authtab[] = {
  { 0, "auth",	tls_authenticate },
  { 0, "check",	tls_auth_check   },
  { 0, NULL }
};

module tls_module = {

  /* Always NULL */
    NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "tls",

  /* Module configuration handler table */
  tls_conftab,

  /* Module command handler table */
  tls_cmdtab,

  /* Module authentication handler table */
  tls_authtab,

  /* Module initialization */
  tls_init,

  /* Session initialization */
  tls_sess_init
};

