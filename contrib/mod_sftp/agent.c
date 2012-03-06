/*
 * ProFTPD - mod_sftp agent
 * Copyright (c) 2012 TJ Saunders
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
 * $Id: agent.c,v 1.1 2012-03-06 01:17:58 castaglia Exp $
 */

#include "mod_sftp.h"
#include "agent.h"
#include "msg.h"

const char *trace_channel = "ssh2";

/* Size of the buffer we use to talk to the agent. */
#define AGENT_REQUEST_MSGSZ		1024

/* Max size of the agent reply that we will handle. */
#define AGENT_REPLY_MAXSZ		(256 * 1024)

/*

#define SFTP_SSH_AGENT_FAILURE                  5
#define SFTP_SSH_AGENT_SUCCESS                  6

#define SFTP_SSH_AGENT_REPLY_IDENTITIES         12
#define SFTP_SSH_AGENT_REPLY_SIGNED_DATA        14

2. Protocol Messages

All protocol messages are prefixed with their length in bytes, encoded
as a 32 bit unsigned integer. Specifically:

        uint32                  message_length
        byte[message_length]    message

The following message descriptions refer only to the content the
"message" field.


The second constraint requires the agent to seek explicit user
confirmation before performing private key operations with the loaded
key. This constraint is encoded as:

        byte                    SSH_AGENT_CONSTRAIN_CONFIRM

Zero or more constraints may be specified when adding a key with one
of the *_CONSTRAINED requests. Multiple constraints are appended
consecutively to the end of the request:

        byte                    constraint1_type
        ....                    constraint1_data
        byte                    constraint2_type
        ....                    constraint2_data
        ....
        byte                    constraintN_type
        ....                    constraintN_data

Such a sequence of zero or more constraints will be referred to below
as "constraint[]". Agents may determine whether there are constraints

  Note that we will automatically skip any key with a CONFIRM constraint,
  due to the server environment.

2.5.2 Requesting a list of protocol 2 keys

A client may send the following message to request a list of
protocol 2 keys that are stored in the agent:

        byte                    SSH2_AGENTC_REQUEST_IDENTITIES

The agent will reply with the following message header:

        byte                    SSH2_AGENT_IDENTITIES_ANSWER
        uint32                  num_keys

Followed by zero or more consecutive keys, encoded as:

        string                  key_blob
        string                  key_comment

Where "key_blob" is encoded as per RFC 4253 section 6.6 "Public Key
Algorithms" for any of the supported protocol 2 key types.

Make keys.c:get_pkey_from_data() a public function,
sftp_keys_get_pkey_from_data(), so that we can use it to populate the keylist.
It automatically understands the key_blob format.

2.6.2 Protocol 2 private key signature request

A client may use the following message to request signing of data using
a protocol 2 key:

        byte                    SSH2_AGENTC_SIGN_REQUEST
        string                  key_blob
        string                  data
        uint32                  flags

Where "key_blob" is encoded as per RFC 4253 section 6.6 "Public Key
Algorithms" for any of the supported protocol 2 key types. "flags" is
a bit-mask, but at present only one possible value is defined (see below
for its meaning):

        SSH_AGENT_OLD_SIGNATURE         1

Upon receiving this request, the agent will look up the private key that
corresponds to the public key contained in key_blob. It will use this
private key to sign the "data" and produce a signature blob using the
key type-specific method described in RFC 4253 section 6.6 "Public Key
Algorithms".

An exception to this is for "ssh-dss" keys where the "flags" word
contains the value SSH_AGENT_OLD_SIGNATURE. In this case, a legacy
signature encoding is used in lieu of the standard one. In this case,
the DSA signature blob is encoded as:

        byte[40]                signature

The signature will be returned in the response message:

        byte                    SSH2_AGENT_SIGN_RESPONSE
        string                  signature_blob

If the agent cannot find the key specified by the supplied key_blob then
it will return SSH_AGENT_FAILURE.

XXX When is it necessary to use the OLD_SIGNATURE flag?

Use keys.c:sftp_keys_get_hostkey_data() for example of how to generate
the key_blob format for given EVP_PKEY.
 */

static int agent_failure(char resp_status) {
  int failed = FALSE;

  switch (resp_status) {
    case SFTP_SSH_AGENT_FAILURE:
      failed = TRUE;
      break;

    case SFTP_SSH_AGENT_EXTENDED_FAILURE:
      failed = TRUE;
      break;

    case SFTP_SSHCOM_AGENT_FAILURE:
      failed = TRUE;
      break;
  }

  return failed;
}

static unsigned char *agent_request(pool *p, int fd, unsigned char *req,
    uint32_t reqlen, uint32_t *resplen) {
  unsigned char msg[AGENT_REQUEST_MSGSZ], *buf, *ptr;
  uint32_t bufsz, buflen;
  int res;

  bufsz = buflen = sizeof(msg);
  buf = ptr = msg;

  sftp_msg_write_int(&buf, &buflen, reqlen);

  /* Send the message length to the agent. */

  res = write(fd, ptr, (bufsz - buflen));
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3, "error sending request length to agent: %s",
      strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  /* Handle short writes. */
  if (res != (bufsz - buflen)) {
    pr_trace_msg(trace_channel, 3,
      "short write (%d of %lu bytes sent) when talking to agent", res,
      (unsigned long) (bufsz - buflen));
    errno = EIO;
    return NULL;
  }

  /* Send the message payload to the agent. */

  res = write(fd, req, reqlen);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3, "error sending request payload to agent: %s",
      strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  /* Handle short writes. */
  if (res != reqlen) {
    pr_trace_msg(trace_channel, 3,
      "short write (%d of %lu bytes sent) when talking to agent", res,
      (unsigned long) reqlen);
    errno = EIO;
    return NULL;
  }

  /* Wait for a response from the server. */
  /* XXX This needs a timeout, prevent a blocked/bad agent from stalling
   * the server.  Maybe just set an internal timer?
   */

  res = read(fd, msg, sizeof(uint32_t));
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3,
      "error reading response length from agent: %s", strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  /* Sanity check the returned length; we could be dealing with a buggy
   * client (or something else is injecting data into the Unix domain socket).
   * Best be conservative: if we get a response length of more than 256KB,
   * it's too big.  (What about very long lists of keys, and/or large keys?)
   */
  if (res > AGENT_REPLY_MAXSZ) {
    pr_trace_msg(trace_channel, 1,
      "response length (%d) from agent exceeds maximum (%lu), ignoring", res,
      (unsigned long) AGENT_REPLY_MAXSZ);
    errno = EIO;
    return NULL;
  }

  buf = msg;
  buflen = res;

  *resplen = sftp_msg_read_int(p, &buf, &buflen);

  bufsz = buflen = *resplen;
  buf = ptr = palloc(p, bufsz);

  buflen = 0;
  while (buflen != *resplen) {
    pr_signals_handle();

    res = read(fd, buf + buflen, bufsz - buflen);
    if (res < 0) {
      int xerrno = errno;

      pr_trace_msg(trace_channel, 3,
        "error reading %d bytes of response payload from agent: %s",
        (bufsz - buflen), strerror(xerrno));

      errno = xerrno;
      return NULL;
    }

    /* XXX Handle short reads? */
    buflen += res;
  }

  return ptr;
}

static int agent_connect(const char *path) {
  int fd, len;
  struct sockaddr_un sun;

  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  sstrncpy(sun.sun_path, path, sizeof(sun.sun_path));
  len = sizeof(sun);

  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3, "error opening Unix domain socket: %s",
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  fcntl(fd, F_SETFD, FD_CLOEXEC);

  if (connect(fd, (struct sockaddr *) &sun, len) < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2, "error connecting to '%s': %s", path,
      strerror(xerrno));

    (void) close(fd);
    errno = xerrno;
    return -1;
  }

  return fd;
}

int sftp_agent_get_keys(pool *p, const char *agent_path,
    array_header *key_list) {
  int fd, res;
  unsigned char *buf, *req, *resp;
  uint32_t buflen, reqlen, reqsz, resplen;
  char resp_status;

  fd = agent_connect(agent_path);
  if (fd < 0) {
    return -1;
  }

  /* Write out the request for the identities (i.e. the public keys). */

  reqsz = buflen = 64;
  req = buf = palloc(p, reqsz);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH_AGENT_REQ_IDS);

  reqlen = reqsz - buflen;
  resp = agent_request(p, fd, req, reqlen, &resplen);
  if (resp == NULL) {
    int xerrno = errno;

    (void) close(fd);
    errno = xerrno;
    return -1;
  }

  (void) close(fd);

  /* Read the response from the agent. */
 
  resp_status = sftp_msg_read_byte(p, &resp, &resplen); 
  if (agent_failure(resp_status) == TRUE) {
    pr_trace_msg(trace_channel, 5,
      "agent indicated failure (%d) for identities request", resp_status);
    errno = EPERM;
    return -1;
  }

  if (resp_status != SFTP_SSH_AGENT_RESP_IDS) {
    pr_trace_msg(trace_channel, 5, "unknown response type %d from agent",
      resp_status);
    errno = EACCES;
    return -1;
  }

  /* XXX Need to process the data */

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "agent returned %lu bytes of identity data", (unsigned long) resplen);

  errno = ENOSYS;
  return -1;
}

const unsigned char *sftp_agent_sign_data(pool *p, const char *agent_path,
    const unsigned char *key_data, uint32_t key_datalen,
    const unsigned char *data, uint32_t datalen, uint32_t *sig_datalen) {
  int fd;
  unsigned char *buf, *req, *resp, *sig_data;
  uint32_t buflen, flags, reqlen, reqsz, resplen;
  char resp_status;

  fd = agent_connect(agent_path);
  if (fd < 0) {
    return NULL;
  }

  /* XXX When to set flags to OLD_SIGNATURE? */
  flags = 0;

  /* Write out the request for signing the given data. */
  reqsz = buflen = 1 + key_datalen + datalen + 4;
  req = buf = palloc(p, reqsz);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH_AGENT_REQ_SIGN_DATA);
  sftp_msg_write_data(&buf, &buflen, key_data, key_datalen, TRUE);
  sftp_msg_write_data(&buf, &buflen, data, datalen, TRUE);
  sftp_msg_write_int(&buf, &buflen, flags);

  reqlen = reqsz - buflen;
  resp = agent_request(p, fd, req, reqlen, &resplen);
  if (resp == NULL) {
    int xerrno = errno;

    (void) close(fd);
    errno = xerrno;
    return NULL;
  }

  (void) close(fd);

  /* Read the response from the agent. */
 
  resp_status = sftp_msg_read_byte(p, &resp, &resplen); 
  if (agent_failure(resp_status) == TRUE) {
    pr_trace_msg(trace_channel, 5,
      "agent indicated failure (%d) for data signing request", resp_status);
    errno = EPERM;
    return NULL;
  }

  if (resp_status != SFTP_SSH_AGENT_RESP_SIGN_DATA) {
    pr_trace_msg(trace_channel, 5, "unknown response type %d from agent",
      resp_status);
    errno = EACCES;
    return NULL;
  }

  *sig_datalen = sftp_msg_read_int(p, &resp, &resplen);
  sig_data = sftp_msg_read_data(p, &resp, &resplen, *sig_datalen);

  return sig_data; 
}
