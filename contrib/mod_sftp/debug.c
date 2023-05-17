/*
 * ProFTPD - mod_sftp debug msgs
 * Copyright (c) 2008-2017 TJ Saunders
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
 */

#include "mod_sftp.h"
#include "ssh2.h"
#include "msg.h"
#include "packet.h"
#include "debug.h"

extern module sftp_module;

static const char *trace_channel = "ssh2";

static char debug_buf[SFTP_SSH2_DEBUG_MSG_MAX] = {'\0'};

void sftp_debug_message(unsigned char always_show, const char *fmt, ...) {
  struct ssh2_packet *pkt;
  const char *lang = "en-US";
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz;
  int res;
  va_list msg;

  if (fmt == NULL) {
    return;
  }

  va_start(msg, fmt);
  res = pr_vsnprintf(debug_buf, sizeof(debug_buf), fmt, msg);
  va_end(msg);

  debug_buf[sizeof(debug_buf) - 1] = '\0';

  /* Send the client a DEBUG mesg. */
  pkt = sftp_ssh2_packet_create(sftp_pool);

  buflen = bufsz = SFTP_SSH2_DEBUG_MSG_MAX * 2;;
  ptr = buf = palloc(pkt->pool, bufsz);

  pr_trace_msg(trace_channel, 9, "debug message: '%s'", debug_buf);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_DEBUG);
  sftp_msg_write_bool(&buf, &buflen, always_show);
  sftp_msg_write_string(&buf, &buflen, debug_buf);
  sftp_msg_write_string(&buf, &buflen, lang);

  pkt->payload = ptr;
  pkt->payload_len = (bufsz - buflen);

  if (sftp_ssh2_packet_write(sftp_conn->wfd, pkt) < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 12,
      "error writing DEBUG message: %s", strerror(xerrno));
  }

  destroy_pool(pkt->pool);
}

