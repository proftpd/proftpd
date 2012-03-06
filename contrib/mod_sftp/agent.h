/*
 * ProFTPD - mod_sftp SSH agent interaction
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
 * $Id: agent.h,v 1.1 2012-03-06 01:17:58 castaglia Exp $
 */

#include "mod_sftp.h"

#ifndef MOD_SFTP_AGENT_H
#define MOD_SFTP_AGENT_H

struct agent_key {
  const unsigned char *key_data;
  uint32_t key_datalen;
  const char *agent_path;
};

/* These values from OpenSSH's PROTOCOL.agent file, with some from the
 * OpenSSH authfd.h header.
 */
#define SFTP_SSH_AGENT_FAILURE			5
#define SFTP_SSH_AGENT_SUCCESS			6

#define SFTP_SSH_AGENT_REQ_IDS			11
#define SFTP_SSH_AGENT_RESP_IDS			12

#define SFTP_SSH_AGENT_REQ_SIGN_DATA		13
#define SFTP_SSH_AGENT_RESP_SIGN_DATA		14

#define SFTP_SSH_AGENT_EXTENDED_FAILURE		30

/* Error code for ssh.com's ssh-agent2 process. */
#define SFTP_SSHCOM_AGENT_FAILURE		102

int sftp_agent_get_keys(pool *p, const char *, array_header *);
const unsigned char *sftp_agent_sign_data(pool *, const char *,
  const unsigned char *, uint32_t, const unsigned char *, uint32_t, uint32_t *);

#endif
