/*
 * ProFTPD - mod_sftp sftp (fxp)
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
 * $Id: fxp.h,v 1.4 2009-07-27 01:00:59 castaglia Exp $
 */

#include "mod_sftp.h"

#ifndef MOD_SFTP_FXP_H
#define MOD_SFTP_FXP_H

/* SFTP Packet Types */
#define SFTP_SSH2_FXP_INIT		1
#define SFTP_SSH2_FXP_VERSION		2
#define SFTP_SSH2_FXP_OPEN		3
#define SFTP_SSH2_FXP_CLOSE		4 
#define SFTP_SSH2_FXP_READ		5 
#define SFTP_SSH2_FXP_WRITE		6
#define SFTP_SSH2_FXP_LSTAT		7
#define SFTP_SSH2_FXP_FSTAT		8
#define SFTP_SSH2_FXP_SETSTAT		9
#define SFTP_SSH2_FXP_FSETSTAT		10 
#define SFTP_SSH2_FXP_OPENDIR		11
#define SFTP_SSH2_FXP_READDIR		12
#define SFTP_SSH2_FXP_REMOVE		13
#define SFTP_SSH2_FXP_MKDIR		14
#define SFTP_SSH2_FXP_RMDIR		15
#define SFTP_SSH2_FXP_REALPATH		16
#define SFTP_SSH2_FXP_STAT		17
#define SFTP_SSH2_FXP_RENAME		18
#define SFTP_SSH2_FXP_READLINK		19
#define SFTP_SSH2_FXP_SYMLINK		20
#define SFTP_SSH2_FXP_LINK		21
#define SFTP_SSH2_FXP_LOCK		22
#define SFTP_SSH2_FXP_UNLOCK		23
#define SFTP_SSH2_FXP_STATUS		101
#define SFTP_SSH2_FXP_HANDLE		102
#define SFTP_SSH2_FXP_DATA		103
#define SFTP_SSH2_FXP_NAME		104
#define SFTP_SSH2_FXP_ATTRS		105
#define SFTP_SSH2_FXP_EXTENDED		200
#define SFTP_SSH2_FXP_EXTENDED_REPLY	201

int sftp_fxp_handle_packet(pool *, void *, uint32_t, char *, uint32_t);

int sftp_fxp_open_session(uint32_t);
int sftp_fxp_close_session(uint32_t);

int sftp_fxp_set_protocol_version(unsigned int, unsigned int);

/* Set the SFTP protocol version at which UTF8 decoding/encoding will be done
 * on the paths/strings sent to/from the SFTP client.  The default SFTP
 * protocol version at which this happens, by IETF Draft, is 4.  Some sites
 * (e.g. Japanese sites) may need the encoding facilities for other SFTP
 * protocol versions, however.
 */
int sftp_fxp_set_utf8_protocol_version(unsigned int);

void sftp_fxp_use_gmt(int);

#endif
