/*
 * ProFTPD - mod_sftp compression mgmt
 * Copyright (c) 2008-2016 TJ Saunders
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

#ifndef MOD_SFTP_COMPRESS_H
#define MOD_SFTP_COMPRESS_H

#include "mod_sftp.h"
#include "packet.h"

#define SFTP_COMPRESS_FL_NEW_KEY		1
#define SFTP_COMPRESS_FL_AUTHENTICATED		2

/* Tell the SFTP Compression API to enable only the use of Huffman encoding
 * in zlib (Issue #2366).
 */
#define SFTP_COMPRESS_OPT_USE_HUFFMAN_ONLY	0x001

int sftp_compress_init_read(int flags, unsigned long compress_opts);
const char *sftp_compress_get_read_algo(void);
int sftp_compress_set_read_algo(const char *);
int sftp_compress_read_data(struct ssh2_packet *);

int sftp_compress_init_write(int flags, unsigned long compress_opts);
const char *sftp_compress_get_write_algo(void);
int sftp_compress_set_write_algo(const char *);
int sftp_compress_write_data(struct ssh2_packet *);

#endif /* MOD_SFTP_COMPRESS_H */
