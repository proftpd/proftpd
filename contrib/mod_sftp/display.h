/*
 * ProFTPD - mod_sftp Display files
 * Copyright (c) 2010 TJ Saunders
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
 * $Id: display.h,v 1.2 2010-12-03 20:42:57 castaglia Exp $
 */

#include "mod_sftp.h"

#ifndef MOD_SFTP_DISPLAY_H
#define MOD_SFTP_DISPLAY_H

const char *sftp_display_fh_get_msg(pool *, pr_fh_t *);

#endif /* MOD_SFTP_DISPLAY_H */
