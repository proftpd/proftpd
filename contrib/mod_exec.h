/*
 * ProFTPD: mod_exec.h -- header file for mod_exec and backends
 * Copyright (c) 2018 The ProFTPD Project
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
 * As a special exemption, Andrew Houghton and other respective copyright
 * holders give permission to link this program with OpenSSL, and distribute
 * the resulting executable, without including the source code for OpenSSL in
 * the source distribution.
 *
 * $Id: mod_exec.h $
 */

#ifndef MOD_EXEC_H
#define MOD_EXEC_H

const char *exec_subst_var(pool *, const char *, cmd_rec *);
int exec_register_backend(const char *prefix, int (*exec_cmd)(cmd_rec *, config_rec *, int));
extern int exec_engine;

struct exec_event_data {
  unsigned int flags;
  config_rec *c;
  const char *event;
};

#endif /* MOD_EXEC_H */
