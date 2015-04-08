/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2014-2015 The ProFTPD Project team
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
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* Coverity modeling file. */

typedef struct module_struct module;

/* ProFTPD functions */
void pr_session_disconnect(module *m, int reason_code, const char *details) {
  __coverity_panic__();
}

/* libc functions */
int setenv(const char *key, const char *value, int overwrite) {
  __coverity_tainted_data_sink__(key);
  __coverity_tainted_data_sink__(value);
}

char *strerror(int errnum) {
  /* ignore */
}

void tpl_fatal(char *fmt, ...) {
  __coverity_panic__();
}
