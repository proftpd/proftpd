/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2016 The ProFTPD Project team
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

/* File hiding API */

#ifndef PR_HIDING_H
#define PR_HIDING_H

/* Determine whether the given path should be "hidden" or not, akin to
 * dotfiles in Unix.
 *
 * Returns:
 *   1 if the path is to be hidden
 *   0 if the path is not hidden
 *  -1 if there was an error (with errno set appropriately)
 */
int pr_hiding_hide_path(pool *p, const char *path);

/* Register a hiding handler.
 *
 * The return value of the callback handler should match that of the
 * pr_hiding_hide_path() function.
 */
int pr_hiding_register(module *m, const char *handler_name,
  int (*hide_path)(pool *p, const char *, const char *, void *),
  void *user_data);

/* Remove the given hiding handler from the registration lists.  The
 * return value is zero if successful, and -1 if there was an error (in
 * which case, errno will be set appropriately).
 *
 * If the module pointer is non-NULL, the hiding handler being unregistered
 * must have been registered by that module.  If the hiding handler name is
 * non-NULL, then only the handler with that name is unregistered; otherwise,
 * all handlers for the given module will be unregistered.
 *
 * This arrangement means that it is possible, though considered terribly
 * impolite, for the caller to unregister all handlers, regardless of registree,
 * using:
 *
 *  pr_hiding_unregister(NULL, handler_name);
 *
 * Although rare, there are cases where this kind of blanket unregistration
 * is necessary.  More common will be the case where a module needs to
 * unregister all of its hiding handlers at once:
 *
 *  pr_hiding_unregister(&my_module, NULL);
 */
int pr_hiding_unregister(module *m, const char *handler_name);

/* Dump Hiding information. */
void pr_hiding_dump(void (*)(const char *, ...));

/* Internal use only. */
int hiding_init(void);
int hiding_finish(void);

#endif /* PR_HIDING_H */
