/*
 * ProFTPD: mod_ldap.h -- header file for mod_ldap and mod_ldap extensions
 * Copyright (c) 2017 The ProFTPD Project
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
 */

#ifndef MOD_LDAP_H
#define MOD_LDAP_H

extern int ldap_logfd;
extern LDAP *ld;
extern char *ldap_authbind_dn;

extern int pr_ldap_connect(LDAP **, int);

#endif /* MOD_LDAP_H */
