/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 2001, 2002, 2003 The ProFTPD Project team
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
 * As a special exemption, Public Flood Software/MacGyver aka Habeeb J. Dihu
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

/* Utility module linked to utilities to provide functions normally
 * present in full src tree.
 * $Id: misc.c,v 1.2 2003-01-02 17:28:23 castaglia Exp $
 */

#include "conf.h"

/* Validate anything returned from the 'outside', since it's untrusted
 * information.
 */
char *inet_validate(char *buf) {
  char *p;
  
  /* Validate anything returned from a DNS.
   */
  for(p = buf; p && *p; p++) {
    /* Per RFC requirements, these are all that are valid from a DNS.
     */
    if(!isalnum(*p) && *p != '.' && *p != '-') {
      /* We set it to _ because we know that's an invalid, yet safe, option
       * for a DNS entry.
       */
      *p = '_';
    }
  }
  
  return buf;
}

/* "safe" strcat, saves room for \0 at end of dest, and refuses to copy
 * more than "n" bytes.
 */

char *sstrcat(char *dest, const char *src, size_t n) {
  register char *d;
  
  for(d = dest; *d && n > 1; d++, n--) ;
  
  while(n-- > 1 && *src)
    *d++ = *src++;
  
  *d = 0;
  return dest;
}

/* "safe" strncpy, saves room for \0 at end of dest, and refuses to copy
 * more than "n" bytes.
 */
char *sstrncpy(char *dest, const char *src, size_t n) {
  register char *d = dest;
  
  if(!dest)
    return NULL;
  
  if(src && *src) {
    for(; *src && n > 1; n--)
      *d++ = *src++;
  }
  
  *d = '\0';
  
  return dest;
}
