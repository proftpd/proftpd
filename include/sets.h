/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (C) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
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

/* $Id: sets.h,v 1.3 2001-06-18 17:12:45 flood Exp $
 */

#ifndef __SETS_H
#define __SETS_H

#include "pool.h"

typedef struct XAsetmember xasetmember_t;
typedef struct XAset xaset_t;
typedef int (*XASET_COMPARE)(xasetmember_t *v1,xasetmember_t *v2);
typedef xasetmember_t* (*XASET_MCOPY)(xasetmember_t *mem);

struct XAsetmember {
  xasetmember_t	*next,*prev;
};

struct XAset {
  xasetmember_t *xas_list;
  
  pool		*mempool;
  XASET_COMPARE xas_compare;
};

/* Prototypes */
xaset_t *xaset_create(pool *pool,XASET_COMPARE compf);
xaset_t *xaset_copy(pool *pool,xaset_t *set, size_t msize,
                    XASET_MCOPY copyf);
xaset_t *xaset_subtract(pool *pool, xaset_t *set1, xaset_t *set2, 
                        size_t msize,
                        XASET_MCOPY copyf);
xaset_t *xaset_union(pool *pool, xaset_t *set1, xaset_t *set2,
                     size_t msize,
	             XASET_MCOPY copyf);

int xaset_insert(xaset_t *set, xasetmember_t *member);
int xaset_insert_end(xaset_t *set, xasetmember_t *member);
int xaset_remove(xaset_t *set, xasetmember_t *member);
int xaset_insert_sort(xaset_t *set, xasetmember_t *member, int dupes_allowed);

#endif /* __SETS_H */
