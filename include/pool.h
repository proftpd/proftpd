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
 */

/* Memory allocation/anti-leak system.  Yes, this *IS* stolen from Apache
 * also.  What can I say?  It makes sense, and it's safe (more overhead
 * though)
 * $Id: pool.h,v 1.4 2000-08-02 05:25:24 macgyver Exp $
 */

#ifndef __POOL_H
#define __POOL_H

typedef struct pool pool;

extern pool *permanent_pool;
void init_alloc();
pool *make_sub_pool(pool*);		/* All pools are sub-pools of perm */
pool *make_named_sub_pool(pool*,const char*);

/* Low-level memory allocation */
void *xmalloc(size_t);
void *xcalloc(size_t,size_t);
void *xrealloc(void*,size_t);
void pool_release_free_block_list(void);

/* Clears out _everything_ in a pool, destroying any sub-pools */
void destroy_pool(struct pool*);
void cleanup_for_exec();

/* allocate memory from a pool */
void *palloc(struct pool*, int nbytes);
void *pcalloc(struct pool*, int nbytes);
extern char *pstrdup(struct pool*, const char *s);
extern char *pstrndup(struct pool*, const char *s, int n);
char *pstrcat(struct pool*,...);       /* Must be char* */
char *pdircat(struct pool*,...);	/* Must be char* */

/* MM debugging */
void debug_walk_pools();

/* Array management */

typedef struct {
  pool *pool;
  int elt_size;
  int nelts;
  int nalloc;
  void *elts;
} array_header;

array_header *make_array(pool *p, int nelts, int elt_size);
void *push_array(array_header*);
void array_cat(array_header *dst, const array_header *src);
array_header *append_arrays(pool *, const array_header *,
                            const array_header *);
array_header *copy_array(pool *p, const array_header *src);
array_header *copy_array_hdr(pool *p, const array_header *src);
 
/* Alarm signals can easily interfere with the pooled memory operations,
   thus block_alarms() and unblock_alarms() provide for re-entrant
   security. */

extern void block_alarms();
extern void unblock_alarms();

FILE *pfopen(struct pool *, const char *name, const char *fmode);
FILE *pfdopen(struct pool *, int fd, const char *fmode);
int popenf(struct pool *, const char *name, int flg, int mode);

int pfclose(struct pool *, FILE *);
int pclosef(struct pool *, int fd);


/* Functions for cleanup handlers */
void register_cleanup(pool*,void*,void (*plain_cleanup)(void*),
                      void (*child_cleanup)(void*));
void kill_cleanup(pool*,void*,void (*cleanup)(void*));
void cleanup_for_exec();

/* minimum free bytes in a new block pool */

#define BLOCK_MINFREE TUNABLE_NEW_POOL_SIZE

/* accounting */
long bytes_in_pool(pool *p);
long bytes_in_free_blocks();

#endif /* __POOL_H */
