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

/*
 * Resource allocation code
 */

#include "conf.h"

/* Manage free storage blocks */

union align
{
  char *cp;
  void (*f)();
  long l;
  FILE *fp;
  double d;
};

#define CLICK_SZ (sizeof(union align))

union block_hdr
{
  union align a;

  /* Actual header */

  struct {
    char *endp;
    union block_hdr *next;
    char *first_avail;
  } h;
};

union block_hdr *block_freelist = NULL;

/* Statistics */
unsigned int stat_malloc = 0;	/* incr when malloc required */
unsigned int stat_freehit = 0;	/* incr when freelist used */

/* Lowest level memory allocation functions
 */

static void *null_alloc(size_t size)
{
  void *ret = 0;

  if(size == 0)
    ret = malloc(size);
  if(ret == 0) {
    log_pri(LOG_ERR,"Fatal: Memory exhausted.");
    exit(1);
  }

  return ret;
}

void *xmalloc(size_t size)
{
  void *ret;

  ret = malloc(size);
  if(ret == 0)
    ret = null_alloc(size);
  return ret;
}

void *xcalloc(size_t num, size_t size)
{
  void *ret;

  ret = calloc(num,size);
  if(ret == 0)
    ret = null_alloc(num * size);
  return ret;
}

void *xrealloc(void *p, size_t size)
{
  if(p == 0)
    return xmalloc(size);
  p = realloc(p,size);
  if(p == 0)
    p = null_alloc(size);
  return p;
}

/* Grab a completely new block from the system pool.  Relies on malloc()
 * to return truely aligned memory.
 */

union block_hdr *malloc_block(int size)
{
  union block_hdr *blok =
    (union block_hdr*)xmalloc(size + sizeof(union block_hdr));

  blok->h.next = NULL;
  blok->h.first_avail = (char *)(blok+1);
  blok->h.endp = size + blok->h.first_avail;

  return blok;
}

void chk_on_blk_list(union block_hdr *blok, union block_hdr *free_blk)
{
  /* Debug code */

  while(free_blk) {
    if(free_blk == blok) {
      log_pri(LOG_ERR,"Fatal: DEBUG: Attempt to free already free block in chk_on_blk_list().");
      exit(1);
    }

    free_blk = free_blk->h.next;
  }
}

/* Free a chain of blocks -- _must_ call with alarms blocked. */

void free_blocks(union block_hdr *blok)
{
  /* Puts new blocks at head of block list, point next pointer of
   * last block in chain to free blocks we already had.
   */

  union block_hdr *old_free_list = block_freelist;

  if(!blok)
    return;		/* Shouldn't be freeing an empty pool */

  block_freelist = blok;

  /* Adjust first_avail pointers */

  while(blok->h.next) {
    chk_on_blk_list(blok,old_free_list);
    blok->h.first_avail = (char *)(blok + 1);
    blok = blok->h.next;
  }

  chk_on_blk_list(blok,old_free_list);
  blok->h.first_avail = (char*)(blok + 1);
  blok->h.next = old_free_list;
}

/* Get a new block, from the free list if possible, otherwise malloc
 * a new one.  *BLOCK ALARMS BEFORE CALLING*
 */

union block_hdr *new_block(int min_size)
{
  int biggest = 0;
  union block_hdr **lastptr = &block_freelist;
  union block_hdr *blok = block_freelist;

  min_size = 1 + ((min_size - 1) / BLOCK_MINFREE);
  min_size *= BLOCK_MINFREE;

  while(blok) {
    biggest = blok->h.endp - blok->h.first_avail;
    if(min_size <= blok->h.endp - blok->h.first_avail) {
      /* It's available */
      *lastptr = blok->h.next;
      stat_freehit++;
      blok->h.next = NULL;
      return blok;
    } else {
      lastptr = &blok->h.next;
      blok = blok->h.next;
    }
  }

  /* malloc a new one */
  stat_malloc++;
  return malloc_block(min_size);
}

/* accounting */

long bytes_in_block_list(union block_hdr *blok)
{
  long size = 0;

  while(blok) {
    size += blok->h.endp - (char*)(blok+1);
    blok = blok->h.next;
  }

  return size;
}

struct cleanup;

static void run_cleanups(struct cleanup *);

/* Pool internal and management */

struct pool {
  union block_hdr *first;
  union block_hdr *last;
  struct cleanup *cleanups;
  struct pool *sub_pools;
  struct pool *sub_next;
  struct pool *sub_prev;
  struct pool *parent;
  char *free_first_avail;
  char symbol;
};

pool *permanent_pool = NULL;
pool *global_config_pool = NULL;

/* Each pool structure is allocated in the start of it's own first block,
 * so there is a need to know how many bytes that is (once properly
 * aligned).
 */

#define POOL_HDR_CLICKS (1 + ((sizeof(struct pool) - 1) / CLICK_SZ))
#define POOL_HDR_BYTES (POOL_HDR_CLICKS * CLICK_SZ)

/* walk all pools, starting with top level permanent pool, displaying a
 * tree.
 */

static long __walk_pools(pool *p, int level)
{
  char _levelpad[80] = "";
  long total = 0;

  if(!p)
    return 0;

  if(level > 1) {
    memset(_levelpad,' ',sizeof(_levelpad)-1);
    if((level - 1) * 3 >= sizeof(_levelpad))
      _levelpad[sizeof(_levelpad)-1] = 0;
    else
      _levelpad[(level - 1) * 3] = '\0';
  }

  for(; p; p = p->sub_next) {
    total += bytes_in_block_list(p->first);
    if(level == 0) {
      if(p->symbol)
        log_pri(LOG_NOTICE,"(%s)0x%08x bytes",
			&p->symbol,
			bytes_in_block_list(p->first));
      else
        log_pri(LOG_NOTICE,"0x%08x bytes",
	  	      	bytes_in_block_list(p->first));
    } else {
      if(p->symbol)
	log_pri(LOG_NOTICE,"%s(%s)\\- 0x%08x bytes",_levelpad,
			&p->symbol,
			bytes_in_block_list(p->first));
      else
        log_pri(LOG_NOTICE,"%s\\- 0x%08x bytes",_levelpad,
              bytes_in_block_list(p->first));
    }
    
    /* recurse */
    if(p->sub_pools)
      total += __walk_pools(p->sub_pools,level+1);  
  }

  return total;
}

void debug_pool_info(void)
{
  if(block_freelist)
    log_pri(LOG_NOTICE,"Free block list: 0x%08x bytes",
            bytes_in_block_list(block_freelist));
  else
    log_pri(LOG_NOTICE,"Free block list: EMPTY");

  log_pri(LOG_NOTICE,"%u count blocks malloc'd.",stat_malloc);
  log_pri(LOG_NOTICE,"%u count blocks reused.",stat_freehit); 
}

void debug_walk_pools(void)
{
  log_pri(LOG_NOTICE,"Memory pool allocation:");
  log_pri(LOG_NOTICE,"Total 0x%08x bytes allocated",
          __walk_pools(permanent_pool,0));
  debug_pool_info();
}

/* Release the entire free block list */
void pool_release_free_block_list(void)
{
  union block_hdr *blok,*next;

  block_alarms();
  
  blok = block_freelist;
  if(blok) {
    for(next = blok->h.next; next; blok = next, next = blok->h.next)
      free(blok);
  }
  block_freelist = NULL;

  unblock_alarms();
}

struct pool *make_named_sub_pool(struct pool *p, const char *symbol)
{
  union block_hdr *blok;
  pool *new_pool;

  block_alarms();

  blok = new_block(0);
  new_pool = (pool *) blok->h.first_avail;
  
  blok->h.first_avail += POOL_HDR_BYTES;
  memset((char *) new_pool, 0, sizeof(struct pool));

#if 0 /* This is simply unused, and will be removed in 1.3 - MacGyver */  
  if(symbol) {
    /* This could be questionable... - MacGyver
     */
    sstrncpy(&new_pool->symbol, symbol, strlen(&new_pool->symbol));
    
    /* Alignment issues on Sparc, SGI, and probably other hardware,
     * demand this.
     */
    blok->h.first_avail += (strlen(symbol) / POOL_HDR_BYTES + 1) *
      POOL_HDR_BYTES;
  }
#endif

  new_pool->free_first_avail = blok->h.first_avail;
  new_pool->first = new_pool->last = blok;
  
  if(p) {
    new_pool->parent = p;
    new_pool->sub_next = p->sub_pools;
    if(new_pool->sub_next)
      new_pool->sub_next->sub_prev = new_pool;
    p->sub_pools = new_pool;
  }

  unblock_alarms();

  return new_pool;
}

struct pool *make_sub_pool(struct pool *p)
{
  return make_named_sub_pool(p,NULL);
}

/* Initialize the pool system by creating the base permanent_pool. */

void init_alloc(void) {
  permanent_pool = make_named_sub_pool(NULL, "permanent_pool");
}

static void clear_pool(struct pool *p)
{

  if(!p)
    return;			/* Sanity check */

  block_alarms();

  run_cleanups(p->cleanups);	 	p->cleanups = NULL;

  while(p->sub_pools)
    destroy_pool(p->sub_pools);

  p->sub_pools = NULL;

  free_blocks(p->first->h.next);	p->first->h.next = NULL;

  p->last = p->first;
  p->first->h.first_avail = p->free_first_avail;

  unblock_alarms();
}

void destroy_pool(pool *p)
{
  block_alarms();

  if(p->parent) {
    if(p->parent->sub_pools == p) p->parent->sub_pools = p->sub_next;
    if(p->sub_prev) p->sub_prev->sub_next = p->sub_next;
    if(p->sub_next) p->sub_next->sub_prev = p->sub_prev;
  }

  clear_pool(p);

  free_blocks(p->first);

  unblock_alarms();
}

long bytes_in_pool(pool *p) { return bytes_in_block_list(p->first); }
long bytes_in_free_blocks(void) { return bytes_in_block_list(block_freelist); }

/* Allocation inteface ... 
 */

void *palloc(struct pool *p, int reqsize)
{
  /* Round up requested size to an even number of aligned units */

  int nclicks = 1 + ((reqsize - 1) / CLICK_SZ);
  int size = nclicks * CLICK_SZ;

  /* For performance, see if space is availabe in most recently
   * allocated block.
   */

  union block_hdr *blok = p->last;
  char *first_avail = blok->h.first_avail;
  char *new_first_avail;

  if(reqsize <= 0)
    return NULL;

  block_alarms();
  new_first_avail = first_avail + size;

  if(new_first_avail <= blok->h.endp) {
    blok->h.first_avail = new_first_avail;
    unblock_alarms();
    return (void *)first_avail;
  }

  /* Need a new one that's big enough */

  blok = new_block(size);
  p->last->h.next = blok;
  p->last = blok;

  first_avail = blok->h.first_avail;
  blok->h.first_avail += size;

  unblock_alarms();
  return (void*)first_avail;
}

void *pcalloc(struct pool *p, int size)
{
  void *res = palloc(p,size);
  memset(res,'\0',size);
  return res;
}

char *pstrdup(struct pool *p, const char *s)
{
  char *res;

  if(!s)
    return NULL;

  res = palloc(p, strlen(s) + 1);
  sstrncpy(res, s, strlen(s) + 1);
  return res;
}

char *pstrndup(struct pool *p, const char *s, int n)
{
  char *res;

  if(!s)
    return NULL;

  res = palloc(p, n + 1);

  sstrncpy(res, s, n + 1);
  return res;
}

char *pdircat(pool *p, ...)
{
  char *argp, *res;
  char last;

  int len = 0, count = 0;
  va_list dummy;

  va_start(dummy,p);

  last = 0;

  while((res = va_arg(dummy,char*)) != NULL) {
    /* If the first argument is "", we have to account for a leading /
     * which must be added.  -jss 3/2/2001
     */
    if(!count++ && !*res)
      len++;
    else if(last && last != '/' && *res != '/')
      len++;
    else if(last && last == '/' && *res == '/')
      len--;
    len += strlen(res);
    last = res[strlen(res) - 1];
  }

  va_end(dummy);
  res = (char *) pcalloc(p, len + 1);
  
  va_start(dummy, p);
  
  last = 0;
  
  while((argp = va_arg(dummy, char *)) != NULL) {
    if(last && last == '/' && *argp == '/')
      argp++;
    else if(last && last != '/' && *argp != '/')
      sstrcat(res, "/", len + 1);
    
    sstrcat(res, argp, len + 1);
    last = res[strlen(res) - 1];
  }

  va_end(dummy);

  return res;
}

char *pstrcat(pool *p, ...)
{
  char *argp, *res;

  int len = 0;
  va_list dummy;

  va_start(dummy,p);
  
  while((res = va_arg(dummy, char *)) != NULL)
    len += strlen(res);
  
  va_end(dummy);
  
  res = (char*) pcalloc(p, len + 1);
  
  va_start(dummy,p);
  
  while((argp = va_arg(dummy, char *)) != NULL)
    sstrcat(res, argp, len + 1);
  
  va_end(dummy);
  
  return res;
}

/*
 * Array functions
 */

array_header *make_array(pool *p, int nelts, int elt_size)
{
  array_header *res = (array_header*) palloc(p, sizeof(array_header));

  if(nelts < 1) nelts = 1;

  res->elts = pcalloc(p, nelts * elt_size);
  res->pool = p;
  res->elt_size = elt_size;
  res->nelts = 0;
  res->nalloc = nelts;

  return res;
}

void *push_array(array_header *arr)
{
  if(arr->nelts == arr->nalloc) {
    char *new_data = pcalloc(arr->pool, arr->nalloc * arr->elt_size * 2);

    memcpy(new_data, arr->elts, arr->nalloc * arr->elt_size);
    arr->elts = new_data;
    arr->nalloc *= 2;
  }

  ++arr->nelts;
  return ((char*)arr->elts) + (arr->elt_size * (arr->nelts - 1));
}

void array_cat(array_header *dst, const array_header *src)
{
  int elt_size = dst->elt_size;

  if(dst->nelts + src->nelts > dst->nalloc) {
    int new_size = dst->nalloc * 2;
    char *new_data;

    if(new_size == 0) ++new_size;

    while(dst->nelts + src->nelts > new_size)
      new_size *= 2;

    new_data = pcalloc(dst->pool, elt_size * new_size);
    memcpy(new_data, dst->elts, dst->nalloc * elt_size);

    dst->elts = new_data;
    dst->nalloc = new_size;
  }

  memcpy(((char*)dst->elts) + dst->nelts * elt_size, (char*)src->elts,
         elt_size * src->nelts);
  dst->nelts += src->nelts;
}

array_header *copy_array(pool *p, const array_header *arr)
{
  array_header *res = make_array(p,arr->nalloc,arr->elt_size);

  memcpy(res->elts, arr->elts, arr->elt_size * arr->nelts);
  res->nelts = arr->nelts;
  return res;
}

/* copy an array that is assumed to consist solely of strings */
array_header *copy_array_str(pool *p, const array_header *arr)
{
  array_header *res = copy_array(p,arr);
  int i;

  for(i = 0; i < arr->nelts; i++)
    ((char**)res->elts)[i] = pstrdup(p,((char**)res->elts)[i]);

  return res;
}

array_header *copy_array_hdr(pool *p, const array_header *arr)
{
  array_header *res = (array_header *)palloc(p,sizeof(array_header));

  res->elts = arr->elts;
  res->pool = p;
  res->elt_size = arr->elt_size;
  res->nelts = arr->nelts;
  res->nalloc = arr->nelts;		/* Force overflow on push */

  return res;
}

array_header *append_arrays(pool *p,
                            const array_header *first,
			    const array_header *second)
{
  array_header *res = copy_array_hdr(p,first);

  array_cat(res,second);
  return res;
}

/*
 * Generic cleanups
 */

struct cleanup {
  void *data;
  void (*plain_cleanup)(void*);
  void (*child_cleanup)(void*);
  struct cleanup *next;
};

void register_cleanup(pool *p, void *data, void (*plain_cleanup)(void*),
                      void (*child_cleanup)(void*))
{
  struct cleanup *c = (struct cleanup*)palloc(p, sizeof(struct cleanup));
  c->data = data;
  c->plain_cleanup = plain_cleanup;
  c->child_cleanup = child_cleanup;
  c->next = p->cleanups;
  p->cleanups = c;
}

void kill_cleanup(pool *p, void *data, void (*cleanup)(void*))
{
  struct cleanup *c = p->cleanups;
  struct cleanup **lastp = &p->cleanups;

  while(c) {
    if(c->data == data && c->plain_cleanup == cleanup) {
      *lastp = c->next;
      break;
    }

    lastp = &c->next;
    c = c->next;
  }
}

void run_cleanup(pool *p, void *data, void (*cleanup)(void*))
{
  block_alarms();
  (*cleanup)(data);
  kill_cleanup(p,data,cleanup);
  unblock_alarms();
}

static void run_cleanups(struct cleanup *c)
{
  while(c) {
    (*c->plain_cleanup)(c->data);
    c = c->next;
  }
}

static void run_child_cleanups(struct cleanup *c)
{
  while(c) {
    (*c->child_cleanup)(c->data);
    c = c ->next;
  }
}

static void cleanup_pool_for_exec(pool *p)
{
  run_child_cleanups(p->cleanups);
  p->cleanups = NULL;

  for(p = p->sub_pools; p; p = p->sub_next)
    cleanup_pool_for_exec(p);
}

void cleanup_for_exec(void)
{
  block_alarms();
  cleanup_pool_for_exec(permanent_pool);
  unblock_alarms();
}

/*
 * Files and file descriptors
 */

static void fd_cleanup(void *fdv) { close ((int)fdv); }

void note_cleanups_for_fd(pool *p, int fd)
{
  register_cleanup(p,(void*)fd,fd_cleanup,fd_cleanup);
}

void kill_cleanups_for_fd(pool *p, int fd)
{
  kill_cleanup(p,(void*)fd,fd_cleanup);
}

int popenf(pool *p, const char *name, int flg, int mode)
{
  int fd;

  block_alarms();
  fd = open(name,flg,mode);
  if(fd >= 0)
    note_cleanups_for_fd(p,fd);
  unblock_alarms();
  return fd;
}

int pclosef(pool *p, int fd)
{
  int res;

  block_alarms();
  res = close(fd);
  kill_cleanup(p, (void*)fd, fd_cleanup);
  unblock_alarms();
  return res;
}

/* Sep. plain and child cleanups for FILE *, since fclose() flushes
 * the stream
 */

static void file_cleanup(void *fpv) { fclose((FILE*)fpv); }
static void file_child_cleanup(void *fpv)
{ close(fileno((FILE*)fpv)); }

void note_cleanups_for_file(pool *p, FILE *fp)
{
  register_cleanup(p,(void*)fp,file_cleanup,file_child_cleanup);
}

FILE *pfopen(pool *p, const char *name, const char *mode)
{
  FILE *fd = NULL;
  int baseFlag, desc;

  block_alarms();

  if(*mode == 'a') {
    baseFlag = (*(mode+1) == '+') ? O_RDWR : O_WRONLY;
    desc = open(name, baseFlag | O_APPEND | O_CREAT,
                S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
    if(desc >= 0)
      fd = fdopen(desc, mode);
  } else {
    fd = fopen(name, mode);
  }

  if(fd)
    note_cleanups_for_file(p,fd);
  unblock_alarms();
  return fd;
}

FILE *pfdopen(pool *p, int fd, const char *mode)
{
  FILE *f;

  block_alarms();
  f = fdopen(fd,mode);
  if(f)
    note_cleanups_for_file(p,f);

  unblock_alarms();
  return f;
}

int pfclose(pool *p, FILE *fd)
{
  int res;

  block_alarms();
  res = fclose(fd);
  kill_cleanup(p, (void*)fd, file_cleanup);
  unblock_alarms();
  return res;
}

