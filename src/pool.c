/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001-2022 The ProFTPD Project team
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
 * As a special exemption, Public Flood Software/MacGyver aka Habeeb J. Dihu
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

/* Resource allocation code */

#include "conf.h"

/* Manage free storage blocks */

union align {
  char *cp;
  void (*f)(void);
  long l;
  FILE *fp;
  double d;
};

#define CLICK_SZ (sizeof(union align))

union block_hdr {
  union align a;

  /* Padding */
#if defined(_LP64) || defined(__LP64__)
  char pad[32];
#endif

  /* Actual header */
  struct {
    void *endp;
    union block_hdr *next;
    void *first_avail;
  } h;
};

static union block_hdr *block_freelist = NULL;

/* Statistics */
static unsigned int stat_malloc = 0;	/* incr when malloc required */
static unsigned int stat_freehit = 0;	/* incr when freelist used */

static const char *trace_channel = "pool";

/* Debug flags */
static int debug_flags = 0;

#ifdef PR_USE_DEVEL
static void oom_printf(const char *fmt, ...) {
  char buf[PR_TUNABLE_BUFFER_SIZE];
  va_list msg;

  memset(buf, '\0', sizeof(buf));

  va_start(msg, fmt);
  pr_vsnprintf(buf, sizeof(buf), fmt, msg);
  va_end(msg);

  buf[sizeof(buf)-1] = '\0';
  fprintf(stderr, "%s\n", buf);
}
#endif /* PR_USE_DEVEL */

/* Lowest level memory allocation functions
 */

static void null_alloc(void) {
  pr_log_pri(PR_LOG_ALERT, "Out of memory!");
#ifdef PR_USE_DEVEL
  if (debug_flags & PR_POOL_DEBUG_FL_OOM_DUMP_POOLS) {
    pr_pool_debug_memory(oom_printf);
  }
#endif

  exit(1);
}

static void *smalloc(size_t size) {
  void *res;

  if (size == 0) {
    /* Avoid zero-length malloc(); on non-POSIX systems, the behavior is
     * not dependable.  And on POSIX systems, malloc(3) might still return
     * a "unique pointer" for a zero-length allocation (or NULL).
     *
     * Either way, a zero-length allocation request here means that someone
     * is doing something they should not be doing.
     */
    null_alloc();
  }

  res = malloc(size);
  if (res == NULL) {
    null_alloc();
  }

  return res;
}

/* Grab a completely new block from the system pool.  Relies on malloc()
 * to return truly aligned memory.
 */
static union block_hdr *malloc_block(size_t size) {
  union block_hdr *blok =
    (union block_hdr *) smalloc(size + sizeof(union block_hdr));

  blok->h.next = NULL;
  blok->h.first_avail = (char *) (blok + 1);
  blok->h.endp = size + (char *) blok->h.first_avail;

  return blok;
}

static void chk_on_blk_list(union block_hdr *blok, union block_hdr *free_blk,
    const char *pool_tag) {

#ifdef PR_USE_DEVEL
  /* Debug code */

  while (free_blk) {
    if (free_blk != blok) {
      free_blk = free_blk->h.next;
      continue;
    }

    pr_log_pri(PR_LOG_WARNING, "fatal: DEBUG: Attempt to free already free "
     "block in pool '%s'", pool_tag ? pool_tag : "<unnamed>");
    exit(1);
  }
#endif /* PR_USE_DEVEL */
}

/* Free a chain of blocks -- _must_ call with signals blocked. */

static void free_blocks(union block_hdr *blok, const char *pool_tag) {
  /* Puts new blocks at head of block list, point next pointer of
   * last block in chain to free blocks we already had.
   */

  union block_hdr *old_free_list = block_freelist;

  if (blok == NULL) {
    /* Don't free an empty pool. */
    return;
  }

  block_freelist = blok;

  /* Adjust first_avail pointers */

  while (blok->h.next) {
    chk_on_blk_list(blok, old_free_list, pool_tag);
    blok->h.first_avail = (char *) (blok + 1);
    blok = blok->h.next;
  }

  chk_on_blk_list(blok, old_free_list, pool_tag);
  blok->h.first_avail = (char *) (blok + 1);
  blok->h.next = old_free_list;
}

/* Get a new block, from the free list if possible, otherwise malloc a new
 * one.  minsz is the requested size of the block to be allocated.
 * If exact is TRUE, then minsz is the exact size of the allocated block;
 * otherwise, the allocated size will be rounded up from minsz to the nearest
 * multiple of BLOCK_MINFREE.
 *
 * Important: BLOCK ALARMS BEFORE CALLING
 */

static union block_hdr *new_block(int minsz, int exact) {
  union block_hdr **lastptr = &block_freelist;
  union block_hdr *blok = block_freelist;

  if (!exact) {
    minsz = 1 + ((minsz - 1) / BLOCK_MINFREE);
    minsz *= BLOCK_MINFREE;
  }

  /* Check if we have anything of the requested size on our free list first...
   */
  while (blok) {
    if (minsz <= ((char *) blok->h.endp - (char *) blok->h.first_avail)) {
      *lastptr = blok->h.next;
      blok->h.next = NULL;

      stat_freehit++;
      return blok;
    }

    lastptr = &blok->h.next;
    blok = blok->h.next;
  }

  /* Nope...damn.  Have to malloc() a new one. */
  stat_malloc++;
  return malloc_block(minsz);
}

struct cleanup;

static void run_cleanups(struct cleanup *);

/* Pool internal and management */

struct pool_rec {
  union block_hdr *first;
  union block_hdr *last;
  struct cleanup *cleanups;
  struct pool_rec *sub_pools;
  struct pool_rec *sub_next;
  struct pool_rec *sub_prev;
  struct pool_rec *parent;
  char *free_first_avail;
  const char *tag;
};

pool *permanent_pool = NULL;
pool *global_config_pool = NULL;

/* Each pool structure is allocated in the start of it's own first block,
 * so there is a need to know how many bytes that is (once properly
 * aligned).
 */

#define POOL_HDR_CLICKS (1 + ((sizeof(struct pool_rec) - 1) / CLICK_SZ))
#define POOL_HDR_BYTES (POOL_HDR_CLICKS * CLICK_SZ)

static unsigned long blocks_in_block_list(union block_hdr *blok) {
  unsigned long count = 0;

  while (blok) {
    count++;
    blok = blok->h.next;
  }

  return count;
}

static unsigned long bytes_in_block_list(union block_hdr *blok) {
  unsigned long size = 0;

  while (blok) {
    size += ((char *) blok->h.endp - (char *) (blok + 1));
    blok = blok->h.next;
  }

  return size;
}

static unsigned int subpools_in_pool(pool *p) {
  unsigned int count = 0;
  pool *iter;

  if (p->sub_pools == NULL) {
    return 0;
  }

  for (iter = p->sub_pools; iter; iter = iter->sub_next) {
    /* Count one for the current subpool (iter). */
    count += (subpools_in_pool(iter) + 1);
  }

  return count;
}

/* Visit all pools, starting with the top-level permanent pool, walking the
 * hierarchy.
 */
static unsigned long visit_pools(pool *p, unsigned long level,
    void (*visit)(const pr_pool_info_t *, void *), void *user_data) {
  unsigned long total_bytes = 0;

  if (p == NULL) {
    return 0;
  }

  for (; p; p = p->sub_next) {
    unsigned long byte_count = 0, block_count = 0;
    unsigned int subpool_count = 0;
    pr_pool_info_t pinfo;

    byte_count = bytes_in_block_list(p->first);
    block_count = blocks_in_block_list(p->first);
    subpool_count = subpools_in_pool(p);

    total_bytes += byte_count;

    memset(&pinfo, 0, sizeof(pinfo));
    pinfo.have_pool_info = TRUE;
    pinfo.tag = p->tag;
    pinfo.ptr = p;
    pinfo.byte_count = byte_count;
    pinfo.block_count = block_count;
    pinfo.subpool_count = subpool_count;
    pinfo.level = level;

    visit(&pinfo, user_data);

    /* Recurse */
    if (p->sub_pools) {
      total_bytes += visit_pools(p->sub_pools, level + 1, visit, user_data);
    }
  }

  return total_bytes;
}

static void pool_printf(const char *fmt, ...) {
  char buf[PR_TUNABLE_BUFFER_SIZE];
  va_list msg;

  memset(buf, '\0', sizeof(buf));

  va_start(msg, fmt);
  pr_vsnprintf(buf, sizeof(buf), fmt, msg);
  va_end(msg);

  buf[sizeof(buf)-1] = '\0';
  pr_trace_msg(trace_channel, 5, "%s", buf);
}

static void pool_visitf(const pr_pool_info_t *pinfo, void *user_data) {
  void (*debugf)(const char *, ...) = user_data;

  if (pinfo->have_pool_info) {

    /* The emitted message is:
     *
     *  <pool-tag> [pool-ptr] (n B, m L, r P)
     *
     * where n is the number of bytes (B), m is the number of allocated blocks
     * in the pool list (L), and r is the number of sub-pools (P).
     */

    if (pinfo->level == 0) {
      debugf("%s [%p] (%lu B, %lu L, %u P)",
        pinfo->tag ? pinfo->tag : "<unnamed>", pinfo->ptr,
        pinfo->byte_count, pinfo->block_count, pinfo->subpool_count);

    } else {
      char indent_text[80] = "";

      if (pinfo->level > 1) {
        memset(indent_text, ' ', sizeof(indent_text)-1);

        if ((pinfo->level - 1) * 3 >= sizeof(indent_text)) {
          indent_text[sizeof(indent_text)-1] = 0;

        } else {
          indent_text[(pinfo->level - 1) * 3] = '\0';
        }
      }

      debugf("%s + %s [%p] (%lu B, %lu L, %u P)", indent_text,
        pinfo->tag ? pinfo->tag : "<unnamed>", pinfo->ptr,
        pinfo->byte_count, pinfo->block_count, pinfo->subpool_count);
    }
  }

  if (pinfo->have_freelist_info) {
    debugf("Free block list: %lu bytes", pinfo->freelist_byte_count);
  }

  if (pinfo->have_total_info) {
    debugf("Total %lu bytes allocated", pinfo->total_byte_count);
    debugf("%lu blocks allocated", pinfo->total_blocks_allocated);
    debugf("%lu blocks reused", pinfo->total_blocks_reused);
  }
}

void pr_pool_debug_memory(void (*debugf)(const char *, ...)) {
  if (debugf == NULL) {
    debugf = pool_printf;
  }

  debugf("Memory pool allocation:");
  pr_pool_debug_memory2(pool_visitf, debugf);
}

void pr_pool_debug_memory2(void (*visit)(const pr_pool_info_t *, void *),
    void *user_data) {
  unsigned long freelist_byte_count = 0, freelist_block_count = 0,
    total_byte_count = 0;
  pr_pool_info_t pinfo;

  if (visit == NULL) {
    return;
  }

  /* Per pool */
  total_byte_count = visit_pools(permanent_pool, 0, visit, user_data);

  /* Free list */
  if (block_freelist) {
    freelist_byte_count = bytes_in_block_list(block_freelist);
    freelist_block_count = blocks_in_block_list(block_freelist);
  }

  memset(&pinfo, 0, sizeof(pinfo));
  pinfo.have_freelist_info = TRUE;
  pinfo.freelist_byte_count = freelist_byte_count;
  pinfo.freelist_block_count = freelist_block_count;

  visit(&pinfo, user_data);

  /* Totals */
  memset(&pinfo, 0, sizeof(pinfo));
  pinfo.have_total_info = TRUE;
  pinfo.total_byte_count = total_byte_count;
  pinfo.total_blocks_allocated = stat_malloc;
  pinfo.total_blocks_reused = stat_freehit;

  visit(&pinfo, user_data);
}

int pr_pool_debug_set_flags(int flags) {
  if (flags < 0) {
    errno = EINVAL;
    return -1;
  }

  debug_flags = flags;
  return 0;
}

void pr_pool_tag(pool *p, const char *tag) {
  if (p == NULL ||
      tag == NULL) {
    return;
  }

  p->tag = tag;
}

const char *pr_pool_get_tag(pool *p) {
  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return p->tag;
}

/* Release the entire free block list */
static void pool_release_free_block_list(void) {
  union block_hdr *blok = NULL, *next = NULL;

  pr_signals_block();

  for (blok = block_freelist; blok; blok = next) {
    next = blok->h.next;
    free(blok);
  }
  block_freelist = NULL;

  pr_signals_unblock();
}

struct pool_rec *make_sub_pool(struct pool_rec *p) {
  union block_hdr *blok;
  pool *new_pool;

  pr_signals_block();

  blok = new_block(0, FALSE);

  new_pool = (pool *) blok->h.first_avail;
  blok->h.first_avail = POOL_HDR_BYTES + (char *) blok->h.first_avail;

  memset(new_pool, 0, sizeof(struct pool_rec));
  new_pool->free_first_avail = blok->h.first_avail;
  new_pool->first = new_pool->last = blok;

  if (p != NULL) {
    new_pool->parent = p;
    new_pool->sub_next = p->sub_pools;

    if (new_pool->sub_next) {
      new_pool->sub_next->sub_prev = new_pool;
    }

    p->sub_pools = new_pool;
  }

  pr_signals_unblock();

  return new_pool;
}

struct pool_rec *pr_pool_create_sz(struct pool_rec *p, size_t sz) {
  union block_hdr *blok;
  pool *new_pool;

  pr_signals_block();

  blok = new_block(sz + POOL_HDR_BYTES, TRUE);

  new_pool = (pool *) blok->h.first_avail;
  blok->h.first_avail = POOL_HDR_BYTES + (char *) blok->h.first_avail;

  memset(new_pool, 0, sizeof(struct pool_rec));
  new_pool->free_first_avail = blok->h.first_avail;
  new_pool->first = new_pool->last = blok;

  if (p != NULL) {
    new_pool->parent = p;
    new_pool->sub_next = p->sub_pools;

    if (new_pool->sub_next) {
      new_pool->sub_next->sub_prev = new_pool;
    }

    p->sub_pools = new_pool;
  }

  pr_signals_unblock();

  return new_pool;
}

/* Initialize the pool system by creating the base permanent_pool. */

void init_pools(void) {
  if (permanent_pool == NULL) {
    permanent_pool = make_sub_pool(NULL);
  }

  pr_pool_tag(permanent_pool, "permanent_pool");
}

void free_pools(void) {
  destroy_pool(permanent_pool);
  permanent_pool = NULL;
  pool_release_free_block_list();
}

static void clear_pool(struct pool_rec *p) {

  /* Sanity check. */
  if (p == NULL) {
    return;
  }

  pr_signals_block();

  /* Run through any cleanups. */
  run_cleanups(p->cleanups);
  p->cleanups = NULL;

  /* Destroy subpools. */
  while (p->sub_pools != NULL) {
    destroy_pool(p->sub_pools);
  }

  p->sub_pools = NULL;

  free_blocks(p->first->h.next, p->tag);
  p->first->h.next = NULL;

  p->last = p->first;
  p->first->h.first_avail = p->free_first_avail;

  p->tag = NULL;
  pr_signals_unblock();
}

void destroy_pool(pool *p) {
  if (p == NULL) {
    return;
  }

  pr_signals_block();

  if (p->parent != NULL) {
    if (p->parent->sub_pools == p) {
      p->parent->sub_pools = p->sub_next;
    }

    if (p->sub_prev != NULL) {
      p->sub_prev->sub_next = p->sub_next;
    }

    if (p->sub_next != NULL) {
      p->sub_next->sub_prev = p->sub_prev;
    }
  }

  clear_pool(p);
  free_blocks(p->first, p->tag);

  pr_signals_unblock();

#ifdef PR_DEVEL_NO_POOL_FREELIST
  /* If configured explicitly to do so, call free(3) on the freelist after
   * a pool is destroyed.  This can be useful for tracking down use-after-free
   * and other memory issues using libraries such as dmalloc.
   */
  pool_release_free_block_list();
#endif /* PR_EVEL_NO_POOL_FREELIST */
}

/* Allocation interface...
 */

static void *alloc_pool(struct pool_rec *p, size_t reqsz, int exact) {
  /* Round up requested size to an even number of aligned units */
  size_t nclicks = 1 + ((reqsz - 1) / CLICK_SZ);
  size_t sz = nclicks * CLICK_SZ;
  union block_hdr *blok;
  char *first_avail, *new_first_avail;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  /* For performance, see if space is available in the most recently
   * allocated block.
   */

  blok = p->last;
  if (blok == NULL) {
    errno = EINVAL;
    return NULL;
  }

  first_avail = blok->h.first_avail;

  if (reqsz == 0) {
    /* Don't try to allocate memory of zero length.
     *
     * This should NOT happen normally; if it does, by returning NULL we
     * almost guarantee a null pointer dereference.
     */
    errno = EINVAL;
    return NULL;
  }

  new_first_avail = first_avail + sz;

  if (new_first_avail <= (char *) blok->h.endp) {
    blok->h.first_avail = new_first_avail;
    return (void *) first_avail;
  }

  /* Need a new one that's big enough */
  pr_signals_block();

  blok = new_block(sz, exact);
  p->last->h.next = blok;
  p->last = blok;

  first_avail = blok->h.first_avail;
  blok->h.first_avail = sz + (char *) blok->h.first_avail;

  pr_signals_unblock();
  return (void *) first_avail;
}

void *palloc(struct pool_rec *p, size_t sz) {
  return alloc_pool(p, sz, FALSE);
}

void *pallocsz(struct pool_rec *p, size_t sz) {
  return alloc_pool(p, sz, TRUE);
}

void *pcalloc(struct pool_rec *p, size_t sz) {
  void *res;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  res = palloc(p, sz);
  memset(res, '\0', sz);

  return res;
}

void *pcallocsz(struct pool_rec *p, size_t sz) {
  void *res;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  res = pallocsz(p, sz);
  memset(res, '\0', sz);

  return res;
}

/* Array functions */

array_header *make_array(pool *p, unsigned int nelts, size_t elt_size) {
  array_header *res;

  if (p == NULL ||
      elt_size == 0) {
    errno = EINVAL;
    return NULL;
  }

  res = palloc(p, sizeof(array_header));

  if (nelts < 1) {
    nelts = 1;
  }

  res->elts = pcalloc(p, nelts * elt_size);
  res->pool = p;
  res->elt_size = elt_size;
  res->nelts = 0;
  res->nalloc = nelts;

  return res;
}

void clear_array(array_header *arr) {
  if (arr == NULL) {
    return;
  }

  arr->elts = pcalloc(arr->pool, arr->nalloc * arr->elt_size);
  arr->nelts = 0;
}

void *push_array(array_header *arr) {
  if (arr == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (arr->nelts == arr->nalloc) {
    char *new_data = pcalloc(arr->pool, arr->nalloc * arr->elt_size * 2);

    memcpy(new_data, arr->elts, arr->nalloc * arr->elt_size);
    arr->elts = new_data;
    arr->nalloc *= 2;
  }

  ++arr->nelts;
  return ((char *) arr->elts) + (arr->elt_size * (arr->nelts - 1));
}

int array_cat2(array_header *dst, const array_header *src) {
  size_t elt_size;

  if (dst == NULL ||
      src == NULL) {
    errno = EINVAL;
    return -1;
  }

  elt_size = dst->elt_size;

  if (dst->nelts + src->nelts > dst->nalloc) {
    size_t new_size;
    char *new_data;

    new_size = dst->nalloc * 2;
    if (new_size == 0) {
      ++new_size;
    }

    while ((dst->nelts + src->nelts) > new_size) {
      new_size *= 2;
    }

    new_data = pcalloc(dst->pool, elt_size * new_size);
    memcpy(new_data, dst->elts, dst->nalloc * elt_size);

    dst->elts = new_data;
    dst->nalloc = new_size;
  }

  memcpy(((char *) dst->elts) + (dst->nelts * elt_size), (char *) src->elts,
         elt_size * src->nelts);
  dst->nelts += src->nelts;

  return 0;
}

void array_cat(array_header *dst, const array_header *src) {
  (void) array_cat2(dst, src);
}

array_header *copy_array(pool *p, const array_header *arr) {
  array_header *res;

  if (p == NULL ||
      arr == NULL) {
    errno = EINVAL;
    return NULL;
  }

  res = make_array(p, arr->nalloc, arr->elt_size);

  memcpy(res->elts, arr->elts, arr->elt_size * arr->nelts);
  res->nelts = arr->nelts;
  return res;
}

/* copy an array that is assumed to consist solely of strings */
array_header *copy_array_str(pool *p, const array_header *arr) {
  register unsigned int i;
  array_header *res;

  if (p == NULL ||
      arr == NULL) {
    errno = EINVAL;
    return NULL;
  }

  res = copy_array(p, arr);

  for (i = 0; i < arr->nelts; i++) {
    ((char **) res->elts)[i] = pstrdup(p, ((char **) res->elts)[i]);
  }

  return res;
}

array_header *copy_array_hdr(pool *p, const array_header *arr) {
  array_header *res;

  if (p == NULL ||
      arr == NULL) {
    errno = EINVAL;
    return NULL;
  }

  res = palloc(p, sizeof(array_header));

  res->elts = arr->elts;
  res->pool = p;
  res->elt_size = arr->elt_size;
  res->nelts = arr->nelts;
  res->nalloc = arr->nelts;		/* Force overflow on push */

  return res;
}

array_header *append_arrays(pool *p, const array_header *first,
    const array_header *second) {
  array_header *res;

  if (p == NULL ||
      first == NULL ||
      second == NULL) {
    errno = EINVAL;
    return NULL;
  }

  res = copy_array_hdr(p, first);

  array_cat(res, second);
  return res;
}

/* Generic cleanups */

typedef struct cleanup {
  void *user_data;
  void (*cleanup_cb)(void *);
  struct cleanup *next;

} cleanup_t;

void register_cleanup2(pool *p, void *user_data, void (*cleanup_cb)(void*)) {
  cleanup_t *c;

  if (p == NULL) {
    return;
  }

  c = pcalloc(p, sizeof(cleanup_t));
  c->user_data = user_data;
  c->cleanup_cb = cleanup_cb;

  /* Add this cleanup to the given pool's list of cleanups. */
  c->next = p->cleanups;
  p->cleanups = c;
}

void register_cleanup(pool *p, void *user_data, void (*plain_cleanup_cb)(void*),
    void (*child_cleanup_cb)(void *)) {
  (void) child_cleanup_cb;
  register_cleanup2(p, user_data, plain_cleanup_cb);
}

void unregister_cleanup(pool *p, void *user_data, void (*cleanup_cb)(void *)) {
  cleanup_t *c, **lastp;

  if (p == NULL) {
    return;
  }

  c = p->cleanups;
  lastp = &p->cleanups;

  while (c != NULL) {
    if (c->user_data == user_data &&
        (c->cleanup_cb == cleanup_cb || cleanup_cb == NULL)) {

      /* Remove the given cleanup by pointing the previous next pointer to
       * the matching cleanup's next pointer.
       */
      *lastp = c->next;
      break;
    }

    lastp = &c->next;
    c = c->next;
  }
}

static void run_cleanups(cleanup_t *c) {
  while (c != NULL) {
    if (c->cleanup_cb) {
      (*c->cleanup_cb)(c->user_data);
    }

    c = c->next;
  }
}
