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

/* Hiding API implementation */

#include "conf.h"

struct hiding_handler {
  struct hiding_handler *next, *prev;
  module *module;
  const char *handler_name;
  size_t handler_namelen;
  pool *pool;
  int (*hide_path)(pool *, const char *, const char *, void *);
  void *user_data;
  pr_table_t *notes;
  unsigned long flags;
};

static pool *hiding_pool = NULL;
static struct hiding_handler *hiding_handlers = NULL;

#define PR_HIDING_FL_DISABLED		0x0001

static const char *trace_channel = "hiding";

#define PR_HIDING_POOL_SZ		256

static void destroy_handler(struct hiding_handler *h) {
  if (h->next != NULL) {
    h->next->prev = h->prev;
  }

  if (h->prev != NULL) {
    h->prev->next = h->next;

  } else {
    /* This is the head of the list. */
    hiding_handlers = h->next;
  }

  destroy_pool(h->pool);
}

static struct hiding_handler *get_handler(module *m, const char *handler_name,
    size_t handler_namelen) {
  register struct hiding_handler *h;

/* XXX Are hiding handler names globally unique, or only unique within a
 * module?  Maybe automatically use the module as a prefix for the given
 * handler name, to enforce the namespacing?
 */

  for (h = hiding_handlers; h; h = h->next) {
    pr_signals_handle();

    if (h->module == m &&
        h->handler_namelen == handler_namelen &&
        strncmp(h->handler_name, handler_name, handler_namelen + 1) == 0) {
      return h;
    }
  }

  errno = ENOENT;
  return NULL;
}

int pr_hiding_register(module *m, const char *handler_name,
    int (*hide_path)(pool *, const char *, const char *, void *),
    void *user_data) {
  struct hiding_handler *h;
  pool *p;
  size_t handler_namelen = 0;
  unsigned long flags = 0;

  if (handler_name == NULL ||
      hide_path == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (hiding_pool == NULL) {
    /* Note: hiding_init() SHOULD have been called already. */
    errno = EPERM;
    return -1;
  }

  handler_namelen = strlen(handler_name);
  h = get_handler(m, handler_name, handler_namelen);
  if (h != NULL) {
    errno = EEXIST;
    return -1;
  }

  pr_trace_msg(trace_channel, 3,
    "module '%s' (%p) registering handler '%s' (at %p)",
    m ? m->name : "(none)", m, handler_name, hide_path);

  p = pr_pool_create_sz(hiding_pool, PR_HIDING_POOL_SZ);
  pr_pool_tag(p, "Hiding handler pool");

  h = pcalloc(p, sizeof(struct hiding_handler));
  h->pool = p;
  h->module = m;
  h->handler_name = pstrndup(p, handler_name, handler_namelen);
  h->handler_namelen = handler_namelen;
  h->hide_path = hide_path;
  h->user_data = user_data;
  h->flags = flags;
  h->notes = pr_table_nalloc(p, 0, 2);

  h->next = hiding_handlers;

  if (hiding_handlers != NULL) {
    hiding_handlers->prev = h;
  }

  hiding_handlers = h;

  return 0;
}

int pr_hiding_unregister(module *m, const char *handler_name) {
  struct hiding_handler *h, *next_h;

  if (hiding_handlers == NULL) {
    errno = EPERM;
    return -1;
  }

  pr_trace_msg(trace_channel, 3,
    "module '%s' (%p) unregistering handler '%s'",
    m ? m->name : "(none)", m, handler_name ? handler_name : "(all)");

  /* For now, simply remove the handler_handler entry.  In the future, add a
   * static counter, and churn the hiding pool after a certain number of
   * unregistrations, so that the memory pool doesn't grow unnecessarily.
   */

  if (handler_name != NULL) {
    size_t handler_namelen;

    handler_namelen = strlen(handler_name);
    h = get_handler(m, handler_name, handler_namelen);
    if (h == NULL) {
      return -1;
    }

    destroy_handler(h);
    return 0;
  }

  /* No handler name given?  Then we unregister all handlers from the
   * given module.
   */

  for (h = hiding_handlers; h; h = next_h) {
    pr_signals_handle();

    next_h = h->next;

    if (m != NULL &&
        h->module != m) {
      continue;
    }

    destroy_handler(h);
  }

  return 0;
}

/* ALL active handlers must agree that the path is NOT hidden for a value
 * of 0 (not hidden) to be returned.  The first handler returning 1 (hidden)
 * stops the check.
 */
int pr_hiding_hide_path(pool *p, const char *path) {
  register struct hiding_handler *h;
  const char *abs_path = NULL;

  if (p == NULL ||
      path == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (hiding_handlers == NULL) {
    return 0;
  }

  abs_path = dir_abs_path(p, path, TRUE);
  if (abs_path == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3,
      "error obtaining absolute path for '%s': %s", path, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  for (h = hiding_handlers; h; h = h->next) {
    int res = 0;

    pr_signals_handle();

    if (h->flags & PR_HIDING_FL_DISABLED) {
      continue;
    }

    if (h->module != NULL) {
      pr_trace_msg(trace_channel, 8,
        "asking handler '%s' (from mod_%s, at %p) about path '%s'",
        h->handler_name, h->module->name, h->hide_path, abs_path);

    } else {
      pr_trace_msg(trace_channel, 8,
        "asking handler '%s' (from core, at %p) about path '%s'",
        h->handler_name, h->hide_path, abs_path);
    }

    res = (h->hide_path)(h->pool, path, abs_path, h->user_data);
    if (res == 1) {
      if (h->module != NULL) {
        pr_trace_msg(trace_channel, 8,
          "handler '%s' (from mod_%s) declared path '%s' to be HIDDEN",
          h->handler_name, h->module->name, abs_path);

      } else {
        pr_trace_msg(trace_channel, 8,
          "handler '%s' (from core) declared path '%s' to be HIDDEN",
          h->handler_name, abs_path);
      }

      return 1;

    } else if (res < 0) {
      if (h->module != NULL) {
        pr_trace_msg(trace_channel, 2,
          "handler '%s' (from mod_%s) failed handling path '%s': %s",
          h->handler_name, h->module->name, abs_path, strerror(errno));

      } else {
        pr_trace_msg(trace_channel, 2,
          "handler '%s' (from core) failed handling path '%s': %s",
          h->handler_name, abs_path, strerror(errno));
      }
    }
  }

  return 0;
}

void pr_hiding_dump(void (*dumpf)(const char *, ...)) {
  register struct hiding_handler *h;

  if (dumpf == NULL) {
    return;
  }

  if (hiding_handlers == NULL) {
    dumpf("%s", "No handlers registered");
    return;
  }

  for (h = hiding_handlers; h; h = h->next) {
    pr_signals_handle();

    if (h->module != NULL) {
      dumpf("handler '%s' (mod_%s)", h->handler_name, h->module->name);

    } else {
      dumpf("handler '%s' (core)", h->handler_name);
    }
  }

  return;
}

int hiding_init(void) {
  if (hiding_pool != NULL) {
    destroy_pool(hiding_pool);
    hiding_handlers = NULL;
  }

  hiding_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(hiding_pool, "Hiding Pool");

  return 0;
}

int hiding_finish(void) {
  if (hiding_pool != NULL) {
    destroy_pool(hiding_pool);
    hiding_pool = NULL;
    hiding_handlers = NULL;
  }

  return 0;
}
