/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2003 The ProFTPD Project team
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
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* Event management code
 * $Id: event.c,v 1.4 2003-11-09 23:32:07 castaglia Exp $
 */

#include "conf.h"

/* Note: as more events are added, and as this API grows more and more used
 * by the core code, look into using a different ADT for storage/retrieval
 * of these objects, such as hash tables.
 */

struct event_handler {
  struct event_handler *next, *prev;
  module *module;
  void (*cb)(const void *, void *);
  void *user_data;
};

struct event_list {
  struct event_list *next;
  const char *event;
  struct event_handler *handlers;
};

static pool *event_pool = NULL;
static struct event_list *events = NULL;

int pr_event_register(module *m, const char *event,
    void (*cb)(const void *, void *), void *user_data) {
  struct event_handler *evh;
  struct event_list *evl;

  if (!event || !cb) {
    errno = EINVAL;
    return -1;
  }

  /* If no event pool has been allocated, create one. */
  if (!event_pool)
    event_pool = make_sub_pool(permanent_pool);

  evh = pcalloc(event_pool, sizeof(struct event_handler));

  evh->module = m;
  evh->cb = cb;
  evh->user_data = user_data;

  /* Scan the currently registered lists, looking for where to add this
   * registration.
   */

  for (evl = events; evl; evl = evl->next) {
    if (strcmp(evl->event, event) == 0) {
      evh->next = evl->handlers;
      evl->handlers->prev = evh;
      evl->handlers = evh;

      /* All done */
      return 0;
    }
  }

  evl = pcalloc(event_pool, sizeof(struct event_list));

  /* XXX This may need to be pstrdup()'d in the future. */
  evl->event = event;
  evl->handlers = evh; 
  evl->next = events;

  events = evl;

  return 0;
}

int pr_event_unregister(module *m, const char *event,
    void (*cb)(const void *, void *)) {
  struct event_list *evl;

  if (!event) {
    errno = EINVAL;
    return -1;
  }

  if (!events)
    return 0;

  /* For now, simply remove the event_handler entry for this callback.  In
   * the future, add a static counter, and churn the event pool after a
   * certain number of unregistrations, so that the memory pool doesn't
   * grow unnecessarily.
   */

  for (evl = events; evl; evl = evl->next) {
    if (strcmp(evl->event, event) == 0) {

      /* If there are no handlers for this event, this is nothing to
       * unregister.
       */
      if (!evl->handlers)
        return 0;

      if (cb) {
        struct event_handler *evh;

        for (evh = evl->handlers; evh;) {

          if ((m == NULL || evh->module == m) &&
              (cb == NULL || evh->cb == cb)) { 
            struct event_handler *tmp = evh->next;

            if (evh->prev)
              evh->prev->next = evh->next;

            if (evh->next)
              evh->next->prev = evh->prev;
          
            evh = tmp;
  
          } else
            evh = evh->next;
        }
      }
    }
  }

  return 0;
}

void pr_event_generate(const char *event, const void *event_data) {
  struct event_list *evl;

  if (!event)
    return;

  /* If there are no registered callbacks, be done. */
  if (!events)
    return;

  /* Lookup callbacks for this event. */
  for (evl = events; evl; evl = evl->next) {

    if (strcmp(evl->event, event) == 0) {  
      struct event_handler *evh;

      /* If there are no registered callbacks for this event, be done. */
      if (!evl->handlers) {
        pr_log_debug(DEBUG10, "no event handlers registered for '%s'", event);
        return;
      }

      for (evh = evl->handlers; evh; evh = evh->next) {
        pr_log_debug(DEBUG10, "dispatching event '%s' to mod_%s", event,
          evh->module->name);
        evh->cb(event_data, evh->user_data);
      }

      break;
    }
  }

  return;
}
