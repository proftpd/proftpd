/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * BUT witHOUT ANY WARRANTY; without even the implied warranty of
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
 * Timer system, based on alarm() and SIGALRM
 * $Id: timers.c,v 1.8 2002-05-21 18:59:15 castaglia Exp $
 */

#include <signal.h>

#include "conf.h"

static int _current_timeout = 0;
static int _total_time = 0;
static int _sleep_sem = 0;
static int alarms_blocked = 0,alarm_pending = 0;
static xaset_t *timers = NULL;
static xaset_t *recycled = NULL;
static int _indispatch = 0;
static int dynamic_timerno = 1024;
static int _alarm_received = 0;
static time_t _alarmed_time = 0;

xaset_t *free_timers = NULL;

static int _compare_timer(timer_t *t1, timer_t *t2) {
  if (t1->count < t2->count)
    return -1;

  if (t1->count > t2->count)
    return 1;

  return 0;
}

static int _reset_timers(int elapsed) {
  timer_t *t = NULL, *next = NULL;

  if (!recycled)
    recycled = xaset_create(NULL, NULL);

  if (!elapsed && !recycled->xas_list)
    return (timers->xas_list ? ((timer_t*) timers->xas_list)->count : 0);

  /* Critical code, no interruptions please */
  if (_indispatch)
    return 0;

  _indispatch++;
  block_alarms();

  if (elapsed) {
    for (t = (timer_t*)timers->xas_list; t; t=next) {
      /* If this timer has already been handled, skip */
      next = t->next;

      if (t->remove) {
        /* Move the timer onto the free_timers chain, for later reuse. */
        xaset_remove(timers, (xasetmember_t *) t);
        xaset_insert(free_timers, (xasetmember_t *) t);

      } else if ((t->count -= elapsed) <= 0) {
        if (t->callback(t->interval, t->timerno, t->interval - t->count,
            t->mod) == 0) {
          xaset_remove(timers,(xasetmember_t*)t);
          xaset_insert(free_timers,(xasetmember_t*)t);

        } else {
         /*
          log_debug(DEBUG5,"moving timer %d to recycled list.",
                    t->timerno);
          */
          /* Restart the timer */
          xaset_remove(timers,(xasetmember_t*)t);
          t->count = t->interval;
          xaset_insert(recycled,(xasetmember_t*)t);
        }
      }
    }
  }

  /* Put the recycled timers back into the main timer list */
  while ((t = (timer_t*)recycled->xas_list) != NULL) {
    xaset_remove(recycled, (xasetmember_t*)t);
    xaset_insert_sort(timers, (xasetmember_t*)t,TRUE);
  }

  unblock_alarms();
  _indispatch--;

  /* If no active timers remain in the list, there is no reason
     to set the alarm */

  return (timers->xas_list ? ((timer_t*)timers->xas_list)->count : 0);
}

void sig_alarm(int signum) {
  struct sigaction act;

  _alarm_received++;
  act.sa_handler = sig_alarm;
  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;
#ifdef SA_INTERRUPT
  act.sa_flags |= SA_INTERRUPT;
#endif
  sigaction(SIGALRM,&act,NULL);
#ifdef HAVE_SIGINTERRUPT
  siginterrupt(SIGALRM,1);
#endif

  /* Reset the alarm */
  _total_time += _current_timeout;
  if (_current_timeout) {
    _alarmed_time = time(NULL);
    alarm(_current_timeout);
  }
}

void set_sig_alarm() {
  struct sigaction act;

  act.sa_handler = sig_alarm;
  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;
#ifdef SA_INTERRUPT
  act.sa_flags |= SA_INTERRUPT;
#endif
  sigaction(SIGALRM,&act,NULL);
#ifdef HAVE_SIGINTERRUPT
  siginterrupt(SIGALRM,1);
#endif
}

void handle_sig_alarm() {
  int new_timeout = 0;

  /* We need to adjust for any time that might be remaining on the alarm,
   * in case we were called in order change alarm durations.  Note
   * that rapid-fire calling of this function will probably screw
   * up the already poor resolution of alarm() _horribly_.  Oh well,
   * this shouldn't be used for any precise work anyway, it's only
   * for modules to perform approximate timing.
   */

  /* It's possible that alarms are blocked when this function is
   * called, if so, increment alarm_pending and exit swiftly
   */

  while (_alarm_received) {
    _alarm_received = 0;

    if (!alarms_blocked) {
      int alarm_elapsed;

      alarm(0);
      alarm_elapsed = _alarmed_time ? (int) time(NULL) - _alarmed_time : 0;
      new_timeout = _total_time + alarm_elapsed;
      _total_time = 0;
      new_timeout = _reset_timers(new_timeout);

      _alarmed_time = time(NULL);
      alarm(_current_timeout = new_timeout);

    } else
      alarm_pending++;
  }
}

int reset_timer(int timerno, module *mod) {
  timer_t *t = NULL;

  if (_indispatch)
    return -1;

  block_alarms();

  if (!recycled)
    recycled = xaset_create(NULL, NULL);

  for (t = (timer_t*)timers->xas_list; t; t=t->next)
    if (t->timerno == timerno && (t->mod == mod || mod == ANY_MODULE)) {
      t->count = t->interval;
      xaset_remove(timers, (xasetmember_t*)t);
      xaset_insert(recycled, (xasetmember_t*)t);
      _alarm_received++;
      handle_sig_alarm();
      break;
    }

  unblock_alarms();

  return (t ? t->timerno : 0);
}

int remove_timer(int timerno, module *mod) {
  timer_t *t = NULL;

  /* If there are no timers currently registered, do nothing. */
  if (!timers)
    return 0;

  block_alarms();

  for (t = (timer_t *) timers->xas_list; t; t = t->next)
    if (t->timerno == timerno && (t->mod == mod || mod == ANY_MODULE)) {
      if (_indispatch) {
        t->remove++;

      } else {
        xaset_remove(timers,(xasetmember_t*)t);
        xaset_insert(free_timers,(xasetmember_t*)t);
	_alarm_received++;
        handle_sig_alarm();
      }      
      break;
    }

  unblock_alarms();

  return (t ? t->timerno : 0);
}

int add_timer(int seconds, int timerno, module *mod, callback_t cb) {
  timer_t *t = NULL;

  if (!timers)
    timers = xaset_create(NULL, (XASET_COMPARE)_compare_timer);

  if (!free_timers)
    free_timers = xaset_create(NULL, NULL);

  /* Try to use an old timer first */
  block_alarms();
  if ((t = (timer_t*)free_timers->xas_list) != NULL)
    xaset_remove(free_timers, (xasetmember_t*)t);
  else
    /* Must allocate a new one */
    t = palloc(permanent_pool, sizeof(timer_t));

  if (timerno == -1) { 
    /* Dynamic timer */
    if (dynamic_timerno < 1024)
      dynamic_timerno = 1024;
    timerno = dynamic_timerno++;
  }

  t->timerno = timerno;
  t->count = t->interval = seconds;
  t->callback = cb;
  t->mod = mod;
  t->remove = 0;

  /* If called while _indispatch, add to the recycled list to prevent
   * list corruption
   */

  if (_indispatch) {
    if (!recycled)
      recycled = xaset_create(NULL, NULL);
    xaset_insert(recycled, (xasetmember_t*)t);

  } else {
    xaset_insert_sort(timers, (xasetmember_t*)t, TRUE);
    _alarm_received++;
    set_sig_alarm();
    handle_sig_alarm();
  }

  unblock_alarms();

  return timerno;
}

/* Alarm blocking.  This is done manually rather than with syscalls,
 * so as to allow for easier signal handling, portability and
 * detecting the number of blocked alarms, as well as nesting the
 * block/unblock functions.
 */

void block_alarms() {
  ++alarms_blocked;
}

void unblock_alarms() {
  --alarms_blocked;
  if (alarms_blocked == 0 && alarm_pending) {
    alarm_pending = 0;
    _alarm_received++;
    handle_sig_alarm();
  }
}

static int _sleep_callback(CALLBACK_FRAME) {
  _sleep_sem++;
  return 0;
}

int timer_sleep(int seconds) {
  int timerno = 0;
  sigset_t oset;

  _sleep_sem = 0;

  if (alarms_blocked || _indispatch)
    return -1;

  timerno = add_timer(seconds, -1, NULL, _sleep_callback);
  if (timerno == -1)
    return -1;

  sigemptyset(&oset);
  while (!_sleep_sem) {
    sigsuspend(&oset);
    handle_sig_alarm();
  }
  
  return 0;  
}
