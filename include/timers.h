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

#ifndef __TIMERS_H
#define __TIMERS_H

typedef struct timer_struc {
  struct timer_struc *next,*prev;

  long count;			/* Amount of time remaining */
  long interval;		/* Original length of timer */

  int timerno;			/* Caller dependent timer number */
  module *mod;			/* Module owning this timer */
  callback_t callback;		/* Function to callback */
  char remove;			/* Internal use */
} timer_t;


/* Prototypes */
int add_timer(int seconds,int timerno,module *mod, callback_t cb);
int remove_timer(int timerno,module *mod);
int reset_timer(int timerno,module *mod);
int timer_sleep(int);
void handle_sig_alarm();

#endif /* __TIMERS_H */
