/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
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
 *
 * $Id*
 */

#ifndef PR_TIMERS_H
#define PR_TIMERS_H

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
int add_timer(int, int, module *, callback_t);
int remove_timer(int, module *);
int reset_timer(int, module *);
int timer_sleep(int);
void handle_alarm(void);
void set_sig_alarm(void);

#endif /* __TIMERS_H */
