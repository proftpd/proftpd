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
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 */

/*
 * Ident (RFC1413) protocol support
 */

#include "conf.h"

static int ident_timeout;
static IOFILE *io;

static int _ident_timeout(CALLBACK_FRAME)
{
  ident_timeout++;

  if(io)
    /* Abort the IOFILE, which will cause io_poll (and thus io_read) to
     * also abort.  This is similar to the way data connects are aborted
     */
    io_abort(io);
    
  return 0;
}

char *get_ident(pool *p,conn_t *c)
{
  char *ret = "UNKNOWN";
  pool *tmpp;
  conn_t *ident_conn,*ident_io;
  char buf[256] = {'\0'}, *tok,*tmp;
  int timer,i = 0;
  int ident_port = inet_getservport(p,"ident","tcp");

  tmpp = make_sub_pool(p);
  ident_timeout = 0;
  io = NULL;

  if(ident_port == -1) {
    destroy_pool(tmpp);
    return pstrdup(p,ret);    
  }
 
  /* Set up our timer before going any further */
  timer = add_timer(TUNABLE_TIMEOUTIDENT,-1,NULL,(callback_t)_ident_timeout);
  if(timer <= 0) {
    destroy_pool(tmpp);
    return pstrdup(p,ret);
  }
  
  ident_conn = inet_create_connection(tmpp,NULL,-1,c->local_ipaddr,INPORT_ANY,FALSE);
  inet_setnonblock(tmpp,ident_conn);
  i = inet_connect_nowait(tmpp,ident_conn,c->remote_ipaddr,ident_port);
  if(i < 0) {
    remove_timer(timer,NULL);
    inet_close(tmpp,ident_conn);
    destroy_pool(tmpp);
    return pstrdup(p,ret);
  }
  
  if(!i) {				/* Not yet connected */
    io = io_open(p,ident_conn->listen_fd,IO_READ);
    io_set_poll_sleep(io,1);
    switch(io_poll(io)) {
    case 1: /* Abort, Timeout? */
		if(ident_timeout) {
	          remove_timer(timer,NULL);
              	  io_close(io);
		  destroy_pool(tmpp);
		  return pstrdup(p,ret);
		}
		break;
    case -1: /* Error */
		remove_timer(timer,NULL);
		io_close(io);
		destroy_pool(tmpp);
		return pstrdup(p,ret);
    default: /* connected */
		ident_conn->mode = CM_OPEN;
		inet_get_conn_info(ident_conn,ident_conn->listen_fd);
		break;
    }
  }

  ident_io = inet_openrw(tmpp,ident_conn,NULL,-1,-1,-1,FALSE);
  io = ident_io->inf;
  inet_setnonblock(tmpp,ident_io);
  io_set_poll_sleep(ident_io->inf,1);
  io_set_poll_sleep(ident_io->outf,1);
  io_printf(ident_io->outf,"%d, %d\r\n",c->remote_port,c->local_port);

  /* If the timer fires while in io_gets, io_gets will simply return
   * either a partial string, or NULL.  This works because _ident_timeout
   * aborts the IOFILE we are reading on.  io_set_poll_sleep() is used
   * to make sure significant delays don't occur on systems that
   * automatically restart syscalls after the SIGALRM signal.
   */
  
  if(io_gets(buf,sizeof(buf),ident_io->inf)) {
    strip_end(buf,"\r\n");
    
    tmp = buf;
    tok = get_token(&tmp,":");
    if(tok && (tok = get_token(&tmp,":"))) {
      while(*tok && isspace((UCHAR)*tok)) tok++;
      strip_end(tok," \t");

      if(strcasecmp(tok,"ERROR") == 0) {
        if(tmp) {
          while(*tmp && isspace((UCHAR)*tmp)) tmp++;
	  strip_end(tmp," \t");
          if(strcasecmp(tmp,"HIDDEN-USER") == 0)
            ret = "HIDDEN-USER";
        }
      } else if(strcasecmp(tok,"USERID") == 0) {
        if(tmp && (tok = get_token(&tmp,":"))) {
          if(tmp) {
            while(*tmp && isspace((UCHAR)*tmp)) tmp++;
            strip_end(tmp," \t");
            ret = tmp;
          }
        }
      }
    }
  }

  remove_timer(timer,NULL);
  inet_close(tmpp,ident_io);
  inet_close(tmpp,ident_conn);
  destroy_pool(tmpp);

  return pstrdup(p,ret);
}
