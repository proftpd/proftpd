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

static
int set_ident_timeout(CALLBACK_FRAME)
{
  ident_timeout++;
  return 0;				/* Don't restart timer */
}

char *get_ident(pool *p,conn_t *c)
{
  char *ret = "UNKNOWN";
  conn_t *ident_conn,*ident_io;
  char buf[256],*tok,*tmp;
  int timer,i = 0;

  int ident_port = inet_getservport(p,"ident","tcp");

  if(ident_port == -1)
    return pstrdup(p,ret);    

  ident_timeout = 0;
  timer = add_timer(TUNABLE_TIMEOUTIDENT,-1,NULL,set_ident_timeout);

  ident_conn = inet_create_connection(p,NULL,-1,c->local_ipaddr,INPORT_ANY,FALSE);
  inet_setnonblock(p,ident_conn);

  while(!i && !ident_timeout) {
    i = inet_connect_nowait(p,ident_conn,c->remote_ipaddr,ident_port);
    if(i == 0) {
      fd_set rfd;

      FD_ZERO(&rfd);
      FD_SET(ident_conn->listen_fd,&rfd);
      select(1,&rfd,NULL,NULL,NULL);
    }
  }

  if(i < 0 || ident_timeout) {
    if(!ident_timeout)
      remove_timer(timer,NULL);

    inet_close(p,ident_conn);
    return pstrdup(p,ret);
  }

  remove_timer(timer,NULL);

  ident_io = inet_openrw(p,ident_conn,NULL,-1,-1,-1,FALSE);
  inet_setblock(p,ident_io);
  io_printf(ident_io->outf,"%d, %d\r\n",c->remote_port,c->local_port);

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

  inet_close(p,ident_io);
  inet_close(p,ident_conn);

  return pstrdup(p,ret);
}
