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

char *get_ident(pool *p,conn_t *c)
{
  char *ret = "UNKNOWN";
  conn_t *ident_conn,*ident_io;
  char buf[256],*tok,*tmp;
  int i = 0;
  int ident_timeout = 0;
  int ident_port = inet_getservport(p,"ident","tcp");

  if(ident_port == -1)
    return pstrdup(p,ret);    

  ident_conn = inet_create_connection(p,NULL,-1,c->local_ipaddr,INPORT_ANY,FALSE);
  inet_setnonblock(p,ident_conn);
  i = inet_connect_nowait(p,ident_conn,c->remote_ipaddr,ident_port);

  while(!i && !ident_timeout) {
    fd_set rfd;
    struct timeval tv;
    
    tv.tv_sec = TUNABLE_TIMEOUTIDENT;
    tv.tv_usec = 0;
    FD_ZERO(&rfd);
    FD_SET(ident_conn->listen_fd,&rfd);
    i = select(1,&rfd,NULL,NULL,&tv);
    switch(i) {
    	case -1: if(errno == EINTR) continue;
		 break;
	case 0:  ident_timeout++; break;
	default: 
		 ident_conn->mode = CM_OPEN;
		 inet_get_conn_info(ident_conn,ident_conn->listen_fd);
		 inet_setblock(ident_conn->pool,ident_conn);
		 break;
    }
  }

  if(i < 0 || ident_timeout) {
    inet_close(p,ident_conn);
    return pstrdup(p,ret);
  }

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
