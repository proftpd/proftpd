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
 
/*
 * Data connection management functions
 * $Id: data.c,v 1.18 2000-08-08 00:54:46 macgyver Exp $
 */

#include "conf.h"

#include <signal.h>

#ifdef HAVE_SYS_SENDFILE_H
#include <sys/sendfile.h>
#endif /* HAVE_SYS_SENDFILE_H */

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif /* HAVE_SYS_UIO_H */

/* local macro */

#define MODE_STRING	(session.flags & (SF_ASCII|SF_ASCII_OVERRIDE) ? \
			 "ASCII" : "BINARY")

/* Internal usage: pointer to current data connection IOFILE in
 * use (may be in either read or write mode)
 */
static IOFILE *curf = NULL;

/* Called if the "Stalled" timer goes off
 */
static int stalled_timeout(CALLBACK_FRAME) {
  log_pri(LOG_NOTICE,"Data transfer stall timeout: %d seconds",
	  TimeoutStalled);
  
  end_login(1);

  /* Prevent compiler warning.
   */
  return 0;
}

/* this signal is raised if we get OOB data on the control connection, and
 * a data transfer is in progress
 */
RETSIGTYPE data_urgent(int sig) {
  if(curf) {
    session.flags |= SF_ABORT;
    io_abort(curf);
  }

  signal(SIGURG,data_urgent);
}

static int _translate_ascii(char **buf, int *bufsize, int *adjlen) {
  char *res = *buf;
  int newbufsize = 0;
  int thislen = *bufsize;
  
  if(**buf == '\n') {
    *--res = '\r';
    (*buf)++;
    newbufsize = 2;
    (*adjlen)++; thislen--;
  }
  
  while(thislen-- > 0 && newbufsize < *bufsize && **buf != '\n') {
    (*buf)++;
    newbufsize++;
  }
  
  *bufsize = newbufsize;
  *buf = res;
  return newbufsize;
}

static void _data_new_xfer(char *filename, int direction) {
  if(session.xfer.p) {
    destroy_pool(session.xfer.p);
    bzero(&session.xfer,sizeof(session.xfer));
  }
  
  session.xfer.p = make_sub_pool(session.pool);
  session.xfer.filename = pstrdup(session.xfer.p,filename);
  session.xfer.direction = direction;
  session.xfer.bufsize = 1024;
  session.xfer.buf = (char*)palloc(session.xfer.p,1025);
  session.xfer.buf++;	/* leave room for ascii translation */
}

static int _data_pasv_open(char *reason, unsigned long size) {
  conn_t *c;
  int rev;
  
  if(!reason && session.xfer.filename)
    reason = session.xfer.filename;
  
  /* Set the "stalled" timer, if any, to prevent the connection
   * open from taking too long
   */
  if(TimeoutStalled)
    add_timer(TimeoutStalled, TIMER_STALLED, NULL, stalled_timeout);
  
  /* We save the state of our current disposition for doing reverse
   * lookups, and then set it to what the configuration wants it to
   * be.
   */
  rev = inet_reverse_dns(session.xfer.p,ServerUseReverseDNS);
  c = inet_accept(session.xfer.p, session.d, session.c, -1, -1, TRUE);
  inet_reverse_dns(session.xfer.p,rev);
  
  if(c && c->mode != CM_ERROR) {
    inet_close(session.pool,session.d);
    inet_setnonblock(session.pool,c);
    session.d = c;
    
    if(size) {
      send_response(R_150,
		    "Opening %s mode data connection for %s (%lu bytes).",
		    MODE_STRING, reason, size);
    } else {
      send_response(R_150,"Opening %s mode data connection for %s",
		    MODE_STRING, reason);
    }
    
    return 0;
  }
  
  /* Check for error conditions.
   * - MacGyver
   */
  if(c && c->mode == CM_ERROR) {
    log_pri(LOG_ERR,
	    "Error: unable to accept an incoming data connection (%s)",
	    strerror(c->xerrno));
  }
  
  add_response_err(R_425,"Can't build data connection: %s",
		   strerror(session.d->xerrno));
  destroy_pool(session.d->pool);
  session.d = NULL;
  return -1;
}

static int _data_active_open(char *reason, unsigned long size) {
  conn_t *c;
  int rev;
  
  if(!reason && session.xfer.filename)
    reason = session.xfer.filename;
  
  session.d = inet_create_connection(session.pool,NULL,-1,
				     session.c->local_ipaddr,
				     session.c->local_port-1,TRUE);
  
  /* Set the "stalled" timer, if any, to prevent the connection
   * open from taking too long
   */
  if(TimeoutStalled)
    add_timer(TimeoutStalled, TIMER_STALLED, NULL, stalled_timeout);
  
  rev = inet_reverse_dns(session.pool,ServerUseReverseDNS);
  
  if(inet_connect(session.d->pool,session.d,&session.data_addr,
		  session.data_port) == -1) {
    add_response_err(R_425,"Can't build data connection: %s",
		     strerror(session.d->xerrno));
    destroy_pool(session.d->pool);
    session.d = NULL;
    return -1;
  }
  
  c = inet_openrw(session.pool, session.d, NULL, session.d->listen_fd,
		  -1, -1, TRUE);
  
  inet_reverse_dns(session.pool,rev);
  
  if(c) {
    log_debug(DEBUG4,"active data connection opened - local  : %s:%d",
	      inet_ntoa(*session.d->local_ipaddr), session.d->local_port);
    log_debug(DEBUG4,"active data connection opened - remote : %s:%d",
	      inet_ntoa(*session.d->remote_ipaddr),
	      session.d->remote_port);
    
    if(size) {
      send_response(R_150,
		    "Opening %s mode data connection for %s (%lu bytes).",
		    MODE_STRING,reason,size);
    } else {
      send_response(R_150,
		    "Opening %s mode data connection for %s.",
		    MODE_STRING,reason);
    }
    
    inet_close(session.pool,session.d);
    inet_setnonblock(session.pool,session.d);
    session.d = c;
    return 0;
  }
  
  
  add_response_err(R_425,"Can't build data connection: %s",
		   strerror(session.d->xerrno));
  destroy_pool(session.d->pool);
  session.d = NULL;
  return -1;
}

void data_reset() {
  if(session.d && session.d->pool)
    destroy_pool(session.d->pool);
  session.d = NULL;
  session.flags &= (SF_ALL^(SF_ABORT|SF_XFER|SF_PASSIVE|SF_ASCII_OVERRIDE));
}

void data_init(char *filename, int direction) {
  if(!session.xfer.p) {
    _data_new_xfer(filename,direction);
  } else {
    if(!(session.flags & SF_PASSIVE))
      log_debug(DEBUG0,
		"data_init oddity: session.xfer exists in non-PASV mode.");
    
    session.xfer.direction = direction;
  }
}

int data_open(char *filename, char *reason, int direction,
	      unsigned long size) {
  struct sigaction	act;
  int			ret = 0;
  
  if(!session.xfer.p)
    _data_new_xfer(filename,direction);
  else
    session.xfer.direction = direction;
  
  if(!reason)
    reason = filename;
  
  if(session.flags & SF_PASSIVE) {
    if(!session.d) {
      log_pri(LOG_ERR,"Internal error: PASV mode set, but no data connection listening.");
      end_login(1);
    }
    
    ret = _data_pasv_open(reason,size);
  } else { /* active mode */
    if(session.d) {
      log_pri(LOG_ERR,"Internal error: non-PASV mode, yet data connection already exists?!?");
      end_login(1);
    }
    
    ret = _data_active_open(reason,size);
  }
  
  if(ret >= 0) {
    gettimeofday(&session.xfer.start_time,NULL);
    if(session.xfer.direction == IO_READ) {
      inet_setoptions(session.d->pool,session.d,
		      (main_server->tcp_rwin_override ?
		       main_server->tcp_rwin : 0),0);
      inet_set_proto_options(session.pool,session.d,0,0,1,1);
      curf = session.d->inf;
    } else {
      inet_setoptions(session.d->pool,session.d,0,
		      (main_server->tcp_swin_override ?
		       main_server->tcp_swin : 0));
      inet_set_proto_options(session.pool,session.d,0,0,1,1);
      curf = session.d->outf;
    }
    
    session.flags |= SF_XFER;
    
    if(TimeoutNoXfer)
      reset_timer(TIMER_NOXFER,ANY_MODULE);
    
    /* allow aborts */
    /* set curf to allow interrupted syscalls, so our
     * SIGURG handler can interrupt it
     */
    io_set_poll_sleep(curf,1);	/* 1 second sleep in select() */
    
    /* PORTABILITY: sigaction is used here to allow us
     * to indicate (w/ POSIX at least) that we want
     * SIGURG to interrupt syscalls.  Put in whatever
     * is necessary for your arch here (probably not necessary
     * as the only _important_ interrupted syscall is select()),
     * which on any sensible system is interrupted.
     */
    
    act.sa_handler = data_urgent;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
#ifdef SA_INTERRUPT
    act.sa_flags |= SA_INTERRUPT;
#endif
    sigaction(SIGURG, &act, NULL);
#ifdef HAVE_SIGINTERRUPT
    /* this is the BSD way of ensuring interruption.
     * Linux uses it too (??)
     */
    siginterrupt(SIGURG, 1);
#endif
  }
  return ret;
}

/* close == successful transfer */
void data_close(int quiet) {
  curf = NULL;
  if(session.d) {
    inet_close(session.pool,session.d);
    session.d = NULL;
  }
  
#if 0
  if(session.xfer.p)
    destroy_pool(session.xfer.p);
  
  bzero(&session.xfer,sizeof(session.xfer));
#endif
  
  session.data_port = session.c->remote_port - 1;
  
  /* aborts no longer necessary */
  signal(SIGURG,SIG_IGN);
  
  if(TimeoutNoXfer)
    reset_timer(TIMER_NOXFER,ANY_MODULE);
  
  if(TimeoutStalled)
    remove_timer(TIMER_STALLED,ANY_MODULE);
  
  session.flags &= (SF_ALL^SF_PASSIVE);
  session.flags &= (SF_ALL^(SF_ABORT|SF_XFER|SF_PASSIVE|SF_ASCII_OVERRIDE));
  main_set_idle();
  
  if(!quiet)
    add_response(R_226,"Transfer complete.");
}

/* Note: true_abort may be false in real abort situations, because
 * some ftp clients close the data connection at the same time as they
 * send the OOB byte (which results in a broken pipe on our
 * end).  Thus, it's a race between the OOB data and the tcp close
 * finishing.  Either way, it's ok (client will see either "Broken pipe"
 * error or "Aborted").  cmd_abor in mod_xfer cleans up the session
 * flags in any case.  session flags will end up have SF_POST_ABORT
 * set if the OOB byte won the race.
 */
void data_cleanup() {
  if(session.xfer.p)
    destroy_pool(session.xfer.p);
  
  bzero(&session.xfer,sizeof(session.xfer));
}

void data_abort(int err, int quiet) {
  int true_abort = XFER_ABORTED;
  
  curf = NULL;
  if(session.d) {
    inet_close(session.pool,session.d);
    session.d = NULL;
  }
  
  if(session.xfer.p)
    destroy_pool(session.xfer.p);
  
  bzero(&session.xfer,sizeof(session.xfer));
  
  session.data_port = session.c->remote_port - 1;
  
  if(TimeoutNoXfer)
    reset_timer(TIMER_NOXFER,ANY_MODULE);
  
  if(TimeoutStalled)
    remove_timer(TIMER_STALLED,ANY_MODULE);
  
  session.flags &= (SF_ALL^SF_PASSIVE);
  session.flags &= (SF_ALL^(SF_XFER|SF_PASSIVE|SF_ASCII_OVERRIDE));
  main_set_idle();
  
  /* aborts no longer necessary */
  signal(SIGURG,SIG_IGN);
  
  if(TimeoutNoXfer)
    reset_timer(TIMER_NOXFER,ANY_MODULE);
  
  if(!quiet) {
    char	*respcode = R_426;
    char	*fmt = NULL;
    char	*msg = NULL;
    char	msgbuf[64];
    
    switch (err) {
      
    case 0:
      respcode = R_426;
      msg = "Data connection closed.";
      break;
      
#ifdef ENXIO
    case ENXIO:
      respcode = R_451;
      msg = "Unexpected streams hangup.";
      break;
      
#endif
      
#ifdef EAGAIN
    case EAGAIN:		/* FALLTHROUGH */
#endif
#ifdef ENOMEM
    case ENOMEM:
#endif
#if defined(EAGAIN) || defined(ENOMEM)
      respcode = R_451;
      msg = "Insufficient memory or file locked.";
      break;
#endif
      
#ifdef ETXTBSY
    case ETXTBSY:		/* FALLTHROUGH */
#endif
#ifdef EBUSY
    case EBUSY:
#endif
#if defined(ETXTBSY) || defined(EBUSY)
      respcode = R_451;
      break;
#endif
      
#ifdef ENOSPC
    case ENOSPC:
      respcode = R_452;
      break;
#endif
      
#ifdef EDQUOT
    case EDQUOT:		/* FALLTHROUGH */
#endif
#ifdef EFBIG
    case EFBIG:
#endif
#if defined(EDQUOT) || defined(EFBIG)
      respcode = R_552;
      break;
#endif
      
#ifdef ECOMM
    case ECOMM:		/* FALLTHROUGH */
#endif
#ifdef EDEADLK
    case EDEADLK:		/* FALLTHROUGH */
#endif
#ifdef EDEADLOCK
# if !defined(EDEADLK) || (EDEADLOCK != EDEADLK)
    case EDEADLOCK:		/* FALLTHROUGH */
# endif
#endif
#ifdef EXFULL
    case EXFULL:		/* FALLTHROUGH */
#endif
#ifdef ENOSR
    case ENOSR:		/* FALLTHROUGH */
#endif
#ifdef EPROTO
    case EPROTO:		/* FALLTHROUGH */
#endif
#ifdef ETIME
    case ETIME:		/* FALLTHROUGH */
#endif
#ifdef EIO
    case EIO:		/* FALLTHROUGH */
#endif
#ifdef EFAULT
    case EFAULT:		/* FALLTHROUGH */
#endif
#ifdef ESPIPE
    case ESPIPE:		/* FALLTHROUGH */
#endif
#ifdef EPIPE
    case EPIPE:
#endif
#if defined(ECOMM) || defined(EDEADLK) ||  defined(EDEADLOCK) \
	|| defined(EXFULL) || defined(ENOSR) || defined(EPROTO) \
	|| defined(ETIME) || defined(EIO) || defined(EFAULT) \
	|| defined(ESPIPE) || defined(EPIPE)
      respcode = R_451;
      break;
#endif
      
#ifdef EREMCHG
    case EREMCHG:		/* FALLTHROUGH */
#endif
#ifdef ESRMNT
    case ESRMNT:		/* FALLTHROUGH */
#endif
#ifdef ESTALE
    case ESTALE:		/* FALLTHROUGH */
#endif
#ifdef ENOLINK
    case ENOLINK:		/* FALLTHROUGH */
#endif
#ifdef ENOLCK
    case ENOLCK:		/* FALLTHROUGH */
#endif
#ifdef ENETRESET
    case ENETRESET:		/* FALLTHROUGH */
#endif
#ifdef ECONNABORTED
    case ECONNABORTED:	/* FALLTHROUGH */
#endif
#ifdef ECONNRESET
    case ECONNRESET:	/* FALLTHROUGH */
#endif
#ifdef ETIMEDOUT
    case ETIMEDOUT:
#endif
#if defined(EREMCHG) || defined(ESRMNT) ||  defined(ESTALE) \
	|| defined(ENOLINK) || defined(ENOLCK) || defined(ENETRESET) \
	|| defined(ECONNABORTED) || defined(ECONNRESET) || defined(ETIMEDOUT)
      respcode = R_450;
      msg = "Link to file server lost.";
      break;
#endif
    }
    
    if ( msg == NULL && (msg = strerror(err)) == NULL ) {
      if ( snprintf(msgbuf, sizeof msgbuf,
		    "Unknown or out of range errno [%d].",
		    err) > 0 )
	msg = msgbuf;
    }
    add_response_err(respcode,
		     fmt ? fmt : "Transfer aborted.  %s",
		     msg ? msg : ""
		     );
    /* ??? syslog the response for the help desk??? */
  }
  
  if(true_abort)
    session.flags |= SF_POST_ABORT;
}

/* data_xfer actually transfers the data on the data connection ..
 * ascii translation is performed if necessary.  direction set
 * when data connection was opened determine if the client buffer
 * is read from or written to.  return 0 if reading and data connection
 * closes, or -1 if error
 */

int data_xfer(char *cl_buf, int cl_size) {
  char *buf = session.xfer.buf;
  int len = 0;
  int total = 0;
  
  if(session.xfer.direction == IO_READ) {
    if(session.d && (len = io_read(session.d->inf, cl_buf, cl_size, 1)) > 0) {
      if(TimeoutStalled)
	reset_timer(TIMER_STALLED, ANY_MODULE);
      
      if(session.flags & (SF_ASCII|SF_ASCII_OVERRIDE)) {
	char *cp = cl_buf, *dest = cl_buf;
	register int i = len;
	
	while(i--)
	  if(*cp != '\r')
	    *dest++ = *cp++;
	  else {
	    len--; total++;
	    cp++;
	  }
      }
      
      total += len;
    }
  } else { /* IO_WRITE */
    
    /* copy client buffer to internal buffer, and
     * xlate ascii as necessary
     */
    
    while(cl_size) {
      int o_size,size = cl_size;
      int wsize,adjlen;
      char *wb;
      
      if(size > 1024)
	size = 1024;
      
      o_size = size;
      bcopy(cl_buf,buf,size);
      while(size) {
	wb = buf; wsize = size; adjlen = 0;
	
	if(session.flags & (SF_ASCII|SF_ASCII_OVERRIDE))
	  _translate_ascii(&wb,&wsize,&adjlen);
	
	if(io_write(session.d->outf,wb,wsize) == -1)
	  return -1;
	
	if(TimeoutStalled)
	  reset_timer(TIMER_STALLED, ANY_MODULE);
	
	total += wsize;
	size -= (wsize - adjlen);
	if(size) {
	  wb = buf + (wsize - adjlen);
	  bcopy(wb,buf,size);
	}
      }
      
      cl_size -= o_size;
      cl_buf += o_size;
    }
    
    len = total;
  }
  
  if(total && TimeoutIdle)
    reset_timer(TIMER_IDLE,ANY_MODULE);
  
  session.xfer.total_bytes += total;
  session.total_bytes += total;
  return len;
}

#ifdef HAVE_SENDFILE
/* data_sendfile actually transfers the data on the data connection.
 * ASCII translation is not performed.
 * return 0 if reading and data connection closes, or -1 if error
 */
pr_sendfile_t data_sendfile(int retr_fd, off_t *offset, size_t count) {
  int flags, error;
  pr_sendfile_t len = 0, total = 0;
  
  if(session.xfer.direction == IO_READ)
    return -1;
  
  if((flags = fcntl(session.d->outf->fd, F_GETFL)) == -1)
    return -1;
  
  /* set fd to blocking-mode for sendfile() */
  if (flags & O_NONBLOCK)
    if(fcntl(session.d->outf->fd, F_SETFL, flags ^ O_NONBLOCK) == -1)
      return -1;
  
  log_debug(DEBUG4, "data_sendfile(%d,%d,%d)", retr_fd, *offset, count);
  
  for(;;) {
#if defined(HAVE_LINUX_SENDFILE)
    /* Linux semantics are fairly straightforward in a glibc 2.x world:
     *
     * #include <sys/sendfile.h>
     *
     * ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
     */
    if((len = sendfile(session.d->outf->fd, retr_fd, offset, count)) == -1) {
#elif defined(HAVE_BSD_SENDFILE) || defined(HAVE_HPUX_SENDFILE)

#if defined(HAVE_BSD_SENDFILE)
    /* BSD semantics for sendfile are flexible...it'd be nice if we could
     * standardize on something like it.  The semantics are:
     *
     * #include <sys/types.h>
     * #include <sys/socket.h>
     * #include <sys/uio.h>
     *
     * int sendfile(int in_fd, int out_fd, off_t offset, size_t count,
     *              struct sf_hdtr *hdtr, off_t *len, int flags)
     */
    if(sendfile(retr_fd, session.d->outf->fd, *offset, count, NULL, &len,
		  0) == -1) {
#elif defined(HAVE_HPUX_SENDFILE)
    /* HP/UX semantics for sendfile() are similar to BSD's, however the
     * prototype is different:
     *
     * #include <sys/socket.h>
     *
     * ssize_t sendfile(int out_fd, int in_fd, off_t offset, size_t count,
     *                  const struct iovec *hdtrl, int flags)
     */
    if((len = sendfile(session.d->outf->fd, retr_fd, *offset, count, NULL,
		       0)) == -1) {
#endif /* HAVE_BSD_SENDFILE */

      /* IMO, BSD's semantics are warped.  Apparently, since we have our
       * alarms tagged SA_INTERRUPT (allowing system calls to be
       * interrupted - primarily for select), BSD will interrupt a
       * sendfile operation as well, so we have to catch and handle this
       * case specially.  It should also be noted that the sendfile(2) man
       * page doesn't state any of this.
       *
       * HP/UX has the same semantics, however, EINTR is well documented
       * as a side effect in the sendfile(2) man page.
       */
      if(errno == EINTR) {
	/* If we got everything in this transaction, we're done.
	 */
	if((count -= len) <= 0)
	  break;
	
	*offset += len;
	
	if(TimeoutStalled)
	  reset_timer(TIMER_STALLED, ANY_MODULE);
	
	if(TimeoutIdle)
	  reset_timer(TIMER_IDLE, ANY_MODULE);
	
	session.xfer.total_bytes += len;
	session.total_bytes += len;
	total += len;
	
	continue;
      }
#endif /* HAVE_LINUX_SENDFILE */
      
      error = errno;
      fcntl(session.d->outf->fd, F_SETFL, flags);
      errno = error;
      
      return -1;
    }

    break;
  }
  
  log_debug(DEBUG4, "data_sendfile: %ld", total);
  
  if (flags & O_NONBLOCK)
    fcntl(session.d->outf->fd, F_SETFL, flags);
  
  if(TimeoutStalled)
    reset_timer(TIMER_STALLED, ANY_MODULE);
  
  if(TimeoutIdle)
    reset_timer(TIMER_IDLE, ANY_MODULE);
  
  session.xfer.total_bytes += len;
  session.total_bytes += len;
  total += len;
  
  return total;
}
#endif /* HAVE_SENDFILE */
