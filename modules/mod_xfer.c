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
 * Data transfer module for ProFTPD
 * $Id: mod_xfer.c,v 1.42 2000-08-08 00:54:46 macgyver Exp $
 */

/* History Log:
 *
 * 8/15/99
 *   - rate control <grin@tolna.net>
 * 4/24/97 0.99.0pl1
 *   _translate_ascii was returning a buffer larger than the max buffer
 *   size causing memory overrun and all sorts of neat corruption.
 *   Status: Stomped
 *
 */

#include "conf.h"
#include "privs.h"

#ifdef HAVE_SYS_SENDFILE_H
#include <sys/sendfile.h>
#endif

#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

extern module auth_module;
extern pid_t mpid;

/* From the auth module */
char *auth_map_uid(int);
char *auth_map_gid(int);

void xfer_abort(IOFILE*,int);

/* Variables for this module */
static fsdir_t *retr_file = NULL;
static fsdir_t *stor_file = NULL;
static int stor_fd;
static int retr_fd;

module xfer_module;

static void _log_transfer(char direction, char abort_flag) {
  struct timeval end_time;
  char *fullpath;

  gettimeofday(&end_time,NULL);

  end_time.tv_sec -= session.xfer.start_time.tv_sec;
  if(end_time.tv_usec >= session.xfer.start_time.tv_usec)
    end_time.tv_usec -= session.xfer.start_time.tv_usec;
  else {
    end_time.tv_usec = 1000000L - (session.xfer.start_time.tv_usec -
                       end_time.tv_usec);
    end_time.tv_sec--;
  }

  fullpath = dir_abs_path(session.xfer.p,session.xfer.path,TRUE);

  if((session.flags & SF_ANON) != 0) {
    log_xfer(end_time.tv_sec,session.c->remote_name,session.xfer.total_bytes,
             fullpath,(session.flags & SF_ASCII ? 'a' : 'b'),
             direction,'a',session.anon_user, abort_flag);
  } else {
    log_xfer(end_time.tv_sec,session.c->remote_name,session.xfer.total_bytes,
             fullpath,(session.flags & SF_ASCII ? 'a' : 'b'),
             direction,'r',session.user, abort_flag);
  }

  log_debug(DEBUG1, "Transfer %s %d bytes in %d.%02d seconds.",
	    abort_flag == 'c' ? " completed:" : " aborted after",
	    session.xfer.total_bytes,end_time.tv_sec,
	    (end_time.tv_usec / 10000));
}

/* This routine counts the difference in usec between timeval's
 */
static float _rate_diffusec(struct timeval tlast, struct timeval t) {
    float diffsec, diffusec;

    diffsec = t.tv_sec - tlast.tv_sec;
    diffusec= t.tv_usec- tlast.tv_usec;
    log_debug(DEBUG5,
	      "_rate_diffusec: last=%ld %ld  now=%ld %ld  diff=%f %f  res=%f.",
	      tlast.tv_sec,tlast.tv_usec,
	      t.tv_sec,t.tv_usec,
	      diffsec, diffusec,
	      ( diffsec * 10e5 + diffusec ) );
    return( diffsec * 10e5 + diffusec );
}

/* Bandwidth Throttling. <grin@tolna.net>
 *
 * If the rate sent were too high throttles the required amount (max 100 sec).
 * No throttling for the first FreeBytes bytes
 *   (but this includes REST as well).
 *
 * If HardBPS then forces BPS throughout FreeBytes as well.
 *
 * input: 	rate_pos:	position in file
 *              rate_bytes:     bytes xferred (same as rate_pos if !REST)
 *              rate_tvlast:    when the transfer was started
 *              rate_freebytes: no throttling unless that many xferred
 *              rate_bps:       max byte / sec bandwidth allowed
 *              rate_hardbps:   if FALSE then forces BPS only after FreeBytes
 */
static void _rate_throttle(unsigned long rate_pos, long rate_bytes,
			   struct timeval rate_tvlast,
			   long rate_freebytes, long rate_bps,
			   int rate_hardbps)
{
  /* rate_tv:        now (the diff of those gives the time spent)
   */
  struct timeval rate_tv;
  float dtime, wtime;

  gettimeofday(&rate_tv, NULL);
  
  /* no rate control unless more than free bytes DL'ed */
  log_debug(DEBUG5,
	    "_rate_throttle: rate_bytes=%ld  rate_pos=%ld  rate_freebytes=%ld "
	    "rate_bps=%ld  rate_hardbps=%i.",
	    rate_bytes, rate_pos,
	    rate_freebytes, rate_bps, rate_hardbps);

  if(rate_pos < rate_freebytes)
    return;
  
  if(!rate_hardbps)
    rate_bytes -= rate_freebytes;
  
  dtime = _rate_diffusec(rate_tvlast, rate_tv);
  wtime = 10e5 * rate_bytes / rate_bps;
  
  /* Setup for the select.
   */
  memset(&rate_tv, 0, sizeof(rate_tv));
  
  if(wtime > dtime) {
    /* too fast, doze a little */
    log_debug(DEBUG5, "_rate_throttle: wtime=%f  dtime=%f.", wtime, dtime);

    if(wtime - dtime > 10e7) {
      /* >100sec, umm that'd timeout */
      log_debug(DEBUG5, "Sleeping 100 seconds.");
      rate_tv.tv_usec = 10e7;
      log_debug(DEBUG5, "Sleeping 100 seconds done!");
    } else {
      log_debug(DEBUG5, "Sleeping %f sec.", (wtime - dtime) / 10e5);
      rate_tv.tv_usec = wtime - dtime;
      log_debug(DEBUG5, "Sleeping %f sec done!", (wtime - dtime) / 10e5);
    }
    
    /* For completeness, break it up into seconds and microseconds -- some
     * platforms have problems dealing with large values for microseconds.
     *
     * Due to a bug in GCC/EGCS, we can't say x % 10e5, so we spell it out...
     */
    rate_tv.tv_sec = rate_tv.tv_usec / 1000000;
    rate_tv.tv_usec = rate_tv.tv_usec % 1000000;
    
    /* We use select() instead of usleep() because it seems to be far more
     * portable across platforms.
     */
    if(select(0, (fd_set *) 0, (fd_set *) 0, (fd_set *) 0, &rate_tv) < 0) {
      log_pri(LOG_WARNING, "Unable to throttle bandwidth: %s.",
	      strerror(errno));
    }
  }
}

static int _transmit_normal(char *buf, long bufsize) {
  long count;
  
  if((count = fs_read(retr_file, retr_fd, buf, bufsize)) <= 0)
    return 0;
  
  return data_xfer(buf, count);
}

#ifdef HAVE_SENDFILE
static int _transmit_sendfile(int rate_bps, unsigned long count, off_t offset,
			       pr_sendfile_t *retval) {
  
  /* We don't use sendfile() if:
   * - We're using bandwidth throttling.
   * - We're transmitting an ASCII file.
   * - There's no data left to transmit.
   */
  if(rate_bps ||
     !(session.xfer.file_size - count) ||
     (session.flags & (SF_ASCII | SF_ASCII_OVERRIDE))) {
    return 0;
  }

 retry:
  *retval = data_sendfile(retr_fd, &offset, session.xfer.file_size - count);

  if(*retval == -1) {
    switch (errno) {
    case EAGAIN:
    case EINTR:
      /* Interrupted call, or the other side wasn't ready yet.
       */
      goto retry;
      
    case EPIPE:
    case ECONNRESET:
    case ETIMEDOUT:
    case EHOSTUNREACH:
      /* Other side broke the connection.
       */
      break;
      
#ifdef ENOSYS
    case ENOSYS:
#endif /* ENOSYS */
      
    case EINVAL:
      /* No sendfile support, apparently.  Try it the normal way.
       */
      return 0;
      break;
      
    default:
      log_pri(LOG_ERR,
	      "_transmit_sendfile error "
	      "(reverting to normal data transmission) %d: %s.",
	      errno, strerror(errno));
      return 0;
    }
  }
  
  return 1;
}
#endif /* HAVE_SENDFILE */

static long _transmit_data(int rate_bps, unsigned long count, off_t offset,
			   char *buf, long bufsize) {
#ifdef HAVE_SENDFILE
  pr_sendfile_t retval;
  
  if(!_transmit_sendfile(rate_bps, count, offset, &retval))
    return _transmit_normal(buf, bufsize);
  else
    return (long) retval;
#else
  return _transmit_normal(buf, bufsize);
#endif /* HAVE_SENDFILE */
}

static void _stor_done() {
  struct stat sbuf;

  fs_close(stor_file,stor_fd);
  stor_file = NULL;

  if(session.fsuid && session.xfer.path) {
    fs_stat(session.xfer.path,&sbuf);
    PRIVS_ROOT;
    if(chown(session.xfer.path,(uid_t)session.fsuid,(gid_t)session.fsgid) == -1)
      log_pri(LOG_WARNING, "chown(%s) as root failed: %s.",
              session.xfer.path, strerror(errno));
    else
      fs_chmod(session.xfer.path,sbuf.st_mode);
    PRIVS_RELINQUISH;
  } else if(session.fsgid && session.xfer.path) {
    fs_stat(session.xfer.path,&sbuf);
    if(chown(session.xfer.path,(uid_t)-1,(gid_t)session.fsgid) == -1)
      log_pri(LOG_WARNING, "chown(%s) failed: %s.",
              session.xfer.path, strerror(errno));
    else
      fs_chmod(session.xfer.path,sbuf.st_mode);
  }
}

static void _retr_done() {
  fs_close(retr_file,retr_fd);
  retr_file = NULL;
}

static void _stor_abort() {
  fs_close(stor_file,stor_fd);
  stor_file = NULL;

  if(session.xfer.xfer_type == STOR_HIDDEN) {
    /* If hidden stor aborted, remove only hidden file, not real one */
    if(session.xfer.path_hidden)
      fs_unlink(session.xfer.path_hidden);
  } else if(session.xfer.path) {
    if(get_param_int(TOPLEVEL_CONF, "DeleteAbortedStores", FALSE) == 1)
      fs_unlink(session.xfer.path);
  }

  _log_transfer('i', 'i');
}

static void _retr_abort() {
  /* Isn't necessary to send anything here, just cleanup */
  fs_close(retr_file,retr_fd);
  retr_file = NULL;
  _log_transfer('o', 'i');
}

/* cmd_pre_stor is a PRE_CMD handler which checks security, etc, and
 * places the full filename to receive in cmd->private [note that we CANNOT
 * use cmd->tmp_pool for this, as tmp_pool only lasts for the duration
 * of this function.
 */

MODRET pre_cmd_stor(cmd_rec *cmd) {
  char *dir;
  mode_t fmode;
  privdata_t *p, *p_hidden;

  if(cmd->argc < 2) {
    add_response_err(R_500,"'%s' not understood.",get_full_cmd(cmd));
    return ERROR(cmd);
  }
  
  /* No PORT command has been issued.
   */
  if(!(session.flags & SF_PASSIVE) &&
     (session.d != NULL || !(session.flags & SF_PORT))) {
    add_response_err(R_503, "No PORT command issued first.");
    return ERROR(cmd);
  }

  session.flags &= ~SF_PORT;
  
  dir = dir_best_path(cmd->tmp_pool,cmd->arg);

  if(!dir || !dir_check(cmd->tmp_pool,cmd->argv[0],cmd->group,dir,NULL)) {
    add_response_err(R_550,"%s: %s",cmd->arg,strerror(errno));
    return ERROR(cmd);
  }

  fmode = file_mode(dir);

  if(fmode && (session.xfer.xfer_type != STOR_APPEND) && 
	       get_param_int(CURRENT_CONF,"AllowOverwrite",FALSE) != 1) {
    add_response_err(R_550,"%s: Overwrite permission denied",cmd->arg);
    return ERROR(cmd);
  }

  if(fmode && !S_ISREG(fmode)) {
    add_response_err(R_550,"%s: Not a regular file",cmd->arg);
    return ERROR(cmd);
  }

  /* If restarting, check permissions on this directory, if
   * AllowStoreRestart is set, permit it
   */

  if(fmode &&
     (session.restart_pos || (session.xfer.xfer_type == STOR_APPEND)) &&
     get_param_int(CURRENT_CONF,"AllowStoreRestart",FALSE) != TRUE) {
    add_response_err(R_451,"%s: Append/Restart not permitted, try again.",
                  cmd->arg);
    session.restart_pos = 0L;
    session.xfer.xfer_type = STOR_DEFAULT;
    return ERROR(cmd);
  }

  /* otherwise everthing is good */
  p = mod_privdata_alloc(cmd, "stor_filename", strlen(dir) + 1);
  sstrncpy(p->value.str_val, dir, strlen(dir) + 1);

  if(get_param_int(CURRENT_CONF,"HiddenStor",FALSE) == 1) {
    /* We have to also figure out the temporary hidden file name for
     * receiving this transfer.
     * Length is +5 due to .in. prepended and "." at end.
     */

    char *c;
    int dotcount, foundslash, basenamestart, maxlen;

    dotcount = foundslash = basenamestart = 0;

    /* Figure out where the basename starts */
    for (c=dir; *c; ++c) {
      if (*c == '/') {
	foundslash = 1;
	basenamestart = dotcount = 0;
      } else if (*c == '.') {
	++ dotcount;

	/* Keep track of leading dots, ... is normal, . and .. are special.
	 * So if we exceed ".." it becomes a normal file, retroactively consider
	 * this the possible start of the basename
	 */
	if ((dotcount > 2) && (!basenamestart))
	  basenamestart = ((unsigned long)c - (unsigned long)dir) - dotcount;
      } else {
	/* We found a nonslash, nondot character; if this is the first time
	 * we found one since the last slash, remember this as the possible
	 * start of the basename.
	 */
	if (!basenamestart)
	  basenamestart = ((unsigned long)c - (unsigned long)dir) - dotcount;
      }
    }

    if (! basenamestart) {
      /* This probably shouldn't happen */
      add_response_err(R_451,"%s: Bad file name.", dir);
      return ERROR(cmd);
    }

    maxlen = strlen(dir) + 1 + 5;

    if (maxlen > MAXPATHLEN) {
      /* This probably shouldn't happen */
      add_response_err(R_451,"%s: File name too long.", dir);
      return ERROR(cmd);
    }
    
    p_hidden = mod_privdata_alloc(cmd, "stor_hidden_filename", maxlen);

    if (! foundslash) {
      /* Simple local file name */
      sstrncpy(p_hidden->value.str_val, ".in.", maxlen);
      sstrcat(p_hidden->value.str_val, dir, maxlen);
      sstrcat(p_hidden->value.str_val, ".", maxlen);
      log_pri(LOG_DEBUG, "Local path, will rename %s to %s.",
	p_hidden->value.str_val, p->value.str_val);
    } else {
      /* Complex relative path or absolute path */
      sstrncpy(p_hidden->value.str_val, dir, maxlen);
      p_hidden->value.str_val[basenamestart] = '\0';
      sstrcat(p_hidden->value.str_val, ".in.", maxlen);
      sstrcat(p_hidden->value.str_val, dir + basenamestart, maxlen);
      sstrcat(p_hidden->value.str_val, ".", maxlen);
      log_pri(LOG_DEBUG, "Complex path, will rename %s to %s.",
	p_hidden->value.str_val, p->value.str_val);

      if(file_mode(p_hidden->value.str_val)) {
        add_response_err(R_550,"%s: Temporary hidden file %s already exists",
		cmd->arg, p_hidden->value.str_val);
        return ERROR(cmd);
      }
    }

    session.xfer.xfer_type = STOR_HIDDEN;
  }



  return HANDLED(cmd);
}

/* cmd_pre_appe is the PRE_CMD handler for the APPEnd command, which
 * simply sets xfer_type to STOR_APPEND and calls pre_cmd_stor
 */

MODRET pre_cmd_appe(cmd_rec *cmd)
{
  session.xfer.xfer_type = STOR_APPEND;
  session.restart_pos = 0L;
  
  return pre_cmd_stor(cmd);
}

MODRET cmd_stor(cmd_rec *cmd)
{
  char *dir;
  char *lbuf;
  int bufsize,len;
  unsigned long respos = 0;
  privdata_t *p, *p_hidden;

#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  regex_t *preg;
  int ret;
#endif /* REGEX */

  long rate_pos=0, rate_bytes=0, rate_freebytes=0, rate_bps=0;
  int rate_hardbps=0;
  struct timeval rate_tvstart;

  if( (rate_bps = get_param_int(CURRENT_CONF,"RateWriteBPS",FALSE)) == -1 ) { rate_bps=0; }
  if( (rate_freebytes = get_param_int(CURRENT_CONF,"RateWriteFreeBytes",FALSE)) == -1 ) { rate_freebytes=0; }
  rate_hardbps = get_param_int(CURRENT_CONF,"RateWriteHardBPS",FALSE) == 1;
      
  if( rate_bps != 0 ) {
      /* I am not sure this _is_ allowed in ftp protocol... ideas, anyone?
       add_response(R_211,"Allowed bandwidth is %ld bps (starting at %ld).",rate_bps,rate_freebytes);
       */
      log_debug(DEBUG2, "Allowed bandwidth is %ld bps (starting at %ld).",
		rate_bps, rate_freebytes);
  }
  
  p_hidden = NULL;
  p = mod_privdata_find(cmd,"stor_filename",NULL);

  if(!p) {
    add_response_err(R_550,"%s: internal error, stor_filename not set by cmd_pre_stor",cmd->arg);
    return ERROR(cmd);
  }

  dir = p->value.str_val;

  if(session.xfer.xfer_type == STOR_HIDDEN) {
    p_hidden = mod_privdata_find(cmd,"stor_hidden_filename",NULL);
    if(!p_hidden) {
      add_response_err(R_550,"%s: internal error, stor_hidden_filename not set by cmd_pre_retr",cmd->arg);
      return ERROR(cmd);
    }
  }

#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  preg = (regex_t*)get_param_ptr(TOPLEVEL_CONF,"PathAllowFilter",FALSE);

  if(preg && ((ret = regexec(preg,cmd->arg,0,NULL,0)) != 0)) {
    char errmsg[200];
    regerror(ret,preg,errmsg,200);
    log_debug(DEBUG2, "'%s' didn't pass regex: %s.", cmd->arg, errmsg);
    add_response_err(R_550,"%s: Forbidden filename", cmd->arg);
    return ERROR(cmd);
  }

  preg = (regex_t*)get_param_ptr(TOPLEVEL_CONF,"PathDenyFilter",FALSE);

  if(preg && ((ret = regexec(preg,cmd->arg,0,NULL,0)) == 0)) {
    add_response_err(R_550,"%s: Forbidden filename", cmd->arg);
    return ERROR(cmd);
  }
#endif /* REGEX */

  if(session.xfer.xfer_type == STOR_HIDDEN)
    stor_file = fs_open(p_hidden->value.str_val,
	O_WRONLY|(session.restart_pos ? 0 : O_CREAT|O_EXCL),&stor_fd);

  else if(session.xfer.xfer_type == STOR_APPEND)
    stor_file = fs_open(dir, O_WRONLY|O_CREAT|O_APPEND,&stor_fd);

  else /* Normal session */
    stor_file = fs_open(dir,
	O_WRONLY|(session.restart_pos ? 0 : O_TRUNC|O_CREAT),&stor_fd);


  if(stor_file && session.restart_pos) {
    if(fs_lseek(stor_file,stor_fd,session.restart_pos,SEEK_SET) == -1) {
      int _errno = errno;
      fs_close(stor_file,stor_fd);
      errno = _errno;
      stor_file = NULL;
    }

    respos = session.restart_pos;
    rate_pos = respos;
    session.restart_pos = 0L;
  }

  if(!stor_file) {
    add_response_err(R_550,"%s: %s",cmd->arg,strerror(errno));
    return ERROR(cmd);
  } else {
    /* perform the actual transfer now */
    data_init(cmd->arg,IO_READ);

    session.xfer.path = pstrdup(session.xfer.p,dir);
    if(session.xfer.xfer_type == STOR_HIDDEN)
      session.xfer.path_hidden = pstrdup(session.xfer.p, p_hidden->value.str_val);
    else
      session.xfer.path_hidden = NULL;
      
    session.xfer.file_size = respos;

    if(data_open(cmd->arg,NULL,IO_READ,0) < 0) {
      data_abort(0,TRUE);
      return HANDLED(cmd);
    }

    bufsize = (main_server->tcp_rwin > 0 ? main_server->tcp_rwin : 1024);
    lbuf = (char*) palloc(cmd->tmp_pool, bufsize);
    
    gettimeofday(&rate_tvstart, NULL);
    while((len = data_xfer(lbuf, bufsize)) > 0) {
      if(XFER_ABORTED)
        break;

      len = fs_write(stor_file, stor_fd, lbuf, len);
      if(len < 0) {
        int s_errno = errno;
        _stor_abort();
        data_abort(s_errno, FALSE);
        return ERROR(cmd);
      }

      if(rate_bps) {
          rate_pos += len;
          rate_bytes += len;
	  _rate_throttle(rate_pos, rate_bytes, rate_tvstart, rate_freebytes,
			 rate_bps, rate_hardbps);
      }
    }

    if(XFER_ABORTED) {
      _stor_abort();
      data_abort(0,0);
      return ERROR(cmd);
    } else if(len < 0) {
      _stor_abort();
      data_abort(session.d->inf->xerrno,FALSE);
      return ERROR(cmd);
    } else {
      if(session.xfer.path && session.xfer.path_hidden) {
        if(fs_rename(session.xfer.path_hidden,session.xfer.path) != 0) {
          /* This should only fail on a race condition with a chmod/chown
           * or if STOR_APPEND is on and the permissions are squirrely.
           * The poor user will have to re-upload, but we've got more important
           * problems to worry about and this failure should be fairly rare.
           */
           log_pri(LOG_WARNING, "Rename of %s to %s failed: %s.",
             session.xfer.path_hidden, session.xfer.path, strerror(errno));

           add_response_err(R_550,"%s: rename of hidden file %s failed: %s",
             session.xfer.path, session.xfer.path_hidden, strerror(errno));

           fs_unlink(session.xfer.path_hidden);

           return ERROR(cmd);
         }
      }
      _stor_done();
      data_close(FALSE);
    }
  }
  return HANDLED(cmd);
}

MODRET cmd_rest(cmd_rec *cmd)
{
  long int pos;
  char *endp;

  if(cmd->argc != 2) {
    add_response_err(R_500,"'%s': command not understood.",get_full_cmd(cmd));
    return ERROR(cmd);
  }

  pos = strtol(cmd->argv[1],&endp,10);
  if((endp && *endp) || pos < 0) {
    add_response_err(R_501,"REST requires a value greater than or equal to 0.");
    return ERROR(cmd);
  }

  session.restart_pos = pos;
  add_response(R_350,"Restarting at %ld. Send STORE or RETRIEVE to initiate transfer.",
                pos);
  return HANDLED(cmd);
}

/* cmd_pre_retr is a PRE_CMD handler which checks security, etc, and
 * places the full filename to send in cmd->private [note that we CANNOT
 * use cmd->tmp_pool for this, as tmp_pool only lasts for the duration
 * of this function.
 */

MODRET pre_cmd_retr(cmd_rec *cmd)
{
  char *dir;
  mode_t fmode;
  privdata_t *p;

  if(cmd->argc < 2) {
    add_response_err(R_500,"'%s' not understood.",get_full_cmd(cmd));
    return ERROR(cmd);
  }

  dir = dir_realpath(cmd->tmp_pool,cmd->arg);

  if(!dir || !dir_check(cmd->tmp_pool,cmd->argv[0],cmd->group,dir,NULL)) {
    add_response_err(R_550,"%s: %s",cmd->arg,strerror(errno));
    return ERROR(cmd);
  }


  fmode = file_mode(dir);

  if(!S_ISREG(fmode)) {
    if(!fmode)
      add_response_err(R_550,"%s: %s",cmd->arg,strerror(errno));
    else
      add_response_err(R_550,"%s: Not a regular file",cmd->arg);
    return ERROR(cmd);
  }

  /* If restart is on, check to see if AllowRestartRetrieve
   * is off, in which case we disallow the transfer and
   * clear restart_pos
   */

  if(session.restart_pos &&
     get_param_int(CURRENT_CONF,"AllowRetrieveRestart",FALSE) == 0) {
    add_response_err(R_451,"%s: Restart not permitted, try again.",
                  cmd->arg);
    session.restart_pos = 0L;
    return ERROR(cmd);
  }

  /* otherwise everthing is good */
  p = mod_privdata_alloc(cmd,"retr_filename",strlen(dir)+1);
  sstrncpy(p->value.str_val, dir, strlen(dir) + 1);
  return HANDLED(cmd);
}

MODRET cmd_retr(cmd_rec *cmd)
{
  char *dir, *lbuf;
  struct stat sbuf;
  struct timeval rate_tvstart;
  privdata_t *p;
  long bufsize, len = 0;
  long rate_hardbps = 0;
  unsigned long respos = 0,cnt = 0,cnt_steps = 0,cnt_next = 0;
  long rate_bytes = 0, rate_freebytes = 0, rate_bps = 0;
  
  if((rate_bps = get_param_int(CURRENT_CONF, "RateReadBPS", FALSE)) == -1)
    rate_bps = 0;

  if((rate_freebytes = get_param_int(CURRENT_CONF,
				     "RateReadFreeBytes", FALSE)) == -1)
    rate_freebytes = 0;
  
  rate_hardbps = get_param_int(CURRENT_CONF,"RateReadHardBPS",FALSE) == 1;
  
  if(rate_bps != 0) {
      /* I am not sure this _is_ allowed in ftp protocol... ideas, anyone?
	 add_response(R_211,"Allowed bandwidth is %ld bps (starting at %ld).",rate_bps,rate_freebytes);
      */
    log_debug(DEBUG2, "Allowed bandwidth is %ld bps (starting at %ld).",
	      rate_bps, rate_freebytes);
  }
  
  p = mod_privdata_find(cmd,"retr_filename",NULL);
  
  if(!p) {
    add_response_err(R_550, "%s: internal error, what happened to "
		     "cmd_pre_retr?!?", cmd->arg);
    return ERROR(cmd);
  }
  
  dir = p->value.str_val;
  retr_file = fs_open(dir,O_RDONLY,&retr_fd);

  if(session.restart_pos) {
    if(fs_lseek(retr_file,retr_fd,session.restart_pos,SEEK_SET) == -1) {
      int _errno = errno;
      fs_close(retr_file,retr_fd);
      errno = _errno;
      retr_file = NULL;
    }

    respos = session.restart_pos;
    session.restart_pos = 0L;
  }

  if(!retr_file || fs_stat(dir,&sbuf) == -1) {
    add_response_err(R_550,"%s: %s",cmd->arg,strerror(errno));
    return ERROR(cmd);
  } else {
    /* send the data */
    data_init(cmd->arg,IO_WRITE);
    
    session.xfer.path = pstrdup(session.xfer.p,dir);
    session.xfer.file_size = (unsigned long) sbuf.st_size;
    cnt_steps = session.xfer.file_size / 100;
    if(cnt_steps == 0)
      cnt_steps = 1;

    if(data_open(cmd->arg, NULL, IO_WRITE, sbuf.st_size - respos) < 0) {
      data_abort(0, TRUE);
      return ERROR(cmd);
    }
    
    bufsize = (main_server->tcp_swin > 0 ? main_server->tcp_swin : 1024);
    lbuf = (char *) palloc(cmd->tmp_pool, bufsize);

    cnt = respos;
    log_add_run(mpid, NULL, session.user,
		(session.class && session.class->name) ? session.class->name :
		"",
		NULL, 0, session.xfer.file_size, 0, NULL);

    gettimeofday(&rate_tvstart, NULL);
    
    while(cnt != session.xfer.file_size) {
      if(XFER_ABORTED)
        break;
      
      /* INSERT CODE HERE */
      if((len = _transmit_data(rate_bps, cnt, respos, lbuf, bufsize)) == 0)
	break;
      
      if(len < 0) {
        _retr_abort();
        data_abort(session.d->outf->xerrno,FALSE);
        return ERROR(cmd);
      }

      cnt += len;
      rate_bytes += len;
      
      if((cnt / cnt_steps) != cnt_next) {
	cnt_next = cnt / cnt_steps;
	log_add_run(mpid, NULL, session.user,
		    (session.class && session.class->name) ?
		    session.class->name : "",
		    NULL, 0, session.xfer.file_size, cnt, NULL);
      }
      
      if(rate_bps) {
	_rate_throttle(cnt, rate_bytes, rate_tvstart, rate_freebytes,
		       rate_bps, rate_hardbps);
      }
    }
    
    if(XFER_ABORTED) {
      _retr_abort();
      data_abort(0,0);
      return ERROR(cmd);
    } else if(len < 0) {
      _retr_abort();
      data_abort(errno,FALSE);
      return ERROR(cmd);
    } else {
      _retr_done();
      data_close(FALSE);
    }
  }
  
  return HANDLED(cmd);
}

MODRET cmd_abor(cmd_rec *cmd)
{
  if(cmd->argc != 1) {
    add_response_err(R_500,"'%s' not understood.",get_full_cmd(cmd));
    return ERROR(cmd);
  }

  if(session.flags & (SF_POST_ABORT|SF_ABORT)) {
    session.flags &= ~(SF_POST_ABORT|SF_ABORT);
    add_response(R_226,"Abort successful");
    return HANDLED(cmd);
  }

  add_response_err(R_500,"No command to abort.");
  return ERROR(cmd);
}

MODRET cmd_type(cmd_rec *cmd)
{
  if(cmd->argc < 2 || cmd->argc > 3) {
    add_response_err(R_500,"'%s' not understood.",get_full_cmd(cmd));
    return ERROR(cmd);
  }

  cmd->argv[1][0] = toupper(cmd->argv[1][0]);
  
  /* TYPE A(SCII) or TYPE L 7.
   */
  if(!strcmp(cmd->argv[1], "A") ||
     (cmd->argc == 3 &&
      !strcmp(cmd->argv[1], "L") && !strcmp(cmd->argv[2], "7"))) {
    session.flags |= SF_ASCII;
  } else if(!strcmp(cmd->argv[1], "I") ||
	    (cmd->argc == 3 &&
	     !strcmp(cmd->argv[1], "L") && !strcmp(cmd->argv[2], "8"))) {
    /* TYPE I(MAGE) or TYPE L 8.
     */
    session.flags &= (SF_ALL^SF_ASCII);
  } else {
    add_response_err(R_500, "'%s' not understood.", get_full_cmd(cmd));
    return ERROR(cmd);
  }

  add_response(R_200, "Type set to %s.", cmd->argv[1]);
  return HANDLED(cmd);
}


MODRET
cmd_stru(cmd_rec *cmd)
{
	if ( cmd->argc != 2 ) {
		add_response_err(R_501, "'%s' not understood.",
						get_full_cmd(cmd));
		return ERROR(cmd);
	}

	cmd->argv[1][0] = toupper(cmd->argv[1][0]);

	switch ( (int)cmd->argv[1][0] ) {
	case 'F':
		/* Should 202 be returned instead??? */
		add_response(R_200, "Structure set to F.");
		return HANDLED(cmd);
		break;
	case 'R':
		/*
		** Accept R but with no operational difference from F???
		** R is required in minimum implementations by RFC-959, 5.1.
		** RFC-1123, 4.1.2.13, amends this to only apply to servers
		** whose file systems support record structures, but also
		** suggests that such a server "may still accept files
		** with STRU R, recording the byte stream literally."
		** Another configurable choice, perhaps?
		** NB: wu-ftp does not so accept STRU R.
		*/
			/* FALLTHROUGH */
	case 'P':
		/* RFC-1123 recommends against implementing P. */
		add_response_err(R_504, "'%s' unsupported structure type.",
						get_full_cmd(cmd));
		return ERROR(cmd);
		break;
	default:
		add_response_err(R_501, "'%s' unrecognized structure type.",
						get_full_cmd(cmd));
		return ERROR(cmd);
		break;
	}
}


MODRET
cmd_mode(cmd_rec *cmd)
{
	if ( cmd->argc != 2 ) {
		add_response_err(R_501, "'%s' not understood.",
						get_full_cmd(cmd));
		return ERROR(cmd);
	}

	cmd->argv[1][0] = toupper(cmd->argv[1][0]);

	switch ( (int)cmd->argv[1][0] ) {
	case 'S':
		/* Should 202 be returned instead??? */
		add_response(R_200, "Mode set to S.");
		return HANDLED(cmd);
		break;
	case 'B':	/* FALLTHROUGH */
	case 'C':
		add_response_err(R_504, "'%s' unsupported transfer mode.",
						get_full_cmd(cmd));
		return ERROR(cmd);
		break;
	default:
		add_response_err(R_501, "'%s' unrecognized transfer mode.",
						get_full_cmd(cmd));
		return ERROR(cmd);
		break;
	}
}


MODRET
cmd_allo(cmd_rec *cmd)
{
	add_response(R_202, "No storage allocation necessary.");
	return HANDLED(cmd);
}


MODRET
cmd_smnt(cmd_rec *cmd)
{
	add_response(R_502, "SMNT command not implemented.");
	return HANDLED(cmd);
}


MODRET
cmd_stou(cmd_rec *cmd)
{
	add_response(R_502, "STOU command not implemented.");
	return HANDLED(cmd);
}

MODRET log_stor(cmd_rec *cmd)
{
  _log_transfer('i', 'c');
  data_cleanup();
  return DECLINED(cmd);
}

MODRET log_retr(cmd_rec *cmd)
{
  _log_transfer('o', 'c');
  data_cleanup();
  return DECLINED(cmd);
}

static int _noxfer_timeout(CALLBACK_FRAME)
{
  if(session.flags & SF_XFER)
    return TRUE;			/* Transfer in progress, ignore timeout */

  send_response_async(R_421,
           "No Transfer Timeout (%d seconds): closing control connection.",
           TimeoutNoXfer);

#if 0		/* no longer needed */
  schedule(main_exit, 0, (void*) LOG_NOTICE,
	   "FTP no transfer time out, disconnected.",
           (void*) 0, NULL);
#endif
  
  remove_timer(TIMER_IDLE,ANY_MODULE);
  remove_timer(TIMER_LOGIN,ANY_MODULE);

  main_exit((void*) LOG_NOTICE, "FTP no transfer timeout, disconnected.",
		  (void*) 0, NULL);
  return 0;
}

int xfer_init_child()
{
  /* Setup TimeoutNoXfer timer */
  if(TimeoutNoXfer)
    add_timer(TimeoutNoXfer,TIMER_NOXFER,&xfer_module,_noxfer_timeout);
  return 0;
}

MODRET add_ratenum(cmd_rec *cmd)
{
  config_rec *c;
  long ratenum;
  char *endp;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd, CONF_ROOT | CONF_VIRTUAL | CONF_ANON | CONF_DIR | CONF_GLOBAL);

  if(cmd->argc != 2 )
      CONF_ERROR(cmd,"invalid number of arguments");

  if(!strcasecmp(cmd->argv[1],"none"))
    ratenum = 0;
  else {
    ratenum = (int)strtol(cmd->argv[1],&endp,10);

    if((endp && *endp) || ratenum < 0)
      CONF_ERROR(cmd,"argument must be 'none' or a positive integer.");
  }

  log_debug(DEBUG5, "add_ratenum: %s %ld.", cmd->argv[0], ratenum);

  c = add_config_param( cmd->argv[0], 1, (void*)ratenum );
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET add_ratebool(cmd_rec *cmd)
{
  config_rec *c;
  int b;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd, CONF_ROOT | CONF_VIRTUAL | CONF_ANON | CONF_DIR | CONF_GLOBAL);

  if((b = get_boolean(cmd,1)) == -1)
    CONF_ERROR(cmd,"expected boolean argument.");

  log_debug(DEBUG5, "add_ratebool: %s %d.", cmd->argv[0], b);

  c = add_config_param( cmd->argv[0], 1, (void*)b );
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

conftable xfer_config[] = {
  { "RateReadBPS",		add_ratenum,                 },
  { "RateReadFreeBytes",	add_ratenum,	             },
  { "RateReadHardBPS",		add_ratebool,                },
  { "RateWriteBPS",		add_ratenum,                 },
  { "RateWriteFreeBytes",	add_ratenum,	             },
  { "RateWriteHardBPS",		add_ratebool,                },
  { NULL }
};

static cmdtable xfer_commands[] = {
  { CMD,     C_TYPE,	G_NONE,	 cmd_type,	TRUE,	FALSE, CL_MISC },
  { CMD,     C_STRU,	G_NONE,	 cmd_stru,	TRUE,	FALSE, CL_MISC },
  { CMD,     C_MODE,	G_NONE,	 cmd_mode,	TRUE,	FALSE, CL_MISC },
  { CMD,     C_ALLO,	G_NONE,	 cmd_allo,	TRUE,	FALSE, CL_MISC },
  { CMD,     C_SMNT,	G_NONE,	 cmd_smnt,	TRUE,	FALSE, CL_MISC },
  { PRE_CMD, C_RETR,	G_READ,	 pre_cmd_retr,	TRUE,	FALSE },
  { CMD,     C_RETR,	G_READ,	 cmd_retr,	TRUE,	FALSE, CL_READ },
  { LOG_CMD, C_RETR,	G_NONE,	 log_retr,	FALSE,  FALSE },
  { PRE_CMD, C_STOR,	G_WRITE, pre_cmd_stor,	TRUE,	FALSE },
  { CMD,     C_STOR,	G_WRITE, cmd_stor,	TRUE,	FALSE, CL_WRITE },
  { LOG_CMD, C_STOR,    G_NONE,	 log_stor,	FALSE,  FALSE },
  { CMD,     C_STOU,	G_WRITE, cmd_stou,	TRUE,	FALSE, CL_WRITE },
  { PRE_CMD, C_APPE,	G_WRITE, pre_cmd_appe,	TRUE,	FALSE },
  { CMD,     C_APPE,	G_WRITE, cmd_stor,	TRUE,	FALSE, CL_WRITE },
  { LOG_CMD, C_APPE,	G_NONE,  log_stor,	FALSE,  FALSE },
  { CMD,     C_ABOR,	G_NONE,	 cmd_abor,	TRUE,	TRUE,  CL_MISC  },
  { CMD,     C_REST,	G_NONE,	 cmd_rest,	TRUE,	FALSE, CL_MISC  },
  { 0,NULL }
};

module xfer_module = {
  NULL,NULL,				/* Always NULL */
  0x20,					/* API Version */
  "xfer",				/* Module name */
  xfer_config,
  xfer_commands,
  NULL,
  NULL,
  xfer_init_child
};
