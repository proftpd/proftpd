/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001, 2002 The ProFTPD Project team
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
 */

/*
 * Data transfer module for ProFTPD
 * $Id: mod_xfer.c,v 1.85 2002-09-25 02:13:52 jwm Exp $
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

void xfer_abort(pr_netio_stream_t *, int);

/* Variables for this module */
static fsdir_t *retr_file = NULL;
static fsdir_t *stor_file = NULL;
static int stor_fd;
static int retr_fd;

module xfer_module;

static int xfer_errno;

static unsigned long find_max_nbytes(char *directive) {
  config_rec *c = NULL;
  unsigned int ctxt_precedence = 0;
  unsigned char have_user_limit, have_group_limit, have_class_limit,
    have_all_limit;
  unsigned long max_nbytes = 0UL;

  have_user_limit = have_group_limit = have_class_limit =
    have_all_limit = FALSE; 

  c = find_config(CURRENT_CONF, CONF_PARAM, directive, FALSE);

  while (c) {
    if (c->argc == 3) {
      if (!strcmp(c->argv[1], "user")) {

        if (user_expression((char **) &c->argv[2])) {
          if (*((unsigned int *) c->argv[1]) > ctxt_precedence) {

            /* Set the context precedence */
            ctxt_precedence = *((unsigned int *) c->argv[1]);

            max_nbytes = *((unsigned long *) c->argv[0]);

            have_group_limit = have_class_limit = have_all_limit = FALSE;
            have_user_limit = TRUE;
          }
        }

      } else if (!strcmp(c->argv[1], "group")) {

        if (group_expression((char **) &c->argv[2])) {
          if (*((unsigned int *) c->argv[1]) > ctxt_precedence) {

            /* Set the context precedence */
            ctxt_precedence = *((unsigned int *) c->argv[1]);

            max_nbytes = *((unsigned long *) c->argv[0]);

            have_user_limit = have_class_limit = have_all_limit = FALSE;
            have_group_limit = TRUE;
          }
        }

      } else if (!strcmp(c->argv[1], "class")) {

        if (session.class && session.class->name &&
            !strcmp(session.class->name, c->argv[2])) {
          if (*((unsigned int *) c->argv[1]) > ctxt_precedence) {

            /* Set the context precedence */
            ctxt_precedence = *((unsigned int *) c->argv[1]);

            max_nbytes = *((unsigned long *) c->argv[0]);

            have_user_limit = have_group_limit = have_all_limit = FALSE;
            have_class_limit = TRUE;
          }
        }
      }

    } else {

      if (*((unsigned int *) c->argv[1]) > ctxt_precedence) {

        /* Set the context precedence. */
        ctxt_precedence = *((unsigned int *) c->argv[1]);

        max_nbytes = *((unsigned long *) c->argv[0]);

        have_user_limit = have_group_limit = have_class_limit = FALSE;
        have_all_limit = TRUE;
      }
    }

    c = find_config_next(c, c->next, CONF_PARAM, directive, FALSE);
  }

  /* Print out some nice debugging information. */
  if (max_nbytes > 0UL &&
      (have_user_limit || have_group_limit ||
       have_class_limit || have_all_limit)) {
    log_debug(DEBUG5, "%s (%lu bytes) in effect for %s",
      directive, max_nbytes,
      have_user_limit ? "user " : have_group_limit ? "group " :
      have_class_limit ? "class " : "all");
  }

  return max_nbytes;
}

static unsigned long parse_max_nbytes(char *nbytes_str, char *units_str) {
  long res;
  unsigned long nbytes;
  char *endp = NULL;
  float units_factor = 0.0;

  /* clear any previous local errors */
  xfer_errno = 0;

  /* first, check the given units to determine the correct mulitplier
   */
  if (!strcasecmp("Gb", units_str)) {
    units_factor = 1024.0 * 1024.0 * 1024.0;

  } else if (!strcasecmp("Mb", units_str)) {
    units_factor = 1024.0 * 1024.0;

  } else if (!strcasecmp("Kb", units_str)) {
    units_factor = 1024.0;

  } else if (!strcasecmp("b", units_str)) {
    units_factor = 1.0;

  } else {
    xfer_errno = EINVAL;
    return 0;
  }

  /* make sure a number was given */
  if (!isdigit(*nbytes_str)) {
    xfer_errno = EINVAL;
    return 0;
  }

  /* knowing the factor, now convert the given number string to a real
   * number
   */
  res = strtol(nbytes_str, &endp, 10);

  if (errno == ERANGE) {
    xfer_errno = ERANGE;
    return 0;
  }

  if (endp && *endp) {
    xfer_errno = EINVAL;
    return 0;
  }

  /* don't bother to apply the factor if that will cause the number to
   * overflow
   */
  if (res > (ULONG_MAX / units_factor)) {
    xfer_errno = ERANGE;
    return 0;
  }

  nbytes = (unsigned long) res * units_factor;
  return nbytes;
}

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

  log_debug(DEBUG1, "Transfer %s %" PR_LU " bytes in %ld.%02lu seconds.",
	    abort_flag == 'c' ? "completed:" : "aborted after",
	    session.xfer.total_bytes, (long) end_time.tv_sec,
	    (unsigned long)(end_time.tv_usec / 10000));
}

/* This routine counts the difference in usec between timeval's
 */
static float _rate_diffusec(struct timeval tlast, struct timeval t) {
    float diffsec, diffusec;

    diffsec  = t.tv_sec - tlast.tv_sec;
    diffusec = t.tv_usec- tlast.tv_usec;
    log_debug(DEBUG5,
	      "_rate_diffusec: last=%ld %ld  now=%ld %ld  diff=%f %f  res=%f.",
	      tlast.tv_sec, tlast.tv_usec, t.tv_sec, t.tv_usec,
	      diffsec, diffusec, (diffsec * 10e5 + diffusec));
    return(diffsec * 10e5 + diffusec);
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
static void _rate_throttle(off_t rate_pos, off_t rate_bytes,
			   struct timeval rate_tvlast,
			   long rate_freebytes, long rate_bps,
			   int rate_hardbps)
{
  /* rate_tv:        now (the diff of those gives the time spent)
   */
  struct timeval rate_tv;
  float dtime, wtime;

  log_debug(DEBUG5,
            "_rate_throttle: rate_bytes=%" PR_LU " rate_pos=%" PR_LU " "
            "rate_freebytes=%ld rate_bps=%ld rate_hardbps=%i.",
            rate_bytes, rate_pos, rate_freebytes, rate_bps, rate_hardbps);

  /* no rate control unless more than free bytes DL'ed */
  if(rate_pos < rate_freebytes)
    return;
  
  while (1) {
    gettimeofday(&rate_tv, NULL);
  
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

      /* Look for EINTR and restart the entire loop if necessary.
       * jss 2/20/01
       */
    
      if (select(0, NULL, NULL, NULL, &rate_tv) < 0) {
        if(errno != EINTR) {
          log_pri(LOG_WARNING, "Unable to throttle bandwidth: %s.",
	          strerror(errno));
        } else {
          pr_handle_signals();
          continue;
        }
      }
    }
    break;
  }
}

static int _transmit_normal(char *buf, long bufsize) {
  long count;
  
  if((count = fs_read(retr_file, retr_fd, buf, bufsize)) <= 0)
    return 0;
  
  return data_xfer(buf, count);
}

#ifdef HAVE_SENDFILE
static int _transmit_sendfile(int rate_bps, off_t count, off_t *offset,
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
  *retval = data_sendfile(retr_fd, offset, session.xfer.file_size - count);

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

static long _transmit_data(int rate_bps, off_t count, off_t offset,
			   char *buf, long bufsize) {
#ifdef HAVE_SENDFILE
  pr_sendfile_t retval;
  
  if(!_transmit_sendfile(rate_bps, count, &offset, &retval))
    return _transmit_normal(buf, bufsize);
  else
    return (long) retval;
#else
  return _transmit_normal(buf, bufsize);
#endif /* HAVE_SENDFILE */
}

static void _stor_chown(void) {
  struct stat sbuf;
  char *xfer_path = NULL;

  if (session.xfer.xfer_type == STOR_HIDDEN)
    xfer_path = session.xfer.path_hidden;
  else
    xfer_path = session.xfer.path;
 
  /* session.fsgid defaults to -1, so chown(2) won't chgrp unless specifically
   * requested via GroupOwner
   * jss - 07/04/2001
   */
  if ((session.fsuid != (uid_t) -1) && xfer_path) {
    int err = 0, iserr = 0;
    
    fs_stat(xfer_path, &sbuf);
    
    PRIVS_ROOT
    if (fs_chown(xfer_path, session.fsuid, session.fsgid) == -1) {
      iserr++;
      err = errno;
    }
    PRIVS_RELINQUISH

    if (iserr) {
      log_pri(LOG_WARNING, "chown(%s) as root failed: %s", xfer_path,
        strerror(err));
    
    } else {
      if (session.fsgid != (gid_t) -1)
        log_debug(DEBUG2, "root chown(%s) to uid %lu, gid %lu successful",
                  xfer_path,
                  (unsigned long)session.fsuid,
                  (unsigned long)session.fsgid);
      else
        log_debug(DEBUG2, "root chown(%s) to uid %lu successful",
                  xfer_path,
                  (unsigned long)session.fsuid);
      
      fs_chmod(xfer_path, sbuf.st_mode);
    }

  } else if ((session.fsgid != (gid_t) -1) && xfer_path) {
    fs_stat(xfer_path, &sbuf);

    if (fs_chown(xfer_path, (uid_t)-1, session.fsgid) == -1) {
      log_pri(LOG_WARNING, "chown(%s) failed: %s", xfer_path,
         strerror(errno));

    } else {
      log_debug(DEBUG2, "chown(%s) to gid %lu successful",
                xfer_path,
                (unsigned long)session.fsgid);
      fs_chmod(xfer_path, sbuf.st_mode);
    }
  }
}

static void _stor_done(void) {
  fs_close(stor_file, stor_fd);
  stor_file = NULL;
}

static void _retr_done(void) {
  fs_close(retr_file,retr_fd);
  retr_file = NULL;
}

static void _stor_abort(void) {
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

static void _retr_abort(void) {
  /* Isn't necessary to send anything here, just cleanup */
  fs_close(retr_file,retr_fd);
  retr_file = NULL;
  _log_transfer('o', 'i');
}

/* Exit handler, call abort functions if a transfer is in progress. */
static void _xfer_exit(void) {
  if (session.flags & SF_XFER) {

    if (session.xfer.direction == PR_NETIO_IO_RD)
       /* An upload is occurring... */
      _stor_abort();

    else
      /* A download is occurring... */
      _retr_abort();
  }
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

/* pre_cmd_stou is a PRE_CMD handler which changes the uploaded filename
 * to a unique one, after making the requisite security and authorization
 * checks.
 */
MODRET pre_cmd_stou(cmd_rec *cmd) {
  config_rec *c = NULL;
  privdata_t *priv = NULL;
  char *prefix = "ftp", *filename = NULL;
  int tmpfd;
  mode_t mode;

  /* Some FTP clients are "broken" in that they will send a filename
   * along with STOU.  Technically this violates RFC959, but for now, just
   * ignore that filename.  Stupid client implementors.
   */

  if (cmd->argc > 2) {
    add_response_err(R_500, "'%s' not understood.", get_full_cmd(cmd));
    return ERROR(cmd);
  }

  /* Watch for STOU preceded by REST, which makes no sense.
   *
   *   REST: session.restart_pos > 0
   */
  if (session.restart_pos) {
    add_response_err(R_550, "STOU incompatible with REST");
    return ERROR(cmd);
  }

  /* Generate the filename to be stored, depending on the configured
   * unique filename prefix.
   */
  if ((c = find_config(CURRENT_CONF, CONF_PARAM, "StoreUniquePrefix",
      FALSE)) != NULL)
    prefix = c->argv[0];

  /* Now, construct the unique filename using the cmd_rec's pool, the
   * prefix, and mkstemp().
   */
  filename = pstrcat(cmd->pool, prefix, "XXXXXX", NULL);

  if ((tmpfd = mkstemp(filename)) < 0) {
    log_pri(LOG_ERR, "error: unable to use mkstemp(): %s", strerror(errno));

    /* If we can't guarantee a unique filename, refuse the command. */
    add_response_err(R_450, "%s: unable to generate unique filename",
      cmd->argv[0]); 
    return ERROR(cmd);

  } else {
    cmd->arg = filename;

    /* Close the unique file.  This introduces a small race condition
     * between the time this function returns, and the STOU CMD handler
     * opens the unique file, but this may have to do, as closing that
     * race would involve some major restructuring.
     */
    close(tmpfd);
  }

  /* It's OK to reuse the char * pointer for filename.
   */
  filename = dir_best_path(cmd->tmp_pool, cmd->arg);

  if (!filename || !dir_check(cmd->tmp_pool, cmd->argv[0], cmd->group,
      filename, NULL)) {
    add_response_err(R_550, "%s: %s", cmd->arg, strerror(errno));
    return ERROR(cmd);
  }

  mode = file_mode(filename);

  if (mode &&
      session.xfer.xfer_type != STOR_APPEND &&
      get_param_int(CURRENT_CONF,"AllowOverwrite",FALSE) != 1) {
    add_response_err(R_550, "%s: Overwrite permission denied", cmd->arg);
    return ERROR(cmd);
  }

  /* Not likely to _not_ be a regular file, but just to be certain...
   */
  if (mode && !S_ISREG(mode)) {
    add_response_err(R_550, "%s: Not a regular file", cmd->arg);
    return ERROR(cmd);
  }

  /* Otherwise everthing is good */
  priv = mod_privdata_alloc(cmd, "stor_filename", strlen(filename) + 1);
  sstrncpy(priv->value.str_val, filename, strlen(filename) + 1);

  session.xfer.xfer_type = STOR_UNIQUE;
 
  return HANDLED(cmd);
}

/* post_cmd_stou is a POST_CMD handler that changes the mode of the
 * STOU file from 0600, which is what mkstemp() makes it, to 0666,
 * the default for files uploaded via STOR.  This is to prevent users
 * from being surprised.
 */
MODRET post_cmd_stou(cmd_rec *cmd) {

  /* This is the same mode as used in src/fs.c.  Should probably be
   * available as a macro.
   */
  mode_t mode = 0666;

  if (fs_chmod(cmd->arg, mode) < 0) {

    /* Not much to do but log the error. */
    log_pri(LOG_ERR, "error: unable to chmod '%s': %s", cmd->arg,
      strerror(errno));
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
  off_t nbytes_stored, nbytes_max_store = 0;
  unsigned char have_limit = FALSE;
  struct stat sbuf;
  off_t respos = 0;
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

  else if(session.xfer.xfer_type == STOR_APPEND) {
    stor_file = fs_open(dir, O_CREAT|O_WRONLY,&stor_fd);
    if (stor_file)
      if (fs_lseek(stor_file,stor_fd,0,SEEK_END) == -1) {
        fs_close(stor_file,stor_fd);
        stor_file = NULL;
      }
  }

  else /* Normal session */
    stor_file = fs_open(dir,
	O_WRONLY|(session.restart_pos ? 0 : O_TRUNC|O_CREAT),&stor_fd);

  if(stor_file && session.restart_pos) {
    int xerrno = 0;
    
    if(fs_lseek(stor_file,stor_fd,session.restart_pos,SEEK_SET) == -1) {
      xerrno = errno;
    } else if (fs_stat(dir, &sbuf) == -1) {
      xerrno = errno;
    }
    
    if (xerrno) {
      fs_close(stor_file,stor_fd);
      errno = xerrno;
      stor_file = NULL;
    }

    /* make sure that the requested offset is valid (within the size of the
     * file being resumed
     */
    if (stor_file && session.restart_pos > sbuf.st_size) {
      add_response_err(R_554, "%s: invalid REST argument", cmd->arg);
      fs_close(stor_file, stor_fd);
      return ERROR(cmd);
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
    data_init(cmd->arg, PR_NETIO_IO_RD);

    session.xfer.path = pstrdup(session.xfer.p, dir);
    if (session.xfer.xfer_type == STOR_HIDDEN)
      session.xfer.path_hidden = pstrdup(session.xfer.p,
        p_hidden->value.str_val);
    else
      session.xfer.path_hidden = NULL;
      
    session.xfer.file_size = respos;

    /* First, make sure the uploaded file has the requested ownership. */
    _stor_chown();

    if (data_open(cmd->arg, NULL, PR_NETIO_IO_RD, 0) < 0) {
      _stor_abort();
      data_abort(0,TRUE);
      return HANDLED(cmd);
    }

    /* initialize the number of bytes stored */
    nbytes_stored = 0;

    /* retrieve the number of bytes to store, maximum, if present.
     * This check is needed during the data_xfer() loop, below, because
     * the size of the file being uploaded isn't known in advance
     */
    if ((nbytes_max_store = find_max_nbytes("MaxStoreFileSize")) == 0UL)
      have_limit = FALSE;
    else
      have_limit = TRUE;

    /* check the MaxStoreFileSize, and abort now if zero
     */
    if (have_limit && nbytes_max_store == 0) {

      log_pri(LOG_INFO, "MaxStoreFileSize (%" PR_LU " byte%s) reached: "
        "aborting transfer of '%s'", nbytes_max_store,
        nbytes_max_store != 1 ? "s" : "", dir);

      /* abort the transfer
       */
      _stor_abort();

      /* set errno to EPERM ("Operation not permitted");
       */
      data_abort(EPERM, FALSE);
      return ERROR(cmd);
    }

    bufsize = (main_server->tcp_rwin > 0 ? 
	       main_server->tcp_rwin : TUNABLE_BUFFER_SIZE);
    lbuf = (char*) palloc(cmd->tmp_pool, bufsize);
    
    gettimeofday(&rate_tvstart, NULL);
    while ((len = data_xfer(lbuf, bufsize)) > 0) {
      if(XFER_ABORTED)
        break;

      nbytes_stored += len;

      /* double-check the current number of bytes stored against the
       * MaxStoreFileSize, if configured.
       */
      if (have_limit && nbytes_stored > nbytes_max_store) {

        log_pri(LOG_INFO, "MaxStoreFileSize (%" PR_LU " bytes) reached: "
          "aborting transfer of '%s'", nbytes_max_store, dir);

        /* unlink the file being written
         */
        fs_unlink(dir);

        /* abort the transfer
         */
        _stor_abort();

        /* set errno to EPERM ("Operation not permitted")
         */
        data_abort(EPERM, FALSE);
        return ERROR(cmd);
      }

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

    if (XFER_ABORTED) {
      _stor_abort();
      data_abort(0, 0);
      return ERROR(cmd);

    } else if (len < 0) {
      _stor_abort();
      data_abort(PR_NETIO_ERRNO(session.d->instrm), FALSE);
      return ERROR(cmd);

    } else {
      _stor_done();

      if (session.xfer.path && session.xfer.path_hidden) {

        if (fs_rename(session.xfer.path_hidden, session.xfer.path) != 0) {
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

  /* If we're using HiddenStor, then REST won't work. */
  if(get_param_int(CURRENT_CONF,"HiddenStor",FALSE) == 1) {
    add_response_err(R_501,"REST not compatible with server configuration.");
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

MODRET pre_cmd_retr(cmd_rec *cmd) {
  char *dir;
  mode_t fmode;
  privdata_t *p = NULL;

  if (cmd->argc < 2) {
    add_response_err(R_500,"'%s' not understood.",get_full_cmd(cmd));
    return ERROR(cmd);
  }

  dir = dir_realpath(cmd->tmp_pool,cmd->arg);

  if (!dir || !dir_check(cmd->tmp_pool,cmd->argv[0],cmd->group,dir,NULL)) {
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
  unsigned long nbytes_max_retrieve = -1;
  unsigned char have_limit = FALSE;
  privdata_t *p;
  long bufsize, len = 0;
  long rate_hardbps = 0;
  off_t respos = 0, cnt = 0, cnt_steps = 0, cnt_next = 0, rate_bytes = 0;
  long rate_freebytes = 0, rate_bps = 0;
  
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

  if ((retr_file = fs_open(dir, O_RDONLY, &retr_fd)) == NULL) {
    /* Error opening the file. */
    add_response_err(R_550, "%s: %s", cmd->arg, strerror(errno));
    return ERROR(cmd);
  }

  if (fs_stat(dir, &sbuf) < 0) {
    /* Error stat'ing the file. */
    add_response_err(R_550, "%s: %s", cmd->arg, strerror(errno));
    return ERROR(cmd);
  }

  if (session.restart_pos) {

    /* Make sure that the requested offset is valid (within the size of the
     * file being resumed.
     */
    if (session.restart_pos > sbuf.st_size) {
      add_response_err(R_554, "%s: invalid REST argument", cmd->arg);
      fs_close(stor_file, stor_fd);
      return ERROR(cmd);
    }

    if (fs_lseek(retr_file, retr_fd, session.restart_pos,
        SEEK_SET) == (off_t) -1) {
      int _errno = errno;
      fs_close(retr_file,retr_fd);
      errno = _errno;
      retr_file = NULL;
    }

    respos = session.restart_pos;
    session.restart_pos = 0L;
  }

  /* Send the data */
  data_init(cmd->arg, PR_NETIO_IO_WR);
    
  session.xfer.path = pstrdup(session.xfer.p,dir);
  session.xfer.file_size = sbuf.st_size;
  cnt_steps = session.xfer.file_size / 100;
  if(cnt_steps == 0)
    cnt_steps = 1;

  if(data_open(cmd->arg, NULL, PR_NETIO_IO_WR, sbuf.st_size - respos) < 0) {
    data_abort(0, TRUE);
    return ERROR(cmd);
  }
    
  /* Retrieve the number of bytes to retrieve, maximum, if present */
  if ((nbytes_max_retrieve = find_max_nbytes("MaxRetrieveFileSize")) == 0UL)
    have_limit = FALSE;
  else
    have_limit = TRUE;

  /* Check the MaxRetrieveFileSize.  If it is zero, or if the size
   * of the file being retrieved is greater than the MaxRetrieveFileSize,
   * then signal an error and abort the transfer now.
   */
  if (have_limit &&
      ((nbytes_max_retrieve == 0) || (sbuf.st_size > nbytes_max_retrieve))) {

    log_pri(LOG_INFO, "MaxRetrieveFileSize (%lu byte%s) reached: "
      "aborting transfer of '%s'", nbytes_max_retrieve,
      nbytes_max_retrieve != 1 ? "s" : "", dir);

    /* Abort the transfer. */
    _retr_abort();

    /* Set errno to EPERM ("Operation not permitted") */
    data_abort(EPERM, FALSE);
    return ERROR(cmd);
  }
 
  bufsize = (main_server->tcp_swin > 0 ?
             main_server->tcp_swin : TUNABLE_BUFFER_SIZE);
  lbuf = (char *) palloc(cmd->tmp_pool, bufsize);

  cnt = respos;
  log_add_run(mpid, NULL, session.user,
    (session.class && session.class->name) ? session.class->name : "",
    NULL, 0, session.xfer.file_size, 0, NULL);

  gettimeofday(&rate_tvstart, NULL);
    
  while (cnt != session.xfer.file_size) {
    if (XFER_ABORTED)
      break;
      
    /* INSERT CODE HERE */
    if ((len = _transmit_data(rate_bps, cnt, respos, lbuf, bufsize)) == 0)
      break;
      
    if (len < 0) {
      _retr_abort();
      data_abort(PR_NETIO_ERRNO(session.d->outstrm), FALSE);
      return ERROR(cmd);
    }

    cnt += len;
    rate_bytes += len;
      
    if ((cnt / cnt_steps) != cnt_next) {
      cnt_next = cnt / cnt_steps;
      log_add_run(mpid, NULL, session.user,
        (session.class && session.class->name) ?  session.class->name : "",
        NULL, 0, session.xfer.file_size, cnt, NULL);
    }
      
    if (rate_bps) {
      _rate_throttle(cnt, rate_bytes, rate_tvstart, rate_freebytes,
        rate_bps, rate_hardbps);
    }
  }
    
  if (XFER_ABORTED) {
    _retr_abort();
    data_abort(0, 0);
    return ERROR(cmd);

  } else if (len < 0) {
    _retr_abort();
    data_abort(errno, FALSE);
    return ERROR(cmd);

  } else {
    _retr_done();
    data_close(FALSE);
  }
  
  return HANDLED(cmd);
}

MODRET cmd_abor(cmd_rec *cmd)
{
  if(cmd->argc != 1) {
    add_response_err(R_500,"'%s' not understood.",get_full_cmd(cmd));
    return ERROR(cmd);
  }

  add_response(R_226,"Abort successful");
  data_abort(0,FALSE);
  data_reset();
  data_cleanup();
  
  return HANDLED(cmd);
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


MODRET xfer_err_cleanup(cmd_rec *cmd) {
  if (session.xfer.p)
    destroy_pool(session.xfer.p);

  memset(&session.xfer, '\0', sizeof(session.xfer));
  return DECLINED(cmd);
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

static int noxfer_timeout_cb(CALLBACK_FRAME) {
  if (session.flags & SF_XFER)
    /* Transfer in progress, ignore this timeout */
    return 1;

  send_response_async(R_421, "No Transfer Timeout (%d seconds): closing "
    "control connection.", TimeoutNoXfer);

  remove_timer(TIMER_IDLE, ANY_MODULE);
  remove_timer(TIMER_LOGIN, ANY_MODULE);

  main_exit((void*) LOG_NOTICE, "FTP no transfer timeout, disconnected.",
		  (void*) 0, NULL);
  return 0;
}

static int xfer_sess_init(void) {
  config_rec *c = NULL;

  /* Check for a server-specific TimeoutNoTransfer */
  if ((c = find_config(main_server->conf, CONF_PARAM, "TimeoutNoTransfer",
      FALSE)) != NULL) {

    /* NOTE: this isn't pretty, casting a void * to an int.  It'll need
     * to be cleaned up soon.
     */
    TimeoutNoXfer = (int) c->argv[0];
  }

  /* Setup TimeoutNoXfer timer */
  if (TimeoutNoXfer)
    add_timer(TimeoutNoXfer, TIMER_NOXFER, &xfer_module, noxfer_timeout_cb);

  /* Check for a server-specific TimeoutStalled */
  if ((c = find_config(main_server->conf, CONF_PARAM, "TimeoutStalled",
      FALSE)) != NULL) {

    /* NOTE: this isn't pretty, casting a void * to an int.  It'll need
     * to be cleaned up soon.
     */
    TimeoutStalled = (int) c->argv[0];
  }

  /* Note: timers for handling TimeoutStalled timeouts are handled in the
   * data transfer routines, not here.
   */

  /* Exit handler for HiddenStor cleanup */
  add_exit_handler(_xfer_exit);

  return 0;
}

/* Configuration handlers
 */

MODRET set_deleteabortedstores(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|
    CONF_DIR|CONF_DYNDIR);

  if ((bool = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "expected boolean parameter");

  c = add_config_param(cmd->argv[0], 1, (void *) bool);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_hiddenstores(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|CONF_DIR);

  if ((bool = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, (void *) bool);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_maxfilesize(cmd_rec *cmd) {
  config_rec *c = NULL;
  unsigned long nbytes;
  unsigned int precedence = 0;

  int ctxt = (cmd->config && cmd->config->config_type != CONF_PARAM ?
     cmd->config->config_type : cmd->server->config_type ?
     cmd->server->config_type : CONF_ROOT);

  if (cmd->argc-1 != 2 && cmd->argc-1 != 4)
    CONF_ERROR(cmd, "incorrect number of parameters");

  CHECK_CONF(cmd, CONF_ROOT|CONF_ANON|CONF_VIRTUAL|CONF_GLOBAL|CONF_DIR|
    CONF_DYNDIR);

  /* Set the precedence for this config_rec based on its configuration
   * context.
   */
  if (ctxt & CONF_GLOBAL)
    precedence = 1;

  /* These will never appear simultaneously */
  else if (ctxt & CONF_ROOT || ctxt & CONF_VIRTUAL)
    precedence = 2;

  else if (ctxt & CONF_ANON)
    precedence = 3;

  else if (ctxt & CONF_DIR)
    precedence = 4;

  /* If the directive was used with four arguments, it means the optional
   * classifiers and expression were used.  Make sure the classifier is a valid
   * one.
   */
  if (cmd->argc-1 == 4) {
    if (!strcmp(cmd->argv[3], "user") ||
        !strcmp(cmd->argv[3], "group") ||
        !strcmp(cmd->argv[3], "class")) {

       /* no-op */

     } else
       CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown classifier used: '",
         cmd->argv[3], "'", NULL));
  }

  if (!strcmp(cmd->argv[1], "*")) {

    /* Do nothing here -- the "*" signifies an unlimited size, which is
     * what the server provides by default.
     */
    nbytes = 0UL;

  } else {

    /* Pass the cmd_rec off to see what number of bytes was
     * requested/configured.
     */
    if ((nbytes = parse_max_nbytes(cmd->argv[1], cmd->argv[2])) == 0) {
      char ulong_max[80] = {'\0'};
      sprintf(ulong_max, "%lu", ULONG_MAX);

      if (xfer_errno == EINVAL)
        CONF_ERROR(cmd, "invalid parameters");

      if (xfer_errno == ERANGE)
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
         "number of bytes must be between 0 and ", ulong_max, NULL));
    }
  }

  if (cmd->argc-1 == 2) {
    c = add_config_param(cmd->argv[0], 2, NULL, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(unsigned long));
    *((unsigned long *) c->argv[0]) = nbytes;
    c->argv[1] = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) c->argv[1]) = precedence;
 
  } else {
    array_header *acl = NULL;
    int argc = cmd->argc - 4;
    char **argv = cmd->argv + 3;

    acl = parse_group_expression(cmd->tmp_pool, &argc, argv);

    c = add_config_param(cmd->argv[0], 0);
    c->argc = argc + 3;
    c->argv = pcalloc(c->pool, ((argc + 4) * sizeof(char *)));

    argv = (char **) c->argv;

    /* Copy in the configured bytes */
    *argv = pcalloc(c->pool, sizeof(unsigned long));
    *((unsigned long *) *argv++) = nbytes;

    /* Copy in the precedence */
    *argv = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) *argv++) = precedence;

    /* Copy in the classifier. */ 
    *argv++ = pstrdup(c->pool, cmd->argv[3]);

    if (argc && acl) {
      while (argc--) {
        *argv++ = pstrdup(c->pool, *((char **) acl->elts));
        acl->elts = ((char **) acl->elts) + 1;
      }
    }

    /* Don't forget the terminating NULL */
    *argv = NULL;
  }

  c->flags |= CF_MERGEDOWN_MULTI;

  return HANDLED(cmd);
}

MODRET add_ratenum(cmd_rec *cmd) {
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

MODRET add_ratebool(cmd_rec *cmd) {
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

MODRET set_storeuniqueprefix(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|
    CONF_DIR|CONF_DYNDIR);

  /* make sure there are no slashes in the prefix */
  if (strchr(cmd->argv[1], '/') != NULL)
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "no slashes allowed in prefix: '",
      cmd->argv[1], "'", NULL));

  c = add_config_param_str(cmd->argv[0], 1, (void *) cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

MODRET set_timeoutnoxfer(cmd_rec *cmd) {
  int timeout = -1;
  char *endp = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  timeout = (int) strtol(cmd->argv[1], &endp, 10);

  if ((endp && *endp) || timeout < 0 || timeout > 65535)
    CONF_ERROR(cmd, "timeout values must be between 0 and 65535");

  TimeoutNoXfer = timeout;
  return HANDLED(cmd);
}

MODRET set_timeoutstalled(cmd_rec *cmd) {
  int timeout = -1;
  char *endp = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  timeout = (int) strtol(cmd->argv[1], &endp, 10);

  if ((endp && *endp) || timeout < 0 || timeout > 65535)
    CONF_ERROR(cmd, "timeout values must be between 0 and 65535");

  TimeoutStalled = timeout;
  return HANDLED(cmd);
}

/* Module API tables
 */

static conftable xfer_conftab[] = {
  { "DeleteAbortedStores",	set_deleteabortedstores,	},
  { "HiddenStor",		set_hiddenstores,		},
  { "HiddenStores",		set_hiddenstores,		},
  { "MaxRetrieveFileSize",	set_maxfilesize,		},
  { "MaxStoreFileSize",		set_maxfilesize,		},
  { "RateReadBPS",		add_ratenum,                 },
  { "RateReadFreeBytes",	add_ratenum,	             },
  { "RateReadHardBPS",		add_ratebool,                },
  { "RateWriteBPS",		add_ratenum,                 },
  { "RateWriteFreeBytes",	add_ratenum,	             },
  { "RateWriteHardBPS",		add_ratebool,                },
  { "StoreUniquePrefix",	set_storeuniqueprefix,		},
  { "TimeoutNoTransfer",	set_timeoutnoxfer,		},
  { "TimeoutStalled",		set_timeoutstalled,		},
  { NULL }
};

static cmdtable xfer_cmdtab[] = {
  { CMD,     C_TYPE,	G_NONE,	 cmd_type,	TRUE,	FALSE, CL_MISC },
  { CMD,     C_STRU,	G_NONE,	 cmd_stru,	TRUE,	FALSE, CL_MISC },
  { CMD,     C_MODE,	G_NONE,	 cmd_mode,	TRUE,	FALSE, CL_MISC },
  { CMD,     C_ALLO,	G_NONE,	 cmd_allo,	TRUE,	FALSE, CL_MISC },
  { CMD,     C_SMNT,	G_NONE,	 cmd_smnt,	TRUE,	FALSE, CL_MISC },
  { PRE_CMD, C_RETR,	G_READ,	 pre_cmd_retr,	TRUE,	FALSE },
  { CMD,     C_RETR,	G_READ,	 cmd_retr,	TRUE,	FALSE, CL_READ },
  { LOG_CMD, C_RETR,	G_NONE,	 log_retr,	FALSE,  FALSE },
  { LOG_CMD_ERR, C_RETR,G_NONE,  xfer_err_cleanup,  FALSE,  FALSE },
  { PRE_CMD, C_STOR,	G_WRITE, pre_cmd_stor,	TRUE,	FALSE },
  { CMD,     C_STOR,	G_WRITE, cmd_stor,	TRUE,	FALSE, CL_WRITE },
  { LOG_CMD, C_STOR,    G_NONE,	 log_stor,	FALSE,  FALSE },
  { LOG_CMD_ERR, C_STOR,G_NONE,  xfer_err_cleanup,  FALSE,  FALSE },
  { PRE_CMD, C_STOU,	G_WRITE, pre_cmd_stou,	TRUE,	FALSE },
  { CMD,     C_STOU,	G_WRITE, cmd_stor,	TRUE,	FALSE, CL_WRITE },
  { POST_CMD,C_STOU,	G_WRITE, post_cmd_stou,	FALSE,	FALSE },
  { LOG_CMD, C_STOU,	G_NONE,  log_stor,	FALSE,	FALSE },
  { LOG_CMD_ERR, C_STOU,G_NONE,  xfer_err_cleanup,  FALSE,  FALSE },
  { PRE_CMD, C_APPE,	G_WRITE, pre_cmd_appe,	TRUE,	FALSE },
  { CMD,     C_APPE,	G_WRITE, cmd_stor,	TRUE,	FALSE, CL_WRITE },
  { LOG_CMD, C_APPE,	G_NONE,  log_stor,	FALSE,  FALSE },
  { LOG_CMD_ERR, C_APPE,G_NONE,  xfer_err_cleanup,  FALSE,  FALSE },
  { CMD,     C_ABOR,	G_NONE,	 cmd_abor,	TRUE,	TRUE,  CL_MISC  },
  { CMD,     C_REST,	G_NONE,	 cmd_rest,	TRUE,	FALSE, CL_MISC  },
  { 0,NULL }
};

module xfer_module = {
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "xfer",

  /* Module configuration directive table */
  xfer_conftab,

  /* Module command handler table */
  xfer_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  NULL,

  /* Session initialization function */
  xfer_sess_init
};
