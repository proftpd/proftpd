/*
 * Copyright (c) 1983, 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "conf.h"

static int sock_type = SOCK_DGRAM;
static int log_opts = 0;
static const char *log_ident = NULL;
static int log_facility = LOG_USER;
static int log_mask = 0xff;

extern char *__progname;		/* Program name, from crt0. */

static void pr_vsyslog(int sockfd, int pri, register const char *fmt,
    va_list ap) {
  time_t now;
  static char logbuf[TUNABLE_BUFFER_SIZE] = {'\0'};
  size_t buflen = 0;
  int saved_errno = errno;

  /* clear the buffer */
  memset(logbuf, '\0', sizeof(logbuf));

  /* Check for invalid bits. */
  if (pri & ~(LOG_PRIMASK|LOG_FACMASK))
    pri &= LOG_PRIMASK|LOG_FACMASK;

  /* Check priority against setlogmask values. */
  if ((LOG_MASK(LOG_PRI(pri)) & log_mask) == 0)
    return;

  /* Set default facility if none specified. */
  if ((pri & LOG_FACMASK) == 0)
    pri |= log_facility;

  snprintf(logbuf, sizeof(logbuf), "<%d>", pri);
  logbuf[sizeof(logbuf)-1] = '\0';
  buflen = strlen(logbuf);

  time(&now);
 
  if (log_ident == NULL)
    log_ident = __progname;

  if (buflen < sizeof(logbuf) && log_ident != NULL) {
    snprintf(&(logbuf[buflen]), sizeof(logbuf) - buflen, "%s", log_ident);
    logbuf[sizeof(logbuf)-1] = '\0';
    buflen = strlen(logbuf);
  }

  if (buflen < sizeof(logbuf)-1 && (log_opts & LOG_PID)) {
    snprintf(&(logbuf[buflen]), sizeof(logbuf) - buflen, "[%d]", getpid());
    logbuf[sizeof(logbuf)-1] = '\0';
    buflen = strlen(logbuf);
  }

  if (buflen < sizeof(logbuf)-1 && log_ident != NULL) {
    snprintf(&(logbuf[buflen]), sizeof(logbuf) - buflen, ": ");
    logbuf[sizeof(logbuf)-1] = '\0';
    buflen = strlen(logbuf);
  }

  /* Restore errno for %m format.  */
  errno = saved_errno;

  /* We have the header.  Print the user's format into the buffer.  */
  if (buflen < sizeof(logbuf)) {
    vsnprintf(&(logbuf[buflen]), sizeof(logbuf) - buflen, fmt, ap);
    logbuf[sizeof(logbuf)-1] = '\0';
    buflen = strlen(logbuf);
  }

  /* Always make sure the buffer is NUL-terminated
   */
  logbuf[sizeof(logbuf)-1] = '\0';

  /* If we have a SOCK_STREAM connection, also send ASCII NUL as a record
   * terminator.
   */
  if (sock_type == SOCK_STREAM)
    ++buflen;

  send(sockfd, logbuf, buflen, 0);
}

void pr_syslog(int sockfd, int pri, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  pr_vsyslog(sockfd, pri, fmt, ap);
  va_end(ap);
}

/* AF_UNIX address of local logger */
static struct sockaddr syslog_addr;

int pr_openlog(const char *ident, int opts, int facility) {
  int sockfd = -1;

  if (ident != NULL)
    log_ident = ident;

  log_opts = opts;

  if (facility != 0 && (facility &~ LOG_FACMASK) == 0)
    log_facility = facility;

  while (1) {
    if (sockfd == -1) {
      syslog_addr.sa_family = AF_UNIX;
      strncpy(syslog_addr.sa_data, PR_PATH_LOG, sizeof(syslog_addr.sa_data));
      syslog_addr.sa_data[sizeof(syslog_addr.sa_data)-1] = '\0';

      if (log_opts & LOG_NDELAY) {
        if ((sockfd = socket(AF_UNIX, sock_type, 0)) == -1)
          return -1;
        fcntl(sockfd, F_SETFD, 1);
      }
    }

    if (sockfd != -1) {
      int old_errno = errno;

      if (connect(sockfd, &syslog_addr, sizeof(syslog_addr)) == -1) {
        int saved_errno = errno;
        close(sockfd);
        sockfd = -1;

        if (sock_type == SOCK_DGRAM && saved_errno == EPROTOTYPE) {
          /* retry with next SOCK_STREAM */
          sock_type = SOCK_STREAM;
          errno = old_errno;
          continue;
        }
      }
    }
    break;
  }

  return sockfd;
}

void pr_closelog(int sockfd) {
  close(sockfd);
  sockfd = -1;

  /* Clear the identity prefix string. */
  log_ident = NULL;

  /* default */
  sock_type = SOCK_DGRAM;
}

/* setlogmask -- set the log mask level */
int pr_setlogmask(int new_mask) {
  int old_mask;

  old_mask = log_mask;
  if (new_mask != 0)
    log_mask = new_mask;

  return old_mask;
}
