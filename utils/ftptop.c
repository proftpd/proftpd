/*
 * ProFTPD - ftptop: a utility for monitoring proftpd sessions
 * Copyright (C) 2000-2002 TJ Saunders <tj@castaglia.org>
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
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 */

/* Shows who is online via proftpd, in a manner similar to top.  Uses the
 * scoreboard files.
 *
 * $Id: ftptop.c,v 1.10 2002-11-15 16:11:39 castaglia Exp $
 */

#define FTPTOP_VERSION "ftptop/0.8.2"

#include <ctype.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>

#include "utils.h"

static const char *program = "ftptop";

#if defined(HAVE_NCURSES_H) && defined(HAVE_LIBNCURSES)
#define HAVE_NCURSES 1
#include <ncurses.h>
#endif /* HAVE_NCURSES_H */

/* We don't want to include both ncurses.h and curses.h. */
#if defined(HAVE_CURSES_H) && defined(HAVE_LIBCURSES) && !defined(HAVE_NCURSES_H)
#define HAVE_CURSES 1

/* Sigh...portability.  It seems that Solaris' curses.h (at least for 2.8)
 * steps on wide-character macros, generating compiler warnings.  This, then
 * is just a hack to silence the compiler.
 */
# ifdef SOLARIS2
#  define __lint
# endif
# include <curses.h>
#endif /* HAVE_CURSES_H */

#if defined(HAVE_NCURSES) || defined(HAVE_CURSES)

/* Display options */
#define FTPTOP_DISPLAY_FORMAT \
  "%-5d %s %-.10s %-.7s %s 0 %-.20s\n"

#define FTPTOP_SHOW_DOWNLOAD		0x0001
#define FTPTOP_SHOW_UPLOAD		0x0002
#define FTPTOP_SHOW_IDLE		0x0004
#define	FTPTOP_SHOW_ALL \
  (FTPTOP_SHOW_DOWNLOAD|FTPTOP_SHOW_UPLOAD|FTPTOP_SHOW_IDLE)

static int delay = 2;
static unsigned int display_session = FTPTOP_SHOW_ALL;

static char *config_filename = CONFIG_FILE_PATH;

/* Scoreboard variables */
static unsigned int ftp_nsessions = 0;
static unsigned int ftp_nuploads = 0;
static unsigned int ftp_ndownloads = 0;
static unsigned int ftp_nidles = 0;
static char **ftp_sessions = NULL;
static unsigned int chunklen = 3;

/* necessary prototypes */
static void scoreboard_close(void);
static int scoreboard_open(void);

static void show_version(void);
static void usage(void);

static void clear_counters(void) {

  if (ftp_sessions && ftp_nsessions) {
    register unsigned int i = 0;

    for (i = 0; i < ftp_nsessions; i++)
      free(ftp_sessions[i]);
    free(ftp_sessions);
    ftp_sessions = NULL;
  }

  /* Reset the session counters. */
  ftp_nsessions = 0;
  ftp_nuploads = 0;
  ftp_ndownloads = 0;
  ftp_nidles = 0;
}

static void finish(int signo) {
  endwin();
  exit(0);
}

static int check_scoreboard_file(void) {
  struct stat sbuf;

  if (stat(util_get_scoreboard(), &sbuf) < 0)
    return -1;

  return 0;
}

/* scan_config_file() is a kludge for 1.2 which does a very simplistic attempt
 * at determining what the "ScoreboardFile" directive is set to.  It will be
 * replaced in 1.3 with the abstracted configure system (hopefully).
 */
static void scan_config_file(void) {
  FILE *fp = NULL;
  char buf[1024] = {'\0'};
  char *cp, *file = NULL;
 
  if (!config_filename || (fp = fopen(config_filename,"r")) == NULL)
    return;

  while (!file && fgets(buf, sizeof(buf) - 1, fp)) {
    int i = strlen(buf);

    if (i && buf[i - 1] == '\n')
      buf[i-1] = '\0';

    for (cp = buf; *cp && isspace((int) *cp); cp++);

    if (*cp == '#' || !*cp)
      continue;

    i = strlen("ScoreboardFile");

    if (strncasecmp(cp, "ScoreboardFile", i) != 0)
      continue;

    /* Found it! */
    cp += i;

    /* strip whitespace */
    while (*cp && isspace((int) *cp))
      cp++;

    file = cp;

    /* If the scoreboard file argument is quoted, dequote */
    if (*cp == '"') {
      char *src = cp;

      cp++;
      file++;

      while (*++src) {
        switch (*src) {
          case '\\':
            if (*++src)
              *cp++ = *src;
            break;

          case '"':
            src++;
            break;

          default:
            *cp++ = *src;
        }
      }

      *cp = '\0';
    }
  }

  fclose(fp);

  /* If we got something out of all this, go ahead and set it. */
  if (file)
    util_set_scoreboard(file);
}
static void process_opts(int argc, char *argv[]) {
  int optc = 0;
  const char *prgopts = "Dd:f:hIiUV";

  while ((optc = getopt(argc, argv, prgopts)) != -1) {
    switch (optc) {
      case 'D':
        display_session = 0U;
        display_session |= FTPTOP_SHOW_DOWNLOAD;
        break;

      case 'd':
        delay = atoi(optarg);

        if (delay < 0) {
          fprintf(stderr, "%s: negative delay illegal: %d\n", program,
            delay);
          exit(1);
        }

        break;

      case 'f':
        util_set_scoreboard(optarg);
        break;

      case 'h':
        usage();
        break;

      case 'I':
        display_session = 0U;
        display_session |= FTPTOP_SHOW_IDLE;
        break;

      case 'i':
        display_session &= ~FTPTOP_SHOW_IDLE;
        break;

      case 'U':
        display_session = 0U;
        display_session |= FTPTOP_SHOW_UPLOAD;
        break;

      case 'V':
        show_version();
        break;

      case '?':
        break;

     default:
        break;
    }
  }

  /* First attempt to check the supplied/default scoreboard path.  If this is
   * incorrect, try the config file kludge.
   */
  if (check_scoreboard_file() < 0) {
    scan_config_file();
   
    if (check_scoreboard_file() < 0) {
      fprintf(stderr, "%s: %s\n", util_get_scoreboard(), strerror(errno));
      fprintf(stderr, "(Perhaps you need to specify the ScoreboardFile with -f, or change\n");
      fprintf(stderr," the compile-time default directory?)\n");
      exit(1);
    }
  }
}

static void read_scoreboard(void) {
  static char buf[1024] = {'\0'};
  pr_scoreboard_entry_t *score = NULL;

  if ((ftp_sessions = calloc(chunklen, sizeof(char *))) == NULL)
    exit(1);

  if (scoreboard_open() < 0)
    return;

  /* Iterate through the scoreboard. */
  while ((score = util_scoreboard_read_entry()) != NULL) {

    /* Default status: "A" for "authenticating" */
    char *status = "A";

    /* Clear the buffer for this run. */
    memset(buf, '\0', sizeof(buf));

    /* Determine the status symbol to display. */
    if (strstr(score->sce_cmd, "(idle)")) {
      status = "I";
      ftp_nidles++;

      if (!(display_session & FTPTOP_SHOW_IDLE))
        continue;

    } else if (strstr(score->sce_cmd, "RETR")) {
      status = "D";
      ftp_ndownloads++;

      if (!(display_session & FTPTOP_SHOW_DOWNLOAD))
        continue;

    } else if (strstr(score->sce_cmd, "STOR") ||
        strstr(score->sce_cmd, "APPE") ||
        strstr(score->sce_cmd, "STOU")) {
      status = "U";
      ftp_nuploads++;

      if (!(display_session & FTPTOP_SHOW_UPLOAD))
        continue;

    } else if (strstr(score->sce_cmd, "LIST") ||
        strstr(score->sce_cmd, "NLST"))
      status = "L";

    snprintf(buf, sizeof(buf), FTPTOP_DISPLAY_FORMAT, 
      score->sce_pid, status, score->sce_user, score->sce_client_addr,
      score->sce_server_addr, score->sce_cmd);
    buf[sizeof(buf)-1] = '\0';

    /* Make sure there is enough memory allocated in the session list.
     * Allocate more if needed.
     */
    if (ftp_nsessions && ftp_nsessions % chunklen == 0) {
      if ((ftp_sessions = realloc(ftp_sessions,
          (ftp_nsessions + chunklen) * sizeof(char *))) == NULL)
        exit(1);
    }

    if ((ftp_sessions[ftp_nsessions] = calloc(1, strlen(buf) + 1)) == NULL)
      exit(1);
    strncpy(ftp_sessions[ftp_nsessions++], buf, strlen(buf) + 1);

    /* NOTE: that, right now, updates of the proftpd scoreboard only
     *  happen for downloads, not for uploads.  Odd.
     */
  }

  scoreboard_close();
}

static void scoreboard_close(void) {
  util_close_scoreboard();
}

static int scoreboard_open(void) {
  int res = 0;

  if ((res = util_open_scoreboard(O_RDONLY, NULL)) < 0) {
    switch (res) {
      case -1:
        fprintf(stderr, "%s: unable to open scoreboard: %s\n", program,
          strerror(errno));
        return res;

      case UTIL_SCORE_ERR_BAD_MAGIC:
        fprintf(stderr, "%s: scoreboard is corrupted or old\n", program);
        return res;

      case UTIL_SCORE_ERR_OLDER_VERSION:
        fprintf(stderr, "%s: scoreboard is too old\n", program);
        return res;

      case UTIL_SCORE_ERR_NEWER_VERSION:
        fprintf(stderr, "%s: scoreboard is too new\n", program);
        return res;
    }
  }

  return 0;
}

static void show_sessions(void) {
  time_t now;

  clear_counters();
  read_scoreboard();

  time(&now);
  wclear(stdscr);
  move(0, 0);

  attron(A_BOLD);
  printw(FTPTOP_VERSION ": %s", ctime(&now));
  printw("%u Total FTP Sessions: %u downloading, %u uploading, %u idle\n",
    ftp_nsessions, ftp_ndownloads, ftp_nuploads, ftp_nidles);
  attroff(A_BOLD);

  printw("\n");

  attron(A_REVERSE);
  printw("PID   S USER     ADDR        SRVR    TIME COMMAND");
  attroff(A_REVERSE);
  printw("\n");

  /* Write out the scoreboard entries. */
  if (ftp_sessions && ftp_nsessions) {
    register unsigned int i = 0;

    for (i = 0; i < ftp_nsessions; i++)
      printw("%s", ftp_sessions[i]);
  }

  wrefresh(stdscr);
}

static void show_version(void) {
  fprintf(stdout, FTPTOP_VERSION "\n");
  exit(0);
}

static void usage(void) {
  fprintf(stdout, "usage: ftptop [options]\n");
  fprintf(stdout, "\t-D      \t\tshow only downloading sessions\n");
  fprintf(stdout, "\t-d <num>\t\trefresh delay in seconds\n");
  fprintf(stdout, "\t-f      \t\tconfigures the ScoreboardFile to use\n");
  fprintf(stdout, "\t-h      \t\tdisplays this message\n");
  fprintf(stdout, "\t-i      \t\tignores idle connections when listing\n");
  fprintf(stdout, "\t-U      \t\tshow only uploading sessions\n");
  fprintf(stdout, "\t-V      \t\tshows version\n\n");
  exit(0);
}

static void verify_scoreboard_file(void) {
  struct stat sbuf;

  if (stat(util_get_scoreboard(), &sbuf) < 0) {
    fprintf(stderr, "%s: unable to stat '%s': %s\n", program,
      util_get_scoreboard(), strerror(errno));
    exit(1);
  }
}

int main(int argc, char *argv[]) {

  /* Process command line options. */
  process_opts(argc, argv);

  /* Verify that the scoreboard file is useable. */
  verify_scoreboard_file();

  /* Install signal handlers. */
  signal(SIGINT, finish);
  signal(SIGTERM, finish);

  /* Initialize the display. */
  initscr();
  cbreak();
  noecho();
  curs_set(0);

  /* Paint the initial display. */
  show_sessions();

  /* Loop endlessly. */
  for (;;) {
    int c = -1;

    if (halfdelay(delay * 10) != ERR)
      c = getch();

    if (c != -1 && tolower(c) == 'q')
      finish(0);

    show_sessions();
  }

  /* done */
  finish(0);
}

#else /* defined(HAVE_CURSES) || defined(HAVE_NCURSES) */

#include <stdio.h>

int main(int argc, char *argv[]) {
  fprintf(stdout, "%s: no curses or ncurses library on this system\n", program);
  return 1;
}

#endif /* defined(HAVE_CURSES) || defined(HAVE_NCURSES) */
