/* ProFTPD default path configuration.  Normally, Makefiles generated
 * by the top-level configuration script define the RUN_DIR and
 * CONFIG_FILE_PATH macros, so the two below are typically not used.
 */

#ifndef PROFTPD_PATHS_H
#define PROFTPD_PATHS_H

/* The location you wish to place the "run-time" status file used by
 * ftpcount, ftpwho, etc.
 */
#ifndef RUN_DIR
#define RUN_DIR			"/var/run/proftpd"
#endif

/* The location you wish to place any core files produced as a result of
 * fatal errors (memory problems, etc).
 */
#ifndef CORE_DIR
#define CORE_DIR		RUN_DIR
#endif

/* The file in which to write the pid (in ASCII) after the initial fork,
 * when run in standalone daemon mode.
 */
#ifndef PID_FILE_PATH
#define PID_FILE_PATH		"/var/run/proftpd.pid"
#endif

/* The default location of the proftpd configuration file.  Can be
 * overriden at runtime with the '-c' switch
 */
#ifndef CONFIG_FILE_PATH
#define	CONFIG_FILE_PATH	"/etc/proftpd.conf"
#endif

/* The location of your `shells' file; a newline delimited list of
 * valid shells on your system.
 */
#define VALID_SHELL_PATH	"/etc/shells"

/* Where your log files are kept.  The "wu-ftpd style" xferlog is
 * stored here, as well as "extended" (not yet available) transfer
 * log files.  These can be overridden in the configuration file via
 * "TransferLog" and "ExtendedLog".  (note ExtendedLog does not work yet)
 */
#define XFERLOG_PATH		"/var/log/xferlog"
#define EXTLOG_PATH		"/var/log/proftpd-log"

/* Location of the file that tells proftpd to discontinue servicing
 * requests.
 */
#define SHUTMSG_PATH		"/etc/shutmsg"

/* Location of the file containing users that *cannot* use ftp
 * services (odd, eh?)
 */
#define FTPUSERS_PATH		"/etc/ftpusers"

#endif /* PROFTPD_PATHS_H */
