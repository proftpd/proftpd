#!/bin/sh
#
# Startup script for ProFTPd
#
# chkconfig: 345 85 15
# description: ProFTPD is an enhanced FTP server with \
#               a focus toward simplicity, security, and ease of configuration. \
#              It features a very Apache-like configuration syntax, \
#               and a highly customizable server infrastructure, \
#               including support for multiple 'virtual' FTP servers, \
#               anonymous FTP, and permission-based directory visibility.
# processname: proftpd
# config: /etc/proftpd.conf
#
# By: Osman Elliyasa <osman@Cable.EU.org>
# $Id: proftpd.init.d,v 1.2 2001-01-26 23:10:55 flood Exp $

# Source function library.
. /etc/rc.d/init.d/functions

FTPSHUT=/opt/sbin/ftpshut

# See how we were called.
case "$1" in
  start)
	echo -n "Starting proftpd: "
	if [ -x ~ftp-master/bin/advert.sh ]; then
		echo -n "Adverts "
		su - ftp-master -c "bin/advert.sh fifo"
	fi
	$0 resume
	daemon proftpd
	echo
	touch /var/lock/subsys/proftpd
	;;
  stop)
	echo -n "Shutting down proftpd: "
	if [ -x ~ftp-master/bin/advert.sh ]; then
		echo -n "Adverts "
		su - ftp-master -c "bin/advert.sh kfifo"
	fi
	$0 suspend
	killproc proftpd
	echo
	rm -f /var/lock/subsys/proftpd
	;;
  status)
	status proftpd
	;;
  restart)
	$0 stop
	$0 start
	;;
  reread)
	echo -n "Re-reading proftpd config: "
	killproc proftpd -HUP
	echo
	;;
  suspend)
  	if [ -f $FTPSHUT ]; then
  		if [ $# -gt 1 ]; then
			shift
			echo -n "Suspending with '$*' "
			$FTPSHUT $*
		else
			echo -n "Suspending NOW "
			$FTPSHUT now "Maintanance in progress"
		fi
	else
		echo -n "No way to suspend "
	fi
	echo
  	;;
  resume)
	if [ -f /etc/shutmsg ]; then
		echo -n "Allowing sessions again "
		rm -f /etc/shutmsg
	else
		echo -n "Was not suspended "
	fi
	echo
  	;;
  *)
	echo -n "Usage: $0 {start|stop|restart|status|reread|resume"
  	if [ "$FTPSHUT" = "" ]; then
		echo "}"
	else
		echo "|suspend}"
		echo "suspend accepts additional arguments which are passed to ftpshut(8)"
	fi
	exit 1
esac

if [ $# -gt 1 ]; then
	shift
	$0 $*
fi

exit 0
