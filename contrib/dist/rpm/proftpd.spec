# $Id: proftpd.spec,v 1.9 2003-01-03 03:53:45 jwm Exp $

Summary:	ProFTPD -- Professional FTP Server.
Name:		proftpd
Version:	1.2.8rc1
Release:	1
Copyright:	GPL
Group:		System Environment/Daemons
Packager:	John Morrissey <jwm@proftpd.org>
Vendor:		The ProFTPD Group
URL:		http://www.proftpd.org/
Source:		ftp://ftp.proftpd.org/distrib/%{name}-%{version}.tar.bz2
Prefix:		/usr
BuildRoot:	%{_builddir}/%{name}-%{version}-root
Requires:	pam >= 0.72
Provides:	ftpserver
Prereq:		fileutils
Obsoletes:	proftpd-core

%description
ProFTPD is an enhanced FTP server with a focus toward simplicity, security,
and ease of configuration.  It features a very Apache-like configuration
syntax, and a highly customizable server infrastructure, including support for
multiple 'virtual' FTP servers, anonymous FTP, and permission-based directory
visibility.

There are two other packages you can use to setup for inetd or standalone
operation.

%package standalone
Summary:	ProFTPD -- Setup for standalone operation.
Group:		System Environment/Daemons
Requires:	proftpd chkconfig
Obsoletes:	proftpd-inetd

%description standalone
This package is neccesary to setup ProFTPD in standalone operation.

%package inetd
Summary:	ProFTPD -- Setup for inetd operation.
Group:		System Environment/Daemons
Requires:	proftpd
Obsoletes:	proftpd-standalone

%description inetd
This package is neccesary to setup ProFTPD to run from inetd.

%prep
%setup -q
  CFLAGS="$RPM_OPT_FLAGS" ./configure \
	--prefix=%{prefix} \
	--sysconfdir=/etc \
	--localstatedir=/var/run \
	--mandir=%_mandir \
	--with-modules=mod_ratio:mod_readme

%build
  make

%install
  rm -rf $RPM_BUILD_ROOT
  make prefix=$RPM_BUILD_ROOT%{prefix} \
	sysconfdir=$RPM_BUILD_ROOT/etc \
    mandir=$RPM_BUILD_ROOT/%_mandir \
	localstatedir=$RPM_BUILD_ROOT/var/run \
	rundir=$RPM_BUILD_ROOT/var/run/proftpd \
	INSTALL_USER=`id -un` INSTALL_GROUP=`id -gn` \
    install
  mkdir -p $RPM_BUILD_ROOT/home/ftp
  mkdir -p $RPM_BUILD_ROOT/etc/pam.d
  install -m 644 contrib/dist/rpm/ftp.pamd $RPM_BUILD_ROOT/etc/pam.d/ftp
  install -m 644 sample-configurations/basic.conf $RPM_BUILD_ROOT/etc/proftpd.conf
  mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
  sed -e '/FTPSHUT=/c\' \
	  -e 'FTPSHUT=%{prefix}/sbin/ftpshut' \
	contrib/dist/rpm/proftpd.init.d \
  > contrib/dist/rpm/proftpd.init.d.tmp
  mv --force contrib/dist/rpm/proftpd.init.d.tmp contrib/dist/rpm/proftpd.init.d
  install -m 755 contrib/dist/rpm/proftpd.init.d $RPM_BUILD_ROOT/etc/rc.d/init.d/proftpd
  mkdir -p $RPM_BUILD_ROOT/etc/logrotate.d/
  install -m 644 contrib/dist/rpm/proftpd.logrotate $RPM_BUILD_ROOT/etc/logrotate.d/proftpd
  # We don't want this dangling symlinks to make it into the RPM
  rm -f contrib/README.mod_sql
  mkdir -p $RPM_BUILD_ROOT/%{_docdir}
  install -m 644 COPYING CREDITS ChangeLog NEWS $RPM_BUILD_ROOT/%{_docdir}

%pre
  if [ ! -f /etc/ftpusers ]; then
  	touch /etc/ftpusers
  	IFS=":"
	while { read username nu nu gid nu; }; do
		if [ $gid -le 100 -a "$username" != "ftp" ]; then
			echo $username
		fi
  	done < /etc/passwd > /etc/ftpusers
  fi

%preun
  if [ "$1" = 0 ]; then
    if [ -d /var/run/proftpd ]; then
		rm -rf /var/run/proftpd/*
    fi
  fi

%post standalone
  /sbin/chkconfig --add proftpd
  # Force the "ServerType" directive for this operation type.
  tmpfile=/tmp/proftpd-conf.$$
  sed	-e '/ServerType/c\' \
	-e 'ServerType	standalone' \
	/etc/proftpd.conf \
  > $tmpfile
  mv $tmpfile /etc/proftpd.conf

%preun standalone
  if [ "$1" = 0 ]; then
    /sbin/chkconfig --del proftpd
  fi

%post inetd
  # Force the "ServerType" directive for this operation type.
  tmpfile=/tmp/proftpd-conf.$$
  sed	-e '/ServerType/c\' \
	-e 'ServerType	inetd' \
	/etc/proftpd.conf \
  > $tmpfile
  mv $tmpfile /etc/proftpd.conf

  # Look if there is already an entry for 'ftp' service even when commented.
  grep '^[#[:space:]]*ftp' /etc/inetd.conf > /dev/null
  errcode=$?
  if [ $errcode -eq 0 ]; then
  # Found, replace the 'in.ftpd' with 'in.proftpd'
	tmpfile=/tmp/proftpd-inetd.$$
	sed	-e '/^[#[:space:]]*ftp/{' \
		-e 's^in.ftpd.*$^in.proftpd^' \
		-e '}' \
		/etc/inetd.conf \
	> $tmpfile
	mv $tmpfile /etc/inetd.conf
  else
  # Not found, append a new entry.
	echo 'ftp      stream  tcp     nowait  root    /usr/sbin/tcpd  in.proftpd' >> /etc/inetd.conf
  fi
  # Reread 'inetd.conf' file.
  killall -HUP inetd || :

%postun inetd
  if [ "$1" = 0 ]; then
    # Remove ProFTPD entry from /etc/inetd.conf
    tmpfile=/tmp/proftpd-inetd.$$
    sed -e '/^.*proftpd.*$/d' /etc/inetd.conf > $tmpfile
    mv $tmpfile /etc/inetd.conf
    killall -HUP inetd || :
  fi

%clean
rm -rf $RPM_BUILD_ROOT
rm -rf %{_builddir}/%{name}-%{version}

%files
%defattr(-,root,root)
/usr/sbin/*
/usr/bin/*
/etc/logrotate.d/proftpd
%dir /var/run/proftpd
%dir /home/ftp
%config(noreplace) /etc/pam.d/ftp

%doc COPYING CREDITS ChangeLog NEWS
%doc README* doc/*
%doc contrib/README* contrib/xferstats.holger-preiss
%doc sample-configurations
%_mandir/*/*

%files standalone
%defattr(-,root,root)
/etc/rc.d/init.d/proftpd
%config(noreplace) /etc/proftpd.conf

%files inetd
%defattr(-,root,root)
%config(noreplace) /etc/proftpd.conf

%changelog
* Sat Nov  2 2002 John Morrissey <jwm@horde.net>
- Don't let dangling contrib/README.* symlinks get into the built RPM
- logrotate for xferlog

* Wed Aug 14 2002 John Morrissey <jwm@horde.net>
- Added removal of build leftover directory in %clean.
  Submitted by: Christian Pelealu <kurisu@mweb.co.id>

* Wed Jul  3 2002 John Morrissey <jwm@horde.net> 1.2.6rc1-1
- 1.2.6rc1 release.

* Sun Jun  9 2002 John Morrissey <jwm@horde.net> 1.2.5-1
- 1.2.5 release.

* Fri May 10 2002 TJ Saunders <tj@castaglia.org>
- Added use of %defattr to allow build of RPMs by non-root users
  For details see http://bugs.proftpd.org/show_bug.cgi?id=1580

* Mon Mar 05 2001 Daniel Roesen <droesen@entire-systems.com>
- PAM >= 0.72 is now a requirement. Versions before are broken and
  Red Hat provides a PAM update for all RH 6.x releases. See:
  http://www.redhat.com/support/errata/RHSA-2000-120.html
  Thanks to O.Elliyasa <osman@Cable.EU.org> for the suggestion.
  For details see http://bugs.proftpd.org/show_bug.cgi?id=1048
- release: 1.2.1-2

* Wed Mar 01 2001 Daniel Roesen <droesen@entire-systems.com>
- Update to 1.2.1
- release: 1.2.1-1

* Wed Feb 27 2001 Daniel Roesen <droesen@entire-systems.com>
- added "Obsoletes: proftpd-core" to make migration to new RPMs easier.
  Thanks to Sébastien Prud'homme <prudhomme@easy-flying.com> for the hint.
- release: 1.2.0-3

* Wed Feb 26 2001 Daniel Roesen <droesen@entire-systems.com>
- cleaned up .spec formatting (cosmetics)
- fixed CFLAGS (fixes /etc/shadow support)
- included COPYING, CREDITS, ChangeLog and NEWS
- Renamed main package from "proftpd-core" to just "proftpd"
- release: 1.2.0-2

* Wed Feb 14 2001 Daniel Roesen <droesen@entire-systems.com>
- moved Changelog to bottom
- fixed %pre script /etc/ftpusers generator
- removed /ftp/ftpusers from package management. Deinstalling ProFTPD
  should _not_ result in removal of this file.

* Thu Oct 03 1999 O.Elliyasa <osman@Cable.EU.org>
- Multi package creation.
  Created core, standalone, inetd (&doc) package creations.
  Added startup script for init.d
  Need to make the "standalone & inetd" packages being created as "noarch"
- Added URL.
- Added prefix to make the package relocatable.

* Wed Sep 08 1999 O.Elliyasa <osman@Cable.EU.org>
- Corrected inetd.conf line addition/change logic.

* Sat Jul 24 1999 MacGyver <macgyver@tos.net>
- Initial import of spec.
