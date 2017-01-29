#!/bin/bash

set -x

VERSION=${PACKAGE_VERSION:-1.3.6rc5}
exit 0

# Make sure that the necessary packages/tools are installed
yum install -y gcc make git rpm-build

# These are for the basic proftpd build
yum install -y gettext pkgconfig pam-devel ncurses-devel zlib-devel libacl-devel libcap-devel

# And these are for --with everything
yum install -y openldap-devel libmemcached-devel mysql-devel pcre-devel postgresql-devel openssl-devel tcp_wrappers-devel

mkdir git
cd git
git clone --depth 10 https://github.com/proftpd/proftpd.git proftpd-${VERSION}
cd proftpd-${VERSION}/
./configure
rm -fr .git/
make dist
cd ..
tar zcvf proftpd-${VERSION}.tar.gz proftpd-${VERSION}
rpmbuild -ta proftpd-${VERSION}.tar.gz --with everything
