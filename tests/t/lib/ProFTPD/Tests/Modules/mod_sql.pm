package ProFTPD::Tests::Modules::mod_sql;

# Copyright (c) 2026 The ProFTPD Project team
# SPDX-License-Identifier: GPL-2.0-only WITH vsftpd-openssl-exception

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use File::Spec;
use IO::Handle;

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

1;
