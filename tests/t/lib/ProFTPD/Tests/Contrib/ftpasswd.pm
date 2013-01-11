package ProFTPD::Tests::Contrib::ftpasswd;

use lib qw(t/lib);
use base qw(Test::Unit::TestCase ProFTPD::TestSuite::Child);
use strict;

use File::Path qw(mkpath rmtree);
use File::Spec;
use IO::Handle;

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  ftpasswd_append_user_bugXXXX => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub get_ftpasswd_bin {
  my $ftpasswd_bin;

  if ($ENV{PROFTPD_TEST_PATH}) {
    $ftpasswd_bin = "$ENV{PROFTPD_TEST_PATH}/bin/ftpasswd";

  } else {
    $ftpasswd_bin = '../contrib/ftpasswd';
  }

  return $ftpasswd_bin;
}

sub ftpasswd_append_user_bugXXXX {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $log_file = test_get_logfile();

  my $passwd_file = File::Spec->rel2abs("$tmpdir/ftpd.passwd");

  my $user1 = 'proftpd';
  my $passwd1 = 'test1';
  my $home_dir1 = File::Spec->rel2abs($tmpdir);
  my $uid1 = 500;
  my $gid1 = 500;

=pod

if ($ENV{TEST_VERBOSE}) {
  print STDERR "Executing ftpcount: $cmd\n";
}

$ ftpasswd --passwd --name=test@mail.com --uid=3000 
--gid=3000 --home=/home/test --shell=/bin/false 
--file=/home/astocker/proftpd.passwd
ftpasswd: using alternate file: /home/astocker/proftpd.passwd
ftpasswd: creating passwd entry for user test@mail.com

Password:
Re-type password:

ftpasswd: entry created
$ ls -l /home/astocker/proftpd.passwd
-r--r--r-- 1 astocker gmu 80 Jan 11 17:26 /home/astocker/proftpd.passwd
=cut

  my $user1 = 'proftpd';
  my $passwd1 = 'test1';
  my $home_dir1 = File::Spec->rel2abs($tmpdir);
  my $uid1 = 500;
  my $gid1 = 500;

=pod
$ ftpasswd --passwd --name=test2@mail.com --uid=3000 
--gid=3000 --home=/home/test --shell=/bin/false 
--file=/home/astocker/proftpd.passwd
ftpasswd: using alternate file: /home/astocker/proftpd.passwd
ftpasswd: creating passwd entry for user test2@mail.com

Password:
Re-type password:

ftpasswd: entry created
ftpasswd: unable to open /home/astocker/proftpd.passwd: Permission denied
=cut

  unlink($log_file);
}

1;
