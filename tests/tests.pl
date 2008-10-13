#!/usr/bin/env perl

use lib qw(t/lib);
use strict;

use Getopt::Long;
use Test::Harness;

my $opts = {};
GetOptions($opts, 'h|help', 'C|class=s@');

if ($opts->{h}) {
  usage();
}

$| = 1;

# XXX At some point, it might be nice to apply the concept of "test classes"
# to these test files, as well as to the individual tests defined within each
# file.

my $test_files = [qw(
  t/logins.t
  t/commands/pwd.t
  t/commands/cwd.t
  t/commands/cdup.t
  t/commands/syst.t
  t/commands/type.t
  t/commands/mkd.t
  t/commands/rmd.t
  t/commands/dele.t
  t/commands/mdtm.t
  t/commands/size.t 
  t/commands/mode.t
  t/commands/stru.t
  t/commands/allo.t
  t/commands/pasv.t
  t/commands/port.t
)];

$test_files = [@ARGV] if scalar(@ARGV) > 0;

$ENV{PROFTPD_TEST} = 1;

if (defined($opts->{C})) {
  $ENV{PROFTPD_TEST_ENABLE_CLASS} = join(':', @{ $opts->{C} });

} else {
  # Disable all 'inprogress' tests by default
  $ENV{PROFTPD_TEST_DIABLE_CLASS} = 'inprogress';
}

runtests(@$test_files) if scalar(@$test_files) > 0;

exit 0;

sub usage {
  print STDOUT <<EOH;

$0: [--help] [--class=\$name]

Examples:

  perl $0
  perl $0 --class foo
  perl $0 --class bar --class baz

EOH
  exit 0;
}
