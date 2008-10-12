package ProFTPD::TestSuite::Utils;

use strict;

use Carp;
use File::Path;
use File::Spec;
use IO::Socket::INET;

require Exporter;
our @ISA = qw(Exporter);

our @CONFIG = qw(
  config_get_identity
  config_write
);

our @MODULE = qw(
  module_have_compiled
  module_have_loaded
);

our @RUNNING = qw(
  server_start
  server_stop
);

our @TESTSUITE = qw(
  testsuite_empty_test
  testsuite_get_runnable_tests
  testsuite_get_tmp_dir
);

our @EXPORT_OK = (@CONFIG, @MODULE, @RUNNING, @TESTSUITE);

our %EXPORT_TAGS = (
  config => [@CONFIG],
  module => [@MODULE],
  running => [@RUNNING],
  testsuite => [@TESTSUITE],
);

# XXX Assume that the proftpd executable to use is one directory up;
# assume that tests are always run from the tests/ directory.
my $proftpd_bin = "../proftpd";

sub get_high_numbered_port {

  # XXX There's a minor race condition here, between opening a listening
  # socket on a kernel-chosen random port, closing that socket, and returning
  # the port number for use in the proftpd config.

  my $sock = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    Listen => 5,
    Proto => 'tcp',
    ReuseAddr => 1,
  );

  my $port = $sock->sockport();
  $sock->close();

  return $port;
}

sub config_get_identity {
  my ($user, $group);

  unless ($< == 0) {
    # Use $> (effective UID) rather than $< (real UID)
    my $ruid = $>;
    $user = (getpwuid($ruid))[0];

    # Similarly, use $) (effective GID) rather than $( (real GID)
    my $rgid = (split/\s+/, $))[0];
    $group = (getgrgid($rgid))[0];

  } else {
    # If the real user ID is root, try to use some non-root user
    my $users = [qw(daemon www ftp adm nobody)];
    my $groups = [qw(daemon www ftp staff adm nogroup)];

    foreach my $candidate (@$users) {
      my $candidate_uid = (getpwnam($candidate))[2];

      if ($candidate_uid != 0) {
        $user = $candidate;
        last;
      }
    }

    foreach my $candidate (@$groups) {
      my $candidate_gid = (getgrnam($candidate))[2];

      if ($candidate_gid != 0) {
        $group = $candidate;
        last;
      }
    }
  }

  return ($user, $group);
}

sub config_write {
  my $path = shift;
  my $config = shift;

  my $port = get_high_numbered_port();
  my ($user_name, $group_name) = config_get_identity();

  $config->{Port} = $port;
  $config->{User} = $user_name;
  $config->{Group} = $group_name;

  # Set a bunch of defaults, unless overridden by the caller

  unless (defined($config->{DefaultAddress})) {
    $config->{DefaultAddress} = '127.0.0.1';
  }

  unless (defined($config->{DefaultServer})) {
    $config->{DefaultServer} = 'on';
  }

  unless (defined($config->{IdentLookups})) {
    $config->{IdentLookups} = 'off';
  }

  unless (defined($config->{ServerType})) {
    $config->{ServerType} = 'standalone';
  }

  unless (defined($config->{TransferLog})) {
    $config->{TransferLog} = 'none';
  }

  unless (defined($config->{UseFtpUsers})) {
    $config->{UseFtpUsers} = 'off';
  }

  unless (defined($config->{UseReverseDNS})) {
    $config->{UseReverseDNS} = 'off';
  }

  unless (defined($config->{WtmpLog})) {
    $config->{WtmpLog} = 'off';
  }

  my $abs_path = File::Spec->rel2abs($path);

  if (open(my $fh, "> $abs_path")) {
    my $timestamp = scalar(localtime());

    print $fh "# Auto-generated proftpd config file\n";
    print $fh "# Written on: $timestamp\n\n";

    while (my ($k, $v) = each(%$config)) {

      if ($k eq 'IfModules') {
        my $modules = $v;

        foreach my $mod (keys(%$modules)) {
          print $fh "<IfModule $mod>\n";

          while (my ($mod_k, $mod_v) = each(%{ $modules->{$mod} })) {
            print $fh "  $mod_k $mod_v\n";
          }

          print $fh "</IfModule>\n";
        }

      } elsif ($k eq 'Anonymous') {
        my $sections = $v;

        foreach my $anon (keys(%$sections)) {
          print $fh "<Anonymous $anon>\n";

          while (my ($anon_k, $anon_v) = each(%{ $sections->{$anon} })) {
            print $fh "  $anon_k $anon_v\n";
          }

          print $fh "</Anonymous>\n";
        }

      } else {
        print $fh "$k $v\n";
      }
    }

    unless (close($fh)) {
      croak("Error writing $abs_path: $!");
    }

  } else {
    croak("Error opening $abs_path: $!");
  }

  if (wantarray()) {
    return ($port, $user_name, $group_name);
  }

  return 1;
}

sub module_have_compiled {
  my $module = shift;

  if (open(my $cmdh, "$proftpd_bin -l |")) {
    my $mod_list;

    while (my $line = <$cmdh>) {
      chomp($line);

      next if $line =~ /Compiled\-in/;
      $line =~ s/^\s+//;

      push(@$mod_list, $line);

      if (grep { /^$module$/ } @$mod_list) {
        return 1;
      }

      return 0;
    }

    close($cmdh);

  } else {
    croak("Error listing compiled modules");
  }
}

sub module_have_loaded {
  my $module = shift;;
  my $config_file = shift;

  if (open(my $cmdh, "$proftpd_bin -vv -c $config_file |")) {
    my $mod_list;

    while (my $line = <$cmdh>) {
      chomp($line);

      next unless $line =~ /^\s+mod_/;
      $line =~ s/^\s+//;

      push(@$mod_list, $line);

      # Need to be able to handle the listing info for a module which
      # includes the module version, rather than a ".c" ending.
      my $alt_module = $module;
      $alt_module =~ s/\.c$/\//g;

      if (grep { /^($module$|$alt_module)/ } @$mod_list) {
        return 1;
      }

      return 0;
    }

    close($cmdh);

  } else {
    croak("Error listing loaded modules");
  }
}

sub server_start {
  my $config_file = shift;
  croak("Missing config file argument") unless $config_file;
  my $debug_level = shift;

  # Make sure that the config file is an absolute path
  my $abs_config_file = File::Spec->rel2abs($config_file);

  my $cmd = "$proftpd_bin -q -c $abs_config_file";

  if ($debug_level) {
    $cmd .= " -d $debug_level";

  } elsif ($ENV{TEST_VERBOSE}) {
    $cmd .= " -d 10";

  } else {
    $cmd .= " > /dev/null 2>&1";
  }

  if ($ENV{TEST_VERBOSE}) {
    print STDERR "Starting server: $cmd\n";
  }

  `$cmd`;
}

sub server_stop {
  my $pid_file = shift;

  my $pid;
  if (open(my $fh, "< $pid_file")) {
    $pid = <$fh>;
    chomp($pid);
    close($fh);

  } else {
    croak("Can't read $pid_file: $!");
  }

  my $cmd = "kill -TERM $pid";

  if ($ENV{TEST_VERBOSE}) {
    print STDERR "Stopping server: $cmd\n";
  }

  `$cmd`;
}

sub testsuite_empty_test {
}

sub testsuite_get_runnable_tests {
  my $tests = shift;
  return undef unless $tests;

  # Special handling of the 'rootprivs' test class: unless we are running
  # as root, we should exclude those test cases.
  unless ($< == 0) {
    my $skip_tests = [];
    foreach my $test (keys(%$tests)) {
      my $ok = 1;
      foreach my $test_class (@{ $tests->{$test}->{test_class} }) {
        if ($test_class eq 'rootprivs') {
          $ok = 0;
          last;
        }
      }

      unless ($ok) {
        push(@$skip_tests, $test);
      }
    }
 
    foreach my $skip_test (@$skip_tests) {
      delete($tests->{$skip_test});
    }
  }
 
  my $runnables = [];

  if (defined($ENV{PROFTPD_TEST_ENABLE_CLASS})) {
    my $test_classes = [split(':', $ENV{PROFTPD_TEST_ENABLE_CLASS})];
    my $have_test = 0;

    foreach my $test_class (@$test_classes) {
      foreach my $test (keys(%$tests)) {
        foreach my $class (@{ $tests->{$test}->{test_class} }) {
          if ($class eq $test_class) {
            $have_test = 1;
            push(@$runnables, $test);
            last;
          }
        }
      }
    }

    unless ($have_test) {
      $runnables = [qw(testsuite_empty_test)];
    }

  } else {
    $runnables = [keys(%$tests)];
  }

  if (defined($ENV{PROFTPD_TEST_DISABLE_CLASS})) {
    my $test_classes = [split(':', $ENV{PROFTPD_TEST_DISABLE_CLASS})];
    my $new_runnables = [];

    foreach my $test (@$runnables) {
      my $skip_test = 0;

      foreach my $test_class (@$test_classes) {
        foreach my $class (@{ $tests->{$test}->{test_class} }) {
          if ($class eq $test_class) {
            $skip_test = 1;
            last;
          }

          if ($skip_test) {
            last;
          }
        }

        unless ($skip_test) {
          push(@$new_runnables, $test);
        }
      }
    }

    $runnables = $new_runnables;
  }

  $runnables = [sort { $tests->{$a}->{order} <=> $tests->{$b}->{order} } @$runnables];
  return @$runnables;
}

sub testsuite_get_tmp_dir {
  my $tmpdir = '/tmp';
  $tmpdir = $ENV{TMPDIR} if defined($ENV{TMPDIR});

  return $tmpdir;
}

1;
