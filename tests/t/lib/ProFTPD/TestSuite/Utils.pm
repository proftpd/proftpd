package ProFTPD::TestSuite::Utils;

use strict;

use Carp;
use File::Path;
use File::Spec;
use IO::Socket::INET;

require Exporter;
our @ISA = qw(Exporter);

our @AUTH = qw(
  auth_group_write
  auth_user_write
);

our @CONFIG = qw(
  config_get_identity
  config_write
);

our @FEATURES = qw(
  feature_have_feature_enabled
  feature_have_module_compiled
  feature_have_module_loaded
);

our @RUNNING = qw(
  server_start
  server_stop
  server_wait
);

our @TEST = qw(
  test_msg
);

our @TESTSUITE = qw(
  testsuite_empty_test
  testsuite_get_runnable_tests
  testsuite_get_tmp_dir
);

our @EXPORT_OK = (@AUTH, @CONFIG, @FEATURES, @RUNNING, @TEST, @TESTSUITE);

our %EXPORT_TAGS = (
  auth => [@AUTH],
  config => [@CONFIG],
  features => [@FEATURES],
  running => [@RUNNING],
  test => [@TEST],
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

sub get_passwd {
  my $user_passwd = shift;

  # First, try to use MD5 hashing for passwords
  my $md5_salt = '$1$' . join('', (0..9, 'A'..'Z', 'a'..'z')[rand(62), rand(62), rand(62), rand(62), rand(62), rand(62), rand(62), rand(62)]);

  my $hash = crypt($user_passwd, $md5_salt);

  # If the first three characters of the hash are not "$1$", the crypt()
  # implementation doesn't support MD5.  Some crypt()s will happily use
  # "$1" as a salt even though this is not a valid DES salt.  Humf.

  my @string = split('', $hash);
  my $prefix = $string[0] . $string[1] . $string[2];

  if ($prefix ne '$1$') {
    # OK, fall back to using a DES hash.
    my $des_salt = join('', ('.', '/', 0..9, 'A'..'Z', 'a'..'z')[rand(64), rand(64)]);

    $hash = crypt($user_passwd, $des_salt);
  }

  return $hash;

}

sub auth_group_write {
  my $group_file = shift;
  croak("Missing group file argument") unless $group_file;
  my $group_name = shift;
  croak("Missing group name argument") unless $group_name;
  my $group_id = shift;
  croak("Missing group ID argument") unless $group_id;

  my @member_names = @_;

  if (open(my $fh, "> $group_file")) {
    print $fh "$group_name:*:$group_id:" . join(',', @member_names) . "\n";

    unless (close($fh)) {
      croak("Can't write $group_file: $!");
    }

  } else {
    croak("Can't open $group_file: $!");
  }
}

sub auth_user_write {
  my $user_file = shift;
  croak("Missing user file argument") unless $user_file;
  my $user_name = shift;
  croak("Missing user name argument") unless $user_name;
  my $user_passwd = shift;
  croak("Missing user password argument") unless $user_passwd;
  my $user_id = shift;
  croak("Missing user ID argument") unless $user_id;
  my $group_id = shift;
  croak("Missing group ID argument") unless $group_id;
  my $home = shift;
  croak("Missing home directory argument") unless $home;
  my $shell = shift;
  croak("Missing shell argument") unless $shell;

  my $passwd = get_passwd($user_passwd);

  if (open(my $fh, "> $user_file")) {
    print $fh join(':', ($user_name, $passwd, $user_id, $group_id, '', $home,
      $shell)), "\n";

    unless (close($fh)) {
      croak("Can't write $user_file: $!");
    }

  } else {
    croak("Can't open $user_file: $!");
  }
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
    my $candidate;

    foreach $candidate (@$users) {
      my $candidate_uid = (getpwnam($candidate))[2];

      if ($candidate_uid != 0) {
        $user = $candidate;
        last;
      }
    }

    foreach $candidate (@$groups) {
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

  unless (defined($config->{RequireValidShell})) {
    $config->{RequireValidShell} = 'off';
  }

  unless (defined($config->{ServerType})) {
    $config->{ServerType} = 'standalone';
  }

  unless (defined($config->{TimeoutIdle})) {
    $config->{TimeoutIdle} = '10';
  }

  unless (defined($config->{TransferLog})) {
    $config->{TransferLog} = 'none';
  }

  unless (defined($config->{UseFtpUsers})) {
    $config->{UseFtpUsers} = 'off';
  }

  if (feature_have_feature_enabled('ipv6')) {
    unless (defined($config->{UseIPv6})) {
      $config->{UseIPv6} = 'off';
    }
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

      } elsif ($k eq 'Directory') {
        my $sections = $v;

        foreach my $dir (keys(%$sections)) {
          print $fh "<Directory $dir>\n";

          while (my ($dir_k, $dir_v) = each(%{ $sections->{$dir} })) {
            print $fh "  $dir_k $dir_v\n";
          }

          print $fh "</Directory>\n";
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

sub feature_have_feature_enabled {
  my $feat = shift;

  if (open(my $cmdh, "$proftpd_bin -V |")) {
    my $feat_list;

    while (my $line = <$cmdh>) {
      chomp($line);

      next unless $line =~ /\s+(\-|\+)\s+(\S+)\s+support/;

      my $flag = $1;
      my $feature = $2;

      if ($flag eq '+') {
        push(@$feat_list, $feature);
      }
    }

    close($cmdh);

    my $matches = grep { /^$feat$/i } @$feat_list;

    return $matches;

  } else {
    croak("Error listing features");
  }
}

sub feature_have_module_compiled {
  my $module = shift;

  if (open(my $cmdh, "$proftpd_bin -l |")) {
    my $mod_list;

    while (my $line = <$cmdh>) {
      chomp($line);

      next if $line =~ /Compiled\-in/;
      $line =~ s/^\s+//;

      push(@$mod_list, $line);
    }

    close($cmdh);

    my $matches = grep { /^$module$/ } @$mod_list;

    return $matches;

  } else {
    croak("Error listing compiled modules");
  }
}

sub feature_have_module_loaded {
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
    $cmd .= " -d10";

  } else {
    $cmd .= " > /dev/null 2>&1";
  }

  if ($ENV{TEST_VERBOSE}) {
    print STDERR "Starting server: $cmd\n";
  }

  my @output = `$cmd`;
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

  my @output = `$cmd`;
}

my $server_wait_timeout = 0;
sub server_wait_alarm {
  croak("Test timed out after $server_wait_timeout secs");
}

sub server_wait {
  my $config_file = shift;
  my $rfh = shift;
  $server_wait_timeout = shift;
  $server_wait_timeout = 10 unless defined($server_wait_timeout);

  # Start server
  server_start($config_file);

  $SIG{ALRM} = \&server_wait_alarm;
  alarm($server_wait_timeout);

  # Wait until we receive word from the child that it has finished its test.
  while (my $msg = <$rfh>) {
    chomp($msg);

    if ($msg eq 'done') {
      last;
    }
  }

  alarm(0);
  $SIG{ALRM} = 'DEFAULT';
  return 1;
}

sub test_msg {
  my $msg = shift;

  my ($pkg, $file, $lineno) = caller();

  return "$msg (at $file:$lineno)";
}

sub testsuite_empty_test {
}

sub testsuite_get_runnable_tests {
  my $tests = shift;
  return undef unless $tests;

  # Special handling of any 'feature_*' test classes; if the compiled proftpd
  # has these features enabled, include those tests.

  my $skip_tests = [];
  foreach my $test (keys(%$tests)) {
    foreach my $class (@{ $tests->{$test}->{test_class} }) {
      if ($class =~ /^feature_\S+$/) {
        my $feat = $class;

        unless (feature_have_feature_enabled($feat)) {
          push(@$skip_tests, $test);
          last;
        }
      }
    }

    foreach my $skip_test (@$skip_tests) {
      delete($tests->{$skip_test});
    }
  }

  # Special handling of any 'mod_*' test classes; if the compiled proftpd
  # has these as static modules, include those tests.

  my $skip_tests = [];
  foreach my $test (keys(%$tests)) {
    foreach my $class (@{ $tests->{$test}->{test_class} }) {
      if ($class =~ /^mod_\S+$/) {
        my $module = $class;

        if ($module !~ /\.c$/) {
          $module .= '.c';
        }

        unless (feature_have_module_compiled($module)) {
          push(@$skip_tests, $test);
          last;
        }
      }
    }

    foreach my $skip_test (@$skip_tests) {
      delete($tests->{$skip_test});
    }
  }

  # Special handling of the 'rootprivs' test class: unless we are running
  # as root, we should exclude those test cases.
  unless ($< == 0) {
    $skip_tests = [];
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

    foreach my $test_class (@$test_classes) {
      foreach my $test (keys(%$tests)) {
        foreach my $class (@{ $tests->{$test}->{test_class} }) {
          if ($class eq $test_class) {
            push(@$runnables, $test);
            last;
          }
        }
      }
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

  if (scalar(@$runnables) > 0) {
    $runnables = [sort { $tests->{$a}->{order} <=> $tests->{$b}->{order} } @$runnables];
  } else { 
    $runnables = [qw(testsuite_empty_test)];
  }

  return @$runnables;
}

sub testsuite_get_tmp_dir {
  my $tmpdir = '/tmp';
  $tmpdir = $ENV{TMPDIR} if defined($ENV{TMPDIR});

  return $tmpdir;
}

1;
